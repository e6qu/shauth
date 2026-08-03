// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"context"
	"fmt"
	"time"
)

// Metrics is a point-in-time count of the durable state an operator watches:
// how many accounts exist and in what shape, how many sessions are live, and
// whether the validation queue is moving. Every number comes from PostgreSQL,
// so it reports what the service actually holds rather than what a process
// happened to observe since it started.
type Metrics struct {
	Users             UserMetrics
	Sessions          SessionMetrics
	Invitations       map[string]int
	Apps              AppMetrics
	Validations       ValidationMetrics
	LogoutCorrelation LogoutCorrelationMetrics
}

type UserMetrics struct {
	Total            int
	Disabled         int
	ByRole           map[string]int
	ByIdentitySource map[string]int
}

type SessionMetrics struct {
	Active  int
	Revoked int
	Total   int
}

type AppMetrics struct {
	Total int
}

type ValidationMetrics struct {
	ByStatus            map[string]int
	Queued              int
	Running             int
	OldestQueuedSeconds *float64
}

type LogoutCorrelationMetrics struct {
	Outstanding int
	Failed      int
}

// Metrics collects the counts in a handful of aggregate queries.
func (s *Store) Metrics(ctx context.Context, now time.Time) (Metrics, error) {
	policy, err := s.SessionPolicy(ctx)
	if err != nil {
		return Metrics{}, err
	}
	metrics := Metrics{
		Users:       UserMetrics{ByRole: map[string]int{}, ByIdentitySource: map[string]int{}},
		Invitations: map[string]int{},
		Validations: ValidationMetrics{ByStatus: map[string]int{}},
	}

	if err := s.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE disabled_at IS NOT NULL) FROM users`).
		Scan(&metrics.Users.Total, &metrics.Users.Disabled); err != nil {
		return Metrics{}, fmt.Errorf("count users: %w", err)
	}
	if err := s.countInto(ctx, `SELECT role, count(*) FROM users GROUP BY role`, metrics.Users.ByRole); err != nil {
		return Metrics{}, err
	}
	if err := s.countInto(ctx, `SELECT CASE WHEN github_login IS NOT NULL THEN 'github' WHEN entra_object_id IS NOT NULL THEN 'entra' ELSE 'local' END, count(*) FROM users GROUP BY 1`, metrics.Users.ByIdentitySource); err != nil {
		return Metrics{}, err
	}

	if err := s.pool.QueryRow(ctx, `SELECT
		count(*),
		count(*) FILTER (WHERE revoked_at IS NULL AND expires_at>$1 AND last_seen_at>$2),
		count(*) FILTER (WHERE revoked_at IS NOT NULL)
		FROM sessions`, now.UTC(), now.UTC().Add(-policy.BrowserIdleTimeout)).
		Scan(&metrics.Sessions.Total, &metrics.Sessions.Active, &metrics.Sessions.Revoked); err != nil {
		return Metrics{}, fmt.Errorf("count sessions: %w", err)
	}

	if err := s.countInto(ctx, `SELECT CASE
		WHEN accepted_at IS NOT NULL THEN 'accepted'
		WHEN revoked_at IS NOT NULL THEN 'revoked'
		WHEN expires_at<=now() THEN 'expired'
		ELSE 'pending' END, count(*) FROM invitations GROUP BY 1`, metrics.Invitations); err != nil {
		return Metrics{}, err
	}

	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM managed_apps`).Scan(&metrics.Apps.Total); err != nil {
		return Metrics{}, fmt.Errorf("count managed apps: %w", err)
	}

	if err := s.countInto(ctx, `SELECT status, count(*) FROM app_validation_runs GROUP BY status`, metrics.Validations.ByStatus); err != nil {
		return Metrics{}, err
	}
	metrics.Validations.Queued = metrics.Validations.ByStatus[ValidationQueued]
	metrics.Validations.Running = metrics.Validations.ByStatus[ValidationRunning]
	// A queue that stops draining is the failure an operator needs to see, so
	// the age of the oldest waiting run is reported alongside its depth.
	if err := s.pool.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM (now() - min(requested_at))) FROM app_validation_runs WHERE status=$1`, ValidationQueued).
		Scan(&metrics.Validations.OldestQueuedSeconds); err != nil {
		return Metrics{}, fmt.Errorf("measure validation queue age: %w", err)
	}

	if err := s.pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE completed_at IS NULL),
		count(*) FILTER (WHERE completed_at IS NULL AND cleanup_attempts>0)
		FROM logout_correlation_grants`).
		Scan(&metrics.LogoutCorrelation.Outstanding, &metrics.LogoutCorrelation.Failed); err != nil {
		return Metrics{}, fmt.Errorf("count logout correlation grants: %w", err)
	}
	return metrics, nil
}

func (s *Store) countInto(ctx context.Context, query string, target map[string]int) error {
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("aggregate counts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var count int
		if err := rows.Scan(&key, &count); err != nil {
			return fmt.Errorf("scan aggregate count: %w", err)
		}
		target[key] = count
	}
	return rows.Err()
}
