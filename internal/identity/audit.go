// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Audit event types. They are stable strings because operators and alerting
// filter on them; the set only grows.
const (
	AuditSignInSucceeded      = "sign_in.succeeded"
	AuditSignInFailed         = "sign_in.failed"
	AuditSignInBlocked        = "sign_in.blocked"
	AuditSessionRevoked       = "session.revoked"
	AuditAccountSessionsEnded = "account.sessions_ended"
	AuditAccountCreated       = "account.created"
	AuditAccountDisabled      = "account.disabled"
	AuditAccountEnabled       = "account.enabled"
	AuditInvitationCreated    = "invitation.created"
	AuditInvitationAccepted   = "invitation.accepted"
	AuditInvitationRevoked    = "invitation.revoked"
	AuditOIDCClientCreated    = "oidc_client.created"
	AuditOIDCClientDeleted    = "oidc_client.deleted"
	AuditAppCreated           = "app.created"
	AuditAppDeleted           = "app.deleted"
	AuditGitHubMappingCreated = "github_mapping.created"
	AuditGitHubMappingDeleted = "github_mapping.deleted"
	AuditSessionPolicyUpdated = "session_policy.updated"
	AuditValidationEnqueued   = "app_validation.enqueued"
	AuditLogoutCompleted      = "logout.completed"
	AuditLogoutFailed         = "logout.failed"
)

// AuditEvent is one durable record of a security-relevant action. It answers
// who did what to whom, from where, and how it turned out -- the questions an
// operator asks after an incident, which no log line retained for a few days
// can answer.
type AuditEvent struct {
	ID            string
	EventType     string
	ActorUserID   string
	SubjectUserID string
	SessionID     string
	RemoteAddress net.IP
	CreatedAt     time.Time
	Details       map[string]any
}

// AuditEntry is one event to record. Identifiers are optional: a failed
// sign-in for an unknown username has no subject, and a token-authorized
// operation has no actor.
type AuditEntry struct {
	EventType     string
	ActorUserID   string
	SubjectUserID string
	SessionID     string
	RemoteAddress net.IP
	Details       map[string]any
}

// RecordAuditEvent appends one event. Recording must never carry a secret:
// callers pass identifiers and outcomes, never credentials or tokens.
func (s *Store) RecordAuditEvent(ctx context.Context, entry AuditEntry, now time.Time) error {
	if strings.TrimSpace(entry.EventType) == "" {
		return invalidInput("an audit event requires a type")
	}
	details := entry.Details
	if details == nil {
		details = map[string]any{}
	}
	encoded, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("encode audit details: %w", err)
	}
	var address any
	if entry.RemoteAddress != nil {
		address = entry.RemoteAddress.String()
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO audit_events (id,actor_user_id,subject_user_id,session_id,event_type,remote_address,created_at,details)
	VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8)`,
		randomUUID(), nullableUUID(entry.ActorUserID), nullableUUID(entry.SubjectUserID), nullableUUID(entry.SessionID),
		entry.EventType, address, now.UTC(), encoded)
	if err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}

func nullableUUID(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

// AuditFilter narrows an audit query to the account, event type, or window an
// operator is investigating.
type AuditFilter struct {
	SubjectUserID string
	ActorUserID   string
	EventType     string
	Since         time.Time
	Until         time.Time
}

// ListAuditEvents reports matching events newest first with the total number
// of matches, so an operator can page through an investigation.
func (s *Store) ListAuditEvents(ctx context.Context, filter AuditFilter, page Page) ([]AuditEvent, int, error) {
	page = page.normalized()
	conditions := []string{"TRUE"}
	arguments := []any{}
	add := func(condition string, value any) {
		arguments = append(arguments, value)
		conditions = append(conditions, fmt.Sprintf(condition, len(arguments)))
	}
	if filter.SubjectUserID != "" {
		add("subject_user_id=$%d::uuid", filter.SubjectUserID)
	}
	if filter.ActorUserID != "" {
		add("actor_user_id=$%d::uuid", filter.ActorUserID)
	}
	if filter.EventType != "" {
		add("event_type=$%d", filter.EventType)
	}
	if !filter.Since.IsZero() {
		add("created_at>=$%d", filter.Since.UTC())
	}
	if !filter.Until.IsZero() {
		add("created_at<=$%d", filter.Until.UTC())
	}
	where := strings.Join(conditions, " AND ")
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE `+where, arguments...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit events: %w", err)
	}
	rows, err := s.pool.Query(ctx, `SELECT id::text,event_type,COALESCE(actor_user_id::text,''),COALESCE(subject_user_id::text,''),COALESCE(session_id::text,''),remote_address,created_at,details
	FROM audit_events WHERE `+where+fmt.Sprintf(` ORDER BY created_at DESC, id LIMIT $%d OFFSET $%d`, len(arguments)+1, len(arguments)+2),
		append(arguments, page.Limit, page.Offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	var events []AuditEvent
	for rows.Next() {
		var event AuditEvent
		var details []byte
		if err := rows.Scan(&event.ID, &event.EventType, &event.ActorUserID, &event.SubjectUserID, &event.SessionID, &event.RemoteAddress, &event.CreatedAt, &details); err != nil {
			return nil, 0, fmt.Errorf("scan audit event: %w", err)
		}
		if len(details) > 0 {
			if err := json.Unmarshal(details, &event.Details); err != nil {
				return nil, 0, fmt.Errorf("decode audit details: %w", err)
			}
		}
		events = append(events, event)
	}
	return events, total, rows.Err()
}

// ErrAuditEventNotFound reports that no audit event matches the identifier.
var ErrAuditEventNotFound = errors.New("audit event not found")

// AuditEvent reads one event by identifier.
func (s *Store) AuditEvent(ctx context.Context, id string) (AuditEvent, error) {
	var event AuditEvent
	var details []byte
	err := s.pool.QueryRow(ctx, `SELECT id::text,event_type,COALESCE(actor_user_id::text,''),COALESCE(subject_user_id::text,''),COALESCE(session_id::text,''),remote_address,created_at,details FROM audit_events WHERE id=$1::uuid`, id).
		Scan(&event.ID, &event.EventType, &event.ActorUserID, &event.SubjectUserID, &event.SessionID, &event.RemoteAddress, &event.CreatedAt, &details)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuditEvent{}, ErrAuditEventNotFound
	}
	if err != nil {
		return AuditEvent{}, fmt.Errorf("read audit event: %w", err)
	}
	if len(details) > 0 {
		if err := json.Unmarshal(details, &event.Details); err != nil {
			return AuditEvent{}, fmt.Errorf("decode audit details: %w", err)
		}
	}
	return event, nil
}

// LogoutGrant reports the state of one global-logout attempt. A logout that
// never completes leaves relying-party sessions alive, and until now that
// state was written but never readable.
type LogoutGrant struct {
	ID              string
	SubjectID       string
	ManagedClientID string
	CreatedAt       time.Time
	ConsumedAt      *time.Time
	CompletedAt     *time.Time
	CleanupAfter    *time.Time
	CleanupAttempts int
	LastError       string
}

// ListLogoutGrants reports logout attempts newest first. When onlyOutstanding
// is set it reports only those that have not completed, which is the set an
// operator investigating a stuck sign-out needs.
func (s *Store) ListLogoutGrants(ctx context.Context, onlyOutstanding bool, page Page) ([]LogoutGrant, int, error) {
	page = page.normalized()
	where := "TRUE"
	if onlyOutstanding {
		where = "completed_at IS NULL"
	}
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM logout_correlation_grants WHERE `+where).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count logout grants: %w", err)
	}
	rows, err := s.pool.Query(ctx, `SELECT id::text,subject_id::text,COALESCE(managed_client_id,''),created_at,consumed_at,completed_at,cleanup_after,cleanup_attempts,COALESCE(last_error,'')
	FROM logout_correlation_grants WHERE `+where+` ORDER BY created_at DESC, id LIMIT $1 OFFSET $2`, page.Limit, page.Offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list logout grants: %w", err)
	}
	defer rows.Close()
	var grants []LogoutGrant
	for rows.Next() {
		var grant LogoutGrant
		if err := rows.Scan(&grant.ID, &grant.SubjectID, &grant.ManagedClientID, &grant.CreatedAt, &grant.ConsumedAt,
			&grant.CompletedAt, &grant.CleanupAfter, &grant.CleanupAttempts, &grant.LastError); err != nil {
			return nil, 0, fmt.Errorf("scan logout grant: %w", err)
		}
		grants = append(grants, grant)
	}
	return grants, total, rows.Err()
}

// SessionDetail is one browser session with the provider sessions correlated
// to it. A sign-in that cannot be correlated is the usual cause of a stuck
// login, and the correlation was previously invisible.
type SessionDetail struct {
	Session         Session
	User            User
	HydraSessionIDs []string
}

// SessionByID reads one session with its account and provider correlation.
func (s *Store) SessionByID(ctx context.Context, sessionID string) (SessionDetail, error) {
	var detail SessionDetail
	err := s.pool.QueryRow(ctx, `SELECT id::text,user_id::text,created_at,last_seen_at,expires_at,revoked_at,user_agent,remote_address FROM sessions WHERE id=$1::uuid`, sessionID).
		Scan(&detail.Session.ID, &detail.Session.UserID, &detail.Session.CreatedAt, &detail.Session.LastSeen,
			&detail.Session.ExpiresAt, &detail.Session.RevokedAt, &detail.Session.UserAgent, &detail.Session.RemoteIP)
	if errors.Is(err, pgx.ErrNoRows) {
		return SessionDetail{}, ErrSessionNotFound
	}
	if err != nil {
		return SessionDetail{}, fmt.Errorf("read session: %w", err)
	}
	policy, err := s.SessionPolicy(ctx)
	if err != nil {
		return SessionDetail{}, err
	}
	now := time.Now().UTC()
	detail.Session.Active = detail.Session.RevokedAt == nil && detail.Session.ExpiresAt.After(now) &&
		detail.Session.LastSeen.After(now.Add(-policy.BrowserIdleTimeout))
	if detail.User, err = s.UserByID(ctx, detail.Session.UserID); err != nil {
		return SessionDetail{}, err
	}
	if detail.HydraSessionIDs, err = s.HydraLoginSessionIDs(ctx, sessionID); err != nil {
		return SessionDetail{}, err
	}
	// An empty correlation is a list with nothing in it, not an absent one:
	// a consumer should not have to special-case null.
	if detail.HydraSessionIDs == nil {
		detail.HydraSessionIDs = []string{}
	}
	return detail, nil
}
