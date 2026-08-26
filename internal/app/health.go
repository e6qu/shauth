// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"time"

	"github.com/e6qu/shauth/internal/identity"
)

// Health statuses. A dependency is unhealthy when the service cannot do its
// job without it, and degraded when the service still works but something an
// operator must fix has drifted.
const (
	healthHealthy   = "healthy"
	healthDegraded  = "degraded"
	healthUnhealthy = "unhealthy"
)

// healthCheck is one dependency or invariant and what it reported.
type healthCheck struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
	LatencyMS *int64 `json:"latency_ms,omitempty"`
}

// deepHealth verifies every dependency and startup invariant on demand, so an
// operator can tell a database outage from provider drift without reading
// logs. The shallow /healthz probe answers the container scheduler; this
// answers the human.
func (s *Server) deepHealth(ctx context.Context) (string, []healthCheck) {
	checks := []healthCheck{
		s.timedCheck(ctx, "postgresql", func(ctx context.Context) (string, string) {
			if err := s.store.Ping(ctx); err != nil {
				return healthUnhealthy, "the session store did not answer"
			}
			return healthHealthy, ""
		}),
		s.timedCheck(ctx, "hydra_public", func(ctx context.Context) (string, string) {
			if !hydraEndpointReady(ctx, s.httpClient, s.config.HydraPublicURL) {
				return healthUnhealthy, "the authorization provider public endpoint is not ready"
			}
			return healthHealthy, ""
		}),
		s.timedCheck(ctx, "hydra_admin", func(ctx context.Context) (string, string) {
			if !hydraEndpointReady(ctx, s.httpClient, s.config.HydraAdminURL) {
				return healthUnhealthy, "the authorization provider administration endpoint is not ready"
			}
			return healthHealthy, ""
		}),
		s.timedCheck(ctx, "session_policy", func(ctx context.Context) (string, string) {
			if _, err := s.store.SessionPolicy(ctx); err != nil {
				return healthUnhealthy, "the durable session policy could not be read"
			}
			return healthHealthy, ""
		}),
		s.timedCheck(ctx, "oauth_clients", func(ctx context.Context) (string, string) {
			if _, err := s.hydraClients(ctx); err != nil {
				return healthUnhealthy, "the OAuth client catalog could not be listed"
			}
			return healthHealthy, ""
		}),
		s.timedCheck(ctx, "managed_app_registration", s.checkManagedAppRegistration),
		s.timedCheck(ctx, "application_monitoring", s.checkApplicationMonitoring),
		s.timedCheck(ctx, "validation_queue", s.checkValidationQueue),
		s.timedCheck(ctx, "invitation_mailer", func(context.Context) (string, string) {
			if s.config.SESRegion == "" || s.config.InvitationEmailFrom == "" {
				return healthDegraded, "invitations cannot be sent: no mail region or sender is configured"
			}
			return healthHealthy, ""
		}),
	}
	overall := healthHealthy
	for _, check := range checks {
		if check.Status == healthUnhealthy {
			return healthUnhealthy, checks
		}
		if check.Status == healthDegraded {
			overall = healthDegraded
		}
	}
	return overall, checks
}

func (s *Server) timedCheck(ctx context.Context, name string, run func(context.Context) (string, string)) healthCheck {
	checkContext, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	started := time.Now()
	status, detail := run(checkContext)
	elapsed := time.Since(started).Milliseconds()
	return healthCheck{Name: name, Status: status, Detail: detail, LatencyMS: &elapsed}
}

// checkManagedAppRegistration reports drift between the catalog and the
// authorization provider without repairing it, so a read never changes state.
// Drift means single sign-on is already broken for that relying party.
func (s *Server) checkManagedAppRegistration(ctx context.Context) (string, string) {
	apps, err := s.store.ListManagedApps(ctx)
	if err != nil {
		return healthUnhealthy, "the application catalog could not be read"
	}
	clients, err := s.hydraClients(ctx)
	if err != nil {
		return healthUnhealthy, "the OAuth client catalog could not be listed"
	}
	registered := make(map[string]oidcClient, len(clients))
	for _, client := range clients {
		registered[client.ID] = client
	}
	for _, app := range apps {
		client, exists := registered[app.OIDCClientID]
		if !exists {
			return healthUnhealthy, fmt.Sprintf("application %q references OAuth client %q, which is not registered", app.Slug, app.OIDCClientID)
		}
		if err := validateManagedAppClient(app, client); err != nil {
			return healthUnhealthy, fmt.Sprintf("application %q registration no longer satisfies its contract: %v", app.Slug, err)
		}
		if app.OIDCContractHash != oidcClientContractHash(client) {
			return healthDegraded, fmt.Sprintf("application %q registration changed since it was recorded and needs reconciling", app.Slug)
		}
	}
	return healthHealthy, ""
}

// checkValidationQueue reports a queue that has stopped draining. Browser
// checks run one at a time, so a queue that never advances silently stops
// proving that single sign-on works.
func (s *Server) checkValidationQueue(ctx context.Context) (string, string) {
	metrics, err := s.store.Metrics(ctx, time.Now())
	if err != nil {
		return healthUnhealthy, "the validation queue could not be measured"
	}
	if metrics.Validations.OldestQueuedSeconds == nil {
		return healthHealthy, ""
	}
	const stalledAfter = 30 * time.Minute
	waited := time.Duration(*metrics.Validations.OldestQueuedSeconds) * time.Second
	if waited > stalledAfter {
		return healthDegraded, fmt.Sprintf("the oldest queued application check has waited %s; the validator may not be running", waited.Round(time.Minute))
	}
	return healthHealthy, ""
}

// failedValidationSummary reports the applications whose latest check failed,
// which is the first question after a single sign-on incident.
func (s *Server) failedValidationSummary(ctx context.Context) ([]string, error) {
	runs, err := s.store.LatestAppValidationRuns(ctx)
	if err != nil {
		return nil, err
	}
	var failed []string
	for _, directions := range runs {
		for direction, run := range directions {
			if run.Status == identity.ValidationFailed {
				failed = append(failed, run.AppSlug+":"+direction)
			}
		}
	}
	return failed, nil
}
