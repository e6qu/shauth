// SPDX-License-Identifier: AGPL-3.0-or-later

// Observability contracts. An operator investigating an incident needs the
// durable record of what happened, the counts that show whether the service
// is healthy, and a dependency-by-dependency verdict. All three are read-only
// and answer the same versioned envelope as the rest of the API.
package app

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/e6qu/shauth/internal/identity"
	"github.com/e6qu/shauth/internal/observe"
	"github.com/e6qu/shauth/internal/version"
)

type auditEventRecord struct {
	ID            string         `json:"id"`
	EventType     string         `json:"event_type"`
	ActorUserID   string         `json:"actor_user_id,omitempty"`
	SubjectUserID string         `json:"subject_user_id,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
	RemoteAddress string         `json:"remote_address,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	Details       map[string]any `json:"details"`
}

func newAuditEventRecord(event identity.AuditEvent) auditEventRecord {
	record := auditEventRecord{
		ID: event.ID, EventType: event.EventType, ActorUserID: event.ActorUserID,
		SubjectUserID: event.SubjectUserID, SessionID: event.SessionID,
		CreatedAt: event.CreatedAt.UTC(), Details: event.Details,
	}
	if event.RemoteAddress != nil {
		record.RemoteAddress = event.RemoteAddress.String()
	}
	if record.Details == nil {
		record.Details = map[string]any{}
	}
	return record
}

// auditEventsAPI reports the durable record of security-relevant actions.
func (s *Server) auditEventsAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	page, err := requestedPage(r)
	if err != nil {
		writeOperationFailure(w, "list audit events", err)
		return
	}
	filter, err := requestedAuditFilter(r)
	if err != nil {
		writeOperationFailure(w, "list audit events", err)
		return
	}
	if subject := r.PathValue("id"); subject != "" {
		if err := requireUUID(subject, identity.ErrUserNotFound); err != nil {
			writeOperationFailure(w, "list audit events", err)
			return
		}
		filter.SubjectUserID = subject
	}
	events, total, err := s.store.ListAuditEvents(r.Context(), filter, page)
	if err != nil {
		writeOperationFailure(w, "list audit events", err)
		return
	}
	records := make([]auditEventRecord, 0, len(events))
	for _, event := range events {
		records = append(records, newAuditEventRecord(event))
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.audit-events/v1",
		"observed_at":    time.Now().UTC(),
		"page":           pageEnvelope(page, len(records), total),
		"events":         records,
	})
}

func requestedAuditFilter(r *http.Request) (identity.AuditFilter, error) {
	filter := identity.AuditFilter{
		SubjectUserID: strings.TrimSpace(r.URL.Query().Get("subject")),
		ActorUserID:   strings.TrimSpace(r.URL.Query().Get("actor")),
		EventType:     strings.TrimSpace(r.URL.Query().Get("event_type")),
	}
	for name, target := range map[string]*time.Time{"since": &filter.Since, "until": &filter.Until} {
		raw := strings.TrimSpace(r.URL.Query().Get(name))
		if raw == "" {
			continue
		}
		moment, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return identity.AuditFilter{}, identity.Invalid("%s must be an RFC 3339 timestamp", name)
		}
		*target = moment
	}
	for name, value := range map[string]string{"subject": filter.SubjectUserID, "actor": filter.ActorUserID} {
		if value != "" && !uuidPathPattern.MatchString(value) {
			return identity.AuditFilter{}, identity.Invalid("%s must be an account identifier", name)
		}
	}
	return filter, nil
}

// metricsAPI reports the counts an operator watches. Every number is read
// from PostgreSQL, so it describes what the service holds rather than what
// one process has observed since it started.
func (s *Server) metricsAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	metrics, err := s.store.Metrics(r.Context(), time.Now())
	if err != nil {
		writeOperationFailure(w, "read metrics", err)
		return
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.metrics/v1",
		"observed_at":    time.Now().UTC(),
		"build":          buildRecord(),
		"users": map[string]any{
			"total": metrics.Users.Total, "disabled": metrics.Users.Disabled,
			"by_role": metrics.Users.ByRole, "by_identity_source": metrics.Users.ByIdentitySource,
		},
		"sessions": map[string]any{
			"active": metrics.Sessions.Active, "revoked": metrics.Sessions.Revoked, "total": metrics.Sessions.Total,
		},
		"invitations": metrics.Invitations,
		"apps":        map[string]any{"total": metrics.Apps.Total},
		"app_validations": map[string]any{
			"by_status": metrics.Validations.ByStatus, "queued": metrics.Validations.Queued,
			"running": metrics.Validations.Running, "oldest_queued_seconds": metrics.Validations.OldestQueuedSeconds,
		},
		"logout_correlation": map[string]any{
			"outstanding": metrics.LogoutCorrelation.Outstanding, "retrying": metrics.LogoutCorrelation.Failed,
		},
	})
}

// requestMetricsAPI reports what this instance has actually served: which
// routes are used, which are failing, and how slow they are. Nothing else
// observes status codes, so without it a rising error rate is only visible by
// reading container logs by hand.
func (s *Server) requestMetricsAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	report := s.traffic.report()
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.request-metrics/v1",
		"observed_at":    time.Now().UTC(),
		"build":          buildRecord(),
		"traffic":        report,
	})
}

func buildRecord() map[string]any {
	return map[string]any{
		"revision": version.Revision(), "started_at": version.StartedAt(),
		"uptime_seconds": int64(time.Since(version.StartedAt()).Seconds()),
	}
}

// deepHealthAPI verifies every dependency and startup invariant on demand.
// The shallow probe answers the scheduler; this answers the operator, and
// says which dependency is at fault rather than only that something is.
func (s *Server) deepHealthAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	status, checks := s.deepHealth(r.Context())
	code := http.StatusOK
	if status == healthUnhealthy {
		code = http.StatusServiceUnavailable
	}
	payload := map[string]any{
		"schema_version": "shauth.deep-health/v1",
		"observed_at":    time.Now().UTC(),
		"status":         status,
		"build":          buildRecord(),
		"checks":         checks,
	}
	if failed, err := s.failedValidationSummary(r.Context()); err == nil && len(failed) > 0 {
		payload["failing_validations"] = failed
	}
	writeAdminAPIJSON(w, code, payload)
}

// sessionAPI reports one browser session with the provider sessions
// correlated to it. A sign-in that cannot be correlated is the usual cause of
// a stuck login, and that correlation had no read path.
func (s *Server) sessionAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	sessionID := r.PathValue("id")
	if err := requireUUID(sessionID, identity.ErrSessionNotFound); err != nil {
		writeOperationFailure(w, "read session", err)
		return
	}
	detail, err := s.store.SessionByID(r.Context(), sessionID)
	if err != nil {
		writeOperationFailure(w, "read session", err)
		return
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version":    "shauth.session/v1",
		"observed_at":       time.Now().UTC(),
		"session":           newSessionRecord(detail.Session),
		"user":              newUserRecord(detail.User),
		"oauth_session_ids": detail.HydraSessionIDs,
	})
}

type logoutGrantRecord struct {
	ID              string     `json:"id"`
	SubjectUserID   string     `json:"subject_user_id"`
	ManagedClientID string     `json:"managed_client_id,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	ConsumedAt      *time.Time `json:"consumed_at"`
	CompletedAt     *time.Time `json:"completed_at"`
	RetryAfter      *time.Time `json:"retry_after"`
	Attempts        int        `json:"cleanup_attempts"`
	LastError       string     `json:"last_error,omitempty"`
}

// logoutGrantsAPI reports global-logout attempts and why they are stuck. A
// logout that never completes leaves relying-party sessions alive, which is
// the opposite of what the person asked for.
func (s *Server) logoutGrantsAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	page, err := requestedPage(r)
	if err != nil {
		writeOperationFailure(w, "list logout grants", err)
		return
	}
	onlyOutstanding := r.URL.Query().Get("state") != "all"
	grants, total, err := s.store.ListLogoutGrants(r.Context(), onlyOutstanding, page)
	if err != nil {
		writeOperationFailure(w, "list logout grants", err)
		return
	}
	records := make([]logoutGrantRecord, 0, len(grants))
	for _, grant := range grants {
		records = append(records, logoutGrantRecord{
			ID: grant.ID, SubjectUserID: grant.SubjectID, ManagedClientID: grant.ManagedClientID,
			CreatedAt: grant.CreatedAt.UTC(), ConsumedAt: grant.ConsumedAt, CompletedAt: grant.CompletedAt,
			RetryAfter: grant.CleanupAfter, Attempts: grant.CleanupAttempts, LastError: grant.LastError,
		})
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.logout-grants/v1",
		"observed_at":    time.Now().UTC(),
		"page":           pageEnvelope(page, len(records), total),
		"outstanding":    onlyOutstanding,
		"grants":         records,
	})
}

// appAPI reports one application: its coordinates, live health, and the
// latest check in each direction. Polling one relying party should not mean
// downloading the whole catalog and probing every other app's health.
func (s *Server) appAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireApplicationReadToken(w, r) {
		return
	}
	slug := r.PathValue("slug")
	views, err := s.appViews(r.Context())
	if err != nil {
		writeOperationFailure(w, "read application", err)
		return
	}
	for _, view := range views {
		if view.Slug != slug {
			continue
		}
		writeAdminAPIJSON(w, http.StatusOK, map[string]any{
			"schema_version": "shauth.app/v1",
			"observed_at":    time.Now().UTC(),
			"app":            newAppRecord(view),
		})
		return
	}
	writeAdminAPIError(w, http.StatusNotFound, "managed app not found")
}

// mySessionsAPI lets a signed-in person see their own sessions. Until now
// only an administrator could, so nobody could check their own devices.
func (s *Server) mySessionsAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	user, current, err := s.current(r)
	if err != nil {
		writeAdminAPIError(w, http.StatusUnauthorized, "sign-in required")
		return
	}
	sessions, err := s.store.ListSessions(r.Context(), user.ID)
	if err != nil {
		writeOperationFailure(w, "list your sessions", err)
		return
	}
	records := make([]map[string]any, 0, len(sessions))
	for _, session := range sessions {
		record := map[string]any{"session": newSessionRecord(session), "current": session.ID == current.ID}
		records = append(records, record)
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.my-sessions/v1",
		"observed_at":    time.Now().UTC(),
		"user":           newUserRecord(user),
		"sessions":       records,
	})
}

// revokeMySessionAPI ends one of the caller's own sessions. It refuses any
// session that is not theirs, so this cannot become a way to end someone
// else's.
func (s *Server) revokeMySessionAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	user, session, err := s.current(r)
	if err != nil {
		writeAdminAPIError(w, http.StatusUnauthorized, "sign-in required")
		return
	}
	sessionID := r.PathValue("id")
	if err := requireUUID(sessionID, identity.ErrSessionNotFound); err != nil {
		writeOperationFailure(w, "end your session", err)
		return
	}
	owner, err := s.store.SessionUserID(r.Context(), sessionID)
	if err != nil || owner != user.ID {
		writeAdminAPIError(w, http.StatusNotFound, "session not found")
		return
	}
	if _, err := s.revokeSession(r.Context(), sessionID, browserActor(r, user, session)); err != nil {
		writeOperationFailure(w, "end your session", err)
		return
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.session-revoke/v1",
		"observed_at":    time.Now().UTC(),
		"session_id":     sessionID,
		"user_id":        user.ID,
	})
}

// account is a person's own page: the devices signed in as them, and a way to
// end any of them. An administrator could always see this for others; nobody
// could see it for themselves.
func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	user, current, err := s.current(r)
	if err != nil {
		http.Redirect(w, r, "/login?next=/account", http.StatusSeeOther)
		return
	}
	sessions, err := s.store.ListSessions(r.Context(), user.ID)
	if err != nil {
		s.failPage(w, r, http.StatusInternalServerError, "Your sessions could not be loaded.")
		return
	}
	type ownSession struct {
		sessionRecord
		Current bool
	}
	records := make([]ownSession, 0, len(sessions))
	for _, session := range sessions {
		records = append(records, ownSession{sessionRecord: newSessionRecord(session), Current: session.ID == current.ID})
	}
	s.render(w, "account", s.view(r, "Your account", map[string]any{
		"SignedIn": true, "IsAdmin": user.Role == identity.RoleAdmin, "Account": newUserRecord(user),
		"Sessions": records, "Done": r.URL.Query().Get("done"), "Error": r.URL.Query().Get("error"),
	}))
}

// revokeOwnSession ends one of the caller's own sessions from the browser.
func (s *Server) revokeOwnSession(w http.ResponseWriter, r *http.Request) {
	user, session, err := s.current(r)
	if err != nil {
		http.Redirect(w, r, "/login?next=/account", http.StatusSeeOther)
		return
	}
	sessionID := r.PathValue("id")
	owner, err := s.store.SessionUserID(r.Context(), sessionID)
	if err != nil || owner != user.ID {
		s.failPage(w, r, http.StatusNotFound, "That session does not belong to your account.")
		return
	}
	if _, err := s.revokeSession(r.Context(), sessionID, browserActor(r, user, session)); err != nil {
		s.failOperation(w, r, "end your session", "/account", err)
		return
	}
	if sessionID == session.ID {
		s.expireCookie(w, browserSessionCookie)
		http.Redirect(w, r, "/signed-out", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/account?done="+url.QueryEscape("That session was ended."), http.StatusSeeOther)
}

// adminAudit renders the same audit record the API publishes, so an operator
// without a token can still read it.
func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	page, err := requestedPage(r)
	if err != nil {
		page = identity.Page{}
	}
	filter, err := requestedAuditFilter(r)
	if err != nil {
		filter = identity.AuditFilter{}
	}
	events, total, err := s.store.ListAuditEvents(r.Context(), filter, page)
	if err != nil {
		observe.Errorf("list audit events: %v", err)
		s.failPage(w, r, http.StatusInternalServerError, "The audit record could not be loaded.")
		return
	}
	records := make([]auditEventRecord, 0, len(events))
	for _, event := range events {
		records = append(records, newAuditEventRecord(event))
	}
	s.render(w, "audit", s.view(r, "Audit record", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Events": records,
		"EventType": filter.EventType, "Page": browserPage(r, page, len(records), total),
	}))
}
