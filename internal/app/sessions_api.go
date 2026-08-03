// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"net/http"
	"strings"
	"time"

	"github.com/e6qu/shauth/internal/identity"
	"github.com/e6qu/shauth/internal/observe"
)

// accountSessionRecord is one session with the account it belongs to. A
// listing across accounts is read to answer "who is signed in", so the name
// travels with the row rather than costing a lookup per session.
type accountSessionRecord struct {
	sessionRecord
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

// sessionsAPI reports sessions across every account. Sessions could only be
// listed one account at a time, which means an operator had to know which
// account to ask about before they could see anything -- the wrong way round
// during an incident.
func (s *Server) sessionsAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	page, err := requestedPage(r)
	if err != nil {
		writeOperationFailure(w, "list sessions", err)
		return
	}
	filter, err := requestedSessionFilter(r)
	if err != nil {
		writeOperationFailure(w, "list sessions", err)
		return
	}
	sessions, total, err := s.store.ListAllSessions(r.Context(), filter, page)
	if err != nil {
		writeOperationFailure(w, "list sessions", err)
		return
	}
	records := make([]accountSessionRecord, 0, len(sessions))
	for _, listed := range sessions {
		records = append(records, accountSessionRecord{
			sessionRecord: newSessionRecord(listed.Session),
			UserID:        listed.Session.UserID,
			Username:      listed.Username, Email: listed.Email, Role: string(listed.Role),
		})
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.sessions/v1",
		"observed_at":    time.Now().UTC(),
		"page":           pageEnvelope(page, len(records), total),
		"sessions":       records,
	})
}

// requestedSessionFilter reads the narrowing an operator asked for.
func requestedSessionFilter(r *http.Request) (identity.SessionFilter, error) {
	query := r.URL.Query()
	filter := identity.SessionFilter{UserID: strings.TrimSpace(query.Get("user_id"))}
	switch state := strings.ToLower(strings.TrimSpace(query.Get("state"))); state {
	case "", "all":
	case "active":
		filter.ActiveOnly = true
	default:
		return identity.SessionFilter{}, identity.Invalid("state must be active or all")
	}
	if raw := strings.TrimSpace(query.Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return identity.SessionFilter{}, identity.Invalid("since must be an RFC 3339 timestamp")
		}
		filter.Since = since
	}
	return filter, nil
}

// revokeUserSessionsAPI ends every session for one account. The browser
// interface could do this and the administration API could not, so an
// operator holding the write credential had to fall back to revoking one
// session at a time -- and a session created while they worked survived.
func (s *Server) revokeUserSessionsAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIWriteToken(w, r) {
		return
	}
	userID, err := s.revokeUserSessions(r.Context(), r.PathValue("id"), "", tokenActor(r))
	if err != nil {
		writeOperationFailure(w, "revoke account sessions", err)
		return
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.session-revocation/v1",
		"observed_at":    time.Now().UTC(),
		"user_id":        userID,
		"scope":          "account",
	})
}

// adminSessions is the browser view of the same listing: who is signed in
// right now, across accounts, with the control to end any of them. Sessions
// could only be seen one account at a time, so an operator had to know whose
// session to look for before they could look.
func (s *Server) adminSessions(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	page, err := requestedPage(r)
	if err != nil {
		page = identity.Page{}
	}
	filter, err := requestedSessionFilter(r)
	message := r.URL.Query().Get("error")
	if err != nil {
		_, message = describeOperationFailure("list sessions", err)
		filter = identity.SessionFilter{}
	}
	sessions, total, err := s.store.ListAllSessions(r.Context(), filter, page)
	if err != nil {
		observe.Errorf("list sessions: %v", err)
		s.failPage(w, r, http.StatusInternalServerError, "The sessions could not be listed.")
		return
	}
	state := "all"
	if filter.ActiveOnly {
		state = "active"
	}
	s.render(w, "sessions-all", s.view(r, "Signed-in sessions", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Sessions": sessions, "State": state,
		"Error": message, "Done": r.URL.Query().Get("done"),
		"Page": browserPage(r, page, len(sessions), total),
	}))
}
