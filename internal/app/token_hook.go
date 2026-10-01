// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"

	"github.com/e6qu/shauth/internal/identity"
	"github.com/e6qu/shauth/internal/observe"
)

// hydraTokenHookRequest is the part of Ory Hydra's token hook body Shauth
// reads: who the token is for, and the claims Hydra already holds for it.
type hydraTokenHookRequest struct {
	Session struct {
		IDToken struct {
			Subject string `json:"subject"`
			Claims  struct {
				Subject string         `json:"sub"`
				Extra   map[string]any `json:"ext"`
			} `json:"id_token_claims"`
		} `json:"id_token"`
		Extra map[string]any `json:"extra"`
	} `json:"session"`
}

// hydraTokenHook answers Ory Hydra before it issues any token, including
// every refresh. Claims accepted at consent would otherwise ride along each
// refresh for as long as the refresh token lives, so the account is read
// again here: a disabled or deleted account gets no new token, and a new
// token carries the account's current role and email. Anything that stops
// this answer stops the token, because Hydra refuses to issue one when the
// hook fails.
func (s *Server) hydraTokenHook(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !bearerTokenMatches(r, s.config.TokenHookToken) {
		unauthorized(w, "token hook authentication failed")
		return
	}
	var request hydraTokenHookRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request); err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid token hook request")
		return
	}
	subject := request.Session.IDToken.Claims.Subject
	if subject == "" {
		subject = request.Session.IDToken.Subject
	}
	if subject == "" {
		// A client-credentials grant acts for the client, not a person;
		// there is no account to read again.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !uuidPathPattern.MatchString(subject) {
		writeAdminAPIError(w, http.StatusForbidden, "the token's subject is not a Shauth account")
		return
	}
	user, err := s.store.UserByID(r.Context(), subject)
	if errors.Is(err, identity.ErrUserNotFound) || (err == nil && user.DisabledAt != nil) {
		writeAdminAPIError(w, http.StatusForbidden, "the account is disabled or no longer exists")
		return
	}
	if err != nil {
		observe.Errorf("token hook: read account %s: %v", subject, err)
		writeAdminAPIError(w, http.StatusInternalServerError, "the account could not be read")
		return
	}
	// Hydra replaces both claim sets with what this returns, and its own
	// entries, such as the login session's sid that back-channel logout
	// relies on, live in the same maps; they are carried over and only the
	// identity claims Shauth owns are replaced.
	claims := oidcIdentityClaims(user)
	accessToken := maps.Clone(request.Session.Extra)
	if accessToken == nil {
		accessToken = map[string]any{}
	}
	idToken := maps.Clone(request.Session.IDToken.Claims.Extra)
	if idToken == nil {
		idToken = map[string]any{}
	}
	maps.Copy(accessToken, claims)
	maps.Copy(idToken, claims)
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"session": map[string]any{"access_token": accessToken, "id_token": idToken},
	})
}
