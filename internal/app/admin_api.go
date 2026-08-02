// SPDX-License-Identifier: AGPL-3.0-or-later

// Token-authorized administration API. Every surface of the signed-in HTMX
// administration interface is also reachable as a versioned, machine-readable
// contract so operators and agents can inspect and drive Shauth without a
// browser session. Reads live under /api/v1/ behind the dedicated read
// credential; state changes live under /internal/ behind the distinct write
// credential, because bearer-token requests carry no browser CSRF token.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/e6qu/shauth/internal/identity"
	"github.com/e6qu/shauth/internal/monitoring"
)

var uuidPathPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// requireAdminAPIReadToken authorizes the closed machine-readable
// administration reads with the dedicated read-only bearer credential.
func (s *Server) requireAdminAPIReadToken(w http.ResponseWriter, r *http.Request) bool {
	if s.config.AdminAPIReadToken == "" {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "administration API reads are not configured")
		return false
	}
	if !bearerTokenMatches(r, s.config.AdminAPIReadToken) {
		writeAdminAPIError(w, http.StatusUnauthorized, "administration API authentication failed")
		return false
	}
	return true
}

// requireAdminAPIWriteToken authorizes token-driven administration writes
// with the write credential, which is distinct from the read credential so a
// read-only consumer never holds a state-changing secret.
func (s *Server) requireAdminAPIWriteToken(w http.ResponseWriter, r *http.Request) bool {
	if s.config.AdminAPIWriteToken == "" {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "administration API writes are not configured")
		return false
	}
	if !bearerTokenMatches(r, s.config.AdminAPIWriteToken) {
		writeAdminAPIError(w, http.StatusUnauthorized, "administration API authentication failed")
		return false
	}
	return true
}

func writeAdminAPIJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeAdminAPIError(w http.ResponseWriter, status int, message string) {
	writeAdminAPIJSON(w, status, map[string]string{"error": message})
}

type userRecord struct {
	ID             string     `json:"id"`
	Username       string     `json:"username"`
	Email          string     `json:"email"`
	EmailVerified  bool       `json:"email_verified"`
	IdentitySource string     `json:"identity_source"`
	GitHubLogin    string     `json:"github_login,omitempty"`
	Role           string     `json:"role"`
	DisabledAt     *time.Time `json:"disabled_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// newUserRecord reports only the identity source the store resolved. It never
// guesses: publishing "local" for a federated account would misrepresent how
// the account authenticates.
func newUserRecord(user identity.User) userRecord {
	return userRecord{
		ID: user.ID, Username: user.Username, Email: user.Email, EmailVerified: user.EmailVerified,
		IdentitySource: user.IdentitySource, GitHubLogin: user.GitHubLogin, Role: string(user.Role),
		DisabledAt: user.DisabledAt, CreatedAt: user.CreatedAt,
	}
}

// writeAdminAPIStoreError separates a rejected request from a failed
// dependency: invalid input answers 400 with the store's message, a
// uniqueness conflict answers 409, and anything else is logged and answered
// generically so internal database detail never reaches the caller.
func writeAdminAPIStoreError(w http.ResponseWriter, action string, err error) {
	var invalid identity.InvalidInputError
	switch {
	case errors.As(err, &invalid):
		writeAdminAPIError(w, http.StatusBadRequest, invalid.Error())
	case errors.Is(err, identity.ErrAlreadyExists):
		writeAdminAPIError(w, http.StatusConflict, action+" already exists")
	default:
		log.Printf("%s: %v", action, err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not complete the request")
	}
}

func (s *Server) usersAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	users, err := s.store.ListUsers(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		log.Printf("list users: %v", err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not list users")
		return
	}
	records := make([]userRecord, 0, len(users))
	for _, user := range users {
		records = append(records, newUserRecord(user))
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.users/v1",
		"observed_at":    time.Now().UTC(),
		"users":          records,
	})
}

type sessionRecord struct {
	ID            string     `json:"id"`
	CreatedAt     time.Time  `json:"created_at"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	UserAgent     string     `json:"user_agent"`
	RemoteAddress string     `json:"remote_address,omitempty"`
	Active        bool       `json:"active"`
}

func newSessionRecord(session identity.Session) sessionRecord {
	record := sessionRecord{
		ID: session.ID, CreatedAt: session.CreatedAt, LastSeenAt: session.LastSeen,
		ExpiresAt: session.ExpiresAt, RevokedAt: session.RevokedAt,
		UserAgent: session.UserAgent, Active: session.Active,
	}
	if session.RemoteIP != nil {
		record.RemoteAddress = session.RemoteIP.String()
	}
	return record
}

func (s *Server) userSessionsAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	userID := r.PathValue("id")
	if !uuidPathPattern.MatchString(userID) {
		writeAdminAPIError(w, http.StatusNotFound, "user not found")
		return
	}
	user, err := s.store.UserByID(r.Context(), userID)
	if errors.Is(err, identity.ErrUserNotFound) {
		writeAdminAPIError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		log.Printf("read user %s: %v", userID, err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not read user")
		return
	}
	sessions, err := s.store.ListSessions(r.Context(), userID)
	if err != nil {
		log.Printf("list sessions for user %s: %v", userID, err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not list sessions")
		return
	}
	records := make([]sessionRecord, 0, len(sessions))
	for _, session := range sessions {
		records = append(records, newSessionRecord(session))
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.user-sessions/v1",
		"observed_at":    time.Now().UTC(),
		"user":           newUserRecord(user),
		"sessions":       records,
	})
}

// sessionPolicyRecord carries the durable session policy in the same
// operator-facing units as the administration form.
type sessionPolicyRecord struct {
	BrowserAbsoluteHours int64 `json:"browser_absolute_hours"`
	BrowserIdleMinutes   int64 `json:"browser_idle_minutes"`
	OIDCSSOHours         int64 `json:"oidc_sso_hours"`
	AccessTokenMinutes   int64 `json:"access_token_minutes"`
	IDTokenMinutes       int64 `json:"id_token_minutes"`
	RefreshTokenHours    int64 `json:"refresh_token_hours"`
}

func newSessionPolicyRecord(policy identity.SessionPolicy) sessionPolicyRecord {
	return sessionPolicyRecord{
		BrowserAbsoluteHours: int64(policy.BrowserAbsoluteLifetime / time.Hour),
		BrowserIdleMinutes:   int64(policy.BrowserIdleTimeout / time.Minute),
		OIDCSSOHours:         int64(policy.OIDCSessionLifetime / time.Hour),
		AccessTokenMinutes:   int64(policy.AccessTokenLifetime / time.Minute),
		IDTokenMinutes:       int64(policy.IDTokenLifetime / time.Minute),
		RefreshTokenHours:    int64(policy.RefreshTokenLifetime / time.Hour),
	}
}

func (record sessionPolicyRecord) sessionPolicy() (identity.SessionPolicy, error) {
	parse := func(name string, value int64, unit time.Duration) (time.Duration, error) {
		if value <= 0 {
			return 0, fmt.Errorf("%s must be a positive whole number", strings.ReplaceAll(name, "_", " "))
		}
		if value > int64((90*24*time.Hour)/unit) {
			return 0, fmt.Errorf("%s exceeds the maximum supported duration", strings.ReplaceAll(name, "_", " "))
		}
		return time.Duration(value) * unit, nil
	}
	var policy identity.SessionPolicy
	var err error
	if policy.BrowserAbsoluteLifetime, err = parse("browser_absolute_hours", record.BrowserAbsoluteHours, time.Hour); err != nil {
		return identity.SessionPolicy{}, err
	}
	if policy.BrowserIdleTimeout, err = parse("browser_idle_minutes", record.BrowserIdleMinutes, time.Minute); err != nil {
		return identity.SessionPolicy{}, err
	}
	if policy.OIDCSessionLifetime, err = parse("oidc_sso_hours", record.OIDCSSOHours, time.Hour); err != nil {
		return identity.SessionPolicy{}, err
	}
	if policy.AccessTokenLifetime, err = parse("access_token_minutes", record.AccessTokenMinutes, time.Minute); err != nil {
		return identity.SessionPolicy{}, err
	}
	if policy.IDTokenLifetime, err = parse("id_token_minutes", record.IDTokenMinutes, time.Minute); err != nil {
		return identity.SessionPolicy{}, err
	}
	if policy.RefreshTokenLifetime, err = parse("refresh_token_hours", record.RefreshTokenHours, time.Hour); err != nil {
		return identity.SessionPolicy{}, err
	}
	if err := policy.Validate(); err != nil {
		return identity.SessionPolicy{}, err
	}
	return policy, nil
}

func (s *Server) sessionPolicyAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	policy, err := s.store.SessionPolicy(r.Context())
	if err != nil {
		log.Printf("read session policy: %v", err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not load session policy")
		return
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.session-policy/v1",
		"observed_at":    time.Now().UTC(),
		"policy":         newSessionPolicyRecord(policy),
	})
}

// updateSessionPolicyAPI is the token-authorized twin of the session policy
// form: it validates the requested lifetimes, applies them to every Ory Hydra
// client, and persists them, restoring the previous policy if either the
// provider or PostgreSQL update fails.
func (s *Server) updateSessionPolicyAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIWriteToken(w, r) {
		return
	}
	var request sessionPolicyRecord
	if err := decodeSingleJSONBody(http.MaxBytesReader(w, r.Body, 4*1024), &request); err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid session policy request")
		return
	}
	policy, err := request.sessionPolicy()
	if err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	previous, err := s.store.SessionPolicy(r.Context())
	if err != nil {
		log.Printf("load current session policy: %v", err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not load current session policy")
		return
	}
	if err := s.applyHydraSessionPolicy(r.Context(), policy); err != nil {
		if rollbackErr := s.applyHydraSessionPolicy(r.Context(), previous); rollbackErr != nil {
			log.Printf("restore Ory Hydra session policy after client update failed: %v", rollbackErr)
		}
		log.Printf("apply Ory Hydra session policy: %v", err)
		writeAdminAPIError(w, http.StatusBadGateway, "could not update OAuth client lifetimes")
		return
	}
	if err := s.store.UpdateSessionPolicy(r.Context(), policy, time.Now()); err != nil {
		if rollbackErr := s.applyHydraSessionPolicy(r.Context(), previous); rollbackErr != nil {
			log.Printf("restore Ory Hydra session policy after PostgreSQL update failed: %v", rollbackErr)
		}
		log.Printf("save session policy: %v", err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not save session policy")
		return
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.session-policy/v1",
		"observed_at":    time.Now().UTC(),
		"policy":         newSessionPolicyRecord(policy),
	})
}

func (s *Server) oidcClientsAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	clients, err := s.hydraClients(r.Context())
	if err != nil {
		log.Printf("list OAuth clients: %v", err)
		writeAdminAPIError(w, http.StatusBadGateway, "could not query OAuth clients")
		return
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].ID < clients[j].ID })
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.oidc-clients/v1",
		"observed_at":    time.Now().UTC(),
		"clients":        clients,
	})
}

type oidcClientCreateRequest struct {
	ClientID               string   `json:"client_id"`
	ClientName             string   `json:"client_name"`
	ClientSecret           string   `json:"client_secret"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	FrontchannelLogoutURI  string   `json:"frontchannel_logout_uri"`
	BackchannelLogoutURI   string   `json:"backchannel_logout_uri"`
}

func (s *Server) createOIDCClientAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIWriteToken(w, r) {
		return
	}
	var request oidcClientCreateRequest
	if err := decodeSingleJSONBody(http.MaxBytesReader(w, r.Body, 16*1024), &request); err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid OAuth client request")
		return
	}
	input := oidcClientInput{
		ID:                    strings.TrimSpace(request.ClientID),
		Name:                  strings.TrimSpace(request.ClientName),
		Secret:                request.ClientSecret,
		FrontChannelLogoutURI: strings.TrimSpace(request.FrontchannelLogoutURI),
		BackChannelLogoutURI:  strings.TrimSpace(request.BackchannelLogoutURI),
	}
	for _, rawURI := range request.RedirectURIs {
		if uri := strings.TrimSpace(rawURI); uri != "" {
			input.RedirectURIs = append(input.RedirectURIs, uri)
		}
	}
	for _, rawURI := range request.PostLogoutRedirectURIs {
		if uri := strings.TrimSpace(rawURI); uri != "" {
			input.PostLogoutRedirectURIs = append(input.PostLogoutRedirectURIs, uri)
		}
	}
	if err := input.validate(); err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.createHydraClient(r.Context(), input); err != nil {
		if errors.Is(err, errHydraClientConflict) {
			writeAdminAPIError(w, http.StatusConflict, "OAuth client already exists")
			return
		}
		log.Printf("create OAuth client %s: %v", input.ID, err)
		writeAdminAPIError(w, http.StatusBadGateway, "could not create OAuth client")
		return
	}
	client := registeredOIDCClient(input)
	client.Name = input.Name
	writeAdminAPIJSON(w, http.StatusCreated, map[string]any{
		"schema_version": "shauth.oidc-client/v1",
		"client":         client,
	})
}

func (s *Server) deleteOIDCClientAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIWriteToken(w, r) {
		return
	}
	clientID := r.PathValue("id")
	if !deletableOIDCClientID(clientID) {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid client ID")
		return
	}
	used, err := s.store.ManagedAppUsesOIDCClient(r.Context(), clientID)
	if err != nil {
		log.Printf("verify connected apps for client %s: %v", clientID, err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not verify connected apps")
		return
	}
	if used {
		writeAdminAPIError(w, http.StatusConflict, "delete the connected app before deleting its OAuth client")
		return
	}
	if err := s.deleteHydraClient(r.Context(), clientID); err != nil {
		if errors.Is(err, errHydraClientNotFound) {
			writeAdminAPIError(w, http.StatusNotFound, "OAuth client not found")
			return
		}
		log.Printf("delete OAuth client %s: %v", clientID, err)
		writeAdminAPIError(w, http.StatusBadGateway, "could not delete OAuth client")
		return
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.oidc-client-delete/v1",
		"client_id":      clientID,
	})
}

type githubRoleMappingRecord struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Target    string    `json:"target"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

func newGitHubRoleMappingRecord(mapping identity.GitHubRoleMapping) githubRoleMappingRecord {
	return githubRoleMappingRecord{
		ID: mapping.ID, Kind: mapping.Kind, Target: mapping.Target,
		Role: string(mapping.Role), CreatedAt: mapping.CreatedAt,
	}
}

func (s *Server) githubMappingsAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	mappings, err := s.store.ListGitHubRoleMappings(r.Context())
	if err != nil {
		log.Printf("list GitHub role mappings: %v", err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not query GitHub role mappings")
		return
	}
	records := make([]githubRoleMappingRecord, 0, len(mappings))
	for _, mapping := range mappings {
		records = append(records, newGitHubRoleMappingRecord(mapping))
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.github-role-mappings/v1",
		"observed_at":    time.Now().UTC(),
		"mappings":       records,
	})
}

type githubRoleMappingCreateRequest struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Role   string `json:"role"`
}

func (s *Server) createGitHubMappingAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIWriteToken(w, r) {
		return
	}
	var request githubRoleMappingCreateRequest
	if err := decodeSingleJSONBody(http.MaxBytesReader(w, r.Body, 4*1024), &request); err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid GitHub role mapping request")
		return
	}
	mapping, err := s.store.CreateGitHubRoleMapping(r.Context(), request.Kind, request.Target, identity.Role(request.Role))
	if err != nil {
		writeAdminAPIStoreError(w, "create GitHub role mapping", err)
		return
	}
	writeAdminAPIJSON(w, http.StatusCreated, map[string]any{
		"schema_version": "shauth.github-role-mapping/v1",
		"mapping":        newGitHubRoleMappingRecord(mapping),
	})
}

func (s *Server) deleteGitHubMappingAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIWriteToken(w, r) {
		return
	}
	mappingID := r.PathValue("id")
	if !uuidPathPattern.MatchString(mappingID) {
		writeAdminAPIError(w, http.StatusNotFound, "GitHub role mapping not found")
		return
	}
	if err := s.store.DeleteGitHubRoleMapping(r.Context(), mappingID); err != nil {
		if errors.Is(err, identity.ErrGitHubRoleMappingNotFound) {
			writeAdminAPIError(w, http.StatusNotFound, "GitHub role mapping not found")
			return
		}
		log.Printf("delete GitHub role mapping %s: %v", mappingID, err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not delete GitHub role mapping")
		return
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.github-role-mapping-delete/v1",
		"id":             mappingID,
	})
}

func (s *Server) connectorsAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	github := map[string]any{"enabled": s.oauth != nil}
	if s.oauth != nil {
		github["admin_team"] = s.config.GitHubAdminTeam
		github["developer_team"] = s.config.GitHubDeveloperTeam
	}
	entra := map[string]any{"enabled": s.entraOAuth != nil}
	if s.entraOAuth != nil {
		entra["tenant_id"] = s.config.EntraTenantID
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.connectors/v1",
		"observed_at":    time.Now().UTC(),
		"github":         github,
		"entra":          entra,
	})
}

type monitoringSourceRecord struct {
	Source   string               `json:"source"`
	Stale    bool                 `json:"stale"`
	Error    string               `json:"error,omitempty"`
	Snapshot *monitoring.Snapshot `json:"snapshot,omitempty"`
}

// monitoringAPI publishes the same operational snapshot as the monitoring
// page: active Shauth sessions, PostgreSQL and Ory Hydra health, and every
// configured deployment-neutral infrastructure observation.
func (s *Server) monitoringAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	checkContext, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	postgresHealthy := s.store.Ping(checkContext) == nil
	cancel()
	// The session count needs PostgreSQL, so it is reported as null rather
	// than failing the response: this contract exists to report a database
	// outage, and must not go dark during one.
	var active *int
	if postgresHealthy {
		if counted, err := s.store.CountActiveSessions(r.Context(), time.Now()); err != nil {
			log.Printf("count active sessions: %v", err)
		} else {
			active = &counted
		}
	}
	results := s.monitoringClient.FetchAll(r.Context(), s.config.MonitoringSources)
	records := make([]monitoringSourceRecord, 0, len(results))
	for _, result := range results {
		record := monitoringSourceRecord{Source: result.SourceName, Stale: result.Stale, Error: result.Error}
		if result.Error == "" {
			snapshot := result.Snapshot
			record.Snapshot = &snapshot
		}
		records = append(records, record)
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version":     "shauth.monitoring/v1",
		"observed_at":        time.Now().UTC(),
		"active_sessions":    active,
		"postgresql_healthy": postgresHealthy,
		"hydra_healthy":      s.hydraReady(r.Context()),
		"infrastructure":     records,
	})
}

type userCreateRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (s *Server) createUserAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIWriteToken(w, r) {
		return
	}
	var request userCreateRequest
	if err := decodeSingleJSONBody(http.MaxBytesReader(w, r.Body, 4*1024), &request); err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid user request")
		return
	}
	user, err := s.store.CreatePasswordUser(r.Context(), request.Username, request.Email, request.Password, identity.Role(request.Role))
	if err != nil {
		writeAdminAPIStoreError(w, "create user", err)
		return
	}
	writeAdminAPIJSON(w, http.StatusCreated, map[string]any{
		"schema_version": "shauth.user/v1",
		"user":           newUserRecord(user),
	})
}

// disableUserAPI contains an account: it ends every browser session, revokes
// the correlated Ory Hydra login sessions, and marks the account disabled so
// the credential cannot simply sign in again. Session revocation alone is not
// containment.
func (s *Server) disableUserAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIWriteToken(w, r) {
		return
	}
	userID := r.PathValue("id")
	if !uuidPathPattern.MatchString(userID) {
		writeAdminAPIError(w, http.StatusNotFound, "user not found")
		return
	}
	hydraSessionIDs, err := s.store.DisableUser(r.Context(), userID, time.Now())
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrUserNotFound):
			writeAdminAPIError(w, http.StatusNotFound, "user not found")
		case errors.Is(err, identity.ErrValidationUserProtected):
			writeAdminAPIError(w, http.StatusConflict, err.Error())
		default:
			log.Printf("disable account %s: %v", userID, err)
			writeAdminAPIError(w, http.StatusInternalServerError, "could not disable the account")
		}
		return
	}
	for _, hydraSessionID := range hydraSessionIDs {
		if err := s.revokeHydraLoginSession(r.Context(), hydraSessionID); err != nil {
			log.Printf("revoke Ory Hydra session while disabling account %s: %v", userID, err)
			writeAdminAPIError(w, http.StatusBadGateway, "account disabled and local sessions ended, but OAuth session revocation did not complete")
			return
		}
	}
	if err := s.revokeHydraSubjectSessions(r.Context(), userID); err != nil {
		log.Printf("revoke Ory Hydra subject sessions while disabling account %s: %v", userID, err)
		writeAdminAPIError(w, http.StatusBadGateway, "account disabled and local sessions ended, but OAuth session revocation did not complete")
		return
	}
	user, err := s.store.UserByID(r.Context(), userID)
	if err != nil {
		log.Printf("read disabled account %s: %v", userID, err)
		writeAdminAPIError(w, http.StatusInternalServerError, "the account was disabled but could not be read back")
		return
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.user/v1",
		"user":           newUserRecord(user),
	})
}

// enableUserAPI restores a disabled account. It grants no session; the
// account holder must authenticate again.
func (s *Server) enableUserAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIWriteToken(w, r) {
		return
	}
	userID := r.PathValue("id")
	if !uuidPathPattern.MatchString(userID) {
		writeAdminAPIError(w, http.StatusNotFound, "user not found")
		return
	}
	if err := s.store.EnableUser(r.Context(), userID, time.Now()); err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			writeAdminAPIError(w, http.StatusNotFound, "user not found")
			return
		}
		log.Printf("enable account %s: %v", userID, err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not enable the account")
		return
	}
	user, err := s.store.UserByID(r.Context(), userID)
	if err != nil {
		log.Printf("read enabled account %s: %v", userID, err)
		writeAdminAPIError(w, http.StatusInternalServerError, "the account was enabled but could not be read back")
		return
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.user/v1",
		"user":           newUserRecord(user),
	})
}

type invitationRecord struct {
	ID         string     `json:"id"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	State      string     `json:"state"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	InvitedBy  string     `json:"invited_by,omitempty"`
}

func newInvitationRecord(invitation identity.Invitation) invitationRecord {
	return invitationRecord{
		ID: invitation.ID, Email: invitation.Email, Role: string(invitation.Role),
		State: invitation.State, CreatedAt: invitation.CreatedAt, ExpiresAt: invitation.ExpiresAt,
		AcceptedAt: invitation.AcceptedAt, RevokedAt: invitation.RevokedAt, InvitedBy: invitation.InvitedBy,
	}
}

// invitationsAPI lists every invitation and its state. The single-use token
// is stored only as a hash and is never returned.
func (s *Server) invitationsAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	invitations, err := s.store.ListInvitations(r.Context(), time.Now())
	if err != nil {
		log.Printf("list invitations: %v", err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not list invitations")
		return
	}
	records := make([]invitationRecord, 0, len(invitations))
	for _, invitation := range invitations {
		records = append(records, newInvitationRecord(invitation))
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.invitations/v1",
		"observed_at":    time.Now().UTC(),
		"invitations":    records,
	})
}

// revokeInvitationAPI withdraws an unaccepted invitation so a link sent to
// the wrong address can no longer create an account.
func (s *Server) revokeInvitationAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIWriteToken(w, r) {
		return
	}
	invitationID := r.PathValue("id")
	if !uuidPathPattern.MatchString(invitationID) {
		writeAdminAPIError(w, http.StatusNotFound, "active invitation not found")
		return
	}
	if err := s.store.RevokeInvitation(r.Context(), invitationID, time.Now()); err != nil {
		if errors.Is(err, identity.ErrInvitationNotRevocable) {
			writeAdminAPIError(w, http.StatusNotFound, "active invitation not found")
			return
		}
		log.Printf("revoke invitation %s: %v", invitationID, err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not revoke the invitation")
		return
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.invitation-revoke/v1",
		"id":             invitationID,
	})
}

type invitationCreateRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// createInvitationAPI is the token-authorized twin of the invitation form.
// The invitation link is delivered only through the invitation email; it is
// never returned to the API caller. Token-created invitations record no
// inviting user.
func (s *Server) createInvitationAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIWriteToken(w, r) {
		return
	}
	var request invitationCreateRequest
	if err := decodeSingleJSONBody(http.MaxBytesReader(w, r.Body, 4*1024), &request); err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid invitation request")
		return
	}
	raw, invitation, err := s.store.CreateInvitation(r.Context(), request.Email, identity.Role(request.Role), "", time.Now())
	if err != nil {
		writeAdminAPIStoreError(w, "create invitation", err)
		return
	}
	link := s.config.PublicURL.ResolveReference(&url.URL{Path: "/accept-invitation", RawQuery: "token=" + url.QueryEscape(raw)}).String()
	if err := s.mailer.SendInvitation(r.Context(), invitation.Email, link); err != nil {
		if revokeErr := s.store.RevokeInvitation(r.Context(), invitation.ID, time.Now()); revokeErr != nil {
			log.Printf("revoke unsent invitation %s: %v", invitation.ID, revokeErr)
		}
		log.Printf("send invitation to %s: %v", invitation.Email, err)
		writeAdminAPIError(w, http.StatusBadGateway, "invitation email could not be sent")
		return
	}
	writeAdminAPIJSON(w, http.StatusCreated, map[string]any{
		"schema_version": "shauth.invitation/v1",
		"invitation":     newInvitationRecord(invitation),
	})
}

// revokeSessionAPI is the token-authorized twin of the per-session "Revoke"
// button: it ends one browser session and revokes its correlated Ory Hydra
// login sessions. POST /internal/sessions/reset remains the whole-user reset.
func (s *Server) revokeSessionAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIWriteToken(w, r) {
		return
	}
	sessionID := r.PathValue("id")
	if !uuidPathPattern.MatchString(sessionID) {
		writeAdminAPIError(w, http.StatusNotFound, "session not found")
		return
	}
	userID, err := s.store.SessionUserID(r.Context(), sessionID)
	if errors.Is(err, identity.ErrSessionNotFound) {
		writeAdminAPIError(w, http.StatusNotFound, "session not found")
		return
	}
	if err != nil {
		log.Printf("read session %s: %v", sessionID, err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not read session")
		return
	}
	if err := s.store.RevokeSession(r.Context(), sessionID, time.Now()); err != nil {
		if errors.Is(err, identity.ErrActiveSessionNotFound) {
			writeAdminAPIError(w, http.StatusConflict, "session is already revoked")
			return
		}
		log.Printf("revoke session %s: %v", sessionID, err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not revoke session")
		return
	}
	hydraSessionIDs, err := s.store.HydraLoginSessionIDs(r.Context(), sessionID)
	if err != nil {
		log.Printf("load Ory Hydra correlation for session %s: %v", sessionID, err)
		writeAdminAPIError(w, http.StatusInternalServerError, "local session ended but OAuth session correlation could not be loaded")
		return
	}
	for _, hydraSessionID := range hydraSessionIDs {
		if err := s.revokeHydraLoginSession(r.Context(), hydraSessionID); err != nil {
			log.Printf("revoke Ory Hydra session for session %s: %v", sessionID, err)
			writeAdminAPIError(w, http.StatusBadGateway, "local session ended but OAuth session revocation did not complete")
			return
		}
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.session-revoke/v1",
		"session_id":     sessionID,
		"user_id":        userID,
	})
}

type managedAppCreateRequest struct {
	Slug            string `json:"slug"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	LaunchURL       string `json:"launch_url"`
	OIDCClientID    string `json:"oidc_client_id"`
	HealthURL       string `json:"health_url"`
	MonitoringURL   string `json:"monitoring_url"`
	ValidationURL   string `json:"validation_url"`
	SignedOutURL    string `json:"signed_out_url"`
	ReleaseRevision string `json:"release_revision"`
}

type managedAppRecord struct {
	Slug            string    `json:"slug"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	ReleaseRevision string    `json:"release_revision"`
	LaunchURL       string    `json:"launch_url"`
	HealthURL       string    `json:"health_url,omitempty"`
	MonitoringURL   string    `json:"monitoring_url,omitempty"`
	ValidationURL   string    `json:"validation_url"`
	SignedOutURL    string    `json:"signed_out_url"`
	OIDCClientID    string    `json:"oidc_client_id"`
	CreatedAt       time.Time `json:"created_at"`
}

func newManagedAppRecord(app identity.ManagedApp) managedAppRecord {
	return managedAppRecord{
		Slug: app.Slug, Name: app.Name, Description: app.Description,
		ReleaseRevision: app.ReleaseRevision, LaunchURL: app.LaunchURL,
		HealthURL: app.HealthURL, MonitoringURL: app.MonitoringURL,
		ValidationURL: app.ValidationURL, SignedOutURL: app.SignedOutURL,
		OIDCClientID: app.OIDCClientID, CreatedAt: app.CreatedAt,
	}
}

// createAppAPI registers a managed app exactly like the administration form:
// the OpenID Connect client must already be registered, and the app's
// coordinates must satisfy the same one-origin and logout-bridge invariants.
func (s *Server) createAppAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIWriteToken(w, r) {
		return
	}
	var request managedAppCreateRequest
	if err := decodeSingleJSONBody(http.MaxBytesReader(w, r.Body, 16*1024), &request); err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid managed app request")
		return
	}
	app := identity.ManagedApp{
		Slug:            strings.TrimSpace(request.Slug),
		Name:            strings.TrimSpace(request.Name),
		Description:     strings.TrimSpace(request.Description),
		LaunchURL:       strings.TrimSpace(request.LaunchURL),
		OIDCClientID:    strings.TrimSpace(request.OIDCClientID),
		HealthURL:       strings.TrimSpace(request.HealthURL),
		MonitoringURL:   strings.TrimSpace(request.MonitoringURL),
		ValidationURL:   strings.TrimSpace(request.ValidationURL),
		SignedOutURL:    strings.TrimSpace(request.SignedOutURL),
		ReleaseRevision: strings.TrimSpace(request.ReleaseRevision),
	}
	clients, err := s.hydraClients(r.Context())
	if err != nil {
		log.Printf("verify OAuth client for app %s: %v", app.Slug, err)
		writeAdminAPIError(w, http.StatusBadGateway, "could not verify OAuth client")
		return
	}
	var registeredClient *oidcClient
	for _, client := range clients {
		if client.ID == app.OIDCClientID {
			clientCopy := client
			registeredClient = &clientCopy
			break
		}
	}
	if registeredClient == nil {
		writeAdminAPIError(w, http.StatusBadRequest, "register the OIDC client before adding its app")
		return
	}
	app.OIDCContractHash = oidcClientContractHash(*registeredClient)
	if err := identity.ValidateManagedApp(app); err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateManagedAppClient(app, *registeredClient); err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := s.store.CreateManagedApp(r.Context(), app)
	if err != nil {
		writeAdminAPIStoreError(w, "create managed app", err)
		return
	}
	writeAdminAPIJSON(w, http.StatusCreated, map[string]any{
		"schema_version": "shauth.app/v1",
		"app":            newManagedAppRecord(created),
	})
}

func (s *Server) deleteAppAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIWriteToken(w, r) {
		return
	}
	slug := r.PathValue("slug")
	if err := s.store.DeleteManagedAppBySlug(r.Context(), slug); err != nil {
		if errors.Is(err, identity.ErrManagedAppNotFound) {
			writeAdminAPIError(w, http.StatusNotFound, "managed app not found")
			return
		}
		log.Printf("delete managed app %s: %v", slug, err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not delete managed app")
		return
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.app-delete/v1",
		"slug":           slug,
	})
}
