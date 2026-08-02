// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"encoding/json"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/e6qu/shauth/internal/config"
	"github.com/e6qu/shauth/internal/identity"
	"golang.org/x/oauth2"
)

type adminAPIEndpoint struct {
	method    string
	target    string
	pathValue map[string]string
	write     bool
	handler   http.HandlerFunc
}

func adminAPIEndpoints(server *Server) map[string]adminAPIEndpoint {
	return map[string]adminAPIEndpoint{
		"users":                 {http.MethodGet, "/api/v1/users", nil, false, server.usersAPI},
		"user sessions":         {http.MethodGet, "/api/v1/users/5f61a1a1-27b6-4e8c-9e3f-1f2e3d4c5b6a/sessions", map[string]string{"id": "5f61a1a1-27b6-4e8c-9e3f-1f2e3d4c5b6a"}, false, server.userSessionsAPI},
		"session policy":        {http.MethodGet, "/api/v1/session-policy", nil, false, server.sessionPolicyAPI},
		"oidc clients":          {http.MethodGet, "/api/v1/oidc-clients", nil, false, server.oidcClientsAPI},
		"github mappings":       {http.MethodGet, "/api/v1/github-mappings", nil, false, server.githubMappingsAPI},
		"connectors":            {http.MethodGet, "/api/v1/connectors", nil, false, server.connectorsAPI},
		"monitoring":            {http.MethodGet, "/api/v1/monitoring", nil, false, server.monitoringAPI},
		"create user":           {http.MethodPost, "/internal/users", nil, true, server.createUserAPI},
		"create invitation":     {http.MethodPost, "/internal/invitations", nil, true, server.createInvitationAPI},
		"revoke session":        {http.MethodPost, "/internal/sessions/5f61a1a1-27b6-4e8c-9e3f-1f2e3d4c5b6a/revoke", map[string]string{"id": "5f61a1a1-27b6-4e8c-9e3f-1f2e3d4c5b6a"}, true, server.revokeSessionAPI},
		"update session policy": {http.MethodPut, "/internal/session-policy", nil, true, server.updateSessionPolicyAPI},
		"create oidc client":    {http.MethodPost, "/internal/oidc-clients", nil, true, server.createOIDCClientAPI},
		"delete oidc client":    {http.MethodDelete, "/internal/oidc-clients/some-client", map[string]string{"id": "some-client"}, true, server.deleteOIDCClientAPI},
		"create github mapping": {http.MethodPost, "/internal/github-mappings", nil, true, server.createGitHubMappingAPI},
		"delete github mapping": {http.MethodDelete, "/internal/github-mappings/5f61a1a1-27b6-4e8c-9e3f-1f2e3d4c5b6a", map[string]string{"id": "5f61a1a1-27b6-4e8c-9e3f-1f2e3d4c5b6a"}, true, server.deleteGitHubMappingAPI},
		"create app":            {http.MethodPost, "/internal/apps", nil, true, server.createAppAPI},
		"delete app":            {http.MethodDelete, "/internal/apps/some-app", map[string]string{"slug": "some-app"}, true, server.deleteAppAPI},
	}
}

func adminAPIRequest(endpoint adminAPIEndpoint, authorize func(*http.Request)) *httptest.ResponseRecorder {
	request := httptest.NewRequest(endpoint.method, endpoint.target, nil)
	for name, value := range endpoint.pathValue {
		request.SetPathValue(name, value)
	}
	authorize(request)
	response := httptest.NewRecorder()
	endpoint.handler(response, request)
	return response
}

func TestAdminAPIEndpointsReportUnconfiguredToken(t *testing.T) {
	server := &Server{}
	for name, endpoint := range adminAPIEndpoints(server) {
		t.Run(name, func(t *testing.T) {
			response := adminAPIRequest(endpoint, func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer any")
			})
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("unconfigured response was cacheable")
			}
		})
	}
}

func TestAdminAPIEndpointsRejectMissingWrongOrCrossPurposeTokens(t *testing.T) {
	const readToken = "admin-api-read-token-0123456789abcdef"
	const writeToken = "admin-api-write-token-0123456789abcde"
	server := &Server{config: config.Config{AdminAPIReadToken: readToken, AdminAPIWriteToken: writeToken}}
	for name, endpoint := range adminAPIEndpoints(server) {
		crossPurpose := readToken
		if !endpoint.write {
			crossPurpose = writeToken
		}
		for credential, authorize := range map[string]func(*http.Request){
			"missing":       func(*http.Request) {},
			"wrong":         func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") },
			"cross-purpose": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+crossPurpose) },
		} {
			t.Run(name+" "+credential, func(t *testing.T) {
				response := adminAPIRequest(endpoint, authorize)
				if response.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
				}
			})
		}
	}
}

func TestAdminAPIWriteEndpointsRejectMalformedJSONBodies(t *testing.T) {
	const writeToken = "admin-api-write-token-0123456789abcde"
	server := &Server{config: config.Config{AdminAPIWriteToken: writeToken}}
	for name, endpoint := range map[string]struct {
		target  string
		method  string
		handler http.HandlerFunc
	}{
		"create user":           {"/internal/users", http.MethodPost, server.createUserAPI},
		"create invitation":     {"/internal/invitations", http.MethodPost, server.createInvitationAPI},
		"update session policy": {"/internal/session-policy", http.MethodPut, server.updateSessionPolicyAPI},
		"create oidc client":    {"/internal/oidc-clients", http.MethodPost, server.createOIDCClientAPI},
		"create github mapping": {"/internal/github-mappings", http.MethodPost, server.createGitHubMappingAPI},
		"create app":            {"/internal/apps", http.MethodPost, server.createAppAPI},
	} {
		for kind, body := range map[string]string{
			"unknown field":  `{"nonexistent_field":true}`,
			"trailing value": `{} {}`,
			"not an object":  `"text"`,
			"empty":          "",
		} {
			t.Run(name+" "+kind, func(t *testing.T) {
				request := httptest.NewRequest(endpoint.method, endpoint.target, strings.NewReader(body))
				request.Header.Set("Authorization", "Bearer "+writeToken)
				response := httptest.NewRecorder()
				endpoint.handler(response, request)
				if response.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusBadRequest, response.Body.String())
				}
			})
		}
	}
}

func TestAdminAPIPathIdentifiersAreValidatedBeforeStorageAccess(t *testing.T) {
	const readToken = "admin-api-read-token-0123456789abcdef"
	const writeToken = "admin-api-write-token-0123456789abcde"
	server := &Server{config: config.Config{AdminAPIReadToken: readToken, AdminAPIWriteToken: writeToken}}
	for name, endpoint := range map[string]struct {
		endpoint adminAPIEndpoint
		token    string
		status   int
	}{
		"user sessions garbage id":          {adminAPIEndpoint{http.MethodGet, "/api/v1/users/not-a-uuid/sessions", map[string]string{"id": "not-a-uuid"}, false, server.userSessionsAPI}, readToken, http.StatusNotFound},
		"revoke session garbage id":         {adminAPIEndpoint{http.MethodPost, "/internal/sessions/not-a-uuid/revoke", map[string]string{"id": "not-a-uuid"}, true, server.revokeSessionAPI}, writeToken, http.StatusNotFound},
		"delete github mapping garbage id":  {adminAPIEndpoint{http.MethodDelete, "/internal/github-mappings/not-a-uuid", map[string]string{"id": "not-a-uuid"}, true, server.deleteGitHubMappingAPI}, writeToken, http.StatusNotFound},
		"delete oidc client invalid id":     {adminAPIEndpoint{http.MethodDelete, "/internal/oidc-clients/UPPER%20CASE", map[string]string{"id": "UPPER CASE"}, true, server.deleteOIDCClientAPI}, writeToken, http.StatusBadRequest},
		"sql injection shaped session path": {adminAPIEndpoint{http.MethodPost, "/internal/sessions/1;DROP/revoke", map[string]string{"id": "1;DROP TABLE sessions"}, true, server.revokeSessionAPI}, writeToken, http.StatusNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			response := adminAPIRequest(endpoint.endpoint, func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+endpoint.token)
			})
			if response.Code != endpoint.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, endpoint.status, response.Body.String())
			}
		})
	}
}

func TestSessionPolicyRecordValidatesUnits(t *testing.T) {
	valid := sessionPolicyRecord{
		BrowserAbsoluteHours: 720, BrowserIdleMinutes: 720, OIDCSSOHours: 720,
		AccessTokenMinutes: 15, IDTokenMinutes: 15, RefreshTokenHours: 720,
	}
	policy, err := valid.sessionPolicy()
	if err != nil {
		t.Fatalf("sessionPolicy() error = %v", err)
	}
	if policy.BrowserAbsoluteLifetime != 720*time.Hour || policy.AccessTokenLifetime != 15*time.Minute {
		t.Fatalf("policy = %#v", policy)
	}
	if newSessionPolicyRecord(policy) != valid {
		t.Fatalf("policy record round trip = %#v", newSessionPolicyRecord(policy))
	}
	for name, invalid := range map[string]func(record sessionPolicyRecord) sessionPolicyRecord{
		"zero":                func(r sessionPolicyRecord) sessionPolicyRecord { r.AccessTokenMinutes = 0; return r },
		"negative":            func(r sessionPolicyRecord) sessionPolicyRecord { r.BrowserAbsoluteHours = -1; return r },
		"overflow":            func(r sessionPolicyRecord) sessionPolicyRecord { r.BrowserAbsoluteHours = math.MaxInt64; return r },
		"idle above absolute": func(r sessionPolicyRecord) sessionPolicyRecord { r.BrowserIdleMinutes = 721 * 60; return r },
		"sso above absolute":  func(r sessionPolicyRecord) sessionPolicyRecord { r.OIDCSSOHours = 721; return r },
		"refresh under access": func(r sessionPolicyRecord) sessionPolicyRecord {
			r.RefreshTokenHours = 720
			r.AccessTokenMinutes = 720*60 + 60
			return r
		},
		"access above 24 hours": func(r sessionPolicyRecord) sessionPolicyRecord { r.AccessTokenMinutes = 25 * 60; return r },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := invalid(valid).sessionPolicy(); err == nil {
				t.Fatal("sessionPolicy() accepted an invalid record")
			}
		})
	}
}

func TestUserRecordReportsIdentitySourceAndOmitsEmptyFields(t *testing.T) {
	created := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	local, err := json.Marshal(newUserRecord(identity.User{
		ID: "5f61a1a1-27b6-4e8c-9e3f-1f2e3d4c5b6a", Username: "operator", Email: "operator@example.test",
		EmailVerified: true, Role: identity.RoleAdmin, CreatedAt: created,
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"identity_source":"local"`, `"role":"admin"`, `"email_verified":true`} {
		if !strings.Contains(string(local), expected) {
			t.Fatalf("local user record omitted %s: %s", expected, local)
		}
	}
	for _, unexpected := range []string{"github_login", "disabled_at"} {
		if strings.Contains(string(local), unexpected) {
			t.Fatalf("local user record reported empty optional field %s: %s", unexpected, local)
		}
	}

	disabled := created.Add(time.Hour)
	federated, err := json.Marshal(newUserRecord(identity.User{
		ID: "5f61a1a1-27b6-4e8c-9e3f-1f2e3d4c5b6b", Username: "octocat", Email: "octocat@example.test",
		GitHubLogin: "octocat", IdentitySource: identity.IdentitySourceGitHub,
		Role: identity.RoleDeveloper, DisabledAt: &disabled, CreatedAt: created,
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"identity_source":"github"`, `"github_login":"octocat"`, `"disabled_at":`} {
		if !strings.Contains(string(federated), expected) {
			t.Fatalf("federated user record omitted %s: %s", expected, federated)
		}
	}
}

func TestSessionRecordOmitsMissingRemoteAddress(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	withAddress, err := json.Marshal(newSessionRecord(identity.Session{
		ID: "5f61a1a1-27b6-4e8c-9e3f-1f2e3d4c5b6a", CreatedAt: now, LastSeen: now,
		ExpiresAt: now.Add(time.Hour), UserAgent: "curl/8", RemoteIP: net.ParseIP("192.0.2.10"), Active: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"remote_address":"192.0.2.10"`, `"active":true`, `"user_agent":"curl/8"`} {
		if !strings.Contains(string(withAddress), expected) {
			t.Fatalf("session record omitted %s: %s", expected, withAddress)
		}
	}
	withoutAddress, err := json.Marshal(newSessionRecord(identity.Session{ID: "x", CreatedAt: now, LastSeen: now, ExpiresAt: now}))
	if err != nil {
		t.Fatal(err)
	}
	for _, unexpected := range []string{"remote_address", "revoked_at"} {
		if strings.Contains(string(withoutAddress), unexpected) {
			t.Fatalf("session record reported empty optional field %s: %s", unexpected, withoutAddress)
		}
	}
}

func TestConnectorsAPIReportsConnectorCoordinates(t *testing.T) {
	const readToken = "admin-api-read-token-0123456789abcdef"
	server := &Server{
		config: config.Config{
			AdminAPIReadToken:   readToken,
			GitHubAdminTeam:     "e6qu-org/e6qu-org-admins",
			GitHubDeveloperTeam: "e6qu-org/e6qu-org-members",
		},
		oauth: &oauth2.Config{},
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/connectors", nil)
	request.Header.Set("Authorization", "Bearer "+readToken)
	response := httptest.NewRecorder()
	server.connectorsAPI(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var envelope struct {
		SchemaVersion string    `json:"schema_version"`
		ObservedAt    time.Time `json:"observed_at"`
		GitHub        struct {
			Enabled       bool   `json:"enabled"`
			AdminTeam     string `json:"admin_team"`
			DeveloperTeam string `json:"developer_team"`
		} `json:"github"`
		Entra struct {
			Enabled  bool   `json:"enabled"`
			TenantID string `json:"tenant_id"`
		} `json:"entra"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode connectors envelope: %v: %s", err, response.Body.String())
	}
	if envelope.SchemaVersion != "shauth.connectors/v1" || envelope.ObservedAt.IsZero() {
		t.Fatalf("envelope = %#v", envelope)
	}
	if !envelope.GitHub.Enabled || envelope.GitHub.AdminTeam != "e6qu-org/e6qu-org-admins" || envelope.GitHub.DeveloperTeam != "e6qu-org/e6qu-org-members" {
		t.Fatalf("github connector = %#v", envelope.GitHub)
	}
	if envelope.Entra.Enabled || envelope.Entra.TenantID != "" {
		t.Fatalf("entra connector = %#v", envelope.Entra)
	}
}

func TestCreateOIDCClientAPIRejectsInvalidInputBeforeProviderAccess(t *testing.T) {
	const writeToken = "admin-api-write-token-0123456789abcde"
	server := &Server{config: config.Config{AdminAPIWriteToken: writeToken}}
	body := `{"client_id":"valid-client","client_name":"Valid","client_secret":"short","redirect_uris":["https://app.example.test/callback"],"post_logout_redirect_uris":["https://app.example.test/auth/shauth/logout/complete"],"frontchannel_logout_uri":"https://app.example.test/frontchannel-logout"}`
	request := httptest.NewRequest(http.MethodPost, "/internal/oidc-clients", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+writeToken)
	response := httptest.NewRecorder()
	server.createOIDCClientAPI(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	var failure map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil || !strings.Contains(failure["error"], "client secret") {
		t.Fatalf("failure body = %s (%v)", response.Body.String(), err)
	}
}

func TestCSRFPostsExemptsAdminAPIWrites(t *testing.T) {
	publicURL, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	handler := csrfPosts(publicURL, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for name, request := range map[string]*http.Request{
		"post users":            httptest.NewRequest(http.MethodPost, "https://auth.example.test/internal/users", nil),
		"post invitations":      httptest.NewRequest(http.MethodPost, "https://auth.example.test/internal/invitations", nil),
		"put session policy":    httptest.NewRequest(http.MethodPut, "https://auth.example.test/internal/session-policy", nil),
		"delete oidc client":    httptest.NewRequest(http.MethodDelete, "https://auth.example.test/internal/oidc-clients/some-client", nil),
		"delete github mapping": httptest.NewRequest(http.MethodDelete, "https://auth.example.test/internal/github-mappings/some-id", nil),
		"delete app":            httptest.NewRequest(http.MethodDelete, "https://auth.example.test/internal/apps/some-app", nil),
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d: bearer-token requests present no CSRF token", response.Code, http.StatusNoContent)
			}
		})
	}
}
