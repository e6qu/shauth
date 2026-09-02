// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build acceptance

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/e6qu/shauth/internal/config"
	"github.com/e6qu/shauth/internal/identity"
	"github.com/e6qu/shauth/internal/managedapps"
	"github.com/e6qu/shauth/internal/monitoring"
	"github.com/jackc/pgx/v5/pgxpool"
)

const adminAPIAcceptanceReadToken = "admin-api-acceptance-read-token-0123456789ab"
const adminAPIAcceptanceWriteToken = "admin-api-acceptance-write-token-0123456789a"

// newAdminAPIAcceptanceServer runs the complete handler chain against real
// PostgreSQL (an isolated schema clone) and the real Ory Hydra
// administration endpoint provided by the acceptance stack.
func newAdminAPIAcceptanceServer(t *testing.T) (*pgxpool.Pool, http.Handler, *identity.Store) {
	pool, server, store := newAdminAPIAcceptanceService(t)
	return pool, server.Handler(), store
}

// newAdminAPIAcceptanceService exposes the server itself, for the operations
// no transport reaches with a bearer token.
func newAdminAPIAcceptanceService(t *testing.T) (*pgxpool.Pool, *Server, *identity.Store) {
	t.Helper()
	databaseURL := os.Getenv("SHAUTH_ACCEPTANCE_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("SHAUTH_ACCEPTANCE_DATABASE_URL is required")
	}
	hydraAdmin := os.Getenv("SHAUTH_ACCEPTANCE_HYDRA_ADMIN_URL")
	if hydraAdmin == "" {
		t.Fatal("SHAUTH_ACCEPTANCE_HYDRA_ADMIN_URL is required")
	}
	hydraPublic := os.Getenv("SHAUTH_ACCEPTANCE_HYDRA_PUBLIC_URL")
	if hydraPublic == "" {
		t.Fatal("SHAUTH_ACCEPTANCE_HYDRA_PUBLIC_URL is required")
	}
	hydraAdminURL, err := url.Parse(hydraAdmin)
	if err != nil {
		t.Fatalf("parse Hydra administration URL: %v", err)
	}
	hydraPublicURL, err := url.Parse(hydraPublic)
	if err != nil {
		t.Fatalf("parse Hydra public URL: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	t.Cleanup(adminPool.Close)
	schema := "admin_api_" + strings.ReplaceAll(acceptanceUUID(t), "-", "")
	if _, err := adminPool.Exec(ctx, fmt.Sprintf(`
		CREATE SCHEMA %[1]s;
		CREATE TABLE %[1]s.users (LIKE public.users INCLUDING ALL);
		CREATE TABLE %[1]s.sessions (LIKE public.sessions INCLUDING ALL);
		CREATE TABLE %[1]s.invitations (LIKE public.invitations INCLUDING ALL);
		CREATE TABLE %[1]s.github_role_mappings (LIKE public.github_role_mappings INCLUDING ALL);
		CREATE TABLE %[1]s.session_policy (LIKE public.session_policy INCLUDING ALL);
		CREATE TABLE %[1]s.hydra_login_sessions (LIKE public.hydra_login_sessions INCLUDING ALL);
		CREATE TABLE %[1]s.managed_apps (LIKE public.managed_apps INCLUDING ALL);
		CREATE TABLE %[1]s.app_validation_runs (LIKE public.app_validation_runs INCLUDING ALL);
		CREATE TABLE %[1]s.audit_events (LIKE public.audit_events INCLUDING ALL);
		CREATE TABLE %[1]s.logout_correlation_grants (LIKE public.logout_correlation_grants INCLUDING ALL);
		INSERT INTO %[1]s.session_policy (singleton,browser_absolute_lifetime_seconds,browser_idle_timeout_seconds,oidc_session_lifetime_seconds,access_token_lifetime_seconds,id_token_lifetime_seconds,refresh_token_lifetime_seconds,updated_at)
		VALUES (TRUE, 2592000, 43200, 2592000, 900, 900, 2592000, now())`, schema)); err != nil {
		t.Fatalf("create isolated administration API schema: %v", err)
	}
	t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("connect isolated administration API schema: %v", err)
	}
	t.Cleanup(pool.Close)
	store, err := identity.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	publicURL, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		config: config.Config{
			PublicURL:           publicURL,
			HydraAdminURL:       hydraAdminURL,
			HydraPublicURL:      hydraPublicURL,
			AdminAPIReadToken:   adminAPIAcceptanceReadToken,
			AdminAPIWriteToken:  adminAPIAcceptanceWriteToken,
			GitHubAdminTeam:     "e6qu-org/e6qu-org-admins",
			GitHubDeveloperTeam: "e6qu-org/e6qu-org-members",
		},
		store:            store,
		httpClient:       &http.Client{Timeout: 15 * time.Second},
		managedApps:      managedapps.New(),
		monitoringClient: monitoring.NewClient(),
		hydraPublic:      httputil.NewSingleHostReverseProxy(hydraPublicURL),
	}
	return pool, server, store
}

func adminAPIAcceptanceRequest(t *testing.T, handler http.Handler, method, target, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var request *http.Request
	if body == "" {
		request = httptest.NewRequest(method, target, nil)
	} else {
		request = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestAdminAPIUserLifecycleAndSearch(t *testing.T) {
	_, handler, _ := newAdminAPIAcceptanceServer(t)
	username := "admin-api-user-" + strings.ReplaceAll(acceptanceUUID(t), "-", "")[:12]
	body := fmt.Sprintf(`{"username":%q,"email":%q,"password":"a-long-acceptance-password","role":"developer"}`, username, username+"@example.test")

	created := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/users", adminAPIAcceptanceWriteToken, body)
	if created.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", created.Code, created.Body.String())
	}
	var receipt struct {
		SchemaVersion string     `json:"schema_version"`
		User          userRecord `json:"user"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("decode user receipt: %v: %s", err, created.Body.String())
	}
	if receipt.SchemaVersion != "shauth.user/v1" || receipt.User.Username != username || receipt.User.IdentitySource != "local" || receipt.User.Role != "developer" || receipt.User.ID == "" {
		t.Fatalf("user receipt = %#v", receipt)
	}

	duplicate := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/users", adminAPIAcceptanceWriteToken, body)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate user status = %d, body = %s", duplicate.Code, duplicate.Body.String())
	}
	invalidRole := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/users", adminAPIAcceptanceWriteToken, `{"username":"another","email":"another@example.test","password":"a-long-acceptance-password","role":"owner"}`)
	if invalidRole.Code != http.StatusBadRequest {
		t.Fatalf("invalid role status = %d, body = %s", invalidRole.Code, invalidRole.Body.String())
	}

	listed := adminAPIAcceptanceRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/users?q="+username, adminAPIAcceptanceReadToken, "")
	if listed.Code != http.StatusOK {
		t.Fatalf("list status = %d, body = %s", listed.Code, listed.Body.String())
	}
	var envelope struct {
		SchemaVersion string       `json:"schema_version"`
		ObservedAt    time.Time    `json:"observed_at"`
		Users         []userRecord `json:"users"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode users envelope: %v: %s", err, listed.Body.String())
	}
	if envelope.SchemaVersion != "shauth.users/v1" || envelope.ObservedAt.IsZero() || len(envelope.Users) != 1 {
		t.Fatalf("users envelope = %#v", envelope)
	}
	if envelope.Users[0].ID != receipt.User.ID || envelope.Users[0].IdentitySource != "local" || !envelope.Users[0].EmailVerified {
		t.Fatalf("listed user = %#v", envelope.Users[0])
	}

	missed := adminAPIAcceptanceRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/users?q=no-such-user", adminAPIAcceptanceReadToken, "")
	if err := json.Unmarshal(missed.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if missed.Code != http.StatusOK || len(envelope.Users) != 0 {
		t.Fatalf("filtered users = %d %#v", missed.Code, envelope.Users)
	}
}

func TestAdminAPIUserSessionsReadAndSingleRevoke(t *testing.T) {
	_, handler, store := newAdminAPIAcceptanceServer(t)
	ctx := context.Background()
	user, err := store.CreatePasswordUser(ctx, "session-owner", "session-owner@example.test", "a-long-acceptance-password", identity.RoleDeveloper)
	if err != nil {
		t.Fatal(err)
	}
	_, session, err := store.CreateSession(ctx, user.ID, "curl/8 acceptance", net.ParseIP("192.0.2.10"), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	type sessionsEnvelope struct {
		SchemaVersion string          `json:"schema_version"`
		User          userRecord      `json:"user"`
		Sessions      []sessionRecord `json:"sessions"`
	}
	read := func() sessionsEnvelope {
		t.Helper()
		response := adminAPIAcceptanceRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/users/"+user.ID+"/sessions", adminAPIAcceptanceReadToken, "")
		if response.Code != http.StatusOK {
			t.Fatalf("sessions status = %d, body = %s", response.Code, response.Body.String())
		}
		var envelope sessionsEnvelope
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode sessions envelope: %v: %s", err, response.Body.String())
		}
		return envelope
	}

	active := read()
	if active.SchemaVersion != "shauth.user-sessions/v1" || active.User.ID != user.ID || len(active.Sessions) != 1 {
		t.Fatalf("sessions envelope = %#v", active)
	}
	if got := active.Sessions[0]; got.ID != session.ID || !got.Active || got.RevokedAt != nil || got.UserAgent != "curl/8 acceptance" || got.RemoteAddress != "192.0.2.10" {
		t.Fatalf("active session record = %#v", got)
	}

	unknown := adminAPIAcceptanceRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/users/"+acceptanceUUID(t)+"/sessions", adminAPIAcceptanceReadToken, "")
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown user status = %d, body = %s", unknown.Code, unknown.Body.String())
	}

	revoked := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/sessions/"+session.ID+"/revoke", adminAPIAcceptanceWriteToken, "")
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, body = %s", revoked.Code, revoked.Body.String())
	}
	var receipt struct {
		SchemaVersion string `json:"schema_version"`
		SessionID     string `json:"session_id"`
		UserID        string `json:"user_id"`
	}
	if err := json.Unmarshal(revoked.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("decode revoke receipt: %v: %s", err, revoked.Body.String())
	}
	if receipt.SchemaVersion != "shauth.session-revoke/v1" || receipt.SessionID != session.ID || receipt.UserID != user.ID {
		t.Fatalf("revoke receipt = %#v", receipt)
	}

	after := read()
	if got := after.Sessions[0]; got.Active || got.RevokedAt == nil {
		t.Fatalf("revoked session record = %#v", got)
	}

	again := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/sessions/"+session.ID+"/revoke", adminAPIAcceptanceWriteToken, "")
	if again.Code != http.StatusConflict {
		t.Fatalf("second revoke status = %d, body = %s", again.Code, again.Body.String())
	}
	missing := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/sessions/"+acceptanceUUID(t)+"/revoke", adminAPIAcceptanceWriteToken, "")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unknown session status = %d, body = %s", missing.Code, missing.Body.String())
	}
}

func TestAdminAPISessionPolicyReadAndUpdate(t *testing.T) {
	pool, handler, _ := newAdminAPIAcceptanceServer(t)

	type policyEnvelope struct {
		SchemaVersion string              `json:"schema_version"`
		Policy        sessionPolicyRecord `json:"policy"`
	}
	read := func() policyEnvelope {
		t.Helper()
		response := adminAPIAcceptanceRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/session-policy", adminAPIAcceptanceReadToken, "")
		if response.Code != http.StatusOK {
			t.Fatalf("policy status = %d, body = %s", response.Code, response.Body.String())
		}
		var envelope policyEnvelope
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode policy envelope: %v: %s", err, response.Body.String())
		}
		return envelope
	}

	defaults := sessionPolicyRecord{BrowserAbsoluteHours: 720, BrowserIdleMinutes: 720, OIDCSSOHours: 720, AccessTokenMinutes: 15, IDTokenMinutes: 15, RefreshTokenHours: 720}
	initial := read()
	if initial.SchemaVersion != "shauth.session-policy/v1" || withoutChangeTime(initial.Policy) != defaults {
		t.Fatalf("default policy envelope = %#v", initial)
	}
	if initial.Policy.UpdatedAt.IsZero() {
		t.Fatal("the policy contract did not report when the policy last changed")
	}

	updatedRecord := sessionPolicyRecord{BrowserAbsoluteHours: 480, BrowserIdleMinutes: 360, OIDCSSOHours: 480, AccessTokenMinutes: 30, IDTokenMinutes: 30, RefreshTokenHours: 480}
	updateBody, err := json.Marshal(updatedRecord)
	if err != nil {
		t.Fatal(err)
	}
	// Restore the durable defaults afterwards so the shared Ory Hydra client
	// lifespans return to the values other stack checks expect.
	defer func() {
		restoreBody, err := json.Marshal(defaults)
		if err != nil {
			t.Fatal(err)
		}
		restore := adminAPIAcceptanceRequest(t, handler, http.MethodPut, "https://auth.example.test/internal/session-policy", adminAPIAcceptanceWriteToken, string(restoreBody))
		if restore.Code != http.StatusOK {
			t.Fatalf("restore status = %d, body = %s", restore.Code, restore.Body.String())
		}
	}()
	updated := adminAPIAcceptanceRequest(t, handler, http.MethodPut, "https://auth.example.test/internal/session-policy", adminAPIAcceptanceWriteToken, string(updateBody))
	if updated.Code != http.StatusOK {
		t.Fatalf("update status = %d, body = %s", updated.Code, updated.Body.String())
	}
	after := read()
	if withoutChangeTime(after.Policy) != updatedRecord {
		t.Fatalf("updated policy envelope = %#v", after)
	}
	if !after.Policy.UpdatedAt.After(initial.Policy.UpdatedAt) {
		t.Fatalf("policy change time = %s, want it later than the previous %s", after.Policy.UpdatedAt, initial.Policy.UpdatedAt)
	}
	var storedAccessSeconds int64
	if err := pool.QueryRow(context.Background(), `SELECT access_token_lifetime_seconds FROM session_policy WHERE singleton=TRUE`).Scan(&storedAccessSeconds); err != nil {
		t.Fatal(err)
	}
	if storedAccessSeconds != 30*60 {
		t.Fatalf("stored access token lifetime = %d seconds, want %d", storedAccessSeconds, 30*60)
	}

	invalid := adminAPIAcceptanceRequest(t, handler, http.MethodPut, "https://auth.example.test/internal/session-policy", adminAPIAcceptanceWriteToken, `{"browser_absolute_hours":10,"browser_idle_minutes":720,"oidc_sso_hours":10,"access_token_minutes":15,"id_token_minutes":15,"refresh_token_hours":240}`)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid policy status = %d, body = %s", invalid.Code, invalid.Body.String())
	}
	rejected := read()
	if withoutChangeTime(rejected.Policy) != updatedRecord {
		t.Fatalf("policy changed after a rejected update: %#v", rejected)
	}
	// A refused change must not move the change time either, or the record
	// claims the policy was touched when nothing was stored.
	if !rejected.Policy.UpdatedAt.Equal(after.Policy.UpdatedAt) {
		t.Fatalf("a rejected update moved the change time to %s from %s", rejected.Policy.UpdatedAt, after.Policy.UpdatedAt)
	}
}

func TestAdminAPIGitHubRoleMappingLifecycle(t *testing.T) {
	_, handler, _ := newAdminAPIAcceptanceServer(t)

	created := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/github-mappings", adminAPIAcceptanceWriteToken, `{"kind":"team","target":"e6qu-org/admin-api-team","role":"admin"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", created.Code, created.Body.String())
	}
	var receipt struct {
		SchemaVersion string                  `json:"schema_version"`
		Mapping       githubRoleMappingRecord `json:"mapping"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("decode mapping receipt: %v: %s", err, created.Body.String())
	}
	if receipt.SchemaVersion != "shauth.github-role-mapping/v1" || receipt.Mapping.Kind != "team" || receipt.Mapping.Target != "e6qu-org/admin-api-team" || receipt.Mapping.Role != "admin" || receipt.Mapping.ID == "" {
		t.Fatalf("mapping receipt = %#v", receipt)
	}

	invalid := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/github-mappings", adminAPIAcceptanceWriteToken, `{"kind":"country","target":"e6qu-org","role":"admin"}`)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid mapping status = %d, body = %s", invalid.Code, invalid.Body.String())
	}

	listed := adminAPIAcceptanceRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/github-mappings", adminAPIAcceptanceReadToken, "")
	if listed.Code != http.StatusOK {
		t.Fatalf("list status = %d, body = %s", listed.Code, listed.Body.String())
	}
	var envelope struct {
		SchemaVersion string                    `json:"schema_version"`
		Mappings      []githubRoleMappingRecord `json:"mappings"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode mappings envelope: %v: %s", err, listed.Body.String())
	}
	if envelope.SchemaVersion != "shauth.github-role-mappings/v1" || len(envelope.Mappings) != 1 || envelope.Mappings[0].ID != receipt.Mapping.ID {
		t.Fatalf("mappings envelope = %#v", envelope)
	}

	deleted := adminAPIAcceptanceRequest(t, handler, http.MethodDelete, "https://auth.example.test/internal/github-mappings/"+receipt.Mapping.ID, adminAPIAcceptanceWriteToken, "")
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", deleted.Code, deleted.Body.String())
	}
	missing := adminAPIAcceptanceRequest(t, handler, http.MethodDelete, "https://auth.example.test/internal/github-mappings/"+receipt.Mapping.ID, adminAPIAcceptanceWriteToken, "")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("second delete status = %d, body = %s", missing.Code, missing.Body.String())
	}
}

func TestAdminAPIOIDCClientAndManagedAppLifecycle(t *testing.T) {
	pool, handler, _ := newAdminAPIAcceptanceServer(t)
	slug := "admin-api-" + strings.ReplaceAll(acceptanceUUID(t), "-", "")[:12]
	origin := "https://" + slug + ".example.test"
	hydraAdmin := os.Getenv("SHAUTH_ACCEPTANCE_HYDRA_ADMIN_URL")
	t.Cleanup(func() {
		request, err := http.NewRequest(http.MethodDelete, hydraAdmin+"/admin/clients/"+slug, nil)
		if err != nil {
			return
		}
		response, err := http.DefaultClient.Do(request)
		if err == nil {
			response.Body.Close()
		}
	})

	clientBody := fmt.Sprintf(`{"client_id":%[1]q,"client_name":"Administration API acceptance","client_secret":"an-acceptance-client-secret-0123456789ab","redirect_uris":[%[2]q],"post_logout_redirect_uris":[%[3]q],"frontchannel_logout_uri":%[4]q}`,
		slug, origin+"/auth/callback", origin+"/auth/shauth/logout/complete", origin+"/auth/frontchannel-logout")
	created := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/oidc-clients", adminAPIAcceptanceWriteToken, clientBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("create client status = %d, body = %s", created.Code, created.Body.String())
	}
	var clientReceipt struct {
		SchemaVersion string     `json:"schema_version"`
		Client        oidcClient `json:"client"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &clientReceipt); err != nil {
		t.Fatalf("decode client receipt: %v: %s", err, created.Body.String())
	}
	if clientReceipt.SchemaVersion != "shauth.oidc-client/v1" || clientReceipt.Client.ID != slug || clientReceipt.Client.TokenEndpointAuth != "client_secret_post" {
		t.Fatalf("client receipt = %#v", clientReceipt)
	}
	if strings.Contains(created.Body.String(), "an-acceptance-client-secret") {
		t.Fatalf("client receipt leaked the client secret: %s", created.Body.String())
	}

	conflict := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/oidc-clients", adminAPIAcceptanceWriteToken, clientBody)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("duplicate client status = %d, body = %s", conflict.Code, conflict.Body.String())
	}

	listed := adminAPIAcceptanceRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/oidc-clients", adminAPIAcceptanceReadToken, "")
	if listed.Code != http.StatusOK {
		t.Fatalf("list clients status = %d, body = %s", listed.Code, listed.Body.String())
	}
	var clientsEnvelope struct {
		SchemaVersion string       `json:"schema_version"`
		Clients       []oidcClient `json:"clients"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &clientsEnvelope); err != nil {
		t.Fatalf("decode clients envelope: %v: %s", err, listed.Body.String())
	}
	if clientsEnvelope.SchemaVersion != "shauth.oidc-clients/v1" {
		t.Fatalf("clients envelope = %#v", clientsEnvelope)
	}
	var found bool
	for _, client := range clientsEnvelope.Clients {
		if client.ID == slug {
			found = true
			if len(client.PostLogoutRedirectURIs) != 1 || client.PostLogoutRedirectURIs[0] != origin+"/auth/shauth/logout/complete" {
				t.Fatalf("registered client coordinates = %#v", client)
			}
		}
	}
	if !found {
		t.Fatalf("created client %q missing from catalog: %s", slug, listed.Body.String())
	}

	appBody := fmt.Sprintf(`{"slug":%[1]q,"name":"Administration API acceptance app","description":"Administration API acceptance coverage.","launch_url":%[2]q,"oidc_client_id":%[1]q,"health_url":%[3]q,"validation_url":%[4]q,"signed_out_url":%[5]q,"release_revision":"0123456789ab","monitoring_url":""}`,
		slug, origin+"/", origin+"/healthz", origin+"/auth/validation", origin+"/auth/signed-out")
	appCreated := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/apps", adminAPIAcceptanceWriteToken, appBody)
	if appCreated.Code != http.StatusCreated {
		t.Fatalf("create app status = %d, body = %s", appCreated.Code, appCreated.Body.String())
	}
	var appReceipt struct {
		SchemaVersion string           `json:"schema_version"`
		App           managedAppRecord `json:"app"`
	}
	if err := json.Unmarshal(appCreated.Body.Bytes(), &appReceipt); err != nil {
		t.Fatalf("decode app receipt: %v: %s", err, appCreated.Body.String())
	}
	if appReceipt.SchemaVersion != "shauth.app/v1" || appReceipt.App.Slug != slug || appReceipt.App.OIDCClientID != slug || appReceipt.App.CreatedAt.IsZero() {
		t.Fatalf("app receipt = %#v", appReceipt)
	}

	unregistered := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/apps", adminAPIAcceptanceWriteToken, strings.ReplaceAll(appBody, slug, slug+"-unregistered"))
	if unregistered.Code != http.StatusBadRequest {
		t.Fatalf("unregistered client app status = %d, body = %s", unregistered.Code, unregistered.Body.String())
	}

	blocked := adminAPIAcceptanceRequest(t, handler, http.MethodDelete, "https://auth.example.test/internal/oidc-clients/"+slug, adminAPIAcceptanceWriteToken, "")
	if blocked.Code != http.StatusConflict {
		t.Fatalf("connected client delete status = %d, body = %s", blocked.Code, blocked.Body.String())
	}

	appDeleted := adminAPIAcceptanceRequest(t, handler, http.MethodDelete, "https://auth.example.test/internal/apps/"+slug, adminAPIAcceptanceWriteToken, "")
	if appDeleted.Code != http.StatusOK {
		t.Fatalf("delete app status = %d, body = %s", appDeleted.Code, appDeleted.Body.String())
	}
	var remaining int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM managed_apps WHERE slug=$1`, slug).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("managed app rows after delete = %d", remaining)
	}
	appMissing := adminAPIAcceptanceRequest(t, handler, http.MethodDelete, "https://auth.example.test/internal/apps/"+slug, adminAPIAcceptanceWriteToken, "")
	if appMissing.Code != http.StatusNotFound {
		t.Fatalf("second app delete status = %d, body = %s", appMissing.Code, appMissing.Body.String())
	}

	clientDeleted := adminAPIAcceptanceRequest(t, handler, http.MethodDelete, "https://auth.example.test/internal/oidc-clients/"+slug, adminAPIAcceptanceWriteToken, "")
	if clientDeleted.Code != http.StatusOK {
		t.Fatalf("delete client status = %d, body = %s", clientDeleted.Code, clientDeleted.Body.String())
	}
	clientMissing := adminAPIAcceptanceRequest(t, handler, http.MethodDelete, "https://auth.example.test/internal/oidc-clients/"+slug, adminAPIAcceptanceWriteToken, "")
	if clientMissing.Code != http.StatusNotFound {
		t.Fatalf("second client delete status = %d, body = %s", clientMissing.Code, clientMissing.Body.String())
	}
}

func TestAdminAPIMonitoringSnapshot(t *testing.T) {
	_, handler, _ := newAdminAPIAcceptanceServer(t)
	response := adminAPIAcceptanceRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/monitoring", adminAPIAcceptanceReadToken, "")
	if response.Code != http.StatusOK {
		t.Fatalf("monitoring status = %d, body = %s", response.Code, response.Body.String())
	}
	var envelope struct {
		SchemaVersion     string                   `json:"schema_version"`
		ObservedAt        time.Time                `json:"observed_at"`
		ActiveSessions    *int                     `json:"active_sessions"`
		PostgreSQLHealthy bool                     `json:"postgresql_healthy"`
		HydraHealthy      bool                     `json:"hydra_healthy"`
		Infrastructure    []monitoringSourceRecord `json:"infrastructure"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode monitoring envelope: %v: %s", err, response.Body.String())
	}
	if envelope.SchemaVersion != "shauth.monitoring/v1" || envelope.ObservedAt.IsZero() {
		t.Fatalf("monitoring envelope = %#v", envelope)
	}
	if envelope.ActiveSessions == nil || *envelope.ActiveSessions != 0 {
		t.Fatalf("active sessions = %v, want 0", envelope.ActiveSessions)
	}
	if !envelope.PostgreSQLHealthy || !envelope.HydraHealthy {
		t.Fatalf("health = postgresql %t, hydra %t; the acceptance stack provides both", envelope.PostgreSQLHealthy, envelope.HydraHealthy)
	}
	if len(envelope.Infrastructure) != 0 {
		t.Fatalf("infrastructure = %#v, no sources are configured", envelope.Infrastructure)
	}
}

// Revoking sessions alone is not containment: a local account can sign in
// again immediately. Disabling must end every session and block sign-in.
func TestAdminAPIDisableContainsAnAccountAndEnableRestoresIt(t *testing.T) {
	_, handler, store := newAdminAPIAcceptanceServer(t)
	ctx := context.Background()
	const password = "a-long-acceptance-password"
	user, err := store.CreatePasswordUser(ctx, "containment", "containment@example.test", password, identity.RoleDeveloper)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CreateSession(ctx, user.ID, "curl/8 acceptance", net.ParseIP("192.0.2.20"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AuthenticatePassword(ctx, "containment", password); err != nil {
		t.Fatalf("the account could not authenticate before being disabled: %v", err)
	}

	disabled := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/users/"+user.ID+"/disable", adminAPIAcceptanceWriteToken, "")
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable status = %d, body = %s", disabled.Code, disabled.Body.String())
	}
	var receipt struct {
		SchemaVersion string     `json:"schema_version"`
		User          userRecord `json:"user"`
	}
	if err := json.Unmarshal(disabled.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("decode disable receipt: %v: %s", err, disabled.Body.String())
	}
	if receipt.SchemaVersion != "shauth.user/v1" || receipt.User.DisabledAt == nil {
		t.Fatalf("disable receipt = %#v", receipt)
	}

	// The credential is still correct, so this proves containment rather
	// than a rejected password.
	if _, _, err := store.AuthenticatePassword(ctx, "containment", password); err == nil {
		t.Fatal("a disabled account authenticated with a valid password")
	}
	sessions, err := store.ListSessions(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		if session.Active || session.RevokedAt == nil {
			t.Fatalf("disabling the account left a live session: %#v", session)
		}
	}

	// Disabling is idempotent so a failed provider revocation can be retried.
	if again := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/users/"+user.ID+"/disable", adminAPIAcceptanceWriteToken, ""); again.Code != http.StatusOK {
		t.Fatalf("repeated disable status = %d, body = %s", again.Code, again.Body.String())
	}

	enabled := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/users/"+user.ID+"/enable", adminAPIAcceptanceWriteToken, "")
	if enabled.Code != http.StatusOK {
		t.Fatalf("enable status = %d, body = %s", enabled.Code, enabled.Body.String())
	}
	// Decoded into a fresh value: disabled_at is omitted for an enabled
	// account, so reusing the disable receipt would keep its stale value.
	var enabledReceipt struct {
		SchemaVersion string     `json:"schema_version"`
		User          userRecord `json:"user"`
	}
	if err := json.Unmarshal(enabled.Body.Bytes(), &enabledReceipt); err != nil {
		t.Fatal(err)
	}
	if enabledReceipt.User.DisabledAt != nil {
		t.Fatalf("enable receipt still reported a disabled account: %#v", enabledReceipt.User)
	}
	if _, _, err := store.AuthenticatePassword(ctx, "containment", password); err != nil {
		t.Fatalf("an enabled account could not authenticate: %v", err)
	}
	// Enabling restores sign-in but must not resurrect the revoked sessions.
	sessions, err = store.ListSessions(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		if session.Active {
			t.Fatalf("enabling the account resurrected a revoked session: %#v", session)
		}
	}

	missing := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/users/"+acceptanceUUID(t)+"/disable", adminAPIAcceptanceWriteToken, "")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unknown user disable status = %d, body = %s", missing.Code, missing.Body.String())
	}
}

// The validation identity drives every application check; disabling it would
// stop validation without containing a real account.
func TestAdminAPIRefusesToDisableTheValidationIdentity(t *testing.T) {
	_, handler, store := newAdminAPIAcceptanceServer(t)
	validationPool, err := store.EnsureValidationUsers(context.Background(), "shauth-validator", "shauth-validator@example.test")
	if err != nil {
		t.Fatal(err)
	}
	validation := validationPool[0]
	response := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/users/"+validation.ID+"/disable", adminAPIAcceptanceWriteToken, "")
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusConflict, response.Body.String())
	}
	reloaded, err := store.UserByID(context.Background(), validation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.DisabledAt != nil {
		t.Fatal("the validation identity was disabled")
	}
}

// An invitation grants account creation at a chosen role. One sent to the
// wrong address must be listable and withdrawable.
func TestAdminAPIInvitationsAreListableAndRevocable(t *testing.T) {
	pool, handler, store := newAdminAPIAcceptanceServer(t)
	ctx := context.Background()
	raw, invitation, err := store.CreateInvitation(ctx, "wrong-address@example.test", identity.RoleAdmin, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	listed := adminAPIAcceptanceRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/invitations", adminAPIAcceptanceReadToken, "")
	if listed.Code != http.StatusOK {
		t.Fatalf("list status = %d, body = %s", listed.Code, listed.Body.String())
	}
	var envelope struct {
		SchemaVersion string             `json:"schema_version"`
		Invitations   []invitationRecord `json:"invitations"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode invitations envelope: %v: %s", err, listed.Body.String())
	}
	if envelope.SchemaVersion != "shauth.invitations/v1" || len(envelope.Invitations) != 1 {
		t.Fatalf("invitations envelope = %#v", envelope)
	}
	if got := envelope.Invitations[0]; got.ID != invitation.ID || got.State != identity.InvitationPending || got.Role != string(identity.RoleAdmin) {
		t.Fatalf("listed invitation = %#v", got)
	}
	// The single-use token is stored only as a hash; listing must not
	// reproduce a working invitation link.
	if strings.Contains(listed.Body.String(), raw) {
		t.Fatalf("the invitation listing leaked its token: %s", listed.Body.String())
	}

	revoked := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/invitations/"+invitation.ID+"/revoke", adminAPIAcceptanceWriteToken, "")
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, body = %s", revoked.Code, revoked.Body.String())
	}

	// A revoked invitation must no longer create an account.
	if _, err := store.AcceptInvitation(ctx, raw, "should-not-exist", "a-long-acceptance-password", time.Now()); err == nil {
		t.Fatal("a revoked invitation created an account")
	}
	var users int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE username='should-not-exist'`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if users != 0 {
		t.Fatalf("a revoked invitation created %d accounts", users)
	}

	if err := json.Unmarshal(adminAPIAcceptanceRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/invitations", adminAPIAcceptanceReadToken, "").Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Invitations[0].State != identity.InvitationRevoked || envelope.Invitations[0].RevokedAt == nil {
		t.Fatalf("revoked invitation = %#v", envelope.Invitations[0])
	}

	again := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/invitations/"+invitation.ID+"/revoke", adminAPIAcceptanceWriteToken, "")
	if again.Code != http.StatusNotFound {
		t.Fatalf("second revoke status = %d, body = %s", again.Code, again.Body.String())
	}
}

// A duplicate account is the caller's mistake, not a service failure, and the
// answer must never carry PostgreSQL constraint detail.
func TestAdminAPIRejectsDuplicateUserWithoutLeakingDatabaseDetail(t *testing.T) {
	_, handler, _ := newAdminAPIAcceptanceServer(t)
	body := `{"username":"duplicate","email":"duplicate@example.test","password":"a-long-acceptance-password","role":"developer"}`
	if created := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/users", adminAPIAcceptanceWriteToken, body); created.Code != http.StatusCreated {
		t.Fatalf("first create status = %d, body = %s", created.Code, created.Body.String())
	}
	duplicate := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/users", adminAPIAcceptanceWriteToken, body)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want %d: %s", duplicate.Code, http.StatusConflict, duplicate.Body.String())
	}
	for _, forbidden := range []string{"SQLSTATE", "constraint", "users_email_key", "users_username_key"} {
		if strings.Contains(duplicate.Body.String(), forbidden) {
			t.Fatalf("duplicate response leaked database detail %q: %s", forbidden, duplicate.Body.String())
		}
	}
}

func TestAdminAPIInvitationValidation(t *testing.T) {
	pool, handler, _ := newAdminAPIAcceptanceServer(t)
	for name, body := range map[string]string{
		"missing email": `{"email":"","role":"developer"}`,
		"invalid role":  `{"email":"invitee@example.test","role":"owner"}`,
	} {
		t.Run(name, func(t *testing.T) {
			response := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/invitations", adminAPIAcceptanceWriteToken, body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
	var invitations int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM invitations`).Scan(&invitations); err != nil {
		t.Fatal(err)
	}
	if invitations != 0 {
		t.Fatalf("invitations after rejected requests = %d", invitations)
	}
}

// A list endpoint must answer a bounded window and say how much remains, so a
// consumer can page instead of pulling an unbounded array as the directory
// grows.
func TestAdminAPIUserListIsBoundedAndPageable(t *testing.T) {
	_, handler, store := newAdminAPIAcceptanceServer(t)
	ctx := context.Background()
	for index := 0; index < 5; index++ {
		name := fmt.Sprintf("paged-%02d", index)
		if _, err := store.CreatePasswordUser(ctx, name, name+"@example.test", "a-long-acceptance-password", identity.RoleDeveloper); err != nil {
			t.Fatal(err)
		}
	}

	type usersEnvelope struct {
		Users []userRecord `json:"users"`
		Page  struct {
			Limit, Offset, Returned, Total int
			HasMore                        bool `json:"has_more"`
		} `json:"page"`
	}
	read := func(query string) usersEnvelope {
		t.Helper()
		response := adminAPIAcceptanceRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/users"+query, adminAPIAcceptanceReadToken, "")
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		var envelope usersEnvelope
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode users envelope: %v: %s", err, response.Body.String())
		}
		return envelope
	}

	first := read("?limit=2")
	if len(first.Users) != 2 || first.Page.Total != 5 || first.Page.Returned != 2 || !first.Page.HasMore {
		t.Fatalf("first page = %#v", first.Page)
	}
	second := read("?limit=2&offset=2")
	if len(second.Users) != 2 || second.Page.Offset != 2 || !second.Page.HasMore {
		t.Fatalf("second page = %#v", second.Page)
	}
	last := read("?limit=2&offset=4")
	if len(last.Users) != 1 || last.Page.HasMore {
		t.Fatalf("last page = %#v", last.Page)
	}
	// Pages must not overlap or repeat a record.
	seen := map[string]bool{}
	for _, page := range []usersEnvelope{first, second, last} {
		for _, user := range page.Users {
			if seen[user.ID] {
				t.Fatalf("account %s appeared on more than one page", user.Username)
			}
			seen[user.ID] = true
		}
	}
	if len(seen) != 5 {
		t.Fatalf("paging returned %d distinct accounts, want 5", len(seen))
	}

	// An unbounded request is still bounded by the store's default window.
	if envelope := read(""); envelope.Page.Limit != 100 {
		t.Fatalf("default limit = %d, want the store default", envelope.Page.Limit)
	}
	for _, invalid := range []string{"?limit=0", "?limit=501", "?limit=abc", "?offset=-1"} {
		response := adminAPIAcceptanceRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/users"+invalid, adminAPIAcceptanceReadToken, "")
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want %d", invalid, response.Code, http.StatusBadRequest)
		}
	}
}

// An identity service must be able to answer, after the fact, who did what to
// whom and from where. This proves the record is written by the operations
// themselves rather than by the test.
func TestAdminAPIRecordsAndReportsAuditEvents(t *testing.T) {
	_, handler, store := newAdminAPIAcceptanceServer(t)
	ctx := context.Background()

	created := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/users", adminAPIAcceptanceWriteToken,
		`{"username":"audited","email":"audited@example.test","password":"a-long-acceptance-password","role":"developer"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", created.Code, created.Body.String())
	}
	var receipt struct {
		User userRecord `json:"user"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if disabled := adminAPIAcceptanceRequest(t, handler, http.MethodPost,
		"https://auth.example.test/internal/users/"+receipt.User.ID+"/disable", adminAPIAcceptanceWriteToken, ""); disabled.Code != http.StatusOK {
		t.Fatalf("disable status = %d, body = %s", disabled.Code, disabled.Body.String())
	}
	// A refused sign-in must be recorded with the reason, and the reason must
	// not be the message the person was shown.
	if _, reason, err := store.AuthenticatePassword(ctx, "audited", "a-long-acceptance-password"); err == nil || reason != identity.SignInReasonDisabled {
		t.Fatalf("authenticate after disable = %q, %v", reason, err)
	}

	type auditEnvelope struct {
		SchemaVersion string              `json:"schema_version"`
		Events        []auditEventRecord  `json:"events"`
		Page          struct{ Total int } `json:"page"`
	}
	response := adminAPIAcceptanceRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/audit-events", adminAPIAcceptanceReadToken, "")
	if response.Code != http.StatusOK {
		t.Fatalf("audit status = %d, body = %s", response.Code, response.Body.String())
	}
	var envelope auditEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode audit envelope: %v: %s", err, response.Body.String())
	}
	if envelope.SchemaVersion != "shauth.audit-events/v1" || envelope.Page.Total < 2 {
		t.Fatalf("audit envelope = %#v", envelope)
	}
	recorded := map[string]auditEventRecord{}
	for _, event := range envelope.Events {
		recorded[event.EventType] = event
	}
	for _, expected := range []string{identity.AuditAccountCreated, identity.AuditAccountDisabled} {
		event, ok := recorded[expected]
		if !ok {
			t.Fatalf("no %s event was recorded: %s", expected, response.Body.String())
		}
		if event.SubjectUserID != receipt.User.ID {
			t.Fatalf("%s recorded subject %q, want %q", expected, event.SubjectUserID, receipt.User.ID)
		}
		if len(event.Details) == 0 {
			t.Fatalf("%s recorded no detail", expected)
		}
	}
	if username := recorded[identity.AuditAccountCreated].Details["username"]; username != "audited" {
		t.Fatalf("creation detail = %v, want the username", username)
	}

	// Filtering by account and by event type is what an investigation uses.
	filtered := adminAPIAcceptanceRequest(t, handler, http.MethodGet,
		"https://auth.example.test/api/v1/audit-events?event_type="+identity.AuditAccountDisabled, adminAPIAcceptanceReadToken, "")
	if err := json.Unmarshal(filtered.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Page.Total != 1 || envelope.Events[0].EventType != identity.AuditAccountDisabled {
		t.Fatalf("filtered audit = %#v", envelope)
	}
	perUser := adminAPIAcceptanceRequest(t, handler, http.MethodGet,
		"https://auth.example.test/api/v1/users/"+receipt.User.ID+"/audit-events", adminAPIAcceptanceReadToken, "")
	if err := json.Unmarshal(perUser.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Page.Total != 2 {
		t.Fatalf("per-account audit total = %d, want the two events about that account", envelope.Page.Total)
	}
}

// Metrics must describe what the store holds, not what one process saw.
func TestAdminAPIMetricsCountDurableState(t *testing.T) {
	_, handler, store := newAdminAPIAcceptanceServer(t)
	ctx := context.Background()
	for index := 0; index < 3; index++ {
		name := fmt.Sprintf("counted-%d", index)
		if _, err := store.CreatePasswordUser(ctx, name, name+"@example.test", "a-long-acceptance-password", identity.RoleDeveloper); err != nil {
			t.Fatal(err)
		}
	}
	response := adminAPIAcceptanceRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/metrics", adminAPIAcceptanceReadToken, "")
	if response.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, body = %s", response.Code, response.Body.String())
	}
	var envelope struct {
		SchemaVersion string `json:"schema_version"`
		Users         struct {
			Total            int            `json:"total"`
			ByRole           map[string]int `json:"by_role"`
			ByIdentitySource map[string]int `json:"by_identity_source"`
		} `json:"users"`
		Build struct {
			Revision string `json:"revision"`
		} `json:"build"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode metrics: %v: %s", err, response.Body.String())
	}
	if envelope.SchemaVersion != "shauth.metrics/v1" || envelope.Users.Total != 3 {
		t.Fatalf("metrics = %#v", envelope)
	}
	if envelope.Users.ByRole["developer"] != 3 || envelope.Users.ByIdentitySource["local"] != 3 {
		t.Fatalf("user breakdown = %#v", envelope.Users)
	}
	if envelope.Build.Revision == "" {
		t.Fatal("metrics did not report which build produced them")
	}
}

// TestAcceptingAnInvitationIsRecordedAndSurvivesARejectedUsername covers the
// one path that turns an invitation into an account. It is the only way an
// account appears without an administrator creating it, so it has to leave
// the same trail, and a correctable mistake must not consume the link.
func TestAcceptingAnInvitationIsRecordedAndSurvivesARejectedUsername(t *testing.T) {
	pool, server, store := newAdminAPIAcceptanceService(t)
	ctx := context.Background()
	now := time.Now()
	if _, err := store.CreatePasswordUser(ctx, "occupied", "occupied@example.test", "occupied-account-password", identity.RoleDeveloper); err != nil {
		t.Fatalf("create the account holding the contested username: %v", err)
	}
	raw, invitation, err := store.CreateInvitation(ctx, "recipient@example.test", identity.RoleDeveloper, "", now)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://auth.example.test/accept-invitation", nil)
	request.Header.Set("X-Forwarded-For", "203.0.113.20")
	request.RemoteAddr = "10.0.0.5:41234"

	if _, err := server.claimInvitation(ctx, raw, "occupied", "recipient-account-password", visitorActor(request)); err == nil {
		t.Fatal("accepting with an occupied username created an account")
	}
	if state, err := store.InvitationState(ctx, raw, now); err != nil || state != identity.InvitationPending {
		t.Fatalf("invitation state after a refused username = %q (%v), want it still usable", state, err)
	}

	user, err := server.claimInvitation(ctx, raw, "recipient", "recipient-account-password", visitorActor(request))
	if err != nil {
		t.Fatalf("accept invitation: %v", err)
	}
	if user.Email != "recipient@example.test" || user.Role != identity.RoleDeveloper {
		t.Fatalf("accepted account = %#v, want the invited address and role", user)
	}

	events, _, err := store.ListAuditEvents(ctx, identity.AuditFilter{SubjectUserID: user.ID}, identity.Page{})
	if err != nil {
		t.Fatalf("read the audit record: %v", err)
	}
	recorded := map[string]identity.AuditEvent{}
	for _, event := range events {
		recorded[event.EventType] = event
	}
	for _, expected := range []string{identity.AuditInvitationAccepted, identity.AuditAccountCreated} {
		event, ok := recorded[expected]
		if !ok {
			t.Fatalf("no %s event was recorded for the account the invitation created: %#v", expected, events)
		}
		if event.ActorUserID != "" {
			t.Fatalf("%s named actor %q, but the recipient had no account yet", expected, event.ActorUserID)
		}
		// The recipient's own address, not the gateway's, or the record
		// says every acceptance came from the same place.
		if event.RemoteAddress == nil || event.RemoteAddress.String() != "203.0.113.20" {
			t.Fatalf("%s recorded address %v, want the recipient's", expected, event.RemoteAddress)
		}
		if event.Details["username"] != "recipient" {
			t.Fatalf("%s recorded detail %v, want the chosen username", expected, event.Details)
		}
	}

	var accepted int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM invitations WHERE id=$1::uuid AND accepted_at IS NOT NULL`, invitation.ID).Scan(&accepted); err != nil {
		t.Fatal(err)
	}
	if accepted != 1 {
		t.Fatalf("invitation accepted rows = %d, want the invitation spent exactly once", accepted)
	}
	if _, err := server.claimInvitation(ctx, raw, "recipient-again", "recipient-account-password", visitorActor(request)); !errors.Is(err, identity.ErrInvitationNotAcceptable) {
		t.Fatalf("reusing a spent invitation = %v, want %v", err, identity.ErrInvitationNotAcceptable)
	}
}

// withoutChangeTime compares only the lifetimes, so an assertion never has to
// predict the moment the policy was written.
func withoutChangeTime(record sessionPolicyRecord) sessionPolicyRecord {
	record.UpdatedAt = time.Time{}
	return record
}
