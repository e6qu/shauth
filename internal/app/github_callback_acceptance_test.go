// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build acceptance

package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	githubapi "github.com/e6qu/shauth/internal/github"
	"github.com/e6qu/shauth/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
)

// A failing GitHub API call must never disappear silently: an operator has to
// be able to see it in the logs, and every sign-in attempt -- successful or
// not -- has to leave an audit trail an administrator can review. Both of
// those went missing for every error branch of githubCallback until this
// fix, which is why an operator investigating "could not read GitHub
// identity" reports found neither a log line nor an audit_events row to
// diagnose from.
func TestGitHubCallbackRecordsAFailedSignInWhenGitHubRejectsTheRequest(t *testing.T) {
	databaseURL := os.Getenv("SHAUTH_ACCEPTANCE_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("SHAUTH_ACCEPTANCE_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	t.Cleanup(adminPool.Close)
	schema := "github_callback_" + strings.ReplaceAll(acceptanceUUID(t), "-", "")
	if _, err := adminPool.Exec(ctx, fmt.Sprintf(`
		CREATE SCHEMA %s;
		CREATE TABLE %s.audit_events (LIKE public.audit_events INCLUDING ALL)`, schema, schema)); err != nil {
		t.Fatalf("create isolated schema: %v", err)
	}
	t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("connect isolated schema: %v", err)
	}
	t.Cleanup(pool.Close)
	store, err := identity.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	// This fixture GitHub API accepts the OAuth code exchange (so the
	// callback reaches Profile) but answers /user the way a genuine GitHub
	// outage or API rejection would: with an error status, no body Profile
	// can decode.
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "gho_fixture", "token_type": "bearer"})
		case "/user":
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			t.Fatalf("unexpected GitHub API request: %s", r.URL.Path)
		}
	}))
	defer github.Close()

	githubClient, err := githubapi.NewClient(github.Client(), githubapi.WithBaseURL(github.URL))
	if err != nil {
		t.Fatal(err)
	}

	templates, err := template.New("pages").Funcs(templateHelpers()).Parse(pageTemplates)
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	publicURL, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		store:     store,
		templates: templates,
		github:    githubClient,
		oauth: &oauth2.Config{
			ClientID:     "fixture-client",
			ClientSecret: "fixture-secret",
			Endpoint:     oauth2.Endpoint{TokenURL: github.URL + "/login/oauth/access_token"},
			RedirectURL:  publicURL.String() + "/oauth/github/callback",
		},
	}

	state := hex.EncodeToString(mustRandomBytes(t, 32))
	request := httptest.NewRequest(http.MethodGet, "/oauth/github/callback?state="+state+"&code=fixture-code", http.NoBody)
	request.AddCookie(&http.Cookie{Name: githubStateCookieName(state), Value: "/"})
	recorder := httptest.NewRecorder()

	server.githubCallback(recorder, request)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body: %s", recorder.Code, http.StatusBadGateway, recorder.Body.String())
	}

	var eventType, details string
	row := pool.QueryRow(context.Background(), "SELECT event_type, details::text FROM audit_events ORDER BY created_at DESC LIMIT 1")
	if err := row.Scan(&eventType, &details); err != nil {
		t.Fatalf("read audit event: %v", err)
	}
	if eventType != identity.AuditSignInFailed {
		t.Fatalf("event_type = %q, want %q", eventType, identity.AuditSignInFailed)
	}
	if !strings.Contains(details, "reason") {
		t.Fatalf("audit details lack a failure reason: %s", details)
	}
}

func mustRandomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
