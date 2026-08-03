// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build acceptance

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestGatewayHealthFollowsItsSessionStore covers what Shauth's catalog reads
// to decide an application is up. A gateway that cannot reach its session
// store cannot admit or refuse a single request, so it must not report ready.
func TestGatewayHealthFollowsItsSessionStore(t *testing.T) {
	databaseURL := os.Getenv("SHAUTH_ACCEPTANCE_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("SHAUTH_ACCEPTANCE_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	// Closed explicitly below to make the store unreachable; this is the
	// safety net for an earlier failure.
	t.Cleanup(pool.Close)
	issuer, err := url.Parse("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(pool, "health-acceptance", issuer.String(), "health-acceptance-cookie-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{config: Config{Issuer: issuer}, store: store}

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://console.example.test/auth/healthz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("health with a reachable session store = %d, want %d", response.Code, http.StatusOK)
	}
	if body := strings.TrimSpace(response.Body.String()); body != "ok" {
		t.Fatalf("health body = %q, want %q", body, "ok")
	}

	pool.Close()

	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://console.example.test/auth/healthz", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("health with an unreachable session store = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if body := response.Body.String(); strings.Contains(body, databaseURL) {
		t.Fatal("the health response repeated the database connection string")
	}
}
