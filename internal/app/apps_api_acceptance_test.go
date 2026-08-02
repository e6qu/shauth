// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build acceptance

package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	"github.com/jackc/pgx/v5/pgxpool"
)

const acceptanceStatusToken = "apps-api-acceptance-status-token-0123456789ab"
const acceptanceWriteToken = "apps-api-acceptance-write-token-0123456789abc"

func acceptanceUUID(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func newAcceptanceServer(t *testing.T) (*pgxpool.Pool, http.Handler) {
	t.Helper()
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
	schema := "apps_api_" + strings.ReplaceAll(acceptanceUUID(t), "-", "")
	if _, err := adminPool.Exec(ctx, fmt.Sprintf(`
		CREATE SCHEMA %s;
		CREATE TABLE %s.managed_apps (LIKE public.managed_apps INCLUDING ALL);
		CREATE TABLE %s.app_validation_runs (LIKE public.app_validation_runs INCLUDING ALL);
		CREATE TABLE %s.app_validation_control (LIKE public.app_validation_control INCLUDING ALL);
		INSERT INTO %s.app_validation_control(singleton) VALUES (TRUE)`, schema, schema, schema, schema, schema)); err != nil {
		t.Fatalf("create isolated application API schema: %v", err)
	}
	t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("connect isolated application API schema: %v", err)
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
		config:      config.Config{PublicURL: publicURL, HydraPublicURL: publicURL, ValidationStatusToken: acceptanceStatusToken, AdminAPIWriteToken: acceptanceWriteToken},
		store:       store,
		managedApps: managedapps.New(),
		hydraPublic: httputil.NewSingleHostReverseProxy(publicURL),
	}
	return pool, server.Handler()
}

func insertAcceptanceCatalogApp(t *testing.T, pool *pgxpool.Pool, slug, healthURL string) string {
	t.Helper()
	id := acceptanceUUID(t)
	origin := "https://" + slug + ".example.test"
	if _, err := pool.Exec(context.Background(), `INSERT INTO managed_apps(id,slug,name,description,launch_url,oidc_client_id,oidc_contract_hash,health_url,validation_url,signed_out_url,release_revision,created_at) VALUES($1::uuid,$2,$2,'Application API acceptance',$3,$2,$4,$5,$3||'/validation',$3||'/signed-out','0123456789ab',now())`, id, slug, origin, strings.Repeat("a", 64), healthURL); err != nil {
		t.Fatalf("insert managed app: %v", err)
	}
	return id
}

func acceptanceAPIRequest(t *testing.T, handler http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var request *http.Request
	if body == "" {
		request = httptest.NewRequest(method, target, nil)
	} else {
		request = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	// Reads carry the status credential; queuing is a state change and
	// carries the administration write credential.
	token := acceptanceStatusToken
	if method != http.MethodGet {
		token = acceptanceWriteToken
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestApplicationsAPIListsCatalogHealthAndValidations(t *testing.T) {
	pool, handler := newAcceptanceServer(t)
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(healthy.Close)
	appID := insertAcceptanceCatalogApp(t, pool, "catalog-alpha", healthy.URL)
	insertAcceptanceCatalogApp(t, pool, "catalog-beta", "http://127.0.0.1:9/health")
	duration := int64(3200)
	witnessID := acceptanceUUID(t)
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO app_validation_runs(
			id,managed_app_id,app_slug,app_name,oidc_client_id,launch_url,validation_url,signed_out_url,
			direction,release_revision,validation_contract_hash,
			witness_managed_app_id,witness_app_slug,witness_app_name,witness_oidc_client_id,witness_launch_url,witness_validation_url,witness_signed_out_url,witness_release_revision,
			status,requested_at,started_at,completed_at,duration_milliseconds)
		VALUES ($1::uuid,$2::uuid,'catalog-alpha','catalog-alpha','catalog-alpha','https://catalog-alpha.example.test','https://catalog-alpha.example.test/validation','https://catalog-alpha.example.test/signed-out',
			'from_shauth','0123456789ab',$3,
			$4::uuid,'catalog-beta','catalog-beta','catalog-beta','https://catalog-beta.example.test','https://catalog-beta.example.test/validation','https://catalog-beta.example.test/signed-out','0123456789ab',
			'passed',now()-interval '2 minutes',now()-interval '2 minutes',now()-interval '1 minute',$5)`,
		acceptanceUUID(t), appID, strings.Repeat("b", 64), witnessID, duration); err != nil {
		t.Fatalf("insert validation run: %v", err)
	}

	response := acceptanceAPIRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/apps", "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var envelope struct {
		SchemaVersion string      `json:"schema_version"`
		ObservedAt    time.Time   `json:"observed_at"`
		Apps          []appRecord `json:"apps"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode applications envelope: %v: %s", err, response.Body.String())
	}
	if envelope.SchemaVersion != "shauth.apps/v1" || envelope.ObservedAt.IsZero() || len(envelope.Apps) != 2 {
		t.Fatalf("envelope = %#v", envelope)
	}
	alpha, beta := envelope.Apps[0], envelope.Apps[1]
	if alpha.Slug != "catalog-alpha" || beta.Slug != "catalog-beta" {
		t.Fatalf("apps = %q, %q", alpha.Slug, beta.Slug)
	}
	if !alpha.Health.Healthy || alpha.Health.StatusCode != http.StatusOK || alpha.Health.Error != "" {
		t.Fatalf("healthy app health = %#v", alpha.Health)
	}
	if beta.Health.Healthy || beta.Health.Error == "" {
		t.Fatalf("unreachable app health = %#v", beta.Health)
	}
	if alpha.Validations.FromShauth == nil || alpha.Validations.FromApp != nil {
		t.Fatalf("alpha validations = %#v", alpha.Validations)
	}
	fromShauth := alpha.Validations.FromShauth
	if fromShauth.Status != identity.ValidationPassed || fromShauth.DurationMS == nil || *fromShauth.DurationMS != duration || fromShauth.Witness != "catalog-beta" {
		t.Fatalf("alpha from_shauth = %#v", fromShauth)
	}
	if beta.Validations.FromShauth != nil || beta.Validations.FromApp != nil {
		t.Fatalf("beta validations = %#v", beta.Validations)
	}
}

func TestApplicationValidationHistoryAPIFiltersAndValidatesLimit(t *testing.T) {
	pool, handler := newAcceptanceServer(t)
	alphaID := insertAcceptanceCatalogApp(t, pool, "history-alpha", "http://127.0.0.1:9/health")
	betaID := insertAcceptanceCatalogApp(t, pool, "history-beta", "http://127.0.0.1:9/health")
	for index, appID := range []string{alphaID, betaID, alphaID} {
		if _, err := pool.Exec(context.Background(), `
			INSERT INTO app_validation_runs(
				id,managed_app_id,app_slug,app_name,oidc_client_id,launch_url,validation_url,signed_out_url,
				direction,release_revision,validation_contract_hash,status,requested_at)
			SELECT $1::uuid,id,slug,name,oidc_client_id,launch_url,validation_url,signed_out_url,'from_app',release_revision,$2,'queued',$3
			FROM managed_apps WHERE id=$4::uuid`,
			acceptanceUUID(t), fmt.Sprintf("%063d%d", 0, index), time.Date(2026, 7, 20, 12, index, 0, 0, time.UTC), appID); err != nil {
			t.Fatalf("insert validation run: %v", err)
		}
	}

	response := acceptanceAPIRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/apps/validations/history?slug=history-alpha", "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var envelope struct {
		SchemaVersion string                   `json:"schema_version"`
		Runs          []validationStatusRecord `json:"runs"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode history envelope: %v: %s", err, response.Body.String())
	}
	if envelope.SchemaVersion != "shauth.app-validation-history/v1" || len(envelope.Runs) != 2 {
		t.Fatalf("filtered envelope = %#v", envelope)
	}
	if envelope.Runs[0].Slug != "history-alpha" || envelope.Runs[1].Slug != "history-alpha" || !envelope.Runs[0].RequestedAt.After(envelope.Runs[1].RequestedAt) {
		t.Fatalf("filtered runs = %#v, want history-alpha newest first", envelope.Runs)
	}

	limited := acceptanceAPIRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/apps/validations/history?limit=1", "")
	if err := json.Unmarshal(limited.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if limited.Code != http.StatusOK || len(envelope.Runs) != 1 || envelope.Runs[0].Slug != "history-alpha" {
		t.Fatalf("limited runs = %d %#v", limited.Code, envelope.Runs)
	}

	for _, invalid := range []string{"0", "501", "garbage"} {
		response := acceptanceAPIRequest(t, handler, http.MethodGet, "https://auth.example.test/api/v1/apps/validations/history?limit="+invalid, "")
		if response.Code != http.StatusBadRequest {
			t.Fatalf("limit=%s status = %d, want %d", invalid, response.Code, http.StatusBadRequest)
		}
	}
}

func TestApplicationValidationEnqueueAPIQueuesWithoutABrowserCSRFToken(t *testing.T) {
	pool, handler := newAcceptanceServer(t)
	insertAcceptanceCatalogApp(t, pool, "trigger-alpha", "http://127.0.0.1:9/health")
	insertAcceptanceCatalogApp(t, pool, "trigger-beta", "http://127.0.0.1:9/health")

	// The full handler chain includes csrfPosts; a 202 here proves the
	// /internal/ CSRF exemption, because no CSRF cookie or form field is sent.
	response := acceptanceAPIRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/apps/validations/enqueue", `{"slug":"trigger-alpha"}`)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var receipt struct {
		SchemaVersion string                    `json:"schema_version"`
		Enqueued      []validationEnqueueRecord `json:"enqueued"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("decode enqueue receipt: %v: %s", err, response.Body.String())
	}
	expectedOne := []validationEnqueueRecord{
		{Slug: "trigger-alpha", Direction: identity.ValidationFromShauth},
		{Slug: "trigger-alpha", Direction: identity.ValidationFromApp},
	}
	if receipt.SchemaVersion != "shauth.app-validation-enqueue/v1" || len(receipt.Enqueued) != 2 || receipt.Enqueued[0] != expectedOne[0] || receipt.Enqueued[1] != expectedOne[1] {
		t.Fatalf("single-app receipt = %#v", receipt)
	}
	var queued int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM app_validation_runs WHERE status='queued' AND app_slug='trigger-alpha'`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 2 {
		t.Fatalf("queued trigger-alpha runs = %d, want 2", queued)
	}

	unknown := acceptanceAPIRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/apps/validations/enqueue", `{"slug":"trigger-unknown"}`)
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown slug status = %d, body = %s", unknown.Code, unknown.Body.String())
	}
	var failure map[string]string
	if err := json.Unmarshal(unknown.Body.Bytes(), &failure); err != nil || failure["error"] != "managed app not found" {
		t.Fatalf("unknown slug body = %s (%v)", unknown.Body.String(), err)
	}

	all := acceptanceAPIRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/apps/validations/enqueue", "")
	if all.Code != http.StatusAccepted {
		t.Fatalf("all-apps status = %d, body = %s", all.Code, all.Body.String())
	}
	if err := json.Unmarshal(all.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if len(receipt.Enqueued) != 4 {
		t.Fatalf("all-apps receipt = %#v, want both directions for both apps", receipt)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM app_validation_runs WHERE status='queued'`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 4 {
		t.Fatalf("queued runs = %d, want 4: duplicate pending contracts must collapse", queued)
	}
}
