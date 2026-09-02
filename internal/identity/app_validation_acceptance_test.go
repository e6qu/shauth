// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build acceptance

package identity

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAppValidationTerminalStateAndLeaseTransitionsAreSerialized(t *testing.T) {
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
	defer adminPool.Close()
	schema := "validation_" + strings.ReplaceAll(randomUUID(), "-", "")
	if _, err := adminPool.Exec(ctx, fmt.Sprintf(`
		CREATE SCHEMA %s;
		CREATE TABLE %s.app_validation_runs (LIKE public.app_validation_runs INCLUDING ALL)`, schema, schema)); err != nil {
		t.Fatalf("create isolated validation schema: %v", err)
	}
	defer func() { _, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect isolated validation schema: %v", err)
	}
	defer pool.Close()
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	terminalRunID := insertAcceptanceValidationRun(t, pool, ValidationPassed, now)
	if err := store.ExpireAbandonedAppValidation(ctx, now.Add(time.Minute)); err != nil {
		t.Fatalf("reconcile terminal validation: %v", err)
	}
	assertAcceptanceValidationState(t, pool, terminalRunID, ValidationPassed, "")
	claimed, err := store.ClaimAppValidation(ctx, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("claim with no queued validation: %v", err)
	}
	if claimed != nil {
		t.Fatalf("claim with no queued validation = %#v", claimed)
	}
	assertAcceptanceValidationState(t, pool, terminalRunID, ValidationPassed, "")

	for attempt := 0; attempt < 20; attempt++ {
		runID := insertAcceptanceValidationRun(t, pool, ValidationRunning, now.Add(time.Duration(attempt)*time.Second))
		start := make(chan struct{})
		results := make(chan error, 2)
		go func() {
			<-start
			results <- store.CompleteAppValidation(ctx, runID, ValidationPassed, "", now.Add(10*time.Minute))
		}()
		go func() {
			<-start
			results <- store.ExpireAbandonedAppValidation(ctx, now.Add(10*time.Minute))
		}()
		close(start)
		first, second := <-results, <-results
		if first != nil && second != nil {
			t.Fatalf("attempt %d: completion and expiry both failed: %v; %v", attempt, first, second)
		}
		var status, failure string
		if err := pool.QueryRow(ctx, `SELECT status,failure FROM app_validation_runs WHERE id=$1::uuid`, runID).Scan(&status, &failure); err != nil {
			t.Fatal(err)
		}
		if status != ValidationPassed && (status != ValidationFailed || failure != "validator lease expired") {
			t.Fatalf("attempt %d: terminal state = %q, failure = %q", attempt, status, failure)
		}
		if err := store.CompleteAppValidation(ctx, runID, ValidationPassed, "late worker result", now.Add(11*time.Minute)); err == nil {
			t.Fatalf("attempt %d: stale worker completion changed a terminal result", attempt)
		}
		if err := store.ExpireAbandonedAppValidation(ctx, now.Add(12*time.Minute)); err != nil {
			t.Fatalf("attempt %d: terminal expiry reconciliation: %v", attempt, err)
		}
		assertAcceptanceValidationState(t, pool, runID, status, failure)
	}
}

func TestAppValidationClaimIsBoundedByRunningConcurrencyLimit(t *testing.T) {
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
	defer adminPool.Close()
	schema := "validation_limit_" + strings.ReplaceAll(randomUUID(), "-", "")
	if _, err := adminPool.Exec(ctx, fmt.Sprintf(`
		CREATE SCHEMA %s;
		CREATE TABLE %s.app_validation_runs (LIKE public.app_validation_runs INCLUDING ALL)`, schema, schema)); err != nil {
		t.Fatalf("create isolated validation schema: %v", err)
	}
	defer func() { _, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect isolated validation schema: %v", err)
	}
	defer pool.Close()
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	running := make([]string, appValidationConcurrencyLimit)
	for i := range running {
		running[i] = insertAcceptanceRunningValidationWithLease(t, pool, now.Add(appValidationLeaseDuration))
	}
	queuedID := insertAcceptanceValidationRun(t, pool, ValidationQueued, now)

	claimed, err := store.ClaimAppValidation(ctx, now)
	if err != nil {
		t.Fatalf("claim at running concurrency limit: %v", err)
	}
	if claimed != nil {
		t.Fatalf("claim at running concurrency limit = %#v, want nil", claimed)
	}
	assertAcceptanceValidationState(t, pool, queuedID, ValidationQueued, "")

	if err := store.CompleteAppValidation(ctx, running[0], ValidationPassed, "", now); err != nil {
		t.Fatalf("free a running slot: %v", err)
	}
	claimed, err = store.ClaimAppValidation(ctx, now.Add(time.Second))
	if err != nil {
		t.Fatalf("claim below running concurrency limit: %v", err)
	}
	if claimed == nil || claimed.ID != queuedID {
		t.Fatalf("claim below running concurrency limit = %#v, want run %q", claimed, queuedID)
	}
}

// TestAppValidationClaimNeverRunsAnAppAsTargetAndWitnessConcurrently exercises
// the collision a fixed cyclic witness assignment and bounded concurrency
// created together: with only two apps registered, each is the other's
// witness in both directions, so a full re-validation sweep queues app A
// (witness B) and app B (witness A) at the same time. A's witness step signs
// B in and depends on that session surviving until A's own checks finish
// observing it; claiming B's own validation concurrently -- which exercises
// B's sign-out -- would end that session out from under A's witness step.
func TestAppValidationClaimNeverRunsAnAppAsTargetAndWitnessConcurrently(t *testing.T) {
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
	defer adminPool.Close()
	schema := "witness_conflict_" + strings.ReplaceAll(randomUUID(), "-", "")
	if _, err := adminPool.Exec(ctx, fmt.Sprintf(`
		CREATE SCHEMA %s;
		CREATE TABLE %s.managed_apps (LIKE public.managed_apps INCLUDING ALL);
		CREATE TABLE %s.app_validation_runs (LIKE public.app_validation_runs INCLUDING ALL)`, schema, schema, schema)); err != nil {
		t.Fatalf("create isolated witness-conflict schema: %v", err)
	}
	defer func() { _, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect isolated witness-conflict schema: %v", err)
	}
	defer pool.Close()
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	appAID, appBID := randomUUID(), randomUUID()
	for _, app := range []struct{ id, slug, hash string }{
		{appAID, "witness-app-a", strings.Repeat("a", 64)},
		{appBID, "witness-app-b", strings.Repeat("b", 64)},
	} {
		origin := "https://" + app.slug + ".example.test"
		if _, err := pool.Exec(ctx, `INSERT INTO managed_apps(id,slug,name,description,launch_url,oidc_client_id,oidc_contract_hash,health_url,validation_url,signed_out_url,release_revision,created_at) VALUES($1::uuid,$2,$2,'witness conflict acceptance',$3,$2,$4,$3||'/health',$3||'/validation',$3||'/signed-out','0123456789ab',now())`, app.id, app.slug, origin, app.hash); err != nil {
			t.Fatalf("insert managed app: %v", err)
		}
	}
	// Reconciling both apps' contracts queues app A (witness B) strictly before
	// app B (witness A): with only two apps registered, each is cyclically the
	// other's only eligible witness.
	if err := store.ReconcileManagedAppOIDCContract(ctx, appAID, strings.Repeat("c", 64)); err != nil {
		t.Fatalf("reconcile app A contract: %v", err)
	}
	if err := store.ReconcileManagedAppOIDCContract(ctx, appBID, strings.Repeat("d", 64)); err != nil {
		t.Fatalf("reconcile app B contract: %v", err)
	}
	var queued int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM app_validation_runs WHERE status='queued'`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 4 {
		t.Fatalf("queued validations = %d, want 4 (two directions each for app A and app B)", queued)
	}

	now := time.Now().UTC()
	claimed, err := store.ClaimAppValidation(ctx, now)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if claimed == nil || (claimed.ManagedAppID != appAID && claimed.ManagedAppID != appBID) {
		t.Fatalf("first claim = %#v, want app A or app B claimed", claimed)
	}
	claimedApp, otherApp := claimed.ManagedAppID, appBID
	if claimedApp == appBID {
		otherApp = appAID
	}
	if claimed.Witness == nil || claimed.Witness.ManagedAppID != otherApp {
		t.Fatalf("claimed run witness = %#v, want the other app (%s)", claimed.Witness, otherApp)
	}

	// Three queued runs remain: the claimed app's other direction (busy as the
	// running run's target) and the other app's two directions (busy as the
	// running run's witness). None may be claimed while this run holds the
	// lease.
	for attempt := 0; attempt < 3; attempt++ {
		blocked, err := store.ClaimAppValidation(ctx, now.Add(time.Duration(attempt+1)*time.Second))
		if err != nil {
			t.Fatalf("claim while the first run is active: %v", err)
		}
		if blocked != nil {
			t.Fatalf("claim while the first run is active = %#v, want nil (every remaining app is busy)", blocked)
		}
	}

	if err := store.CompleteAppValidation(ctx, claimed.ID, ValidationPassed, "", now.Add(10*time.Second)); err != nil {
		t.Fatalf("complete the first run: %v", err)
	}

	seenTargets := map[string]bool{}
	for i := 0; i < 3; i++ {
		next, err := store.ClaimAppValidation(ctx, now.Add(time.Duration(20+i)*time.Second))
		if err != nil {
			t.Fatalf("claim after app A's run completed: %v", err)
		}
		if next == nil {
			t.Fatalf("claim %d after app A's run completed = nil, want a queued run", i)
		}
		seenTargets[next.ManagedAppID] = true
		if err := store.CompleteAppValidation(ctx, next.ID, ValidationPassed, "", now.Add(time.Duration(30+i)*time.Second)); err != nil {
			t.Fatalf("complete claim %d: %v", i, err)
		}
	}
	if !seenTargets[appAID] || !seenTargets[appBID] {
		t.Fatalf("targets claimed after app A's run completed = %#v, want both app A and app B represented", seenTargets)
	}
}

func TestOIDCRegistrationContractChangeQueuesBothDirectionsForEveryApp(t *testing.T) {
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
	defer adminPool.Close()
	schema := "oidc_contract_" + strings.ReplaceAll(randomUUID(), "-", "")
	if _, err := adminPool.Exec(ctx, fmt.Sprintf(`
		CREATE SCHEMA %s;
		CREATE TABLE %s.managed_apps (LIKE public.managed_apps INCLUDING ALL);
		CREATE TABLE %s.app_validation_runs (LIKE public.app_validation_runs INCLUDING ALL)`, schema, schema, schema)); err != nil {
		t.Fatalf("create isolated OIDC registration schema: %v", err)
	}
	defer func() { _, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect isolated OIDC registration schema: %v", err)
	}
	defer pool.Close()
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	firstID, secondID := randomUUID(), randomUUID()
	for _, app := range []struct{ id, slug, hash string }{
		{firstID, "contract-alpha", strings.Repeat("a", 64)},
		{secondID, "contract-beta", strings.Repeat("b", 64)},
	} {
		origin := "https://" + app.slug + ".example.test"
		if _, err := pool.Exec(ctx, `INSERT INTO managed_apps(id,slug,name,description,launch_url,oidc_client_id,oidc_contract_hash,health_url,validation_url,signed_out_url,release_revision,created_at) VALUES($1::uuid,$2,$2,'OIDC contract acceptance',$3,$2,$4,$3||'/health',$3||'/validation',$3||'/signed-out','0123456789ab',now())`, app.id, app.slug, origin, app.hash); err != nil {
			t.Fatalf("insert managed app: %v", err)
		}
	}
	changedHash := strings.Repeat("c", 64)
	if err := store.ReconcileManagedAppOIDCContract(ctx, firstID, changedHash); err != nil {
		t.Fatalf("reconcile managed app OIDC contract: %v", err)
	}
	var storedHash string
	if err := pool.QueryRow(ctx, `SELECT oidc_contract_hash FROM managed_apps WHERE id=$1::uuid`, firstID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if storedHash != changedHash {
		t.Fatalf("stored OIDC registration contract hash = %q", storedHash)
	}
	var queued, fromShauth, fromApp int
	if err := pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE direction='from_shauth'),count(*) FILTER (WHERE direction='from_app') FROM app_validation_runs WHERE status='queued'`).Scan(&queued, &fromShauth, &fromApp); err != nil {
		t.Fatal(err)
	}
	if queued != 4 || fromShauth != 2 || fromApp != 2 {
		t.Fatalf("queued validations = %d (%d from Shauth, %d from app), want 4 (2, 2)", queued, fromShauth, fromApp)
	}
	if err := store.ReconcileManagedAppOIDCContract(ctx, firstID, changedHash); err != nil {
		t.Fatalf("repeat OIDC registration reconciliation: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM app_validation_runs WHERE status='queued'`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 4 {
		t.Fatalf("unchanged OIDC registration duplicated queued validations: %d", queued)
	}
}

func insertAcceptanceValidationRun(t *testing.T, pool *pgxpool.Pool, status string, now time.Time) string {
	t.Helper()
	runID := randomUUID()
	startedAt, completedAt, leaseExpiresAt := any(nil), any(nil), any(nil)
	failure := ""
	switch status {
	case ValidationRunning:
		startedAt = now.Add(-2 * time.Minute)
		leaseExpiresAt = now.Add(-time.Minute)
	case ValidationQueued:
	default:
		startedAt = now.Add(-2 * time.Minute)
		completedAt = now.Add(-time.Minute)
	}
	_, err := pool.Exec(context.Background(), `
		INSERT INTO app_validation_runs(
			id,managed_app_id,app_slug,app_name,oidc_client_id,launch_url,validation_url,signed_out_url,
			direction,release_revision,validation_contract_hash,status,requested_at,started_at,completed_at,lease_expires_at,failure)
		VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,'from_shauth','0123456789ab',$9,$10,$11,$12,$13,$14,$15)`,
		runID, randomUUID(), "validation-"+runID[:8], "Validation acceptance", "validation-"+runID,
		"https://validation.example.test/", "https://validation.example.test/me", "https://validation.example.test/signed-out",
		strings.Repeat("a", 64), status, now.Add(-3*time.Minute), startedAt, completedAt, leaseExpiresAt, failure)
	if err != nil {
		t.Fatalf("insert acceptance validation: %v", err)
	}
	return runID
}

func insertAcceptanceRunningValidationWithLease(t *testing.T, pool *pgxpool.Pool, leaseExpiresAt time.Time) string {
	t.Helper()
	runID := randomUUID()
	startedAt := leaseExpiresAt.Add(-appValidationLeaseDuration)
	_, err := pool.Exec(context.Background(), `
		INSERT INTO app_validation_runs(
			id,managed_app_id,app_slug,app_name,oidc_client_id,launch_url,validation_url,signed_out_url,
			direction,release_revision,validation_contract_hash,status,requested_at,started_at,lease_expires_at,failure)
		VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,'from_shauth','0123456789ab',$9,$10,$11,$12,$13,$14)`,
		runID, randomUUID(), "validation-"+runID[:8], "Validation acceptance", "validation-"+runID,
		"https://validation.example.test/", "https://validation.example.test/me", "https://validation.example.test/signed-out",
		strings.Repeat("a", 64), ValidationRunning, startedAt, startedAt, leaseExpiresAt, "")
	if err != nil {
		t.Fatalf("insert running acceptance validation: %v", err)
	}
	return runID
}

func assertAcceptanceValidationState(t *testing.T, pool *pgxpool.Pool, runID, expectedStatus, expectedFailure string) {
	t.Helper()
	var status, failure string
	if err := pool.QueryRow(context.Background(), `
		SELECT status,failure FROM app_validation_runs WHERE id=$1::uuid`, runID).Scan(&status, &failure); err != nil {
		t.Fatal(err)
	}
	if status != expectedStatus || failure != expectedFailure {
		t.Fatalf("validation state = status %q, failure %q; want %q, %q", status, failure, expectedStatus, expectedFailure)
	}
}
