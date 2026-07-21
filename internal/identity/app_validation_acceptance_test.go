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
		CREATE TABLE %s.app_validation_runs (LIKE public.app_validation_runs INCLUDING ALL);
		CREATE TABLE %s.app_validation_control (LIKE public.app_validation_control INCLUDING ALL);
		INSERT INTO %s.app_validation_control(singleton) VALUES (TRUE)`, schema, schema, schema, schema)); err != nil {
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
	if _, err := pool.Exec(ctx, `UPDATE app_validation_control SET active_run_id=$1::uuid,next_start_at=$2 WHERE singleton=TRUE`, terminalRunID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.ExpireAbandonedAppValidation(ctx, now.Add(time.Minute)); err != nil {
		t.Fatalf("reconcile terminal active pointer: %v", err)
	}
	assertAcceptanceValidationState(t, pool, terminalRunID, ValidationPassed, "")
	if _, err := pool.Exec(ctx, `UPDATE app_validation_control SET active_run_id=$1::uuid WHERE singleton=TRUE`, terminalRunID); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimAppValidation(ctx, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("claim with terminal active pointer: %v", err)
	}
	if claimed != nil {
		t.Fatalf("claim with no queued validation = %#v", claimed)
	}
	assertAcceptanceValidationState(t, pool, terminalRunID, ValidationPassed, "")

	for attempt := 0; attempt < 20; attempt++ {
		runID := insertAcceptanceValidationRun(t, pool, ValidationRunning, now.Add(time.Duration(attempt)*time.Second))
		if _, err := pool.Exec(ctx, `UPDATE app_validation_control SET active_run_id=$1::uuid,next_start_at='1970-01-01 00:00:00+00' WHERE singleton=TRUE`, runID); err != nil {
			t.Fatal(err)
		}
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

func insertAcceptanceValidationRun(t *testing.T, pool *pgxpool.Pool, status string, now time.Time) string {
	t.Helper()
	runID := randomUUID()
	startedAt, completedAt, leaseExpiresAt := any(nil), any(nil), any(nil)
	failure := ""
	if status == ValidationRunning {
		startedAt = now.Add(-2 * time.Minute)
		leaseExpiresAt = now.Add(-time.Minute)
	} else {
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

func assertAcceptanceValidationState(t *testing.T, pool *pgxpool.Pool, runID, expectedStatus, expectedFailure string) {
	t.Helper()
	var status, failure string
	var activeRunID *string
	if err := pool.QueryRow(context.Background(), `
		SELECT run.status,run.failure,control.active_run_id::text
		FROM app_validation_runs run CROSS JOIN app_validation_control control
		WHERE run.id=$1::uuid AND control.singleton=TRUE`, runID).Scan(&status, &failure, &activeRunID); err != nil {
		t.Fatal(err)
	}
	if status != expectedStatus || failure != expectedFailure || activeRunID != nil {
		t.Fatalf("validation state = status %q, failure %q, active %#v; want %q, %q, nil", status, failure, activeRunID, expectedStatus, expectedFailure)
	}
}
