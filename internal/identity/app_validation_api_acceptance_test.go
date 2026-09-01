// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build acceptance

package identity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func newAcceptanceValidationStore(t *testing.T, prefix string) (*pgxpool.Pool, *Store) {
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
	schema := prefix + "_" + strings.ReplaceAll(randomUUID(), "-", "")
	if _, err := adminPool.Exec(ctx, fmt.Sprintf(`
		CREATE SCHEMA %s;
		CREATE TABLE %s.managed_apps (LIKE public.managed_apps INCLUDING ALL);
		CREATE TABLE %s.app_validation_runs (LIKE public.app_validation_runs INCLUDING ALL)`, schema, schema, schema)); err != nil {
		t.Fatalf("create isolated validation schema: %v", err)
	}
	t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect isolated validation schema: %v", err)
	}
	t.Cleanup(pool.Close)
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	return pool, store
}

func insertAcceptanceManagedApp(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	id := randomUUID()
	origin := "https://" + slug + ".example.test"
	if _, err := pool.Exec(context.Background(), `INSERT INTO managed_apps(id,slug,name,description,launch_url,oidc_client_id,oidc_contract_hash,health_url,validation_url,signed_out_url,release_revision,created_at) VALUES($1::uuid,$2,$2,'Validation API acceptance',$3,$2,$4,$3||'/health',$3||'/validation',$3||'/signed-out','0123456789ab',now())`, id, slug, origin, strings.Repeat("a", 64)); err != nil {
		t.Fatalf("insert managed app: %v", err)
	}
	return id
}

func TestEnqueueAppValidationsBySlugQueuesBothDirectionsWithoutARequester(t *testing.T) {
	pool, store := newAcceptanceValidationStore(t, "enqueue_slug")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	insertAcceptanceManagedApp(t, pool, "enqueue-alpha")
	insertAcceptanceManagedApp(t, pool, "enqueue-beta")

	if _, err := store.EnqueueAppValidations(ctx, ManagedAppRef{Slug: "enqueue-alpha"}, "", time.Now()); err != nil {
		t.Fatalf("enqueue by slug: %v", err)
	}
	var queued, fromShauth, fromApp, requesters int
	if err := pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE direction='from_shauth'),count(*) FILTER (WHERE direction='from_app'),count(requested_by) FROM app_validation_runs WHERE status='queued' AND app_slug='enqueue-alpha'`).Scan(&queued, &fromShauth, &fromApp, &requesters); err != nil {
		t.Fatal(err)
	}
	if queued != 2 || fromShauth != 1 || fromApp != 1 || requesters != 0 {
		t.Fatalf("queued = %d (%d from Shauth, %d from app, %d requesters), want 2 (1, 1, 0)", queued, fromShauth, fromApp, requesters)
	}
	var witness *string
	if err := pool.QueryRow(ctx, `SELECT witness_app_slug FROM app_validation_runs WHERE app_slug='enqueue-alpha' AND direction='from_shauth'`).Scan(&witness); err != nil {
		t.Fatal(err)
	}
	if witness == nil || *witness != "enqueue-beta" {
		t.Fatalf("witness = %v, want enqueue-beta", witness)
	}

	_, err := store.EnqueueAppValidations(ctx, ManagedAppRef{Slug: "enqueue-unknown"}, "", time.Now())
	if !errors.Is(err, ErrManagedAppNotFound) {
		t.Fatalf("unknown slug error = %v, want ErrManagedAppNotFound", err)
	}
}

func TestEnqueueAllAppValidationsReturnsSlugsAndCollapsesDuplicates(t *testing.T) {
	pool, store := newAcceptanceValidationStore(t, "enqueue_all")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	insertAcceptanceManagedApp(t, pool, "fleet-alpha")
	insertAcceptanceManagedApp(t, pool, "fleet-beta")

	if _, err := store.EnqueueAppValidations(ctx, ManagedAppRef{Slug: "fleet-alpha"}, "", time.Now()); err != nil {
		t.Fatalf("prime one app: %v", err)
	}
	slugs, err := store.EnqueueAppValidations(ctx, ManagedAppRef{}, "", time.Now())
	if err != nil {
		t.Fatalf("enqueue all: %v", err)
	}
	if len(slugs) != 2 || slugs[0] != "fleet-alpha" || slugs[1] != "fleet-beta" {
		t.Fatalf("enqueued slugs = %v, want [fleet-alpha fleet-beta]", slugs)
	}
	var queued int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM app_validation_runs WHERE status='queued'`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 4 {
		t.Fatalf("queued = %d, want 4: identical pending contracts must collapse", queued)
	}
}

func TestAppValidationRunHistoryOrdersFiltersAndLimits(t *testing.T) {
	pool, store := newAcceptanceValidationStore(t, "history")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	duration := int64(2500)
	insert := func(slug, direction, status string, requestedAt time.Time, withDuration, withWitness bool) string {
		t.Helper()
		id := randomUUID()
		var startedAt, completedAt, storedDuration any
		var witnessID, witnessSlug, witnessName, witnessClientID, witnessLaunchURL, witnessValidationURL, witnessSignedOutURL, witnessRevision any
		if status == ValidationPassed || status == ValidationFailed {
			startedAt, completedAt = requestedAt.Add(time.Second), requestedAt.Add(time.Minute)
			if withDuration {
				storedDuration = duration
			}
		}
		if withWitness {
			witnessID, witnessSlug, witnessName, witnessClientID = randomUUID(), slug+"-witness", slug+"-witness", slug+"-witness"
			witnessLaunchURL = "https://" + slug + "-witness.example.test"
			witnessValidationURL, witnessSignedOutURL, witnessRevision = witnessLaunchURL, witnessLaunchURL, "0123456789ab"
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO app_validation_runs(
				id,managed_app_id,app_slug,app_name,oidc_client_id,launch_url,validation_url,signed_out_url,
				direction,release_revision,validation_contract_hash,
				witness_managed_app_id,witness_app_slug,witness_app_name,witness_oidc_client_id,witness_launch_url,witness_validation_url,witness_signed_out_url,witness_release_revision,
				status,requested_at,started_at,completed_at,duration_milliseconds)
			VALUES ($1::uuid,$2::uuid,$3,$3,$3,'https://'||$3||'.example.test','https://'||$3||'.example.test/validation','https://'||$3||'.example.test/signed-out',
				$4,'0123456789ab',$5,
				$6::uuid,$7,$8,$9,$10,$11,$12,$13,
				$14,$15,$16,$17,$18)`,
			id, randomUUID(), slug, direction, strings.Repeat("b", 64),
			witnessID, witnessSlug, witnessName, witnessClientID, witnessLaunchURL, witnessValidationURL, witnessSignedOutURL, witnessRevision,
			status, requestedAt, startedAt, completedAt, storedDuration); err != nil {
			t.Fatalf("insert validation run: %v", err)
		}
		return id
	}
	oldest := insert("history-alpha", ValidationFromShauth, ValidationPassed, base, true, true)
	middle := insert("history-beta", ValidationFromApp, ValidationFailed, base.Add(time.Hour), true, false)
	newest := insert("history-alpha", ValidationFromApp, ValidationQueued, base.Add(2*time.Hour), false, false)

	runs, err := store.AppValidationRunHistory(ctx, "", 50)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(runs) != 3 || runs[0].ID != newest || runs[1].ID != middle || runs[2].ID != oldest {
		t.Fatalf("history order = %#v, want newest first", runs)
	}
	if runs[2].DurationMilliseconds == nil || *runs[2].DurationMilliseconds != duration {
		t.Fatalf("terminal run duration = %v, want %d", runs[2].DurationMilliseconds, duration)
	}
	if runs[2].Witness == nil || runs[2].Witness.AppSlug != "history-alpha-witness" {
		t.Fatalf("terminal run witness = %#v, want history-alpha-witness", runs[2].Witness)
	}

	filtered, err := store.AppValidationRunHistory(ctx, "history-alpha", 50)
	if err != nil {
		t.Fatalf("filtered history: %v", err)
	}
	if len(filtered) != 2 || filtered[0].ID != newest || filtered[1].ID != oldest {
		t.Fatalf("filtered history = %#v, want the two history-alpha runs newest first", filtered)
	}

	limited, err := store.AppValidationRunHistory(ctx, "", 1)
	if err != nil {
		t.Fatalf("limited history: %v", err)
	}
	if len(limited) != 1 || limited[0].ID != newest {
		t.Fatalf("limited history = %#v, want only the newest run", limited)
	}

	empty, err := store.AppValidationRunHistory(ctx, "history-unknown", 50)
	if err != nil || len(empty) != 0 {
		t.Fatalf("unknown slug history = %#v, %v; want empty", empty, err)
	}
}
