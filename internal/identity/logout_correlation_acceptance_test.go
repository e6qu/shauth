// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build acceptance

package identity

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLogoutCorrelationGrantIsAtomicAndExpires(t *testing.T) {
	databaseURL := os.Getenv("SHAUTH_ACCEPTANCE_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("SHAUTH_ACCEPTANCE_DATABASE_URL is required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pool.Close()
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	userID, sessionID, familyID := randomUUID(), randomUUID(), randomUUID()
	futureSessionID, futureFamilyID := randomUUID(), randomUUID()
	suffix := strings.ReplaceAll(userID, "-", "")
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,email,role,created_at,email_verified) VALUES ($1::uuid,$2,$3,'developer',$4,TRUE)`, userID, "logout-"+suffix, "logout-"+suffix+"@example.test", now); err != nil {
		t.Fatalf("create acceptance user: %v", err)
	}
	defer func() {
		_, _ = pool.Exec(ctx, `DELETE FROM logout_correlation_grants WHERE subject_id=$1::uuid`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM hydra_login_sessions WHERE browser_session_id=ANY($1::uuid[])`, []string{sessionID, futureSessionID})
		_, _ = pool.Exec(ctx, `DELETE FROM sessions WHERE id=ANY($1::uuid[])`, []string{sessionID, futureSessionID})
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, userID)
	}()
	if _, err := pool.Exec(ctx, `INSERT INTO sessions(id,user_id,refresh_family_id,created_at,last_seen_at,expires_at,user_agent,remote_address) VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$4,$5,'logout acceptance','127.0.0.1')`, sessionID, userID, familyID, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("create acceptance session: %v", err)
	}
	for _, providerSessionID := range []string{"provider-current-a", "provider-current-b", "provider-remote"} {
		if err := store.RecordHydraLoginSession(ctx, sessionID, providerSessionID, now); err != nil {
			t.Fatal(err)
		}
	}

	raw, createdGrant, err := store.CreateLogoutCorrelationGrant(ctx, userID, sessionID, "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO sessions(id,user_id,refresh_family_id,created_at,last_seen_at,expires_at,user_agent,remote_address) VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$4,$5,'future logout acceptance','127.0.0.1')`, futureSessionID, userID, futureFamilyID, now.Add(time.Second), now.Add(time.Hour)); err != nil {
		t.Fatalf("create future acceptance session: %v", err)
	}
	if err := store.RevokeSessions(ctx, createdGrant.ActiveBrowserSessionIDs, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	var originalRevoked, futureRevoked bool
	if err := pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM sessions WHERE id=$1::uuid`, sessionID).Scan(&originalRevoked); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM sessions WHERE id=$1::uuid`, futureSessionID).Scan(&futureRevoked); err != nil {
		t.Fatal(err)
	}
	if !originalRevoked || futureRevoked {
		t.Fatalf("snapshot revocation original=%t future=%t", originalRevoked, futureRevoked)
	}
	var successes int
	var failures []error
	var mutex sync.Mutex
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			grant, err := store.ConsumeLogoutCorrelationGrant(ctx, raw, userID, now.Add(time.Second))
			mutex.Lock()
			defer mutex.Unlock()
			if err != nil {
				failures = append(failures, err)
				return
			}
			successes++
			if grant.ID != createdGrant.ID ||
				!slices.Equal(grant.ActiveBrowserSessionIDs, createdGrant.ActiveBrowserSessionIDs) ||
				!slices.Equal(grant.BrowserHydraSessionIDs, createdGrant.BrowserHydraSessionIDs) ||
				!slices.Equal(grant.ActiveHydraSessionIDs, createdGrant.ActiveHydraSessionIDs) {
				failures = append(failures, fmt.Errorf("consumed grant snapshot = %#v, want %#v", grant, createdGrant))
			}
		}()
	}
	workers.Wait()
	if successes != 1 || len(failures) != 1 || !strings.Contains(failures[0].Error(), "unavailable") {
		t.Fatalf("atomic consume successes=%d failures=%v", successes, failures)
	}
	claimed, err := store.ClaimAbandonedLogoutCorrelationGrant(ctx, now.Add(LogoutCompletionLifetime))
	if err != nil {
		t.Fatal(err)
	}
	if claimed != nil {
		t.Fatalf("consumed browser flow was recovered before its completion window: %#v", claimed)
	}
	claimed, err = store.ClaimAbandonedLogoutCorrelationGrant(ctx, now.Add(LogoutCompletionLifetime+2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if claimed == nil || claimed.ID != createdGrant.ID {
		t.Fatalf("consumed browser flow was not recoverable after its completion window: %#v", claimed)
	}
	if err := store.CompleteLogoutCorrelationGrant(ctx, createdGrant.ID, now.Add(LogoutCompletionLifetime+3*time.Second)); err != nil {
		t.Fatal(err)
	}

	if err := store.RecordHydraLoginSession(ctx, futureSessionID, "provider-future", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	staleRaw, staleGrant, err := store.CreateLogoutCorrelationGrant(ctx, userID, futureSessionID, "", "", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeLogoutCorrelationGrant(ctx, staleRaw, userID, now.Add(LogoutCorrelationLifetime+time.Second)); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("stale grant was not rejected: %v", err)
	}
	claimed, err = store.ClaimAbandonedLogoutCorrelationGrant(ctx, now.Add(LogoutCorrelationLifetime+time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if claimed == nil || claimed.ID != staleGrant.ID || len(claimed.ActiveBrowserSessionIDs) != 1 || len(claimed.BrowserHydraSessionIDs) != 1 || len(claimed.ActiveHydraSessionIDs) != 1 {
		t.Fatalf("claimed stale grant = %#v", claimed)
	}
	deleted, err := store.DeleteCompletedLogoutCorrelationGrants(ctx, now.Add(LogoutCompletionLifetime+4*time.Second), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("deleted completed grants = %d, want 1", deleted)
	}
	var completedCount, incompleteCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE id=$1::uuid),count(*) FILTER (WHERE id=$2::uuid) FROM logout_correlation_grants WHERE id IN ($1::uuid,$2::uuid)`, createdGrant.ID, staleGrant.ID).Scan(&completedCount, &incompleteCount); err != nil {
		t.Fatal(err)
	}
	if completedCount != 0 || incompleteCount != 1 {
		t.Fatalf("garbage collection completed=%d incomplete=%d", completedCount, incompleteCount)
	}
	for _, deletion := range []struct {
		statement string
		argument  any
	}{
		{`DELETE FROM hydra_login_sessions WHERE browser_session_id=ANY($1::uuid[])`, []string{sessionID, futureSessionID}},
		{`DELETE FROM sessions WHERE id=$1::uuid`, sessionID},
		{`DELETE FROM sessions WHERE id=$1::uuid`, futureSessionID},
		{`DELETE FROM users WHERE id=$1::uuid`, userID},
	} {
		if _, err := pool.Exec(ctx, deletion.statement, deletion.argument); err != nil {
			t.Fatalf("remove identity retention row: %v", err)
		}
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM logout_correlation_grants WHERE id=$1::uuid`, staleGrant.ID).Scan(&incompleteCount); err != nil {
		t.Fatal(err)
	}
	if incompleteCount != 1 {
		t.Fatal("unfinished recovery evidence was deleted with its browser session")
	}
}

func TestLogoutCorrelationGrantPersistsEmptyInitiatorProviderSnapshot(t *testing.T) {
	databaseURL := os.Getenv("SHAUTH_ACCEPTANCE_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("SHAUTH_ACCEPTANCE_DATABASE_URL is required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pool.Close()
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	userID := randomUUID()
	initiatorSessionID, initiatorFamilyID := randomUUID(), randomUUID()
	witnessSessionID, witnessFamilyID := randomUUID(), randomUUID()
	suffix := strings.ReplaceAll(userID, "-", "")
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,email,role,created_at,email_verified) VALUES ($1::uuid,$2,$3,'developer',$4,TRUE)`, userID, "mixed-logout-"+suffix, "mixed-logout-"+suffix+"@example.test", now); err != nil {
		t.Fatalf("create acceptance user: %v", err)
	}
	defer func() {
		_, _ = pool.Exec(ctx, `DELETE FROM logout_correlation_grants WHERE subject_id=$1::uuid`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM hydra_login_sessions WHERE browser_session_id=ANY($1::uuid[])`, []string{initiatorSessionID, witnessSessionID})
		_, _ = pool.Exec(ctx, `DELETE FROM sessions WHERE id=ANY($1::uuid[])`, []string{initiatorSessionID, witnessSessionID})
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, userID)
	}()
	for _, session := range []struct{ id, family string }{{initiatorSessionID, initiatorFamilyID}, {witnessSessionID, witnessFamilyID}} {
		if _, err := pool.Exec(ctx, `INSERT INTO sessions(id,user_id,refresh_family_id,created_at,last_seen_at,expires_at,user_agent,remote_address) VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$4,$5,'mixed logout acceptance','127.0.0.1')`, session.id, userID, session.family, now, now.Add(time.Hour)); err != nil {
			t.Fatalf("create acceptance session: %v", err)
		}
	}
	if err := store.RecordHydraLoginSession(ctx, witnessSessionID, "provider-witness", now); err != nil {
		t.Fatal(err)
	}

	raw, grant, err := store.CreateLogoutCorrelationGrant(ctx, userID, initiatorSessionID, "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || grant.BrowserHydraSessionIDs == nil || len(grant.BrowserHydraSessionIDs) != 0 {
		t.Fatalf("initiator provider snapshot = %#v, raw token present=%t", grant.BrowserHydraSessionIDs, raw != "")
	}
	if !slices.Equal(grant.ActiveHydraSessionIDs, []string{"provider-witness"}) {
		t.Fatalf("active provider snapshot = %#v", grant.ActiveHydraSessionIDs)
	}
	var browserProviderCount, activeProviderCount int
	if err := pool.QueryRow(ctx, `SELECT cardinality(browser_hydra_session_ids),cardinality(active_hydra_session_ids) FROM logout_correlation_grants WHERE id=$1::uuid`, grant.ID).Scan(&browserProviderCount, &activeProviderCount); err != nil {
		t.Fatal(err)
	}
	if browserProviderCount != 0 || activeProviderCount != 1 {
		t.Fatalf("stored provider snapshot cardinalities = initiator %d, active %d", browserProviderCount, activeProviderCount)
	}
	consumed, err := store.ConsumeLogoutCorrelationGrant(ctx, raw, userID, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if consumed.BrowserHydraSessionIDs == nil || len(consumed.BrowserHydraSessionIDs) != 0 || !slices.Equal(consumed.ActiveHydraSessionIDs, []string{"provider-witness"}) {
		t.Fatalf("consumed provider snapshot = initiator %#v, active %#v", consumed.BrowserHydraSessionIDs, consumed.ActiveHydraSessionIDs)
	}
}

func TestLogoutSerializationPreservesACompleteOrdering(t *testing.T) {
	databaseURL := os.Getenv("SHAUTH_ACCEPTANCE_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("SHAUTH_ACCEPTANCE_DATABASE_URL is required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pool.Close()
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("concurrent browser session creation", func(t *testing.T) {
		for iteration := range 20 {
			userID := createLogoutAcceptanceUser(t, ctx, pool, "create", iteration)
			_, browser, err := store.CreateSession(ctx, userID, "logout race baseline", nil, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			providerSID := fmt.Sprintf("provider-create-%d-%s", iteration, userID)
			if err := store.RecordHydraLoginSession(ctx, browser.ID, providerSID, time.Now()); err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			type createResult struct {
				session Session
				err     error
			}
			created := make(chan createResult, 1)
			type logoutResult struct {
				grant LogoutCorrelationGrant
				err   error
			}
			loggedOut := make(chan logoutResult, 1)
			go func() {
				<-start
				_, session, err := store.CreateSession(ctx, userID, "logout race concurrent", nil, time.Now())
				created <- createResult{session: session, err: err}
			}()
			go func() {
				<-start
				_, grant, err := store.CreateLogoutCorrelationGrant(ctx, userID, browser.ID, "", "", time.Now())
				loggedOut <- logoutResult{grant: grant, err: err}
			}()
			close(start)
			createOutcome, logoutOutcome := <-created, <-loggedOut
			if createOutcome.err != nil || logoutOutcome.err != nil {
				t.Fatalf("iteration %d create=%v logout=%v", iteration, createOutcome.err, logoutOutcome.err)
			}
			var revoked bool
			if err := pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM sessions WHERE id=$1::uuid`, createOutcome.session.ID).Scan(&revoked); err != nil {
				t.Fatal(err)
			}
			captured := slices.Contains(logoutOutcome.grant.ActiveBrowserSessionIDs, createOutcome.session.ID)
			if captured != revoked {
				t.Fatalf("iteration %d captured=%t revoked=%t; session was neither coherently before nor after logout", iteration, captured, revoked)
			}
			deleteLogoutAcceptanceUser(t, ctx, pool, userID)
		}
	})

	t.Run("concurrent Ory Hydra session correlation", func(t *testing.T) {
		for iteration := range 20 {
			userID := createLogoutAcceptanceUser(t, ctx, pool, "hydra", iteration)
			_, browser, err := store.CreateSession(ctx, userID, "Hydra logout race", nil, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			providerSID := fmt.Sprintf("provider-hydra-%d-%s", iteration, userID)
			start := make(chan struct{})
			recorded := make(chan error, 1)
			type logoutResult struct {
				raw   string
				grant LogoutCorrelationGrant
				err   error
			}
			loggedOut := make(chan logoutResult, 1)
			go func() {
				<-start
				recorded <- store.RecordHydraLoginSession(ctx, browser.ID, providerSID, time.Now())
			}()
			go func() {
				<-start
				raw, grant, err := store.CreateLogoutCorrelationGrant(ctx, userID, browser.ID, "", "", time.Now())
				loggedOut <- logoutResult{raw: raw, grant: grant, err: err}
			}()
			close(start)
			recordErr, logoutOutcome := <-recorded, <-loggedOut
			if logoutOutcome.err != nil {
				t.Fatalf("iteration %d logout: %v", iteration, logoutOutcome.err)
			}
			if recordErr == nil {
				if logoutOutcome.raw == "" || !slices.Contains(logoutOutcome.grant.ActiveHydraSessionIDs, providerSID) {
					t.Fatalf("iteration %d accepted provider correlation was omitted from logout evidence: %#v", iteration, logoutOutcome.grant)
				}
			} else if logoutOutcome.raw != "" || len(logoutOutcome.grant.ActiveHydraSessionIDs) != 0 {
				t.Fatalf("iteration %d rejected provider correlation leaked into logout evidence: record=%v grant=%#v", iteration, recordErr, logoutOutcome.grant)
			}
			deleteLogoutAcceptanceUser(t, ctx, pool, userID)
		}
	})
}

func TestStaleProviderLogoutDoesNotRevokeFreshSessions(t *testing.T) {
	databaseURL := os.Getenv("SHAUTH_ACCEPTANCE_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("SHAUTH_ACCEPTANCE_DATABASE_URL is required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pool.Close()
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	userID := createLogoutAcceptanceUser(t, ctx, pool, "stale", 0)
	defer deleteLogoutAcceptanceUser(t, ctx, pool, userID)
	now := time.Now().UTC()
	_, oldBrowser, err := store.CreateSession(ctx, userID, "old browser", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	oldProviderSID := "old-provider-" + userID
	if err := store.RecordHydraLoginSession(ctx, oldBrowser.ID, oldProviderSID, now); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeSession(ctx, oldBrowser.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, freshBrowser, err := store.CreateSession(ctx, userID, "fresh browser", nil, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	freshProviderSID := "fresh-provider-" + userID
	if err := store.RecordHydraLoginSession(ctx, freshBrowser.ID, freshProviderSID, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	clientID := "stale-client-" + strings.ReplaceAll(userID, "-", "")
	if _, err := store.CreateManagedApp(ctx, ManagedApp{Slug: "stale-" + strings.ReplaceAll(userID, "-", "")[:12], Name: "Stale provider acceptance", Description: "Exact provider-only logout coverage.", LaunchURL: "https://stale.example.test/", OIDCClientID: clientID, HealthURL: "https://stale.example.test/healthz", ValidationURL: "https://stale.example.test/me", SignedOutURL: "https://stale.example.test/signed-out", ReleaseRevision: "0123456789ab"}); err != nil {
		t.Fatal(err)
	}
	raw, grant, err := store.CreateLogoutCorrelationGrant(ctx, userID, "", oldProviderSID, clientID, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || len(grant.ActiveBrowserSessionIDs) != 0 || !slices.Equal(grant.ActiveHydraSessionIDs, []string{oldProviderSID}) || grant.SignedOutURL != "https://stale.example.test/signed-out" {
		t.Fatalf("provider-only grant = %#v", grant)
	}
	var freshRevoked bool
	if err := pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM sessions WHERE id=$1::uuid`, freshBrowser.ID).Scan(&freshRevoked); err != nil {
		t.Fatal(err)
	}
	if freshRevoked {
		t.Fatal("stale provider logout revoked the fresh Shauth session")
	}
}

func createLogoutAcceptanceUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, prefix string, iteration int) string {
	t.Helper()
	userID := randomUUID()
	suffix := strings.ReplaceAll(userID, "-", "")
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,email,role,created_at,email_verified) VALUES ($1::uuid,$2,$3,'developer',now(),TRUE)`, userID, fmt.Sprintf("%s-%d-%s", prefix, iteration, suffix), fmt.Sprintf("%s-%d-%s@example.test", prefix, iteration, suffix)); err != nil {
		t.Fatal(err)
	}
	return userID
}

func deleteLogoutAcceptanceUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID string) {
	t.Helper()
	for _, query := range []string{
		`DELETE FROM logout_correlation_grants WHERE subject_id=$1::uuid`,
		`DELETE FROM managed_apps WHERE oidc_client_id='stale-client-' || replace($1::text,'-','')`,
		`DELETE FROM hydra_login_sessions WHERE browser_session_id IN (SELECT id FROM sessions WHERE user_id=$1::uuid)`,
		`DELETE FROM refresh_tokens WHERE session_id IN (SELECT id FROM sessions WHERE user_id=$1::uuid)`,
		`DELETE FROM sessions WHERE user_id=$1::uuid`,
		`DELETE FROM users WHERE id=$1::uuid`,
	} {
		if _, err := pool.Exec(ctx, query, userID); err != nil {
			t.Fatalf("clean logout acceptance fixture: %v", err)
		}
	}
}
