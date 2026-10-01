// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build acceptance

package identity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// An Entra mail attribute or UPN is mutable by people other than the account
// owner. Only an address Entra itself verified may link to an existing
// account, and only to an account whose own address is verified.
func TestEntraSignInLinksAnExistingAccountOnlyThroughAVerifiedEmail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store, _ := invitationAcceptanceStore(ctx, t)

	admin, err := store.CreatePasswordUser(ctx, "entra-target", "target@entra-link.test", "target-password-1", RoleAdmin)
	if err != nil {
		t.Fatalf("create the existing administrator: %v", err)
	}
	tenant := randomUUID()

	unverified, err := store.FindOrCreateEntraUser(ctx, tenant, randomUUID(), "impostor-1", "target@entra-link.test", false)
	if err == nil {
		t.Fatalf("an unverified Entra email signed in as %s (%s), want refusal", unverified.Username, unverified.Role)
	}
	var linked int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE id=$1::uuid AND entra_object_id IS NOT NULL`, admin.ID).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if linked != 0 {
		t.Fatal("an unverified Entra email was linked to the existing administrator")
	}

	verified, err := store.FindOrCreateEntraUser(ctx, tenant, randomUUID(), "owner-1", "target@entra-link.test", true)
	if err != nil {
		t.Fatalf("a verified Entra email for the same address: %v", err)
	}
	if verified.ID != admin.ID {
		t.Fatalf("verified Entra email linked to %s, want the existing account %s", verified.ID, admin.ID)
	}
}

// Containing a compromised break-glass credential must survive a restart.
func TestBootstrapAdministratorStaysDisabledAcrossRestarts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store, _ := invitationAcceptanceStore(ctx, t)

	first, err := store.EnsureBootstrapAdmin(ctx, "break-glass@bootstrap.test", "bootstrap-password-1")
	if err != nil {
		t.Fatalf("create bootstrap administrator: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE users SET disabled_at=now() WHERE id=$1::uuid`, first.ID); err != nil {
		t.Fatalf("disable bootstrap administrator: %v", err)
	}
	restarted, err := store.EnsureBootstrapAdmin(ctx, "break-glass@bootstrap.test", "bootstrap-password-1")
	if err != nil {
		t.Fatalf("reconcile bootstrap administrator after restart: %v", err)
	}
	if restarted.DisabledAt == nil {
		t.Fatal("a restart re-enabled the disabled bootstrap administrator")
	}
	if _, _, err := store.AuthenticatePassword(ctx, restarted.Username, "bootstrap-password-1"); err == nil {
		t.Fatal("the disabled bootstrap administrator could still sign in")
	}
}

// bcrypt reads at most 72 bytes. A longer password is the person's input
// error, reported as such, not an internal fault.
func TestOverlongPasswordIsRejectedAsInvalidInput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store, _ := invitationAcceptanceStore(ctx, t)

	_, err := store.CreatePasswordUser(ctx, "overlong", "overlong@password.test", strings.Repeat("p", maxPasswordBytes+1), RoleDeveloper)
	if err == nil {
		t.Fatal("a password longer than bcrypt accepts was stored")
	}
	var invalid InvalidInputError
	if !errors.As(err, &invalid) {
		t.Fatalf("overlong password error = %v, want an invalid-input rejection", err)
	}
	if _, err := store.CreatePasswordUser(ctx, "longest", "longest@password.test", strings.Repeat("p", maxPasswordBytes), RoleDeveloper); err != nil {
		t.Fatalf("a password of exactly %d bytes: %v", maxPasswordBytes, err)
	}
}

// Password guessing is bounded per username and per address, from the same
// durable audit record every instance writes.
func TestPasswordSignInIsThrottledPerUsernameAndAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	databaseURL := os.Getenv("SHAUTH_ACCEPTANCE_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("SHAUTH_ACCEPTANCE_DATABASE_URL is required")
	}
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	t.Cleanup(adminPool.Close)
	schema := "throttle_" + strings.ReplaceAll(randomUUID(), "-", "")
	if _, err := adminPool.Exec(ctx, fmt.Sprintf(`
		CREATE SCHEMA %[1]s;
		CREATE TABLE %[1]s.audit_events (LIKE public.audit_events INCLUDING ALL)`, schema)); err != nil {
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
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	fail := func(username string, address net.IP, at time.Time) {
		t.Helper()
		if err := store.RecordAuditEvent(ctx, AuditEntry{EventType: AuditSignInFailed, RemoteAddress: address, Details: map[string]any{"method": "password", "username": username}}, at); err != nil {
			t.Fatalf("record failure: %v", err)
		}
	}
	throttled := func(username string, address net.IP) bool {
		t.Helper()
		limited, err := store.PasswordSignInThrottled(ctx, username, address, now)
		if err != nil {
			t.Fatalf("check throttle: %v", err)
		}
		return limited
	}

	target := net.ParseIP("192.0.2.10")
	for attempt := 0; attempt < PasswordFailuresPerUsername-1; attempt++ {
		fail("victim", net.ParseIP(fmt.Sprintf("198.51.100.%d", attempt+1)), now.Add(-time.Minute))
	}
	if throttled("victim", target) {
		t.Fatal("throttled below the per-username limit")
	}
	fail("victim", net.ParseIP("198.51.100.200"), now.Add(-time.Minute))
	if !throttled("victim", target) {
		t.Fatal("not throttled at the per-username limit, from a different address")
	}
	if throttled("bystander", target) {
		t.Fatal("another username was throttled by the victim's failures")
	}

	// Failures older than the window no longer count.
	for attempt := 0; attempt < PasswordFailuresPerUsername; attempt++ {
		fail("earlier", target, now.Add(-PasswordFailureWindow-time.Minute))
	}
	if throttled("earlier", net.ParseIP("192.0.2.99")) {
		t.Fatal("failures outside the window still throttled the username")
	}

	sprayer := net.ParseIP("203.0.113.5")
	for attempt := 0; attempt < PasswordFailuresPerAddress; attempt++ {
		fail(fmt.Sprintf("sprayed-%d", attempt), sprayer, now.Add(-time.Minute))
	}
	if !throttled("fresh-target", sprayer) {
		t.Fatal("an address over the per-address limit was not throttled")
	}
	if throttled("fresh-target", net.ParseIP("203.0.113.6")) {
		t.Fatal("a different address was throttled by another address's failures")
	}
}

func sessionAcceptanceStore(ctx context.Context, t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	databaseURL := os.Getenv("SHAUTH_ACCEPTANCE_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("SHAUTH_ACCEPTANCE_DATABASE_URL is required")
	}
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	t.Cleanup(adminPool.Close)
	schema := "session_" + strings.ReplaceAll(randomUUID(), "-", "")
	if _, err := adminPool.Exec(ctx, fmt.Sprintf(`
		CREATE SCHEMA %[1]s;
		CREATE TABLE %[1]s.users (LIKE public.users INCLUDING ALL);
		CREATE TABLE %[1]s.sessions (LIKE public.sessions INCLUDING ALL);
		CREATE TABLE %[1]s.session_policy (LIKE public.session_policy INCLUDING ALL);
		INSERT INTO %[1]s.session_policy SELECT * FROM public.session_policy`, schema)); err != nil {
		t.Fatalf("create isolated session schema: %v", err)
	}
	t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("connect isolated session schema: %v", err)
	}
	t.Cleanup(pool.Close)
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	return store, pool
}

// A page that polls in the background must not keep an unattended session
// alive, and an administrator who shortens the absolute lifetime ends
// sessions that are already older than the new limit.
func TestSessionActivityAndAbsoluteLifetimeFollowTheCurrentPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store, pool := sessionAcceptanceStore(ctx, t)

	user, err := store.CreatePasswordUser(ctx, "session-owner", "owner@session.test", "session-password-1", RoleDeveloper)
	if err != nil {
		t.Fatal(err)
	}
	raw, session, err := store.CreateSession(ctx, user.ID, "acceptance", net.ParseIP("192.0.2.1"), time.Now())
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	stale := time.Now().UTC().Add(-time.Minute)
	if _, err := pool.Exec(ctx, `UPDATE sessions SET last_seen_at=$2 WHERE id=$1::uuid`, session.ID, stale); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.PeekCurrentUser(ctx, raw, time.Now()); err != nil {
		t.Fatalf("peek an active session: %v", err)
	}
	var lastSeen time.Time
	if err := pool.QueryRow(ctx, `SELECT last_seen_at FROM sessions WHERE id=$1::uuid`, session.ID).Scan(&lastSeen); err != nil {
		t.Fatal(err)
	}
	if lastSeen.After(stale.Add(time.Second)) {
		t.Fatalf("a background read recorded activity: last seen %s, was %s", lastSeen, stale)
	}
	if _, _, err := store.CurrentUser(ctx, raw, time.Now()); err != nil {
		t.Fatalf("read an active session: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT last_seen_at FROM sessions WHERE id=$1::uuid`, session.ID).Scan(&lastSeen); err != nil {
		t.Fatal(err)
	}
	if !lastSeen.After(stale.Add(30 * time.Second)) {
		t.Fatal("a person's request did not record activity")
	}

	// The session began three hours ago under a long absolute lifetime.
	if _, err := pool.Exec(ctx, `UPDATE sessions SET created_at=now()-interval '3 hours' WHERE id=$1::uuid`, session.ID); err != nil {
		t.Fatal(err)
	}
	policy, err := store.SessionPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy.BrowserAbsoluteLifetime = 2 * time.Hour
	policy.BrowserIdleTimeout = time.Hour
	policy.OIDCSessionLifetime = time.Hour
	if _, err := store.UpdateSessionPolicy(ctx, policy); err != nil {
		t.Fatalf("shorten the absolute lifetime: %v", err)
	}
	if _, _, err := store.CurrentUser(ctx, raw, time.Now()); err == nil {
		t.Fatal("a session older than the shortened absolute lifetime was still accepted")
	}
}
