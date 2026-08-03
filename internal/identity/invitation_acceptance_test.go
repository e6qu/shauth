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

// TestAnInvitationSurvivesARejectedAccountAndIsSpentExactlyOnce covers the
// only path that turns an invitation into an account. The recipient gets one
// link, so a username collision must leave that link usable and a successful
// acceptance must make it unusable.
func TestAnInvitationSurvivesARejectedAccountAndIsSpentExactlyOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store, _ := invitationAcceptanceStore(ctx, t)

	now := time.Now().UTC()
	inviter, err := store.CreatePasswordUser(ctx, "invitation-operator", "operator@invitation.test", "operator-password-1", RoleAdmin)
	if err != nil {
		t.Fatalf("create inviting administrator: %v", err)
	}
	occupant, err := store.CreatePasswordUser(ctx, "already-taken", "occupant@invitation.test", "occupant-password-1", RoleDeveloper)
	if err != nil {
		t.Fatalf("create the account that owns the contested username: %v", err)
	}

	token, invitation, err := store.CreateInvitation(ctx, "recipient@invitation.test", RoleDeveloper, inviter.ID, now)
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	if token == "" {
		t.Fatal("CreateInvitation returned no token for the recipient")
	}

	// A username somebody else already holds is a correctable mistake.
	if _, err := store.AcceptInvitation(ctx, token, "already-taken", "recipient-password-1", now); err == nil {
		t.Fatal("accepting with an occupied username must be refused")
	} else if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("accept with an occupied username = %v, want %v", err, ErrAlreadyExists)
	}
	if state, err := store.InvitationState(ctx, token, now); err != nil || state != InvitationPending {
		t.Fatalf("invitation state after a refused username = %q (%v), want %q", state, err, InvitationPending)
	}

	// A password below the local-credential floor is equally correctable.
	if _, err := store.AcceptInvitation(ctx, token, "recipient", "short", now); err == nil {
		t.Fatal("accepting with a password below the minimum length must be refused")
	}
	if state, err := store.InvitationState(ctx, token, now); err != nil || state != InvitationPending {
		t.Fatalf("invitation state after a refused password = %q (%v), want %q", state, err, InvitationPending)
	}

	user, err := store.AcceptInvitation(ctx, token, "recipient", "recipient-password-1", now)
	if err != nil {
		t.Fatalf("accept invitation: %v", err)
	}
	if user.Email != "recipient@invitation.test" {
		t.Fatalf("accepted account email = %q, want the invited address", user.Email)
	}
	if user.Role != RoleDeveloper {
		t.Fatalf("accepted account role = %q, want the invited role", user.Role)
	}
	if !user.EmailVerified {
		t.Fatal("an address that received the invitation link is verified by accepting it")
	}
	if user.ID == occupant.ID {
		t.Fatal("acceptance returned the existing account instead of creating one")
	}
	if _, _, err := store.AuthenticatePassword(ctx, "recipient", "recipient-password-1"); err != nil {
		t.Fatalf("sign in with the credential chosen at acceptance: %v", err)
	}

	if state, err := store.InvitationState(ctx, token, now); err != nil || state != InvitationAccepted {
		t.Fatalf("invitation state after acceptance = %q (%v), want %q", state, err, InvitationAccepted)
	}
	if _, err := store.AcceptInvitation(ctx, token, "recipient-again", "recipient-password-2", now); !errors.Is(err, ErrInvitationNotAcceptable) {
		t.Fatalf("reusing a spent invitation = %v, want %v", err, ErrInvitationNotAcceptable)
	}

	listed, total, err := store.ListInvitations(ctx, now, Page{})
	if err != nil {
		t.Fatalf("list invitations: %v", err)
	}
	if total != 1 || len(listed) != 1 {
		t.Fatalf("ListInvitations reported %d of %d, want exactly the one invitation", len(listed), total)
	}
	if listed[0].ID != invitation.ID || listed[0].State != InvitationAccepted {
		t.Fatalf("listed invitation = %+v, want %s reported as accepted", listed[0], invitation.ID)
	}
}

// TestARevokedOrExpiredInvitationCannotCreateAnAccount holds the fail-closed
// half of the contract: withdrawing or outliving a link is enough to stop it.
func TestARevokedOrExpiredInvitationCannotCreateAnAccount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store, pool := invitationAcceptanceStore(ctx, t)

	now := time.Now().UTC()
	inviter, err := store.CreatePasswordUser(ctx, "invitation-operator", "operator@invitation.test", "operator-password-1", RoleAdmin)
	if err != nil {
		t.Fatalf("create inviting administrator: %v", err)
	}

	revokedToken, revoked, err := store.CreateInvitation(ctx, "revoked@invitation.test", RoleDeveloper, inviter.ID, now)
	if err != nil {
		t.Fatalf("create invitation to revoke: %v", err)
	}
	if err := store.RevokeInvitation(ctx, revoked.ID, now); err != nil {
		t.Fatalf("revoke invitation: %v", err)
	}
	if _, err := store.AcceptInvitation(ctx, revokedToken, "revoked-recipient", "revoked-password-1", now); !errors.Is(err, ErrInvitationNotAcceptable) {
		t.Fatalf("accepting a revoked invitation = %v, want %v", err, ErrInvitationNotAcceptable)
	}
	if err := store.RevokeInvitation(ctx, revoked.ID, now); !errors.Is(err, ErrInvitationNotRevocable) {
		t.Fatalf("revoking twice = %v, want %v", err, ErrInvitationNotRevocable)
	}

	expiredToken, expired, err := store.CreateInvitation(ctx, "expired@invitation.test", RoleDeveloper, inviter.ID, now)
	if err != nil {
		t.Fatalf("create invitation to expire: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE invitations SET expires_at=$2 WHERE id=$1::uuid`, expired.ID, now.Add(-time.Minute)); err != nil {
		t.Fatalf("age the invitation past its expiry: %v", err)
	}
	if state, err := store.InvitationState(ctx, expiredToken, now); err != nil || state != InvitationExpired {
		t.Fatalf("expired invitation state = %q (%v), want %q", state, err, InvitationExpired)
	}
	if _, err := store.AcceptInvitation(ctx, expiredToken, "expired-recipient", "expired-password-1", now); !errors.Is(err, ErrInvitationNotAcceptable) {
		t.Fatalf("accepting an expired invitation = %v, want %v", err, ErrInvitationNotAcceptable)
	}

	if _, err := store.AcceptInvitation(ctx, "not-a-real-token", "stranger", "stranger-password-1", now); !errors.Is(err, ErrInvitationNotAcceptable) {
		t.Fatalf("accepting an invented token = %v, want %v", err, ErrInvitationNotAcceptable)
	}

	var accounts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&accounts); err != nil {
		t.Fatalf("count accounts: %v", err)
	}
	if accounts != 1 {
		t.Fatalf("accounts after every refused acceptance = %d, want only the inviting administrator", accounts)
	}
}

// invitationAcceptanceStore builds an isolated schema so these tests run
// against the real PostgreSQL definitions without sharing rows.
func invitationAcceptanceStore(ctx context.Context, t *testing.T) (*Store, *pgxpool.Pool) {
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
	schema := "invitation_" + strings.ReplaceAll(randomUUID(), "-", "")
	if _, err := adminPool.Exec(ctx, fmt.Sprintf(`
		CREATE SCHEMA %[1]s;
		CREATE TABLE %[1]s.users (LIKE public.users INCLUDING ALL);
		CREATE TABLE %[1]s.invitations (LIKE public.invitations INCLUDING ALL)`, schema)); err != nil {
		t.Fatalf("create isolated invitation schema: %v", err)
	}
	t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("connect isolated invitation schema: %v", err)
	}
	t.Cleanup(pool.Close)
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	return store, pool
}
