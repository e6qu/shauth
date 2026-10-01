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

// A user rule names a GitHub account by its numeric ID. A rule from before IDs
// were kept binds once, to the first account signing in with its login, and
// from then on admits only that account.
func TestGitHubUserRuleIsBoundToOneNumericAccount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store := githubIdentityAcceptanceStore(ctx, t)

	if _, err := store.CreateGitHubRoleMapping(ctx, "user", "octocat", 0, RoleAdmin); err == nil {
		t.Fatal("a user rule was created without a GitHub account ID")
	}
	if _, err := store.CreateGitHubRoleMapping(ctx, "organization", "example-org", 42, RoleAdmin); err == nil {
		t.Fatal("an organization rule was created with a GitHub account ID")
	}
	bound, err := store.CreateGitHubRoleMapping(ctx, "user", "Octocat", 583231, RoleAdmin)
	if err != nil {
		t.Fatalf("create a bound user rule: %v", err)
	}
	if bound.Target != "octocat" || bound.GitHubUserID != 583231 {
		t.Fatalf("created rule = %+v", bound)
	}
	if _, err := store.CreateGitHubRoleMapping(ctx, "user", "octocat-renamed", 583231, RoleDeveloper); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("a second rule for the same account: err = %v, want ErrAlreadyExists", err)
	}

	// A rule recorded before this release: no ID.
	var legacyID string
	if err := store.pool.QueryRow(ctx, `INSERT INTO github_role_mappings (id,kind,target,role,created_at) VALUES ($1::uuid,'user','legacy-login','developer',now()) RETURNING id::text`, randomUUID()).Scan(&legacyID); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.BindGitHubUserMapping(ctx, legacyID, 583231); err != nil || ok {
		t.Fatalf("bound a legacy rule to an account another rule names: ok=%v err=%v", ok, err)
	}
	if ok, err := store.BindGitHubUserMapping(ctx, legacyID, 1001); err != nil || !ok {
		t.Fatalf("bind the legacy rule: ok=%v err=%v", ok, err)
	}
	if ok, err := store.BindGitHubUserMapping(ctx, legacyID, 1002); err != nil || ok {
		t.Fatalf("rebound an already-bound rule: ok=%v err=%v", ok, err)
	}
	mappings, err := store.ListGitHubRoleMappings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, mapping := range mappings {
		if mapping.ID == legacyID && mapping.GitHubUserID != 1001 {
			t.Fatalf("legacy rule bound to %d, want 1001", mapping.GitHubUserID)
		}
	}

	deleted, err := store.DeleteGitHubRoleMapping(ctx, bound.ID)
	if err != nil || deleted.GitHubUserID != 583231 || deleted.Role != RoleAdmin {
		t.Fatalf("DeleteGitHubRoleMapping() = %+v, %v", deleted, err)
	}
	if _, err := store.DeleteGitHubRoleMapping(ctx, bound.ID); !errors.Is(err, ErrGitHubRoleMappingNotFound) {
		t.Fatalf("second delete: err = %v, want ErrGitHubRoleMappingNotFound", err)
	}
}

// GitHub sign-in follows the account across a rename, releases the old login
// to whoever claims it next, and reports a lost administrator role.
func TestGitHubSignInFollowsRenamesAndReportsDemotion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store := githubIdentityAcceptanceStore(ctx, t)

	original, demoted, err := store.FindOrCreateGitHubUser(ctx, 2001, "alice", "alice@github-rename.test", RoleAdmin)
	if err != nil || demoted {
		t.Fatalf("first sign-in: demoted=%v err=%v", demoted, err)
	}
	renamed, demoted, err := store.FindOrCreateGitHubUser(ctx, 2001, "alice-renamed", "alice@github-rename.test", RoleDeveloper)
	if err != nil {
		t.Fatalf("sign-in after rename: %v", err)
	}
	if renamed.ID != original.ID || renamed.GitHubLogin != "alice-renamed" || renamed.Role != RoleDeveloper || !demoted {
		t.Fatalf("after rename and demotion: %+v demoted=%v", renamed, demoted)
	}
	if _, demoted, err := store.FindOrCreateGitHubUser(ctx, 2001, "alice-renamed", "alice@github-rename.test", RoleDeveloper); err != nil || demoted {
		t.Fatalf("an unchanged developer reported demotion=%v err=%v", demoted, err)
	}

	// GitHub hands "alice-renamed" to someone else after the first account
	// renames again before signing in. The newcomer signs in as themselves,
	// and the login is released from the account that gave it up.
	newcomer, _, err := store.FindOrCreateGitHubUser(ctx, 2002, "alice-renamed", "newcomer@github-rename.test", RoleDeveloper)
	if err != nil {
		t.Fatalf("the login's new holder: %v", err)
	}
	if newcomer.ID == original.ID || newcomer.GitHubLogin != "alice-renamed" {
		t.Fatalf("the login's new holder signed in as %+v", newcomer)
	}
	var released string
	if err := store.pool.QueryRow(ctx, `SELECT COALESCE(github_login,'') FROM users WHERE id=$1::uuid`, original.ID).Scan(&released); err != nil || released != "" {
		t.Fatalf("the renamed account still records login %q (err %v)", released, err)
	}

	// The original username "alice" is now held by the first account; a
	// third person given the login "alice" is named by their numeric ID.
	third, _, err := store.FindOrCreateGitHubUser(ctx, 2003, "alice", "third@github-rename.test", RoleDeveloper)
	if err != nil {
		t.Fatalf("a GitHub login equal to another account's username: %v", err)
	}
	if third.ID == original.ID || third.Username != "github-2003" || third.GitHubLogin != "alice" {
		t.Fatalf("third account = %+v", third)
	}

	if _, err := store.pool.Exec(ctx, `UPDATE users SET disabled_at=now() WHERE id=$1::uuid`, original.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.FindOrCreateGitHubUser(ctx, 2001, "alice-renamed", "alice@github-rename.test", RoleDeveloper); !errors.Is(err, ErrUserInactive) {
		t.Fatalf("a disabled GitHub account signed in: err = %v, want ErrUserInactive", err)
	}

	granted, err := store.GitHubAccountsPossiblyGrantedBy(ctx, GitHubRoleMapping{Kind: "team", Target: "org/team", Role: RoleDeveloper})
	if err != nil {
		t.Fatal(err)
	}
	if len(granted) != 2 || !((granted[0] == newcomer.ID && granted[1] == third.ID) || (granted[0] == third.ID && granted[1] == newcomer.ID)) {
		t.Fatalf("accounts a developer team rule may grant = %v, want the active GitHub developers %s and %s", granted, newcomer.ID, third.ID)
	}
}

// Microsoft Entra ID may link to a local account through a verified email,
// but never to a GitHub-federated one: its role follows GitHub's rules.
func TestEntraSignInNeverLinksAGitHubAccount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store := githubIdentityAcceptanceStore(ctx, t)

	github, _, err := store.FindOrCreateGitHubUser(ctx, 3001, "entra-target", "shared@entra-github.test", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	entra, err := store.FindOrCreateEntraUser(ctx, randomUUID(), randomUUID(), "entra-person", "shared@entra-github.test", true)
	if err == nil && entra.ID == github.ID {
		t.Fatal("a Microsoft Entra ID sign-in was linked to a GitHub administrator")
	}
	var linked int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE id=$1::uuid AND entra_object_id IS NOT NULL`, github.ID).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if linked != 0 {
		t.Fatal("the GitHub account gained a Microsoft Entra ID link")
	}
}

func githubIdentityAcceptanceStore(ctx context.Context, t *testing.T) *Store {
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
	schema := "github_identity_" + strings.ReplaceAll(randomUUID(), "-", "")
	if _, err := adminPool.Exec(ctx, fmt.Sprintf(`
		CREATE SCHEMA %[1]s;
		CREATE TABLE %[1]s.users (LIKE public.users INCLUDING ALL);
		CREATE TABLE %[1]s.github_role_mappings (LIKE public.github_role_mappings INCLUDING ALL)`, schema)); err != nil {
		t.Fatalf("create isolated GitHub identity schema: %v", err)
	}
	t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return &Store{pool: pool}
}
