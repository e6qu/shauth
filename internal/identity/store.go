// SPDX-License-Identifier: AGPL-3.0-or-later

// Package identity persists Shauth users and browser sessions in PostgreSQL.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

const sessionLifetime = 30 * 24 * time.Hour

type Role string

const (
	RoleDeveloper Role = "developer"
	RoleAdmin     Role = "admin"
)

type User struct {
	ID          string
	Username    string
	Email       string
	GitHubLogin string
	Role        Role
	DisabledAt  *time.Time
	CreatedAt   time.Time
}

type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
	UserAgent string
	RemoteIP  net.IP
}
type Invitation struct {
	ID        string
	Email     string
	Role      Role
	ExpiresAt time.Time
}
type GitHubRoleMapping struct {
	ID        string
	Kind      string
	Target    string
	Role      Role
	CreatedAt time.Time
}
type ManagedApp struct {
	ID            string
	Slug          string
	Name          string
	Description   string
	LaunchURL     string
	OIDCClientID  string
	HealthURL     string
	MonitoringURL string
	CreatedAt     time.Time
}

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, fmt.Errorf("identity store requires a PostgreSQL pool")
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Store) EnsureGitHubRoleMapping(ctx context.Context, kind, target string, role Role) error {
	if err := validateGitHubRoleMapping(kind, target, role); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO github_role_mappings (id,kind,target,role,created_at) VALUES ($1::uuid,$2,$3,$4,now()) ON CONFLICT (kind,target) DO NOTHING`, randomUUID(), kind, normalizeGitHubTarget(kind, target), role)
	if err != nil {
		return fmt.Errorf("ensure GitHub role mapping: %w", err)
	}
	return nil
}

// EnsureInitialGitHubRoleMappings records the configured defaults exactly once.
// Administrators may subsequently remove or replace them from the private UI.
func (s *Store) EnsureInitialGitHubRoleMappings(ctx context.Context, developerTeam, adminTeam string) error {
	if err := validateGitHubRoleMapping("team", developerTeam, RoleDeveloper); err != nil {
		return err
	}
	if err := validateGitHubRoleMapping("team", adminTeam, RoleAdmin); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin initial GitHub mappings: %w", err)
	}
	defer tx.Rollback(ctx)
	var createdAt time.Time
	err = tx.QueryRow(ctx, `INSERT INTO service_metadata (key,created_at) VALUES ('initial_github_role_mappings',now()) ON CONFLICT (key) DO NOTHING RETURNING created_at`).Scan(&createdAt)
	if err == pgx.ErrNoRows {
		return tx.Commit(ctx)
	}
	if err != nil {
		return fmt.Errorf("record initial GitHub mappings: %w", err)
	}
	for _, mapping := range []struct {
		target string
		role   Role
	}{{developerTeam, RoleDeveloper}, {adminTeam, RoleAdmin}} {
		_, err = tx.Exec(ctx, `INSERT INTO github_role_mappings (id,kind,target,role,created_at) VALUES ($1::uuid,'team',$2,$3,now())`, randomUUID(), normalizeGitHubTarget("team", mapping.target), mapping.role)
		if err != nil {
			return fmt.Errorf("create initial GitHub mapping: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit initial GitHub mappings: %w", err)
	}
	return nil
}

func (s *Store) CreateGitHubRoleMapping(ctx context.Context, kind, target string, role Role) (GitHubRoleMapping, error) {
	if err := validateGitHubRoleMapping(kind, target, role); err != nil {
		return GitHubRoleMapping{}, err
	}
	var mapping GitHubRoleMapping
	err := s.pool.QueryRow(ctx, `INSERT INTO github_role_mappings (id,kind,target,role,created_at) VALUES ($1::uuid,$2,$3,$4,now()) RETURNING id::text,kind,target,role,created_at`, randomUUID(), kind, normalizeGitHubTarget(kind, target), role).
		Scan(&mapping.ID, &mapping.Kind, &mapping.Target, &mapping.Role, &mapping.CreatedAt)
	if err != nil {
		return GitHubRoleMapping{}, fmt.Errorf("create GitHub role mapping: %w", err)
	}
	return mapping, nil
}

func (s *Store) ListGitHubRoleMappings(ctx context.Context) ([]GitHubRoleMapping, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text,kind,target,role,created_at FROM github_role_mappings ORDER BY kind,target`)
	if err != nil {
		return nil, fmt.Errorf("list GitHub role mappings: %w", err)
	}
	defer rows.Close()
	var mappings []GitHubRoleMapping
	for rows.Next() {
		var mapping GitHubRoleMapping
		if err := rows.Scan(&mapping.ID, &mapping.Kind, &mapping.Target, &mapping.Role, &mapping.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan GitHub role mapping: %w", err)
		}
		mappings = append(mappings, mapping)
	}
	return mappings, rows.Err()
}

func (s *Store) DeleteGitHubRoleMapping(ctx context.Context, id string) error {
	command, err := s.pool.Exec(ctx, `DELETE FROM github_role_mappings WHERE id=$1::uuid`, id)
	if err != nil {
		return fmt.Errorf("delete GitHub role mapping: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("GitHub role mapping not found")
	}
	return nil
}

func (s *Store) CreateManagedApp(ctx context.Context, app ManagedApp) (ManagedApp, error) {
	app = normalizeManagedApp(app)
	if err := ValidateManagedApp(app); err != nil {
		return ManagedApp{}, err
	}
	err := s.pool.QueryRow(ctx, `INSERT INTO managed_apps (id,slug,name,description,launch_url,oidc_client_id,health_url,monitoring_url,created_at) VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,NULLIF($8,''),now()) RETURNING id::text,slug,name,description,launch_url,oidc_client_id,health_url,COALESCE(monitoring_url,''),created_at`, randomUUID(), app.Slug, app.Name, app.Description, app.LaunchURL, app.OIDCClientID, app.HealthURL, app.MonitoringURL).Scan(&app.ID, &app.Slug, &app.Name, &app.Description, &app.LaunchURL, &app.OIDCClientID, &app.HealthURL, &app.MonitoringURL, &app.CreatedAt)
	if err != nil {
		return ManagedApp{}, fmt.Errorf("create managed app: %w", err)
	}
	return app, nil
}

// ReconcileBootstrapManagedApp makes bootstrap configuration authoritative
// while refusing to take over an administrator-owned slug with another client.
func (s *Store) ReconcileBootstrapManagedApp(ctx context.Context, app ManagedApp) (ManagedApp, error) {
	app = normalizeManagedApp(app)
	if err := ValidateManagedApp(app); err != nil {
		return ManagedApp{}, err
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO managed_apps (id,slug,name,description,launch_url,oidc_client_id,health_url,monitoring_url,created_at)
		VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,NULLIF($8,''),now())
		ON CONFLICT (slug) DO UPDATE SET
			name=EXCLUDED.name,
			description=EXCLUDED.description,
			launch_url=EXCLUDED.launch_url,
			health_url=EXCLUDED.health_url,
			monitoring_url=EXCLUDED.monitoring_url
		WHERE managed_apps.oidc_client_id=EXCLUDED.oidc_client_id
		RETURNING id::text,slug,name,description,launch_url,oidc_client_id,health_url,COALESCE(monitoring_url,''),created_at`,
		randomUUID(), app.Slug, app.Name, app.Description, app.LaunchURL, app.OIDCClientID, app.HealthURL, app.MonitoringURL).
		Scan(&app.ID, &app.Slug, &app.Name, &app.Description, &app.LaunchURL, &app.OIDCClientID, &app.HealthURL, &app.MonitoringURL, &app.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ManagedApp{}, fmt.Errorf("managed app slug %q belongs to another OpenID Connect client", app.Slug)
	}
	if err != nil {
		return ManagedApp{}, fmt.Errorf("reconcile bootstrap managed app: %w", err)
	}
	return app, nil
}

func normalizeManagedApp(app ManagedApp) ManagedApp {
	app.Slug = strings.TrimSpace(app.Slug)
	app.Name = strings.TrimSpace(app.Name)
	app.Description = strings.TrimSpace(app.Description)
	app.LaunchURL = strings.TrimSpace(app.LaunchURL)
	app.OIDCClientID = strings.TrimSpace(app.OIDCClientID)
	app.HealthURL = strings.TrimSpace(app.HealthURL)
	app.MonitoringURL = strings.TrimSpace(app.MonitoringURL)
	return app
}

func (s *Store) ListManagedApps(ctx context.Context) ([]ManagedApp, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text,slug,name,description,launch_url,oidc_client_id,health_url,COALESCE(monitoring_url,''),created_at FROM managed_apps ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list managed apps: %w", err)
	}
	defer rows.Close()
	var apps []ManagedApp
	for rows.Next() {
		var app ManagedApp
		if err := rows.Scan(&app.ID, &app.Slug, &app.Name, &app.Description, &app.LaunchURL, &app.OIDCClientID, &app.HealthURL, &app.MonitoringURL, &app.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan managed app: %w", err)
		}
		apps = append(apps, app)
	}
	return apps, rows.Err()
}

// IsManagedOIDCClient reports whether an OAuth client belongs to an app that
// Shauth administrators have explicitly enrolled as an e6qu service.
func (s *Store) IsManagedOIDCClient(ctx context.Context, clientID string) (bool, error) {
	var managed bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM managed_apps WHERE oidc_client_id=$1)`, strings.TrimSpace(clientID)).Scan(&managed); err != nil {
		return false, fmt.Errorf("check managed OAuth client: %w", err)
	}
	return managed, nil
}

func (s *Store) ManagedApp(ctx context.Context, id string) (ManagedApp, error) {
	var app ManagedApp
	err := s.pool.QueryRow(ctx, `SELECT id::text,slug,name,description,launch_url,oidc_client_id,health_url,COALESCE(monitoring_url,''),created_at FROM managed_apps WHERE id=$1::uuid`, id).Scan(&app.ID, &app.Slug, &app.Name, &app.Description, &app.LaunchURL, &app.OIDCClientID, &app.HealthURL, &app.MonitoringURL, &app.CreatedAt)
	if err != nil {
		return ManagedApp{}, fmt.Errorf("get managed app: %w", err)
	}
	return app, nil
}

func (s *Store) DeleteManagedApp(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx, `DELETE FROM managed_apps WHERE id=$1::uuid`, id)
	if err != nil {
		return fmt.Errorf("delete managed app: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("managed app not found")
	}
	return nil
}

func validateGitHubRoleMapping(kind, target string, role Role) error {
	if kind != "user" && kind != "organization" && kind != "team" {
		return fmt.Errorf("GitHub mapping kind must be user, organization, or team")
	}
	if strings.TrimSpace(target) == "" || (kind == "team" && len(strings.Split(strings.TrimSpace(target), "/")) != 2) {
		return fmt.Errorf("GitHub mapping target is invalid")
	}
	if role != RoleDeveloper && role != RoleAdmin {
		return fmt.Errorf("GitHub mapping role is invalid")
	}
	return nil
}

// ValidateManagedApp checks app-owned endpoint coordinates.
func ValidateManagedApp(app ManagedApp) error {
	if len(app.Slug) < 3 || len(app.Slug) > 63 {
		return fmt.Errorf("app slug must be between 3 and 63 characters")
	}
	for index, character := range app.Slug {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' || (character == '-' && (index == 0 || index == len(app.Slug)-1)) {
			return fmt.Errorf("app slug must use lowercase letters, digits, and interior hyphens")
		}
	}
	if strings.TrimSpace(app.Name) == "" || strings.TrimSpace(app.Description) == "" || strings.TrimSpace(app.OIDCClientID) == "" {
		return fmt.Errorf("app name, description, and OIDC client ID are required")
	}
	launchURL, err := url.ParseRequestURI(strings.TrimSpace(app.LaunchURL))
	if err != nil || launchURL.Scheme != "https" || launchURL.Host == "" || launchURL.Fragment != "" {
		return fmt.Errorf("app launch URL must use HTTPS")
	}
	healthURL, err := url.ParseRequestURI(strings.TrimSpace(app.HealthURL))
	if err != nil || healthURL.Scheme != "https" || healthURL.Host == "" || healthURL.Fragment != "" {
		return fmt.Errorf("app health URL must use HTTPS")
	}
	if app.MonitoringURL != "" {
		monitoringURL, err := url.ParseRequestURI(app.MonitoringURL)
		if err != nil || monitoringURL.Scheme != "https" || monitoringURL.Host == "" || monitoringURL.Fragment != "" {
			return fmt.Errorf("app monitoring URL must use HTTPS")
		}
	}
	return nil
}

func normalizeGitHubTarget(kind, target string) string {
	target = strings.TrimSpace(target)
	if kind == "user" || kind == "organization" || kind == "team" {
		return strings.ToLower(target)
	}
	return target
}

func (s *Store) CreatePasswordUser(ctx context.Context, username, email, password string, role Role) (User, error) {
	username, email = strings.TrimSpace(username), strings.ToLower(strings.TrimSpace(email))
	if username == "" || email == "" || len(password) < 14 {
		return User{}, fmt.Errorf("username, email, and a password of at least 14 characters are required")
	}
	if role != RoleDeveloper && role != RoleAdmin {
		return User{}, fmt.Errorf("invalid role")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
	}
	return s.insertUser(ctx, randomUUID(), username, email, hash, nil, "", role)
}

// EnsureBootstrapAdmin creates the explicitly configured break-glass admin on
// first start and promotes the same email on later starts.
func (s *Store) EnsureBootstrapAdmin(ctx context.Context, email, password string) (User, error) {
	if email == "" {
		return User{}, nil
	}
	username := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")[0]
	user, err := s.CreatePasswordUser(ctx, username, email, password, RoleAdmin)
	if err == nil {
		return user, nil
	}
	var existing User
	err = s.pool.QueryRow(ctx, `UPDATE users SET role='admin', disabled_at=NULL WHERE email=$1 RETURNING id::text,username,email,COALESCE(github_login,''),role,disabled_at,created_at`, strings.ToLower(strings.TrimSpace(email))).Scan(&existing.ID, &existing.Username, &existing.Email, &existing.GitHubLogin, &existing.Role, &existing.DisabledAt, &existing.CreatedAt)
	if err != nil {
		return User{}, fmt.Errorf("ensure bootstrap admin: %w", err)
	}
	return existing, nil
}

func (s *Store) CreateInvitation(ctx context.Context, email string, role Role, invitedBy string, now time.Time) (string, Invitation, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || (role != RoleDeveloper && role != RoleAdmin) {
		return "", Invitation{}, fmt.Errorf("valid email and role are required")
	}
	raw, err := randomToken()
	if err != nil {
		return "", Invitation{}, err
	}
	hash := sha256.Sum256([]byte(raw))
	invitation := Invitation{ID: randomUUID(), Email: email, Role: role, ExpiresAt: now.UTC().Add(7 * 24 * time.Hour)}
	err = s.pool.QueryRow(ctx, `INSERT INTO invitations (id,email,role,token_hash,invited_by,created_at,expires_at) VALUES ($1::uuid,$2,$3,$4,$5::uuid,$6,$7) RETURNING id::text`, invitation.ID, email, role, hash[:], invitedBy, now.UTC(), invitation.ExpiresAt).Scan(&invitation.ID)
	if err != nil {
		return "", Invitation{}, fmt.Errorf("create invitation: %w", err)
	}
	return raw, invitation, nil
}

func (s *Store) AcceptInvitation(ctx context.Context, raw, username, password string, now time.Time) (User, error) {
	hash := sha256.Sum256([]byte(raw))
	var email string
	var role Role
	err := s.pool.QueryRow(ctx, `UPDATE invitations SET accepted_at=$2 WHERE token_hash=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>$2 RETURNING email,role`, hash[:], now.UTC()).Scan(&email, &role)
	if err != nil {
		return User{}, fmt.Errorf("accept invitation: %w", err)
	}
	user, err := s.CreatePasswordUser(ctx, username, email, password, role)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (s *Store) RevokeInvitation(ctx context.Context, id string, now time.Time) error {
	command, err := s.pool.Exec(ctx, `UPDATE invitations SET revoked_at=$2 WHERE id=$1::uuid AND accepted_at IS NULL AND revoked_at IS NULL`, id, now.UTC())
	if err != nil {
		return fmt.Errorf("revoke invitation: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("active invitation not found")
	}
	return nil
}

func (s *Store) insertUser(ctx context.Context, id, username, email string, hash []byte, githubID *int64, githubLogin string, role Role) (User, error) {
	var user User
	err := s.pool.QueryRow(ctx, `INSERT INTO users (id, username, email, password_hash, github_id, github_login, role, created_at)
	VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,now()) RETURNING id::text,username,email,COALESCE(github_login,''),role,disabled_at,created_at`, id, username, email, hash, githubID, nullable(githubLogin), role).
		Scan(&user.ID, &user.Username, &user.Email, &user.GitHubLogin, &user.Role, &user.DisabledAt, &user.CreatedAt)
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func (s *Store) AuthenticatePassword(ctx context.Context, username, password string) (User, error) {
	var user User
	var hash []byte
	err := s.pool.QueryRow(ctx, `SELECT id::text,username,email,COALESCE(github_login,''),role,disabled_at,created_at,password_hash FROM users WHERE username=$1`, strings.TrimSpace(username)).
		Scan(&user.ID, &user.Username, &user.Email, &user.GitHubLogin, &user.Role, &user.DisabledAt, &user.CreatedAt, &hash)
	if err != nil || user.DisabledAt != nil || len(hash) == 0 || bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil {
		return User{}, fmt.Errorf("invalid username or password")
	}
	return user, nil
}

func (s *Store) FindOrCreateGitHubUser(ctx context.Context, githubID int64, login, email string, role Role) (User, error) {
	var user User
	err := s.pool.QueryRow(ctx, `SELECT id::text,username,email,COALESCE(github_login,''),role,disabled_at,created_at FROM users WHERE github_id=$1`, githubID).
		Scan(&user.ID, &user.Username, &user.Email, &user.GitHubLogin, &user.Role, &user.DisabledAt, &user.CreatedAt)
	if err == nil {
		if user.DisabledAt != nil {
			return User{}, fmt.Errorf("user is disabled")
		}
		if user.Role != role {
			_, err = s.pool.Exec(ctx, `UPDATE users SET role=$2 WHERE id=$1::uuid`, user.ID, role)
			if err != nil {
				return User{}, fmt.Errorf("synchronize GitHub user role: %w", err)
			}
			user.Role = role
		}
		return user, nil
	}
	if err != pgx.ErrNoRows {
		return User{}, fmt.Errorf("find GitHub user: %w", err)
	}
	login = strings.TrimSpace(login)
	email = strings.ToLower(strings.TrimSpace(email))
	if login == "" || email == "" {
		return User{}, fmt.Errorf("GitHub account must provide login and verified email")
	}
	return s.insertUser(ctx, randomUUID(), login, email, nil, &githubID, login, role)
}

func (s *Store) CreateSession(ctx context.Context, userID, userAgent string, remoteIP net.IP, now time.Time) (string, Session, error) {
	raw, err := randomToken()
	if err != nil {
		return "", Session{}, err
	}
	tokenHash := sha256.Sum256([]byte(raw))
	id := randomUUID()
	family := randomUUID()
	expiry := now.UTC().Add(sessionLifetime)
	var session Session
	err = s.pool.QueryRow(ctx, `INSERT INTO sessions (id,user_id,refresh_family_id,browser_token_hash,created_at,last_seen_at,expires_at,user_agent,remote_address)
	VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,$5,$6,$7,$8) RETURNING id::text,user_id::text,created_at,last_seen_at,expires_at,revoked_at,user_agent,remote_address`, id, userID, family, tokenHash[:], now.UTC(), expiry, userAgent, remoteIP).
		Scan(&session.ID, &session.UserID, &session.CreatedAt, &session.LastSeen, &session.ExpiresAt, &session.RevokedAt, &session.UserAgent, &session.RemoteIP)
	if err != nil {
		return "", Session{}, fmt.Errorf("create session: %w", err)
	}
	return raw, session, nil
}

func (s *Store) CurrentUser(ctx context.Context, raw string, now time.Time) (User, Session, error) {
	hash := sha256.Sum256([]byte(raw))
	var user User
	var session Session
	err := s.pool.QueryRow(ctx, `SELECT u.id::text,u.username,u.email,COALESCE(u.github_login,''),u.role,u.disabled_at,u.created_at,s.id::text,s.user_id::text,s.created_at,s.last_seen_at,s.expires_at,s.revoked_at,s.user_agent,s.remote_address
	FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.browser_token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>$2 AND u.disabled_at IS NULL`, hash[:], now.UTC()).
		Scan(&user.ID, &user.Username, &user.Email, &user.GitHubLogin, &user.Role, &user.DisabledAt, &user.CreatedAt, &session.ID, &session.UserID, &session.CreatedAt, &session.LastSeen, &session.ExpiresAt, &session.RevokedAt, &session.UserAgent, &session.RemoteIP)
	if err != nil {
		return User{}, Session{}, fmt.Errorf("read active session: %w", err)
	}
	_, err = s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at=$2 WHERE id=$1::uuid`, session.ID, now.UTC())
	if err != nil {
		return User{}, Session{}, fmt.Errorf("touch session: %w", err)
	}
	session.LastSeen = now.UTC()
	return user, session, nil
}

func (s *Store) ListUsers(ctx context.Context, query string) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text,username,email,COALESCE(github_login,''),role,disabled_at,created_at FROM users WHERE username ILIKE '%' || $1 || '%' OR email ILIKE '%' || $1 || '%' ORDER BY created_at DESC`, strings.TrimSpace(query))
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.GitHubLogin, &u.Role, &u.DisabledAt, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}
func (s *Store) ListSessions(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text,user_id::text,created_at,last_seen_at,expires_at,revoked_at,user_agent,remote_address FROM sessions WHERE user_id=$1::uuid ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()
	var sessions []Session
	for rows.Next() {
		var v Session
		if err := rows.Scan(&v.ID, &v.UserID, &v.CreatedAt, &v.LastSeen, &v.ExpiresAt, &v.RevokedAt, &v.UserAgent, &v.RemoteIP); err != nil {
			return nil, err
		}
		sessions = append(sessions, v)
	}
	return sessions, rows.Err()
}
func (s *Store) RevokeSession(ctx context.Context, id string, now time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at=$2 WHERE id=$1::uuid AND revoked_at IS NULL`, id, now.UTC())
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("active session not found")
	}
	return nil
}
func (s *Store) SessionUserID(ctx context.Context, id string) (string, error) {
	var userID string
	err := s.pool.QueryRow(ctx, `SELECT user_id::text FROM sessions WHERE id=$1::uuid`, id).Scan(&userID)
	if err != nil {
		return "", fmt.Errorf("read session user: %w", err)
	}
	return userID, nil
}
func (s *Store) RevokeUserSessions(ctx context.Context, userID string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at=$2 WHERE user_id=$1::uuid AND revoked_at IS NULL`, userID, now.UTC())
	if err != nil {
		return fmt.Errorf("revoke user sessions: %w", err)
	}
	return nil
}
func (s *Store) CountActiveSessions(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at>$1`, now.UTC()).Scan(&n)
	return n, err
}
func nullable(v string) any {
	if v == "" {
		return nil
	}
	return v
}
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
func randomUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
