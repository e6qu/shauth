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
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type Role string

const (
	RoleDeveloper Role = "developer"
	RoleAdmin     Role = "admin"
)

var immutableReleaseRevisionPattern = regexp.MustCompile(`^([0-9a-f]{12,64}|sha256:[0-9a-f]{64})$`)
var browserBootstrapTokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

const validationBrowserBootstrapLifetime = 10 * time.Minute

type User struct {
	ID                string
	Username          string
	Email             string
	EmailVerified     bool
	GitHubLogin       string
	FederatedIdentity string
	Role              Role
	DisabledAt        *time.Time
	CreatedAt         time.Time
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
	Active    bool
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
	ID              string
	Slug            string
	Name            string
	Description     string
	LaunchURL       string
	OIDCClientID    string
	HealthURL       string
	MonitoringURL   string
	ValidationURL   string
	SignedOutURL    string
	ReleaseRevision string
	CreatedAt       time.Time
}

type AppValidationRun struct {
	ID                     string
	ManagedAppID           string
	AppSlug                string
	AppName                string
	OIDCClientID           string
	LaunchURL              string
	ValidationURL          string
	SignedOutURL           string
	Direction              string
	ReleaseRevision        string
	ValidationContractHash string
	Status                 string
	RequestedAt            time.Time
	StartedAt              *time.Time
	CompletedAt            *time.Time
	DurationMilliseconds   *int64
	Failure                string
	Witness                *AppValidationWitness
}

type AppValidationWitness struct {
	ManagedAppID    string `json:"managed_app_id"`
	AppSlug         string `json:"app_slug"`
	AppName         string `json:"app_name"`
	OIDCClientID    string `json:"oidc_client_id"`
	LaunchURL       string `json:"launch_url"`
	ValidationURL   string `json:"validation_url"`
	SignedOutURL    string `json:"signed_out_url"`
	ReleaseRevision string `json:"release_revision"`
}

const (
	ValidationFromShauth = "from_shauth"
	ValidationFromApp    = "from_app"
	ValidationQueued     = "queued"
	ValidationRunning    = "running"
	ValidationPassed     = "passed"
	ValidationFailed     = "failed"
)

type Store struct{ pool *pgxpool.Pool }

const bootstrapManagedAppsLockID int64 = 0x5348415554484150

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, fmt.Errorf("identity store requires a PostgreSQL pool")
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// LockBootstrapManagedApps serializes the cross-system PostgreSQL/Ory Hydra
// reconciliation performed by every Shauth replica during startup.
func (s *Store) LockBootstrapManagedApps(ctx context.Context) (func(), error) {
	connection, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire bootstrap reconciliation connection: %w", err)
	}
	if _, err := connection.Exec(ctx, `SELECT pg_advisory_lock($1)`, bootstrapManagedAppsLockID); err != nil {
		connection.Release()
		return nil, fmt.Errorf("lock bootstrap reconciliation: %w", err)
	}
	return func() {
		_, _ = connection.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, bootstrapManagedAppsLockID)
		connection.Release()
	}, nil
}

func (s *Store) SessionPolicy(ctx context.Context) (SessionPolicy, error) {
	var absoluteSeconds, idleSeconds, oidcSeconds, accessSeconds, idSeconds, refreshSeconds int64
	err := s.pool.QueryRow(ctx, `SELECT browser_absolute_lifetime_seconds,browser_idle_timeout_seconds,oidc_session_lifetime_seconds,access_token_lifetime_seconds,id_token_lifetime_seconds,refresh_token_lifetime_seconds FROM session_policy WHERE singleton=TRUE`).
		Scan(&absoluteSeconds, &idleSeconds, &oidcSeconds, &accessSeconds, &idSeconds, &refreshSeconds)
	if err != nil {
		return SessionPolicy{}, fmt.Errorf("read session policy: %w", err)
	}
	policy := SessionPolicy{
		BrowserAbsoluteLifetime: time.Duration(absoluteSeconds) * time.Second,
		BrowserIdleTimeout:      time.Duration(idleSeconds) * time.Second,
		OIDCSessionLifetime:     time.Duration(oidcSeconds) * time.Second,
		AccessTokenLifetime:     time.Duration(accessSeconds) * time.Second,
		IDTokenLifetime:         time.Duration(idSeconds) * time.Second,
		RefreshTokenLifetime:    time.Duration(refreshSeconds) * time.Second,
	}
	if err := policy.Validate(); err != nil {
		return SessionPolicy{}, fmt.Errorf("stored session policy: %w", err)
	}
	return policy, nil
}

func (s *Store) UpdateSessionPolicy(ctx context.Context, policy SessionPolicy, now time.Time) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	command, err := s.pool.Exec(ctx, `UPDATE session_policy SET browser_absolute_lifetime_seconds=$1,browser_idle_timeout_seconds=$2,oidc_session_lifetime_seconds=$3,access_token_lifetime_seconds=$4,id_token_lifetime_seconds=$5,refresh_token_lifetime_seconds=$6,updated_at=$7 WHERE singleton=TRUE`,
		int64(policy.BrowserAbsoluteLifetime/time.Second), int64(policy.BrowserIdleTimeout/time.Second), int64(policy.OIDCSessionLifetime/time.Second), int64(policy.AccessTokenLifetime/time.Second), int64(policy.IDTokenLifetime/time.Second), int64(policy.RefreshTokenLifetime/time.Second), now.UTC())
	if err != nil {
		return fmt.Errorf("update session policy: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("session policy record is missing")
	}
	return nil
}

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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ManagedApp{}, fmt.Errorf("begin create managed app: %w", err)
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `INSERT INTO managed_apps (id,slug,name,description,launch_url,oidc_client_id,health_url,monitoring_url,validation_url,signed_out_url,release_revision,created_at) VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9,$10,$11,now()) RETURNING id::text,slug,name,description,launch_url,oidc_client_id,health_url,COALESCE(monitoring_url,''),validation_url,signed_out_url,release_revision,created_at`, randomUUID(), app.Slug, app.Name, app.Description, app.LaunchURL, app.OIDCClientID, app.HealthURL, app.MonitoringURL, app.ValidationURL, app.SignedOutURL, app.ReleaseRevision).Scan(&app.ID, &app.Slug, &app.Name, &app.Description, &app.LaunchURL, &app.OIDCClientID, &app.HealthURL, &app.MonitoringURL, &app.ValidationURL, &app.SignedOutURL, &app.ReleaseRevision, &app.CreatedAt)
	if err != nil {
		return ManagedApp{}, fmt.Errorf("create managed app: %w", err)
	}
	if err := enqueueAllAppValidations(ctx, tx, nil, time.Now().UTC()); err != nil {
		return ManagedApp{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ManagedApp{}, fmt.Errorf("commit create managed app: %w", err)
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ManagedApp{}, fmt.Errorf("begin reconcile bootstrap managed app: %w", err)
	}
	defer tx.Rollback(ctx)
	var previous ManagedApp
	previousErr := tx.QueryRow(ctx, `SELECT name,description,launch_url,oidc_client_id,health_url,COALESCE(monitoring_url,''),validation_url,signed_out_url,release_revision FROM managed_apps WHERE slug=$1 FOR UPDATE`, app.Slug).
		Scan(&previous.Name, &previous.Description, &previous.LaunchURL, &previous.OIDCClientID, &previous.HealthURL, &previous.MonitoringURL, &previous.ValidationURL, &previous.SignedOutURL, &previous.ReleaseRevision)
	if previousErr != nil && !errors.Is(previousErr, pgx.ErrNoRows) {
		return ManagedApp{}, fmt.Errorf("read bootstrap managed app revision: %w", previousErr)
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO managed_apps (id,slug,name,description,launch_url,oidc_client_id,health_url,monitoring_url,validation_url,signed_out_url,release_revision,created_at)
		VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9,$10,$11,now())
		ON CONFLICT (slug) DO UPDATE SET
			name=EXCLUDED.name,
			description=EXCLUDED.description,
			launch_url=EXCLUDED.launch_url,
			health_url=EXCLUDED.health_url,
			monitoring_url=EXCLUDED.monitoring_url,
			validation_url=EXCLUDED.validation_url,
			signed_out_url=EXCLUDED.signed_out_url,
			release_revision=EXCLUDED.release_revision
		WHERE managed_apps.oidc_client_id=EXCLUDED.oidc_client_id
		RETURNING id::text,slug,name,description,launch_url,oidc_client_id,health_url,COALESCE(monitoring_url,''),validation_url,signed_out_url,release_revision,created_at`,
		randomUUID(), app.Slug, app.Name, app.Description, app.LaunchURL, app.OIDCClientID, app.HealthURL, app.MonitoringURL, app.ValidationURL, app.SignedOutURL, app.ReleaseRevision).
		Scan(&app.ID, &app.Slug, &app.Name, &app.Description, &app.LaunchURL, &app.OIDCClientID, &app.HealthURL, &app.MonitoringURL, &app.ValidationURL, &app.SignedOutURL, &app.ReleaseRevision, &app.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ManagedApp{}, fmt.Errorf("managed app slug %q belongs to another OpenID Connect client", app.Slug)
	}
	if err != nil {
		return ManagedApp{}, fmt.Errorf("reconcile bootstrap managed app: %w", err)
	}
	if errors.Is(previousErr, pgx.ErrNoRows) || !sameManagedAppValidationContract(previous, app) {
		if err := enqueueAllAppValidations(ctx, tx, nil, time.Now().UTC()); err != nil {
			return ManagedApp{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ManagedApp{}, fmt.Errorf("commit reconcile bootstrap managed app: %w", err)
	}
	return app, nil
}

func sameManagedAppValidationContract(left, right ManagedApp) bool {
	return left.Name == right.Name &&
		left.Description == right.Description &&
		left.LaunchURL == right.LaunchURL &&
		left.OIDCClientID == right.OIDCClientID &&
		left.HealthURL == right.HealthURL &&
		left.MonitoringURL == right.MonitoringURL &&
		left.ValidationURL == right.ValidationURL &&
		left.SignedOutURL == right.SignedOutURL &&
		left.ReleaseRevision == right.ReleaseRevision
}

func managedAppValidationContractHash(app ManagedApp, witness *ManagedApp) string {
	fields := []string{
		app.Slug,
		app.Name,
		app.Description,
		app.LaunchURL,
		app.OIDCClientID,
		app.HealthURL,
		app.MonitoringURL,
		app.ValidationURL,
		app.SignedOutURL,
		app.ReleaseRevision,
	}
	if witness != nil {
		fields = append(fields,
			witness.ID,
			witness.Slug,
			witness.Name,
			witness.OIDCClientID,
			witness.LaunchURL,
			witness.ValidationURL,
			witness.SignedOutURL,
			witness.ReleaseRevision,
		)
	}
	contract := strings.Join(fields, "\x00")
	digest := sha256.Sum256([]byte(contract))
	return hex.EncodeToString(digest[:])
}

// ValidateBootstrapManagedAppOwnership reports whether the catalog already
// contains the exact slug/client pair that bootstrap is allowed to reconcile.
// Either coordinate belonging to a different record is an ownership conflict.
func (s *Store) ValidateBootstrapManagedAppOwnership(ctx context.Context, app ManagedApp) (bool, error) {
	app = normalizeManagedApp(app)
	rows, err := s.pool.Query(ctx, `SELECT slug,oidc_client_id FROM managed_apps WHERE slug=$1 OR oidc_client_id=$2`, app.Slug, app.OIDCClientID)
	if err != nil {
		return false, fmt.Errorf("query bootstrap managed app ownership: %w", err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var slug, clientID string
		if err := rows.Scan(&slug, &clientID); err != nil {
			return false, fmt.Errorf("scan bootstrap managed app ownership: %w", err)
		}
		if slug != app.Slug || clientID != app.OIDCClientID {
			return false, fmt.Errorf("managed app slug %q or OpenID Connect client %q belongs to another registration", app.Slug, app.OIDCClientID)
		}
		found = true
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("read bootstrap managed app ownership: %w", err)
	}
	return found, nil
}

func normalizeManagedApp(app ManagedApp) ManagedApp {
	app.Slug = strings.TrimSpace(app.Slug)
	app.Name = strings.TrimSpace(app.Name)
	app.Description = strings.TrimSpace(app.Description)
	app.LaunchURL = strings.TrimSpace(app.LaunchURL)
	app.OIDCClientID = strings.TrimSpace(app.OIDCClientID)
	app.HealthURL = strings.TrimSpace(app.HealthURL)
	app.MonitoringURL = strings.TrimSpace(app.MonitoringURL)
	app.ValidationURL = strings.TrimSpace(app.ValidationURL)
	app.SignedOutURL = strings.TrimSpace(app.SignedOutURL)
	app.ReleaseRevision = strings.TrimSpace(app.ReleaseRevision)
	return app
}

func (s *Store) ListManagedApps(ctx context.Context) ([]ManagedApp, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text,slug,name,description,launch_url,oidc_client_id,health_url,COALESCE(monitoring_url,''),validation_url,signed_out_url,release_revision,created_at FROM managed_apps ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list managed apps: %w", err)
	}
	defer rows.Close()
	var apps []ManagedApp
	for rows.Next() {
		var app ManagedApp
		if err := rows.Scan(&app.ID, &app.Slug, &app.Name, &app.Description, &app.LaunchURL, &app.OIDCClientID, &app.HealthURL, &app.MonitoringURL, &app.ValidationURL, &app.SignedOutURL, &app.ReleaseRevision, &app.CreatedAt); err != nil {
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
	err := s.pool.QueryRow(ctx, `SELECT id::text,slug,name,description,launch_url,oidc_client_id,health_url,COALESCE(monitoring_url,''),validation_url,signed_out_url,release_revision,created_at FROM managed_apps WHERE id=$1::uuid`, id).Scan(&app.ID, &app.Slug, &app.Name, &app.Description, &app.LaunchURL, &app.OIDCClientID, &app.HealthURL, &app.MonitoringURL, &app.ValidationURL, &app.SignedOutURL, &app.ReleaseRevision, &app.CreatedAt)
	if err != nil {
		return ManagedApp{}, fmt.Errorf("get managed app: %w", err)
	}
	return app, nil
}

func (s *Store) DeleteManagedApp(ctx context.Context, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin delete managed app: %w", err)
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `DELETE FROM managed_apps WHERE id=$1::uuid`, id)
	if err != nil {
		return fmt.Errorf("delete managed app: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("managed app not found")
	}
	if err := enqueueAllAppValidations(ctx, tx, nil, time.Now().UTC()); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delete managed app: %w", err)
	}
	return nil
}

func (s *Store) ManagedAppUsesOIDCClient(ctx context.Context, clientID string) (bool, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM managed_apps WHERE oidc_client_id=$1)`, strings.TrimSpace(clientID)).Scan(&exists); err != nil {
		return false, fmt.Errorf("query managed app OAuth client: %w", err)
	}
	return exists, nil
}

func loadManagedAppsForValidation(ctx context.Context, tx pgx.Tx) ([]ManagedApp, error) {
	rows, err := tx.Query(ctx, `SELECT id::text,slug,name,description,launch_url,oidc_client_id,health_url,COALESCE(monitoring_url,''),validation_url,signed_out_url,release_revision FROM managed_apps ORDER BY slug FOR UPDATE`)
	if err != nil {
		return nil, fmt.Errorf("lock managed app validation contracts: %w", err)
	}
	defer rows.Close()
	var apps []ManagedApp
	for rows.Next() {
		var app ManagedApp
		if err := rows.Scan(&app.ID, &app.Slug, &app.Name, &app.Description, &app.LaunchURL, &app.OIDCClientID, &app.HealthURL, &app.MonitoringURL, &app.ValidationURL, &app.SignedOutURL, &app.ReleaseRevision); err != nil {
			return nil, fmt.Errorf("scan managed app validation contract: %w", err)
		}
		apps = append(apps, app)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list managed app validation contracts: %w", err)
	}
	return apps, nil
}

func validationWitness(target ManagedApp, apps []ManagedApp) *ManagedApp {
	targetURL, _ := url.Parse(target.LaunchURL)
	targetIndex := -1
	for index := range apps {
		if apps[index].ID == target.ID {
			targetIndex = index
			break
		}
	}
	for offset := 1; offset < len(apps); offset++ {
		index := (targetIndex + offset) % len(apps)
		candidate := &apps[index]
		candidateURL, _ := url.Parse(candidate.LaunchURL)
		if candidate.ID != target.ID && candidate.OIDCClientID != target.OIDCClientID && !sameURLOrigin(targetURL, candidateURL) {
			return candidate
		}
	}
	return nil
}

func enqueueAppValidation(ctx context.Context, tx pgx.Tx, app ManagedApp, witness *ManagedApp, requestedBy *string, now time.Time) error {
	contractHash := managedAppValidationContractHash(app, witness)
	var witnessID, witnessSlug, witnessName, witnessClientID, witnessLaunchURL, witnessValidationURL, witnessSignedOutURL, witnessRevision any
	if witness != nil {
		witnessID, witnessSlug, witnessName = witness.ID, witness.Slug, witness.Name
		witnessClientID, witnessLaunchURL = witness.OIDCClientID, witness.LaunchURL
		witnessValidationURL, witnessSignedOutURL, witnessRevision = witness.ValidationURL, witness.SignedOutURL, witness.ReleaseRevision
	}
	for _, direction := range []string{ValidationFromShauth, ValidationFromApp} {
		var requester any
		if requestedBy != nil {
			requester = *requestedBy
		}
		_, err := tx.Exec(ctx, `
			DELETE FROM app_validation_runs WHERE managed_app_id=$1::uuid AND direction=$2 AND status='queued' AND validation_contract_hash<>$3`,
			app.ID, direction, contractHash)
		if err != nil {
			return fmt.Errorf("remove superseded %s application validation: %w", direction, err)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO app_validation_runs(
				id,managed_app_id,app_slug,app_name,oidc_client_id,launch_url,validation_url,signed_out_url,
				direction,release_revision,validation_contract_hash,
				witness_managed_app_id,witness_app_slug,witness_app_name,witness_oidc_client_id,witness_launch_url,witness_validation_url,witness_signed_out_url,witness_release_revision,
				status,requested_by,requested_at)
			VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::uuid,$13,$14,$15,$16,$17,$18,$19,'queued',$20::uuid,$21)
			ON CONFLICT (managed_app_id,direction,validation_contract_hash)
			WHERE status IN ('queued','running') DO NOTHING`,
			randomUUID(), app.ID, app.Slug, app.Name, app.OIDCClientID, app.LaunchURL, app.ValidationURL, app.SignedOutURL,
			direction, app.ReleaseRevision, contractHash,
			witnessID, witnessSlug, witnessName, witnessClientID, witnessLaunchURL, witnessValidationURL, witnessSignedOutURL, witnessRevision,
			requester, now)
		if err != nil {
			return fmt.Errorf("enqueue %s application validation: %w", direction, err)
		}
	}
	return nil
}

func enqueueAllAppValidations(ctx context.Context, tx pgx.Tx, requestedBy *string, now time.Time) error {
	apps, err := loadManagedAppsForValidation(ctx, tx)
	if err != nil {
		return err
	}
	for _, app := range apps {
		if err := enqueueAppValidation(ctx, tx, app, validationWitness(app, apps), requestedBy, now); err != nil {
			return err
		}
	}
	return nil
}

// EnqueueAppValidations schedules both catalog-entry and direct-entry browser
// checks. Duplicate pending checks for the exact same application contract
// collapse into one queue entry per direction.
func (s *Store) EnqueueAppValidations(ctx context.Context, appID, requestedBy string, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin enqueue application validations: %w", err)
	}
	defer tx.Rollback(ctx)
	apps, err := loadManagedAppsForValidation(ctx, tx)
	if err != nil {
		return err
	}
	for _, app := range apps {
		if app.ID == appID {
			if err := enqueueAppValidation(ctx, tx, app, validationWitness(app, apps), &requestedBy, now.UTC()); err != nil {
				return err
			}
			if err := tx.Commit(ctx); err != nil {
				return fmt.Errorf("commit enqueue application validations: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("managed app not found")
}

// LatestAppValidationRuns returns the most recent durable result for each app
// and direction, including queued and running work.
func (s *Store) LatestAppValidationRuns(ctx context.Context) (map[string]map[string]AppValidationRun, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (r.managed_app_id,r.direction)
			r.id::text,r.managed_app_id::text,r.app_slug,r.app_name,r.oidc_client_id,r.launch_url,r.validation_url,r.signed_out_url,r.direction,r.release_revision,r.validation_contract_hash,r.status,
			r.requested_at,r.started_at,r.completed_at,r.duration_milliseconds,r.failure,
			r.witness_managed_app_id::text,r.witness_app_slug,r.witness_app_name,r.witness_oidc_client_id,r.witness_launch_url,r.witness_validation_url,r.witness_signed_out_url,r.witness_release_revision
		FROM app_validation_runs r
		ORDER BY r.managed_app_id,r.direction,r.requested_at DESC,r.id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list application validation results: %w", err)
	}
	defer rows.Close()
	results := map[string]map[string]AppValidationRun{}
	for rows.Next() {
		var run AppValidationRun
		var witnessID, witnessSlug, witnessName, witnessClientID, witnessLaunchURL, witnessValidationURL, witnessSignedOutURL, witnessRevision *string
		if err := rows.Scan(&run.ID, &run.ManagedAppID, &run.AppSlug, &run.AppName, &run.OIDCClientID, &run.LaunchURL, &run.ValidationURL, &run.SignedOutURL, &run.Direction, &run.ReleaseRevision, &run.ValidationContractHash, &run.Status, &run.RequestedAt, &run.StartedAt, &run.CompletedAt, &run.DurationMilliseconds, &run.Failure,
			&witnessID, &witnessSlug, &witnessName, &witnessClientID, &witnessLaunchURL, &witnessValidationURL, &witnessSignedOutURL, &witnessRevision); err != nil {
			return nil, fmt.Errorf("scan application validation result: %w", err)
		}
		if witnessID != nil {
			run.Witness = &AppValidationWitness{ManagedAppID: *witnessID, AppSlug: *witnessSlug, AppName: *witnessName, OIDCClientID: *witnessClientID, LaunchURL: *witnessLaunchURL, ValidationURL: *witnessValidationURL, SignedOutURL: *witnessSignedOutURL, ReleaseRevision: *witnessRevision}
		}
		if results[run.ManagedAppID] == nil {
			results[run.ManagedAppID] = map[string]AppValidationRun{}
		}
		results[run.ManagedAppID][run.Direction] = run
	}
	return results, rows.Err()
}

// LatestAppValidationRunsForApp returns the most recent durable result for one
// app in each direction without scanning other app histories.
func (s *Store) LatestAppValidationRunsForApp(ctx context.Context, appID string) (map[string]AppValidationRun, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (r.direction)
			r.id::text,r.managed_app_id::text,r.app_slug,r.app_name,r.oidc_client_id,r.launch_url,r.validation_url,r.signed_out_url,r.direction,r.release_revision,r.validation_contract_hash,r.status,
			r.requested_at,r.started_at,r.completed_at,r.duration_milliseconds,r.failure,
			r.witness_managed_app_id::text,r.witness_app_slug,r.witness_app_name,r.witness_oidc_client_id,r.witness_launch_url,r.witness_validation_url,r.witness_signed_out_url,r.witness_release_revision
		FROM app_validation_runs r
		WHERE r.managed_app_id=$1::uuid
		ORDER BY r.direction,r.requested_at DESC,r.id DESC`, appID)
	if err != nil {
		return nil, fmt.Errorf("list application validation results: %w", err)
	}
	defer rows.Close()
	results := map[string]AppValidationRun{}
	for rows.Next() {
		var run AppValidationRun
		var witnessID, witnessSlug, witnessName, witnessClientID, witnessLaunchURL, witnessValidationURL, witnessSignedOutURL, witnessRevision *string
		if err := rows.Scan(&run.ID, &run.ManagedAppID, &run.AppSlug, &run.AppName, &run.OIDCClientID, &run.LaunchURL, &run.ValidationURL, &run.SignedOutURL, &run.Direction, &run.ReleaseRevision, &run.ValidationContractHash, &run.Status, &run.RequestedAt, &run.StartedAt, &run.CompletedAt, &run.DurationMilliseconds, &run.Failure,
			&witnessID, &witnessSlug, &witnessName, &witnessClientID, &witnessLaunchURL, &witnessValidationURL, &witnessSignedOutURL, &witnessRevision); err != nil {
			return nil, fmt.Errorf("scan application validation result: %w", err)
		}
		if witnessID != nil {
			run.Witness = &AppValidationWitness{ManagedAppID: *witnessID, AppSlug: *witnessSlug, AppName: *witnessName, OIDCClientID: *witnessClientID, LaunchURL: *witnessLaunchURL, ValidationURL: *witnessValidationURL, SignedOutURL: *witnessSignedOutURL, ReleaseRevision: *witnessRevision}
		}
		results[run.Direction] = run
	}
	return results, rows.Err()
}

// ClaimAppValidation leases exactly one queued check. PostgreSQL serializes all
// workers globally and enforces at least 30 seconds between check starts.
func (s *Store) ClaimAppValidation(ctx context.Context, now time.Time) (*AppValidationRun, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin claim application validation: %w", err)
	}
	defer tx.Rollback(ctx)
	var activeRunID *string
	var nextStart time.Time
	if err := tx.QueryRow(ctx, `SELECT active_run_id::text,next_start_at FROM app_validation_control WHERE singleton=TRUE FOR UPDATE`).Scan(&activeRunID, &nextStart); err != nil {
		return nil, fmt.Errorf("lock application validation queue: %w", err)
	}
	if activeRunID != nil {
		var lease time.Time
		if err := tx.QueryRow(ctx, `SELECT lease_expires_at FROM app_validation_runs WHERE id=$1::uuid`, *activeRunID).Scan(&lease); err != nil {
			return nil, fmt.Errorf("read active application validation lease: %w", err)
		}
		if lease.After(now) {
			return nil, tx.Commit(ctx)
		}
		if _, err := tx.Exec(ctx, `UPDATE app_validation_runs SET status='failed',completed_at=$2,lease_expires_at=NULL,duration_milliseconds=GREATEST(0,EXTRACT(EPOCH FROM ($2-started_at))*1000)::bigint,failure='validator lease expired' WHERE id=$1::uuid AND status='running'`, *activeRunID, now.UTC()); err != nil {
			return nil, fmt.Errorf("expire abandoned application validation: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE app_validation_control SET active_run_id=NULL WHERE singleton=TRUE`); err != nil {
			return nil, fmt.Errorf("clear abandoned application validation: %w", err)
		}
	}
	if nextStart.After(now) {
		return nil, tx.Commit(ctx)
	}
	var run AppValidationRun
	var witnessID, witnessSlug, witnessName, witnessClientID, witnessLaunchURL, witnessValidationURL, witnessSignedOutURL, witnessRevision *string
	err = tx.QueryRow(ctx, `
		SELECT r.id::text,r.managed_app_id::text,r.app_slug,r.app_name,r.oidc_client_id,r.launch_url,r.validation_url,r.signed_out_url,r.direction,r.release_revision,r.status,r.requested_at,
			r.witness_managed_app_id::text,r.witness_app_slug,r.witness_app_name,r.witness_oidc_client_id,r.witness_launch_url,r.witness_validation_url,r.witness_signed_out_url,r.witness_release_revision
		FROM app_validation_runs r
		WHERE r.status='queued' ORDER BY r.requested_at,r.id LIMIT 1 FOR UPDATE OF r SKIP LOCKED`).
		Scan(&run.ID, &run.ManagedAppID, &run.AppSlug, &run.AppName, &run.OIDCClientID, &run.LaunchURL, &run.ValidationURL, &run.SignedOutURL, &run.Direction, &run.ReleaseRevision, &run.Status, &run.RequestedAt,
			&witnessID, &witnessSlug, &witnessName, &witnessClientID, &witnessLaunchURL, &witnessValidationURL, &witnessSignedOutURL, &witnessRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, tx.Commit(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("select application validation: %w", err)
	}
	if witnessID != nil {
		run.Witness = &AppValidationWitness{ManagedAppID: *witnessID, AppSlug: *witnessSlug, AppName: *witnessName, OIDCClientID: *witnessClientID, LaunchURL: *witnessLaunchURL, ValidationURL: *witnessValidationURL, SignedOutURL: *witnessSignedOutURL, ReleaseRevision: *witnessRevision}
	}
	started := now.UTC()
	lease := started.Add(10 * time.Minute)
	if _, err := tx.Exec(ctx, `UPDATE app_validation_runs SET status='running',started_at=$2,lease_expires_at=$3 WHERE id=$1::uuid`, run.ID, started, lease); err != nil {
		return nil, fmt.Errorf("lease application validation: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE app_validation_control SET active_run_id=$1::uuid,next_start_at=$2 WHERE singleton=TRUE`, run.ID, started.Add(30*time.Second)); err != nil {
		return nil, fmt.Errorf("advance application validation cooldown: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit claim application validation: %w", err)
	}
	run.Status, run.StartedAt = ValidationRunning, &started
	return &run, nil
}

func (s *Store) CompleteAppValidation(ctx context.Context, runID, status, failure string, now time.Time) error {
	if status != ValidationPassed && status != ValidationFailed {
		return fmt.Errorf("application validation result must be passed or failed")
	}
	if len(failure) > 1000 {
		failure = failure[:1000]
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin complete application validation: %w", err)
	}
	defer tx.Rollback(ctx)
	command, err := tx.Exec(ctx, `UPDATE app_validation_runs SET status=$2,completed_at=$3,lease_expires_at=NULL,duration_milliseconds=GREATEST(0,EXTRACT(EPOCH FROM ($3-started_at))*1000)::bigint,failure=$4 WHERE id=$1::uuid AND status='running'`, runID, status, now.UTC(), strings.TrimSpace(failure))
	if err != nil {
		return fmt.Errorf("complete application validation: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("active application validation not found")
	}
	if _, err := tx.Exec(ctx, `UPDATE app_validation_control SET active_run_id=NULL WHERE singleton=TRUE AND active_run_id=$1::uuid`, runID); err != nil {
		return fmt.Errorf("release application validation queue: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit application validation result: %w", err)
	}
	return nil
}

// ExpireAbandonedAppValidation records a durable failure when a worker did not
// complete its leased browser check. A later worker can then claim the queue.
func (s *Store) ExpireAbandonedAppValidation(ctx context.Context, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin expire application validation: %w", err)
	}
	defer tx.Rollback(ctx)
	var activeRunID *string
	if err := tx.QueryRow(ctx, `SELECT active_run_id::text FROM app_validation_control WHERE singleton=TRUE FOR UPDATE`).Scan(&activeRunID); err != nil {
		return fmt.Errorf("lock application validation queue: %w", err)
	}
	if activeRunID == nil {
		return tx.Commit(ctx)
	}
	var lease time.Time
	if err := tx.QueryRow(ctx, `SELECT lease_expires_at FROM app_validation_runs WHERE id=$1::uuid AND status='running'`, *activeRunID).Scan(&lease); err != nil {
		return fmt.Errorf("read active application validation lease: %w", err)
	}
	if lease.After(now) {
		return tx.Commit(ctx)
	}
	completed := now.UTC()
	if _, err := tx.Exec(ctx, `UPDATE app_validation_runs SET status='failed',completed_at=$2,lease_expires_at=NULL,duration_milliseconds=GREATEST(0,EXTRACT(EPOCH FROM ($2-started_at))*1000)::bigint,failure='validator lease expired' WHERE id=$1::uuid AND status='running'`, *activeRunID, completed); err != nil {
		return fmt.Errorf("expire abandoned application validation: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE app_validation_control SET active_run_id=NULL WHERE singleton=TRUE AND active_run_id=$1::uuid`, *activeRunID); err != nil {
		return fmt.Errorf("release abandoned application validation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit expired application validation: %w", err)
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
	if !immutableReleaseRevisionPattern.MatchString(app.ReleaseRevision) {
		return fmt.Errorf("app release revision must be a 12–64 character lowercase hexadecimal commit or a sha256 digest")
	}
	launchURL, err := url.ParseRequestURI(strings.TrimSpace(app.LaunchURL))
	if err != nil || !validManagedAppURL(launchURL) {
		return fmt.Errorf("app launch URL must use HTTPS unless it targets loopback")
	}
	healthURL, err := url.ParseRequestURI(strings.TrimSpace(app.HealthURL))
	if err != nil || !validManagedAppURL(healthURL) {
		return fmt.Errorf("app health URL must use HTTPS unless it targets loopback")
	}
	if !sameURLOrigin(launchURL, healthURL) {
		return fmt.Errorf("app launch and health URLs must use one application origin")
	}
	for label, raw := range map[string]string{"validation": app.ValidationURL, "signed-out": app.SignedOutURL} {
		coordinate, err := url.ParseRequestURI(raw)
		if err != nil || !validManagedAppURL(coordinate) {
			return fmt.Errorf("app %s URL must use HTTPS unless it targets loopback", label)
		}
		if !sameURLOrigin(launchURL, coordinate) {
			return fmt.Errorf("app launch and %s URLs must use one application origin", label)
		}
	}
	if app.MonitoringURL != "" {
		monitoringURL, err := url.ParseRequestURI(app.MonitoringURL)
		if err != nil || !validManagedAppURL(monitoringURL) {
			return fmt.Errorf("app monitoring URL must use HTTPS unless it targets loopback")
		}
		if !sameURLOrigin(launchURL, monitoringURL) {
			return fmt.Errorf("app launch and monitoring URLs must use one application origin")
		}
	}
	return nil
}

func sameURLOrigin(left, right *url.URL) bool {
	return left != nil && right != nil && strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func validManagedAppURL(value *url.URL) bool {
	if value == nil || value.Host == "" || value.User != nil || value.Fragment != "" {
		return false
	}
	if value.Scheme == "https" {
		return true
	}
	host := strings.Trim(strings.ToLower(value.Hostname()), "[]")
	return value.Scheme == "http" && (host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "::1" || net.ParseIP(host).IsLoopback())
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
	return s.insertUser(ctx, randomUUID(), username, email, true, hash, nil, "", role)
}

// EnsureBootstrapAdmin creates the explicitly configured break-glass admin on
// first start and promotes the same email on later starts.
func (s *Store) EnsureBootstrapAdmin(ctx context.Context, email, password string) (User, error) {
	if email == "" {
		return User{}, nil
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || len(password) < 14 {
		return User{}, fmt.Errorf("bootstrap admin email and a password of at least 14 characters are required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, fmt.Errorf("hash bootstrap admin password: %w", err)
	}
	username := strings.Split(email, "@")[0]
	var user User
	err = s.pool.QueryRow(ctx, `INSERT INTO users (id,username,email,email_verified,password_hash,role,created_at)
	VALUES ($1::uuid,$2,$3,TRUE,$4,'admin',now())
	ON CONFLICT (email) DO UPDATE SET password_hash=EXCLUDED.password_hash,email_verified=TRUE,role='admin',disabled_at=NULL
	WHERE users.is_validation=FALSE
	RETURNING id::text,username,email,email_verified,COALESCE(github_login,''),role,disabled_at,created_at`, randomUUID(), username, email, hash).
		Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.GitHubLogin, &user.Role, &user.DisabledAt, &user.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, fmt.Errorf("bootstrap administrator email belongs to the validation account")
	}
	if err != nil {
		return User{}, fmt.Errorf("ensure bootstrap admin: %w", err)
	}
	return user, nil
}

// EnsureValidationUser provisions the dedicated real browser-validation
// account. It has the developer role and no administrative privileges.
func (s *Store) EnsureValidationUser(ctx context.Context, username, email string) (User, error) {
	if username == "" && email == "" {
		return User{}, nil
	}
	username = strings.TrimSpace(username)
	email = strings.ToLower(strings.TrimSpace(email))
	if username == "" || email == "" {
		return User{}, fmt.Errorf("validation username and email are required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("begin validation user provisioning: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('shauth-validation-identity'))`); err != nil {
		return User{}, fmt.Errorf("lock validation user provisioning: %w", err)
	}
	var existingID string
	err = tx.QueryRow(ctx, `SELECT id::text FROM users WHERE is_validation=TRUE FOR UPDATE`).Scan(&existingID)
	var user User
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		err = tx.QueryRow(ctx, `INSERT INTO users (id,username,email,email_verified,password_hash,role,is_validation,created_at)
			VALUES ($1::uuid,$2,$3,TRUE,NULL,'developer',TRUE,now())
			RETURNING id::text,username,email,email_verified,COALESCE(github_login,''),role,disabled_at,created_at`, randomUUID(), username, email).
			Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.GitHubLogin, &user.Role, &user.DisabledAt, &user.CreatedAt)
	case err == nil:
		err = tx.QueryRow(ctx, `UPDATE users
			SET username=$2,email=$3,password_hash=NULL,github_id=NULL,github_login=NULL,entra_tenant_id=NULL,entra_object_id=NULL,email_verified=TRUE,role='developer',disabled_at=NULL
			WHERE id=$1::uuid AND is_validation=TRUE
			RETURNING id::text,username,email,email_verified,COALESCE(github_login,''),role,disabled_at,created_at`, existingID, username, email).
			Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.GitHubLogin, &user.Role, &user.DisabledAt, &user.CreatedAt)
	default:
		return User{}, fmt.Errorf("find validation user: %w", err)
	}
	if err != nil {
		return User{}, fmt.Errorf("ensure validation user: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("commit validation user provisioning: %w", err)
	}
	return user, nil
}

// CreateValidationBrowserBootstraps creates short-lived, single-use browser
// session grants for the dedicated validation identity. Only SHA-256 hashes are
// persisted; the raw tokens are returned once to the authenticated worker.
func (s *Store) CreateValidationBrowserBootstraps(ctx context.Context, nextPaths []string, now time.Time) ([]string, error) {
	if len(nextPaths) == 0 || len(nextPaths) > 3 {
		return nil, fmt.Errorf("one to three validation browser bootstraps are required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin validation browser bootstrap creation: %w", err)
	}
	defer tx.Rollback(ctx)
	var userID string
	if err := tx.QueryRow(ctx, `SELECT id::text FROM users WHERE is_validation=TRUE AND disabled_at IS NULL AND role='developer'`).Scan(&userID); err != nil {
		return nil, fmt.Errorf("find validation identity: %w", err)
	}
	created := now.UTC()
	if _, err := tx.Exec(ctx, `DELETE FROM validation_browser_bootstraps WHERE expires_at<$1 OR consumed_at<$2`, created, created.Add(-24*time.Hour)); err != nil {
		return nil, fmt.Errorf("remove expired validation browser bootstraps: %w", err)
	}
	rawTokens := make([]string, 0, len(nextPaths))
	for _, nextPath := range nextPaths {
		raw, err := randomToken()
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256([]byte(raw))
		if _, err := tx.Exec(ctx, `INSERT INTO validation_browser_bootstraps (id,token_hash,validation_user_id,next_path,created_at,expires_at) VALUES ($1::uuid,$2,$3::uuid,$4,$5,$6)`, randomUUID(), hash[:], userID, nextPath, created, created.Add(validationBrowserBootstrapLifetime)); err != nil {
			return nil, fmt.Errorf("create validation browser bootstrap: %w", err)
		}
		rawTokens = append(rawTokens, raw)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit validation browser bootstraps: %w", err)
	}
	return rawTokens, nil
}

// ConsumeValidationBrowserBootstrap atomically exchanges one unexpired token
// for the validation identity and its prevalidated local destination.
func (s *Store) ConsumeValidationBrowserBootstrap(ctx context.Context, raw string, now time.Time) (User, string, error) {
	if !browserBootstrapTokenPattern.MatchString(raw) {
		return User{}, "", fmt.Errorf("validation browser bootstrap is unavailable")
	}
	hash := sha256.Sum256([]byte(raw))
	var user User
	var nextPath string
	err := s.pool.QueryRow(ctx, `UPDATE validation_browser_bootstraps bootstrap
		SET consumed_at=$2
		FROM users
		WHERE bootstrap.token_hash=$1
		  AND bootstrap.consumed_at IS NULL
		  AND bootstrap.expires_at>$2
		  AND users.id=bootstrap.validation_user_id
		  AND users.is_validation=TRUE
		  AND users.disabled_at IS NULL
		  AND users.role='developer'
		RETURNING users.id::text,users.username,users.email,users.email_verified,COALESCE(users.github_login,''),users.role,users.disabled_at,users.created_at,bootstrap.next_path`, hash[:], now.UTC()).
		Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.GitHubLogin, &user.Role, &user.DisabledAt, &user.CreatedAt, &nextPath)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, "", fmt.Errorf("validation browser bootstrap is unavailable")
	}
	if err != nil {
		return User{}, "", fmt.Errorf("consume validation browser bootstrap: %w", err)
	}
	return user, nextPath, nil
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

func (s *Store) insertUser(ctx context.Context, id, username, email string, emailVerified bool, hash []byte, githubID *int64, githubLogin string, role Role) (User, error) {
	var user User
	err := s.pool.QueryRow(ctx, `INSERT INTO users (id,username,email,email_verified,password_hash,github_id,github_login,role,created_at)
	VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,now()) RETURNING id::text,username,email,email_verified,COALESCE(github_login,''),role,disabled_at,created_at`, id, username, email, emailVerified, hash, githubID, nullable(githubLogin), role).
		Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.GitHubLogin, &user.Role, &user.DisabledAt, &user.CreatedAt)
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func (s *Store) AuthenticatePassword(ctx context.Context, username, password string) (User, error) {
	var user User
	var hash []byte
	err := s.pool.QueryRow(ctx, `SELECT id::text,username,email,email_verified,COALESCE(github_login,''),role,disabled_at,created_at,password_hash FROM users WHERE username=$1 AND is_validation=FALSE`, strings.TrimSpace(username)).
		Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.GitHubLogin, &user.Role, &user.DisabledAt, &user.CreatedAt, &hash)
	if err != nil || user.DisabledAt != nil || len(hash) == 0 || bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil {
		return User{}, fmt.Errorf("invalid username or password")
	}
	return user, nil
}

func (s *Store) FindOrCreateGitHubUser(ctx context.Context, githubID int64, login, email string, role Role) (User, error) {
	login = strings.TrimSpace(login)
	email = strings.ToLower(strings.TrimSpace(email))
	var user User
	err := s.pool.QueryRow(ctx, `SELECT id::text,username,email,email_verified,COALESCE(github_login,''),role,disabled_at,created_at FROM users WHERE github_id=$1`, githubID).
		Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.GitHubLogin, &user.Role, &user.DisabledAt, &user.CreatedAt)
	if err == nil {
		if user.DisabledAt != nil {
			return User{}, fmt.Errorf("user is disabled")
		}
		if user.Role != role || user.Email != email || !user.EmailVerified {
			_, err = s.pool.Exec(ctx, `UPDATE users SET role=$2,email=$3,email_verified=TRUE WHERE id=$1::uuid`, user.ID, role, email)
			if err != nil {
				return User{}, fmt.Errorf("synchronize GitHub user: %w", err)
			}
			user.Role = role
			user.Email = email
			user.EmailVerified = true
		}
		return user, nil
	}
	if err != pgx.ErrNoRows {
		return User{}, fmt.Errorf("find GitHub user: %w", err)
	}
	if login == "" || email == "" {
		return User{}, fmt.Errorf("GitHub account must provide login and verified email")
	}
	return s.insertUser(ctx, randomUUID(), login, email, true, nil, &githubID, login, role)
}

func (s *Store) FindOrCreateEntraUser(ctx context.Context, tenantID, objectID, username, email string, emailVerified bool) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	username = strings.TrimSpace(username)
	if tenantID == "" || objectID == "" || email == "" || username == "" {
		return User{}, fmt.Errorf("Microsoft Entra ID account must provide tenant, object, username, and email claims")
	}
	var user User
	err := s.pool.QueryRow(ctx, `UPDATE users SET email_verified=CASE WHEN email=$3 THEN email_verified OR $4 ELSE $4 END,email=$3 WHERE entra_tenant_id=$1::uuid AND entra_object_id=$2::uuid RETURNING id::text,username,email,email_verified,COALESCE(github_login,''),role,disabled_at,created_at`, tenantID, objectID, email, emailVerified).
		Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.GitHubLogin, &user.Role, &user.DisabledAt, &user.CreatedAt)
	if err == nil {
		if user.DisabledAt != nil {
			return User{}, fmt.Errorf("user is disabled")
		}
		return user, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return User{}, fmt.Errorf("find Microsoft Entra ID user: %w", err)
	}
	err = s.pool.QueryRow(ctx, `UPDATE users SET entra_tenant_id=$2::uuid,entra_object_id=$3::uuid,email_verified=email_verified OR $4 WHERE email=$1 AND entra_tenant_id IS NULL AND disabled_at IS NULL AND is_validation=FALSE RETURNING id::text,username,email,email_verified,COALESCE(github_login,''),role,disabled_at,created_at`, email, tenantID, objectID, emailVerified).
		Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.GitHubLogin, &user.Role, &user.DisabledAt, &user.CreatedAt)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return User{}, fmt.Errorf("link Microsoft Entra ID user: %w", err)
	}
	id := randomUUID()
	err = s.pool.QueryRow(ctx, `INSERT INTO users (id,username,email,email_verified,password_hash,role,entra_tenant_id,entra_object_id,created_at) VALUES ($1::uuid,$2,$3,$4,NULL,'developer',$5::uuid,$6::uuid,now()) RETURNING id::text,username,email,email_verified,COALESCE(github_login,''),role,disabled_at,created_at`, id, username, email, emailVerified, tenantID, objectID).
		Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.GitHubLogin, &user.Role, &user.DisabledAt, &user.CreatedAt)
	if err != nil {
		return User{}, fmt.Errorf("create Microsoft Entra ID user: %w", err)
	}
	return user, nil
}

func (s *Store) CreateSession(ctx context.Context, userID, userAgent string, remoteIP net.IP, now time.Time) (string, Session, error) {
	policy, err := s.SessionPolicy(ctx)
	if err != nil {
		return "", Session{}, err
	}
	raw, err := randomToken()
	if err != nil {
		return "", Session{}, err
	}
	tokenHash := sha256.Sum256([]byte(raw))
	id := randomUUID()
	family := randomUUID()
	expiry := now.UTC().Add(policy.BrowserAbsoluteLifetime)
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
	policy, err := s.SessionPolicy(ctx)
	if err != nil {
		return User{}, Session{}, err
	}
	hash := sha256.Sum256([]byte(raw))
	var user User
	var session Session
	err = s.pool.QueryRow(ctx, `SELECT u.id::text,u.username,u.email,u.email_verified,COALESCE(u.github_login,''),u.role,u.disabled_at,u.created_at,s.id::text,s.user_id::text,s.created_at,s.last_seen_at,s.expires_at,s.revoked_at,s.user_agent,s.remote_address
	FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.browser_token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>$2 AND s.last_seen_at>$3 AND u.disabled_at IS NULL`, hash[:], now.UTC(), now.UTC().Add(-policy.BrowserIdleTimeout)).
		Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.GitHubLogin, &user.Role, &user.DisabledAt, &user.CreatedAt, &session.ID, &session.UserID, &session.CreatedAt, &session.LastSeen, &session.ExpiresAt, &session.RevokedAt, &session.UserAgent, &session.RemoteIP)
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
	rows, err := s.pool.Query(ctx, `SELECT id::text,username,email,email_verified,COALESCE(github_login,''),CASE WHEN github_login IS NOT NULL THEN 'GitHub: ' || github_login WHEN entra_object_id IS NOT NULL THEN 'Microsoft Entra ID' ELSE 'Local account' END,role,disabled_at,created_at FROM users WHERE username ILIKE '%' || $1 || '%' OR email ILIKE '%' || $1 || '%' OR COALESCE(github_login,'') ILIKE '%' || $1 || '%' ORDER BY created_at DESC`, strings.TrimSpace(query))
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.EmailVerified, &u.GitHubLogin, &u.FederatedIdentity, &u.Role, &u.DisabledAt, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}
func (s *Store) ListSessions(ctx context.Context, userID string) ([]Session, error) {
	policy, err := s.SessionPolicy(ctx)
	if err != nil {
		return nil, err
	}
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
		now := time.Now().UTC()
		v.Active = v.RevokedAt == nil && v.ExpiresAt.After(now) && v.LastSeen.After(now.Add(-policy.BrowserIdleTimeout))
		sessions = append(sessions, v)
	}
	return sessions, rows.Err()
}

func (s *Store) RecordHydraLoginSession(ctx context.Context, browserSessionID, hydraSessionID string, now time.Time) error {
	if strings.TrimSpace(browserSessionID) == "" || strings.TrimSpace(hydraSessionID) == "" {
		return fmt.Errorf("browser and Ory Hydra session IDs are required")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO hydra_login_sessions (hydra_session_id,browser_session_id,created_at)
	VALUES ($1,$2::uuid,$3) ON CONFLICT (hydra_session_id) DO UPDATE SET browser_session_id=EXCLUDED.browser_session_id`, hydraSessionID, browserSessionID, now.UTC())
	if err != nil {
		return fmt.Errorf("record Ory Hydra login session: %w", err)
	}
	return nil
}

func (s *Store) HydraLoginSessionIDs(ctx context.Context, browserSessionID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT hydra_session_id FROM hydra_login_sessions WHERE browser_session_id=$1::uuid ORDER BY created_at,hydra_session_id`, browserSessionID)
	if err != nil {
		return nil, fmt.Errorf("list Ory Hydra login sessions: %w", err)
	}
	defer rows.Close()
	var sessionIDs []string
	for rows.Next() {
		var sessionID string
		if err := rows.Scan(&sessionID); err != nil {
			return nil, fmt.Errorf("scan Ory Hydra login session: %w", err)
		}
		sessionIDs = append(sessionIDs, sessionID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list Ory Hydra login sessions: %w", err)
	}
	return sessionIDs, nil
}

func (s *Store) UserHydraLoginSessionIDs(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT h.hydra_session_id
	FROM hydra_login_sessions h JOIN sessions s ON s.id=h.browser_session_id
	WHERE s.user_id=$1::uuid ORDER BY h.hydra_session_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list user Ory Hydra login sessions: %w", err)
	}
	defer rows.Close()
	var sessionIDs []string
	for rows.Next() {
		var sessionID string
		if err := rows.Scan(&sessionID); err != nil {
			return nil, fmt.Errorf("scan user Ory Hydra login session: %w", err)
		}
		sessionIDs = append(sessionIDs, sessionID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list user Ory Hydra login sessions: %w", err)
	}
	return sessionIDs, nil
}

func (s *Store) ActiveUserHydraLoginSessionIDs(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT h.hydra_session_id
	FROM hydra_login_sessions h JOIN sessions s ON s.id=h.browser_session_id
	WHERE s.user_id=$1::uuid AND s.revoked_at IS NULL
	ORDER BY h.hydra_session_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list active user Ory Hydra login sessions: %w", err)
	}
	defer rows.Close()
	var sessionIDs []string
	for rows.Next() {
		var sessionID string
		if err := rows.Scan(&sessionID); err != nil {
			return nil, fmt.Errorf("scan active user Ory Hydra login session: %w", err)
		}
		sessionIDs = append(sessionIDs, sessionID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list active user Ory Hydra login sessions: %w", err)
	}
	return sessionIDs, nil
}

func (s *Store) RevokeSession(ctx context.Context, id string, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin session revocation: %w", err)
	}
	defer tx.Rollback(ctx)
	var familyID string
	if err := tx.QueryRow(ctx, `UPDATE sessions SET revoked_at=$2 WHERE id=$1::uuid AND revoked_at IS NULL RETURNING refresh_family_id::text`, id, now.UTC()).Scan(&familyID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("active session not found")
		}
		return fmt.Errorf("revoke session: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=$2 WHERE family_id=$1::uuid AND revoked_at IS NULL`, familyID, now.UTC()); err != nil {
		return fmt.Errorf("revoke session refresh tokens: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit session revocation: %w", err)
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
	_, err := s.pool.Exec(ctx, `WITH revoked AS (
		UPDATE sessions
		SET revoked_at=$2
		WHERE user_id=$1::uuid AND revoked_at IS NULL
		RETURNING refresh_family_id
	)
	UPDATE refresh_tokens
	SET revoked_at=$2
	WHERE family_id IN (SELECT refresh_family_id FROM revoked) AND revoked_at IS NULL`, userID, now.UTC())
	if err != nil {
		return fmt.Errorf("revoke user sessions: %w", err)
	}
	return nil
}
func (s *Store) CountActiveSessions(ctx context.Context, now time.Time) (int, error) {
	policy, err := s.SessionPolicy(ctx)
	if err != nil {
		return 0, err
	}
	var n int
	err = s.pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at>$1 AND last_seen_at>$2`, now.UTC(), now.UTC().Add(-policy.BrowserIdleTimeout)).Scan(&n)
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
