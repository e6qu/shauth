// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

const migrationLockID int64 = 0x5348415554484757

// Migrate applies only the schema owned by the generic OIDC relying-party
// gateway. It is safe for several replicas to call concurrently against the
// relying party's dedicated PostgreSQL database.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("read gateway migrations: %w", err)
	}
	filenames := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			filenames = append(filenames, entry.Name())
		}
	}
	sort.Strings(filenames)
	for _, filename := range filenames {
		if err := applyMigration(ctx, pool, filename); err != nil {
			return err
		}
	}
	return nil
}

func applyMigration(ctx context.Context, pool *pgxpool.Pool, filename string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin gateway migration %s: %w", filename, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("lock gateway migrations: %w", err)
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS shauth_gateway_schema_migrations (filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL)`); err != nil {
		return fmt.Errorf("create gateway migration ledger: %w", err)
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM shauth_gateway_schema_migrations WHERE filename=$1)`, filename).Scan(&exists); err != nil {
		return fmt.Errorf("read gateway migration ledger: %w", err)
	}
	if exists {
		return tx.Commit(ctx)
	}
	body, err := migrationFiles.ReadFile("migrations/" + filename)
	if err != nil {
		return fmt.Errorf("read gateway migration %s: %w", filename, err)
	}
	if _, err := tx.Exec(ctx, string(body)); err != nil {
		return fmt.Errorf("apply gateway migration %s: %w", filename, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO shauth_gateway_schema_migrations(filename,applied_at) VALUES ($1,now())`, filename); err != nil {
		return fmt.Errorf("record gateway migration %s: %w", filename, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit gateway migration %s: %w", filename, err)
	}
	return nil
}
