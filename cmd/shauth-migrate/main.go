// SPDX-License-Identifier: AGPL-3.0-or-later

// shauth-migrate applies the immutable Shauth PostgreSQL migrations.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultMigrationsDirectory = "/migrations"

func main() {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL must be set")
	}
	directory := os.Getenv("SHAUTH_MIGRATIONS_DIR")
	if directory == "" {
		directory = defaultMigrationsDirectory
	}

	// A migration that cannot take its locks must fail with a clear error,
	// not wait forever behind a task that is still serving traffic.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		log.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pool.Close()
	if err := apply(ctx, pool, directory); err != nil {
		log.Fatal(err)
	}
}

// migrationLockID serializes migrators: two tasks starting together must not
// both find a migration missing and race to apply it.
const migrationLockID int64 = 0x5348415554484d47

func apply(ctx context.Context, pool *pgxpool.Pool, directory string) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("wait for other migrators: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockID)
	}()
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	filenames := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			filenames = append(filenames, entry.Name())
		}
	}
	sort.Strings(filenames)

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS shauth_schema_migrations (filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	for _, filename := range filenames {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM shauth_schema_migrations WHERE filename = $1)`, filename).Scan(&exists); err != nil {
			return fmt.Errorf("read migration ledger: %w", err)
		}
		if exists {
			continue
		}
		body, err := os.ReadFile(filepath.Join(directory, filename))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", filename, err)
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", filename, err)
		}
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '30s'`); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("bound lock wait for migration %s: %w", filename, err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", filename, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO shauth_schema_migrations (filename, applied_at) VALUES ($1, now())`, filename); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", filename, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", filename, err)
		}
	}
	return nil
}
