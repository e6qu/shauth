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

	context := context.Background()
	pool, err := pgxpool.New(context, databaseURL)
	if err != nil {
		log.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pool.Close()
	if err := apply(context, pool, directory); err != nil {
		log.Fatal(err)
	}
}

func apply(ctx context.Context, pool *pgxpool.Pool, directory string) error {
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

	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS shauth_schema_migrations (filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	for _, filename := range filenames {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM shauth_schema_migrations WHERE filename = $1)`, filename).Scan(&exists); err != nil {
			return fmt.Errorf("read migration ledger: %w", err)
		}
		if exists {
			continue
		}
		body, err := os.ReadFile(filepath.Join(directory, filename))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", filename, err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", filename, err)
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
