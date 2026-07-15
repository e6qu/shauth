// SPDX-License-Identifier: AGPL-3.0-or-later

// Shauth is the e6qu identity administration and observability service.
package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/e6qu/shauth/internal/app"
	"github.com/e6qu/shauth/internal/config"
	"github.com/e6qu/shauth/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	cfg, err := config.FromEnvironment()
	if err != nil {
		log.Fatal(err)
	}
	pool, err := pgxpool.New(context.Background(), cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pool.Close()
	store, err := identity.NewStore(pool)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := store.EnsureBootstrapAdmin(context.Background(), cfg.BootstrapAdminEmail, cfg.BootstrapAdminPassword); err != nil {
		log.Fatalf("bootstrap administrator: %v", err)
	}
	if err := store.EnsureInitialGitHubRoleMappings(context.Background(), cfg.GitHubDeveloperTeam, cfg.GitHubAdminTeam); err != nil {
		log.Fatalf("bootstrap GitHub role mappings: %v", err)
	}
	serverApp, err := app.New(cfg, store)
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              cfg.Address,
		Handler:           serverApp.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("shauth listening on %s", cfg.Address)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
