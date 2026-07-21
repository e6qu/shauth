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
	if _, err := store.EnsureValidationUser(context.Background(), cfg.ValidationUsername, cfg.ValidationEmail); err != nil {
		log.Fatalf("bootstrap validation account: %v", err)
	}
	if err := store.EnsureInitialGitHubRoleMappings(context.Background(), cfg.GitHubDeveloperTeam, cfg.GitHubAdminTeam); err != nil {
		log.Fatalf("bootstrap GitHub role mappings: %v", err)
	}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for observedAt := range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			err := store.ExpireAbandonedAppValidation(ctx, observedAt)
			cancel()
			if err != nil {
				log.Printf("expire abandoned application validation: %v", err)
			}
		}
	}()
	serverApp, err := app.New(cfg, store)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for observedAt := range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			recoveryErr := serverApp.RecoverAbandonedLogout(ctx, observedAt)
			_, cleanupErr := store.DeleteCompletedLogoutCorrelationGrants(ctx, observedAt.Add(-identity.LogoutCorrelationRetention), 1000)
			cancel()
			if recoveryErr != nil {
				log.Printf("recover abandoned provider logout: %v", recoveryErr)
			}
			if cleanupErr != nil {
				log.Printf("delete completed provider logout evidence: %v", cleanupErr)
			}
		}
	}()

	server := &http.Server{
		Addr:              cfg.Address,
		Handler:           serverApp.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
	log.Printf("shauth listening on %s", cfg.Address)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
