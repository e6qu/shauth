// SPDX-License-Identifier: AGPL-3.0-or-later

// Shauth Gateway is the generic OIDC relying-party reverse proxy for UI-only
// services enrolled in Shauth.
package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/e6qu/shauth/internal/gateway"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	config, err := gateway.FromEnvironment()
	if err != nil {
		log.Fatal(err)
	}
	pool, err := pgxpool.New(context.Background(), config.DatabaseURL)
	if err != nil {
		log.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pool.Close()
	if err := gateway.Migrate(context.Background(), pool); err != nil {
		log.Fatalf("migrate gateway PostgreSQL schema: %v", err)
	}
	application, err := gateway.New(context.Background(), config, pool)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: config.Address, Handler: application.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 * 1024}
	log.Printf("Shauth OIDC gateway listening on %s", config.Address)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
