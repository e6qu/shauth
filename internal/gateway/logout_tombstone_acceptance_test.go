// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build acceptance

package gateway

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPausedCallbackCannotCreateSessionAfterProviderLogout(t *testing.T) {
	databaseURL := os.Getenv("SHAUTH_ACCEPTANCE_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("SHAUTH_ACCEPTANCE_DATABASE_URL is required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pool.Close()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate gateway schema: %v", err)
	}

	for _, test := range []struct {
		name   string
		revoke func(*Store, string, time.Time) error
	}{
		{
			name: "front-channel",
			revoke: func(store *Store, sid string, now time.Time) error {
				return store.RevokeFrontchannelSession(ctx, sid, now)
			},
		},
		{
			name: "back-channel",
			revoke: func(store *Store, sid string, now time.Time) error {
				return store.RevokeProviderSession(ctx, sid, "logout-token-"+sid, now.Add(time.Minute), now)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC()
			sessionID := randomGatewayUUID()
			providerSID := "provider-" + strings.ReplaceAll(sessionID, "-", "")
			clientID := "acceptance-" + strings.ReplaceAll(randomGatewayUUID(), "-", "")
			store, err := NewStore(pool, clientID, "https://auth.example.test", strings.Repeat("s", 32), time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				_, _ = pool.Exec(ctx, `DELETE FROM oidc_gateway_sessions WHERE client_id=$1`, clientID)
				_, _ = pool.Exec(ctx, `DELETE FROM oidc_gateway_logout_tokens WHERE client_id=$1`, clientID)
				_, _ = pool.Exec(ctx, `DELETE FROM oidc_gateway_logout_tombstones WHERE client_id=$1`, clientID)
			}()

			// The relying-party callback has verified its provider response but is
			// paused before persistence. Logout must win durably even though no
			// local application session exists yet.
			if err := test.revoke(store, providerSID, now); err != nil {
				t.Fatalf("record provider logout: %v", err)
			}
			session := Session{
				ID:                sessionID,
				Subject:           randomGatewayUUID(),
				ProviderSessionID: providerSID,
				IDToken:           "verified-id-token",
				Username:          "acceptance-user",
				Email:             "acceptance@example.test",
				Role:              "developer",
				ExpiresAt:         now.Add(time.Hour),
			}
			if err := store.Create(ctx, session, []byte("paused-callback-token"), now.Add(time.Second)); err == nil || !strings.Contains(err.Error(), "logged out") {
				t.Fatalf("paused callback was not rejected after logout: %v", err)
			}
			var sessions int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM oidc_gateway_sessions WHERE client_id=$1 AND provider_session_id=$2`, clientID, providerSID).Scan(&sessions); err != nil {
				t.Fatal(err)
			}
			if sessions != 0 {
				t.Fatalf("logged-out provider session was persisted %d times", sessions)
			}
		})
	}
}

func randomGatewayUUID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}
