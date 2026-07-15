// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is the PostgreSQL source of truth for multi-device sessions and their
// refresh-token families.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, fmt.Errorf("session store requires a PostgreSQL pool")
	}
	return &Store{pool: pool}, nil
}

// RevokeSession atomically revokes exactly one active session and every token
// in its refresh-token family.
func (store *Store) RevokeSession(ctx context.Context, id ID, now time.Time) error {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin session revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var familyID string
	if err := tx.QueryRow(ctx, revokeSessionSQL, id, now.UTC()).Scan(&familyID); err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("session %q is not active", id)
		}
		return fmt.Errorf("revoke session: %w", err)
	}
	if _, err := tx.Exec(ctx, revokeFamilySQL, familyID, now.UTC()); err != nil {
		return fmt.Errorf("revoke refresh-token family: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit session revocation: %w", err)
	}
	return nil
}

// RevokeUserSessions atomically invalidates every currently active session and
// refresh token belonging to one user.
func (store *Store) RevokeUserSessions(ctx context.Context, userID UserID, now time.Time) error {
	command, err := store.pool.Exec(ctx, revokeUserSessionsSQL, userID, now.UTC())
	if err != nil {
		return fmt.Errorf("revoke user sessions: %w", err)
	}
	if command.RowsAffected() == 0 {
		return fmt.Errorf("user %q has no active sessions", userID)
	}
	return nil
}
