// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Session struct {
	ID                string
	Subject           string
	ProviderSessionID string
	IDToken           string
	Username          string
	Email             string
	Role              string
	ExpiresAt         time.Time
}

type Store struct {
	pool              *pgxpool.Pool
	clientID          string
	issuer            string
	aead              cipher.AEAD
	tombstoneLifetime time.Duration
}

func NewStore(pool *pgxpool.Pool, clientID, issuer, secret string, tombstoneLifetime time.Duration) (*Store, error) {
	if tombstoneLifetime <= 0 {
		return nil, fmt.Errorf("gateway logout tombstone lifetime must be positive")
	}
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create gateway session cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gateway session AEAD: %w", err)
	}
	return &Store{pool: pool, clientID: clientID, issuer: issuer, aead: aead, tombstoneLifetime: tombstoneLifetime}, nil
}

func (store *Store) Create(ctx context.Context, session Session, browserToken []byte, now time.Time) error {
	nonce := make([]byte, store.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate ID-token nonce: %w", err)
	}
	ciphertext := append(nonce, store.aead.Seal(nil, nonce, []byte(session.IDToken), sessionAdditionalData(store.clientID, store.issuer, session))...)
	tokenHash := sha256.Sum256(browserToken)
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin gateway session creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.lockProviderSession(ctx, tx, session.ProviderSessionID); err != nil {
		return err
	}
	if err := deleteExpiredLogoutTombstones(ctx, tx, now, 1000); err != nil {
		return err
	}
	var tombstoned bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM oidc_gateway_logout_tombstones
		WHERE client_id=$1 AND issuer=$2 AND provider_session_id=$3 AND expires_at>$4
	)`, store.clientID, store.issuer, session.ProviderSessionID, now.UTC()).Scan(&tombstoned); err != nil {
		return fmt.Errorf("read gateway logout tombstone: %w", err)
	}
	if tombstoned {
		return fmt.Errorf("provider session was logged out before callback completion")
	}
	_, err = tx.Exec(ctx, `INSERT INTO oidc_gateway_sessions
		(id,client_id,token_hash,issuer,subject,provider_session_id,id_token_ciphertext,username,email,role,created_at,expires_at)
		VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, session.ID, store.clientID, tokenHash[:], store.issuer, session.Subject, session.ProviderSessionID, ciphertext, session.Username, session.Email, session.Role, now.UTC(), session.ExpiresAt.UTC())
	if err != nil {
		return fmt.Errorf("create gateway session: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit gateway session creation: %w", err)
	}
	return nil
}

func (store *Store) Find(ctx context.Context, browserToken []byte, now time.Time) (Session, error) {
	tokenHash := sha256.Sum256(browserToken)
	var session Session
	var ciphertext []byte
	err := store.pool.QueryRow(ctx, `SELECT id::text,subject,provider_session_id,id_token_ciphertext,username,email,role,expires_at
		FROM oidc_gateway_sessions WHERE client_id=$1 AND token_hash=$2 AND issuer=$3 AND revoked_at IS NULL AND expires_at>$4`, store.clientID, tokenHash[:], store.issuer, now.UTC()).Scan(&session.ID, &session.Subject, &session.ProviderSessionID, &ciphertext, &session.Username, &session.Email, &session.Role, &session.ExpiresAt)
	if err != nil {
		return Session{}, err
	}
	if len(ciphertext) < store.aead.NonceSize() {
		return Session{}, fmt.Errorf("gateway session ID token is corrupt")
	}
	plain, err := store.aead.Open(nil, ciphertext[:store.aead.NonceSize()], ciphertext[store.aead.NonceSize():], sessionAdditionalData(store.clientID, store.issuer, session))
	if err != nil {
		return Session{}, fmt.Errorf("decrypt gateway session ID token: %w", err)
	}
	session.IDToken = string(plain)
	return session, nil
}

func sessionAdditionalData(clientID, issuer string, session Session) []byte {
	value, _ := json.Marshal([5]string{clientID, issuer, session.ID, session.Subject, session.ProviderSessionID})
	return value
}

func (store *Store) RevokeToken(ctx context.Context, browserToken []byte, now time.Time) error {
	tokenHash := sha256.Sum256(browserToken)
	_, err := store.pool.Exec(ctx, `UPDATE oidc_gateway_sessions SET revoked_at=$3 WHERE client_id=$1 AND token_hash=$2 AND revoked_at IS NULL`, store.clientID, tokenHash[:], now.UTC())
	return err
}

func (store *Store) RevokeFrontchannelSession(ctx context.Context, sid string, now time.Time) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.lockProviderSession(ctx, tx, sid); err != nil {
		return err
	}
	if err := store.recordLogoutTombstone(ctx, tx, sid, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE oidc_gateway_sessions SET revoked_at=$4 WHERE client_id=$1 AND issuer=$2 AND provider_session_id=$3 AND revoked_at IS NULL`, store.clientID, store.issuer, sid, now.UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *Store) RevokeProviderSession(ctx context.Context, sid, jti string, expiresAt, now time.Time) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.lockProviderSession(ctx, tx, sid); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oidc_gateway_logout_tokens WHERE expires_at<=$1`, now.UTC()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO oidc_gateway_logout_tokens(client_id,token_id,expires_at) VALUES ($1,$2,$3)`, store.clientID, jti, expiresAt.UTC()); err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return fmt.Errorf("logout token was already used")
		}
		return fmt.Errorf("record logout token: %w", err)
	}
	if err := store.recordLogoutTombstone(ctx, tx, sid, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE oidc_gateway_sessions SET revoked_at=$4 WHERE client_id=$1 AND issuer=$2 AND provider_session_id=$3 AND revoked_at IS NULL`, store.clientID, store.issuer, sid, now.UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *Store) lockProviderSession(ctx context.Context, tx pgx.Tx, sid string) error {
	if sid == "" {
		return fmt.Errorf("provider session ID is required")
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(31) || $2 || chr(31) || $3, 0))`, store.clientID, store.issuer, sid); err != nil {
		return fmt.Errorf("lock gateway provider session: %w", err)
	}
	return nil
}

func (store *Store) recordLogoutTombstone(ctx context.Context, tx pgx.Tx, sid string, now time.Time) error {
	if err := deleteExpiredLogoutTombstones(ctx, tx, now, 1000); err != nil {
		return err
	}
	expiresAt := now.UTC().Add(store.tombstoneLifetime)
	_, err := tx.Exec(ctx, `INSERT INTO oidc_gateway_logout_tombstones(client_id,issuer,provider_session_id,created_at,expires_at)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (client_id,issuer,provider_session_id) DO UPDATE
		SET created_at=LEAST(oidc_gateway_logout_tombstones.created_at,EXCLUDED.created_at),
		    expires_at=GREATEST(oidc_gateway_logout_tombstones.expires_at,EXCLUDED.expires_at)`, store.clientID, store.issuer, sid, now.UTC(), expiresAt)
	if err != nil {
		return fmt.Errorf("record gateway logout tombstone: %w", err)
	}
	return nil
}

func deleteExpiredLogoutTombstones(ctx context.Context, tx pgx.Tx, now time.Time, limit int) error {
	_, err := tx.Exec(ctx, `WITH expired AS (
		SELECT client_id,issuer,provider_session_id FROM oidc_gateway_logout_tombstones
		WHERE expires_at<=$1 ORDER BY expires_at LIMIT $2
	)
	DELETE FROM oidc_gateway_logout_tombstones item USING expired
	WHERE item.client_id=expired.client_id AND item.issuer=expired.issuer AND item.provider_session_id=expired.provider_session_id`, now.UTC(), limit)
	if err != nil {
		return fmt.Errorf("delete expired gateway logout tombstones: %w", err)
	}
	return nil
}
