// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

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
	pool     *pgxpool.Pool
	clientID string
	issuer   string
	aead     cipher.AEAD
}

func NewStore(pool *pgxpool.Pool, clientID, issuer, secret string) (*Store, error) {
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create gateway session cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gateway session AEAD: %w", err)
	}
	return &Store{pool: pool, clientID: clientID, issuer: issuer, aead: aead}, nil
}

func (store *Store) Create(ctx context.Context, session Session, browserToken []byte, now time.Time) error {
	nonce := make([]byte, store.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate ID-token nonce: %w", err)
	}
	ciphertext := append(nonce, store.aead.Seal(nil, nonce, []byte(session.IDToken), []byte(store.clientID))...)
	tokenHash := sha256.Sum256(browserToken)
	_, err := store.pool.Exec(ctx, `INSERT INTO oidc_gateway_sessions
		(id,client_id,token_hash,issuer,subject,provider_session_id,id_token_ciphertext,username,email,role,created_at,expires_at)
		VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, session.ID, store.clientID, tokenHash[:], store.issuer, session.Subject, session.ProviderSessionID, ciphertext, session.Username, session.Email, session.Role, now.UTC(), session.ExpiresAt.UTC())
	if err != nil {
		return fmt.Errorf("create gateway session: %w", err)
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
	plain, err := store.aead.Open(nil, ciphertext[:store.aead.NonceSize()], ciphertext[store.aead.NonceSize():], []byte(store.clientID))
	if err != nil {
		return Session{}, fmt.Errorf("decrypt gateway session ID token: %w", err)
	}
	session.IDToken = string(plain)
	return session, nil
}

func (store *Store) RevokeToken(ctx context.Context, browserToken []byte, now time.Time) error {
	tokenHash := sha256.Sum256(browserToken)
	_, err := store.pool.Exec(ctx, `UPDATE oidc_gateway_sessions SET revoked_at=$3 WHERE client_id=$1 AND token_hash=$2 AND revoked_at IS NULL`, store.clientID, tokenHash[:], now.UTC())
	return err
}

func (store *Store) RevokeProviderSession(ctx context.Context, sid, jti string, expiresAt, now time.Time) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
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
	if _, err := tx.Exec(ctx, `UPDATE oidc_gateway_sessions SET revoked_at=$4 WHERE client_id=$1 AND issuer=$2 AND provider_session_id=$3 AND revoked_at IS NULL`, store.clientID, store.issuer, sid, now.UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
