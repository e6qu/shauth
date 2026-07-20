-- SPDX-License-Identifier: AGPL-3.0-or-later

CREATE TABLE IF NOT EXISTS oidc_gateway_sessions (
    id UUID PRIMARY KEY,
    client_id TEXT NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    provider_session_id TEXT NOT NULL,
    id_token_ciphertext BYTEA NOT NULL,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('developer', 'admin')),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS oidc_gateway_sessions_provider_idx
    ON oidc_gateway_sessions(client_id, issuer, provider_session_id)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS oidc_gateway_logout_tokens (
    client_id TEXT NOT NULL,
    token_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, token_id)
);
