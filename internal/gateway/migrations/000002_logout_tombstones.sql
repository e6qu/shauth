-- SPDX-License-Identifier: AGPL-3.0-or-later

CREATE TABLE IF NOT EXISTS oidc_gateway_logout_tombstones (
    client_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    provider_session_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, issuer, provider_session_id),
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS oidc_gateway_logout_tombstones_expiry_idx
    ON oidc_gateway_logout_tombstones(expires_at);
