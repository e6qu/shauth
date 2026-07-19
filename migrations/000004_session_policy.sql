-- SPDX-License-Identifier: AGPL-3.0-or-later
-- The single identity-service session policy is durable and is enforced by
-- both Shauth and every OpenID Connect client registered with Ory Hydra.

CREATE TABLE session_policy (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    browser_absolute_lifetime_seconds BIGINT NOT NULL CHECK (browser_absolute_lifetime_seconds > 0),
    browser_idle_timeout_seconds BIGINT NOT NULL CHECK (browser_idle_timeout_seconds > 0),
    oidc_session_lifetime_seconds BIGINT NOT NULL CHECK (oidc_session_lifetime_seconds > 0),
    access_token_lifetime_seconds BIGINT NOT NULL CHECK (access_token_lifetime_seconds > 0),
    id_token_lifetime_seconds BIGINT NOT NULL CHECK (id_token_lifetime_seconds > 0),
    refresh_token_lifetime_seconds BIGINT NOT NULL CHECK (refresh_token_lifetime_seconds > 0),
    updated_at TIMESTAMPTZ NOT NULL
);

INSERT INTO session_policy (
    singleton,
    browser_absolute_lifetime_seconds,
    browser_idle_timeout_seconds,
    oidc_session_lifetime_seconds,
    access_token_lifetime_seconds,
    id_token_lifetime_seconds,
    refresh_token_lifetime_seconds,
    updated_at
) VALUES (TRUE, 2592000, 43200, 2592000, 900, 900, 2592000, now());

ALTER TABLE users ADD COLUMN entra_tenant_id UUID;
ALTER TABLE users ADD COLUMN entra_object_id UUID;
CREATE UNIQUE INDEX users_entra_identity_idx ON users(entra_tenant_id, entra_object_id) WHERE entra_tenant_id IS NOT NULL AND entra_object_id IS NOT NULL;
