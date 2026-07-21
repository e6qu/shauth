-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Durable, deployment-neutral browser acceptance checks for registered apps.

ALTER TABLE users ADD COLUMN is_validation BOOLEAN NOT NULL DEFAULT FALSE;

CREATE UNIQUE INDEX users_single_validation_identity_idx
    ON users(is_validation)
    WHERE is_validation = TRUE;

CREATE TABLE validation_browser_bootstraps (
    id UUID PRIMARY KEY,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    validation_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    next_path TEXT NOT NULL CHECK (next_path LIKE '/%'),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX validation_browser_bootstraps_expiry
    ON validation_browser_bootstraps(expires_at)
    WHERE consumed_at IS NULL;

ALTER TABLE managed_apps
    ADD COLUMN release_revision TEXT,
    ADD COLUMN validation_url TEXT,
    ADD COLUMN signed_out_url TEXT;

-- Existing catalog entries retained their real first-party origin. Their
-- first validation truthfully fails until the application publishes the two
-- explicit acceptance coordinates and its registration is updated.
UPDATE managed_apps
SET release_revision = 'legacy-unvalidated',
    validation_url = launch_url,
    signed_out_url = launch_url;

ALTER TABLE managed_apps
    ALTER COLUMN release_revision SET NOT NULL,
    ALTER COLUMN validation_url SET NOT NULL,
    ALTER COLUMN signed_out_url SET NOT NULL;

CREATE TABLE app_validation_runs (
    id UUID PRIMARY KEY,
    managed_app_id UUID NOT NULL REFERENCES managed_apps(id) ON DELETE CASCADE,
    app_slug TEXT NOT NULL,
    app_name TEXT NOT NULL,
    oidc_client_id TEXT NOT NULL,
    launch_url TEXT NOT NULL,
    validation_url TEXT NOT NULL,
    signed_out_url TEXT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('from_shauth', 'from_app')),
    release_revision TEXT NOT NULL,
    validation_contract_hash TEXT NOT NULL CHECK (validation_contract_hash ~ '^[0-9a-f]{64}$'),
    witness_managed_app_id UUID,
    witness_app_slug TEXT,
    witness_app_name TEXT,
    witness_oidc_client_id TEXT,
    witness_launch_url TEXT,
    witness_validation_url TEXT,
    witness_signed_out_url TEXT,
    witness_release_revision TEXT,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'passed', 'failed')),
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,
    duration_milliseconds BIGINT,
    failure TEXT NOT NULL DEFAULT '',
    CHECK (
        (witness_managed_app_id IS NULL AND witness_app_slug IS NULL AND witness_app_name IS NULL AND witness_oidc_client_id IS NULL AND witness_launch_url IS NULL AND witness_validation_url IS NULL AND witness_signed_out_url IS NULL AND witness_release_revision IS NULL)
        OR
        (witness_managed_app_id IS NOT NULL AND witness_app_slug IS NOT NULL AND witness_app_name IS NOT NULL AND witness_oidc_client_id IS NOT NULL AND witness_launch_url IS NOT NULL AND witness_validation_url IS NOT NULL AND witness_signed_out_url IS NOT NULL AND witness_release_revision IS NOT NULL)
    ),
    CHECK (witness_managed_app_id IS DISTINCT FROM managed_app_id),
    CHECK ((status = 'running') = (started_at IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK ((status IN ('passed', 'failed')) = (completed_at IS NOT NULL))
);

CREATE UNIQUE INDEX app_validation_one_pending_revision
    ON app_validation_runs(managed_app_id, direction, validation_contract_hash)
    WHERE status IN ('queued', 'running');

CREATE INDEX app_validation_recent
    ON app_validation_runs(managed_app_id, direction, requested_at DESC);

CREATE TABLE app_validation_control (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    active_run_id UUID REFERENCES app_validation_runs(id) ON DELETE SET NULL,
    next_start_at TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00'
);

INSERT INTO app_validation_control(singleton) VALUES (TRUE);
