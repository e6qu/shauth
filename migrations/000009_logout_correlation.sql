-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Fail-closed, one-time correlation for browser-initiated global logout.

CREATE TABLE logout_correlation_grants (
    id UUID PRIMARY KEY,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    subject_id UUID NOT NULL,
    browser_session_id UUID NOT NULL,
    active_browser_session_ids UUID[] NOT NULL,
    browser_hydra_session_ids TEXT[] NOT NULL,
    active_hydra_session_ids TEXT[] NOT NULL CHECK (cardinality(active_hydra_session_ids) > 0),
    managed_client_id TEXT NOT NULL DEFAULT '',
    signed_out_url TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    cleanup_after TIMESTAMPTZ NOT NULL,
    cleanup_claimed_until TIMESTAMPTZ,
    cleanup_attempts INTEGER NOT NULL DEFAULT 0 CHECK (cleanup_attempts >= 0),
    last_error TEXT NOT NULL DEFAULT '',
    CHECK (expires_at > created_at),
    CHECK (cleanup_after >= created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    CHECK (completed_at IS NULL OR completed_at >= created_at)
);

CREATE INDEX logout_correlation_cleanup
    ON logout_correlation_grants(cleanup_after, cleanup_claimed_until)
    WHERE completed_at IS NULL;
