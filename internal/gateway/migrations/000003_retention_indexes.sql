-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Ended sessions and spent logout tokens are removed in bounded batches as
-- people sign in and log out; these indexes keep each batch from scanning the
-- whole table.
CREATE INDEX IF NOT EXISTS oidc_gateway_sessions_retention_idx
    ON oidc_gateway_sessions(client_id, expires_at);
CREATE INDEX IF NOT EXISTS oidc_gateway_sessions_revoked_idx
    ON oidc_gateway_sessions(client_id, revoked_at)
    WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS oidc_gateway_logout_tokens_expiry_idx
    ON oidc_gateway_logout_tokens(client_id, expires_at);
