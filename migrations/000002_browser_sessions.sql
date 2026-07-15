-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Browser session credentials are stored only as SHA-256 hashes.

ALTER TABLE sessions ADD COLUMN browser_token_hash BYTEA UNIQUE;
ALTER TABLE sessions ADD COLUMN last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE sessions ALTER COLUMN remote_address DROP NOT NULL;

CREATE INDEX sessions_browser_token_idx ON sessions(browser_token_hash) WHERE revoked_at IS NULL;
