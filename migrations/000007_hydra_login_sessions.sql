-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Correlate Shauth browser sessions with Ory Hydra login session IDs. Hydra's
-- sid is the standards-defined key used for Front- and Back-Channel Logout.

CREATE TABLE hydra_login_sessions (
    hydra_session_id TEXT PRIMARY KEY,
    browser_session_id UUID NOT NULL REFERENCES sessions(id),
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX hydra_login_sessions_browser_session_idx
    ON hydra_login_sessions(browser_session_id);
