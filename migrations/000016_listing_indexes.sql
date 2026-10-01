-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Indexes for the filters and orderings the administration interface and API
-- page through. Without them each listing scans and sorts its whole table,
-- which grows with every sign-in, invitation and logout.

-- Audit record filtered by who acted or by what happened, newest first.
CREATE INDEX audit_events_actor_created_idx ON audit_events (actor_user_id, created_at DESC);
CREATE INDEX audit_events_type_created_idx ON audit_events (event_type, created_at DESC);

-- Service-wide and per-account session listings, newest first.
CREATE INDEX sessions_created_idx ON sessions (created_at DESC, id);
CREATE INDEX sessions_user_created_idx ON sessions (user_id, created_at DESC, id);

-- Invitation and global-logout listings, newest first.
CREATE INDEX invitations_created_idx ON invitations (created_at DESC, id);
CREATE INDEX logout_correlation_grants_created_idx ON logout_correlation_grants (created_at DESC, id);
