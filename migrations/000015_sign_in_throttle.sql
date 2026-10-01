-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Password sign-in is throttled from the audit record it already writes:
-- recent failures for one username, or from one address, are counted before
-- a password is checked. These partial indexes keep that count to the few
-- rows that matter however large the audit record grows.

CREATE INDEX audit_events_password_failure_username_idx
    ON audit_events ((details->>'username'), created_at DESC)
    WHERE event_type = 'sign_in.failed' AND details->>'method' = 'password';

CREATE INDEX audit_events_password_failure_address_idx
    ON audit_events (remote_address, created_at DESC)
    WHERE event_type = 'sign_in.failed' AND details->>'method' = 'password';
