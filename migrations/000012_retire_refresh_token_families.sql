-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Ory Hydra issues, rotates, and revokes refresh tokens and owns their
-- storage. Shauth's own refresh_tokens table has never held a row, so the
-- revocation statements that cascaded into it always affected nothing while
-- reading like a security control. Retire the table and the session column
-- that pointed at it rather than leave a durable claim the service cannot
-- honour. Revoking a Shauth session already ends the Ory Hydra login session
-- correlated with it, which is what actually invalidates refresh tokens.

DROP TABLE refresh_tokens;

ALTER TABLE sessions DROP COLUMN refresh_family_id;
