-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Preserve the authentication source's evidence that a user's stored email is
-- verified. Existing local accounts were administrator-managed, and existing
-- GitHub accounts were admitted only after Shauth obtained a verified email.

ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE users
SET email_verified = TRUE
WHERE password_hash IS NOT NULL OR github_id IS NOT NULL;
