// SPDX-License-Identifier: AGPL-3.0-or-later

package session

const revokeSessionSQL = `
UPDATE sessions
SET revoked_at = $2
WHERE id = $1 AND revoked_at IS NULL AND expires_at > $2
RETURNING refresh_family_id`

const revokeFamilySQL = `
UPDATE refresh_tokens
SET revoked_at = $2
WHERE family_id = $1 AND revoked_at IS NULL`

const revokeUserSessionsSQL = `
WITH revoked AS (
    UPDATE sessions
    SET revoked_at = $2
    WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
    RETURNING refresh_family_id
)
UPDATE refresh_tokens
SET revoked_at = $2
WHERE family_id IN (SELECT refresh_family_id FROM revoked) AND revoked_at IS NULL`
