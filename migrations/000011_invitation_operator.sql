-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Token-authorized operators can create invitations without a browser
-- session, so an invitation no longer requires a recorded inviting user.

ALTER TABLE invitations ALTER COLUMN invited_by DROP NOT NULL;
