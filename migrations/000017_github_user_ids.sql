-- SPDX-License-Identifier: AGPL-3.0-or-later
-- A GitHub login can be renamed and then claimed by a different person, so a
-- user access rule records GitHub's numeric account ID, which never changes
-- hands. Rules created before this migration carry no ID; the first sign-in
-- whose login matches binds them, and from then on only that account matches.
ALTER TABLE github_role_mappings
    ADD COLUMN github_user_id BIGINT
    CHECK (github_user_id IS NULL OR (kind = 'user' AND github_user_id > 0));

CREATE UNIQUE INDEX github_role_mappings_user_id_idx
    ON github_role_mappings (github_user_id)
    WHERE github_user_id IS NOT NULL;
