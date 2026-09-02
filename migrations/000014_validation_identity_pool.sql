-- SPDX-License-Identifier: AGPL-3.0-or-later
-- The application-validation queue runs up to appValidationConcurrencyLimit
-- checks at once, but every concurrent run still authenticated as the same
-- single validation identity. Ory Hydra's back-channel logout token carries
-- both sid and sub; a relying party that correlates logout by sub as well as
-- sid (a legitimate way to implement account-wide "log out everywhere")
-- then treats one run's routine sign-out check as an account-wide
-- revocation, silently signing out every other concurrently running run's
-- session for that same subject. Give each concurrent run its own
-- validation identity, checked out for the run's lifetime, so no two
-- concurrently running checks ever share a subject.

DROP INDEX users_single_validation_identity_idx;

ALTER TABLE users
    ADD COLUMN validation_run_id UUID REFERENCES app_validation_runs(id) ON DELETE SET NULL;

CREATE UNIQUE INDEX users_validation_run_checkout_idx
    ON users(validation_run_id)
    WHERE validation_run_id IS NOT NULL;
