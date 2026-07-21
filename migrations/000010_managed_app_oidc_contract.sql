-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Persist the exact OpenID Connect registration contract validated for each app.

ALTER TABLE managed_apps
    ADD COLUMN oidc_contract_hash TEXT NOT NULL DEFAULT repeat('0', 64)
    CHECK (oidc_contract_hash ~ '^[0-9a-f]{64}$');
