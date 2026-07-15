-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Real application catalog records are paired with an OIDC client and an
-- Amazon Elastic Container Service service that Shauth can operate.

CREATE TABLE managed_apps (
    id UUID PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    launch_url TEXT NOT NULL,
    oidc_client_id TEXT NOT NULL UNIQUE,
    ecs_service_name TEXT NOT NULL UNIQUE,
    cloudwatch_log_group TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
