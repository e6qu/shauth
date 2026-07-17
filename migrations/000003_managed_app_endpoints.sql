-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Managed applications are deployment-neutral: Shauth monitors their own URLs.

ALTER TABLE managed_apps ADD COLUMN health_url TEXT;
ALTER TABLE managed_apps ADD COLUMN monitoring_url TEXT;
UPDATE managed_apps SET health_url = CASE slug
  WHEN 'bleephub' THEN 'https://bleephub.dev.e6qu.dev/health'
  WHEN 'intraktible' THEN 'https://intraktible.dev.e6qu.dev/health'
  WHEN 'sharecrop' THEN 'https://sharecrop.dev.e6qu.dev/health'
END WHERE health_url IS NULL;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM managed_apps WHERE health_url IS NULL) THEN
    RAISE EXCEPTION 'managed_apps health_url must be explicitly configured';
  END IF;
END $$;
ALTER TABLE managed_apps ALTER COLUMN health_url SET NOT NULL;
ALTER TABLE managed_apps DROP COLUMN ecs_service_name;
ALTER TABLE managed_apps DROP COLUMN cloudwatch_log_group;
