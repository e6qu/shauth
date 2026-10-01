# Operations

## Configuration

Shauth reads its environment once, at start-up. It refuses to start if a value
is missing, malformed or inconsistent. Credentials have no defaults and must
come from the runtime's secret injection.

| Variable | Required | Meaning |
|---|---|---|
| `SHAUTH_PUBLIC_URL` | yes | Public origin, and the OIDC issuer. Must be HTTPS unless insecure cookies are allowed on loopback. |
| `SHAUTH_LISTEN_ADDRESS` | no | Default `:8080`. The container health check follows it. |
| `SHAUTH_ALLOW_INSECURE_COOKIES` | no | `true` drops the cookies' `Secure` flag. Loopback URLs only. |
| `DATABASE_URL` | yes | Shauth's PostgreSQL database. |
| `HYDRA_ADMIN_URL` | yes | Hydra's admin API. Never publish it. |
| `HYDRA_PUBLIC_INTERNAL_URL` | yes | Hydra's public API, as Shauth reaches it internally. |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | yes | GitHub OAuth app. Its only callback is `<public URL>/oauth/github/callback`. |
| `GITHUB_ADMIN_TEAM`, `GITHUB_DEVELOPER_TEAM` | yes | `org/team`. Seeds the first access rules. |
| `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` | all or none | Enables Microsoft Entra ID for one tenant, given as a UUID. `common` and `organizations` are rejected. |
| `SHAUTH_SES_REGION`, `SHAUTH_INVITATION_EMAIL_FROM` | yes | Amazon SES region and verified sender, used for invitations. |
| `SHAUTH_BOOTSTRAP_ADMIN_EMAIL`, `SHAUTH_BOOTSTRAP_ADMIN_PASSWORD` | together | Break-glass administrator. The password is 14 to 72 bytes. Disabling this account sticks across restarts. |
| `SHAUTH_BOOTSTRAP_APPS_JSON` | no | [Clients and apps](integrating-apps.md#bootstrap-configuration) to reconcile at start-up. |
| `SHAUTH_MONITORING_SOURCES_JSON` | no | [Monitoring sources](#monitoring-sources). |
| `SHAUTH_VALIDATION_USERNAME`, `SHAUTH_VALIDATION_EMAIL`, `SHAUTH_VALIDATOR_TOKEN` | together | The browser-validation identity and the validator's credential. |
| `SHAUTH_TOKEN_HOOK_TOKEN` | yes | Bearer that Hydra presents to the token hook. |
| `SHAUTH_VALIDATION_STATUS_TOKEN` | no | Application catalog reads. |
| `SHAUTH_ADMIN_API_READ_TOKEN`, `SHAUTH_ADMIN_API_WRITE_TOKEN` | no | [Administration API](api.md#credentials). |
| `SHAUTH_SESSION_RESET_TOKEN` | no | Whole-account session reset. |

Every bearer token must be at least 32 characters and unique.

**Hydra settings.** Hydra must call the token hook with the same token:

```
OAUTH2_TOKEN_HOOK_URL=<shauth internal URL>/internal/hydra/token-hook
OAUTH2_TOKEN_HOOK_AUTH_TYPE=api_key
OAUTH2_TOKEN_HOOK_AUTH_CONFIG_IN=header
OAUTH2_TOKEN_HOOK_AUTH_CONFIG_NAME=Authorization
OAUTH2_TOKEN_HOOK_AUTH_CONFIG_VALUE=Bearer <SHAUTH_TOKEN_HOOK_TOKEN>
```

`compose.yaml` shows Hydra's full configuration. Hydra's system secret must
stay the same across restarts.

**Migrations.** `/shauth-migrate` reads `DATABASE_URL` and
`SHAUTH_MIGRATIONS_DIR` (default `/migrations`). It:

- takes an advisory lock, so concurrent runs are safe;
- waits at most 30 seconds for any table lock;
- gives up after ten minutes.

Run `/hydra migrate sql up --read-from-env --yes` with `DSN` set to Hydra's database.

## Monitoring sources

The Monitoring page reports Shauth's own health: PostgreSQL, Hydra, and active
sessions. It can also show infrastructure observations from HTTPS endpoints
that the deployment provides. Shauth only reads them. It cannot start, stop or
change anything.

```json
[{"name": "Platform", "url": "https://observer.example.com/v1/observation", "bearer_token": "<at least 32 characters>"}]
```

An application's `monitoring_url` and `monitoring_token` use the same
contract. Each source answers `Content-Type: application/json` with
`e6qu.monitoring/v1`:

```json
{
  "schema_version": "e6qu.monitoring/v1",
  "observed_at": "2026-07-20T12:00:00Z",
  "resources": [{
    "id": "shared-database",
    "name": "Shared PostgreSQL",
    "kind": "database",
    "health": "healthy",
    "metrics": [
      {"name": "cpu.usage", "label": "CPU usage", "value": 0.04, "unit": "vCPU", "status": "available"},
      {"name": "storage.allocation", "label": "Storage allocation", "unit": "GiB", "status": "not_applicable"}
    ]
  }],
  "cost_estimate": {
    "currency": "USD",
    "basis": "public-on-demand",
    "hours_per_month": 730,
    "hourly": 0.02,
    "daily": 0.48,
    "monthly": 14.60,
    "excludes": ["taxes", "reservations", "savings_plans", "credits", "free_tier"],
    "limitations": ["Data transfer is not included."],
    "line_items": [{"name": "Shared database compute", "hourly": 0.02, "monthly": 14.60}]
  }
}
```

**`health`:** `healthy`, `degraded`, `unhealthy` or `unknown`.

**Metric names:**

- `cpu.allocation`, `cpu.usage`
- `memory.allocation`, `memory.usage`
- `storage.allocation`, `storage.usage`
- `storage.read_iops`, `storage.write_iops`
- any other measurement that applies

**Metric `status`:** `available`, or `not_applicable` with no value.

**Cost estimate:** based on public on-demand prices, and must list the five
exclusions shown.

**Stale reports:** a report older than five minutes is marked stale.

## Images

Every push to `main` builds and publishes:

- `ghcr.io/e6qu/shauth:<sha12>` and `ghcr.io/e6qu/shauth-validator:<sha12>`,
  each a multi-architecture index;
- the single-architecture images as `<sha12>-amd64` and `<sha12>-arm64`.

The workflow verifies each pushed manifest. Nothing is ever published as
`latest` or under a branch name.

Deploy by tag or by digest. The Hydra binary, the Shauth binaries and both sets
of migrations come from the same image, so nothing is built at deploy time.

**Retention.** After each publish, the workflow keeps:

- the newest 20 releases;
- every release younger than 90 days;
- anything younger than 20 minutes, which may belong to a publish still in
  progress.

It deletes older releases and any untagged or non-release versions.

## Deployment

Shauth needs three things:

- a public HTTPS entry point that forwards every path to Shauth;
- private network access to Hydra and both PostgreSQL databases;
- outbound HTTPS to GitHub, Entra ID, Amazon SES, monitoring sources and
  registered applications.

Hydra's admin API and its own public listener must not be reachable from
outside. Every `/internal/` endpoint requires its credential, but should still
not be exposed beyond what clients need.

Run the validator as its own outbound-only service. It needs no inbound access
and only these variables:

| Variable | Meaning |
|---|---|
| `SHAUTH_URL` | Shauth's public URL. |
| `SHAUTH_VALIDATOR_TOKEN` | The same value as Shauth's. |
| `SHAUTH_VALIDATOR_SCRIPT` | The browser script. The image sets it. |

[`terraform/`](../terraform/README.md) is one complete deployment, on Amazon
ECS.

## Health

| Probe | Use |
|---|---|
| `GET /healthz` | Liveness. Unauthenticated, shallow. |
| `GET /api/v1/health/deep` | Readiness and diagnosis. Checks PostgreSQL, Hydra, the session policy, the client catalog, the mailer, the validation queue, and drift between recorded and live app registrations. |
| `/monitoring`, `/admin/logs`, `/admin/audit`, `/admin/sessions` | The same data, for administrators in a browser. |
