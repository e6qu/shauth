# API

Every endpoint returns JSON. Each response names its contract in
`schema_version`, for example `shauth.users/v1`; the tables below leave out the
`shauth.` prefix. Reads also carry `observed_at`. Times are UTC.

## Credentials

Each credential is a bearer token sent as `Authorization: Bearer <token>`. Each
must be at least 32 characters and different from every other credential. An
unset credential disables its endpoints, which then answer `503`.

| Credential | Grants |
|---|---|
| `SHAUTH_ADMIN_API_READ_TOKEN` | `GET /api/v1/*`. |
| `SHAUTH_ADMIN_API_WRITE_TOKEN` | State changes under `/internal/`. |
| `SHAUTH_VALIDATION_STATUS_TOKEN` | The application catalog reads, which the admin read token also accepts. |
| `SHAUTH_SESSION_RESET_TOKEN` | `POST /internal/sessions/reset` only. |
| `SHAUTH_VALIDATOR_TOKEN` | The validator's job queue only. |
| `SHAUTH_TOKEN_HOOK_TOKEN` | Hydra's token hook only. |

Reads never accept the write token, and writes never accept the read token.
Writes live under `/internal/` because a bearer request carries no CSRF token.

## Errors

| Status | Meaning |
|---|---|
| `400` | Invalid input. `error` says why. |
| `401` | Missing or wrong credential. Includes `WWW-Authenticate: Bearer`. |
| `404` | No such record. |
| `409` | Conflicts with existing state, for example a duplicate, or a client still in use. |
| `502` | A dependency failed. The detail goes only to the service log. |
| `503` | The endpoint's credential is not configured. |

Every error body is `{"error": "…"}`.

## Directory

| Endpoint | Schema | Notes |
|---|---|---|
| `GET /api/v1/users?q=&limit=&offset=` | `users/v1` | `q` matches username, email or GitHub login. Paged: `limit` defaults to 100, maximum 500. |
| `GET /api/v1/users/{id}` | `user/v1` | |
| `GET /api/v1/users/{id}/sessions` | `user-sessions/v1` | |
| `GET /api/v1/invitations?limit=&offset=` | `invitations/v1` | State is `pending`, `accepted`, `revoked` or `expired`. The token is never returned. |
| `GET /api/v1/sessions?state=active\|all&user_id=&since=` | `sessions/v1` | Every account's browser sessions. |
| `GET /api/v1/sessions/{id}` | `session/v1` | Includes the correlated Hydra login sessions. |
| `GET /api/v1/session-policy` | `session-policy/v1` | |
| `GET /api/v1/oidc-clients` | `oidc-clients/v1` | Never includes secrets. |
| `GET /api/v1/github-mappings` | `github-role-mappings/v1` | User rules include `github_user_id`. |
| `GET /api/v1/connectors` | `connectors/v1` | GitHub and Entra ID settings. |

A paged response has a `page` object with `limit`, `offset`, `returned`,
`total` and `has_more`. Users report `identity_source` (`local`, `github` or
`entra`), and `disabled_at` is always present (`null` when enabled).

## Changes

| Endpoint | Body | Result |
|---|---|---|
| `POST /internal/users` | `username`, `email`, `password`, `role` | `201` `user/v1` |
| `POST /internal/users/{id}/disable` | | `user/v1`. Ends every session and blocks sign-in. Idempotent. Refuses the validation identity. |
| `POST /internal/users/{id}/enable` | | `user/v1`. Ended sessions stay ended. |
| `POST /internal/users/{id}/sessions/revoke` | | Ends every session of the account. |
| `POST /internal/sessions/{id}/revoke` | | `session-revoke/v1` |
| `POST /internal/sessions/reset` | `user_id` or `email`, as JSON or form | Ends every session of the account. Uses its own credential. |
| `POST /internal/invitations` | `email`, `role` | `201` `invitation/v1`. The link goes only by email. If the email cannot be sent, the invitation is revoked and the call answers `502`. |
| `POST /internal/invitations/{id}/revoke` | | `invitation-revoke/v1`. Answers `404` if already accepted or revoked. |
| `PUT /internal/session-policy` | the `session-policy/v1` fields | Applied to every client. All changes roll back together on failure. |
| `POST /internal/oidc-clients` | client fields | `201` `oidc-client/v1` |
| `DELETE /internal/oidc-clients/{id}` | | Answers `409` while an app uses the client. |
| `POST /internal/github-mappings` | `kind`, `target`, `role` | `github-role-mapping/v1`. A user login is resolved to its numeric ID through GitHub's API. An unknown login answers `400`; if GitHub is unreachable, `502`. |
| `DELETE /internal/github-mappings/{id}` | | Revokes the sessions of accounts the rule admitted. |
| `POST /internal/apps` | [app fields](integrating-apps.md#3-register-the-app-in-the-catalog) | `201` `app/v1` |
| `DELETE /internal/apps/{slug}` | | |

## Applications

These accept the validation status token or the admin read token, except the
enqueue call.

| Endpoint | Schema | Notes |
|---|---|---|
| `GET /api/v1/apps` | `apps/v1` | Every app's coordinates, health, and latest result per direction. |
| `GET /api/v1/apps/{slug}` | `app/v1` | One app. |
| `GET /api/v1/apps/validations` | `app-validations/v1` | Latest run per app and direction, with `duration_ms` and `witness`. |
| `GET /api/v1/apps/validations/history?slug=&limit=` | `app-validation-history/v1` | Newest first. `limit` defaults to 50, maximum 500. |
| `POST /internal/apps/validations/enqueue` | `app-validation-enqueue/v1` | Needs the write token. `{"slug": "…"}` queues one app; no `slug` queues every app. Answers `202`. |

## Observability

| Endpoint | Schema | Notes |
|---|---|---|
| `GET /api/v1/health/deep` | `deep-health/v1` | Checks each dependency and start-up invariant, with its latency. `503` when Shauth cannot work. |
| `GET /api/v1/monitoring` | `monitoring/v1` | Self-checks, active sessions, the build, and each [monitoring source](operations.md#monitoring-sources). Reports `postgresql_healthy: false` instead of failing. |
| `GET /api/v1/metrics` | `metrics/v1` | Counts from PostgreSQL: accounts, sessions, invitations, apps, the validation queue, and the logout backlog. |
| `GET /api/v1/metrics/requests` | `request-metrics/v1` | This instance since it started: per route pattern, counts, status classes and latency percentiles. |
| `GET /api/v1/logs?level=&contains=&since=&limit=` | `logs/v1` | This instance's recent log lines, newest first. Held in memory only. |
| `GET /api/v1/audit-events?subject=&actor=&event_type=&since=&until=` | `audit-events/v1` | The durable security record. |
| `GET /api/v1/users/{id}/audit-events` | `audit-events/v1` | |
| `GET /api/v1/logout-grants?state=outstanding\|all` | `logout-grants/v1` | Global logouts with their retry count and last error. |

**Audit events** record who acted, on whom, the address and session, and a
`details` object. An action no account performed sets `details.actor_kind`:

- `token` for a bearer credential;
- `visitor` for someone without a session;
- `service` for Shauth itself.

A refused sign-in records the reason. The person is only told that the details
did not work.

**Client address:** the rightmost `X-Forwarded-For` entry, which is the one
the gateway in front of Shauth appended. A direct request from a public
address is recorded as that address.

## Self-service

A signed-in person's own browser session authorizes these. No bearer token is
needed.

| Endpoint | Notes |
|---|---|
| `GET /api/v1/me/sessions` | The caller's sessions. |
| `POST /internal/me/sessions/{id}/revoke` | Answers `404` for someone else's session. |

The `/account` page shows the same information.

## Internal callers

| Endpoint | Caller |
|---|---|
| `POST /internal/hydra/token-hook` | Ory Hydra, before issuing any token. |
| `POST /internal/validator/jobs/claim` | The validator. |
| `POST /internal/validator/jobs/{id}/complete` | The validator. |
| `POST /internal/validator/browser-bootstraps` | The validator. |
| `GET /healthz` | The container scheduler. Unauthenticated and shallow. |
