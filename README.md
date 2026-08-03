# Shauth

Shauth is e6qu's Go identity administration and observability service. It uses
Ory Hydra as its OAuth 2.0/OpenID Connect issuer and keeps identity, browser
session, invitation, and audit state in PostgreSQL. GitHub OAuth is the current
federated source. A tenant-bound Microsoft Entra ID application can be enabled
as a second federated source. Connected applications trust only Shauth's OIDC
issuer and never integrate with either upstream source directly.

The Shauth application provides the server-rendered HTMX admin and monitoring
user interface. It manages local accounts, GitHub role mappings, confidential
OpenID Connect clients, invitations, sessions, and connector health. Client
secrets are write-only: an administrator supplies the secret when registering
the client and stores the same value in the relying service's AWS Secrets
Manager secret. Shauth never renders or returns it afterward.
The pinned HTMX 2.0.8 browser asset is embedded in the Shauth binary and served
from the Shauth origin with an immutable URL and Subresource Integrity digest.
Shauth pages do not depend on a browser-side CDN or other external asset host.

## Brokered application login

GitHub permits one callback URL per OAuth application. Shauth is therefore the
sole GitHub OAuth callback at
`https://auth.dev.e6qu.dev/oauth/github/callback`; it completes GitHub login
and issues OpenID Connect tokens to registered e6qu applications. Each relying
application has its own Shauth OIDC client and redirect URI, rather than being
added to the GitHub OAuth application. When Microsoft Entra ID is enabled,
Shauth discovers the configured tenant-specific issuer and verifies the ID
token signature, issuer, audience, tenant, and nonce before linking the stable
tenant and object identifiers to a Shauth user.
Shauth persists email-verification evidence with each identity and publishes
the standard `email_verified` claim in ID tokens, access-token introspection,
and UserInfo. The boolean always comes from the current PostgreSQL identity;
Shauth never promotes an unverified address while issuing tokens. Managed local
accounts are administrator-attested, and GitHub accounts use GitHub's primary
verified email endpoint. Microsoft Entra ID accounts are marked verified only
when the tenant ID token verifies the actual `email` claim; falling back to
`preferred_username` does not imply email verification.

## Access and session lifecycle

Shauth keeps browser sessions in PostgreSQL and Ory Hydra keeps OpenID Connect
login and consent sessions. A normal sign-out is an explicit, same-origin
browser action: Shauth starts Ory Hydra's logout flow, verifies the trusted
challenge subject against the signed-in local user, revokes the local browser
session, and accepts the Ory Hydra logout request without a second confirmation
screen. Relying applications clear their own browser cookie and navigate to
Shauth's published `/oauth2/sessions/logout` endpoint with the ID token hint and
an exact registered post-logout redirect URI; they do not POST cross-origin to
Shauth. Ory Hydra sends signed back-channel logout tokens and, when configured,
front-channel logout requests to every client session correlated by `sid`.
Relying applications validate those notifications and idempotently revoke the
correlated local sessions.
The Shauth container includes Ory Hydra v26.2.0 with the repository's audited
provider patch that adds the Back-Channel Logout 1.0 Errata 1 `exp` claim with
a two-minute lifetime. The same immutable image runs Shauth, Hydra, and their
migration entry points, so production never builds or patches the provider at
startup.
Each push to `main` publishes `ghcr.io/e6qu/shauth:<sha12>` as a Linux amd64
and arm64 image index. The direct single-platform images remain addressable as
`<sha12>-amd64` and `<sha12>-arm64`; no `latest` or branch alias is published.
The workflow verifies the registry manifests and retains exactly the package
versions belonging to the newest 20 immutable releases, removing older,
untagged, and non-release versions.
Shauth exposes Ory Hydra's complete public OpenID Connect surface at its public
issuer, including discovery, authorization, token, UserInfo, revocation,
introspection, and front-channel logout endpoints. Relying applications never
connect to Hydra's private task coordinate directly.

Administrators can invalidate one Shauth browser session or invalidate every
session for a user. Shauth revokes each correlated Ory Hydra login session by
`sid` so relying applications receive logout notifications, then deletes any
remaining subject login state and consent grants to revoke associated access
and refresh tokens.
Administrators also configure the durable browser absolute lifetime, browser
idle timeout, OIDC single sign-on lifetime, and access, ID, and refresh token
lifetimes. Shauth applies the token lifetimes to every paginated Ory Hydra
client and enforces the browser limits from PostgreSQL.
GitHub mappings are evaluated on every GitHub sign-in; a matching administrator
mapping overrides a matching developer mapping. Administration and monitoring
navigation are shown only to administrators, and the corresponding handlers
enforce that role server-side.

The signed-in Apps page is a catalog of real deployed services. Administrators
register an app only after its Shauth OIDC client, launch URL, published health
endpoint, immutable release revision, authenticated validation URL, and local
signed-out URL exist. The normal launch UI exposes the visible authenticated
identity as `data-shauth-user="<username>"` and its real logout action as
`data-shauth-sign-out`; the identity control may reveal the logout action when
clicked. The separate validation URL exposes exact `validation-username`, `validation-email`,
`validation-role`, and `validation-release` fields. The
signed-out URL persists across reloads and exposes an accessible `Sign in with
Shauth` control. Both coordinates use the app's own origin. Release revisions
are immutable 12–64 character lowercase hexadecimal commits or `sha256`
digests; moving labels such as `main` and `latest` are rejected.

Shauth automatically queues two real Chromium checks when an app is registered
or any of its release, endpoint, or OpenID Connect registration coordinates change. The first enters through Shauth's Apps catalog;
the second enters through the app's public launch URL. Both checks authenticate,
establish a second independent relying-party session through silent SSO, verify
the app-owned signed-in page, perform application-initiated global OIDC logout,
verify the exact app-local signed-out destination and its reload behavior, sign
out through the exact app-origin logout bridge, reject hostile bridge queries
and completion replay, sign in again, establish another witness session, then perform provider-initiated
logout from Shauth and verify that both relying parties and the Shauth browser
session were revoked. The validator then signs in again after provider logout
and repeats application-initiated global revocation, proving that logout did
not leave a permanently broken or partially authenticated account. A deployment
without a second registered app on a distinct origin and OIDC client reports a
red result because global SSO logout cannot truthfully be proven in isolation.
The Apps and administration pages report `🟢 Passed`, `🔴 Failed`, or
`🟡 Ongoing` for each direction and let any signed-in user rerun both checks.
PostgreSQL serializes the global queue and enforces at least 30 seconds between
check starts.

The validation account is a dedicated, non-administrative Shauth identity with
no password or federated login. A validator bearer token authorizes creation of
small, bounded sets of short-lived, single-use browser bootstrap links. Shauth
stores only SHA-256 token hashes; each raw token exists only in the worker and a
URL fragment until a same-origin form atomically consumes it. The standalone
validator never gives its reusable bearer token or a bootstrap token to a
relying application, and redacts encoded credentials and OAuth artifacts from
durable failures.

## Infrastructure monitoring contract

Shauth self-monitoring checks its PostgreSQL connection, Ory Hydra readiness,
and active browser sessions. Deployment operators may additionally configure
authenticated observation endpoints with `SHAUTH_MONITORING_SOURCES_JSON`.
Shauth consumes those HTTPS coordinates and does not know which scheduler,
cloud, or storage implementation produced them. It never starts, stops, or
otherwise controls infrastructure.

Each source has `name`, `url`, and a bearer token of at least 32 characters.
The endpoint returns `Content-Type: application/json` and the strict
`e6qu.monitoring/v1` schema:

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
      {"name": "cpu.allocation", "label": "CPU allocation", "value": 0.25, "unit": "vCPU", "status": "available"},
      {"name": "cpu.usage", "label": "CPU usage", "value": 0.04, "unit": "vCPU", "status": "available"},
      {"name": "memory.allocation", "label": "Memory allocation", "value": 512, "unit": "MiB", "status": "available"},
      {"name": "memory.usage", "label": "Memory usage", "value": 192, "unit": "MiB", "status": "available"},
      {"name": "storage.allocation", "label": "Storage allocation", "unit": "GiB", "status": "not_applicable"},
      {"name": "storage.usage", "label": "Storage usage", "value": 4096, "unit": "MiB", "status": "available"},
      {"name": "storage.read_iops", "label": "Read operations", "value": 3.2, "unit": "operations/second", "status": "available"},
      {"name": "storage.write_iops", "label": "Write operations", "value": 1.4, "unit": "operations/second", "status": "available"}
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
    "limitations": ["Request-priced services and data transfer are excluded when the source has no current usage metric."],
    "line_items": [{"name": "Shared database compute", "hourly": 0.02, "monthly": 14.60}]
  }
}
```

Resource health is `healthy`, `degraded`, `unhealthy`, or `unknown`. Metric
names and units are deployment-neutral; sources publish CPU and memory
allocation and use, disk allocation and use where capacity is provisioned,
elastic-storage use and I/O, plus other operational measurements that apply to
the resource. A report older than five minutes is visibly marked stale.
Pricing is an estimate based on public on-demand rates, not a bill. The schema
requires it to exclude taxes, reservations, Savings Plans, credits, and the
free tier.

Terraform can supply `bootstrap_apps` as a sensitive input to register clients
and catalog records idempotently during Shauth startup. The input is stored only
in the Shauth runtime secret and contains each confidential client secret,
sign-in and post-logout redirect URIs, at least one front-channel or
back-channel logout URI, launch URL, health URL, and optional monitoring URL.
Every coordinate for one connected application uses the same scheme, host, and
port, and the client registers the exact app-origin
`/auth/shauth/logout/complete` bridge as its only `post_logout_redirect_uri`. The
bridge returns to Shauth's `/oauth/logout/complete`; Shauth then uses its
one-time durable correlation to reach the trusted app-local `signed_out_url`.
Shauth verifies these invariants against
its PostgreSQL catalog record and Ory Hydra's reconciled client before startup succeeds; bootstrap
configuration cannot take over an administrator-owned slug or client ID. Each
entry also supplies `release_revision`, `validation_url`, and `signed_out_url`;
changing any material registration coordinate queues both browser checks
without coupling Shauth to the app's deployment platform.

Each validation page exposes the exact authenticated username, email,
normalized role, and immutable release revision through documented
`data-testid` fields, while the product launch page remains authoritative for
the user-visible identity and logout controls. The passwordless validation identity is entered only by
short-lived, single-use Shauth browser bootstraps. A distinct bearer
credential, supplied through `SHAUTH_VALIDATION_STATUS_TOKEN`, protects the
closed machine-readable application API used by operators and post-deployment
acceptance gates:

- `GET /api/v1/apps` returns the `shauth.apps/v1` catalog: every registered
  app's coordinates, live health observation, and latest validation result per
  direction.
- `GET /api/v1/apps/validations` returns the `shauth.app-validations/v1`
  status contract with the latest run per app and direction. Terminal runs
  carry `duration_ms`, and runs proven against a second relying party carry
  the `witness` app slug.
- `GET /api/v1/apps/validations/history?slug=<slug>&limit=<n>` returns the
  `shauth.app-validation-history/v1` contract with durable runs ordered newest
  first. `slug` is optional; `limit` defaults to 50 and is capped at 500.
- `POST /internal/apps/validations/enqueue` queues both browser checks for one
  app (`{"slug":"<slug>"}`) or for every app (an omitted `slug`) and answers
  `202` with the `shauth.app-validation-enqueue/v1` receipt. A present but
  empty slug is rejected rather than silently queuing every app. It lives
  under `/internal/` because bearer-token requests carry no browser CSRF
  token, and it requires `SHAUTH_ADMIN_API_WRITE_TOKEN`: queuing starts real
  browser sessions and global logouts against every registered relying party,
  so the read-only status credential above cannot trigger it.

## Administration API

Every remaining surface of the signed-in administration interface is also a
versioned machine-readable contract, so operators and agents can inspect and
drive Shauth without a browser session. Two dedicated bearer credentials
authorize it: `SHAUTH_ADMIN_API_READ_TOKEN` protects the read-only contracts
under `/api/v1/`, and the distinct `SHAUTH_ADMIN_API_WRITE_TOKEN` protects
state changes under `/internal/` (bearer-token requests carry no browser CSRF
token). Each configured token must contain at least 32 characters and must
differ from every other closed-API credential; reads never accept the write
token and writes never accept the read token, so a read-only consumer never
holds a state-changing secret. An unset token keeps its half of the API
disabled, answering `503`.

Reads return an `observed_at` timestamp and a versioned envelope:

List endpoints answer a bounded window. `GET /api/v1/users` and
`GET /api/v1/invitations` accept `limit` (default 100, maximum 500) and
`offset`, and report a `page` object carrying `limit`, `offset`, `returned`,
`total`, and `has_more`, so a consumer can page through a directory instead of
receiving an unbounded array.

- `GET /api/v1/users?q=<query>&limit=<n>&offset=<n>` — `shauth.users/v1`: user catalog with
  machine-readable `identity_source` (`local`, `github`, or `entra`),
  verification, role, and disabled state; `q` filters by username, email, or
  GitHub login exactly like the users page.
- `GET /api/v1/invitations?limit=<n>&offset=<n>` — `shauth.invitations/v1`: invitations with
  its state (`pending`, `accepted`, `revoked`, or `expired`). The single-use
  token is stored only as a hash and is never returned.
- `GET /api/v1/users/{id}/sessions` — `shauth.user-sessions/v1`: the account
  plus every browser session's created/last-seen/expiry times, user agent,
  remote address, revocation state, and computed `active` flag.
- `GET /api/v1/session-policy` — `shauth.session-policy/v1`: durable session
  lifetimes in the same units as the administration form, with `updated_at`
  reporting when the policy last changed. `/admin/audit?event_type=session_policy.updated`
  reports who changed it.
- `GET /api/v1/oidc-clients` — `shauth.oidc-clients/v1`: the Ory Hydra client
  catalog as Shauth manages it (never any client secret).
- `GET /api/v1/github-mappings` — `shauth.github-role-mappings/v1`: GitHub
  kind/target/role rules.
- `GET /api/v1/connectors` — `shauth.connectors/v1`: GitHub and Microsoft
  Entra ID enablement, team names, and tenant.
- `GET /api/v1/monitoring` — `shauth.monitoring/v1`: active Shauth sessions,
  PostgreSQL and Ory Hydra health, and each configured `e6qu.monitoring/v1`
  infrastructure observation (snapshot, staleness, or fetch error) — the same
  data the monitoring page renders.

Writes mirror the corresponding administration forms, validate identically,
and answer with a versioned receipt:

- `POST /internal/users` — create a local account
  (`{"username","email","password","role"}`), answering `201` with
  `shauth.user/v1`. A username or email already in use answers `409`.
- `POST /internal/users/{id}/disable` and `POST /internal/users/{id}/enable` —
  contain or restore an account, answering `shauth.user/v1`. Disabling ends
  every browser session, revokes the correlated provider sessions, and blocks
  sign-in; unlike session revocation alone, the account cannot simply
  authenticate again. It is idempotent, so a failed provider revocation can be
  retried, and it refuses to disable the browser-validation identity (`409`).
  Enabling restores sign-in without resurrecting the revoked sessions.
- `POST /internal/invitations` — invite by email (`{"email","role"}`),
  answering `201` with `shauth.invitation/v1`. The invitation link is
  delivered only through the invitation email; if the email cannot be sent
  the invitation is revoked and the request fails with `502`. Token-created
  invitations record no inviting user.
- `POST /internal/invitations/{id}/revoke` — withdraw an unaccepted
  invitation (`shauth.invitation-revoke/v1`), so a link sent to the wrong
  address can no longer create an account. An already accepted or revoked
  invitation answers `404`.
- `POST /internal/sessions/{id}/revoke` — end one browser session and its
  correlated Ory Hydra login sessions (`shauth.session-revoke/v1`);
  `POST /internal/sessions/reset` remains the whole-user reset behind its own
  `SHAUTH_SESSION_RESET_TOKEN`.
- `PUT /internal/session-policy` — replace the session policy using the same
  fields as `shauth.session-policy/v1`; lifetimes are applied to every OAuth
  client and rolled back together on failure.
- `POST /internal/oidc-clients` and `DELETE /internal/oidc-clients/{id}` —
  register (`201`, `shauth.oidc-client/v1`) or remove an OpenID Connect
  client. Deleting a client still referenced by a managed app answers `409`.
- `POST /internal/github-mappings` and
  `DELETE /internal/github-mappings/{id}` — manage GitHub role mappings
  (`shauth.github-role-mapping/v1`).
- `POST /internal/apps` and `DELETE /internal/apps/{slug}` — register
  (`201`, `shauth.app/v1`) or remove a managed app. Registration enforces the
  same invariants as the form: the OpenID Connect client must already exist,
  every coordinate must share one application origin, and the client must
  register exactly its logout-bridge post-logout redirect URI.

Every administration API response is JSON, including failures, which carry an
`error` message. A rejected request answers `400` with the reason, a
uniqueness conflict answers `409`, a missing record answers `404`, and a
failed dependency answers `502` while its detail goes only to the service log,
so internal database and provider text never reaches a caller. Unauthorized
responses carry a `WWW-Authenticate: Bearer` challenge, and the `Bearer`
scheme is matched case-insensitively as RFC 7235 requires.
`GET /api/v1/monitoring` reports `postgresql_healthy: false` and a null
`active_sessions` when PostgreSQL is unreachable rather than failing, because
that contract exists to report an outage. `GET /api/v1/users/{id}` reads one
account, so polling a single account does not download every account. Record
timestamps are published in UTC, and `disabled_at` is always present (null
when the account is enabled) so a consumer never has to infer state from a
missing key.

## Observability

An incident review needs three things the service did not previously
publish: what happened, how much of it, and which dependency is at fault.

- `GET /api/v1/audit-events?subject=&actor=&event_type=&since=&until=` and
  `GET /api/v1/users/{id}/audit-events` — `shauth.audit-events/v1`: the
  durable record of every security-relevant action. Sign-in outcomes,
  including why a sign-in was refused; session and account changes; every
  invitation, client, application, access rule and policy change; accepting
  an invitation, which is the one way an account appears without an
  administrator creating it; and whether each global logout completed or is
  being retried, with the error that stopped it. Each event carries who
  acted, on whom, from which address and session, and a detail object. The person signing in is always told only that the pair did not
  work, while the record keeps the reason, so a disabled account is
  distinguishable from a mistyped name without telling an attacker which.
  A token-authorized write records no person, because bearer credentials are
  shared and opaque; it records the address it came from.
- `GET /api/v1/metrics` — `shauth.metrics/v1`: accounts by role, identity
  source and disabled state; sessions by state; invitations by state;
  applications; validation runs by status with the queue depth and the age of
  the oldest queued run; and the outstanding global-logout backlog. Every
  number is read from PostgreSQL, so it describes what the service holds
  rather than what one process has counted since it started.
- `GET /api/v1/health/deep` — `shauth.deep-health/v1`: each dependency and
  startup invariant checked on demand with its latency, answering `503` only
  when the service cannot do its job. It reports PostgreSQL, both provider
  endpoints, the durable session policy, the client catalog, the invitation
  mailer, whether the validation queue is still draining, and whether any
  application registration has drifted from what was recorded — drift means
  single sign-on is already broken for that relying party. `/healthz` remains
  the shallow, unauthenticated probe the container scheduler uses.
- `GET /api/v1/metrics/requests` — `shauth.request-metrics/v1`: what this
  instance has served since it started, by route: request counts, outcomes by
  status class, mean, ninety-fifth-percentile and slowest response times, the
  bucketed distribution those percentiles were taken from, the status and time
  of the most recent request, and the number in flight. The route is always
  the pattern the route table matched, never the requested path, so an
  identifier in a URL can never create a series. A request refused before
  routing, by the CSRF check for instance, is attributed to the route it
  targeted rather than to a nameless series. These counters
  are process-local and reset on restart, which is what makes them the right
  answer to "what is this instance doing now" and the wrong answer to "how
  many accounts exist" — that is `/api/v1/metrics`. The `Requests served`
  section of `/monitoring` renders the same report.

- `GET /api/v1/logs?level=&contains=&since=&limit=` — `shauth.logs/v1`: what
  this instance has reported, newest first, filtered by severity, text, or
  time. The buffer tees the same lines the container stream receives, so it
  publishes nothing that was not already written to standard error; the rule
  that secrets are never logged is what keeps it safe to read, and the stack
  gate checks the bootstrap credential does not appear in it. Lines are held
  in memory and lost on restart. `/admin/logs` renders the same buffer.
  Severity comes from the writer, never from guessing at the wording of a
  message: a line written straight to the standard logger by a dependency is
  reported as unlabelled rather than relabelled.
- `GET /api/v1/sessions?state=active|all&user_id=&since=` —
  `shauth.sessions/v1`: browser sessions across every account with the
  account they belong to. Sessions could previously be listed only one
  account at a time, which meant knowing whose session to look for before
  looking. `POST /internal/users/{id}/sessions/revoke` ends every session for
  an account under the write credential, the operation the browser interface
  already had. `/admin/sessions` is the same listing with the same control.

Debugging a specific failure:

- `GET /api/v1/sessions/{id}` — `shauth.session/v1`: one session with its
  account and the provider sessions correlated to it. A sign-in that cannot
  be correlated is the usual cause of a stuck login, and that correlation had
  no read path before.
- `GET /api/v1/logout-grants?state=outstanding|all` —
  `shauth.logout-grants/v1`: global-logout attempts, their retry count and
  their last error. A logout that never completes leaves relying-party
  sessions alive, which was previously visible only in process logs.
- `GET /api/v1/apps/{slug}` — `shauth.app/v1`: one application's coordinates,
  live health and latest check per direction, so polling one relying party
  does not mean probing every other application's health endpoint.

Self-service:

- `GET /api/v1/me/sessions` and `POST /internal/me/sessions/{id}/revoke`,
  authorized by the caller's own browser session, with the matching `/account`
  page. Previously only an administrator could see or end sessions, so nobody
  could review their own devices. Ending a session that is not the caller's
  answers `404`.

The application catalog reads accept either the application status credential
or the administration read credential, so an operator holding the
administration read token is not unable to list applications.

Recorded addresses come from the nearest proxy hop rather than the peer
address. Shauth is reached only through a gateway, so the peer is that
gateway; the rightmost `X-Forwarded-For` entry is the one the gateway
observed and appended and cannot be forged by the caller. A request arriving
directly from a public address is recorded as that address and any forwarded
header is ignored.

## One implementation per operation

The browser interface and the machine API are two transports over one
implementation. Every administrative state change — creating a user,
disabling an account, inviting, revoking a session or an invitation, updating
the session policy, registering or deleting an OAuth client, a GitHub access
rule, or an application, and queuing validations — lives once in
`internal/app/operations.go`. A handler parses its own input, calls one
operation, and renders the result; neither transport reimplements an
operation, so the two cannot drift apart.

Failures are classified once and mapped by each transport: the API answers a
status and a JSON `error`, and the browser returns the operator to the form
with the same message. The acting administrator is an explicit input, so a
browser-created invitation records its inviter and a browser-requested
validation records its requester, exactly as the API does when it supplies
none. Security rules that were previously enforced only in the browser — such
as refusing to disable the account the operator is signed in with — now hold
for every caller.

Browser forms carry their CSRF token from the server rather than having it
injected by script, so signing in, accepting an invitation, signing out, and
every administrative action work without JavaScript. Destructive controls ask
for confirmation, failures render a navigable page instead of unstyled text,
and each page carries its own title.

Every page ends with the build serving it: the short Git revision the image
was built from and when this deployment started, in UTC. The revision is
stamped into the binaries at build time through the `SHAUTH_REVISION` build
argument, so a page and the `shauth.monitoring/v1` contract, which reports the
same `build` object, can never disagree about which code is running. A local
build reports `unknown` rather than a misleading value.

Every screen has an address. Each account is at `/admin/users/{id}` and each
application at `/admin/apps/{slug}`, which shows its coordinates, its current
checks, and the durable validation history that was previously reachable only
through the machine API. The older `/admin/users/{id}/sessions` address
redirects to the account screen, so existing links keep working.

Listings render as tables on a wide screen and as labelled blocks on a narrow
one, so a phone never scrolls sideways to read a row and every value keeps the
column heading that gives it meaning. Rendering is verified at seven viewport
widths from 320 to 1440 pixels.

## Native relying-party gateway

The container also includes `/shauth-gateway`, a native OpenID Connect (OIDC)
relying-party gateway for a first-party web interface that cannot implement the
protocol itself. It replaces a generic authentication proxy without adding a
second identity system. The gateway discovers Shauth's public issuer, performs
the Authorization Code flow with Proof Key for Code Exchange (PKCE), verifies
the ID token signature, issuer, audience, expiry, nonce, subject, and provider
session identifier, and stores opaque application sessions in PostgreSQL.

Authenticated requests are proxied to `OIDC_GATEWAY_UPSTREAM_URL` with verified
`X-Forwarded-Subject`, `X-Forwarded-User`,
`X-Forwarded-Preferred-Username`, `X-Forwarded-Email`, and `X-Forwarded-Role`
headers. The gateway removes any client-supplied values for those headers and
removes the inbound `Authorization` header. Its `/auth/session` endpoint exposes
the verified user to the first-party UI, and `POST /auth/logout` performs an OIDC
relying-party-initiated logout using the stored ID token. Signed back-channel
logout and correlated front-channel logout revoke every matching local session.
Security headers on gateway-owned `/auth/` responses deny framing except for
the issuer-only front-channel logout document. Proxied application responses
retain the upstream application's own Content Security Policy and
`X-Frame-Options`, so same-origin application frames keep working without the
identity gateway weakening or replacing their policy.

The gateway requires `OIDC_GATEWAY_ISSUER`, `OIDC_GATEWAY_CLIENT_ID`,
`OIDC_GATEWAY_CLIENT_SECRET`, `OIDC_GATEWAY_PUBLIC_URL`,
`OIDC_GATEWAY_UPSTREAM_URL`, `OIDC_GATEWAY_POST_LOGOUT_URL`,
`OIDC_GATEWAY_COOKIE_SECRET`, `DATABASE_URL`, and
`APPLICATION_RELEASE_REVISION`. The release revision must be an immutable
12-to-64-character lowercase hexadecimal revision or a `sha256:` container
digest. The post-logout URL must use the application's public origin and must
be registered on its Shauth client.
`OIDC_GATEWAY_SESSION_MAX_AGE` defaults to eight hours. Production issuer,
public, and post-logout coordinates require HTTPS; explicit insecure cookies
are accepted only for loopback integration tests.

The gateway owns `GET /auth/validation`. Anonymous requests redirect exactly
to `/auth/signed-out`; authenticated requests expose the verified username,
email, normalized role, and `APPLICATION_RELEASE_REVISION` through the common
`validation-username`, `validation-email`, `validation-role`, and
`validation-release` test markers. The validation page signs out through the
same real relying-party logout flow used by the application UI.

`GET /auth/healthz` answers `200 ok` only while the gateway can reach its own
session store, and `503` when it cannot. Shauth's catalog polls this endpoint
to decide whether the application is up, and a gateway without its session
store cannot admit or refuse a single request — so reporting ready would tell
an operator the application is working while every request to it is being
turned away. A deployment that also uses this URL as a load-balancer health
check will therefore drain the target during a database outage, which is the
same fail-closed answer.

Each gateway deployment uses its relying party's distinct PostgreSQL database,
not Shauth's identity database. `/shauth-gateway` applies its embedded,
gateway-only session and replay-protection migrations before accepting traffic;
startup fails if the dedicated database is unavailable or cannot be migrated.

## Deployment model

The Terraform module deploys Shauth, Ory Hydra, and a standalone ARM64 browser
validator in private Amazon ECS Fargate subnets. A public HTTPS entry point at
`auth.dev.e6qu.dev` routes only
the required identity endpoints. PostgreSQL is the durable source of truth.
All services remain always-on in the `dev` environment.

Runtime secret requirements: the Hydra system secret must remain stable across
restarts. Terraform creates it and the bootstrap-admin password with a
cryptographically secure generator and stores them in AWS Secrets Manager.
The validator queue token lives in a separate validator secret; the
outbound-only validator task has no task role and its execution role can read
only that secret. GitHub OAuth credentials remain in the separately
managed AWS Secrets Manager secret supplied to the module.

Microsoft Entra ID is enabled only when `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`,
and `ENTRA_CLIENT_SECRET` are all present. The tenant must be a specific UUID;
multi-tenant aliases such as `common` and `organizations` are rejected. The
client secret remains in the deployment secret store and is never rendered.
