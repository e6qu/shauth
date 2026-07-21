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
short-lived, single-use Shauth browser bootstraps. A distinct read-only bearer
credential protects `GET /api/v1/apps/validations`, the closed machine-readable
status contract used by post-deployment acceptance gates.

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
