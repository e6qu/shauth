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
Shauth exposes Ory Hydra's complete public OpenID Connect surface at its public
issuer, including discovery, authorization, token, UserInfo, revocation,
introspection, and front-channel logout endpoints. Relying applications never
connect to Hydra's private task coordinate directly.

Administrators can invalidate one Shauth browser session or invalidate every
session for a user. Subject-wide invalidation deletes the user's Hydra login
and consent sessions as well, revoking associated access and refresh tokens.
Administrators also configure the durable browser absolute lifetime, browser
idle timeout, OIDC single sign-on lifetime, and access, ID, and refresh token
lifetimes. Shauth applies the token lifetimes to every paginated Ory Hydra
client and enforces the browser limits from PostgreSQL.
GitHub mappings are evaluated on every GitHub sign-in; a matching administrator
mapping overrides a matching developer mapping. Administration and monitoring
navigation are shown only to administrators, and the corresponding handlers
enforce that role server-side.

The signed-in Apps page is a catalog of real deployed services. Administrators
register an app only after its Shauth OIDC client, launch URL, and published
health endpoint exist. Users open services through their own startup paths;
Shauth monitors standard HTTPS health endpoints without deployment control.

Terraform can supply `bootstrap_apps` as a sensitive input to register clients
and catalog records idempotently during Shauth startup. The input is stored only
in the Shauth runtime secret and contains each confidential client secret,
sign-in and post-logout redirect URIs, at least one front-channel or
back-channel logout URI, launch URL, health URL, and optional monitoring URL.

## Deployment model

The Terraform module deploys Shauth and Hydra in private Amazon ECS
Fargate subnets. A public HTTPS entry point at `auth.dev.e6qu.dev` routes only
the required identity endpoints. PostgreSQL is the durable source of truth.
All services remain always-on in the `dev` environment.

Runtime secret requirements: the Hydra system secret must remain stable across
restarts. Terraform creates it, the database password, and the bootstrap-admin
password with a cryptographically secure generator and stores them in AWS
Secrets Manager. GitHub OAuth credentials remain in the separately managed
AWS Secrets Manager secret supplied to the module.

Microsoft Entra ID is enabled only when `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`,
and `ENTRA_CLIENT_SECRET` are all present. The tenant must be a specific UUID;
multi-tenant aliases such as `common` and `organizations` are rejected. The
client secret remains in the deployment secret store and is never rendered.
