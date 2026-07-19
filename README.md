# Shauth

Shauth is e6qu's Go identity administration and observability service. It uses
Ory Hydra as its OAuth 2.0/OpenID Connect issuer and keeps identity, browser
session, invitation, and audit state in PostgreSQL. GitHub OAuth is the current
federated source; Azure Entra federation is configured as a future connector.

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
added to the GitHub OAuth application.

## Access and session lifecycle

Shauth keeps browser sessions in PostgreSQL and Ory Hydra keeps OpenID Connect
login and consent sessions. A normal sign-out is an explicit, same-origin
browser action: Shauth starts Hydra's front-channel logout, verifies the
challenge subject against the signed-in local user, revokes the local browser
session, and accepts the Hydra logout request. Relying applications clear their
own session and navigate the browser to Shauth's published
`/oauth2/sessions/logout` endpoint; they do not POST cross-origin to Shauth.
Shauth exposes Ory Hydra's complete public OpenID Connect surface at its public
issuer, including discovery, authorization, token, UserInfo, revocation,
introspection, and front-channel logout endpoints. Relying applications never
connect to Hydra's private task coordinate directly.

Administrators can invalidate one Shauth browser session or invalidate every
session for a user. Subject-wide invalidation deletes the user's Hydra login
and consent sessions as well, revoking associated access and refresh tokens.
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
redirect URI, launch URL, health URL, and optional monitoring URL.

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
