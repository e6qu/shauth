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

The signed-in Apps page is a catalog of real deployed services. Administrators
register an app only after its Shauth OIDC client, Amazon Elastic Container
Service service, and Amazon CloudWatch Logs group exist. Developers can start
registered apps; administrators can also stop them and read their real logs.

Terraform can supply `bootstrap_apps` as a sensitive input to register clients
and catalog records idempotently during Shauth startup. The input is stored only
in the Shauth runtime secret and contains each confidential client secret,
redirect URI, Amazon ECS service name, and Amazon CloudWatch Logs group.

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
