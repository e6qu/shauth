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
