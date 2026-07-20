# Shauth Amazon ECS module

This module deploys Shauth and Ory Hydra as an always-on ARM64 Amazon Elastic
Container Service task in private subnets. It connects to dedicated `shauth`
and `hydra` databases supplied by the shared `fck-rds` PostgreSQL service.
The `fck-rds` service owns database and role creation; Shauth's migration
containers only apply application and Ory Hydra schema migrations.

The only public entry point is an Amazon API Gateway HTTP API with a private
VPC link to Amazon Cloud Map service discovery using SRV records, which carry
the live Amazon ECS task port; no Application Load Balancer is provisioned.
The module creates the regional AWS Certificate Manager
certificate and Route 53 alias for `domain_name` and applies conservative
default-route throttling.

The Cloud Map service name is suffixed with `-srv` so an older A-record
service can be replaced safely: Terraform creates the SRV service, moves the
Amazon ECS and API Gateway registrations, then removes the retired service.
The module waits for the Amazon ECS service to reach steady state before
Terraform retires the previous Cloud Map service.

Pass a pinned multi-architecture image manifest such as
`ghcr.io/e6qu/shauth:0123456789ab`, and the ARN of the GitHub OAuth client
secret stored in AWS Secrets Manager, together with the separate Secrets
Manager ARNs for the Shauth and Ory Hydra database URLs created by `fck-rds`.
The module creates a separate runtime secret containing generated Hydra and
bootstrap-admin secrets.
The supplied Shauth image also provides the patched `/hydra` binary; the task
uses that same immutable image for Hydra and both database migration entry
points. The provider is fully built before deployment.

Set `entra_tenant_id`, `entra_client_id`, and `entra_oauth_secret_arn` together
to enable Microsoft Entra ID as an additional upstream identity source. The
tenant is a specific tenant UUID and the secret ARN names a JSON secret with a
`client_secret` key. Omitting all three leaves the connector disabled; partial
configuration is rejected during Terraform validation.

The caller supplies the shared VPC, private subnet IDs, Amazon ECS cluster,
and Route 53 hosted zone so Shauth can coexist with the other `dev` services.

Shauth's task role has only the permissions required for identity delivery.
Administrators register each managed app with its OIDC client, launch URL,
published health URL, and optional monitoring URL. Shauth checks health through
standard HTTP and remains independent of deployment platforms and log systems.
Each `bootstrap_apps` client also supplies its sign-in redirect URIs, allowed
post-logout redirect URIs, and at least one front-channel or back-channel
logout URI. These coordinates let Ory Hydra propagate one Shauth logout to
every correlated relying-application session.
