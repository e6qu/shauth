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

Pass pinned multi-architecture image manifests such as
`ghcr.io/e6qu/shauth:0123456789ab` and
`ghcr.io/e6qu/shauth-validator:0123456789ab`, and the ARN of the GitHub OAuth client
secret stored in AWS Secrets Manager, together with the separate Secrets
Manager ARNs for the Shauth and Ory Hydra database URLs created by `fck-rds`.
The module creates a runtime secret containing generated Hydra and
bootstrap-admin secrets. It creates a second validator-only secret containing
the independent worker queue token. The validation identity has no password;
the worker exchanges its queue credential for hashed, short-lived, single-use
browser bootstrap links.
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
By default the module also creates and owns its Amazon API Gateway VPC Link and
the link's security group. A deployment that consolidates links can instead set
`create_api_gateway_vpc_link = false`, `api_gateway_vpc_link_id`, and
`api_gateway_vpc_link_security_group_id` together. In that mode the module
creates neither shared resource, permits the supplied link security group to
reach Shauth's task, and attaches the HTTP API integration to the supplied
link. The explicit creation flag remains known while resource-derived IDs are
unknown during planning. Terraform rejects either ownership mode when its
corresponding coordinate contract is not satisfied.

Shauth's task role has only the permissions required for identity delivery.
Administrators register each managed app with its OIDC client, launch URL,
published health URL, and optional monitoring URL. Shauth checks health through
standard HTTP and remains independent of deployment platforms and log systems.
Each `bootstrap_apps` client also supplies its sign-in redirect URIs, allowed
post-logout redirect URIs, and at least one front-channel or back-channel
logout URI. These coordinates let Ory Hydra propagate one Shauth logout to
every correlated relying-application session. Each app also supplies an
immutable `release_revision`, a normal launch UI exposing
`data-shauth-user="<username>"` and an actionable `data-shauth-sign-out`
control, an authenticated `validation_url` exposing exact username, email,
normalized role, and release-revision fields,
and an app-local `signed_out_url` exposing an accessible `Sign in with Shauth`
control. The client must register its exact app-origin
`/auth/shauth/logout/complete` bridge as the only value in
`post_logout_redirect_uris`; the bridge
returns to Shauth's one-time completion endpoint, which then redirects to the
trusted app-local `signed_out_url`. Release revisions and both container images must use immutable
lowercase hexadecimal commits/tags or `sha256` digests; moving labels are
rejected. Any release, endpoint-coordinate, or OpenID Connect registration change queues real browser checks
through both the Shauth catalog and the app's direct launch URL.

The ARM64 validator is a standalone outbound-only Amazon ECS service, not a
sidecar and not an authentication proxy. PostgreSQL leases one check globally
and enforces a 30-second start cooldown. Each check uses a second registered
application on a distinct origin to prove global session revocation; without a
real witness application the result is red. The validator task has no AWS task
role, no ingress, and an execution role limited to its dedicated secret. The
validation identity has no reusable password. The worker exchanges its
dedicated validator credential for short-lived, single-use Shauth browser
bootstraps; only their hashes are stored, and neither credential crosses an
application origin. Managed applications receive and validate ordinary OIDC
artifacts and never receive or directly accept validator credentials.

The module creates a separate `${var.name}/validation-status-reader` secret.
Its read-only bearer token authorizes `GET /api/v1/apps/validations`, which
returns the latest durable result for both directions of every registered app
without exposing browser sessions, OIDC artifacts, or validator-control
credentials.

`monitoring_sources` supplies deployment-neutral, authenticated HTTPS
coordinates that publish the `e6qu.monitoring/v1` observation contract. The
module stores this configuration in the runtime secret, so bearer tokens do
not appear in task-definition environment values. Shauth only reads the
endpoints and receives no deployment-control permission.
