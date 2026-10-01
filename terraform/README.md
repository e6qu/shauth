# Shauth on Amazon ECS

This module runs Shauth on Amazon ECS Fargate (ARM64) in private subnets:

- Shauth, Ory Hydra and both migrations run in one task;
- the browser validator runs as a second service.

The module creates:

| Resource | Purpose |
|---|---|
| ECS task definitions and services | Shauth with Hydra and their migrations; the validator. One task each. A circuit breaker rolls back a deployment that never becomes healthy. Terraform waits for steady state. |
| API Gateway HTTP API, custom domain, ACM certificate, Route 53 alias | The only public entry point, for `domain_name`. Throttled to a burst of 50 and 25 requests per second. |
| VPC Link and its security group | Private route from the API to the task. Reaches the task through a Cloud Map SRV record (`<name>-srv`) on TCP 8080. |
| Secrets Manager secrets | One runtime secret, plus one secret per bearer credential (see below). |
| Generated secrets | The Hydra system secret, the bootstrap admin password, and every bearer token. |
| SES domain identity with DKIM | Invitation email from `invitation_email_from`'s domain. |
| IAM roles | Execution roles that can read exactly the listed secrets. A task role that can only send invitation email. The validator has no task role. |
| CloudWatch log group | `/shauth/<name>`, unless `log_group_name` is set. |

You supply the network, the databases and the identity provider credentials.

## Inputs

| Variable | Required | Meaning |
|---|---|---|
| `region`, `name` | `name` defaults to `shauth` | Resource naming. |
| `vpc_id`, `private_subnet_ids`, `ecs_cluster_arn` | yes | Where to run. |
| `hosted_zone_id`, `domain_name` | yes | Public name and its Route 53 zone. |
| `container_image`, `validator_container_image` | yes | Immutable references: a 12–64 hex tag or a `sha256` digest. |
| `database_url_secret_arn`, `hydra_database_url_secret_arn` | yes | Secrets holding each database's connection URL. Create the databases and roles beforehand; the module only runs migrations. |
| `github_client_id`, `github_oauth_secret_arn` | yes | GitHub OAuth app. The secret is JSON with a `client_secret` key. |
| `github_admin_team`, `github_developer_team` | yes | `org/team-slug`. Seeds the first access rules. |
| `entra_tenant_id`, `entra_client_id`, `entra_oauth_secret_arn` | all or none | Microsoft Entra ID, for one tenant UUID. |
| `bootstrap_admin_email`, `invitation_email_from` | yes | Break-glass admin, and the invitation sender. |
| `bootstrap_apps` | no | Sensitive. The [`SHAUTH_BOOTSTRAP_APPS_JSON`](../docs/integrating-apps.md#bootstrap-configuration) entries. |
| `monitoring_sources` | no | [Monitoring sources](../docs/operations.md#monitoring-sources). Stored in the runtime secret. |
| `create_api_gateway_vpc_link` | default `true` | Set it to `false` to reuse a VPC Link. In that case also set `api_gateway_vpc_link_id` and `api_gateway_vpc_link_security_group_id`. |
| `log_group_name` | no | Keep an existing log group. Renaming a log group replaces it. |
| `tags` | no | Added to every resource. |

## Outputs

| Output | Contents |
|---|---|
| `url` | `https://<domain_name>` |
| `runtime_secret_arn` | The runtime secret. |
| `validation_status_secret_arn` | `SHAUTH_VALIDATION_STATUS_TOKEN` |
| `admin_api_reader_secret_arn` | `SHAUTH_ADMIN_API_READ_TOKEN` |
| `admin_api_writer_secret_arn` | `SHAUTH_ADMIN_API_WRITE_TOKEN` |
| `session_reset_secret_arn` | `SHAUTH_SESSION_RESET_TOKEN` |
| `service_security_group_id`, `api_gateway_vpc_link_id`, `api_gateway_vpc_link_security_group_id` | Network coordinates. |

Each bearer credential has its own secret, so a consumer can be granted exactly
one. Every secret also has a `*_CONFIG_VERSION` environment entry, so rotating
a secret rolls out a new task definition.

## Network egress

Shauth and the validator need outbound DNS and HTTPS:

- Shauth reaches GitHub, Entra ID, SES, monitoring sources and registered
  applications;
- the validator reaches Shauth and the registered applications.

Security groups cannot filter by hostname, so these six egress rules are
marked as reviewed Trivy exceptions (`trivy:ignore` in `main.tf`). If you need
destination filtering, put an egress firewall or proxy in front and narrow the
rules to it.

## Tests

```sh
terraform -chdir=terraform init -backend=false
terraform -chdir=terraform test
```

The tests check, among other things, that:

- every credential the application reads reaches the container;
- the right execution role can read each one;
- each one has a redeploy trigger;
- invalid inputs are rejected at plan time.
