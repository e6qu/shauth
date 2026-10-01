provider "aws" {
  region                      = "eu-west-1"
  access_key                  = "terraform-test"
  secret_key                  = "terraform-test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_requesting_account_id  = true
}

variables {
  region                        = "eu-west-1"
  name                          = "shauth-test"
  vpc_id                        = "vpc-0123456789abcdef0"
  private_subnet_ids            = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
  ecs_cluster_arn               = "arn:aws:ecs:eu-west-1:123456789012:cluster/test"
  hosted_zone_id                = "Z0123456789ABC"
  domain_name                   = "auth.test.example.com"
  container_image               = "ghcr.io/e6qu/shauth@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  validator_container_image     = "ghcr.io/e6qu/shauth-validator@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  github_oauth_secret_arn       = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:github"
  github_client_id              = "test-client"
  bootstrap_admin_email         = "admin@test.example.com"
  invitation_email_from         = "invitations@test.example.com"
  database_url_secret_arn       = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:shauth-database"
  github_admin_team             = "example-org/admins"
  github_developer_team         = "example-org/developers"
  hydra_database_url_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:hydra-database"
}

# Every bearer credential the application supports must actually reach the
# Shauth container. Without these assertions a supported credential can be
# added to the application while Terraform silently never supplies it, leaving
# the corresponding endpoints answering 503 in every deployment.
run "every_closed_api_credential_reaches_the_shauth_container" {
  command = plan

  plan_options {
    refresh = false
  }

  assert {
    condition = length(setsubtract([
      "SHAUTH_VALIDATOR_TOKEN",
      "SHAUTH_VALIDATION_STATUS_TOKEN",
      "SHAUTH_SESSION_RESET_TOKEN",
      "SHAUTH_ADMIN_API_READ_TOKEN",
      "SHAUTH_ADMIN_API_WRITE_TOKEN",
    ], [for secret in local.shauth_secrets : secret.name])) == 0
    error_message = "Every closed-API bearer credential must be injected into the Shauth container."
  }

}

# The execution role policy enumerates secret ARNs explicitly, so a secret
# added without a matching grant leaves the task unable to start. Secret ARNs
# are unknown until apply, so this asserts the count: the six secrets this
# module creates plus the three supplied by the caller. Adding a secret
# without its grant fails here and forces the grant to be added.
run "execution_role_grants_every_module_secret" {
  command = plan

  plan_options {
    refresh = false
  }

  assert {
    condition     = length(local.execution_secret_arns) == 9
    error_message = "The task execution role must enumerate every injected secret: six created here plus the database, Hydra database, and GitHub OAuth secrets."
  }
}

run "enabling_the_entra_connector_grants_its_secret" {
  command = plan

  plan_options {
    refresh = false
  }

  variables {
    entra_tenant_id        = "12345678-1234-4234-8234-123456789abc"
    entra_client_id        = "entra-client"
    entra_oauth_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:entra"
  }

  assert {
    condition     = length(local.execution_secret_arns) == 10
    error_message = "Enabling the Microsoft Entra ID connector must also grant its OAuth secret to the execution role."
  }
}

# Rotating a credential must produce a new task definition revision, otherwise
# the running task keeps the superseded value.
run "each_credential_secret_has_a_redeploy_trigger" {
  command = plan

  plan_options {
    refresh = false
  }

  assert {
    condition = length(setsubtract([
      "SHAUTH_RUNTIME_CONFIG_VERSION",
      "SHAUTH_VALIDATOR_CONFIG_VERSION",
      "SHAUTH_VALIDATION_STATUS_CONFIG_VERSION",
      "SHAUTH_SESSION_RESET_CONFIG_VERSION",
      "SHAUTH_ADMIN_API_READ_CONFIG_VERSION",
      "SHAUTH_ADMIN_API_WRITE_CONFIG_VERSION",
    ], [for entry in local.shauth_environment : entry.name])) == 0
    error_message = "Each credential secret must have a configuration version entry so rotation redeploys the service."
  }
}

# The validator runs as a separate task with its own execution role. It must
# never receive an administration credential.
run "validator_task_receives_only_its_own_credential" {
  command = plan

  plan_options {
    refresh = false
  }

  assert {
    condition     = length(data.aws_iam_policy_document.validator_secrets.statement[0].resources) == 1
    error_message = "The validator execution role must be limited to its own secret."
  }
}

# The module's key encrypts the log group and every secret it creates. The
# Logs service needs the key policy itself to admit this log group, and both
# execution roles need decrypt through Secrets Manager, or no task starts.
run "data_key_admits_logs_and_secret_injection" {
  command = plan

  plan_options {
    refresh = false
  }

  assert {
    condition = anytrue([
      for statement in data.aws_iam_policy_document.data_key.statement :
      contains(flatten([for principal in statement.principals : principal.identifiers]), "logs.eu-west-1.amazonaws.com")
      && one([for condition in statement.condition : condition.values[0]]) == "arn:aws:logs:eu-west-1:123456789012:log-group:/shauth/shauth-test"
    ])
    error_message = "The data key policy must admit CloudWatch Logs for exactly this module's log group."
  }

  assert {
    condition = alltrue([
      for document in [data.aws_iam_policy_document.secrets, data.aws_iam_policy_document.validator_secrets] :
      anytrue([
        for statement in document.statement :
        contains(statement.actions, "kms:Decrypt")
        && one([for condition in statement.condition : condition.values[0]]) == "secretsmanager.eu-west-1.amazonaws.com"
      ])
    ])
    error_message = "Both execution roles must decrypt the module's secrets through Secrets Manager."
  }
}

# Ory Hydra in the task must run with the settings the local stack exercises:
# JWT access tokens, Lax provider cookies, no telemetry, and the token hook
# that has Shauth confirm every issued and refreshed token. The hook's
# credential reaches Hydra only as a secret, never as plain configuration.
run "hydra_runs_with_the_token_hook_and_the_tested_settings" {
  command = plan

  plan_options {
    refresh = false
  }

  assert {
    condition = alltrue([
      for name, value in {
        STRATEGIES_ACCESS_TOKEN            = "jwt"
        SERVE_COOKIES_SAME_SITE_MODE       = "Lax"
        SQA_OPT_OUT                        = "true"
        OAUTH2_TOKEN_HOOK_URL              = "http://localhost:8080/internal/hydra/token-hook"
        OAUTH2_TOKEN_HOOK_AUTH_TYPE        = "api_key"
        OAUTH2_TOKEN_HOOK_AUTH_CONFIG_IN   = "header"
        OAUTH2_TOKEN_HOOK_AUTH_CONFIG_NAME = "Authorization"
      } : contains([for entry in local.hydra_environment : "${entry.name}=${entry.value}"], "${name}=${value}")
    ])
    error_message = "Hydra must issue JWT access tokens, use Lax cookies, opt out of telemetry, and call Shauth's token hook."
  }

  assert {
    condition     = contains([for secret in local.hydra_secrets : secret.name], "OAUTH2_TOKEN_HOOK_AUTH_CONFIG_VALUE") && !contains([for entry in local.hydra_environment : entry.name], "OAUTH2_TOKEN_HOOK_AUTH_CONFIG_VALUE")
    error_message = "The token hook credential must reach Hydra as a secret."
  }

  assert {
    condition     = contains([for secret in local.shauth_secrets : secret.name], "SHAUTH_TOKEN_HOOK_TOKEN")
    error_message = "Shauth must receive the token hook credential it verifies."
  }
}

# The module names no particular organization: both GitHub teams are required
# inputs and must be organization/team-slug.
run "github_teams_are_required_coordinates" {
  command = plan

  plan_options {
    refresh = false
  }

  variables {
    github_admin_team = "not-a-team"
  }

  expect_failures = [var.github_admin_team]
}

# The validator runs Chromium, whose orphaned helpers must be reaped.
run "validator_runs_under_an_init_process" {
  command = plan

  plan_options {
    refresh = false
  }

  assert {
    condition     = local.validator_linux_parameters.initProcessEnabled
    error_message = "The validator container must run under an init process."
  }
}
