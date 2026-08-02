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
