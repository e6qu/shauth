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

run "standalone_module_owns_vpc_link" {
  command = plan

  plan_options {
    refresh = false
  }

  assert {
    condition     = length(aws_apigatewayv2_vpc_link.this) == 1
    error_message = "The standalone module must create exactly one Amazon API Gateway VPC Link."
  }

  assert {
    condition     = length(aws_security_group.api_link) == 1
    error_message = "The standalone module must create exactly one VPC Link security group."
  }
}

run "deployment_owned_vpc_link" {
  command = plan

  variables {
    create_api_gateway_vpc_link            = false
    api_gateway_vpc_link_id                = "vpclink-0123456789abcdef0"
    api_gateway_vpc_link_security_group_id = "sg-0123456789abcdef0"
  }

  plan_options {
    refresh = false
  }

  assert {
    condition     = length(aws_apigatewayv2_vpc_link.this) == 0
    error_message = "The module must not create an Amazon API Gateway VPC Link when a deployment-owned link is supplied."
  }

  assert {
    condition     = length(aws_security_group.api_link) == 0
    error_message = "The module must not create a VPC Link security group when a deployment-owned group is supplied."
  }

  assert {
    condition     = aws_apigatewayv2_integration.this.connection_id == "vpclink-0123456789abcdef0"
    error_message = "The HTTP API integration must use the supplied Amazon API Gateway VPC Link."
  }

  assert {
    condition     = tolist(aws_security_group.task.ingress)[0].security_groups == toset(["sg-0123456789abcdef0"])
    error_message = "The Shauth task must permit ingress only from the supplied VPC Link security group."
  }
}

run "reject_vpc_link_without_security_group" {
  command = plan

  variables {
    create_api_gateway_vpc_link = false
    api_gateway_vpc_link_id     = "vpclink-0123456789abcdef0"
  }

  plan_options {
    refresh = false
  }

  expect_failures = [var.create_api_gateway_vpc_link]
}

run "reject_security_group_without_vpc_link" {
  command = plan

  variables {
    create_api_gateway_vpc_link            = false
    api_gateway_vpc_link_security_group_id = "sg-0123456789abcdef0"
  }

  plan_options {
    refresh = false
  }

  expect_failures = [var.create_api_gateway_vpc_link]
}

run "reject_existing_coordinates_while_owning_vpc_link" {
  command = plan

  variables {
    api_gateway_vpc_link_id                = "vpclink-0123456789abcdef0"
    api_gateway_vpc_link_security_group_id = "sg-0123456789abcdef0"
  }

  plan_options {
    refresh = false
  }

  expect_failures = [var.create_api_gateway_vpc_link]
}

run "reject_unregistered_shauth_completion_url" {
  command = plan

  variables {
    bootstrap_apps = [{
      slug                      = "example-app"
      name                      = "Example app"
      description               = "Exact post-logout redirect validation."
      launch_url                = "https://app.example.test/"
      oidc_client_id            = "example-app"
      oidc_client_secret        = "0123456789abcdef0123456789abcdef"
      redirect_uris             = ["https://app.example.test/auth/callback"]
      post_logout_redirect_uris = ["https://app.example.test/auth/other-signed-out"]
      backchannel_logout_uri    = "https://app.example.test/auth/backchannel-logout"
      health_url                = "https://app.example.test/healthz"
      monitoring_url            = ""
      validation_url            = "https://app.example.test/auth/validation"
      signed_out_url            = "https://app.example.test/auth/signed-out"
      release_revision          = "0123456789ab"
    }]
  }

  plan_options {
    refresh = false
  }

  expect_failures = [var.bootstrap_apps]
}

run "reject_cross_origin_shauth_logout_bridge" {
  command = plan

  variables {
    bootstrap_apps = [{
      slug                      = "example-app"
      name                      = "Example app"
      description               = "Exact post-logout redirect origin validation."
      launch_url                = "https://app.example.test/"
      oidc_client_id            = "example-app"
      oidc_client_secret        = "0123456789abcdef0123456789abcdef"
      redirect_uris             = ["https://app.example.test/auth/callback"]
      post_logout_redirect_uris = ["https://attacker.example.test/auth/shauth/logout/complete"]
      backchannel_logout_uri    = "https://app.example.test/auth/backchannel-logout"
      health_url                = "https://app.example.test/healthz"
      monitoring_url            = ""
      validation_url            = "https://app.example.test/auth/validation"
      signed_out_url            = "https://app.example.test/auth/signed-out"
      release_revision          = "0123456789ab"
    }]
  }

  plan_options {
    refresh = false
  }

  expect_failures = [var.bootstrap_apps]
}

run "reject_cross_origin_oidc_redirect" {
  command = plan

  variables {
    bootstrap_apps = [{
      slug                      = "example-app"
      name                      = "Example app"
      description               = "Exact sign-in redirect origin validation."
      launch_url                = "https://app.example.test/"
      oidc_client_id            = "example-app"
      oidc_client_secret        = "0123456789abcdef0123456789abcdef"
      redirect_uris             = ["https://attacker.example.test/auth/callback"]
      post_logout_redirect_uris = ["https://app.example.test/auth/shauth/logout/complete"]
      backchannel_logout_uri    = "https://app.example.test/auth/backchannel-logout"
      health_url                = "https://app.example.test/healthz"
      monitoring_url            = ""
      validation_url            = "https://app.example.test/auth/validation"
      signed_out_url            = "https://app.example.test/auth/signed-out"
      release_revision          = "0123456789ab"
    }]
  }

  plan_options {
    refresh = false
  }

  expect_failures = [var.bootstrap_apps]
}
