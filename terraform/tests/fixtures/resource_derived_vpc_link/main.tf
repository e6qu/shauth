terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

resource "aws_security_group" "shared" {
  name_prefix = "shauth-test-shared-link-"
  vpc_id      = "vpc-0123456789abcdef0"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_apigatewayv2_vpc_link" "shared" {
  name               = "shauth-test-shared"
  subnet_ids         = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
  security_group_ids = [aws_security_group.shared.id]
}

module "shauth" {
  source = "../../.."

  region                                 = "eu-west-1"
  name                                   = "shauth-test"
  vpc_id                                 = "vpc-0123456789abcdef0"
  private_subnet_ids                     = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
  create_api_gateway_vpc_link            = false
  api_gateway_vpc_link_id                = aws_apigatewayv2_vpc_link.shared.id
  api_gateway_vpc_link_security_group_id = aws_security_group.shared.id
  ecs_cluster_arn                        = "arn:aws:ecs:eu-west-1:123456789012:cluster/test"
  hosted_zone_id                         = "Z0123456789ABC"
  domain_name                            = "auth.test.example.com"
  container_image                        = "ghcr.io/e6qu/shauth@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  github_oauth_secret_arn                = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:github"
  github_client_id                       = "test-client"
  bootstrap_admin_email                  = "admin@test.example.com"
  invitation_email_from                  = "invitations@test.example.com"
  database_url_secret_arn                = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:shauth-database"
  hydra_database_url_secret_arn          = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:hydra-database"
}
