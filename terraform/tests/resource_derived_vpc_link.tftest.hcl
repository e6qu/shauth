provider "aws" {
  region                      = "eu-west-1"
  access_key                  = "terraform-test"
  secret_key                  = "terraform-test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_requesting_account_id  = true
}

run "resource_derived_vpc_link_coordinates" {
  command = plan

  module {
    source = "./tests/fixtures/resource_derived_vpc_link"
  }

  plan_options {
    refresh = false
  }

  assert {
    condition     = aws_apigatewayv2_vpc_link.shared.name == "shauth-test-shared"
    error_message = "The fixture must supply an Amazon API Gateway VPC Link whose ID is unknown until apply."
  }

  assert {
    condition     = aws_security_group.shared.name_prefix == "shauth-test-shared-link-"
    error_message = "The fixture must supply a VPC Link security group whose ID is unknown until apply."
  }
}
