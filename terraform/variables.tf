variable "region" { type = string }
variable "name" {
  type    = string
  default = "shauth"
}
variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "create_api_gateway_vpc_link" {
  type        = bool
  default     = true
  description = "Whether this module creates and owns its Amazon API Gateway VPC Link and link security group."

  validation {
    condition = var.create_api_gateway_vpc_link ? (
      var.api_gateway_vpc_link_id == null && var.api_gateway_vpc_link_security_group_id == null
      ) : (
      var.api_gateway_vpc_link_id != null && trimspace(var.api_gateway_vpc_link_id) != "" &&
      var.api_gateway_vpc_link_security_group_id != null && trimspace(var.api_gateway_vpc_link_security_group_id) != ""
    )
    error_message = "When create_api_gateway_vpc_link is true, the existing VPC Link inputs must be null; when false, api_gateway_vpc_link_id and api_gateway_vpc_link_security_group_id must both be set to non-empty values."
  }
}
variable "api_gateway_vpc_link_id" {
  type        = string
  default     = null
  nullable    = true
  description = "Existing Amazon API Gateway VPC Link ID used when create_api_gateway_vpc_link is false."
}
variable "api_gateway_vpc_link_security_group_id" {
  type        = string
  default     = null
  nullable    = true
  description = "Security group attached to api_gateway_vpc_link_id when create_api_gateway_vpc_link is false."
}
variable "ecs_cluster_arn" { type = string }
variable "hosted_zone_id" { type = string }
variable "domain_name" { type = string }
variable "container_image" {
  type        = string
  description = "Immutable Shauth image reference pinned by 12–64 character lowercase hexadecimal tag or sha256 digest."
  validation {
    condition     = can(regex("(@sha256:[0-9a-f]{64}|:[0-9a-f]{12,64})$", var.container_image))
    error_message = "container_image must use an immutable 12–64 character lowercase hexadecimal tag or sha256 digest."
  }
}
variable "validator_container_image" {
  type        = string
  description = "Immutable Shauth validator image reference pinned by 12–64 character lowercase hexadecimal tag or sha256 digest."
  validation {
    condition     = can(regex("(@sha256:[0-9a-f]{64}|:[0-9a-f]{12,64})$", var.validator_container_image))
    error_message = "validator_container_image must use an immutable 12–64 character lowercase hexadecimal tag or sha256 digest."
  }
}
variable "github_oauth_secret_arn" {
  type        = string
  description = "AWS Secrets Manager ARN for a JSON secret containing a client_secret key."
}
variable "github_client_id" { type = string }
variable "entra_tenant_id" {
  type        = string
  default     = null
  description = "Specific Microsoft Entra ID tenant UUID. Set together with entra_client_id and entra_oauth_secret_arn."
}
variable "entra_client_id" {
  type    = string
  default = null
}
variable "entra_oauth_secret_arn" {
  type        = string
  default     = null
  description = "AWS Secrets Manager ARN for a JSON secret containing the Microsoft Entra ID client_secret key."
}
variable "bootstrap_admin_email" { type = string }
variable "invitation_email_from" {
  type = string
  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.invitation_email_from))
    error_message = "invitation_email_from must be a valid email address."
  }
}
variable "github_admin_team" {
  type    = string
  default = "e6qu-org/e6qu-org-admins"
}
variable "github_developer_team" {
  type    = string
  default = "e6qu-org/e6qu-org-members"
}
variable "database_url_secret_arn" {
  type        = string
  description = "AWS Secrets Manager ARN containing Shauth's dedicated PostgreSQL URL from fck-rds."
}
variable "hydra_database_url_secret_arn" {
  type        = string
  description = "AWS Secrets Manager ARN containing Ory Hydra's dedicated PostgreSQL URL from fck-rds."
}
variable "tags" {
  type    = map(string)
  default = {}
}
variable "bootstrap_apps" {
  description = "Confidential OIDC clients and endpoint-monitored applications Shauth creates idempotently at startup."
  sensitive   = true
  type = list(object({
    slug                      = string
    name                      = string
    description               = string
    launch_url                = string
    oidc_client_id            = string
    oidc_client_secret        = string
    redirect_uris             = list(string)
    post_logout_redirect_uris = list(string)
    frontchannel_logout_uri   = optional(string, "")
    backchannel_logout_uri    = optional(string, "")
    health_url                = string
    monitoring_url            = string
    validation_url            = string
    signed_out_url            = string
    release_revision          = string
  }))
  default = []
  validation {
    condition = alltrue([
      for app in var.bootstrap_apps :
      length(app.post_logout_redirect_uris) == 1 &&
      can(regex("^https?://[^/]+", app.launch_url)) &&
      length(app.redirect_uris) > 0 &&
      alltrue([for uri in app.redirect_uris :
        can(regex("^https?://[^/]+", uri)) &&
        lower(regex("^https?://[^/]+", uri)) == lower(regex("^https?://[^/]+", app.launch_url))
      ]) &&
      alltrue([for uri in app.post_logout_redirect_uris :
        can(regex("^https?://[^/]+", uri)) &&
        lower(regex("^https?://[^/]+", uri)) == lower(regex("^https?://[^/]+", app.launch_url))
      ]) &&
      try(app.post_logout_redirect_uris[0], "") == "${regex("^https?://[^/]+", app.launch_url)}/auth/shauth/logout/complete" &&
      can(regex("^([0-9a-f]{12,64}|sha256:[0-9a-f]{64})$", app.release_revision)) &&
      (trimspace(app.frontchannel_logout_uri) != "" || trimspace(app.backchannel_logout_uri) != "")
    ])
    error_message = "Each bootstrap app must keep its launch and redirect URIs on one exact origin, register only that origin's exact /auth/shauth/logout/complete bridge URI as its post-logout redirect, set an immutable release_revision, and set frontchannel_logout_uri, backchannel_logout_uri, or both."
  }
}
variable "monitoring_sources" {
  description = "Deployment-neutral authenticated endpoints publishing the e6qu.monitoring/v1 contract."
  sensitive   = true
  type = list(object({
    name         = string
    url          = string
    bearer_token = string
  }))
  default = []
  validation {
    condition = alltrue([
      for source in var.monitoring_sources :
      trimspace(source.name) != "" &&
      can(regex("^https://", source.url)) &&
      length(source.bearer_token) >= 32 &&
      !can(regex("[[:space:][:cntrl:]]", source.bearer_token))
    ])
    error_message = "Monitoring sources require a name, an HTTPS URL, and a bearer token of at least 32 non-whitespace characters."
  }
}
