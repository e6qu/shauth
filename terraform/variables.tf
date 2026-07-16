variable "region" { type = string }
variable "name" {
  type    = string
  default = "shauth"
}
variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "ecs_cluster_arn" { type = string }
variable "hosted_zone_id" { type = string }
variable "domain_name" { type = string }
variable "container_image" { type = string }
variable "github_oauth_secret_arn" {
  type        = string
  description = "AWS Secrets Manager ARN for a JSON secret containing a client_secret key."
}
variable "github_client_id" { type = string }
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
  description = "Confidential OIDC clients and managed ECS applications Shauth creates idempotently at startup. This input contains client secrets and must be supplied as a Terraform sensitive value."
  sensitive   = true
  type = list(object({
    slug                 = string
    name                 = string
    description          = string
    launch_url           = string
    oidc_client_id       = string
    oidc_client_secret   = string
    redirect_uris        = list(string)
    ecs_service_name     = string
    cloudwatch_log_group = string
  }))
  default = []
}
