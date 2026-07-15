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
variable "github_oauth_secret_arn" { type = string }
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
variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro"
}
variable "tags" {
  type    = map(string)
  default = {}
}
