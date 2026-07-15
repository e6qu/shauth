# Shauth Amazon ECS module

This module deploys Shauth and Ory Hydra as an always-on ARM64 Amazon Elastic
Container Service task in private subnets. It uses one small, encrypted,
single-AZ Amazon RDS for PostgreSQL instance, with isolated `shauth` and
`hydra` databases. The task's migration containers create and migrate those
databases before either application starts.

Automated Amazon RDS backups default to seven days and can be tailored with
`db_backup_retention_period` when an account plan imposes a lower limit.

The only public entry point is an Amazon API Gateway HTTP API with a private
VPC link to Amazon Cloud Map service discovery; no Application Load Balancer
is provisioned. The module creates the regional AWS Certificate Manager
certificate and Route 53 alias for `domain_name` and applies conservative
default-route throttling.

Pass a pinned multi-architecture image manifest such as
`ghcr.io/e6qu/shauth:0123456789ab`, and the ARN of the GitHub OAuth client
secret stored in AWS Secrets Manager. The module creates a separate runtime
secret containing the generated database, Hydra, and bootstrap-admin secrets.

The caller supplies the shared VPC, private subnet IDs, Amazon ECS cluster,
and Route 53 hosted zone so Shauth can coexist with the other `dev` services.
