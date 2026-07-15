locals {
  tags                    = merge(var.tags, { service = "shauth", managed-by = "terraform" })
  public_url              = "https://${var.domain_name}"
  invitation_email_domain = split("@", var.invitation_email_from)[1]
}

data "aws_availability_zones" "available" { state = "available" }

resource "aws_cloudwatch_log_group" "this" {
  name              = "/e6qu/${var.name}"
  retention_in_days = 30
  tags              = local.tags
}

resource "aws_security_group" "task" {
  name_prefix = "${var.name}-task-"
  vpc_id      = var.vpc_id
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.api_link.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

resource "aws_security_group" "api_link" {
  name_prefix = "${var.name}-api-link-"
  vpc_id      = var.vpc_id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

resource "aws_security_group" "database" {
  name_prefix = "${var.name}-database-"
  vpc_id      = var.vpc_id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.task.id]
  }
  tags = local.tags
}

resource "aws_db_subnet_group" "this" {
  name       = var.name
  subnet_ids = var.private_subnet_ids
  tags       = local.tags
}

resource "random_password" "database" {
  length  = 40
  special = false
}
resource "random_password" "hydra" {
  length  = 48
  special = false
}
resource "random_password" "bootstrap" {
  length  = 40
  special = false
}

resource "aws_db_instance" "this" {
  identifier                 = var.name
  engine                     = "postgres"
  engine_version             = "17"
  instance_class             = var.db_instance_class
  allocated_storage          = 20
  max_allocated_storage      = 50
  storage_type               = "gp3"
  storage_encrypted          = true
  db_name                    = "shauth"
  username                   = "shauth"
  password                   = random_password.database.result
  port                       = 5432
  db_subnet_group_name       = aws_db_subnet_group.this.name
  vpc_security_group_ids     = [aws_security_group.database.id]
  publicly_accessible        = false
  multi_az                   = false
  backup_retention_period    = var.db_backup_retention_period
  deletion_protection        = true
  skip_final_snapshot        = false
  final_snapshot_identifier  = "${var.name}-final"
  auto_minor_version_upgrade = true
  copy_tags_to_snapshot      = true
  tags                       = local.tags
}

resource "aws_secretsmanager_secret" "runtime" {
  name                    = "${var.name}/runtime"
  recovery_window_in_days = 7
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_version" "runtime" {
  secret_id = aws_secretsmanager_secret.runtime.id
  secret_string = jsonencode({
    DATABASE_URL                    = "postgresql://shauth:${random_password.database.result}@${aws_db_instance.this.address}:5432/shauth?sslmode=require"
    DATABASE_ADMIN_URL              = "postgresql://shauth:${random_password.database.result}@${aws_db_instance.this.address}:5432/postgres?sslmode=require"
    HYDRA_DSN                       = "postgresql://shauth:${random_password.database.result}@${aws_db_instance.this.address}:5432/hydra?sslmode=require"
    HYDRA_SYSTEM_SECRET             = random_password.hydra.result
    SHAUTH_BOOTSTRAP_ADMIN_PASSWORD = random_password.bootstrap.result
  })
}

resource "aws_ses_domain_identity" "invitations" {
  domain = local.invitation_email_domain
}

resource "aws_route53_record" "ses_identity" {
  zone_id = var.hosted_zone_id
  name    = "_amazonses.${local.invitation_email_domain}"
  type    = "TXT"
  ttl     = 600
  records = [aws_ses_domain_identity.invitations.verification_token]
}

resource "aws_ses_domain_dkim" "invitations" {
  domain = aws_ses_domain_identity.invitations.domain
}

resource "aws_route53_record" "ses_dkim" {
  count   = 3
  zone_id = var.hosted_zone_id
  name    = "${aws_ses_domain_dkim.invitations.dkim_tokens[count.index]}._domainkey.${local.invitation_email_domain}"
  type    = "CNAME"
  ttl     = 600
  records = ["${aws_ses_domain_dkim.invitations.dkim_tokens[count.index]}.dkim.amazonses.com"]
}

data "aws_iam_policy_document" "task_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "execution" {
  name_prefix        = "${var.name}-execution-"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
  tags               = local.tags
}
resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
data "aws_iam_policy_document" "secrets" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.runtime.arn, var.github_oauth_secret_arn]
  }
}
data "aws_iam_policy_document" "task" {
  statement {
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = [aws_ses_domain_identity.invitations.arn]
  }
}
resource "aws_iam_role_policy" "execution_secrets" {
  name   = "read-runtime-secrets"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.secrets.json
}
resource "aws_iam_role" "task" {
  name_prefix        = "${var.name}-task-"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
  tags               = local.tags
}
resource "aws_iam_role_policy" "task_ses" {
  name   = "send-invitations"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}

resource "aws_service_discovery_private_dns_namespace" "this" {
  name = "${var.name}.internal"
  vpc  = var.vpc_id
  tags = local.tags
}
resource "aws_service_discovery_service" "this" {
  name = "${var.name}-srv"
  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.this.id
    dns_records {
      ttl  = 10
      type = "SRV"
    }
    routing_policy = "MULTIVALUE"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }
  container_definitions = jsonencode([
    { name = "shauth-migrate", image = var.container_image, essential = false, entryPoint = ["/shauth-migrate"], environment = [{ name = "SHAUTH_MIGRATIONS_DIR", value = "/migrations" }], secrets = [{ name = "DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.runtime.arn}:DATABASE_URL::" }, { name = "DATABASE_ADMIN_URL", valueFrom = "${aws_secretsmanager_secret.runtime.arn}:DATABASE_ADMIN_URL::" }], logConfiguration = { logDriver = "awslogs", options = { awslogs-group = aws_cloudwatch_log_group.this.name, awslogs-region = var.region, awslogs-stream-prefix = "migrate" } } },
    { name = "hydra-migrate", image = "oryd/hydra:v26.2.0", essential = false, command = ["migrate", "sql", "up", "--read-from-env", "--yes"], dependsOn = [{ containerName = "shauth-migrate", condition = "SUCCESS" }], secrets = [{ name = "DSN", valueFrom = "${aws_secretsmanager_secret.runtime.arn}:HYDRA_DSN::" }], logConfiguration = { logDriver = "awslogs", options = { awslogs-group = aws_cloudwatch_log_group.this.name, awslogs-region = var.region, awslogs-stream-prefix = "hydra-migrate" } } },
    { name = "hydra", image = "oryd/hydra:v26.2.0", essential = true, command = ["serve", "all"], dependsOn = [{ containerName = "hydra-migrate", condition = "SUCCESS" }], environment = [{ name = "URLS_SELF_ISSUER", value = local.public_url }, { name = "URLS_LOGIN", value = "${local.public_url}/oauth/login" }, { name = "URLS_CONSENT", value = "${local.public_url}/oauth/consent" }, { name = "URLS_LOGOUT", value = "${local.public_url}/oauth/logout" }, { name = "TTL_ACCESS_TOKEN", value = "15m" }, { name = "TTL_REFRESH_TOKEN", value = "720h" }, { name = "TTL_ID_TOKEN", value = "15m" }, { name = "TTL_AUTH_CODE", value = "10m" }], secrets = [{ name = "DSN", valueFrom = "${aws_secretsmanager_secret.runtime.arn}:HYDRA_DSN::" }, { name = "SECRETS_SYSTEM_0", valueFrom = "${aws_secretsmanager_secret.runtime.arn}:HYDRA_SYSTEM_SECRET::" }], portMappings = [{ containerPort = 4444, protocol = "tcp" }], logConfiguration = { logDriver = "awslogs", options = { awslogs-group = aws_cloudwatch_log_group.this.name, awslogs-region = var.region, awslogs-stream-prefix = "hydra" } } },
    { name = "shauth", image = var.container_image, essential = true, dependsOn = [{ containerName = "hydra", condition = "START" }], portMappings = [{ containerPort = 8080, protocol = "tcp" }], environment = [{ name = "SHAUTH_LISTEN_ADDRESS", value = ":8080" }, { name = "SHAUTH_PUBLIC_URL", value = local.public_url }, { name = "HYDRA_ADMIN_URL", value = "http://127.0.0.1:4445" }, { name = "HYDRA_PUBLIC_INTERNAL_URL", value = "http://127.0.0.1:4444" }, { name = "GITHUB_CLIENT_ID", value = var.github_client_id }, { name = "GITHUB_DEVELOPER_TEAM", value = var.github_developer_team }, { name = "GITHUB_ADMIN_TEAM", value = var.github_admin_team }, { name = "SHAUTH_BOOTSTRAP_ADMIN_EMAIL", value = var.bootstrap_admin_email }, { name = "SHAUTH_SES_REGION", value = var.region }, { name = "SHAUTH_INVITATION_EMAIL_FROM", value = var.invitation_email_from }], secrets = [{ name = "DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.runtime.arn}:DATABASE_URL::" }, { name = "GITHUB_CLIENT_SECRET", valueFrom = var.github_oauth_secret_arn }, { name = "SHAUTH_BOOTSTRAP_ADMIN_PASSWORD", valueFrom = "${aws_secretsmanager_secret.runtime.arn}:SHAUTH_BOOTSTRAP_ADMIN_PASSWORD::" }], logConfiguration = { logDriver = "awslogs", options = { awslogs-group = aws_cloudwatch_log_group.this.name, awslogs-region = var.region, awslogs-stream-prefix = "shauth" } } }
  ])
  tags = local.tags
}

resource "aws_ecs_service" "this" {
  name            = var.name
  cluster         = var.ecs_cluster_arn
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = false
  }
  service_registries {
    registry_arn   = aws_service_discovery_service.this.arn
    container_name = "shauth"
    container_port = 8080
  }
  lifecycle { ignore_changes = [desired_count] }
  tags = local.tags
}

resource "aws_apigatewayv2_vpc_link" "this" {
  name               = var.name
  subnet_ids         = var.private_subnet_ids
  security_group_ids = [aws_security_group.api_link.id]
  tags               = local.tags
}
resource "aws_apigatewayv2_api" "this" {
  name                         = var.name
  protocol_type                = "HTTP"
  disable_execute_api_endpoint = true
  tags                         = local.tags
}
resource "aws_apigatewayv2_integration" "this" {
  api_id                 = aws_apigatewayv2_api.this.id
  integration_type       = "HTTP_PROXY"
  integration_uri        = aws_service_discovery_service.this.arn
  integration_method     = "ANY"
  connection_type        = "VPC_LINK"
  connection_id          = aws_apigatewayv2_vpc_link.this.id
  payload_format_version = "1.0"
}
resource "aws_apigatewayv2_route" "this" {
  api_id    = aws_apigatewayv2_api.this.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.this.id}"
}
resource "aws_apigatewayv2_stage" "this" {
  api_id      = aws_apigatewayv2_api.this.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_burst_limit = 50
    throttling_rate_limit  = 25
  }
  tags = local.tags
}

resource "aws_acm_certificate" "this" {
  domain_name       = var.domain_name
  validation_method = "DNS"
  tags              = local.tags
}
resource "aws_route53_record" "certificate" {
  for_each        = { for option in aws_acm_certificate.this.domain_validation_options : option.domain_name => option }
  zone_id         = var.hosted_zone_id
  name            = each.value.resource_record_name
  type            = each.value.resource_record_type
  records         = [each.value.resource_record_value]
  ttl             = 60
  allow_overwrite = true
}
resource "aws_acm_certificate_validation" "this" {
  certificate_arn         = aws_acm_certificate.this.arn
  validation_record_fqdns = [for record in aws_route53_record.certificate : record.fqdn]
}
resource "aws_apigatewayv2_domain_name" "this" {
  domain_name = var.domain_name
  domain_name_configuration {
    certificate_arn = aws_acm_certificate_validation.this.certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
}
resource "aws_apigatewayv2_api_mapping" "this" {
  api_id      = aws_apigatewayv2_api.this.id
  domain_name = aws_apigatewayv2_domain_name.this.id
  stage       = aws_apigatewayv2_stage.this.id
}
resource "aws_route53_record" "this" {
  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"
  alias {
    name                   = aws_apigatewayv2_domain_name.this.domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.this.domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}
