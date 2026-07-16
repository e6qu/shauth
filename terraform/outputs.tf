output "url" { value = "https://${var.domain_name}" }
output "runtime_secret_arn" { value = aws_secretsmanager_secret.runtime.arn }
output "service_security_group_id" { value = aws_security_group.task.id }
