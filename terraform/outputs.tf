output "url" { value = "https://${var.domain_name}" }
output "runtime_secret_arn" { value = aws_secretsmanager_secret.runtime.arn }
output "database_endpoint" { value = aws_db_instance.this.address }
