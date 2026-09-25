# Outputs an operator needs to use and tear down the stack. Nothing sensitive in
# plain text: the tokens live only in the secret and in state, and are fetched
# with the emitted get-secret-value command, never printed here (R19).

output "service_url" {
  description = "The MCP endpoint. Point an MCP client with a bearer token here."
  value       = "https://${local.service_host}/mcp/"
}

output "health_url" {
  description = "Unauthenticated ALB health endpoint. A 200 means the task is serving."
  value       = "https://${local.service_host}/health"
}

output "alb_dns_name" {
  description = "The ALB's own DNS name, useful for debugging before the apex record propagates."
  value       = aws_lb.this.dns_name
}

output "approvals_table_name" {
  description = "DynamoDB approvals table name."
  value       = aws_dynamodb_table.approvals.name
}

output "audit_table_name" {
  description = "DynamoDB audit table name."
  value       = aws_dynamodb_table.audit.name
}

output "log_group_name" {
  description = "CloudWatch log group carrying the gate's JSON logs and the fail_closed signal."
  value       = aws_cloudwatch_log_group.task.name
}

output "tokens_secret_arn" {
  description = "ARN of the bearer-token secret. An identifier, not a credential; fetch the values with tokens_get_command."
  value       = aws_secretsmanager_secret.tokens.arn
}

output "tokens_get_command" {
  description = <<-EOT
    Fetch the generated bearer tokens (token -> caller/team map) from Secrets
    Manager. Run this rather than exposing the tokens as a Terraform output.
  EOT
  value       = "aws secretsmanager get-secret-value --region ${var.aws_region} --secret-id ${aws_secretsmanager_secret.tokens.arn} --query SecretString --output text"
}

output "operator_cli_env" {
  description = <<-EOT
    Export these before running `bouncer approve` / `bouncer list` / `bouncer
    log` against the deployed DynamoDB store from a laptop (R32). The operator's
    own AWS credentials must allow the DynamoDB actions on these tables.
  EOT
  value = join(" ", [
    "BOUNCER_STORE=dynamodb",
    "BOUNCER_DYNAMODB_TABLE=${aws_dynamodb_table.approvals.name}",
    "BOUNCER_DYNAMODB_AUDIT_TABLE=${aws_dynamodb_table.audit.name}",
    "AWS_REGION=${var.aws_region}",
    "AWS_DEFAULT_REGION=${var.aws_region}",
  ])
}

output "allowed_cidrs_effective" {
  description = "The source CIDRs actually allowed to reach the ALB (the discovered /32 when allowed_cidrs was left null)."
  value       = local.allowed_cidrs
}

output "cluster_name" {
  description = "ECS cluster name, for `aws ecs` debugging."
  value       = aws_ecs_cluster.this.name
}
