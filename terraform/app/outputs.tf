# Outputs an operator needs to use and tear down the stack. Nothing sensitive is
# in plain text: the tokens live only in the secret and in state, and are fetched
# with the emitted get-secret-value command, never printed here.

output "gateway_url" {
  description = "The public HTTPS base for the LiteLLM gateway (the only host the ALB serves)."
  value       = "https://${local.gateway_host}"
}

output "gateway_openai_base_url" {
  description = "OpenAI-compatible base URL for agents: point an OpenAI client's base_url here (it appends /chat/completions and /models, the only paths the ALB forwards)."
  value       = "https://${local.gateway_host}/v1"
}

output "alb_dns_name" {
  description = "The ALB's own DNS name, useful for debugging before the gateway record propagates. Note the ALB answers only the gateway host, so a request to this name returns 404."
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

output "litellm_log_group_name" {
  description = "CloudWatch log group carrying the LiteLLM gateway's JSON logs (prompts/responses not logged)."
  value       = aws_cloudwatch_log_group.litellm.name
}

output "litellm_master_key_get_command" {
  description = <<-EOT
    Fetch the generated LiteLLM master key from Secrets Manager. Run this rather
    than exposing the key as a Terraform output (it is LiteLLM's admin key); it
    is the Authorization: Bearer value an agent uses for model calls.
  EOT
  value       = "aws secretsmanager get-secret-value --region ${var.aws_region} --secret-id ${aws_secretsmanager_secret.litellm_master_key.arn} --query SecretString --output text"
}

output "agent_mcp_tool_shape" {
  description = <<-EOT
    Shape of the MCP tool block an agent sends to the gateway on
    /v1/chat/completions. The agent forwards its own gate token in the
    x-mcp-bouncer-authorization header; model calls use the master key.
  EOT
  value = {
    server_label = "bouncer"
    server_url   = "litellm_proxy/mcp/bouncer"
    header_name  = "x-mcp-bouncer-authorization"
    header_value = "Bearer <gate token>"
  }
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
    log` against the deployed DynamoDB store from a laptop. The operator's own
    AWS credentials must allow the DynamoDB actions on these tables.
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

output "dashboard_name" {
  description = "Name of the CloudWatch dashboard. The README derives it from this output rather than pasting a value."
  value       = aws_cloudwatch_dashboard.this.dashboard_name
}

output "dashboard_url" {
  description = <<-EOT
    Console URL for the CloudWatch dashboard, built from references (the region
    data source and the dashboard name) so no region or account literal is
    pasted. Open it after `terraform apply`.
  EOT
  value       = "https://${data.aws_region.current.region}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.region}#dashboards:name=${aws_cloudwatch_dashboard.this.dashboard_name}"
}
