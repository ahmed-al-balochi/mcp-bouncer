# Security groups for the ALB, the private tasks and the VPC endpoints. Rules are
# standalone resources so two groups can reference each other without a cycle.

# --- ALB security group ----------------------------------------------------

resource "aws_security_group" "alb" {
  name_prefix = "${var.project_name}-alb-"
  description = "Public ALB: ingress from the operator allowlist only, egress to tasks only."
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${var.project_name}-alb" }

  lifecycle {
    create_before_destroy = true
  }
}

# 443 and 80 ingress from the operator-supplied allowlist only. 80 exists solely
# to 301-redirect to 443 (see alb.tf); no plaintext traffic is served.
resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  for_each = toset(local.allowed_cidrs)

  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from allowlisted source"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_ingress_rule" "alb_http_redirect" {
  for_each = toset(local.allowed_cidrs)

  security_group_id = aws_security_group.alb.id
  description       = "HTTP from allowlisted source (redirected to HTTPS)"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
}

# The ALB only ever forwards to the LiteLLM gateway; the gate is internal-only
# now. Scoped to the LiteLLM SG on its port, not the whole VPC and not the gate
# task SG (the from-ALB path to the gate is gone).
resource "aws_vpc_security_group_egress_rule" "alb_to_litellm" {
  security_group_id            = aws_security_group.alb.id
  description                  = "To the LiteLLM gateway on its container port"
  referenced_security_group_id = aws_security_group.litellm.id
  ip_protocol                  = "tcp"
  from_port                    = local.litellm_port
  to_port                      = local.litellm_port
}

# --- task security group ---------------------------------------------------

resource "aws_security_group" "task" {
  name_prefix = "${var.project_name}-task-"
  description = "Fargate tasks: ingress from ALB only, egress to VPC endpoints and AWS prefix lists only."
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${var.project_name}-task" }

  lifecycle {
    create_before_destroy = true
  }
}

# Only the LiteLLM gateway may reach the gate's container port: the gate is
# internal-only, reachable from the gateway and nowhere else. The from-ALB
# ingress is deliberately gone; the ALB has no path to the gate.
resource "aws_vpc_security_group_ingress_rule" "task_from_litellm" {
  security_group_id            = aws_security_group.task.id
  description                  = "From the LiteLLM gateway on the container port"
  referenced_security_group_id = aws_security_group.litellm.id
  ip_protocol                  = "tcp"
  from_port                    = local.container_port
  to_port                      = local.container_port
}

# Egress is 443 to the interface endpoints (ECR api/dkr, Logs, Secrets Manager)
# and 443 to the S3 and DynamoDB gateway endpoints via their managed prefix
# lists. No 0.0.0.0/0 egress: the task cannot reach anything but these services.
resource "aws_vpc_security_group_egress_rule" "task_to_endpoints" {
  security_group_id            = aws_security_group.task.id
  description                  = "To interface VPC endpoints (ECR, Logs, Secrets Manager)"
  referenced_security_group_id = aws_security_group.endpoints.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "task_to_s3" {
  security_group_id = aws_security_group.task.id
  description       = "To S3 gateway endpoint (ECR image layers) via its prefix list"
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "task_to_dynamodb" {
  security_group_id = aws_security_group.task.id
  description       = "To DynamoDB gateway endpoint via its prefix list"
  prefix_list_id    = aws_vpc_endpoint.dynamodb.prefix_list_id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# --- interface endpoint security group -------------------------------------

resource "aws_security_group" "endpoints" {
  name_prefix = "${var.project_name}-endpoints-"
  description = "Interface VPC endpoints: 443 from the task SG only."
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${var.project_name}-endpoints" }

  lifecycle {
    create_before_destroy = true
  }
}

# The endpoints accept 443 from the tasks and nothing else.
resource "aws_vpc_security_group_ingress_rule" "endpoints_from_tasks" {
  security_group_id            = aws_security_group.endpoints.id
  description                  = "HTTPS from tasks"
  referenced_security_group_id = aws_security_group.task.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

# LiteLLM also needs the endpoints on 443: ECR and Logs at boot, Secrets Manager
# for the master key, and bedrock-runtime for model calls.
resource "aws_vpc_security_group_ingress_rule" "endpoints_from_litellm" {
  security_group_id            = aws_security_group.endpoints.id
  description                  = "HTTPS from the LiteLLM gateway"
  referenced_security_group_id = aws_security_group.litellm.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

# --- LiteLLM gateway security group ----------------------------------------

# The gateway sits between the ALB and both the gate and Bedrock. Ingress: only
# the ALB on 4000. Egress: 443 to the interface endpoints, 443 to the S3 prefix
# list (image layers), and 8000 to the gate. No 0.0.0.0/0, so no internet path.

resource "aws_security_group" "litellm" {
  name_prefix = "${var.project_name}-litellm-"
  description = "LiteLLM gateway: ingress from ALB only, egress to endpoints, S3 layers and the gate only."
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${var.project_name}-litellm" }

  lifecycle {
    create_before_destroy = true
  }
}

# Only the ALB may reach the gateway, only on 4000.
resource "aws_vpc_security_group_ingress_rule" "litellm_from_alb" {
  security_group_id            = aws_security_group.litellm.id
  description                  = "From the ALB on the gateway port"
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = local.litellm_port
  to_port                      = local.litellm_port
}

# 443 to the interface endpoints (ECR api/dkr and Logs at boot, Secrets Manager
# for the master key, bedrock-runtime for model calls).
resource "aws_vpc_security_group_egress_rule" "litellm_to_endpoints" {
  security_group_id            = aws_security_group.litellm.id
  description                  = "To interface VPC endpoints (ECR, Logs, Secrets Manager, Bedrock)"
  referenced_security_group_id = aws_security_group.endpoints.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

# 443 to the S3 gateway endpoint for image layers, via its managed prefix list.
resource "aws_vpc_security_group_egress_rule" "litellm_to_s3" {
  security_group_id = aws_security_group.litellm.id
  description       = "To S3 gateway endpoint (image layers) via its prefix list"
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# 8000 to the gate: LiteLLM forwards MCP tool calls to the gate's container port.
resource "aws_vpc_security_group_egress_rule" "litellm_to_gate" {
  security_group_id            = aws_security_group.litellm.id
  description                  = "To the gate on its container port (MCP tool calls)"
  referenced_security_group_id = aws_security_group.task.id
  ip_protocol                  = "tcp"
  from_port                    = local.container_port
  to_port                      = local.container_port
}
