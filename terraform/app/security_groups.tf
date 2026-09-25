# Security groups for the three tiers: the public ALB, the private tasks, and
# the interface VPC endpoints. Rules are defined as standalone
# aws_vpc_security_group_*_rule resources rather than inline blocks so two groups
# can reference each other (ALB<->task, task<->endpoint) without a cycle: the
# groups are created first, then the rules that wire them together.

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

# 443 and 80 ingress from the operator-supplied allowlist ONLY (R37). 80 exists
# solely to 301-redirect to 443 (see alb.tf); no plaintext traffic is served.
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

# The ALB only ever forwards to the task container port; it needs no other
# egress. Scoped to the task SG, not the whole VPC.
resource "aws_vpc_security_group_egress_rule" "alb_to_tasks" {
  security_group_id            = aws_security_group.alb.id
  description                  = "To tasks on the container port"
  referenced_security_group_id = aws_security_group.task.id
  ip_protocol                  = "tcp"
  from_port                    = local.container_port
  to_port                      = local.container_port
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

# Only the ALB may reach the container port. No other ingress.
resource "aws_vpc_security_group_ingress_rule" "task_from_alb" {
  security_group_id            = aws_security_group.task.id
  description                  = "From the ALB on the container port"
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = local.container_port
  to_port                      = local.container_port
}

# Egress is 443 to the interface endpoints (ECR api/dkr, Logs, Secrets Manager)
# and 443 to the S3 and DynamoDB gateway endpoints via their managed prefix
# lists. There is no 0.0.0.0/0 egress: the task literally cannot reach anything
# but these AWS services (D4.4).
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
