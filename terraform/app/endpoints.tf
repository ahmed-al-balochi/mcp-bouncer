# VPC endpoints, all with resource-scoped policies. Without a policy an endpoint
# accepts any account's credentials, so a compromised container could exfiltrate
# through it; each policy pins the endpoint to our resources or principals.

# Roles are scoped with `Principal "*"` plus an `aws:PrincipalArn` condition. A
# role ARN in `Principal` is resolved when the endpoint is created and may not
# exist yet, which failed all four interface endpoints on the first apply.

# Two gateway endpoints (S3, DynamoDB) attach to the private route table. Four
# interface endpoints (ECR api/dkr, Logs, Secrets Manager) live in the private
# subnets with private DNS, admitting 443 from the task SG only. No NAT anywhere.

# --- S3 gateway endpoint (ECR image layers) --------------------------------

data "aws_iam_policy_document" "s3_endpoint" {
  # s3:GetObject on the AWS-owned ECR layer bucket only. Principal "*" with no
  # account condition, because ECR fetches layers via presigned URLs signed with
  # its own credentials; resource scoping still limits reach to that one bucket.
  statement {
    sid       = "AllowEcrLayerPull"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = [local.ecr_layer_bucket_arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  policy            = data.aws_iam_policy_document.s3_endpoint.json

  tags = { Name = "${var.project_name}-s3" }
}

# --- DynamoDB gateway endpoint ---------------------------------------------

data "aws_iam_policy_document" "dynamodb_endpoint" {
  # The task role's exact DynamoDB actions, statement for statement with iam.tf,
  # and only the task role may use them. The audit table's statement has PutItem
  # and Query only, so append-only holds at the network layer too, not just IAM.
  statement {
    sid    = "TaskRoleApprovals"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query",
    ]
    resources = [
      aws_dynamodb_table.approvals.arn,
      "${aws_dynamodb_table.approvals.arn}/index/GSI1",
      "${aws_dynamodb_table.approvals.arn}/index/GSI2",
    ]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.task.arn]
    }
  }

  statement {
    sid       = "TaskRoleAuditAppendOnly"
    effect    = "Allow"
    actions   = ["dynamodb:PutItem", "dynamodb:Query"]
    resources = [aws_dynamodb_table.audit.arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.task.arn]
    }
  }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  policy            = data.aws_iam_policy_document.dynamodb_endpoint.json

  tags = { Name = "${var.project_name}-dynamodb" }
}

# --- interface endpoints ---------------------------------------------------

# ECR api + dkr and Logs are used by the EXECUTION role (image pull, log stream
# setup). GetAuthorizationToken cannot be resource-scoped (AWS design), so it is
# Resource "*" but still bounded to our execution role as principal.
data "aws_iam_policy_document" "ecr_endpoint" {
  statement {
    sid       = "EcrAuthToken"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.execution.arn, aws_iam_role.litellm_execution.arn]
    }
  }

  statement {
    sid    = "EcrPull"
    effect = "Allow"
    actions = [
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchCheckLayerAvailability",
    ]
    # Each execution role pulls only its own repository; both repositories are
    # listed here and IAM (iam.tf) restricts each role to one, so the endpoint
    # policy and IAM intersect to the correct pairing.
    resources = [data.aws_ecr_repository.this.arn, data.aws_ecr_repository.litellm.arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.execution.arn, aws_iam_role.litellm_execution.arn]
    }
  }
}

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for s in aws_subnet.private : s.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  policy              = data.aws_iam_policy_document.ecr_endpoint.json

  tags = { Name = "${var.project_name}-ecr-api" }
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for s in aws_subnet.private : s.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  policy              = data.aws_iam_policy_document.ecr_endpoint.json

  tags = { Name = "${var.project_name}-ecr-dkr" }
}

# Logs: CreateLogStream/PutLogEvents on the gate, LiteLLM and Service Connect log
# groups and their streams, both execution roles only.
data "aws_iam_policy_document" "logs_endpoint" {
  statement {
    sid    = "LogsWrite"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      aws_cloudwatch_log_group.task.arn,
      "${aws_cloudwatch_log_group.task.arn}:*",
      aws_cloudwatch_log_group.litellm.arn,
      "${aws_cloudwatch_log_group.litellm.arn}:*",
      aws_cloudwatch_log_group.serviceconnect.arn,
      "${aws_cloudwatch_log_group.serviceconnect.arn}:*",
    ]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.execution.arn, aws_iam_role.litellm_execution.arn]
    }
  }
}

resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for s in aws_subnet.private : s.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  policy              = data.aws_iam_policy_document.logs_endpoint.json

  tags = { Name = "${var.project_name}-logs" }
}

# Secrets Manager: GetSecretValue on exactly the token secret (gate task role)
# and exactly the master-key secret (LiteLLM execution role). Two statements so
# each principal reaches only its own secret; the gate's statement is unchanged.
data "aws_iam_policy_document" "secretsmanager_endpoint" {
  statement {
    sid       = "TokenSecretRead"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.tokens.arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.task.arn]
    }
  }

  statement {
    sid       = "MasterKeyRead"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.litellm_master_key.arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.litellm_execution.arn]
    }
  }
}

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for s in aws_subnet.private : s.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  policy              = data.aws_iam_policy_document.secretsmanager_endpoint.json

  tags = { Name = "${var.project_name}-secretsmanager" }
}

# --- bedrock-runtime interface endpoint ------------------------------------

# The third EU-only layer: the network path to Bedrock is scoped to the EU
# profile ARN, the EU model ARNs it routes to, and the LiteLLM task role, so any
# other model or principal has no route out. IAM carries the profile condition.
data "aws_iam_policy_document" "bedrock_endpoint" {
  statement {
    sid    = "InvokeEuModelsOnly"
    effect = "Allow"
    actions = [
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream",
    ]
    resources = concat([local.bedrock_profile_arn], local.bedrock_model_arns)

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.litellm_task.arn]
    }
  }
}

resource "aws_vpc_endpoint" "bedrock_runtime" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.aws_region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for s in aws_subnet.private : s.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  policy              = data.aws_iam_policy_document.bedrock_endpoint.json

  tags = { Name = "${var.project_name}-bedrock-runtime" }
}
