# VPC endpoints, all with RESOURCE-SCOPED policies (D4.5, owner decision).
#
# Without an endpoint policy, an endpoint accepts requests signed by ANY
# account's credentials, so a compromised container could exfiltrate to an
# attacker's own in-region bucket or table THROUGH our endpoints -- "no path
# out" would shrink to "only AWS services, any account". Each policy below pins
# the endpoint to exactly our resources (or, where AWS forbids scoping, to our
# account's principals), so the endpoint is a second enforcement layer that
# intersects with the IAM policies in iam.tf.
#
# Role scoping is expressed as `Principal "*"` plus an `aws:PrincipalArn`
# condition, NOT as the role ARN in `Principal`. The two scope identically: for
# an assumed-role session aws:PrincipalArn is the ROLE's ARN, and if the key is
# absent the Allow simply does not apply. The difference is WHEN it is checked.
# A role ARN in `Principal` is resolved when the endpoint is created, and a role
# created seconds earlier in the same apply may not have propagated yet -- the
# first apply of this stack failed all four interface endpoints with
# `InvalidPolicyDocument: UnknownError`, and an unchanged retry succeeded
# (DECISIONS D4.13). A condition value is only compared at request time, so the
# race cannot occur. The S3 policy is deliberately left without any principal
# condition (see below).
#
# Two gateway endpoints (S3, DynamoDB) attach to the private route table and add
# the only routes it carries. Four interface endpoints (ECR api/dkr, Logs,
# Secrets Manager) live in the private subnets with private DNS, guarded by the
# endpoint SG that admits 443 from the task SG only. No STS endpoint (the task
# needs no STS call at runtime); no NAT anywhere.

# --- S3 gateway endpoint (ECR image layers) --------------------------------

data "aws_iam_policy_document" "s3_endpoint" {
  # s3:GetObject on the AWS-owned ECR layer bucket ONLY. Principal "*" and NO
  # aws:PrincipalAccount / SourceAccount condition, on purpose: the AWS ECR
  # VPC-endpoint docs' own example uses Principal "*" with no account condition,
  # because image layers are believed to be fetched via presigned URLs that ECR
  # signs with its OWN service credentials -- the requesting principal is not in
  # our account, so an account condition would break the pull. (This is the
  # understood-but-not-yet-verified assumption from D4.5; confirm empirically in
  # phase 5.) Resource scoping alone still closes the exfil path: the only
  # reachable object store through this endpoint is an AWS-owned, read-only
  # bucket.
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
  # and only the task role may use them. The audit table gets its own statement
  # with PutItem and Query only, so append-only (R29) holds at the network layer
  # too, not just in IAM: even a principal with broader IAM rights could not
  # update or delete audit rows through this endpoint.
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

# --- bedrock-runtime interface endpoint (R53 layer 3, R57, D6.10) ----------
#
# The third EU-only layer: even the network path to Bedrock is resource-scoped
# to the EU profile ARN and the EU foundation-model ARNs it routes to, and to
# the LiteLLM task role as principal. So a request for any other model, or from
# any other principal, has no route out -- InvokeModel on a non-EU model is
# refused at the endpoint as well as in IAM (iam.tf) and at LiteLLM's model list
# (layer 1). The action/resource set matches the IAM policy exactly; the
# foundation-model resources sit in the same statement as the profile because a
# VPC endpoint policy has no bedrock:InferenceProfileArn analogue to condition
# on -- the IAM layer carries that constraint, and the endpoint simply bounds the
# reachable ARNs to the EU set.
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
