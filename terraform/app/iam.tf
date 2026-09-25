# Least-privilege IAM (R38). Two roles, each with exactly the actions it uses on
# exactly its own resources. No wildcards on resources anywhere, with the one
# documented exception AWS itself requires (ecr:GetAuthorizationToken cannot be
# resource-scoped).
#
# These roles reference only resource ARNs (tables, secret, repository, log
# group). They deliberately do NOT reference the VPC endpoints, so there is no
# dependency cycle: the endpoint policies reference the role ARNs (one
# direction), never the reverse.

# Both roles are assumed by ECS tasks. The SourceAccount condition prevents the
# confused-deputy case where another account's ECS service could assume the role
# through the shared ecs-tasks service principal.
data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# --- execution role: pulls the image and writes the log stream -------------
#
# Deliberately NOT the AWS-managed AmazonECSTaskExecutionRolePolicy: that policy
# grants ecr:* and logs actions on Resource "*", which R38 forbids. Instead an
# inline policy scoped to exactly this repository and this log group.

resource "aws_iam_role" "execution" {
  name               = "${var.project_name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json

  tags = { Name = "${var.project_name}-execution" }
}

data "aws_iam_policy_document" "execution" {
  # ECR image pull, scoped to this repository. GetAuthorizationToken is the sole
  # documented wildcard: AWS scopes it to the whole registry and rejects a
  # resource-qualified ARN, so it MUST be Resource "*". Every other ECR action
  # is pinned to the repository ARN.
  statement {
    sid       = "EcrAuthToken"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "EcrPull"
    effect = "Allow"
    actions = [
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchCheckLayerAvailability",
    ]
    resources = [data.aws_ecr_repository.this.arn]
  }

  # Log stream creation and writes, scoped to this task's log group and its
  # streams. The group itself is created in monitoring.tf.
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
    ]
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "${var.project_name}-execution"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}

# --- task role: the application's own runtime permissions ------------------
#
# Exactly the DynamoDB actions the store issues on exactly its two tables (and
# the approvals table's two GSIs), and GetSecretValue on exactly the token
# secret. No Scan, no BatchGetItem; no Update/Delete on the audit table so
# append-only is enforced by IAM as well as structurally (R29).

resource "aws_iam_role" "task" {
  name               = "${var.project_name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json

  tags = { Name = "${var.project_name}-task" }
}

data "aws_iam_policy_document" "task" {
  # Approvals table: the store's full read/write set, plus Query on the table
  # and both GSI ARNs. Omitting the index ARNs breaks list_pending, expire,
  # create-time dedup and approve (NOTES).
  statement {
    sid    = "ApprovalsTable"
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
  }

  # Audit table: PutItem and Query ONLY. Deliberately no UpdateItem or
  # DeleteItem -- append-only enforced by IAM (R29). No GSI, so no index ARN.
  statement {
    sid    = "AuditTableAppendOnly"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:Query",
    ]
    resources = [aws_dynamodb_table.audit.arn]
  }

  # The token secret: GetSecretValue only, on exactly this secret. Only
  # get_secret_value is called (NOTES). No kms:Decrypt because the secret uses
  # the AWS-managed key.
  statement {
    sid       = "TokenSecretRead"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.tokens.arn]
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "${var.project_name}-task"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}
