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

  # Log stream creation and writes, scoped to this task's log group and the
  # Service Connect sidecar log group, plus their streams. The gate is now a
  # Service Connect SERVER (ecs.tf), so its task runs an Envoy sidecar whose
  # awslogs driver uses THIS execution role to create/write streams in the
  # serviceconnect group (ecs.tf log_configuration -> serviceconnect group).
  # awslogs stream creation is an execution-role action, and IAM intersects with
  # the Logs VPC-endpoint policy, so without this group the sidecar's log-stream
  # creation is denied and the gate task fails to start (R35/R57). Groups are
  # created in monitoring.tf.
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
      aws_cloudwatch_log_group.serviceconnect.arn,
      "${aws_cloudwatch_log_group.serviceconnect.arn}:*",
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

# --- LiteLLM roles (R38, R53, D6.10) ---------------------------------------
#
# Separate execution and task roles for the gateway, NOT shared with the gate,
# so each is scoped to only what the gateway needs.

# LiteLLM execution role: pull the litellm image, write the gateway and Service
# Connect log streams, and read the master-key secret at container start.
resource "aws_iam_role" "litellm_execution" {
  name               = "${var.project_name}-litellm-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json

  tags = { Name = "${var.project_name}-litellm-execution" }
}

data "aws_iam_policy_document" "litellm_execution" {
  # ECR pull scoped to the litellm repository ONLY (D6.10: the reason the two
  # images are separate repositories). GetAuthorizationToken is the one
  # unavoidable wildcard AWS will not let us scope.
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
    resources = [data.aws_ecr_repository.litellm.arn]
  }

  # Logs on the gateway's own log group and the Service Connect sidecar log
  # group (the execution role sets up log streams for both the app container and
  # the Envoy sidecar).
  statement {
    sid    = "LogsWrite"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      aws_cloudwatch_log_group.litellm.arn,
      "${aws_cloudwatch_log_group.litellm.arn}:*",
      aws_cloudwatch_log_group.serviceconnect.arn,
      "${aws_cloudwatch_log_group.serviceconnect.arn}:*",
    ]
  }

  # Read the master-key secret at container start (injected via the `secrets`
  # block). GetSecretValue on exactly that secret.
  statement {
    sid       = "MasterKeyRead"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.litellm_master_key.arn]
  }
}

resource "aws_iam_role_policy" "litellm_execution" {
  name   = "${var.project_name}-litellm-execution"
  role   = aws_iam_role.litellm_execution.id
  policy = data.aws_iam_policy_document.litellm_execution.json
}

# LiteLLM task role: Bedrock ONLY (R53). InvokeModel and
# InvokeModelWithResponseStream on (1) the EU inference profile ARN and (2) the
# foundation-model ARNs it routes to. The foundation-model statement is
# conditioned on bedrock:InferenceProfileArn = the profile ARN, so the role can
# reach those models only THROUGH the EU profile, never directly (this is A14's
# IAM layer). All ARNs come from the data source (main.tf), not typed.
resource "aws_iam_role" "litellm_task" {
  name               = "${var.project_name}-litellm-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json

  tags = { Name = "${var.project_name}-litellm-task" }
}

data "aws_iam_policy_document" "litellm_task" {
  # Invoke the inference profile itself.
  statement {
    sid    = "InvokeEuProfile"
    effect = "Allow"
    actions = [
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream",
    ]
    resources = [local.bedrock_profile_arn]
  }

  # Invoke the routed foundation models, but ONLY via the EU profile: the
  # condition ties every such call to the profile ARN, so the role cannot invoke
  # a foundation model directly or through any other profile.
  statement {
    sid    = "InvokeEuFoundationModelsViaProfile"
    effect = "Allow"
    actions = [
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream",
    ]
    resources = local.bedrock_model_arns

    condition {
      test     = "StringEquals"
      variable = "bedrock:InferenceProfileArn"
      values   = [local.bedrock_profile_arn]
    }
  }
}

resource "aws_iam_role_policy" "litellm_task" {
  name   = "${var.project_name}-litellm-task"
  role   = aws_iam_role.litellm_task.id
  policy = data.aws_iam_policy_document.litellm_task.json
}
