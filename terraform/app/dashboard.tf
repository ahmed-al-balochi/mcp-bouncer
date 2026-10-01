# The single CloudWatch dashboard for the stack, plus the governance metric
# filters that back its per-team row. Everything it names is a Terraform
# reference, never a literal, so no account id, region, ARN or IP is written here.

# The governance metric filters live here, not in monitoring.tf, because they
# feed only this dashboard's governance row. monitoring.tf keeps the one alarm
# (fail_closed) and its filter untouched; this file reuses FailClosed by name.

# "no data" vs 0: CloudWatch creates a metric only once it is first emitted, so a
# widget on a metric that may never fire would read "no data"; each wraps its
# series in FILL(m, 0), the only way to make a quiet dimensioned metric read 0.

locals {
  # --- Service level targets ----------------------------------------------

  # These targets are illustrative for a demo workload, not a negotiated SLO. The
  # two latency targets are provisional placeholders until a baseline is measured.
  # Gathered here so the annotations and docs read from one source.
  sli_targets = {
    gateway_availability_pct  = 99.5 # illustrative
    gateway_latency_p95_s     = 30   # provisional; replace with measured baseline
    error_rate_pct            = 1    # illustrative
    model_latency_p95_s       = 15   # provisional; replace with measured baseline
    gate_fail_closed_rate_pct = 0    # illustrative (a fail-closed is always a fault)
  }

  # The region every metric widget is drawn in. data.aws_region.current.region
  # is a reference, so no region literal appears in this file.
  dashboard_region = data.aws_region.current.region

  # Dimension values, all derived from Terraform references so nothing is typed:
  # the gate/LiteLLM service names and cluster, the Service Connect discovery
  # name, and the ALB and target-group arn_suffix values ELB metrics key on.
  gate_service_name    = aws_ecs_service.this.name
  litellm_service_name = aws_ecs_service.litellm.name
  cluster_name         = aws_ecs_cluster.this.name

  # Service Connect discovery name == the gate's port_name, read from the gate
  # service itself (ecs.tf sets no explicit discovery_name). A reference, so
  # renaming the port cannot leave the dashboard querying a name that is gone.
  connect_discovery_name = tolist(aws_ecs_service.this.service_connect_configuration[0].service)[0].port_name

  alb_arn_suffix        = aws_lb.this.arn_suffix
  litellm_tg_arn_suffix = aws_lb_target_group.litellm.arn_suffix

  # The Bedrock ModelId dimension value is the inference profile id, referenced
  # from the variable, never the literal.
  bedrock_model_id = var.bedrock_inference_profile_id

  # The gate's custom-metric namespace, shared with the existing FailClosed
  # filter in monitoring.tf so the dashboard reads one namespace.
  gate_metric_namespace = "${var.project_name}/gate"

  # DynamoDB operations the store actually issues, from the least-privilege IAM
  # in iam.tf. SystemErrors is published only on the (TableName, Operation) pair,
  # never TableName alone, so a widget must name an operation.
  ddb_approvals_ops = ["GetItem", "PutItem", "Query", "DeleteItem"]
  ddb_audit_ops     = ["PutItem", "Query"]

  # The two table names, from the table resources.
  approvals_table = aws_dynamodb_table.approvals.name
  audit_table     = aws_dynamodb_table.audit.name

  # Teams whose governance metrics the dashboard separates, from the distinct
  # team values in var.callers. Keying on team keeps cardinality bounded; never
  # per-caller, tool or args_hash, which would be unbounded and leak detail.
  dashboard_teams = distinct(values(var.callers))
}

# --- Governance metric filters ---------------------------------------------

# These read the gate's JSON decision/fail_closed log lines and turn bounded
# fields into metrics, keyed on $.event with team as the only dimension; caller,
# tool and args_hash are never dimensions as they are unbounded and leak detail.

# decision lines, split by classification, dimensioned by team. One filter per
# classification value so the widget can stack them per team; classification is a
# bounded enum, so this is a fixed, small set of filters, not a cardinality risk.
resource "aws_cloudwatch_log_metric_filter" "decision_by_classification" {
  for_each = toset(["read", "write", "destructive", "unknown"])

  name           = "${var.project_name}-decision-${each.key}"
  log_group_name = aws_cloudwatch_log_group.task.name

  # $.event = decision AND $.classification = <this class>. team is pulled out as
  # a dimension below; a decision line always carries a (possibly-attributed)
  # team, so the dimension is populated for every matched line.
  pattern = "{ $.event = \"decision\" && $.classification = \"${each.key}\" }"

  metric_transformation {
    name      = "Decision_${each.key}"
    namespace = local.gate_metric_namespace
    value     = "1"
    # No default_value: this metric is dimensioned (team), and AWS forbids a
    # default_value on a dimensioned metric-filter metric. The widget FILLs 0.
    dimensions = {
      team = "$.team"
    }
  }
}

# decision lines split by OUTCOME (pass|approve|block), dimensioned by team.
# decision is a bounded enum, so again a fixed small filter count. "approve" is
# the parked-call outcome the governance row surfaces as "parks".
resource "aws_cloudwatch_log_metric_filter" "decision_by_outcome" {
  for_each = toset(["pass", "approve", "block"])

  name           = "${var.project_name}-outcome-${each.key}"
  log_group_name = aws_cloudwatch_log_group.task.name

  pattern = "{ $.event = \"decision\" && $.decision = \"${each.key}\" }"

  metric_transformation {
    name      = "Outcome_${each.key}"
    namespace = local.gate_metric_namespace
    value     = "1"
    dimensions = {
      team = "$.team"
    }
  }
}

# Unknown-tool denials, dimensioned by team. A decision line with
# classification=unknown is exactly the deny-by-default case. Kept as its own
# metric name so the widget can show it directly, not re-derive it.
resource "aws_cloudwatch_log_metric_filter" "unknown_denials" {
  name           = "${var.project_name}-unknown-denials"
  log_group_name = aws_cloudwatch_log_group.task.name

  pattern = "{ $.event = \"decision\" && $.classification = \"unknown\" }"

  metric_transformation {
    name      = "UnknownDenials"
    namespace = local.gate_metric_namespace
    value     = "1"
    dimensions = {
      team = "$.team"
    }
  }
}

# auth_rejected lines. tool is unbounded so it is not a dimension, and the line
# carries no team (identity failed), so this metric is undimensioned and can
# carry default_value = 0; the widget FILLs anyway for symmetry.
resource "aws_cloudwatch_log_metric_filter" "auth_rejected" {
  name           = "${var.project_name}-auth-rejected"
  log_group_name = aws_cloudwatch_log_group.task.name

  pattern = "{ $.event = \"auth_rejected\" }"

  metric_transformation {
    name          = "AuthRejected"
    namespace     = local.gate_metric_namespace
    value         = "1"
    default_value = "0"
  }
}

# fail_closed lines dimensioned by team. A team=null line (identity failed before
# the caller was known) does not populate the team dimension, so the dashboard
# also reads the undimensioned FailClosed total to show unattributed = total - sum.

# This is a separate metric name (FailClosedByTeam) from the existing FailClosed:
# that filter and its alarm in monitoring.tf are left unchanged; this adds the
# per-team view alongside.
resource "aws_cloudwatch_log_metric_filter" "fail_closed_by_team" {
  name           = "${var.project_name}-fail-closed-by-team"
  log_group_name = aws_cloudwatch_log_group.task.name

  pattern = "{ $.event = \"fail_closed\" }"

  metric_transformation {
    name      = "FailClosedByTeam"
    namespace = local.gate_metric_namespace
    value     = "1"
    dimensions = {
      team = "$.team"
    }
  }
}

# --- The dashboard ----------------------------------------------------------

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = var.project_name

  dashboard_body = jsonencode({
    widgets = concat(
      local.row_platform_health,
      local.row_gateway_traffic,
      local.row_model,
      local.row_governance,
      local.row_sli,
      local.row_absences_text,
    )
  })
}

