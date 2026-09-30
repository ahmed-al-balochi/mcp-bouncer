# The single CloudWatch dashboard for the stack (R58-R61, A17), plus the
# governance metric filters that back its per-team row. Everything the dashboard
# names -- service names, cluster, table names, ARNs, dimensions, the region --
# is a Terraform reference, never a literal (R2, R3, R39). There is no account
# id, region string, domain, ARN or IP written anywhere in this file.
#
# WHY the governance metric filters live here and not in monitoring.tf: they
# exist ONLY to feed this dashboard's governance row, and reading them next to
# the widgets that consume them keeps the decision-log -> metric -> widget chain
# in one place. monitoring.tf owns the ONE operational alarm (fail_closed) and
# its filter; those stay there, untouched. The existing
# aws_cloudwatch_log_metric_filter.fail_closed (metric FailClosed) is NOT
# duplicated or altered here -- this file adds new, differently-named filters and
# the dashboard reuses the existing FailClosed metric by name for the total.
#
# A NOTE ON "no data" vs 0 (A17): CloudWatch only creates a metric once it is
# first emitted, so any widget on a metric that may never fire in a healthy
# stack (5xx, server errors, throttles, a team that sent no traffic yet) would
# read "no data" rather than 0. Every such widget below wraps its series in
# metric math FILL(m, 0) so a healthy stack shows a flat 0 line, not a blank.
# Dimensioned metric-filter metrics additionally CANNOT carry a filter
# default_value (AWS: "If you assign dimensions to metrics that metric filters
# generate, you can't specify default values for those metrics" --
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntaxForMetricFilters.html),
# so FILL in the widget is the ONLY way to make a quiet team read 0; the total
# FailClosed filter (no dimensions, in monitoring.tf) keeps its default_value = 0.

locals {
  # --- Service level targets (R59) ----------------------------------------
  #
  # These targets are ILLUSTRATIVE for a demo workload, not a negotiated SLO.
  # The two latency targets are PROVISIONAL: no baseline has been measured yet,
  # so they are placeholders to be replaced by a measured baseline from the live
  # run. They are gathered here so a widget's annotation and the docs read from
  # one source rather than repeating a number.
  sli_targets = {
    gateway_availability_pct  = 99.5 # illustrative
    gateway_latency_p95_s     = 30   # PROVISIONAL -- replace with measured baseline
    error_rate_pct            = 1    # illustrative
    model_latency_p95_s       = 15   # PROVISIONAL -- replace with measured baseline
    gate_fail_closed_rate_pct = 0    # illustrative (a fail-closed is always a fault)
  }

  # The region every metric widget is drawn in. data.aws_region.current.region
  # is the provider 6.x attribute (the deprecated .name is gone); it is a
  # reference, so no region literal appears in this file (R2, R3).
  dashboard_region = data.aws_region.current.region

  # Dimension values, all derived from Terraform references so nothing is typed:
  #   - the gate/LiteLLM ECS service names and the cluster name;
  #   - the Service Connect discovery name, which defaults to the port_name in
  #     ecs.tf's service_connect_configuration ("gate") since no explicit
  #     discovery_name is set -- read from the gate service's own
  #     service_connect_configuration, not a literal;
  #   - the ALB and target-group arn_suffix values CloudWatch keys ELB metrics on.
  gate_service_name    = aws_ecs_service.this.name
  litellm_service_name = aws_ecs_service.litellm.name
  cluster_name         = aws_ecs_cluster.this.name

  # Service Connect discovery name == the gate's port_name, read from the gate
  # service itself (ecs.tf sets no explicit discovery_name, so it defaults to the
  # port name). A reference, so renaming the port in ecs.tf cannot leave the
  # dashboard querying a discovery name that no longer exists.
  connect_discovery_name = tolist(aws_ecs_service.this.service_connect_configuration[0].service)[0].port_name

  alb_arn_suffix        = aws_lb.this.arn_suffix
  litellm_tg_arn_suffix = aws_lb_target_group.litellm.arn_suffix

  # The Bedrock ModelId dimension value IS the inference profile id. Referenced
  # from the variable, never the literal (facts, R2).
  bedrock_model_id = var.bedrock_inference_profile_id

  # The gate's custom-metric namespace, shared with the existing FailClosed
  # filter in monitoring.tf so the dashboard reads one namespace.
  gate_metric_namespace = "${var.project_name}/gate"

  # DynamoDB operations the store actually issues, from the least-privilege IAM
  # in iam.tf (GetItem/PutItem/Query/DeleteItem on approvals; PutItem/Query on
  # audit). SuccessfulRequestLatency and SystemErrors are published ONLY on the
  # (TableName, Operation) dimension pair -- never TableName alone -- so a widget
  # must name an operation
  # (https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html).
  # These are the operations that will have data on a working stack.
  ddb_approvals_ops = ["GetItem", "PutItem", "Query", "DeleteItem"]
  ddb_audit_ops     = ["PutItem", "Query"]

  # The two table names, from the table resources.
  approvals_table = aws_dynamodb_table.approvals.name
  audit_table     = aws_dynamodb_table.audit.name

  # Teams whose governance metrics the dashboard separates. Bounded by
  # policy.yaml (R60): the callers variable maps caller => team, and every team
  # named there must exist in policy.yaml or the gate refuses to boot. Taking the
  # distinct set of team VALUES keeps dimension cardinality bounded to the number
  # of teams (two by default) -- never per-caller, per-tool or per-args_hash,
  # which would be unbounded and would leak identity/argument detail (R33, R60).
  dashboard_teams = distinct(values(var.callers))
}

# --- Governance metric filters (R58 governance row, R59 fail-closed rate) ---
#
# These read the gate's JSON decision/fail_closed log lines (log group
# aws_cloudwatch_log_group.task) and turn bounded fields into metrics. They key
# off $.event exactly as the existing fail_closed filter does, and use ONLY
# team (bounded by policy.yaml) as a dimension. caller, tool and args_hash are
# NEVER dimensions: they are unbounded and would both explode custom-metric
# cardinality and surface identity/argument detail the dashboard must not show
# (R33, R60). A dimensioned metric-filter metric cannot carry a default_value
# (AWS docs, cited above), so these have none and the widgets FILL(...,0).

# decision lines, split by classification, dimensioned by team. One filter per
# classification value so the widget can stack read/write/destructive/unknown
# per team. classification is a bounded enum (read|write|destructive|unknown),
# so this is a fixed, small number of filters, not a cardinality risk.
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
# classification=unknown is exactly the deny-by-default case (R8). Kept as its
# own metric name so the governance widget can show it directly rather than
# re-deriving it from the classification split.
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

# auth_rejected lines. reason is a bounded shape (missing header / unknown
# token), tool is unbounded so it is NOT a dimension. The auth_rejected line
# carries no team (identity failed), so this metric is UNDIMENSIONED and can
# carry a default_value = 0 -- a healthy stack then reads a flat 0 without needing
# FILL, though the widget FILLs anyway for symmetry.
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

# fail_closed lines dimensioned BY TEAM (R59 per-team fail-closed rate). The
# fail_closed line carries team=null when identity failed before the caller was
# known; such a line does NOT populate the team dimension (AWS: a dimension "will
# only be published for a metric if the value is found in the log event" --
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-logs-metricfilter-dimension.html),
# so a null-team fail-closed is NOT counted by this per-team metric. That is why
# the dashboard also reads the existing UNdimensioned FailClosed total
# (monitoring.tf) and computes `unattributed = total - sum(per-team)` via metric
# math, so a null-team block is still visible rather than silently dropped.
#
# This is a SEPARATE metric name (FailClosedByTeam) from the existing FailClosed:
# the existing filter and its alarm in monitoring.tf are left exactly as they
# are (R: keep them unchanged); this adds the per-team view alongside.
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

