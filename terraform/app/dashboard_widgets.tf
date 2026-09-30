# The dashboard's widget rows, assembled as locals so dashboard.tf's body stays
# readable and each row is documented where it is built. Every metric array uses
# Terraform references for names/dimensions (R2, R3, R39); metrics that may never
# fire on a healthy stack are wrapped in FILL(m, 0) so the row shows 0, not "no
# data" (A17). Region on every widget is local.dashboard_region (the provider
# 6.x data.aws_region.current.region attribute), never a literal.
#
# Grid: CloudWatch lays widgets on a 24-column grid. Each row here sets y so the
# rows stack top to bottom; widths sum to <= 24 per row.

locals {
  _r = local.dashboard_region

  # ======================================================================
  # ROW A -- Platform health (R58a)
  # Both ECS services (CPU/memory/LiveTaskCount), the ALB healthy host count for
  # the LiteLLM target group, the Service Connect gate hop, and both DynamoDB
  # tables. LiveTaskCount, healthy-host and the 5xx series can read "no data" on
  # a quiet/healthy stack, so each is FILLed to 0.
  # ======================================================================
  row_platform_health = [
    {
      type   = "text"
      x      = 0
      y      = 0
      width  = 24
      height = 1
      properties = {
        markdown = "## Platform health — both Fargate services, the load balancer, the Service Connect gate hop, and both DynamoDB tables. Model-call indicators are platform-wide (shared master key, no per-agent identity); governance is per team below."
      }
    },
    # ECS CPU/Memory for gate and LiteLLM. These always have data once a task
    # runs; no FILL needed, but LiveTaskCount (next widget) is FILLed.
    {
      type   = "metric"
      x      = 0
      y      = 1
      width  = 8
      height = 6
      properties = {
        title  = "ECS CPU % (avg) — gate vs LiteLLM"
        region = local._r
        view   = "timeSeries"
        stat   = "Average"
        metrics = [
          ["AWS/ECS", "CPUUtilization", "ClusterName", local.cluster_name, "ServiceName", local.gate_service_name, { label = "gate" }],
          ["AWS/ECS", "CPUUtilization", "ClusterName", local.cluster_name, "ServiceName", local.litellm_service_name, { label = "litellm" }],
        ]
      }
    },
    {
      type   = "metric"
      x      = 8
      y      = 1
      width  = 8
      height = 6
      properties = {
        title  = "ECS Memory % (avg) — gate vs LiteLLM"
        region = local._r
        view   = "timeSeries"
        stat   = "Average"
        metrics = [
          ["AWS/ECS", "MemoryUtilization", "ClusterName", local.cluster_name, "ServiceName", local.gate_service_name, { label = "gate" }],
          ["AWS/ECS", "MemoryUtilization", "ClusterName", local.cluster_name, "ServiceName", local.litellm_service_name, { label = "litellm" }],
        ]
      }
    },
    # LiveTaskCount: FILLed because a stopped/scaled-to-zero service reports no
    # data rather than 0, and A17 wants a number.
    {
      type   = "metric"
      x      = 16
      y      = 1
      width  = 8
      height = 6
      properties = {
        title  = "ECS running tasks — gate vs LiteLLM"
        region = local._r
        view   = "timeSeries"
        metrics = [
          [{ expression = "FILL(mg, 0)", label = "gate tasks", id = "eg" }],
          [{ expression = "FILL(ml, 0)", label = "litellm tasks", id = "el" }],
          ["AWS/ECS", "LiveTaskCount", "ClusterName", local.cluster_name, "ServiceName", local.gate_service_name, { id = "mg", stat = "Average", visible = false }],
          ["AWS/ECS", "LiveTaskCount", "ClusterName", local.cluster_name, "ServiceName", local.litellm_service_name, { id = "ml", stat = "Average", visible = false }],
        ]
      }
    },
    # ALB healthy host count for the LiteLLM target group (the gate has no target
    # group). FILLed: before the first health check reports, the metric is absent.
    {
      type   = "metric"
      x      = 0
      y      = 7
      width  = 8
      height = 6
      properties = {
        title  = "ALB healthy hosts — LiteLLM target group"
        region = local._r
        view   = "timeSeries"
        metrics = [
          [{ expression = "FILL(mh, 0)", label = "healthy hosts", id = "eh" }],
          ["AWS/ApplicationELB", "HealthyHostCount", "LoadBalancer", local.alb_arn_suffix, "TargetGroup", local.litellm_tg_arn_suffix, { id = "mh", stat = "Average", visible = false }],
        ]
      }
    },
    # Service Connect gate hop: requests, p95 response time, and 2xx/4xx/5xx.
    #
    # DIMENSIONS -- verified against the AWS/ECS metric table
    # (https://docs.aws.amazon.com/AmazonECS/latest/developerguide/available-metrics.html),
    # NOT guessed. Service Connect publishes two distinct dimension families:
    #   - INBOUND (server-side) metrics -- RequestCount, ActiveConnectionCount,
    #     NewConnectionCount -- on `DiscoveryName` OR
    #     `DiscoveryName, ServiceName, ClusterName`, where ServiceName is the
    #     SERVER service. The gate is the server, so (DiscoveryName=gate,
    #     ServiceName=gate, ClusterName) is a published set -> RequestCount below.
    #   - TARGET-attributed metrics -- HTTPCode_Target_2XX/4XX/5XX_Count,
    #     TargetResponseTime, RequestCountPerTarget -- on `TargetDiscoveryName`
    #     OR `TargetDiscoveryName, ServiceName, ClusterName`, where ServiceName
    #     is the CALLING (client) service, i.e. litellm, NOT the gate.
    # The earlier (ClusterName, ServiceName=gate, TargetDiscoveryName) set the
    # target metrics used is NOT a documented set (it pairs a target metric with
    # the server's ServiceName), so it would match no metric and render "no
    # data" -- and FILL() cannot rescue a series that matches nothing (A17). We
    # therefore query the target metrics on `TargetDiscoveryName` ALONE (the
    # single-dimension published set): it aggregates target responses across all
    # callers of the `gate` discovery name, which is exactly the gate hop, and
    # does not depend on which client ServiceName CloudWatch stamps for a
    # client-only Service Connect config (gateway.tf: litellm is client-only).
    # The discovery-name value is `gate`, derived from the port_name, not typed.
    # 4xx/5xx are FILLed (may never fire).
    {
      type   = "metric"
      x      = 8
      y      = 7
      width  = 8
      height = 6
      properties = {
        title  = "Service Connect gate hop — requests & p95 response time"
        region = local._r
        view   = "timeSeries"
        metrics = [
          ["AWS/ECS", "RequestCount", "ClusterName", local.cluster_name, "DiscoveryName", local.connect_discovery_name, "ServiceName", local.gate_service_name, { stat = "Sum", label = "requests" }],
          ["AWS/ECS", "TargetResponseTime", "TargetDiscoveryName", local.connect_discovery_name, { stat = "p95", label = "p95 response time (ms)", yAxis = "right" }],
        ]
      }
    },
    {
      type   = "metric"
      x      = 16
      y      = 7
      width  = 8
      height = 6
      properties = {
        title  = "Service Connect gate hop — response codes (2xx/4xx/5xx)"
        region = local._r
        view   = "timeSeries"
        metrics = [
          [{ expression = "FILL(m2, 0)", label = "2xx", id = "e2" }],
          [{ expression = "FILL(m4, 0)", label = "4xx", id = "e4" }],
          [{ expression = "FILL(m5, 0)", label = "5xx", id = "e5" }],
          ["AWS/ECS", "HTTPCode_Target_2XX_Count", "TargetDiscoveryName", local.connect_discovery_name, { id = "m2", stat = "Sum", visible = false }],
          ["AWS/ECS", "HTTPCode_Target_4XX_Count", "TargetDiscoveryName", local.connect_discovery_name, { id = "m4", stat = "Sum", visible = false }],
          ["AWS/ECS", "HTTPCode_Target_5XX_Count", "TargetDiscoveryName", local.connect_discovery_name, { id = "m5", stat = "Sum", visible = false }],
        ]
      }
    },
    # DynamoDB, both tables. SuccessfulRequestLatency and SystemErrors are
    # published only on (TableName, Operation) -- never TableName alone -- so each
    # names the operations the store issues (iam.tf least-privilege). SystemErrors
    # and ThrottledRequests may never fire, so FILLed.
    # https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html
    {
      type   = "metric"
      x      = 0
      y      = 13
      width  = 12
      height = 6
      properties = {
        title  = "DynamoDB SuccessfulRequestLatency p95 (ms) — approvals & audit, by operation"
        region = local._r
        view   = "timeSeries"
        stat   = "p95"
        metrics = concat(
          [for op in local.ddb_approvals_ops :
            ["AWS/DynamoDB", "SuccessfulRequestLatency", "TableName", local.approvals_table, "Operation", op, { label = "approvals ${op}" }]
          ],
          [for op in local.ddb_audit_ops :
            ["AWS/DynamoDB", "SuccessfulRequestLatency", "TableName", local.audit_table, "Operation", op, { label = "audit ${op}" }]
          ],
        )
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 13
      width  = 12
      height = 6
      properties = {
        title  = "DynamoDB throttles & system errors — both tables (0 when healthy)"
        region = local._r
        view   = "timeSeries"
        metrics = [
          # ThrottledRequests is published on TableName; SystemErrors needs
          # (TableName, Operation). All FILLed to 0 so a healthy stack is a flat
          # line, not "no data".
          [{ expression = "FILL(ta, 0)", label = "approvals throttled", id = "eta" }],
          [{ expression = "FILL(tb, 0)", label = "audit throttled", id = "etb" }],
          [{ expression = "FILL(sa, 0)", label = "approvals 5xx (GetItem)", id = "esa" }],
          [{ expression = "FILL(sb, 0)", label = "audit 5xx (PutItem)", id = "esb" }],
          ["AWS/DynamoDB", "ThrottledRequests", "TableName", local.approvals_table, { id = "ta", stat = "Sum", visible = false }],
          ["AWS/DynamoDB", "ThrottledRequests", "TableName", local.audit_table, { id = "tb", stat = "Sum", visible = false }],
          ["AWS/DynamoDB", "SystemErrors", "TableName", local.approvals_table, "Operation", "GetItem", { id = "sa", stat = "Sum", visible = false }],
          ["AWS/DynamoDB", "SystemErrors", "TableName", local.audit_table, "Operation", "PutItem", { id = "sb", stat = "Sum", visible = false }],
        ]
      }
    },
  ]

  # ======================================================================
  # ROW B -- Gateway traffic (R58b)
  # ALB RequestCount, TargetResponseTime p50/p95, and the 4xx/5xx split into
  # ELB-generated vs target-generated. All error series FILLed to 0.
  # ======================================================================
  row_gateway_traffic = [
    {
      type   = "text"
      x      = 0
      y      = 19
      width  = 24
      height = 1
      properties = {
        markdown = "## Gateway traffic — the public ALB in front of LiteLLM. 4xx/5xx are split ELB-generated vs target-generated so a gateway fault is distinguishable from an upstream one."
      }
    },
    {
      type   = "metric"
      x      = 0
      y      = 20
      width  = 8
      height = 6
      properties = {
        title  = "ALB request count"
        region = local._r
        view   = "timeSeries"
        metrics = [
          [{ expression = "FILL(mrc, 0)", label = "requests", id = "erc" }],
          ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", local.alb_arn_suffix, { id = "mrc", stat = "Sum", visible = false }],
        ]
      }
    },
    {
      type   = "metric"
      x      = 8
      y      = 20
      width  = 8
      height = 6
      properties = {
        title  = "ALB target response time — p50 / p95 (s)"
        region = local._r
        view   = "timeSeries"
        metrics = [
          ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", local.alb_arn_suffix, "TargetGroup", local.litellm_tg_arn_suffix, { stat = "p50", label = "p50" }],
          ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", local.alb_arn_suffix, "TargetGroup", local.litellm_tg_arn_suffix, { stat = "p95", label = "p95" }],
        ]
      }
    },
    {
      type   = "metric"
      x      = 16
      y      = 20
      width  = 8
      height = 6
      properties = {
        title  = "ALB 4xx/5xx — ELB-generated vs target-generated (0 when healthy)"
        region = local._r
        view   = "timeSeries"
        metrics = [
          [{ expression = "FILL(elb4, 0)", label = "ELB 4xx", id = "eelb4" }],
          [{ expression = "FILL(elb5, 0)", label = "ELB 5xx", id = "eelb5" }],
          [{ expression = "FILL(tgt4, 0)", label = "target 4xx", id = "etgt4" }],
          [{ expression = "FILL(tgt5, 0)", label = "target 5xx", id = "etgt5" }],
          ["AWS/ApplicationELB", "HTTPCode_ELB_4XX_Count", "LoadBalancer", local.alb_arn_suffix, { id = "elb4", stat = "Sum", visible = false }],
          ["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", local.alb_arn_suffix, { id = "elb5", stat = "Sum", visible = false }],
          ["AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", "LoadBalancer", local.alb_arn_suffix, "TargetGroup", local.litellm_tg_arn_suffix, { id = "tgt4", stat = "Sum", visible = false }],
          ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", local.alb_arn_suffix, "TargetGroup", local.litellm_tg_arn_suffix, { id = "tgt5", stat = "Sum", visible = false }],
        ]
      }
    },
  ]

  # ======================================================================
  # ROW C -- Model (R58c). Bedrock, platform-wide (R60): ModelId dimension is the
  # inference profile id (= var.bedrock_inference_profile_id). Invocations,
  # InvocationLatency p95, input/output tokens, output:input ratio, and errors
  # split client/server/throttles. Server errors and throttles have never fired,
  # so FILLed.
  # ======================================================================
  row_model = [
    {
      type   = "text"
      x      = 0
      y      = 26
      width  = 24
      height = 1
      properties = {
        markdown = "## Model — Amazon Bedrock via the EU inference profile. Platform-wide, not per team: with a shared master key and no per-agent gateway keys, a model call carries no team identity (R60)."
      }
    },
    {
      type   = "metric"
      x      = 0
      y      = 27
      width  = 8
      height = 6
      properties = {
        title  = "Bedrock invocations & latency p95 (ms)"
        region = local._r
        view   = "timeSeries"
        metrics = [
          [{ expression = "FILL(minv, 0)", label = "invocations", id = "einv" }],
          ["AWS/Bedrock", "Invocations", "ModelId", local.bedrock_model_id, { id = "minv", stat = "Sum", visible = false }],
          ["AWS/Bedrock", "InvocationLatency", "ModelId", local.bedrock_model_id, { stat = "p95", label = "latency p95 (ms)", yAxis = "right" }],
        ]
      }
    },
    {
      type   = "metric"
      x      = 8
      y      = 27
      width  = 8
      height = 6
      properties = {
        title  = "Bedrock tokens — input, output, and output:input ratio"
        region = local._r
        view   = "timeSeries"
        metrics = [
          [{ expression = "FILL(min, 0)", label = "input tokens", id = "ein" }],
          [{ expression = "FILL(mout, 0)", label = "output tokens", id = "eout" }],
          # Ratio guarded against divide-by-zero: max(input,1) in the denominator
          # so a quiet minute reads 0, not an error.
          [{ expression = "FILL(mout, 0)/IF((FILL(min, 0)) > 0, FILL(min, 0), 1)", label = "output:input ratio", id = "eratio", yAxis = "right" }],
          ["AWS/Bedrock", "InputTokenCount", "ModelId", local.bedrock_model_id, { id = "min", stat = "Sum", visible = false }],
          ["AWS/Bedrock", "OutputTokenCount", "ModelId", local.bedrock_model_id, { id = "mout", stat = "Sum", visible = false }],
        ]
      }
    },
    {
      type   = "metric"
      x      = 16
      y      = 27
      width  = 8
      height = 6
      properties = {
        title  = "Bedrock errors — client / server / throttles (0 when healthy)"
        region = local._r
        view   = "timeSeries"
        metrics = [
          [{ expression = "FILL(mce, 0)", label = "client errors", id = "ece" }],
          [{ expression = "FILL(mse, 0)", label = "server errors", id = "ese" }],
          [{ expression = "FILL(mth, 0)", label = "throttles", id = "eth" }],
          ["AWS/Bedrock", "InvocationClientErrors", "ModelId", local.bedrock_model_id, { id = "mce", stat = "Sum", visible = false }],
          ["AWS/Bedrock", "InvocationServerErrors", "ModelId", local.bedrock_model_id, { id = "mse", stat = "Sum", visible = false }],
          ["AWS/Bedrock", "InvocationThrottles", "ModelId", local.bedrock_model_id, { id = "mth", stat = "Sum", visible = false }],
        ]
      }
    },
  ]

  # ======================================================================
  # ROW D -- Governance, per team (R58d, R60). Built from the metric filters
  # above (namespace ${project}/gate), dimensioned by team only. Every per-team
  # series is FILLed to 0 so a team that sent no traffic still shows a 0 line and
  # the row separates the teams (A17). Content is never surfaced (R33/R60): these
  # are counts keyed on bounded fields, no caller/tool/args_hash.
  # ======================================================================
  row_governance = [
    {
      type   = "text"
      x      = 0
      y      = 33
      width  = 24
      height = 1
      properties = {
        markdown = "## Governance — per team, from the gate's decision log. Counts only; no prompt, response or tool-argument content (R33, R60). A quiet team shows a flat 0, not a blank."
      }
    },
    # Decisions by classification, per team. Each visible series is a FILLed math
    # expression over a hidden source metric (the Decision_<class> filter,
    # dimensioned by team); the hidden sources are appended so every math id
    # resolves. Built with single-level setproduct comprehensions so each metric
    # ARRAY stays one element -- flatten() would recurse into the arrays and
    # dissolve them. Teams come from distinct(values(var.callers)), bounded by
    # policy.
    {
      type   = "metric"
      x      = 0
      y      = 34
      width  = 12
      height = 6
      properties = {
        title   = "Decisions by classification, per team"
        region  = local._r
        view    = "timeSeries"
        stacked = true
        metrics = concat(
          [for p in setproduct(range(length(local.dashboard_teams)), ["read", "write", "destructive", "unknown"]) :
            [{ expression = "FILL(mc_${p[0]}_${index(["read", "write", "destructive", "unknown"], p[1])}, 0)", label = "${local.dashboard_teams[p[0]]} ${p[1]}", id = "ec_${p[0]}_${index(["read", "write", "destructive", "unknown"], p[1])}" }]
          ],
          [for p in setproduct(range(length(local.dashboard_teams)), ["read", "write", "destructive", "unknown"]) :
            ["${var.project_name}/gate", "Decision_${p[1]}", "team", local.dashboard_teams[p[0]], { id = "mc_${p[0]}_${index(["read", "write", "destructive", "unknown"], p[1])}", stat = "Sum", visible = false }]
          ],
        )
      }
    },
    # Decisions by outcome, per team (pass/approve/block). "approve" == parked.
    {
      type   = "metric"
      x      = 12
      y      = 34
      width  = 12
      height = 6
      properties = {
        title   = "Decisions by outcome, per team (approve = parked)"
        region  = local._r
        view    = "timeSeries"
        stacked = true
        metrics = concat(
          [for p in setproduct(range(length(local.dashboard_teams)), ["pass", "approve", "block"]) :
            [{ expression = "FILL(mo_${p[0]}_${index(["pass", "approve", "block"], p[1])}, 0)", label = "${local.dashboard_teams[p[0]]} ${p[1]}", id = "eo_${p[0]}_${index(["pass", "approve", "block"], p[1])}" }]
          ],
          [for p in setproduct(range(length(local.dashboard_teams)), ["pass", "approve", "block"]) :
            ["${var.project_name}/gate", "Outcome_${p[1]}", "team", local.dashboard_teams[p[0]], { id = "mo_${p[0]}_${index(["pass", "approve", "block"], p[1])}", stat = "Sum", visible = false }]
          ],
        )
      }
    },
    # Unknown-tool denials and parks, per team.
    {
      type   = "metric"
      x      = 0
      y      = 40
      width  = 12
      height = 6
      properties = {
        title  = "Unknown-tool denials & parks, per team"
        region = local._r
        view   = "timeSeries"
        metrics = concat(
          [for ti in range(length(local.dashboard_teams)) :
            [{ expression = "FILL(mu_${ti}, 0)", label = "${local.dashboard_teams[ti]} unknown denials", id = "eu_${ti}" }]
          ],
          [for ti in range(length(local.dashboard_teams)) :
            [{ expression = "FILL(mp_${ti}, 0)", label = "${local.dashboard_teams[ti]} parks", id = "ep_${ti}" }]
          ],
          [for ti in range(length(local.dashboard_teams)) :
            ["${var.project_name}/gate", "UnknownDenials", "team", local.dashboard_teams[ti], { id = "mu_${ti}", stat = "Sum", visible = false }]
          ],
          [for ti in range(length(local.dashboard_teams)) :
            ["${var.project_name}/gate", "Outcome_approve", "team", local.dashboard_teams[ti], { id = "mp_${ti}", stat = "Sum", visible = false }]
          ],
        )
      }
    },
    # Auth rejections (undimensioned: no team on an auth_rejected line) and the
    # per-team fail-closed count plus the unattributed remainder.
    {
      type   = "metric"
      x      = 12
      y      = 40
      width  = 12
      height = 6
      properties = {
        title  = "Auth rejections (no team) & fail-closed by team + unattributed"
        region = local._r
        view   = "timeSeries"
        metrics = concat(
          [
            [{ expression = "FILL(mar, 0)", label = "auth rejections", id = "ear" }],
            ["${var.project_name}/gate", "AuthRejected", { id = "mar", stat = "Sum", visible = false }],
          ],
          [for ti in range(length(local.dashboard_teams)) :
            [{ expression = "FILL(mfc_${ti}, 0)", label = "${local.dashboard_teams[ti]} fail-closed", id = "efc_${ti}" }]
          ],
          [for ti in range(length(local.dashboard_teams)) :
            ["${var.project_name}/gate", "FailClosedByTeam", "team", local.dashboard_teams[ti], { id = "mfc_${ti}", stat = "Sum", visible = false }]
          ],
          [
            # unattributed = total FailClosed - sum(per-team). Guarded to >= 0 so
            # a transient ordering never draws a negative. The total is the
            # existing undimensioned FailClosed metric (monitoring.tf), so a
            # null-team block still shows up here even though the per-team filter
            # cannot attribute it.
            [{ expression = "IF((FILL(mfct,0) - (${join(" + ", [for ti, _team in local.dashboard_teams : "FILL(mfc_${ti},0)"])})) > 0, FILL(mfct,0) - (${join(" + ", [for ti, _team in local.dashboard_teams : "FILL(mfc_${ti},0)"])}), 0)", label = "unattributed fail-closed", id = "efcu" }],
            ["${var.project_name}/gate", "FailClosed", { id = "mfct", stat = "Sum", visible = false }],
          ],
        )
      }
    },
  ]
}
