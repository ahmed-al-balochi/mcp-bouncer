# The dashboard's widget rows. Names and dimensions are Terraform references,
# never literals, and metrics that may never fire are wrapped in FILL(m, 0) so a
# quiet row shows 0 instead of "no data".

# Grid: CloudWatch lays widgets on a 24-column grid. Each row sets y so rows
# stack top to bottom; widths sum to <= 24 per row.

locals {
  _r = local.dashboard_region

  # ======================================================================
  # ROW A: Platform health
  # ======================================================================

  # Both ECS services (CPU/memory/LiveTaskCount), the ALB healthy host count for
  # the LiteLLM target group, the Service Connect gate hop, and both DynamoDB
  # tables. The sparse series read "no data" on a quiet stack, so each is FILLed.
  row_platform_health = [
    {
      type   = "text"
      x      = 0
      y      = 0
      width  = 24
      height = 1
      properties = {
        markdown = "## Platform health"
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
        title  = "CPU % (gate, LiteLLM)"
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
        title  = "Memory % (gate, LiteLLM)"
        region = local._r
        view   = "timeSeries"
        stat   = "Average"
        metrics = [
          ["AWS/ECS", "MemoryUtilization", "ClusterName", local.cluster_name, "ServiceName", local.gate_service_name, { label = "gate" }],
          ["AWS/ECS", "MemoryUtilization", "ClusterName", local.cluster_name, "ServiceName", local.litellm_service_name, { label = "litellm" }],
        ]
      }
    },
    # LiveTaskCount: FILLed because a stopped or scaled-to-zero service reports
    # no data rather than 0.
    {
      type   = "metric"
      x      = 16
      y      = 1
      width  = 8
      height = 6
      properties = {
        title  = "Running tasks"
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
        title  = "Healthy LiteLLM targets"
        region = local._r
        view   = "timeSeries"
        metrics = [
          [{ expression = "FILL(mh, 0)", label = "healthy hosts", id = "eh" }],
          ["AWS/ApplicationELB", "HealthyHostCount", "LoadBalancer", local.alb_arn_suffix, "TargetGroup", local.litellm_tg_arn_suffix, { id = "mh", stat = "Average", visible = false }],
        ]
      }
    },
    # Service Connect gate hop: requests, p95 response time, and 2xx/4xx/5xx.
    # Inbound RequestCount uses DiscoveryName+ServiceName (server); target
    # metrics (HTTPCode_Target_*, TargetResponseTime) use TargetDiscoveryName.

    # Pairing a target metric with the server's ServiceName is not a published
    # set and renders "no data", which FILL cannot rescue. So target metrics use
    # TargetDiscoveryName alone, aggregating responses across callers of `gate`.
    {
      type   = "metric"
      x      = 8
      y      = 7
      width  = 8
      height = 6
      properties = {
        title  = "Gate hop: requests, p95 (ms)"
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
        title  = "Gate hop: response codes"
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
    # DynamoDB, both tables. SystemErrors is published only on (TableName,
    # Operation), never TableName alone, so it names an operation the store
    # issues. SystemErrors and ThrottledRequests may never fire, so FILLed.
    {
      type   = "metric"
      x      = 0
      y      = 13
      width  = 24
      height = 6
      properties = {
        title  = "DynamoDB throttles and errors"
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

  # ROW B: Gateway traffic. Requests, response time, and 4xx/5xx split by
  # whether the ALB or LiteLLM produced them.
  row_gateway_traffic = [
    {
      type   = "text"
      x      = 0
      y      = 19
      width  = 24
      height = 1
      properties = {
        markdown = "## Gateway traffic"
      }
    },
    {
      type   = "metric"
      x      = 0
      y      = 20
      width  = 8
      height = 6
      properties = {
        title  = "Requests"
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
        title  = "Response time p50, p95 (s)"
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
        title  = "4xx/5xx: ALB vs LiteLLM"
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

  # ROW C: Model, platform-wide. Bedrock keys these metrics on the inference
  # profile id, and a model call carries no team, so nothing here is per team.
  row_model = [
    {
      type   = "text"
      x      = 0
      y      = 26
      width  = 24
      height = 1
      properties = {
        markdown = "## Model, platform-wide"
      }
    },
    {
      type   = "metric"
      x      = 0
      y      = 27
      width  = 8
      height = 6
      properties = {
        title  = "Invocations, latency p95 (ms)"
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
        title  = "Tokens, output:input ratio"
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
        title  = "Errors: client, server, throttle"
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

  # ROW D: Governance per team, from the gate's decision-log metric filters.
  # Counts keyed on team only, never caller, tool or argument hash, and FILLed
  # so a team with no traffic still shows a 0 line.
  row_governance = [
    {
      type   = "text"
      x      = 0
      y      = 33
      width  = 24
      height = 1
      properties = {
        markdown = "## Governance per team"
      }
    },
    # Each visible series is FILL() over a hidden per-team source metric. Built
    # with setproduct rather than flatten(), which would dissolve the metric
    # arrays into their elements.
    {
      type   = "metric"
      x      = 0
      y      = 34
      width  = 12
      height = 6
      properties = {
        title   = "By classification"
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
        title   = "By outcome (approve = parked)"
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
        title  = "Unknown-tool denials, parks"
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
        title  = "Auth rejections, fail-closed"
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
            # Unattributed = total FailClosed minus the per-team sum, floored at 0.
            # A block with no team never reaches the per-team metric, so this is
            # the only place it shows up.
            [{ expression = "IF((FILL(mfct,0) - (${join(" + ", [for ti, _team in local.dashboard_teams : "FILL(mfc_${ti},0)"])})) > 0, FILL(mfct,0) - (${join(" + ", [for ti, _team in local.dashboard_teams : "FILL(mfc_${ti},0)"])}), 0)", label = "unattributed fail-closed", id = "efcu" }],
            ["${var.project_name}/gate", "FailClosed", { id = "mfct", stat = "Sum", visible = false }],
          ],
        )
      }
    },
  ]
}
