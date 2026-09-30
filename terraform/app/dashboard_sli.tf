# The SLI row (R59) and the absent-indicators text widget (R60, R61). Kept in
# their own file so the SLI math and the target annotations read next to each
# other. Every SLI with a target draws that target as a horizontal annotation
# whose value comes from local.sli_targets (one source, R59), and where
# CloudWatch can express attainment over the viewed range a singleValue widget
# shows it. The two indicators without a hard target (token ratio) carry a label
# saying why, not a line.

locals {
  # ======================================================================
  # ROW E -- Service level indicators (R59)
  # ======================================================================
  row_sli = [
    {
      type   = "text"
      x      = 0
      y      = 46
      width  = 24
      height = 2
      properties = {
        markdown = <<-EOT
        ## Service levels — targets are **illustrative for a demo workload**; the two latency targets are **PROVISIONAL** and will be replaced by a measured baseline from the live run.
        Each SLI draws its target as a horizontal annotation. Attainment over the viewed range is shown as a single value where CloudWatch can express it.
        EOT
      }
    },

    # --- Gateway availability = 1 - (Target_5XX + ELB_5XX)/RequestCount -------
    # Drawn as a percentage time series with the 99.5% target annotation, plus a
    # single-value attainment over the range. All error inputs FILLed so a
    # healthy stack computes 100%, not "no data".
    {
      type   = "metric"
      x      = 0
      y      = 48
      width  = 12
      height = 6
      properties = {
        title  = "SLI — gateway availability (%)"
        region = local._r
        view   = "timeSeries"
        yAxis  = { left = { min = 90, max = 100 } }
        metrics = [
          [{ expression = "100 * (1 - (FILL(av_t5,0) + FILL(av_e5,0)) / IF((FILL(av_rc,0)) > 0, FILL(av_rc,0), 1))", label = "availability %", id = "av" }],
          ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", local.alb_arn_suffix, "TargetGroup", local.litellm_tg_arn_suffix, { id = "av_t5", stat = "Sum", visible = false }],
          ["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", local.alb_arn_suffix, { id = "av_e5", stat = "Sum", visible = false }],
          ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", local.alb_arn_suffix, { id = "av_rc", stat = "Sum", visible = false }],
        ]
        annotations = {
          horizontal = [
            { label = "target ${local.sli_targets.gateway_availability_pct}%", value = local.sli_targets.gateway_availability_pct },
          ]
        }
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 48
      width  = 6
      height = 6
      properties = {
        title  = "Availability attainment (range)"
        region = local._r
        view   = "singleValue"
        metrics = [
          [{ expression = "100 * (1 - (FILL(sv_t5,0) + FILL(sv_e5,0)) / IF((FILL(sv_rc,0)) > 0, FILL(sv_rc,0), 1))", label = "availability %", id = "sv" }],
          ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", local.alb_arn_suffix, "TargetGroup", local.litellm_tg_arn_suffix, { id = "sv_t5", stat = "Sum", visible = false }],
          ["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", local.alb_arn_suffix, { id = "sv_e5", stat = "Sum", visible = false }],
          ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", local.alb_arn_suffix, { id = "sv_rc", stat = "Sum", visible = false }],
        ]
      }
    },

    # --- Gateway end-to-end latency p95 (ALB TargetResponseTime) -------------
    # PROVISIONAL 30 s target as an annotation.
    {
      type   = "metric"
      x      = 18
      y      = 48
      width  = 6
      height = 6
      properties = {
        title  = "SLI — gateway latency p95 (s)"
        region = local._r
        view   = "timeSeries"
        metrics = [
          ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", local.alb_arn_suffix, "TargetGroup", local.litellm_tg_arn_suffix, { stat = "p95", label = "p95 (s)" }],
        ]
        annotations = {
          horizontal = [
            { label = "target ${local.sli_targets.gateway_latency_p95_s}s (PROVISIONAL)", value = local.sli_targets.gateway_latency_p95_s },
          ]
        }
      }
    },

    # --- Error rate split by class -------------------------------------------
    # ELB 4xx, ELB 5xx, target 4xx, target 5xx, Bedrock client/server/throttle,
    # each as a % of the relevant request count, with the <1% target annotation.
    # ALB classes are over ALB RequestCount; Bedrock classes over Bedrock
    # Invocations. All FILLed so a healthy stack reads 0%.
    {
      type   = "metric"
      x      = 0
      y      = 54
      width  = 18
      height = 6
      properties = {
        title  = "SLI — error rate by class (% of requests)"
        region = local._r
        view   = "timeSeries"
        metrics = [
          [{ expression = "100 * FILL(er_elb4,0) / IF((FILL(er_rc,0)) > 0, FILL(er_rc,0), 1)", label = "ELB 4xx %", id = "pe4" }],
          [{ expression = "100 * FILL(er_elb5,0) / IF((FILL(er_rc,0)) > 0, FILL(er_rc,0), 1)", label = "ELB 5xx %", id = "pe5" }],
          [{ expression = "100 * FILL(er_t4,0) / IF((FILL(er_rc,0)) > 0, FILL(er_rc,0), 1)", label = "target 4xx %", id = "pt4" }],
          [{ expression = "100 * FILL(er_t5,0) / IF((FILL(er_rc,0)) > 0, FILL(er_rc,0), 1)", label = "target 5xx %", id = "pt5" }],
          [{ expression = "100 * FILL(er_bce,0) / IF((FILL(er_inv,0)) > 0, FILL(er_inv,0), 1)", label = "Bedrock client %", id = "pbc" }],
          [{ expression = "100 * FILL(er_bse,0) / IF((FILL(er_inv,0)) > 0, FILL(er_inv,0), 1)", label = "Bedrock server %", id = "pbs" }],
          [{ expression = "100 * FILL(er_bth,0) / IF((FILL(er_inv,0)) > 0, FILL(er_inv,0), 1)", label = "Bedrock throttle %", id = "pbt" }],
          ["AWS/ApplicationELB", "HTTPCode_ELB_4XX_Count", "LoadBalancer", local.alb_arn_suffix, { id = "er_elb4", stat = "Sum", visible = false }],
          ["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", local.alb_arn_suffix, { id = "er_elb5", stat = "Sum", visible = false }],
          ["AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", "LoadBalancer", local.alb_arn_suffix, "TargetGroup", local.litellm_tg_arn_suffix, { id = "er_t4", stat = "Sum", visible = false }],
          ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", local.alb_arn_suffix, "TargetGroup", local.litellm_tg_arn_suffix, { id = "er_t5", stat = "Sum", visible = false }],
          ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", local.alb_arn_suffix, { id = "er_rc", stat = "Sum", visible = false }],
          ["AWS/Bedrock", "InvocationClientErrors", "ModelId", local.bedrock_model_id, { id = "er_bce", stat = "Sum", visible = false }],
          ["AWS/Bedrock", "InvocationServerErrors", "ModelId", local.bedrock_model_id, { id = "er_bse", stat = "Sum", visible = false }],
          ["AWS/Bedrock", "InvocationThrottles", "ModelId", local.bedrock_model_id, { id = "er_bth", stat = "Sum", visible = false }],
          ["AWS/Bedrock", "Invocations", "ModelId", local.bedrock_model_id, { id = "er_inv", stat = "Sum", visible = false }],
        ]
        annotations = {
          horizontal = [
            { label = "target ${local.sli_targets.error_rate_pct}%", value = local.sli_targets.error_rate_pct },
          ]
        }
      }
    },

    # --- Model latency p95 (Bedrock InvocationLatency) -----------------------
    # PROVISIONAL 15 s target. InvocationLatency is in ms, so the target is drawn
    # at 15000 ms and the label states the seconds.
    {
      type   = "metric"
      x      = 18
      y      = 54
      width  = 6
      height = 6
      properties = {
        title  = "SLI — model latency p95 (ms)"
        region = local._r
        view   = "timeSeries"
        metrics = [
          ["AWS/Bedrock", "InvocationLatency", "ModelId", local.bedrock_model_id, { stat = "p95", label = "p95 (ms)" }],
        ]
        annotations = {
          horizontal = [
            { label = "target ${local.sli_targets.model_latency_p95_s}s (PROVISIONAL)", value = local.sli_targets.model_latency_p95_s * 1000 },
          ]
        }
      }
    },

    # --- Output:input token ratio -- NO target (R59) -------------------------
    # Shown without a target line; the label states a normal band needs history
    # this demo does not have.
    {
      type   = "metric"
      x      = 0
      y      = 60
      width  = 12
      height = 6
      properties = {
        title  = "SLI — output:input token ratio (no target — needs history this demo lacks)"
        region = local._r
        view   = "timeSeries"
        metrics = [
          [{ expression = "FILL(tr_out,0) / IF((FILL(tr_in,0)) > 0, FILL(tr_in,0), 1)", label = "output:input ratio", id = "tr" }],
          ["AWS/Bedrock", "OutputTokenCount", "ModelId", local.bedrock_model_id, { id = "tr_out", stat = "Sum", visible = false }],
          ["AWS/Bedrock", "InputTokenCount", "ModelId", local.bedrock_model_id, { id = "tr_in", stat = "Sum", visible = false }],
        ]
      }
    },

    # --- Gate fail-closed rate per team = fc / (decisions + fc) --------------
    # per team, plus unattributed, target 0%. Denominator is decision lines +
    # fail_closed lines for that team (a fail-closed writes no decision line).
    # All inputs FILLed so a quiet/healthy team reads 0%.
    {
      type   = "metric"
      x      = 12
      y      = 60
      width  = 12
      height = 6
      properties = {
        title  = "SLI — gate fail-closed rate per team (%)"
        region = local._r
        view   = "timeSeries"
        metrics = concat(
          [for ti in range(length(local.dashboard_teams)) :
            # rate = 100 * fc / (pass+approve+block+fc) for the team. The
            # per-team decision total is the sum of the three outcome metrics;
            # denominator floored at 1 so a silent team reads 0%.
            [{ expression = "100 * FILL(fr_fc_${ti},0) / IF((FILL(fr_p_${ti},0)+FILL(fr_a_${ti},0)+FILL(fr_b_${ti},0)+FILL(fr_fc_${ti},0)) > 0, FILL(fr_p_${ti},0)+FILL(fr_a_${ti},0)+FILL(fr_b_${ti},0)+FILL(fr_fc_${ti},0), 1)", label = "${local.dashboard_teams[ti]} fail-closed %", id = "fr_${ti}" }]
          ],
          [for ti in range(length(local.dashboard_teams)) :
            ["${var.project_name}/gate", "Outcome_pass", "team", local.dashboard_teams[ti], { id = "fr_p_${ti}", stat = "Sum", visible = false }]
          ],
          [for ti in range(length(local.dashboard_teams)) :
            ["${var.project_name}/gate", "Outcome_approve", "team", local.dashboard_teams[ti], { id = "fr_a_${ti}", stat = "Sum", visible = false }]
          ],
          [for ti in range(length(local.dashboard_teams)) :
            ["${var.project_name}/gate", "Outcome_block", "team", local.dashboard_teams[ti], { id = "fr_b_${ti}", stat = "Sum", visible = false }]
          ],
          [for ti in range(length(local.dashboard_teams)) :
            ["${var.project_name}/gate", "FailClosedByTeam", "team", local.dashboard_teams[ti], { id = "fr_fc_${ti}", stat = "Sum", visible = false }]
          ],
        )
        annotations = {
          horizontal = [
            { label = "target ${local.sli_targets.gate_fail_closed_rate_pct}%", value = local.sli_targets.gate_fail_closed_rate_pct },
          ]
        }
      }
    },
  ]

  # ======================================================================
  # ROW F -- Absent indicators text (R60, R61)
  # ======================================================================
  row_absences_text = [
    {
      type   = "text"
      x      = 0
      y      = 66
      width  = 24
      height = 6
      properties = {
        markdown = <<-EOT
        ## What is deliberately absent, and why

        Model-call indicators above are **platform-wide, not per team**: without per-agent gateway keys a model call carries no team identity, so Bedrock usage cannot be attributed to a team (R60). Tool-call governance *is* per team, from the gate's decision log.

        Indicators intentionally **not shown**, because the deployment cannot measure them honestly (R61):

        - **Time to first token** — the gateway calls Bedrock non-streaming, so `TimeToFirstToken` has never been emitted. Showing it would imply a streaming path that does not exist.
        - **Fallback engagement** — there is one model and no fallback, so there is nothing to measure.
        - **Cache hit rate** — no prompt caching is configured, so there are no cache hits or misses.
        - **Cost in currency** — pricing would have to be hardcoded (no live price feed in the no-internet VPC, and a hardcoded rate would silently go stale). Input/output **token counts** are shown instead, from which cost can be derived out of band.

        Alarms are deliberately limited to the single **fail-closed** alarm; these widgets are for observation, not paging (REQUIREMENTS §8).
        EOT
      }
    },
  ]
}
