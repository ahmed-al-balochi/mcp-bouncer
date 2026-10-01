# The SLI row and the absent-indicators text widget. Every SLI with a target
# draws it as a horizontal annotation whose value comes from local.sli_targets;
# the token ratio has no hard target and carries a label saying why.

locals {
  # ======================================================================
  # ROW E: Service level indicators
  # ======================================================================
  row_sli = [
    {
      type   = "text"
      x      = 0
      y      = 46
      width  = 24
      height = 1
      properties = {
        markdown = "## Service levels"
      }
    },

    # --- Gateway availability = 1 - (Target_5XX + ELB_5XX)/RequestCount -------
    # Drawn as a percentage time series with the 99.5% target annotation. All
    # error inputs FILLed so a healthy stack computes 100%, not "no data".
    {
      type   = "metric"
      x      = 0
      y      = 47
      width  = 12
      height = 6
      properties = {
        title  = "Gateway availability (%)"
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

    # --- Gateway end-to-end latency p95 (ALB TargetResponseTime) -------------
    # PROVISIONAL 30 s target as an annotation.
    {
      type   = "metric"
      x      = 12
      y      = 47
      width  = 12
      height = 6
      properties = {
        title  = "Gateway latency p95 (s)"
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

    # ELB 4xx/5xx, target 4xx/5xx, Bedrock client/server/throttle, each as a % of
    # the relevant request count with the target annotation. ALB classes over ALB
    # RequestCount, Bedrock over Invocations. All FILLed so a healthy stack reads 0%.
    {
      type   = "metric"
      x      = 0
      y      = 53
      width  = 18
      height = 6
      properties = {
        title  = "Error rate by class (%)"
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
      y      = 53
      width  = 6
      height = 6
      properties = {
        title  = "Model latency p95 (ms)"
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

    # --- Output:input token ratio, no target ---------------------------------
    # Shown without a target line; the label states a normal band needs history
    # this demo does not have.
    {
      type   = "metric"
      x      = 0
      y      = 59
      width  = 12
      height = 6
      properties = {
        title  = "Token ratio (no target yet)"
        region = local._r
        view   = "timeSeries"
        metrics = [
          [{ expression = "FILL(tr_out,0) / IF((FILL(tr_in,0)) > 0, FILL(tr_in,0), 1)", label = "output:input ratio", id = "tr" }],
          ["AWS/Bedrock", "OutputTokenCount", "ModelId", local.bedrock_model_id, { id = "tr_out", stat = "Sum", visible = false }],
          ["AWS/Bedrock", "InputTokenCount", "ModelId", local.bedrock_model_id, { id = "tr_in", stat = "Sum", visible = false }],
        ]
      }
    },

    # Fail-closed rate per team = fc / (decisions + fc), target 0%. A fail-closed
    # block writes no decision line, so both counts go in the denominator.
    # All inputs FILLed so a quiet/healthy team reads 0%.
    {
      type   = "metric"
      x      = 12
      y      = 59
      width  = 12
      height = 6
      properties = {
        title  = "Fail-closed rate per team (%)"
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
  # ROW F: Absent indicators text
  # ======================================================================
  row_absences_text = [
    {
      type   = "text"
      x      = 0
      y      = 65
      width  = 24
      height = 5
      properties = {
        markdown = <<-EOT
        ## Not measured, and why
        - **Time to first token**: Bedrock is called non-streaming, so it is never emitted.
        - **Fallback engagement**: one model, no fallback.
        - **Cache hit rate**: no prompt caching.
        - **Cost in currency**: would hardcode a price; token counts are shown instead.
        - **Token ratio target**: a normal band needs history this demo lacks.

        Model rows are platform-wide: without per-agent gateway keys a model call carries no team. Targets are illustrative; latency targets are provisional. The only alarm is fail-closed.
        EOT
      }
    },
  ]
}
