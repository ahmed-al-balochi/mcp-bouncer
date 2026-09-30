"""Static guards for the CloudWatch dashboard and its metric filters (R43,
R58-R61, A17).

These assert on committed Terraform text, not on a live dashboard. python-hcl2
is not installed and this suite adds no dependency (R44), so the HCL is read as
text and matched with narrow, commented regexes -- the same approach as
tests/test_gateway_config.py.

A recurring hazard with text guards is matching a word in a COMMENT rather than
in a directive: an earlier guard in this repo passed vacuously because it matched
its own explanatory comment. So the helpers here strip `#` comments before
matching whenever a property could also be named in prose, and each guard was
proven by breaking the property in a TEMP COPY of the guarded file (never the
real one) and confirming the guard fails.

What can and cannot be checked offline: these prove the committed HCL declares
the intended resources, references (not literals), FILL-wrapped sparse metrics,
target annotations, and comment-stripped metric-filter shapes. They CANNOT prove
that a metric-math expression renders in the CloudWatch UI or that a metric ever
carries data -- only a live dashboard shows that.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_TF_DIR = REPO_ROOT / "terraform" / "app"
DASHBOARD_TF = APP_TF_DIR / "dashboard.tf"
WIDGETS_TF = APP_TF_DIR / "dashboard_widgets.tf"
SLI_TF = APP_TF_DIR / "dashboard_sli.tf"
MONITORING_TF = APP_TF_DIR / "monitoring.tf"


def _strip_comments(text: str) -> str:
    """Drop whole-line and trailing `#` comments so a guard cannot match prose.

    A line-oriented strip: it removes a `#` and everything after it on each line.
    Limit: it does not understand a `#` inside a string literal, but none of the
    guarded HCL puts a `#` inside a string (the markdown widget bodies use `##`
    headers, which this would truncate -- so guards that must read markdown text
    use the RAW text deliberately and say so).
    """
    out = []
    for line in text.splitlines():
        h = line.find("#")
        out.append(line if h == -1 else line[:h])
    return "\n".join(out)


def _all_dashboard_text() -> str:
    """Concatenated text of the three dashboard files, comments stripped."""
    return "\n".join(
        _strip_comments(p.read_text())
        for p in (DASHBOARD_TF, WIDGETS_TF, SLI_TF)
    )


def _all_dashboard_text_raw() -> str:
    """Concatenated RAW text (comments intact), for markdown-body checks."""
    return "\n".join(p.read_text() for p in (DASHBOARD_TF, WIDGETS_TF, SLI_TF))


# --- the dashboard resource exists and is jsonencode'd ----------------------


def test_dashboard_resource_exists_and_is_jsonencoded():
    """R58: exactly one aws_cloudwatch_dashboard, body via jsonencode()."""
    text = _strip_comments(DASHBOARD_TF.read_text())
    header = re.search(r'resource\s+"aws_cloudwatch_dashboard"\s+"this"\s*\{', text)
    assert header, "no aws_cloudwatch_dashboard resource in dashboard.tf"
    # The body must be produced by jsonencode(...), not a raw heredoc string.
    assert re.search(r"dashboard_body\s*=\s*jsonencode\(", text), (
        "dashboard_body must be built with jsonencode() (R58)"
    )
    # Name derives from the project_name variable, not a literal.
    assert re.search(r"dashboard_name\s*=\s*var\.project_name", text), (
        "dashboard_name must come from var.project_name, not a literal"
    )


# --- no account id / region / arn / ip literal (R2, R3, R39) ----------------


def test_no_twelve_digit_account_id_anywhere():
    """R2/R39: no 12-digit AWS account id in any dashboard file (comments too)."""
    for p in (DASHBOARD_TF, WIDGETS_TF, SLI_TF):
        raw = p.read_text()
        # A 12-digit run not part of a longer number. Account ids are exactly 12.
        m = re.search(r"(?<!\d)\d{12}(?!\d)", raw)
        assert not m, f"a 12-digit account id appears in {p.name}: {m.group(0)!r}"


def test_no_literal_region_string():
    """R2/R3: no hardcoded region code (comments too).

    Matches the region-code shape `xx-word-N`. The region must always come from
    data.aws_region.current.region.
    """
    pat = re.compile(r"\b[a-z]{2}-[a-z]+-\d\b")
    for p in (DASHBOARD_TF, WIDGETS_TF, SLI_TF):
        raw = p.read_text()
        m = pat.search(raw)
        assert not m, f"a literal region string appears in {p.name}: {m.group(0)!r}"


def test_no_literal_arn():
    """R2/R39: no `arn:aws` literal; ARNs come from references (arn_suffix etc.)."""
    for p in (DASHBOARD_TF, WIDGETS_TF, SLI_TF):
        raw = p.read_text()
        assert "arn:aws" not in raw, f"a literal arn:aws appears in {p.name}"


def test_no_ip_literal():
    """R2: no dotted-quad IP literal anywhere in the dashboard files."""
    pat = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    for p in (DASHBOARD_TF, WIDGETS_TF, SLI_TF):
        raw = p.read_text()
        m = pat.search(raw)
        assert not m, f"an IP literal appears in {p.name}: {m.group(0)!r}"


def test_region_is_the_data_source_reference():
    """R2/R3: the region is data.aws_region.current.region (provider 6.x attr)."""
    text = _all_dashboard_text()
    assert "data.aws_region.current.region" in text, (
        "the dashboard must take its region from data.aws_region.current.region"
    )


# --- governance metric filters key on $.event and use team, never caller/... -


def _metric_filter_block(text: str, resource_name: str) -> str:
    """Brace-matched body of a named aws_cloudwatch_log_metric_filter block.

    Comments must be stripped by the caller if it wants to avoid matching prose;
    this returns the slice verbatim from whatever text it is given.
    """
    header = re.search(
        rf'resource\s+"aws_cloudwatch_log_metric_filter"\s+"{re.escape(resource_name)}"\s*\{{',
        text,
    )
    assert header, f"metric filter {resource_name!r} not found"
    depth = 0
    start = header.end() - 1
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise AssertionError(f"unbalanced braces parsing {resource_name!r}")


def test_governance_filters_key_on_event_and_use_team_dimension():
    """R58d/R60: the decision and fail-closed-per-team filters key on $.event and
    use team as their only dimension -- never caller, tool or args_hash.

    Comments are stripped first so a mention of `caller`/`tool`/`args_hash` in an
    explanatory comment cannot make this pass or fail spuriously.
    """
    text = _strip_comments(DASHBOARD_TF.read_text())

    # Every metric filter for-each'd or named in dashboard.tf that carries a team
    # dimension must key on $.event and must not name a forbidden field.
    named = [
        "decision_by_classification",
        "decision_by_outcome",
        "unknown_denials",
        "fail_closed_by_team",
    ]
    for name in named:
        block = _metric_filter_block(text, name)
        assert "$.event" in block, f"{name} must key its pattern on $.event"
        assert re.search(r"team\s*=\s*\"\$\.team\"", block), (
            f"{name} must use team = \"$.team\" as a dimension"
        )
        for forbidden in ("caller", "tool", "args_hash"):
            assert forbidden not in block, (
                f"{name} must not reference {forbidden!r} (R33/R60 cardinality/leak)"
            )


def test_no_forbidden_field_is_ever_a_dimension():
    """R33/R60: caller, tool and args_hash never appear as a metric dimension.

    Scans (comment-stripped) for a `$.caller` / `$.tool` / `$.args_hash` token in
    any dimensions map. A JSON-field reference like `$.caller` only appears in a
    metric-filter pattern or dimension; the governance patterns key on $.event
    and $.classification / $.decision only, so any of these three is a red flag.
    """
    text = _all_dashboard_text()
    for forbidden in (r"\$\.caller", r"\$\.tool\b", r"\$\.args_hash"):
        m = re.search(forbidden, text)
        assert not m, f"a forbidden JSON field {forbidden!r} is referenced as a dimension"


# --- sparse metrics are wrapped in FILL -------------------------------------


def test_sparse_error_metrics_are_filled():
    """A17: metrics that may never fire on a healthy stack are FILLed to 0.

    Rather than enumerate every id, assert that each sparse SOURCE metric that
    can be absent (5xx, server errors, throttles, per-team counts) is referenced
    by a FILL() expression somewhere in the same file. The check: for a set of
    metric names known to be sparse, the file both references the metric AND
    contains at least one FILL( call, and no sparse metric is drawn as a bare
    visible series.
    """
    text = _all_dashboard_text()
    assert "FILL(" in text, "no FILL() used at all -- sparse metrics would read 'no data' (A17)"

    # These metric names are emitted only on error/quiet paths (per the measured
    # facts) and must never be a directly-visible series without FILL. We assert
    # each appears only inside a hidden (visible = false) source entry, so its
    # visible rendering is the FILLed math expression.
    sparse = [
        "HTTPCode_ELB_5XX_Count",
        "HTTPCode_Target_5XX_Count",
        "InvocationServerErrors",
        "InvocationThrottles",
        "SystemErrors",
        "ThrottledRequests",
        "FailClosedByTeam",
    ]
    for name in sparse:
        # Inspect only widget SOURCE-ARRAY lines: a metric array entry looks like
        # `["AWS/...", "Metric", ...]` or `["${var.project_name}/gate", "Metric",
        # ...]` and starts (after indentation) with `[`. The metric-filter
        # DEFINITION lines (`name = "FailClosedByTeam"`) are not array entries and
        # are excluded, so this does not false-positive on the filter that emits
        # the metric.
        for line in text.splitlines():
            stripped = line.strip()
            is_source_array = stripped.startswith("[") and (
                '"AWS/' in stripped or "/gate\"" in stripped or "gate\"," in stripped
            )
            if not is_source_array:
                continue
            if f'"{name}"' in stripped:
                assert "visible = false" in stripped, (
                    f"sparse metric {name} is drawn without visible=false on its source "
                    f"line (it must be a hidden source behind a FILL expression): {stripped!r}"
                )


def test_token_ratio_uses_fill_and_divide_guard():
    """A17 + divide-by-zero: the output:input ratio FILLs and floors the divisor.

    A ratio over a quiet minute must read 0, not error, so the denominator is
    IF(x > 0, x, 1) (see test_no_max_of_a_series_and_a_scalar for why not MAX).
    """
    text = _all_dashboard_text()
    assert re.search(
        r"FILL\(tr_out,\s*0\)\s*/\s*IF\(\(FILL\(tr_in,\s*0\)\)\s*>\s*0,\s*FILL\(tr_in,\s*0\),\s*1\)",
        text,
    ), (
        "the token ratio SLI must FILL both series and floor the divisor at 1"
    )


# --- every SLI with a target carries an annotation from locals --------------


def test_sli_targets_live_in_one_locals_block():
    """R59: all targets are in one locals block, marked illustrative/provisional."""
    text = DASHBOARD_TF.read_text()  # raw: we want to read the comment too
    assert re.search(r"sli_targets\s*=\s*\{", text), "no sli_targets locals block"
    # The comment must mark targets illustrative and the latency ones provisional.
    assert "illustrative" in text.lower(), "sli_targets must be documented as illustrative"
    assert "provisional" in text.lower(), "the latency targets must be marked PROVISIONAL"


def test_every_sli_with_a_target_annotates_it_from_locals():
    """R59: each SLI target is drawn as a horizontal annotation whose value comes
    from local.sli_targets -- never a bare number.

    Checks (comment-stripped) that every horizontal annotation value references
    local.sli_targets, and that the five targeted SLIs are each present.
    """
    text = _strip_comments(_all_dashboard_text())

    # Every `value = ...` inside an annotations horizontal entry must reference
    # local.sli_targets. Find each annotations block and assert it.
    ann_values = re.findall(r"annotations\s*=\s*\{.*?horizontal\s*=\s*\[(.*?)\]", text, re.S)
    assert ann_values, "no horizontal annotations found -- SLI targets are not drawn (R59)"
    for chunk in ann_values:
        # Each entry has value = <expr>; that expr must mention local.sli_targets.
        for value_expr in re.findall(r"value\s*=\s*([^,}\n]+)", chunk):
            assert "local.sli_targets." in value_expr, (
                f"an annotation target value is not from local.sli_targets: {value_expr.strip()!r}"
            )

    # The five targeted SLIs each reference their target key.
    for key in (
        "gateway_availability_pct",
        "gateway_latency_p95_s",
        "error_rate_pct",
        "model_latency_p95_s",
        "gate_fail_closed_rate_pct",
    ):
        assert f"local.sli_targets.{key}" in text, (
            f"SLI target {key} is never referenced by an annotation (R59)"
        )


def test_token_ratio_sli_has_no_target_annotation():
    """R59: the output:input ratio is shown WITHOUT a target line."""
    text = _strip_comments(_all_dashboard_text())
    # Locate the ratio SLI widget by its title and assert its slice has no
    # horizontal annotation. The widget title is distinctive.
    m = re.search(r'title\s*=\s*"Token ratio[^"]*"', text)
    assert m, "the token-ratio SLI widget was not found by title"
    # Slice a window after the title up to the next widget title or end.
    after = text[m.end() :]
    nxt = re.search(r'title\s*=\s*"', after)
    window = after[: nxt.start()] if nxt else after
    assert "horizontal" not in window, (
        "the output:input ratio SLI must not draw a target annotation (R59)"
    )


# --- absent-indicators text names all four ----------------------------------


def test_absent_indicators_text_names_all_four():
    """R61: the absences text names all four absent indicators with a reason.

    Reads the RAW markdown body (the text widget content is prose, so comment
    stripping would not help and could truncate the `##` headers).
    """
    text = _all_dashboard_text_raw().lower()
    # The four indicators R61 requires named.
    assert "time to first token" in text, "absences text must name time to first token"
    assert "fallback" in text, "absences text must name fallback engagement"
    assert "cache hit" in text, "absences text must name cache hit rate"
    assert "cost" in text, "absences text must name cost in currency"
    # And the reasoning tokens for each (no streaming / one model / no caching /
    # tokens shown instead).
    assert "non-streaming" in text or "no streaming" in text or "not stream" in text
    assert "token" in text  # tokens shown instead of cost


def test_model_indicators_documented_platform_wide():
    """R60: the dashboard states, in a visible text widget, that model indicators
    are platform-wide.

    Checks the markdown widget BODIES only (lines containing `markdown` or inside
    a heredoc), not comments -- a `platform-wide` mention buried in a `#` comment
    would not satisfy R60, which is about what the dashboard shows a viewer.
    """
    raw = _all_dashboard_text_raw()
    # Keep only lines that are part of a markdown body: either the single-line
    # `markdown = "..."` form or lines inside a `markdown = <<-EOT ... EOT`
    # heredoc. A small state machine tracks the heredoc.
    body_lines: list[str] = []
    in_heredoc = False
    for line in raw.splitlines():
        if in_heredoc:
            if line.strip() == "EOT":
                in_heredoc = False
            else:
                body_lines.append(line)
            continue
        if re.search(r"markdown\s*=\s*<<-EOT", line):
            in_heredoc = True
        elif re.search(r"markdown\s*=\s*\"", line):
            body_lines.append(line)
    body = "\n".join(body_lines).lower()
    assert "platform-wide" in body, (
        "a visible text widget must state model-call indicators are platform-wide (R60)"
    )


# --- the existing FailClosed filter is unchanged ----------------------------


def test_existing_fail_closed_filter_is_unchanged():
    """The existing fail_closed metric filter (monitoring.tf) keeps its exact
    pattern and metric name; the dashboard must not have altered it.

    Reads monitoring.tf directly and asserts the FailClosed filter's pattern and
    metric name are exactly as they were. Comment-stripped so the assertion is on
    the directive, not the surrounding prose (the comment names $.event too).
    """
    text = _strip_comments(MONITORING_TF.read_text())
    block = _metric_filter_block(text, "fail_closed")
    # Exact pattern on $.event = "fail_closed".
    assert re.search(r'pattern\s*=\s*"\{ \$\.event = \\"fail_closed\\" \}"', block), (
        "the existing fail_closed filter pattern must be unchanged"
    )
    # Metric name FailClosed, default_value 0, namespace ${project}/gate.
    assert re.search(r'name\s*=\s*"FailClosed"', block), (
        "the existing FailClosed metric name must be unchanged"
    )
    assert re.search(r'default_value\s*=\s*"0"', block), (
        "the existing FailClosed filter must keep default_value = 0"
    )


def test_dashboard_does_not_redefine_the_fail_closed_metric_name():
    """The dashboard's per-team filter uses a DIFFERENT metric name so it cannot
    clobber the existing FailClosed metric the alarm reads.

    The per-team filter must be named FailClosedByTeam, and no metric_filter in
    dashboard.tf may emit a metric literally named "FailClosed" (which would
    collide with monitoring.tf's).
    """
    text = _strip_comments(DASHBOARD_TF.read_text())
    # Find every metric_transformation name in dashboard.tf.
    names = re.findall(r'name\s*=\s*"([A-Za-z0-9_]+)"', text)
    # FailClosedByTeam must exist; a bare FailClosed metric_transformation must not
    # (the dashboard only READS FailClosed by string in a widget, never redefines
    # it as a filter output).
    assert "FailClosedByTeam" in names, "the per-team fail-closed filter must exist"
    # Ensure no metric_transformation emits exactly "FailClosed" in dashboard.tf.
    for block_name in ("decision_by_classification", "decision_by_outcome",
                       "unknown_denials", "auth_rejected", "fail_closed_by_team"):
        block = _metric_filter_block(text, block_name)
        transform_names = re.findall(r'name\s*=\s*"([A-Za-z0-9_]+)"', block)
        assert "FailClosed" not in transform_names, (
            f"{block_name} must not emit a metric named exactly FailClosed (collides with monitoring.tf)"
        )


# --- substantive-content guards (harden beyond pure structure) --------------
#
# The structural guards above prove the dashboard is shaped right (resources,
# jsonencode, references-not-literals, FILL, annotations). They would NOT catch a
# well-formed-but-WRONG dimension set, a mis-wired availability formula, or a
# governance row that silently dropped a table or a service. These guards assert
# the substance: the specific dimension families Service Connect actually
# publishes, the SLI arithmetic, and that both tables + both services are drawn.


def test_service_connect_target_metrics_use_a_published_dimension_set():
    """A17: the Service Connect TARGET-attributed metrics
    (HTTPCode_Target_2XX/4XX/5XX_Count, TargetResponseTime) must be queried on a
    PUBLISHED dimension set, else they render 'no data' and FILL cannot rescue
    them (FILL fills gaps in a metric that resolves, not one that matches
    nothing).

    AWS publishes these on `TargetDiscoveryName` alone OR on
    `TargetDiscoveryName, ServiceName, ClusterName` where ServiceName is the
    CALLING (client) service. The set `(ClusterName, ServiceName=gate,
    TargetDiscoveryName)` -- pairing a target metric with the gate's OWN
    ServiceName -- is NOT published. This guard fails if any target-metric source
    array names ServiceName while using TargetDiscoveryName (the wrong shape the
    reviewer flagged), and passes only when the target metrics stand on
    TargetDiscoveryName without a gate ServiceName.

    Ref: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/available-metrics.html
    """
    text = _strip_comments(_all_dashboard_text())
    target_metrics = (
        "HTTPCode_Target_2XX_Count",
        "HTTPCode_Target_4XX_Count",
        "HTTPCode_Target_5XX_Count",
    )
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("["):
            continue
        # Only the ECS Service Connect target series (not the ALB ones, which
        # legitimately pair TargetGroup with LoadBalancer).
        if '"AWS/ECS"' not in stripped:
            continue
        names_here = [m for m in target_metrics if f'"{m}"' in stripped]
        # TargetResponseTime on AWS/ECS is also a target metric.
        if '"TargetResponseTime"' in stripped:
            names_here.append("TargetResponseTime")
        if not names_here:
            continue
        assert '"TargetDiscoveryName"' in stripped, (
            f"ECS target metric {names_here} must query TargetDiscoveryName: {stripped!r}"
        )
        # Must NOT also carry ServiceName -- that would be the unpublished
        # gate-ServiceName shape (or force a client ServiceName we can't rely on
        # for a client-only Service Connect config).
        assert '"ServiceName"' not in stripped, (
            f"ECS target metric {names_here} must not pair TargetDiscoveryName with "
            f"ServiceName (unpublished dimension set): {stripped!r}"
        )


def test_service_connect_requestcount_uses_server_side_set():
    """The inbound RequestCount (server-side) uses the published
    `DiscoveryName, ServiceName, ClusterName` set (ServiceName = the gate server),
    NOT a TargetDiscoveryName. This is the counterpart to the target-metric guard
    and keeps the two families from being swapped.
    """
    text = _strip_comments(_all_dashboard_text())
    found = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("[") or '"AWS/ECS"' not in stripped:
            continue
        if '"RequestCount"' in stripped:
            found = True
            assert '"DiscoveryName"' in stripped and '"ServiceName"' in stripped, (
                f"Service Connect RequestCount must use DiscoveryName+ServiceName: {stripped!r}"
            )
            assert "local.gate_service_name" in stripped, (
                f"Service Connect RequestCount is published with ServiceName = the "
                f"SERVER (the gate), not the client: {stripped!r}"
            )
            assert '"TargetDiscoveryName"' not in stripped, (
                f"Service Connect RequestCount is a server-side metric and must not "
                f"use TargetDiscoveryName: {stripped!r}"
            )
    assert found, "the Service Connect RequestCount series was not found"


def test_availability_formula_divides_5xx_by_request_count():
    """R59: gateway availability is 1 - (Target_5XX + ELB_5XX)/RequestCount.

    Asserts the availability SLI expression combines BOTH 5xx sources over
    RequestCount (via the FILLed ids), not something structurally-plausible but
    arithmetically wrong. Checked on both the time-series and single-value forms.
    """
    text = _strip_comments(_all_dashboard_text())
    # The availability time series (av_*). The single-value attainment widget
    # was removed at the owner's request.
    for prefix in ("av",):
        pat = re.compile(
            rf"1\s*-\s*\(FILL\({prefix}_t5,0\)\s*\+\s*FILL\({prefix}_e5,0\)\)\s*/\s*"
            rf"IF\(\(FILL\({prefix}_rc,0\)\)\s*>\s*0",
        )
        assert pat.search(text), (
            f"availability ({prefix}) must be 1-(target5xx+ELB5xx)/RequestCount"
        )
    # And the ids must bind to the right metrics: t5->Target_5XX, e5->ELB_5XX,
    # rc->RequestCount on the ALB.
    assert re.search(r'"HTTPCode_Target_5XX_Count".*id = "av_t5"', text), (
        "av_t5 must bind to HTTPCode_Target_5XX_Count"
    )
    assert re.search(r'"HTTPCode_ELB_5XX_Count".*id = "av_e5"', text), (
        "av_e5 must bind to HTTPCode_ELB_5XX_Count"
    )
    assert re.search(r'"RequestCount".*id = "av_rc"', text), (
        "av_rc must bind to ALB RequestCount"
    )


def test_fail_closed_rate_denominator_is_decisions_plus_fail_closed():
    """R59: per-team fail-closed rate = fc / (pass + approve + block + fc).

    A fail-closed writes no decision line, so the denominator is the three
    decision outcomes for the team plus the team's fail-closed count. Assert the
    expression sums exactly those four FILLed ids in the divisor and the fc id in
    the numerator, per team index.
    """
    text = _strip_comments(_all_dashboard_text())
    # The expression is built in a for-comprehension, so the team index is the
    # literal interpolation ${ti}, not a resolved number. Match that form, with
    # the denominator summing exactly pass+approve+block+fc, all FILLed.
    pat = re.compile(
        r"100\s*\*\s*FILL\(fr_fc_\$\{ti\},0\)\s*/\s*IF\(\(FILL\(fr_p_\$\{ti\},0\)\s*\+\s*"
        r"FILL\(fr_a_\$\{ti\},0\)\s*\+\s*FILL\(fr_b_\$\{ti\},0\)\s*\+\s*FILL\(fr_fc_\$\{ti\},0\)"
    )
    assert pat.search(text), (
        "per-team fail-closed rate must be fc / (pass+approve+block+fc) with all "
        "four terms FILLed"
    )
    # Bind the ids: fr_p->Outcome_pass, fr_a->Outcome_approve, fr_b->Outcome_block,
    # fr_fc->FailClosedByTeam.
    assert re.search(r'"Outcome_pass".*id = "fr_p_', text), "fr_p must bind Outcome_pass"
    assert re.search(r'"Outcome_approve".*id = "fr_a_', text), "fr_a must bind Outcome_approve"
    assert re.search(r'"Outcome_block".*id = "fr_b_', text), "fr_b must bind Outcome_block"
    assert re.search(r'"FailClosedByTeam".*id = "fr_fc_', text), (
        "fr_fc must bind FailClosedByTeam"
    )


def test_both_dynamodb_tables_and_both_services_are_referenced():
    """R58a: the platform row draws BOTH DynamoDB tables and BOTH ECS services.

    A structural guard would pass even if a table or a service were quietly
    dropped. Assert each of the four provenance locals is referenced in the
    dashboard widgets (comment-stripped, so a mention in prose does not count).
    """
    text = _strip_comments(_all_dashboard_text())
    # Per metric family, not anywhere in the text: a reference surviving in one
    # widget must not mask the same table or service vanishing from another.
    families = {
        '"ThrottledRequests"': ("local.approvals_table", "local.audit_table"),
        '"CPUUtilization"': ("local.gate_service_name", "local.litellm_service_name"),
        '"MemoryUtilization"': ("local.gate_service_name", "local.litellm_service_name"),
        '"LiveTaskCount"': ("local.gate_service_name", "local.litellm_service_name"),
    }
    for metric, refs in families.items():
        lines = [line for line in text.splitlines() if metric in line]
        assert lines, f"no {metric} series in the dashboard (R58a)"
        for ref in refs:
            assert any(ref in line for line in lines), (
                f"{metric} never draws {ref} -- a table or service is missing "
                f"from the platform row (R58a)"
            )


def test_unattributed_fail_closed_uses_total_minus_per_team():
    """A17: null-team fail-closed blocks are still counted. The governance row
    computes unattributed = max(total FailClosed - sum(per-team), 0), reading the
    UNdimensioned FailClosed total so a team=null block is not silently dropped.
    """
    text = _strip_comments(_all_dashboard_text())
    # The unattributed expression subtracts the per-team FILLed sum from the total
    # FailClosed (mfct) and floors at 0.
    assert re.search(r"IF\(\(FILL\(mfct,0\)\s*-\s*\(", text), (
        "unattributed fail-closed must be total FailClosed - sum(per-team), floored at 0"
    )
    # mfct must bind to the UNdimensioned FailClosed total (no team dimension on
    # that source line).
    m = re.search(r'\["\$\{var\.project_name\}/gate",\s*"FailClosed",[^\]]*id = "mfct"', text)
    assert m, "the unattributed total must read the undimensioned FailClosed metric"
    assert '"team"' not in m.group(0), (
        "the FailClosed total for unattributed math must be undimensioned"
    )


def test_no_max_of_a_series_and_a_scalar():
    """CloudWatch rejects MAX([series, scalar]).

    Measured with GetMetricData against the live account: `MAX([FILL(m,0), 1])`
    fails with "Unsupported operand type(s) for MAX: Array[TimeSeries, Scalar]".
    MAX over an array accepts time series only. A dashboard using it applies
    cleanly and then renders an error in every widget that divides by a floored
    count. Floors are written IF(x > 0, x, 1) instead, which was accepted.
    """
    text = _strip_comments(_all_dashboard_text())
    assert "MAX([" not in text, (
        "MAX([...]) mixing a series and a scalar is rejected by CloudWatch; "
        "floor with IF(x > 0, x, floor) instead"
    )


def test_section_headers_are_four_words_or_fewer():
    """Owner's rule: section headers are labels, four words at most.

    The text widgets that open each row carry only a `## ` heading; longer prose
    belongs in DESIGN.md, not on the dashboard.
    """
    raw = _all_dashboard_text_raw()
    headers = re.findall(r"^\s*(?:markdown\s*=\s*\")?##\s+([^\"\n]+)", raw, re.M)
    assert len(headers) >= 6, f"expected six section headers, found {headers!r}"
    for header in headers:
        words = header.replace(",", " ").split()
        assert len(words) <= 4, f"section header too long ({len(words)} words): {header!r}"


def test_no_widget_title_repeats_the_sli_label():
    """Inside the service-levels section, "SLI" in a title is redundant."""
    text = _strip_comments(_all_dashboard_text())
    titles = re.findall(r'title\s*=\s*"([^"]*)"', text)
    assert titles, "no widget titles found"
    offenders = [t for t in titles if t.upper().startswith("SLI")]
    assert not offenders, f"titles repeat the section label: {offenders!r}"
