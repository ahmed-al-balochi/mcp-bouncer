"""Static guards for the CloudWatch dashboard and its metric filters.
The HCL is read as text and matched with narrow regexes. To avoid matching a
word in a comment, helpers strip `#` comments before matching where it matters."""

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
    It does not understand a `#` inside a string literal, but no guarded HCL puts
    one there; markdown-body guards use the raw text instead and say so."""
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
    """Exactly one aws_cloudwatch_dashboard, body via jsonencode()."""
    text = _strip_comments(DASHBOARD_TF.read_text())
    header = re.search(r'resource\s+"aws_cloudwatch_dashboard"\s+"this"\s*\{', text)
    assert header, "no aws_cloudwatch_dashboard resource in dashboard.tf"
    # The body must be produced by jsonencode(...), not a raw heredoc string.
    assert re.search(r"dashboard_body\s*=\s*jsonencode\(", text), (
        "dashboard_body must be built with jsonencode()"
    )
    # Name derives from the project_name variable, not a literal.
    assert re.search(r"dashboard_name\s*=\s*var\.project_name", text), (
        "dashboard_name must come from var.project_name, not a literal"
    )


# --- no account id / region / arn / ip literal ----------------


def test_no_twelve_digit_account_id_anywhere():
    """No 12-digit AWS account id in any dashboard file (comments too)."""
    for p in (DASHBOARD_TF, WIDGETS_TF, SLI_TF):
        raw = p.read_text()
        # A 12-digit run not part of a longer number. Account ids are exactly 12.
        m = re.search(r"(?<!\d)\d{12}(?!\d)", raw)
        assert not m, f"a 12-digit account id appears in {p.name}: {m.group(0)!r}"


def test_no_literal_region_string():
    """No hardcoded region code (comments too). The region must always
    come from data.aws_region.current.region."""
    pat = re.compile(r"\b[a-z]{2}-[a-z]+-\d\b")
    for p in (DASHBOARD_TF, WIDGETS_TF, SLI_TF):
        raw = p.read_text()
        m = pat.search(raw)
        assert not m, f"a literal region string appears in {p.name}: {m.group(0)!r}"


def test_no_literal_arn():
    """No `arn:aws` literal; ARNs come from references (arn_suffix etc.)."""
    for p in (DASHBOARD_TF, WIDGETS_TF, SLI_TF):
        raw = p.read_text()
        assert "arn:aws" not in raw, f"a literal arn:aws appears in {p.name}"


def test_no_ip_literal():
    """No dotted-quad IP literal anywhere in the dashboard files."""
    pat = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    for p in (DASHBOARD_TF, WIDGETS_TF, SLI_TF):
        raw = p.read_text()
        m = pat.search(raw)
        assert not m, f"an IP literal appears in {p.name}: {m.group(0)!r}"


def test_region_is_the_data_source_reference():
    """The region is data.aws_region.current.region (provider 6.x attr)."""
    text = _all_dashboard_text()
    assert "data.aws_region.current.region" in text, (
        "the dashboard must take its region from data.aws_region.current.region"
    )


# --- governance metric filters key on $.event and use team, never caller/... -


def _metric_filter_block(text: str, resource_name: str) -> str:
    """Brace-matched body of a named aws_cloudwatch_log_metric_filter block.
    Returns the slice verbatim; the caller strips comments if it needs to avoid
    matching prose."""
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
    """The decision and fail-closed-per-team filters key on $.event and
    use team as their only dimension, never caller, tool or args_hash. Comments
    are stripped first so a mention in prose cannot flip the result."""
    text = _strip_comments(DASHBOARD_TF.read_text())

    # Each named filter that carries a team dimension must key on $.event and
    # must not name a forbidden field.
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
                f"{name} must not reference {forbidden!r} (cardinality/leak)"
            )


def test_no_forbidden_field_is_ever_a_dimension():
    """Caller, tool and args_hash never appear as a metric dimension.
    A `$.field` reference only shows up in a filter pattern or dimension, and the
    governance patterns use only $.event, $.classification and $.decision."""
    text = _all_dashboard_text()
    for forbidden in (r"\$\.caller", r"\$\.tool\b", r"\$\.args_hash"):
        m = re.search(forbidden, text)
        assert not m, f"a forbidden JSON field {forbidden!r} is referenced as a dimension"


# --- sparse metrics are wrapped in FILL -------------------------------------


def test_sparse_error_metrics_are_filled():
    """Metrics that may never fire on a healthy stack are FILLed to 0, so a
    quiet minute reads 0 rather than 'no data'. Each known-sparse metric must be
    a hidden source behind a FILL expression, never a bare visible series."""
    text = _all_dashboard_text()
    assert "FILL(" in text, "no FILL() used at all, so sparse metrics would read 'no data'"

    # These metrics fire only on error or quiet paths, so each must be a hidden
    # (visible = false) source whose visible rendering is the FILLed expression.
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
        # Inspect only widget source-array lines (they start with `[`), not the
        # metric-filter definition lines, so this does not false-positive on the
        # filter that emits the metric.
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
    """FILL and divide-by-zero: the output:input ratio FILLs and floors the
    divisor. A ratio over a quiet minute must read 0, not error, so the
    denominator is IF(x > 0, x, 1), not MAX (see test_no_max_of_a_series...)."""
    text = _all_dashboard_text()
    assert re.search(
        r"FILL\(tr_out,\s*0\)\s*/\s*IF\(\(FILL\(tr_in,\s*0\)\)\s*>\s*0,\s*FILL\(tr_in,\s*0\),\s*1\)",
        text,
    ), (
        "the token ratio SLI must FILL both series and floor the divisor at 1"
    )


# --- every SLI with a target carries an annotation from locals --------------


def test_sli_targets_live_in_one_locals_block():
    """All targets are in one locals block, marked illustrative/provisional."""
    text = DASHBOARD_TF.read_text()  # raw: we want to read the comment too
    assert re.search(r"sli_targets\s*=\s*\{", text), "no sli_targets locals block"
    # The comment must mark targets illustrative and the latency ones provisional.
    assert "illustrative" in text.lower(), "sli_targets must be documented as illustrative"
    assert "provisional" in text.lower(), "the latency targets must be marked PROVISIONAL"


def test_every_sli_with_a_target_annotates_it_from_locals():
    """Each SLI target is drawn as a horizontal annotation whose value comes
    from local.sli_targets, never a bare number, and the five targeted SLIs are
    each present."""
    text = _strip_comments(_all_dashboard_text())

    # Every horizontal annotation value must reference local.sli_targets.
    ann_values = re.findall(r"annotations\s*=\s*\{.*?horizontal\s*=\s*\[(.*?)\]", text, re.S)
    assert ann_values, "no horizontal annotations found, so SLI targets are not drawn"
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
            f"SLI target {key} is never referenced by an annotation"
        )


def test_token_ratio_sli_has_no_target_annotation():
    """The output:input ratio is shown WITHOUT a target line."""
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
        "the output:input ratio SLI must not draw a target annotation"
    )


# --- absent-indicators text names all four ----------------------------------


def test_absent_indicators_text_names_all_four():
    """The absences text names all four absent indicators with a reason.
    Reads the raw markdown body, since the content is prose and stripping could
    truncate the `##` headers."""
    text = _all_dashboard_text_raw().lower()
    # The four indicators the absences text must name.
    assert "time to first token" in text, "absences text must name time to first token"
    assert "fallback" in text, "absences text must name fallback engagement"
    assert "cache hit" in text, "absences text must name cache hit rate"
    assert "cost" in text, "absences text must name cost in currency"
    # And a reason for each absence.
    assert "non-streaming" in text or "no streaming" in text or "not stream" in text
    assert "token" in text  # tokens shown instead of cost


def test_model_indicators_documented_platform_wide():
    """A visible text widget must state that model indicators are
    platform-wide. Checks the markdown widget bodies only, since a mention buried
    in a `#` comment would not be shown to a viewer."""
    raw = _all_dashboard_text_raw()
    # Keep only markdown-body lines: the single-line `markdown = "..."` form or
    # lines inside a `markdown = <<-EOT ... EOT` heredoc, tracked by a state
    # machine.
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
        "a visible text widget must state model-call indicators are platform-wide"
    )


# --- the existing FailClosed filter is unchanged ----------------------------


def test_existing_fail_closed_filter_is_unchanged():
    """The existing fail_closed metric filter in monitoring.tf keeps its exact
    pattern and metric name, so the dashboard must not have altered it.
    Comment-stripped so the assertion is on the directive, not the prose."""
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
    """The dashboard's per-team filter uses a different metric name so it cannot
    clobber the FailClosed metric the alarm reads. It must be FailClosedByTeam,
    and no dashboard.tf filter may emit a metric named exactly FailClosed."""
    text = _strip_comments(DASHBOARD_TF.read_text())
    # Find every metric_transformation name in dashboard.tf.
    names = re.findall(r'name\s*=\s*"([A-Za-z0-9_]+)"', text)
    # FailClosedByTeam must exist; the dashboard only reads FailClosed by string
    # in a widget, never redefines it as a filter output.
    assert "FailClosedByTeam" in names, "the per-team fail-closed filter must exist"
    # Ensure no metric_transformation emits exactly "FailClosed" in dashboard.tf.
    for block_name in ("decision_by_classification", "decision_by_outcome",
                       "unknown_denials", "auth_rejected", "fail_closed_by_team"):
        block = _metric_filter_block(text, block_name)
        transform_names = re.findall(r'name\s*=\s*"([A-Za-z0-9_]+)"', block)
        assert "FailClosed" not in transform_names, (
            f"{block_name} must not emit a metric named exactly FailClosed (collides with monitoring.tf)"
        )


# Substantive-content guards. The structural guards above prove the dashboard is
# shaped right but would not catch a well-formed but wrong dimension set, a
# mis-wired formula, or a dropped table or service. These assert that substance.


def test_service_connect_target_metrics_use_a_published_dimension_set():
    """Target-attributed metrics must query a published dimension set, or
    they render 'no data' and FILL cannot rescue a metric that matches nothing.
    Pairing a target metric with the gate's own ServiceName is not published."""
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
        # Only the ECS Service Connect target series, not the ALB ones.
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
        # Must not also carry ServiceName, which would be the unpublished
        # gate-ServiceName shape.
        assert '"ServiceName"' not in stripped, (
            f"ECS target metric {names_here} must not pair TargetDiscoveryName with "
            f"ServiceName (unpublished dimension set): {stripped!r}"
        )


def test_service_connect_requestcount_uses_server_side_set():
    """The inbound RequestCount (server-side) uses the published DiscoveryName,
    ServiceName, ClusterName set with ServiceName as the gate server, not a
    TargetDiscoveryName, keeping the two metric families from being swapped."""
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
    """Gateway availability is 1 - (Target_5XX + ELB_5XX)/RequestCount.
    Asserts the SLI expression combines both 5xx sources over RequestCount via
    the FILLed ids, not something plausible but arithmetically wrong."""
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
    """Per-team fail-closed rate = fc / (pass + approve + block + fc).
    A fail-closed writes no decision line, so the denominator is the three
    decision outcomes plus the team's fail-closed count, all FILLed."""
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
    """R58a: the platform row draws both DynamoDB tables and both ECS services.
    A structural guard would pass even if one were dropped, so assert each of the
    four provenance locals is referenced (comment-stripped, so prose does not count)."""
    text = _strip_comments(_all_dashboard_text())
    # Checked per metric family, so a reference surviving in one
    # widget must not mask the same table or service vanishing from another.
    families = {
        '"ThrottledRequests"': ("local.approvals_table", "local.audit_table"),
        '"CPUUtilization"': ("local.gate_service_name", "local.litellm_service_name"),
        '"MemoryUtilization"': ("local.gate_service_name", "local.litellm_service_name"),
        '"LiveTaskCount"': ("local.gate_service_name", "local.litellm_service_name"),
    }
    for metric, refs in families.items():
        lines = [line for line in text.splitlines() if metric in line]
        assert lines, f"no {metric} series in the dashboard"
        for ref in refs:
            assert any(ref in line for line in lines), (
                f"{metric} never draws {ref}: a table or service is missing "
                f"from the platform row"
            )


def test_unattributed_fail_closed_uses_total_minus_per_team():
    """Null-team fail-closed blocks are still counted. The governance row
    computes unattributed = max(total FailClosed - sum(per-team), 0), reading the
    undimensioned FailClosed total so a team=null block is not dropped."""
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
    """CloudWatch rejects MAX([series, scalar]): MAX over an array accepts time
    series only, so a dashboard using it renders an error in every widget that
    divides by a floored count. Floors are written IF(x > 0, x, 1) instead."""
    text = _strip_comments(_all_dashboard_text())
    assert "MAX([" not in text, (
        "MAX([...]) mixing a series and a scalar is rejected by CloudWatch; "
        "floor with IF(x > 0, x, floor) instead"
    )


def test_section_headers_are_four_words_or_fewer():
    """Owner's rule: section headers are labels, four words at most. The text
    widgets that open each row carry only a `## ` heading. Longer prose belongs
    in DESIGN.md."""
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
