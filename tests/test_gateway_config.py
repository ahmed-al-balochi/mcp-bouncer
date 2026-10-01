"""Static guards for the LLM gateway.

These tests assert on committed artefacts, not a running gateway: litellm.yaml
and the terraform/app HCL text. Each one fails if the property it guards breaks.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
LITELLM_CONFIG = REPO_ROOT / "gateway" / "litellm.yaml"
APP_TF_DIR = REPO_ROOT / "terraform" / "app"
VARIABLES_TF = APP_TF_DIR / "variables.tf"
ECS_TF = APP_TF_DIR / "ecs.tf"
ALB_TF = APP_TF_DIR / "alb.tf"
ACCESS_LOGS_TF = APP_TF_DIR / "access_logs.tf"


def _load_config() -> dict:
    # safe_load: the config is plain data, never Python objects.
    return yaml.safe_load(LITELLM_CONFIG.read_text())


def _terraform_default(var_name: str) -> str:
    """Return the string default of a variable in terraform/app/variables.tf.

    A narrow text parse, not a full HCL parser: it finds the variable block header
    then the first default line after it. These defaults are simple strings.
    """
    text = VARIABLES_TF.read_text()
    header = re.search(rf'variable\s+"{re.escape(var_name)}"\s*\{{', text)
    assert header, f"variable {var_name!r} not found in variables.tf"
    after = text[header.end() :]
    m = re.search(r'default\s*=\s*"([^"]*)"', after)
    assert m, f"no string default found for variable {var_name!r}"
    return m.group(1)


# --- litellm.yaml -----------------------------------------------------------


def test_every_model_targets_an_eu_bedrock_profile():
    """Layer 1 of EU-only: the model list names only bedrock/eu. models."""
    config = _load_config()
    models = config["model_list"]
    assert models, "model_list must not be empty"
    for entry in models:
        model = entry["litellm_params"]["model"]
        assert model.startswith("bedrock/eu."), (
            f"model {model!r} is not an EU Bedrock model (must start with 'bedrock/eu.')"
        )


def test_profile_id_matches_terraform_default():
    """The model the gateway calls must equal the profile IAM/endpoints authorise.

    The yaml's model id (minus the bedrock/ prefix) must equal the default of
    bedrock_inference_profile_id in variables.tf, so the two cannot drift apart.
    """
    config = _load_config()
    model = config["model_list"][0]["litellm_params"]["model"]
    profile_in_yaml = model.removeprefix("bedrock/")
    assert profile_in_yaml == _terraform_default("bedrock_inference_profile_id")


def test_region_is_an_environment_reference_not_a_literal():
    """The region is supplied at runtime, never hardcoded."""
    config = _load_config()
    region = config["model_list"][0]["litellm_params"]["aws_region_name"]
    assert region.startswith("os.environ/"), (
        f"aws_region_name must be an os.environ reference, got {region!r}"
    )


def test_master_key_is_an_environment_reference():
    """The master key is injected from Secrets Manager, never in the file."""
    config = _load_config()
    master_key = config["general_settings"]["master_key"]
    assert master_key.startswith("os.environ/"), (
        f"master_key must be an os.environ reference, got {master_key!r}"
    )


def test_no_sk_literal_anywhere_in_the_config():
    """No literal `sk-` key value leaked into the file.

    The generated key lives only in Secrets Manager; nothing in the config text
    may begin an sk- token.
    """
    text = LITELLM_CONFIG.read_text()
    # A whitespace/quote/colon boundary before sk- so a word like "task-" or a
    # url path cannot false-positive.
    assert not re.search(r'(^|[\s:"\'])sk-', text), "an sk- literal appears in litellm.yaml"


def test_bouncer_mcp_url_is_exact():
    """The gate URL is the Service Connect name with no trailing slash."""
    config = _load_config()
    url = config["mcp_servers"]["bouncer"]["url"]
    assert url == "http://gate:8000/mcp", f"bouncer MCP url must be exactly http://gate:8000/mcp, got {url!r}"


def test_bouncer_auth_is_bearer_with_a_nonempty_value():
    """bearer_token auth with a non-empty (deliberately invalid) value."""
    bouncer = _load_config()["mcp_servers"]["bouncer"]
    assert bouncer["auth_type"] == "bearer_token"
    assert isinstance(bouncer["auth_value"], str) and bouncer["auth_value"].strip(), (
        "auth_value must be a non-empty string so a token-less request is refused, not defaulted"
    )


def test_drop_params_is_true():
    """Sonnet 5 rejects temperature; drop_params must be on."""
    assert _load_config()["litellm_settings"]["drop_params"] is True


def test_message_logging_is_off():
    """Prompts and responses must not be logged."""
    assert _load_config()["litellm_settings"]["turn_off_message_logging"] is True


# --- Terraform static guards ------------------------------------------------


def _gate_service_block(text: str) -> str:
    """Return the body of the gate's `aws_ecs_service "this"` block.

    A brace-matched slice from the resource header, so nested blocks are included
    and the LiteLLM service block is not. A string-literal brace would miscount.
    """
    header = re.search(r'resource\s+"aws_ecs_service"\s+"this"\s*\{', text)
    assert header, 'aws_ecs_service "this" (the gate service) not found in ecs.tf'
    depth = 0
    start = header.end() - 1
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise AssertionError("unbalanced braces parsing the gate service block")


def test_gate_service_has_no_load_balancer_block():
    """The gate is internal-only, so its service has no load_balancer."""
    block = _gate_service_block(ECS_TF.read_text())
    assert not re.search(r'\bload_balancer\s*\{', block), (
        "the gate's aws_ecs_service must not have a load_balancer block"
    )


def test_no_target_group_targets_the_gate_port():
    """No aws_lb_target_group forwards to the gate's port 8000.

    Scans every target group block for the gate port as literal 8000 or the
    local.container_port reference; a match means the ALB was pointed at the gate.
    """
    text = "\n".join(
        p.read_text() for p in APP_TF_DIR.glob("*.tf")
    )
    # Either the literal gate port or the local that resolves to it. Kept in sync
    # with main.tf: if container_port stops being 8000 this literal must move too,
    # but the local.container_port arm catches the reference form regardless.
    gate_port_pat = re.compile(r'\bport\s*=\s*(?:8000\b|local\.container_port\b)')
    for m in re.finditer(r'resource\s+"aws_lb_target_group"\s+"[^"]+"\s*\{', text):
        start = m.end() - 1
        depth = 0
        body = ""
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    body = text[start : i + 1]
                    break
        assert not gate_port_pat.search(body), (
            "an aws_lb_target_group targets the gate port (8000 / local.container_port); "
            "the ALB must not reach the gate"
        )


# --- ALB gateway listener rule: exactly one MCP path opened -----------------


def _gateway_rule_block(text: str) -> str:
    """Return the body of the `aws_lb_listener_rule "gateway"` block from alb.tf.

    Same brace-matched slice as _gate_service_block, so nested condition and
    action blocks are included. A string-literal brace would miscount.
    """
    header = re.search(r'resource\s+"aws_lb_listener_rule"\s+"gateway"\s*\{', text)
    assert header, 'aws_lb_listener_rule "gateway" not found in alb.tf'
    depth = 0
    start = header.end() - 1
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise AssertionError("unbalanced braces parsing the gateway rule block")


def _gateway_path_values(block: str) -> list[str]:
    """Extract the quoted values of the rule's path_pattern list.

    Finds the path_pattern values list and returns every double-quoted string in
    it. Assumes the values are string literals, which they are.
    """
    m = re.search(r"path_pattern\s*\{.*?values\s*=\s*\[(.*?)\]", block, re.S)
    assert m, "no path_pattern values list found in the gateway rule"
    return re.findall(r'"([^"]*)"', m.group(1))


def test_gateway_rule_opens_tools_list_exactly():
    """The one MCP path opened is exactly /mcp-rest/tools/list."""
    values = _gateway_path_values(_gateway_rule_block(ALB_TF.read_text()))
    assert "/mcp-rest/tools/list" in values, (
        "the gateway rule must open /mcp-rest/tools/list for the agent preflight"
    )


def test_gateway_rule_does_not_open_the_whole_mcp_rest_prefix():
    """The rule must NOT wildcard the /mcp-rest prefix.

    A wildcard or a bare /mcp-rest prefix would expose tools/call and every other
    route. This inspects only committed literals, not ALB runtime matching.
    """
    values = _gateway_path_values(_gateway_rule_block(ALB_TF.read_text()))
    for v in values:
        assert "*" not in v, (
            f"gateway rule path {v!r} uses a wildcard; the MCP prefix must be "
            "matched exactly, never /mcp-rest/*"
        )
        # A value equal to the prefix (with or without a trailing slash) would
        # also over-open it.
        assert v.rstrip("/") != "/mcp-rest", (
            "gateway rule opens the bare /mcp-rest prefix; open only "
            "/mcp-rest/tools/list"
        )


def test_gateway_rule_does_not_open_tools_call():
    """/mcp-rest/tools/call must stay closed (404).

    tools/call would let any holder of the gateway key invoke tools directly,
    bypassing the model-in-the-loop path. A substring check on committed values.
    """
    values = _gateway_path_values(_gateway_rule_block(ALB_TF.read_text()))
    for v in values:
        assert "tools/call" not in v, (
            f"gateway rule path {v!r} opens tools/call; it must stay 404"
        )


# --- ALB access logs to S3 --------------------------------------------------


def _alb_resource_block(text: str) -> str:
    """Return the body of the `aws_lb "this"` block from alb.tf.

    Same brace-matched slice as the other block helpers, so the nested
    access_logs block is included. A string-literal brace would miscount.
    """
    header = re.search(r'resource\s+"aws_lb"\s+"this"\s*\{', text)
    assert header, 'aws_lb "this" not found in alb.tf'
    depth = 0
    start = header.end() - 1
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise AssertionError("unbalanced braces parsing the aws_lb block")


def test_alb_has_access_logs_enabled():
    """The ALB writes access logs to S3, and the block is enabled.

    A text/brace parse of committed HCL, not a plan: it proves enabled = true was
    written, not that AWS accepted it. It does not pin the bucket or prefix.
    """
    block = _alb_resource_block(ALB_TF.read_text())
    logs = re.search(r"access_logs\s*\{(.*?)\}", block, re.S)
    assert logs, "the ALB has no access_logs block"
    assert re.search(r"enabled\s*=\s*true", logs.group(1)), (
        "the ALB's access_logs block must set enabled = true"
    )


def test_alb_log_bucket_blocks_all_public_access():
    """The access-log bucket is not public.

    The bucket holds request metadata, so it must never be internet-readable. A
    text scan of access_logs.tf for the four public-access switches set true.
    """
    text = ACCESS_LOGS_TF.read_text()
    header = re.search(
        r'resource\s+"aws_s3_bucket_public_access_block"\s+"alb_logs"\s*\{', text
    )
    assert header, (
        "no aws_s3_bucket_public_access_block for the ALB log bucket"
    )
    # Slice to the block's close brace so we only read this resource's switches.
    depth = 0
    start = header.end() - 1
    block = ""
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                block = text[start : i + 1]
                break
    assert block, "unbalanced braces parsing the public_access_block resource"
    for switch in (
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
    ):
        assert re.search(rf"{switch}\s*=\s*true", block), (
            f"{switch} must be true so the ALB log bucket is not public"
        )


# --- gateway/Dockerfile -----------------------------------------------------


def test_gateway_image_patches_its_base_os_packages():
    """The thin gateway image must refresh the index and upgrade OS packages.

    The only remediation for an OS CVE in the Wolfi base is to patch it here. We
    assert apk update precedes apk upgrade, since a stale index patches nothing.
    """
    # Strip comments first. The reasoning above these directives names both
    # commands in prose, so searching the raw file would match the explanation,
    # not the instruction, and a deleted real `apk update` would stay undetected.
    text = "\n".join(
        line
        for line in (REPO_ROOT / "gateway" / "Dockerfile").read_text().splitlines()
        if not line.lstrip().startswith("#")
    )
    update = text.find("apk update")
    upgrade = text.find("apk upgrade")
    unpin = text.find("/etc/apk/world")
    assert update != -1, "gateway/Dockerfile must run `apk update`"
    assert upgrade != -1, "gateway/Dockerfile must run `apk upgrade`"
    assert update < upgrade, (
        "`apk update` must come before `apk upgrade`: without a fresh index the "
        "upgrade silently patches nothing"
    )
    # The base image pins exact versions in /etc/apk/world and apk upgrade honours
    # them, so without removing those pins the upgrade is a no-op that still
    # reports success. Measured on the real base image, not inferred.
    assert unpin != -1 and unpin < upgrade, (
        "gateway/Dockerfile must unpin the affected packages in /etc/apk/world "
        "before `apk upgrade`, or the upgrade patches nothing"
    )


def test_gateway_image_drops_back_to_the_unprivileged_uid():
    """Patching needs root at build time; the runtime must not keep it.

    Guards the ordering: the last USER directive must be the unprivileged one, so
    a later root step cannot leave the container running as root.
    """
    text = (REPO_ROOT / "gateway" / "Dockerfile").read_text()
    users = re.findall(r"^USER\s+(\S+)", text, re.MULTILINE)
    assert users, "gateway/Dockerfile must set USER"
    assert users[-1].startswith("10001"), (
        f"the final USER must be the unprivileged uid, found {users[-1]!r}"
    )
