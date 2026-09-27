"""Static guards for the LLM gateway (R43, R51-R57, D6.10).

These tests assert on committed artefacts, not on a running gateway:

  * ``gateway/litellm.yaml`` -- the config baked into the thin image; and
  * ``terraform/app`` HCL text -- for the two properties a careless edit could
    silently break (the gate's EU-only routing agreement, and the gate no longer
    being an ALB target).

They are deliberately cheap and offline. PyYAML is available in the dev venv and
is the natural way to read the config; the Terraform files are read as text
because python-hcl2 is not installed and this suite adds no dependency (R44) --
the regexes below are commented with their limits.

Each test is written so that breaking the property it guards makes it fail; that
was checked by editing a temp copy of the guarded file, never the real one.
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


def _load_config() -> dict:
    # safe_load: the config is plain data, never Python objects.
    return yaml.safe_load(LITELLM_CONFIG.read_text())


def _terraform_default(var_name: str) -> str:
    """Return the string default of a variable in terraform/app/variables.tf.

    A narrow text parse, not a full HCL parser: it finds the `variable "<name>"`
    block header, then the first `default = "<value>"` line after it. Adequate
    because these variables have simple string defaults on their own line; it
    would miss a default expressed as an expression or across lines, which these
    are not.
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
    """Layer 1 of EU-only (R53): the model list names only `bedrock/eu.` models."""
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

    The yaml's model id (minus the `bedrock/` prefix) must equal the default of
    bedrock_inference_profile_id in variables.tf, so LiteLLM's routing and the
    ARNs Terraform looks up cannot drift apart (R53).
    """
    config = _load_config()
    model = config["model_list"][0]["litellm_params"]["model"]
    profile_in_yaml = model.removeprefix("bedrock/")
    assert profile_in_yaml == _terraform_default("bedrock_inference_profile_id")


def test_region_is_an_environment_reference_not_a_literal():
    """The region is supplied at runtime, never hardcoded (R2, R3)."""
    config = _load_config()
    region = config["model_list"][0]["litellm_params"]["aws_region_name"]
    assert region.startswith("os.environ/"), (
        f"aws_region_name must be an os.environ reference, got {region!r}"
    )


def test_master_key_is_an_environment_reference():
    """The master key is injected from Secrets Manager, never in the file (R55)."""
    config = _load_config()
    master_key = config["general_settings"]["master_key"]
    assert master_key.startswith("os.environ/"), (
        f"master_key must be an os.environ reference, got {master_key!r}"
    )


def test_no_sk_literal_anywhere_in_the_config():
    """No literal `sk-` key value leaked into the file (R2, R55).

    The generated `sk-` key lives only in Secrets Manager; nothing in the config
    text may begin an `sk-` token.
    """
    text = LITELLM_CONFIG.read_text()
    # A whitespace/quote/colon boundary before `sk-` so a word like "task-" or a
    # url path cannot false-positive; matches a real key value or yaml scalar.
    assert not re.search(r'(^|[\s:"\'])sk-', text), "an sk- literal appears in litellm.yaml"


def test_bouncer_mcp_url_is_exact():
    """The gate URL is the Service Connect name with no trailing slash (D4.16)."""
    config = _load_config()
    url = config["mcp_servers"]["bouncer"]["url"]
    assert url == "http://gate:8000/mcp", f"bouncer MCP url must be exactly http://gate:8000/mcp, got {url!r}"


def test_bouncer_auth_is_bearer_with_a_nonempty_value():
    """bearer_token auth with a non-empty (deliberately invalid) value (R54)."""
    bouncer = _load_config()["mcp_servers"]["bouncer"]
    assert bouncer["auth_type"] == "bearer_token"
    assert isinstance(bouncer["auth_value"], str) and bouncer["auth_value"].strip(), (
        "auth_value must be a non-empty string so a token-less request is refused, not defaulted"
    )


def test_drop_params_is_true():
    """Sonnet 5 rejects temperature; drop_params must be on (D6.5)."""
    assert _load_config()["litellm_settings"]["drop_params"] is True


def test_message_logging_is_off():
    """Prompts and responses must not be logged (R56)."""
    assert _load_config()["litellm_settings"]["turn_off_message_logging"] is True


# --- Terraform static guards ------------------------------------------------


def _gate_service_block(text: str) -> str:
    """Return the body of the gate's `aws_ecs_service "this"` block.

    A brace-matched slice from the resource header, so nested blocks are included
    and the LiteLLM service block (a different resource) is not. Not a full HCL
    parser, but brace counting is robust to the formatting here (terraform fmt
    normalises it) -- its limit is that a stray brace inside a string literal
    would miscount, which none of these blocks contain.
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
    """R52: the gate is internal-only, so its service has no load_balancer."""
    block = _gate_service_block(ECS_TF.read_text())
    assert not re.search(r'\bload_balancer\s*\{', block), (
        "the gate's aws_ecs_service must not have a load_balancer block (R52)"
    )


def test_no_target_group_targets_the_gate_port():
    """R52: no aws_lb_target_group forwards to the gate's port 8000.

    Scans every aws_lb_target_group block for the gate port expressed either as
    the literal ``8000`` or as the ``local.container_port`` reference (main.tf
    defines ``container_port = 8000`` for the gate and ``litellm_port = 4000``
    for the gateway; the LiteLLM target group uses ``local.litellm_port``). A
    match on either form means a target group was pointed at the gate -- exactly
    the ALB-reaches-gate path R52 forbids. Limit: a target group whose port came
    from some other variable/expression would be missed, but this stack only
    ever writes a target-group port as the literal 4000 or ``local.litellm_port``
    for the gateway; the gate's port is the literal 8000 / ``local.container_port``
    guarded here, and the gate has no target group at all.
    """
    text = "\n".join(
        p.read_text() for p in APP_TF_DIR.glob("*.tf")
    )
    # Either the literal gate port or the local that resolves to it. Kept in sync
    # with main.tf: if container_port stops being 8000 this test's literal must
    # move too, but the local.container_port arm catches the reference form
    # regardless of the literal's value.
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
            "the ALB must not reach the gate (R52)"
        )
