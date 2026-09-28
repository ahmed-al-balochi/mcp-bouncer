"""A one-shot LLM demo agent that drives the gate through the LiteLLM gateway.

Where `demo/agent.py` speaks MCP to the gate directly (the no-AWS local demo),
this agent plays the real deployed path: it calls the gateway's
OpenAI-compatible `/v1/chat/completions` with a single `bouncer` MCP tool and
forwards its own gate token, exactly the request shape the 2026-09-27 spike
proved end to end (DECISIONS D6.5, D6.17). LiteLLM presents the OpenAI API for
every backend and translates to Bedrock Converse, so the `openai` SDK is the
right client even though the model is Claude on Bedrock -- the agent never talks
to Bedrock itself (D6.17).

Each run is a fresh, single-turn conversation. That is deliberate: "retry after
approval" in the park -> notify -> retry loop is simply running the same prompt
again, which is the spike's proven shape and tests the gate rather than the
model's memory (D6.17).

This agent needs AWS (a live Bedrock-backed gateway) by nature, so it is behind
the optional `llm-demo` extra and the gate image never installs it. The offline
tests in `tests/test_llm_agent.py` point the real SDK at a stdlib fake server,
so nothing here is exercised against a real gateway until the live G3 run.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Sequence, cast

import openai

# The gate token the agent forwards is the SAME variable demo/agent.py reads, so
# an operator who set up the local demo already has it (D6.17).
TOKEN_ENV = "BOUNCER_DEMO_TOKEN"
GATEWAY_URL_ENV = "BOUNCER_GATEWAY_URL"
GATEWAY_KEY_ENV = "BOUNCER_GATEWAY_KEY"

# The terraform outputs an operator runs to obtain each value. Named in error
# messages so a missing variable is actionable without ever printing the value.
GATEWAY_URL_SOURCE = "terraform output gateway_openai_base_url"
GATEWAY_KEY_SOURCE = "terraform output litellm_master_key_get_command (then run it)"
TOKEN_SOURCE = "terraform output tokens_get_command (then run it)"

DEFAULT_MODEL = "claude-sonnet-5-eu"

# The gate token rides in the MCP tool's own headers under LiteLLM's
# `x-mcp-{server_label}-{header}` forwarding convention, so LiteLLM strips the
# prefix and passes `Authorization: Bearer <token>` to the gate on the tool
# call. This is exactly where the spike put it and what worked end to end
# (.venv-litellm/spike/ask.py:12 -- inside the tool's `headers`, NOT as a
# top-level request header). The request's own Authorization header is the
# LiteLLM master key, a different credential (ask.py:15).
GATE_TOKEN_HEADER = "x-mcp-bouncer-authorization"

# Short and load-bearing: the retry determinism the park/notify/retry loop needs
# rests on THIS instruction, not on temperature -- Sonnet 5 rejects `temperature`
# outright (ValidationException "deprecated for this model", D6.5), so the SDK
# sends none and the prompt is the only lever. Telling the model to relay the
# gate's message verbatim and never work around a refusal is what makes the
# demo's approval id and command reach the human unaltered (R10, R47).
SYSTEM_PROMPT = (
    "You operate a wiki through the provided tools. Use them when asked. "
    "If a tool call is refused or parked, report the gate's message to the user "
    "verbatim, including any approval id and the exact command to run, and do "
    "not try to work around it. When asked to retry, call the tool again with "
    "exactly the same arguments."
)

# Client timeout, in seconds. Chosen against the mesh limits (D6.10): Service
# Connect's per-request timeout is 120 s and the ALB idle timeout is 300 s. A
# single completion turn (one model round plus at most one tool round through
# the gate) should finish well inside 120 s, so we set the client below the
# tightest mesh limit: at 110 s the SDK raises a clean APITimeoutError just
# before Service Connect would cut the request at 120 s, turning an opaque
# mid-stream truncation into a clear local error. The SDK default (600 s) would
# instead hang long past the point the mesh has already given up.
REQUEST_TIMEOUT_SECONDS = 110.0


class ConfigError(Exception):
    """A required environment variable is missing or a flag combination is refused.

    Carries a ready-to-print, actionable message (R47). Raised by pure config
    loading so `main` stays thin and the failure is unit-testable without a
    process exit.
    """


def load_config(env: dict[str, str], *, require_gate_token: bool) -> dict[str, str]:
    """Resolve gateway URL, gateway key and (optionally) the gate token from env.

    Config comes from the environment ONLY (D6.17) so nothing environment-specific
    is ever a committed default. Each missing variable raises `ConfigError` naming
    the variable and the terraform output that yields it -- never the value, so a
    secret cannot leak through an error message (R2, R47, the redaction rule).

    `require_gate_token` is False only under `--without-gate-token`, which exists
    solely to demonstrate A16 (an agent with no gate token runs no tool).
    """
    url = env.get(GATEWAY_URL_ENV, "").strip()
    if not url:
        raise ConfigError(
            f"missing {GATEWAY_URL_ENV}: set it to the gateway's OpenAI base URL "
            f"(ends in /v1). Obtain it with: {GATEWAY_URL_SOURCE}."
        )

    key = env.get(GATEWAY_KEY_ENV, "").strip()
    if not key:
        raise ConfigError(
            f"missing {GATEWAY_KEY_ENV}: set it to the LiteLLM master key. "
            f"Obtain it with: {GATEWAY_KEY_SOURCE}."
        )

    config = {"url": url, "key": key}

    token = env.get(TOKEN_ENV, "").strip()
    if require_gate_token and not token:
        raise ConfigError(
            f"missing {TOKEN_ENV}: the gate requires this agent's own bearer "
            "token, forwarded to the gate on every tool call; without it no tool "
            f"runs (A16). Obtain a token with: {TOKEN_SOURCE}. To deliberately "
            "run WITHOUT a gate token (to demonstrate A16), pass "
            "--without-gate-token."
        )
    # An empty token when not required is intentional: the tool block will carry
    # no gate-token header at all (see build_request).
    config["token"] = token
    return config


def build_request(
    *, model: str, prompt: str, gate_token: str, with_gate_token: bool
) -> dict[str, Any]:
    """Build the kwargs passed to `chat.completions.create`, minus the client.

    Pure so a test can assert the exact request the SDK will send. The MCP tool
    dict is a LiteLLM extension outside the SDK's ChatCompletionToolParam types;
    the plain (non-parsing) create() path builds the body with maybe_transform,
    which keeps keys it has no type for, so the dict reaches the wire unchanged --
    proven by tests/test_llm_agent.py's wire-shape test rather than by the SDK's
    types -- and we pass it through with a typed cast and this comment.

    The gate token goes ONLY inside the tool's `headers`, exactly as the spike
    did (ask.py:12). When `with_gate_token` is False the header is omitted
    entirely -- LiteLLM then forwards its deliberately-invalid default credential,
    the gate returns 401, LiteLLM silently drops the tools and the model answers
    with none (D6.5). That silent drop is the whole point of --without-gate-token:
    it demonstrates A16.

    No `temperature` is set: Sonnet 5 rejects it (D6.5). Retry determinism rests
    on SYSTEM_PROMPT instead.
    """
    tool: dict[str, Any] = {
        "type": "mcp",
        "server_label": "bouncer",
        "server_url": "litellm_proxy/mcp/bouncer",
        "require_approval": "never",
    }
    if with_gate_token:
        tool["headers"] = {GATE_TOKEN_HEADER: f"Bearer {gate_token}"}

    return {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        # cast: the MCP tool block is a LiteLLM extension; see the docstring.
        "tools": cast(Any, [tool]),
    }


def redact(text: str, secrets: Sequence[str]) -> str:
    """Replace any secret substring in `text` with a fixed marker.

    Defence in depth for the rule that the API key and gate token must NEVER
    appear in stdout, stderr, exceptions or logs -- including when the server
    echoes request data back in an error body. We do not rely on the SDK keeping
    secrets out of its exception messages; we strip them from any text we print.
    """
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***redacted***")
    return text


def format_api_error(error: "openai.APIError", secrets: Sequence[str]) -> str:
    """Turn an SDK exception into one redacted, actionable stderr line.

    Covers the SDK's error hierarchy: APIStatusError subclasses
    (AuthenticationError 401, BadRequestError 400 e.g. an unknown model,
    and other APIStatusError) carry an HTTP status and the server's message;
    APIConnectionError / APITimeoutError do not. We surface the status when there
    is one and always redact the key and token (R47, redaction rule).
    """
    status = getattr(error, "status_code", None)
    message = getattr(error, "message", None) or str(error)
    if status is not None:
        line = f"gateway error (HTTP {status}): {message}"
    else:
        line = f"gateway request failed: {message}"
    return redact(line, secrets)


def run(
    config: dict[str, str],
    *,
    model: str,
    prompt: str,
    with_gate_token: bool,
    out=None,
    err=None,
) -> int:
    """Send one completion and print the model's final message, or a clean error.

    `max_retries=0` (D6.17): an auto-retry would resend a turn that may carry a
    destructive call. That is safe because grants are one-shot, but a silent
    resend muddies the A13 park/approve/retry story, so we disable it and let the
    caller re-run explicitly. `timeout` is explicit (see REQUEST_TIMEOUT_SECONDS).

    `out`/`err` resolve to the live `sys.stdout`/`sys.stderr` at call time (not
    def time), so a test that swaps the streams sees the output.
    """
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    secrets = [config["key"], config["token"]]
    client = openai.OpenAI(
        base_url=config["url"],
        api_key=config["key"],
        max_retries=0,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    request = build_request(
        model=model,
        prompt=prompt,
        gate_token=config["token"],
        with_gate_token=with_gate_token,
    )
    try:
        completion = client.chat.completions.create(**request)
    except openai.APIError as error:
        print(format_api_error(error, secrets), file=err)
        return 1

    content = completion.choices[0].message.content or ""
    # Redact defensively: if the model relays request data (it should not, but
    # the gate's verbatim-message instruction means it echoes tool output), no
    # credential leaves in stdout.
    print(redact(content, secrets), file=out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm_agent",
        description=(
            "Ask the model one prompt through the LiteLLM gateway, with the "
            "bouncer MCP tool and this agent's gate token forwarded. A one-shot, "
            "single-turn conversation: retry after approval by running it again."
        ),
    )
    parser.add_argument("prompt", help="the user prompt to send to the model")
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=(
            "gateway model name (default: %(default)s). The default is the "
            "EU-only Bedrock profile used to demonstrate A14."
        ),
    )
    parser.add_argument(
        "--without-gate-token",
        action="store_true",
        help=(
            "deliberately send NO gate token, to demonstrate A16: LiteLLM then "
            "forwards an invalid credential, the gate returns 401, the tools are "
            "silently dropped and the model answers with none. For the demo only."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Thin entry point: parse args, load config, run one completion.

    Config errors and the deliberate --without-gate-token notice go to stderr;
    the model's answer goes to stdout. Keeping this thin leaves the testable
    logic in the pure functions above (R42, R43).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    require_gate_token = not args.without_gate_token
    if args.without_gate_token:
        print(
            "notice: --without-gate-token set; sending NO gate token. The gate "
            "will refuse and its tools will be dropped -- no tool can run (A16).",
            file=sys.stderr,
        )

    try:
        config = load_config(dict(os.environ), require_gate_token=require_gate_token)
    except ConfigError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    return run(
        config,
        model=args.model,
        prompt=args.prompt,
        with_gate_token=require_gate_token,
    )


if __name__ == "__main__":
    sys.exit(main())
