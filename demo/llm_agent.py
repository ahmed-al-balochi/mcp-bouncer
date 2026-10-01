"""One-shot LLM demo agent that drives the gate through the LiteLLM gateway.

It calls the gateway's OpenAI /v1/chat/completions with one bouncer MCP tool and
forwards its own gate token. Each run is a fresh single-turn conversation.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Sequence, cast
from urllib.parse import urlsplit, urlunsplit

import openai

# The openai SDK vendors its HTTP transport as httpx2 (a renamed httpx fork),
# not the public httpx; `import httpx` fails here while httpx2 works. We import
# it only to name its exception types, and it adds no new dependency.
import httpx2

# The gate token the agent forwards is the same variable demo/agent.py reads, so
# an operator who set up the local demo already has it.
TOKEN_ENV = "BOUNCER_DEMO_TOKEN"
GATEWAY_URL_ENV = "BOUNCER_GATEWAY_URL"
GATEWAY_KEY_ENV = "BOUNCER_GATEWAY_KEY"

# The terraform outputs an operator runs to obtain each value. Named in error
# messages so a missing variable is actionable without ever printing the value.
GATEWAY_URL_SOURCE = "terraform output gateway_openai_base_url"
GATEWAY_KEY_SOURCE = "terraform output litellm_master_key_get_command (then run it)"
TOKEN_SOURCE = "terraform output tokens_get_command (then run it)"

DEFAULT_MODEL = "claude-sonnet-5-eu"

# The MCP server alias as LiteLLM knows it. The preflight query and the gate-token
# header prefix are both built from this one name so they cannot drift.
BOUNCER_SERVER_NAME = "bouncer"

# LiteLLM's experimental MCP REST route that lists the tools a server exposes.
# It is guarded by the LiteLLM master key and reads per-server auth headers off
# the request, so the preflight tests the same credentials the tool call uses.
PREFLIGHT_PATH = "/mcp-rest/tools/list"

# The base_url ends in /v1. The MCP REST route is a sibling of /v1 at the ALB
# origin, not under it, so the preflight targets the origin plus PREFLIGHT_PATH.
BASE_URL_API_SUFFIX = "/v1"

# The gate token rides in the MCP tool's own headers under LiteLLM's
# x-mcp-{server_label}-{header} convention, so LiteLLM strips the prefix and
# passes Authorization: Bearer <token> to the gate, not the master key.
GATE_TOKEN_HEADER = "x-mcp-bouncer-authorization"

# Load-bearing: retry determinism rests on this instruction, not on temperature,
# which Sonnet 5 rejects outright. Relaying the gate's message verbatim and never
# working around a refusal is what gets the approval id and command to the human.
SYSTEM_PROMPT = (
    "You operate a wiki through the provided tools. Use them when asked. "
    "If a tool call is refused or parked, report the gate's message to the user "
    "verbatim, including any approval id and the exact command to run, and do "
    "not try to work around it. When asked to retry, call the tool again with "
    "exactly the same arguments."
)

# Client timeout in seconds, set below the tightest mesh limit (Service Connect
# cuts at 120 s). At 110 s the SDK raises a clean APITimeoutError before the mesh
# truncates mid-stream. The SDK default of 600 s would hang long past that.
REQUEST_TIMEOUT_SECONDS = 110.0


class ConfigError(Exception):
    """A required environment variable is missing or a flag combination is refused.

    Carries a ready-to-print, actionable message. Raised by pure config loading so
    the failure is unit-testable without a process exit.
    """


class PreflightError(Exception):
    """The gateway did not confirm the bouncer tools are available.

    Raised on a transport error reaching the REST route or a 200 that lists zero
    bouncer tools. main exits non-zero before any completion, so the model is spared.
    """


def preflight_url(base_url: str) -> str:
    """Derive the MCP REST tools/list URL from the OpenAI base URL.

    The REST route is a sibling of /v1 at the ALB origin, so we strip a trailing
    /v1 and append PREFLIGHT_PATH. The host is never hardcoded.
    """
    parts = urlsplit(base_url)
    path = parts.path.rstrip("/")
    if path.endswith(BASE_URL_API_SUFFIX):
        path = path[: -len(BASE_URL_API_SUFFIX)]
    return urlunsplit((parts.scheme, parts.netloc, path + PREFLIGHT_PATH, "", ""))


def preflight_tool_names(
    client: "openai.OpenAI",
    *,
    gateway_key: str,
    gate_token: str,
) -> list[str]:
    """Return the names of the tools the gateway reports for the bouncer server.

    Reuses the SDK client's own httpx2 transport with a raw GET, so it hits the
    same connection path and does no auto-retry. Raises PreflightError on failure.
    """
    url = preflight_url(str(client.base_url))
    headers = {
        "Authorization": f"Bearer {gateway_key}",
        GATE_TOKEN_HEADER: f"Bearer {gate_token}",
    }
    underlying: httpx2.Client = client._client  # the SDK's own transport
    try:
        response = underlying.get(
            url,
            # The server to list tools for. Named from BOUNCER_SERVER_NAME so the
            # query and the header prefix cannot drift.
            params={"mcp_server_name": BOUNCER_SERVER_NAME},
            headers=headers,
            # Match the completion path's timeout budget; a raw get honours it
            # without the SDK's retry wrapper.
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except httpx2.TimeoutException as error:
        raise PreflightError(
            "preflight to the gateway timed out before the model was asked; "
            "the gateway may be unreachable or overloaded. Check the gateway is "
            f"up and reachable at {url} and retry. (Reason: {type(error).__name__}.)"
        ) from error
    except httpx2.HTTPError as error:
        # ConnectError and every other transport-level failure.
        raise PreflightError(
            "preflight could not reach the gateway before the model was asked; "
            "the gateway may be down or the URL wrong. Check the gateway is up "
            f"and that BOUNCER_GATEWAY_URL points at it ({url}) and retry. "
            f"(Reason: {type(error).__name__}.)"
        ) from error

    status = response.status_code
    if status == 404:
        raise PreflightError(
            "preflight got HTTP 404 from the gateway's MCP tools/list route. The "
            "gateway may not expose this experimental route (a LiteLLM version "
            f"skew), or the ALB may not permit {PREFLIGHT_PATH}. Confirm the "
            "gateway's LiteLLM version and the ALB rule, then retry."
        )
    if status in (401, 403):
        # Two different credentials can produce this and they are indistinguishable
        # from here, so name both rather than guessing. A gate token the gate
        # rejects comes back as 401 on this route, so rotation lands here too.
        raise PreflightError(
            f"preflight got HTTP {status} from the gateway: a credential was "
            "rejected before any tool could be listed. Either the gate rejected "
            "this agent's gate token (it may have been rotated, since the gate reads "
            "its token table once at boot) or the gateway rejected the gateway "
            "key. Re-fetch both from the deployment's secrets and retry. No model "
            "request was made."
        )
    if status >= 400:
        raise PreflightError(
            f"preflight got HTTP {status} from the gateway before the model was "
            "asked. The gateway returned an error rather than a tool list. Check "
            "the gateway's health and logs, then retry."
        )

    # 2xx: parse the tool list. The handler returns {"tools": [...]} where each
    # entry is a dict with a "name". A malformed body counts as no tools confirmed.
    try:
        payload = response.json()
        tools = payload.get("tools", []) if isinstance(payload, dict) else []
        names = [
            t["name"]
            for t in tools
            if isinstance(t, dict) and isinstance(t.get("name"), str)
        ]
    except (ValueError, TypeError, KeyError):
        names = []
    return names


def preflight_or_raise(
    client: "openai.OpenAI", *, gateway_key: str, gate_token: str
) -> list[str]:
    """Run the preflight and raise PreflightError if the bouncer has zero tools.

    Zero tools means LiteLLM silently dropped them (a rejected gate token or an
    unreachable gate), so the model could invent a fake approval. We refuse first.
    """
    names = preflight_tool_names(
        client, gateway_key=gateway_key, gate_token=gate_token
    )
    if not names:
        raise PreflightError(
            "the gateway returned NO tools for the bouncer server, so the model "
            "would have no tools to call. This is refused before asking the model "
            "(a model with no tools can fabricate a plausible-looking approval "
            "that never happened). Likely causes: the gate is rejecting "
            "this agent's gate token (for example it was rotated, since the gate reads "
            "its token table once at boot, so a token minted after boot is "
            "unknown), or the gate is unreachable from the gateway. What to check: "
            "that BOUNCER_DEMO_TOKEN is a current token from the gate's table, and "
            "that the gate service is healthy. No model request was made."
        )
    return names


def load_config(env: dict[str, str], *, require_gate_token: bool) -> dict[str, str]:
    """Resolve gateway URL, gateway key and (optionally) the gate token from env.

    Config comes from the environment only. Each missing variable raises
    ConfigError naming the variable and its terraform output, never the value.
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
            f"runs. Obtain a token with: {TOKEN_SOURCE}. To deliberately "
            "run WITHOUT a gate token, pass "
            "--without-gate-token."
        )
    # An empty token when not required is intentional: the tool block carries no
    # gate-token header at all (see build_request).
    config["token"] = token
    return config


def build_request(
    *, model: str, prompt: str, gate_token: str, with_gate_token: bool
) -> dict[str, Any]:
    """Build the kwargs passed to `chat.completions.create`, minus the client.

    Pure so a test can assert the exact request. The MCP tool dict is a LiteLLM
    extension the SDK does not type but passes through unchanged; no temperature.
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

    Defence in depth so the key and gate token never reach stdout, stderr or logs,
    even when the server echoes request data back in an error body.
    """
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***redacted***")
    return text


def format_api_error(error: "openai.APIError", secrets: Sequence[str]) -> str:
    """Turn an SDK exception into one redacted, actionable stderr line.

    Surfaces the HTTP status when the error carries one (connection and timeout
    errors do not) and always redacts the key and token.
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
    preflight: bool = True,
    out=None,
    err=None,
) -> int:
    """Send one completion and print the model's final message, or a clean error.

    Unless preflight is False, first ask the gateway whether it offers the bouncer
    tools; zero tools or any preflight error exits non-zero before the model runs.
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

    # Preflight before building or sending any completion. The message is already
    # secret-free; redact defensively in case a future one interpolates a credential.
    if preflight:
        try:
            preflight_or_raise(
                client, gateway_key=config["key"], gate_token=config["token"]
            )
        except PreflightError as error:
            print(f"error: {redact(str(error), secrets)}", file=err)
            return 1

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
    # Redact defensively: the verbatim-message instruction means the model may
    # echo tool output, so make sure no credential leaves in stdout.
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
            "EU-only Bedrock profile used in the demo."
        ),
    )
    parser.add_argument(
        "--without-gate-token",
        action="store_true",
        help=(
            "deliberately send NO gate token: LiteLLM then "
            "forwards an invalid credential, the gate returns 401, the tools are "
            "silently dropped and the model answers with none. For the demo only."
        ),
    )
    # --no-preflight (default: preflight ON). The preflight hits an experimental
    # LiteLLM route a version skew could remove, so operators who confirmed tools
    # another way need an escape hatch. It stays on by default to catch tool-drop.
    parser.add_argument(
        "--no-preflight",
        dest="preflight",
        action="store_false",
        help=(
            "skip the pre-model check that the gateway offers the bouncer tools "
            "(default: the check runs). Only for a gateway whose experimental MCP "
            "tools/list route is absent, or when tools were confirmed another way."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Thin entry point: parse args, load config, run one completion.

    Config errors and the --without-gate-token notice go to stderr; the model's
    answer goes to stdout. The testable logic lives in the pure functions above.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    require_gate_token = not args.without_gate_token
    if args.without_gate_token:
        print(
            "notice: --without-gate-token set; sending NO gate token. The gate "
            "will refuse and its tools will be dropped, so no tool can run.",
            file=sys.stderr,
        )

    # The preflight must not run under --without-gate-token: that flag sends no
    # gate token, so zero tools is expected and a preflight would wrongly refuse.
    # Otherwise honour --no-preflight, which defaults to running the preflight.
    preflight = args.preflight and not args.without_gate_token

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
        preflight=preflight,
    )


if __name__ == "__main__":
    sys.exit(main())
