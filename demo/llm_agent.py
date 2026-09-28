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
from urllib.parse import urlsplit, urlunsplit

import openai

# The openai SDK vendors its HTTP transport as `httpx2` (a renamed httpx fork),
# not the public `httpx` -- `import httpx` fails in this venv while the SDK works
# via `httpx2` (verified: openai 3.19.2). The preflight reuses the SDK client's
# OWN underlying `httpx2.Client` (see preflight_tool_names), so we import httpx2
# only to name its exception types; it is already installed as an openai
# dependency, so this adds no new dependency (R44).
import httpx2

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

# The MCP server alias as LiteLLM knows it (gateway/litellm.yaml mcp_servers key,
# and the `server_label` of the completion tool block below). Both the preflight
# query (?mcp_server_name=bouncer) and the gate-token header prefix
# (x-mcp-bouncer-authorization) are built from this one name so they cannot drift.
BOUNCER_SERVER_NAME = "bouncer"

# LiteLLM's experimental MCP REST route that lists the tools a server exposes.
# The router mounts under prefix "/mcp-rest"
# (.venv-litellm/.../mcp_server/rest_endpoints.py:73) and the handler is
# `@router.get("/tools/list")` with a `mcp_server_name` query parameter
# (rest_endpoints.py:858,861) guarded by `Depends(user_api_key_auth)` -- i.e. the
# LiteLLM master key as the request's Authorization bearer, the same credential
# the completion path uses. The handler reads per-server auth headers straight
# off `request.headers` via MCPRequestHandler._get_mcp_server_auth_headers_from_headers
# (rest_endpoints.py:937; parser at user_api_key_auth_mcp.py:1244), so the SAME
# `x-mcp-bouncer-authorization: Bearer <gate token>` header the tool call forwards
# also reaches the gate on THIS route -- the preflight tests the identical
# credential the tool call would. Response shape: a JSON object with a "tools"
# list (rest_endpoints.py:1044); we count that list.
PREFLIGHT_PATH = "/mcp-rest/tools/list"

# The base_url ends in /v1 (D6.10, gateway_openai_base_url). The MCP REST route
# is a SIBLING of /v1 at the ALB origin, not under it, so the preflight targets
# the origin + PREFLIGHT_PATH rather than a base_url-relative path. Terraform
# opens exactly this one path on the listener (D6.22, alb.tf); /mcp-rest/tools/call
# stays 404.
BASE_URL_API_SUFFIX = "/v1"

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


class PreflightError(Exception):
    """The gateway did not confirm the bouncer tools are available.

    Raised by `preflight_tool_names` for either failure mode:
      * an HTTP/transport error reaching the REST route, or
      * a 200 response that lists zero bouncer tools.

    Carries an actionable, secret-free message (R47). `main` catches it, prints
    it to stderr and exits non-zero BEFORE any completion request, so a model
    that has lost its tools is never asked (D6.22, D6.21).
    """


def preflight_url(base_url: str) -> str:
    """Derive the MCP REST tools/list URL from the OpenAI base URL.

    The base URL ends in /v1 (D6.10); the MCP REST route is a sibling at the ALB
    origin, so we strip a trailing /v1 (and any trailing slash) from the PATH and
    append PREFLIGHT_PATH, preserving scheme and host. The host is never
    hardcoded -- it is whatever BOUNCER_GATEWAY_URL carries (D6.22).
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

    Pure-ish and testable: it takes an already-built SDK client and the two
    credentials, issues ONE GET, and returns the parsed tool names. `main` turns
    an empty list or any failure into a non-zero exit before the model is asked.

    Transport choice: the SDK's OWN underlying `httpx2.Client` (`client._client`),
    reached with a raw `.get()`. Justification (D6.22):
      * it is the SAME transport the completion request uses, so the preflight
        exercises the identical connection/TLS/proxy path -- not a parallel client
        that could succeed or fail differently;
      * a raw `.get()` on the httpx2 client performs NO auto-retry (the SDK's
        retry logic lives in its request wrapper, not in the raw verb), so this
        honours `max_retries=0` on the preflight too -- a retry could mask a
        transient gate failure the operator needs to see;
      * it needs no new dependency (httpx2 ships with `openai`, R44).

    Credentials (verified by reading LiteLLM 1.103.0, cited on PREFLIGHT_PATH):
    the gateway master key is the request's `Authorization` bearer (the route's
    `Depends(user_api_key_auth)`), and the gate token rides in the SAME
    `x-mcp-bouncer-authorization` header the completion tool block uses -- the
    REST handler parses per-server auth headers straight off `request.headers`,
    so this preflight tests the identical credential the tool call would.

    A gate token the gate rejects shows up here as HTTP 401 from THIS route, not
    as an empty tool list -- measured against the deployed gateway (D6.23). The
    empty-list absorption (server.py ~2315) is what the chat-completions path
    does; this REST route surfaces the upstream 401 instead. Either way the run
    stops before the model is asked, which is the point of the preflight, but the
    401 message must not blame the gateway key alone.

    Raises PreflightError on any transport/HTTP error, with a message that never
    prints the key or token and never guesses the cause.
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
            # query and the header prefix cannot drift (rest_endpoints.py:862).
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
        # Two different credentials can produce this, and from here they are
        # indistinguishable, so name both rather than guessing (R47). MEASURED
        # against the deployed gateway (D6.23): a gate token the gate rejects
        # comes back as 401 on this route, so the rotation case D6.22 targets
        # lands here, not in the zero-tools branch below.
        raise PreflightError(
            f"preflight got HTTP {status} from the gateway: a credential was "
            "rejected before any tool could be listed. Either the gate rejected "
            "this agent's gate token (it may have been rotated -- the gate reads "
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

    # 2xx: parse the tool list. The handler returns {"tools": [...], ...} where
    # each entry is a dict with a "name" (rest_endpoints.py:1044 / the documented
    # example ~line 890). A malformed body is treated as "no tools confirmed".
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

    Zero tools is the D6.21 failure: LiteLLM silently dropped the bouncer tools
    (most often a gate token the gate rejects -- rotation, since the gate reads
    its token table once at boot -- or the gate being unreachable), so the model
    would be asked with NO tools and could invent a fake approval flow. We refuse
    before asking. The message names the likely causes without GUESSING which one
    fired (the two are indistinguishable from here, D6.22) and never prints a
    credential.
    """
    names = preflight_tool_names(
        client, gateway_key=gateway_key, gate_token=gate_token
    )
    if not names:
        raise PreflightError(
            "the gateway returned NO tools for the bouncer server, so the model "
            "would have no tools to call. This is refused before asking the model "
            "(a model with no tools can fabricate a plausible-looking approval "
            "that never happened, D6.21). Likely causes: the gate is rejecting "
            "this agent's gate token (for example it was rotated -- the gate reads "
            "its token table once at boot, so a token minted after boot is "
            "unknown), or the gate is unreachable from the gateway. What to check: "
            "that BOUNCER_DEMO_TOKEN is a current token from the gate's table, and "
            "that the gate service is healthy. No model request was made."
        )
    return names


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
    preflight: bool = True,
    out=None,
    err=None,
) -> int:
    """Send one completion and print the model's final message, or a clean error.

    Before the completion, run the preflight (D6.22) unless `preflight` is False:
    ask the gateway whether it actually offers the bouncer tools, using the SAME
    client (hence the same transport and credentials). Zero tools, or any
    preflight HTTP/transport error, exits non-zero HERE -- before the model is
    ever asked -- so a model that has lost its tools cannot invent a fake
    approval flow (D6.21). The preflight is skipped for `--without-gate-token`
    (where zero tools is the expected A16 outcome) and can be turned off with
    `--no-preflight`; `main` decides.

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

    # Preflight BEFORE building or sending any completion request (D6.22). The
    # message is already actionable and secret-free; redact defensively anyway in
    # case a future message ever interpolates a credential.
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
    # --no-preflight (default: preflight ON). Justified narrowly: the preflight
    # costs one extra round trip and hits an UPSTREAM-EXPERIMENTAL LiteLLM route
    # that a version skew could remove (D6.22). An operator who has confirmed the
    # tools another way, or who is on a gateway build without the route, needs an
    # escape hatch rather than being unable to run at all. The default is ON
    # because the whole point of D6.22 is to catch the silent tool-drop before
    # the model is asked; you must opt OUT deliberately.
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

    # The preflight MUST NOT run under --without-gate-token: that flag exists to
    # demonstrate A16, where zero bouncer tools is the EXPECTED outcome, so a
    # preflight would (correctly) refuse and defeat the demonstration. Otherwise
    # honour --no-preflight, which defaults to running the preflight (D6.22).
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
