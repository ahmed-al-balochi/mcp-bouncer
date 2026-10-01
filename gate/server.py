"""Runs the gate as a FastMCP proxy in front of a configurable upstream server.

Verified against fastmcp 4.0.1: the proxy is create_proxy and interception is a
Middleware with on_call_tool. A bad identity source or policy refuses the boot.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from fastmcp.server import create_proxy
from fastmcp.server.providers.proxy import FastMCPProxy
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

from gate import observability
from gate.identity import (
    IDENTITY_ENV,
    SECRET_ID_ENV,
    BearerTokenIdentityResolver,
    BouncerTokenVerifier,
    IdentityConfigError,
    IdentityResolver,
    build_identity_resolver,
)
from gate.middleware import ANONYMOUS_CALLER, GateMiddleware
from gate.registry import known_teams, load_registry
from gate.storage import (
    DYNAMODB_AUDIT_TABLE_ENV,
    DYNAMODB_TABLE_ENV,
    STORE_ENV,
    build_approval_store,
    build_audit_log,
)

# The in-memory and stdio transports share the same trust model: the client
# already holds the process, so `--caller` is the authenticated identity. Only
# `http` crosses a network boundary and demands a bearer token.
STDIO_TRANSPORT = "stdio"
HTTP_TRANSPORT = "http"

# The era pinned onto every backend connection, so create_proxy does not mirror
# the front era per request and leave one shared stdio transport asked for two
# different options. "legacy" cannot re-probe discover on a cold child (see tests/test_cold_upstream.py).
BACKEND_PROXY_MODE = "legacy"

# The ALB target group probes this path. It is a separate Starlette route from
# the MCP endpoint, so it never reaches the on_call_tool middleware and needs no
# authentication by design.
HEALTH_PATH = "/health"
# The body is a fixed, meaningless-to-an-attacker token. See
# `_install_health_route` for why it reveals nothing.
_HEALTH_BODY = "ok"

# uvicorn settings applied whenever the gate serves HTTP. Kept as a constant so
# the value is visible in one place and so tests can assert the production path
# uses it rather than reimplementing it. See `run_http`.
UVICORN_CONFIG: Mapping[str, Any] = MappingProxyType(
    {
        # Suppress the `Server:` and `Date:` headers uvicorn sends by default.
        # They apply to every response including the unauthenticated health
        # endpoint, and an ALB does not strip them.
        "server_header": False,
        "date_header": False,
        # uvicorn's access log is plain text, so it would interleave unparsable
        # lines into a stream that is otherwise JSON per line, and the
        # decision log already records every call that matters.
        "access_log": False,
    }
)


def _install_health_route(proxy: FastMCPProxy) -> None:
    """Register the unauthenticated ALB health endpoint.

    A shallow liveness check: fail-closed covers a mid-life store outage,
    so it returns a fixed two-byte body on GET only, leaking nothing.
    """

    @proxy.custom_route(HEALTH_PATH, methods=["GET"], include_in_schema=False)
    async def health(request: Request) -> Response:  # noqa: ARG001 - Starlette signature
        return PlainTextResponse(_HEALTH_BODY, status_code=200)


def build_gate(
    upstream: Any,
    *,
    policy_path: str | os.PathLike[str] | None = None,
    db_path: str | os.PathLike[str] | None = None,
    default_caller: str = ANONYMOUS_CALLER,
    team: str | None = None,
    transport: str = STDIO_TRANSPORT,
    name: str = "mcp-bouncer",
    proxy_mode: str | None = BACKEND_PROXY_MODE,
) -> FastMCPProxy:
    """Build the gate proxy, or raise and refuse to boot.

    An invalid policy or unusable token source is caught before serving.
    `proxy_mode` pins the backend era; the test passes None to drive the collision.
    """
    registry = load_registry(policy_path)
    identity_resolver = build_identity_resolver(
        transport=transport,
        caller=default_caller,
        known_teams=known_teams(registry),
        team=team,
    )
    approvals = build_approval_store(
        db_path=db_path, ttl_minutes=registry.limits.approval_ttl_minutes
    )
    audit = build_audit_log(db_path=db_path)

    proxy = create_proxy(
        upstream, name=name, mode=proxy_mode, **_http_auth(transport, identity_resolver)
    )
    proxy.add_middleware(GateMiddleware(registry, approvals, audit, identity_resolver))
    _install_health_route(proxy)
    return proxy


def _http_auth(transport: str, identity_resolver: IdentityResolver) -> dict[str, Any]:
    """The whole-session authentication wiring, HTTP only.

    Setting auth makes fastmcp require a token for initialize and tools/list too;
    the verifier wraps the SAME resolver GateMiddleware holds.
    """
    if transport != HTTP_TRANSPORT:
        return {}
    if not isinstance(identity_resolver, BearerTokenIdentityResolver):
        # Unreachable while build_identity_resolver keeps its contract, but if it
        # ever broke, serving an HTTP session with no verifier would be the open
        # door the fail-closed design forbids. Refuse to boot instead.
        raise IdentityConfigError(
            "HTTP transport requires a bearer-token identity resolver"
        )
    return {"auth": BouncerTokenVerifier(identity_resolver)}


def run_http(gate: FastMCPProxy, *, host: str, port: int, warm_up: bool = True) -> None:
    """Serve the gate over HTTP, with the response headers a public endpoint needs.

    It suppresses uvicorn's Server/Date headers and banner so nothing leaks into
    the health response or JSON stdout, and warms before serving.
    """

    async def _serve() -> None:
        if warm_up:
            await warm_up_upstream(gate)
        await gate.run_http_async(
            transport="http",
            host=host,
            port=port,
            show_banner=False,
            uvicorn_config=dict(UVICORN_CONFIG),
        )

    asyncio.run(_serve())


class UpstreamUnavailableError(RuntimeError):
    """The upstream could not be reached during the boot warm-up.

    Raised so the gate refuses to boot rather than failing on the first request.
    The message names the failure, usually a bad --upstream path.
    """


async def warm_up_upstream(gate: FastMCPProxy) -> None:
    """Open one upstream connection at boot and list its tools, or refuse to boot.

    Async so it runs in the serving loop the kept-alive session is bound to. It
    warms the child so the first request avoids the cold-spawn latency.
    """
    started = time.monotonic()
    try:
        # Every proxied request builds its client this way, so the warm-up shares
        # the pinned era.
        client = gate.client_factory()
        async with client:
            tools = await client.list_tools()
        tool_count = len(tools)
    except Exception as error:
        # Refuse to boot and surface what failed. The message is the exception's
        # own text, never a token or an argument.
        raise UpstreamUnavailableError(
            f"upstream warm-up failed; refusing to boot: {error}"
        ) from error
    duration_ms = int((time.monotonic() - started) * 1000)
    observability.log_upstream_ready(duration_ms=duration_ms, tool_count=tool_count)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="bouncer-server",
        description="Front an upstream MCP server with the mcp-bouncer policy proxy.",
    )
    parser.add_argument(
        "--upstream",
        required=True,
        help="upstream MCP server: a script path, a URL, or an MCP config file",
    )
    parser.add_argument("--policy", default=None, help="path to policy.yaml")
    parser.add_argument(
        "--db",
        default=None,
        help=f"path to the gate database (SQLite backend only; ignored when ${STORE_ENV} selects another backend)",
    )
    parser.add_argument(
        "--caller",
        default=ANONYMOUS_CALLER,
        help=(
            "caller identity to assume over stdio, where the spawning process IS "
            "the identity; ignored over HTTP, which authenticates a bearer token"
        ),
    )
    parser.add_argument(
        "--team",
        default=None,
        help=(
            "team whose policy applies to --caller over stdio (default: the caller "
            "name); must name a team defined in policy.yaml"
        ),
    )
    parser.add_argument("--transport", default=STDIO_TRANSPORT, choices=(STDIO_TRANSPORT, HTTP_TRANSPORT))
    parser.add_argument("--host", default="127.0.0.1", help="bind host for --transport http")
    parser.add_argument("--port", type=int, default=8000, help="port for --transport http")
    arguments = parser.parse_args(argv)

    # FastMCP 4 deprecates inferring a stdio transport from a bare string path;
    # a pathlib.Path is unambiguous. URLs and config references pass through.
    upstream: Any = arguments.upstream
    if isinstance(upstream, str) and Path(upstream).exists():
        upstream = Path(upstream)

    # Over stdio, stdout is the JSON-RPC framing channel, so a log line there
    # would corrupt the protocol. The log goes to stderr for stdio and stdout for
    # HTTP, which is what CloudWatch ingests.
    log_stream = sys.stderr if arguments.transport == STDIO_TRANSPORT else sys.stdout
    observability.configure_logging(stream=log_stream)

    gate = build_gate(
        upstream,
        policy_path=arguments.policy,
        db_path=arguments.db,
        default_caller=arguments.caller,
        team=arguments.team,
        transport=arguments.transport,
    )

    # Boot configuration, redacted: which knobs are set, never a secret's
    # contents. _redacted_boot_config reads only environment selectors, so it
    # cannot include a value the argument parser holds as a secret.
    observability.log_boot(_redacted_boot_config(arguments))

    # Warm the upstream before serving, on both transports, so the first request
    # does not pay the cold-spawn latency and an unusable --upstream refuses to
    # boot. It must share the serving loop, so each transport warms then serves.
    if arguments.transport == STDIO_TRANSPORT:

        async def _serve_stdio() -> None:
            await warm_up_upstream(gate)
            await gate.run_stdio_async(show_banner=False)

        asyncio.run(_serve_stdio())
    else:
        run_http(gate, host=arguments.host, port=arguments.port)
    return 0


def _redacted_boot_config(arguments: argparse.Namespace) -> dict[str, str]:
    """Assemble the safe-to-log boot summary.

    Everything here is a non-secret selector or an identifier an operator needs
    (host/port, table names, secret id). No token, secret payload, or policy.
    """
    config: dict[str, str] = {
        "transport": arguments.transport,
        "store": os.environ.get(STORE_ENV, "sqlite"),
        "identity_source": os.environ.get(IDENTITY_ENV, "local"),
    }
    if arguments.transport == HTTP_TRANSPORT:
        config["host"] = arguments.host
        config["port"] = str(arguments.port)
    # Table names and secret id are identifiers, not secrets; include them only
    # when set so the line stays honest about what the task is using.
    for label, env in (
        ("dynamodb_table", DYNAMODB_TABLE_ENV),
        ("dynamodb_audit_table", DYNAMODB_AUDIT_TABLE_ENV),
        ("tokens_secret", SECRET_ID_ENV),
    ):
        value = os.environ.get(env, "").strip()
        if value:
            config[label] = value
    return config


if __name__ == "__main__":
    raise SystemExit(main())
