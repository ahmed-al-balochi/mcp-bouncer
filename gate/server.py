"""Runs the gate as a FastMCP proxy in front of a configurable upstream server.

Verified against fastmcp 4.0.1, which is the version pinned in pyproject.toml.
In 4.x the proxy entry point is `fastmcp.server.create_proxy`, which supersedes
the older `FastMCP.as_proxy`, and interception is a `Middleware` subclass with an
`on_call_tool` hook. The gate installs exactly one such hook.

Identity is resolved by transport (see gate.identity): stdio trusts `--caller`,
HTTP authenticates a bearer token. `build_gate` constructs the resolver at boot
and injects it into the one middleware, so the middleware never learns how
authentication works (R21). A misconfigured identity source refuses the boot,
exactly as a bad policy does (R17).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from fastmcp.server import create_proxy
from fastmcp.server.providers.proxy import FastMCPProxy
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

from gate import observability
from gate.identity import IDENTITY_ENV, SECRET_ID_ENV, build_identity_resolver
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

# The ALB target group probes this path. It is a SEPARATE Starlette route from
# the MCP endpoint (see `_install_health_route`), so it is never dispatched
# through the MCP session manager and therefore never reaches the gate's
# `on_call_tool` middleware -- confirmed by reading fastmcp's http app assembly,
# where custom routes are appended to the app's route list beside, not inside,
# the MCP mount. It requires no authentication by design (R31).
HEALTH_PATH = "/health"
# The body is a fixed, meaningless-to-an-attacker token. See
# `_install_health_route` for why it reveals nothing.
_HEALTH_BODY = "ok"

# uvicorn settings applied whenever the gate serves HTTP. Kept as a constant so
# the value is visible in one place and so tests can assert the production path
# uses it rather than reimplementing it. See `run_http`.
UVICORN_CONFIG: Mapping[str, Any] = MappingProxyType(
    {"server_header": False, "date_header": False}
)


def _install_health_route(proxy: FastMCPProxy) -> None:
    """Register the unauthenticated ALB health endpoint (R31).

    Decision: this is a SHALLOW LIVENESS check, not a deep readiness check.

    The gate already refuses to boot on an unreachable store or an unusable
    token source (R17): `build_gate` constructs both before this route can ever
    serve, so by the time an ALB probe arrives, the store and the token source
    were reachable at least once. A deep check that re-verified them on every
    probe would issue a DynamoDB call every few seconds for the life of the
    task, for no new information most of the time, and -- worse -- a transient
    store blip would fail the probe and pull a healthy task out of service. That
    trades a localised, already-safe failure for lost capacity: the gate fails
    CLOSED on a mid-life store outage (R13), so such calls are blocked, never
    mis-served, and removing the task on a blip would only reduce the fleet that
    is still correctly blocking. So the steady-state probe stays shallow.

    The gap a shallow check leaves is a task that boots and then loses its store;
    fail-closed covers the safety of that case, and the operational signal shows
    up in the fail_closed log lines rather than by flapping the target. For a
    production system I would add a SEPARATE deep readiness path, used only at
    task start-up (an ECS container health check or a one-shot startup gate),
    not wired to the steady-state ALB health check, and give any deep check
    hysteresis so a single blip cannot deregister a task.

    Information disclosure: an unauthenticated endpoint on a public ALB is a
    disclosure surface, so it returns the MINIMUM a load balancer needs to
    decide the target is alive -- a 200 and a fixed two-byte body. No version,
    no configuration, no team names, no table names, no backend identity, no
    build info, no hostname. `text/plain` avoids even hinting at a JSON schema.
    The route accepts only GET, so it cannot be coerced into carrying an MCP
    `tools/call` payload (a POST returns 405).
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
) -> FastMCPProxy:
    """Build the gate proxy, or raise and refuse to boot.

    Raises `PolicyConfigError` on an invalid policy and `IdentityConfigError` on
    an unusable token source, so a misconfiguration is caught before any traffic
    is served rather than surfacing per-request.

    `upstream` is anything `create_proxy` accepts: a server script path, a URL, an
    MCP config, or an in-process FastMCP instance (which is how the tests run).

    `transport` selects the identity model, not just how the server listens:
    the in-memory tests and stdio both trust `--caller`; `http` builds a
    bearer-token resolver and rejects unauthenticated calls (R18).

    The stores come from the factory, not from a concrete class, so the same
    binary runs on a local SQLite file or on DynamoDB purely according to
    `BOUNCER_STORE`. The middleware never learns which it holds.
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

    proxy = create_proxy(upstream, name=name)
    proxy.add_middleware(GateMiddleware(registry, approvals, audit, identity_resolver))
    _install_health_route(proxy)
    return proxy


def run_http(gate: FastMCPProxy, *, host: str, port: int) -> None:
    """Serve the gate over HTTP, with the response headers a public endpoint needs.

    This exists as a named function rather than an inline `gate.run(...)` so the
    production path and the tests run the SAME code. A header assertion against a
    listener started some other way would prove nothing about what the container
    actually serves.

    uvicorn sets `Server:` and `Date:` on every response by default, including on
    the unauthenticated health endpoint, so without suppressing them the health
    check announces the ASGI server to anyone who can reach the load balancer --
    precisely the disclosure the health route otherwise goes out of its way to
    avoid (R31). An ALB does not strip them, so it has to happen here. fastmcp
    merges this dict over its own uvicorn defaults.
    """
    gate.run(
        transport="http",
        host=host,
        port=port,
        uvicorn_config=dict(UVICORN_CONFIG),
    )


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

    # Over stdio, stdout IS the JSON-RPC framing channel: a log line written
    # there would corrupt the protocol. So the operational log goes to stderr
    # for stdio and to stdout for HTTP, which is what CloudWatch's container
    # agent ingests. This is the one place the two transports differ for logging.
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

    # Boot configuration, redacted: WHICH knobs are set, never a secret's
    # contents. Table names and a secret id are identifiers an operator needs to
    # correlate the task with its infrastructure, not credentials; the token map
    # and any bearer token are never passed here. `_redacted_boot_config` reads
    # only the environment selectors, so it cannot accidentally include a value
    # the argument parser holds as a secret.
    observability.log_boot(_redacted_boot_config(arguments))

    if arguments.transport == STDIO_TRANSPORT:
        gate.run(transport="stdio")
    else:
        run_http(gate, host=arguments.host, port=arguments.port)
    return 0


def _redacted_boot_config(arguments: argparse.Namespace) -> dict[str, str]:
    """Assemble the safe-to-log boot summary.

    Everything here is either a non-secret selector (transport, store backend,
    identity source) or an identifier an operator legitimately needs to
    correlate a task with its infrastructure (bind host/port, table names, the
    secret id which is a name or ARN). No token, no secret payload, and no policy
    contents appear -- only whether a knob is set and to which non-secret value.
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
    # when set so the line stays honest about what the task is actually using.
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
