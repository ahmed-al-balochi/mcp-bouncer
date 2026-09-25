"""Runs the gate as a FastMCP proxy in front of a configurable upstream server.

Verified against fastmcp 4.0.1, which is the version pinned in pyproject.toml.
In 4.x the proxy entry point is `fastmcp.server.create_proxy`, which supersedes
the older `FastMCP.as_proxy`, and interception is a `Middleware` subclass with an
`on_call_tool` hook. The gate installs exactly one such hook.

Identity is resolved by transport (see gate.identity): stdio trusts `--caller`,
HTTP authenticates a bearer token. Over HTTP the token is enforced TWICE and on
purpose: fastmcp's native auth seam (`auth=BouncerTokenVerifier`, wired only on
the HTTP transport) gates the whole session -- `initialize` and `tools/list`
included -- before the MCP session manager runs, and `GateMiddleware` re-resolves
the same header per tool call as defence in depth. `build_gate` constructs the
resolver at boot and injects it into the one middleware, so the middleware never
learns how authentication works (R21). A misconfigured identity source refuses
the boot, exactly as a bad policy does (R17).
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

# The era pinned onto EVERY backend connection the proxy opens (bug D5.3/D5.8).
#
# Root cause this fixes: for a script-path (stdio) upstream, fastmcp keeps ONE
# shared StdioTransport (keep_alive=True) spawned lazily on the first request.
# With no explicit mode, create_proxy MIRRORS the front's negotiated era onto
# the backend per request (proxy.py `_mirror_front_era_mode`). A cold child that
# takes longer than the client's DISCOVER_TIMEOUT_SECONDS (10 s) makes an
# auto-mode front time out its modern `server/discover` probe and fall back to
# the legacy `initialize` handshake -- so the timed-out modern attempt and the
# legacy fallback ask that one shared transport for DIFFERENT TransportOptions,
# and StdioTransport.connect raises "This stdio transport has a live session
# built for different connection options...". Pinning an explicit mode takes the
# mirroring path out of play (proxy.py `_create_client_factory`, explicit_mode
# branch): every backend connection -- and the boot warm-up -- uses identical
# options regardless of the front era, so no two connections can disagree.
#
# Value chosen EMPIRICALLY (see tests/test_cold_upstream.py).
# The required property is that ONE pinned era serves BOTH a front in
# mode="legacy" and a front in the default mode="auto" (modern), for
# read/write/destructive/park/approve/deny on a cold stdio upstream. Measured
# against the real HTTP listener + the slow stdio child, all three candidates --
# "legacy", the newest modern protocol version, and "auto" -- fix the
# collision and pass every flow for both fronts (the demo upstream uses none of
# the modern-only round-trips like elicitation / sampling / guard tools, so a
# legacy front proxied to a modern backend still works). "legacy" is chosen on a
# robustness tiebreak grounded in the mechanism: it drives the plain
# `initialize` handshake and performs NO backend `server/discover` probe, so it
# is the one candidate that cannot itself become timeout-sensitive on a cold
# child -- pinning "auto" or a modern version would have the BACKEND re-probe
# discover on connect, reintroducing the exact timeout class this bug is about.
# It also interoperates with any MCP server, since a modern server still accepts
# the legacy handshake.
BACKEND_PROXY_MODE = "legacy"

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
    {
        # Suppress the `Server:` and `Date:` headers uvicorn sends by default.
        # They apply to every response including the unauthenticated health
        # endpoint, and an ALB does not strip them.
        "server_header": False,
        "date_header": False,
        # uvicorn's access log is plain text, so it would interleave unparsable
        # lines into a stream that is otherwise JSON per line (R33). It is also
        # mostly noise here: a load balancer probes the health endpoint every few
        # seconds forever, and the gate's own decision log already records every
        # tool call with its caller, classification and outcome. Routing uvicorn
        # through the JSON formatter instead would keep request-level detail, at
        # the cost of owning a uvicorn log_config; for this component the
        # decision log is the record that matters.
        "access_log": False,
    }
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
    proxy_mode: str | None = BACKEND_PROXY_MODE,
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

    `proxy_mode` PINS the backend protocol era for every upstream connection
    (bug D5.3/D5.8; see `BACKEND_PROXY_MODE`). It defaults to the pinned value
    and is a parameter only so the regression test can drive the exact
    mirroring collision by passing `proxy_mode=None` (the pre-fix behaviour) --
    production never overrides it. It is applied for EVERY upstream kind (stdio,
    http, in-memory) so there is no deployed-only code path (R35). An in-process
    FastMCP upstream is passed straight through by create_proxy without a stdio
    transport, so the pin cannot collide there; it is still applied uniformly so
    the tests and the deployed path run the same construction.

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

    proxy = create_proxy(
        upstream, name=name, mode=proxy_mode, **_http_auth(transport, identity_resolver)
    )
    proxy.add_middleware(GateMiddleware(registry, approvals, audit, identity_resolver))
    _install_health_route(proxy)
    return proxy


def _http_auth(transport: str, identity_resolver: IdentityResolver) -> dict[str, Any]:
    """The whole-session authentication wiring -- HTTP only. THE mutation target.

    Returned as kwargs for `create_proxy`, which forwards `**settings` to
    `FastMCPProxy` and thence to `FastMCP.__init__(auth=...)` (verified in
    fastmcp/server/server.py:2501 create_proxy -> providers/proxy.py:1471
    super().__init__(**kwargs) -> server.py:293 auth param, :433 self.auth).
    When `auth` is set, fastmcp wraps the streamable-HTTP MCP route in
    RequireAuthMiddleware, so `initialize` and `tools/list` -- not only tool
    calls -- require a valid token (R18 amended, A6). This is deliberately the
    ONE place session auth is wired: removing this line must make the
    unauthenticated-session tests fail.

    Stdio/in-memory is left entirely alone: no `auth` kwarg is passed, and even
    if it were, `run(transport="stdio")` builds no HTTP app and so never
    constructs RequireAuthMiddleware. Restricting the kwarg to the HTTP branch
    keeps the trusted-transport path provably unchanged.

    The verifier wraps the SAME resolver instance `GateMiddleware` receives,
    rather than building its own from the token source. Building a second one
    would read the token source twice at boot -- two Secrets Manager calls, and
    if the secret rotated between them the session layer and the per-call layer
    would hold different tables. One instance means one table in the process.
    """
    if transport != HTTP_TRANSPORT:
        return {}
    if not isinstance(identity_resolver, BearerTokenIdentityResolver):
        # Unreachable while build_identity_resolver keeps its contract, but if it
        # ever broke, serving an HTTP session with no verifier would be the open
        # door R13 forbids. Refuse to boot instead.
        raise IdentityConfigError(
            "HTTP transport requires a bearer-token identity resolver"
        )
    return {"auth": BouncerTokenVerifier(identity_resolver)}


def run_http(gate: FastMCPProxy, *, host: str, port: int, warm_up: bool = True) -> None:
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

    `show_banner=False` for the same reason the access log is off: the banner is
    several lines of ASCII art and an upgrade advertisement, and it lands in the
    same stdout stream that is supposed to be JSON per line (R33). It is set here
    rather than only via the environment so the production path is correct however
    the gate is launched.

    Warm-up (bug D5.3/D5.8, Part 1) runs in the SAME event loop that serves, not
    in a throwaway one. That ordering is not cosmetic: fastmcp's kept-alive
    stdio session binds its background connect task to the loop it was created
    on, so warming in a separate `asyncio.run` (which closes its loop) would
    leave the shared transport bound to a dead loop and the first real request
    would raise "Event loop is closed" -- verified. So `run_http` opens ONE loop,
    awaits the warm-up (which spawns the child and establishes the shared
    session under the pinned era), and only then starts uvicorn. Because uvicorn
    -- and therefore the `/health` route -- does not exist until after the
    warm-up returns, an ALB probe cannot receive a 200 before the upstream is
    warm: there is no healthy-but-cold window. `warm_up=False` is a TEST SEAM to
    observe the pre-fix cold-first-request behaviour; production never sets it.
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

    Raised so the gate REFUSES TO BOOT rather than starting to serve and failing
    on the first request (R17/R13, in the spirit of the policy/identity refuse-
    to-boot checks). The message names the underlying failure so an operator can
    act on it -- a bad `--upstream` script path is the common case.
    """


async def warm_up_upstream(gate: FastMCPProxy) -> None:
    """Open one upstream connection at boot and list its tools, or refuse to boot.

    Async ON PURPOSE: it must run in the SAME event loop that will serve, because
    fastmcp's kept-alive stdio session is bound to the loop it is created on (see
    `run_http`). A synchronous wrapper that used its own `asyncio.run` would
    close that loop and the shared session with it.

    Why this runs before serving (bug D5.3/D5.8, Part 1):

        For a script-path upstream, fastmcp spawns ONE shared stdio child LAZILY
        on the first request and keeps it alive. On a cold 0.25 vCPU task that
        first spawn can take longer than the client's 10 s discover timeout, and
        a slow spawn is the trigger for the era collision (see
        `BACKEND_PROXY_MODE`) as well as a slow first call for whoever hits it.
        Warming the child here moves that cost to boot -- before any client is
        served -- so the first real request meets an already-running child.

    Why it goes through the proxy's OWN `client_factory`:

        The factory is what every real request uses, so the warm-up connection
        adopts the SAME pinned `BACKEND_PROXY_MODE` and the SAME transport
        options. Warming through a hand-built client with different options would
        itself create the mismatch this fix exists to prevent. Because the pin is
        explicit, `_mirror_front_era_mode` is not consulted, so the absence of a
        front request context here does not matter.

    Why it refuses to boot on failure:

        An unreachable upstream (e.g. a script that cannot serve MCP) means the
        gate can never serve a single call. Discovering that at boot and
        refusing, with an actionable message, is the same posture the gate
        already takes on a bad policy or an unusable token source (R17) -- fail
        before serving, never serve-then-fail (R13).

    Emits exactly one `upstream_ready` log line carrying the warm-up duration in
    milliseconds (the operator's measurement of the real cold-spawn time) and the
    advertised tool count. No tool names, arguments or secrets are logged (R33).
    """
    started = time.monotonic()
    try:
        # `client_factory` is set by FastMCPProxy.__init__; every proxied request
        # builds its client this way, so the warm-up shares the pinned era.
        client = gate.client_factory()
        async with client:
            tools = await client.list_tools()
        tool_count = len(tools)
    except Exception as error:
        # Refuse to boot: surface WHAT failed so the operator can fix it. The
        # message is the exception's own text (a connection or spawn failure),
        # never a token or an argument -- none reach this path.
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

    # Warm the upstream BEFORE serving, on BOTH transports (bug D5.3/D5.8,
    # Part 1). Warming spawns the kept-alive stdio child and establishes the
    # shared session while nothing is being served, so the first real request
    # does not pay the cold-spawn latency that triggers the era collision. It
    # raises `UpstreamUnavailableError` if the upstream cannot be reached, so an
    # unusable `--upstream` refuses to boot here rather than failing later.
    #
    # It MUST share the serving event loop (the kept-alive session is bound to
    # the loop it is created on), so HTTP goes through `run_http` -- which warms
    # then serves in one loop -- and stdio warms then serves in one loop here.
    #
    # ALB health semantics: over HTTP the warm-up completes before uvicorn (and
    # thus the `/health` route) exists, so an ALB probe cannot see a 200 while
    # the upstream is still cold. Over stdio there is no HTTP listener at all.
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
