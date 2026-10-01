"""The ALB health endpoint: open, minimal, and not an authentication bypass.
Exercised through the real ASGI app with Starlette's TestClient and through a
real loopback listener that still rejects an unauthenticated tool call."""

from __future__ import annotations

import asyncio
import http.client
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterator

import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ClientError, MCPError
from starlette.testclient import TestClient

from demo.wiki_server import build_server
from gate.identity import LOCAL_TOKENS_ENV
from gate.server import HEALTH_PATH, build_gate, run_http

DEV_TOKEN = "tok-dev-dddddddddddddddd"
TOKENS = {DEV_TOKEN: {"caller": "dev-agent", "team": "DevChat"}}

# Strings that would betray something about the deployment if any of them ever
# appeared in the health response. Asserting on ABSENCE is the point: a 200 with
# a leaky body still fails the no-disclosure rule.
FORBIDDEN_IN_HEALTH = (
    "0.1.0",  # the package version
    "fastmcp",  # the framework identity
    "mcp-bouncer",  # the server name
    "demo-wiki",  # the upstream identity
    "CustomerChat",  # a team name
    "DevChat",  # a team name
    "sqlite",  # a backend name
    "dynamodb",  # a backend name
    "bouncer.db",  # a table / file name
    "policy.yaml",  # a configuration file name
    socket.gethostname(),  # the host identity
)


@pytest.fixture
def asgi_app(monkeypatch: pytest.MonkeyPatch, policy_path: Path, db_path: Path) -> Any:
    """The gate's real Starlette app, HTTP transport, with a local token source."""
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(TOKENS))
    gate = build_gate(
        build_server(), policy_path=policy_path, db_path=db_path, transport="http"
    )
    return gate.http_app()


def test_health_returns_success_with_no_authorization_header(asgi_app: Any):
    """The load balancer sends no credential; the probe must still succeed."""
    with TestClient(asgi_app) as client:
        response = client.get(HEALTH_PATH)  # no headers at all
    assert response.status_code == 200


def test_health_response_body_reveals_nothing(asgi_app: Any):
    """Assert on what is absent from the body, not merely that the status is 200.
    The body comes from our own handler, so it is fully exercised here; headers
    are checked separately against a real listener."""
    with TestClient(asgi_app) as client:
        response = client.get(HEALTH_PATH)

    body = response.text
    for needle in FORBIDDEN_IN_HEALTH:
        assert needle and needle not in body, f"health body leaked {needle!r}"

    # The body itself is minimal and mentions nothing structured.
    assert len(body) <= 8


def test_health_rejects_non_get_methods(asgi_app: Any):
    """The route accepts only GET, so it cannot be coerced into carrying a
    tools/call payload via POST."""
    with TestClient(asgi_app) as client:
        assert client.post(HEALTH_PATH, content=b"{}").status_code == 405


# --- the health route is not an authentication bypass ---------------------


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _await_listening(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"gate did not start listening on {host}:{port}")


@pytest.fixture
def http_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, policy_path: Path
) -> Iterator[tuple[str, str]]:
    """Run the gate on a real loopback listener; yield (base_url, mcp_url)."""
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(TOKENS))
    db_path = tmp_path / "health-gate.db"
    port = _free_port()
    gate = build_gate(
        build_server(), policy_path=policy_path, db_path=db_path, transport="http"
    )

    thread = threading.Thread(
        target=lambda: run_http(gate, host="127.0.0.1", port=port),
        daemon=True,
    )
    thread.start()
    _await_listening("127.0.0.1", port)
    time.sleep(1.0)  # let uvicorn finish coming up, as the identity lifecycle test does
    base = f"http://127.0.0.1:{port}"
    yield base, f"{base}/mcp/"


def test_health_headers_reveal_nothing_on_a_real_listener(
    http_gate: tuple[str, str],
):
    """The disclosure check that covers the deployed artifact. A real ASGI server
    adds `Server:` and `Date:` headers and the ALB does not strip them, so an
    unauthenticated probe would otherwise announce the server software."""
    base, _ = http_gate

    with urllib.request.urlopen(f"{base}{HEALTH_PATH}", timeout=5) as response:
        header_names = {name.lower() for name in response.headers.keys()}
        body = response.read().decode()

    assert "server" not in header_names, "the ASGI server is announcing itself"
    assert "date" not in header_names
    # `connection` is HTTP/1.1 transport framing chosen by the client's own
    # keep-alive negotiation, not something the application discloses.
    allowed = {"content-length", "content-type", "connection"}
    assert header_names <= allowed, f"unexpected health headers: {header_names - allowed}"

    for needle in FORBIDDEN_IN_HEALTH:
        assert needle not in body


def test_run_http_suppresses_everything_that_would_pollute_the_log_stream(
    monkeypatch: pytest.MonkeyPatch,
):
    """Assert on what `run_http` passes to uvicorn, because the
    defect it guards against is a caller that uses the raw fastmcp entry point
    and silently gets uvicorn's defaults back. `warm_up=False` needs no upstream."""
    captured: dict[str, Any] = {}

    class _FakeGate:
        async def run_http_async(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    run_http(_FakeGate(), host="127.0.0.1", port=1234, warm_up=False)  # type: ignore[arg-type]

    assert captured["transport"] == "http"
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 1234
    # The ASCII banner and upgrade notice would land in the JSON log stream.
    assert captured["show_banner"] is False

    config = captured["uvicorn_config"]
    # Sent on every response, including the unauthenticated health endpoint.
    assert config["server_header"] is False
    assert config["date_header"] is False
    # Plain text, so it would interleave unparsable lines into JSON output.
    assert config["access_log"] is False


def test_health_is_open_while_the_mcp_session_still_requires_a_token(
    http_gate: tuple[str, str],
):
    """The same running server answers /health unauthenticated yet refuses to
    open an MCP session without a token, so an unauthenticated client cannot even
    list tools. Opening health did not open a tool path."""
    base, mcp_url = http_gate

    # Health: no Authorization header, still 200.
    with urllib.request.urlopen(f"{base}{HEALTH_PATH}", timeout=5) as response:
        assert response.status == 200

    # MCP over the same server, no token: the session is rejected before it can
    # initialize, so listing tools raises rather than returning a catalogue.
    async def _list() -> Any:
        transport = StreamableHttpTransport(mcp_url, headers={})  # no token
        async with Client(transport) as client:
            return await client.list_tools()

    with pytest.raises((MCPError, ClientError)):
        asyncio.run(_list())


# --- the 401 itself leaks nothing (disclosure checks) -----------------


def _post_mcp_unauthenticated(mcp_url: str) -> tuple[int, dict[str, str], str]:
    """POST an MCP initialize with no token on the real listener, returning
    (status, lowercased headers, body). urllib raises HTTPError on a 4xx, whose
    error object is the response, so the 401 is read exactly as it went out."""
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "probe", "version": "0"},
            },
        }
    ).encode()
    request = urllib.request.Request(
        mcp_url.rstrip("/"),  # avoid the 307 that /mcp/ -> /mcp issues for POST
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return (
                response.status,
                {k.lower(): v for k, v in response.headers.items()},
                response.read().decode(),
            )
    except urllib.error.HTTPError as error:
        return (
            error.code,
            {k.lower(): v for k, v in error.headers.items()},
            error.read().decode(),
        )


def test_the_401_reveals_no_token_config_or_resource_metadata(
    http_gate: tuple[str, str],
):
    """The unauthenticated 401 must leak nothing useful. With no base_url
    configured, fastmcp advertises no resource-metadata URL and the body is the
    SDK's fixed `invalid_token` shape, naming no token, team, backend or file."""
    _, mcp_url = http_gate
    status, headers, body = _post_mcp_unauthenticated(mcp_url)

    assert status == 401

    # WWW-Authenticate challenges as Bearer but advertises no resource-metadata
    # URL, because none is configured, so it points a client at nothing.
    www_auth = headers.get("www-authenticate", "")
    assert www_auth.lower().startswith("bearer")
    assert "resource_metadata" not in www_auth

    # The body and headers leak no token or configuration.
    for needle in (*FORBIDDEN_IN_HEALTH, DEV_TOKEN):
        assert needle not in body, f"401 body leaked {needle!r}"
        assert needle not in www_auth, f"WWW-Authenticate leaked {needle!r}"


def test_the_401_carries_no_server_or_date_header_on_the_real_listener(
    http_gate: tuple[str, str],
):
    """The Server:/Date: suppression that applies to /health must apply to the
    401 too, since it is served by the same uvicorn and run_http's header
    suppression covers it."""
    _, mcp_url = http_gate
    status, headers, _ = _post_mcp_unauthenticated(mcp_url)

    assert status == 401
    assert "server" not in headers, "the 401 announces the ASGI server"
    assert "date" not in headers


def test_no_unauthenticated_well_known_route_is_registered(asgi_app: Any):
    """Adding auth must not register an unauthenticated
    /.well-known/oauth-protected-resource route: with no base_url, fastmcp
    creates none, so the probe 404s rather than serving discovery metadata."""
    with TestClient(asgi_app) as client:
        response = client.get("/.well-known/oauth-protected-resource")
    assert response.status_code == 404


def _start_listener(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, policy_path: Path, trusted: str
) -> int:
    """Serve the gate through `run_http` with a given proxy-trust setting."""
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(TOKENS))
    # uvicorn reads this when the config leaves forwarded_allow_ips unset, which
    # is exactly how the deployed task configures trust of the ALB.
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", trusted)
    port = _free_port()
    gate = build_gate(
        build_server(),
        policy_path=policy_path,
        db_path=tmp_path / "proxy.db",
        transport="http",
    )
    threading.Thread(
        target=lambda: run_http(gate, host="127.0.0.1", port=port), daemon=True
    ).start()
    _await_listening("127.0.0.1", port)
    time.sleep(1.0)
    return port


def _slash_redirect_location(port: int) -> str:
    """POST to `/mcp/` as an ALB would forward it; return the redirect target."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(
        "POST",
        "/mcp/",
        body="{}",
        headers={
            "Host": "gate.example.test",
            "X-Forwarded-Proto": "https",
            "Content-Type": "application/json",
        },
    )
    response = conn.getresponse()
    location = response.getheader("location", "")
    conn.close()
    assert response.status == 307
    return location


def test_a_redirect_behind_a_trusted_proxy_keeps_https(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, policy_path: Path
) -> None:
    """Behind the ALB, TLS ends at the load balancer so the gate sees HTTP.
    Ignoring X-Forwarded-Proto would make the `/mcp/` redirect point at http://
    and leak the resent body in cleartext, so run_http keeps proxy headers on."""
    port = _start_listener(monkeypatch, tmp_path, policy_path, trusted="127.0.0.1")
    assert _slash_redirect_location(port).startswith("https://gate.example.test/")


def test_an_untrusted_forwarded_proto_is_ignored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, policy_path: Path
) -> None:
    """The header is honoured only from the trusted network. Trusting a network
    the request does not come from makes the forged X-Forwarded-Proto inert,
    proving the previous test passes because of the trust setting, not always."""
    port = _start_listener(monkeypatch, tmp_path, policy_path, trusted="10.99.0.0/24")
    assert _slash_redirect_location(port).startswith("http://gate.example.test/")
