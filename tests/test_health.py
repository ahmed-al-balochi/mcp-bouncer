"""The ALB health endpoint: open, minimal, and not an authentication bypass (R31).

Two levels of exercise:

* Through the real ASGI app (`http_app()`) with Starlette's ASGI-capable
  TestClient, which dispatches in-process without a socket, so the route is
  proven the way a load balancer would hit it -- not by calling the handler
  function directly.
* Through a real HTTP listener alongside the MCP endpoint, to prove that opening
  an unauthenticated health route did not open an unauthenticated tool path: the
  same server that answers `/health` with no token still rejects a tool call
  with no token.

No AWS and no external network: the token source is the local `BOUNCER_TOKENS`
env var and every listener is on loopback (R45).
"""

from __future__ import annotations

import asyncio
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
from starlette.testclient import TestClient

from demo.wiki_server import build_server
from gate.identity import LOCAL_TOKENS_ENV
from gate.middleware import BLOCKED
from gate.server import HEALTH_PATH, build_gate, run_http

DEV_TOKEN = "tok-dev-dddddddddddddddd"
TOKENS = {DEV_TOKEN: {"caller": "dev-agent", "team": "DevChat"}}

# Strings that would betray something about the deployment if any of them ever
# appeared in the health response. Asserting on ABSENCE is the point: a 200 with
# a leaky body still fails R31.
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
    """Assert on what is ABSENT from the body, not merely that the status is 200.

    Headers are checked separately, against a real listener: Starlette's
    in-process TestClient never adds the headers a real ASGI server does, so a
    header assertion here would pass no matter what the container serves. Body
    content, by contrast, comes from our own handler and is fully exercised here.
    """
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
    """The disclosure check that actually covers the deployed artifact.

    A real ASGI server adds headers of its own -- uvicorn sends `Server:` and
    `Date:` by default -- and an ALB does not strip them, so an unauthenticated
    probe would otherwise announce the server software. The in-process TestClient
    cannot see those headers at all, which is why this assertion lives here and
    runs against the same `run_http` the container invokes.
    """
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


def test_health_is_open_while_tool_calls_still_require_a_token(
    http_gate: tuple[str, str],
):
    """The same running server answers /health unauthenticated AND rejects an
    unauthenticated tool call. Opening health did not open a tool path."""
    base, mcp_url = http_gate

    # Health: no Authorization header, still 200.
    with urllib.request.urlopen(f"{base}{HEALTH_PATH}", timeout=5) as response:
        assert response.status == 200

    # Tool call over the same server, no token: rejected before it can run.
    async def _call() -> Any:
        transport = StreamableHttpTransport(mcp_url, headers={})  # no token
        async with Client(transport) as client:
            return await client.call_tool(
                "wiki.read_page", {"title": "home"}, raise_on_error=False
            )

    result = asyncio.run(_call())
    assert result.is_error is True
    assert BLOCKED in result.content[0].text
