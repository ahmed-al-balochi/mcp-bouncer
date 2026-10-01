"""A cold stdio upstream must still serve mixed-era fronts without colliding.
Part 2 pins the backend era so one shared transport is never asked for two
option sets. Part 1 warms the upstream at boot so no request pays the spawn cost."""

from __future__ import annotations

import asyncio
import io
import json
import socket
import threading
import time
from pathlib import Path
from typing import Any, Iterator

import mcp.client.session as mcp_session
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from gate import observability
from gate.cli import main as gate_cli
from gate.identity import LOCAL_TOKENS_ENV
from gate.server import (
    BACKEND_PROXY_MODE,
    UpstreamUnavailableError,
    build_gate,
    run_http,
    warm_up_upstream,
)
from tests.slow_upstream import write_slow_upstream

DEV_TOKEN = "tok-dev-dddddddddddddddd"
TOKENS = {DEV_TOKEN: {"caller": "dev-agent", "team": "DevChat"}}

# Enough delay that the child is demonstrably still cold past the shortened
# discover timeout, but small enough to keep the file fast.
COLD_DELAY_SECONDS = 2.0
SHORT_DISCOVER_TIMEOUT = 1.0

_STDIO_COLLISION_TEXT = "live session built for different connection options"


# --- shared helpers -------------------------------------------------------


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _await_listening(host: str, port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"gate did not start listening on {host}:{port}")


@pytest.fixture
def cold_upstream_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide a local token source and shrink the front discover timeout, so a
    ~2 s baked child delay reproduces the production ordering (spawn slower than
    the probe) quickly."""
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(TOKENS))
    # The mcp client reads this module-level constant when it builds the auto
    # probe timeout (mcp/client/session.py DISCOVER_TIMEOUT_SECONDS).
    monkeypatch.setattr(
        mcp_session, "DISCOVER_TIMEOUT_SECONDS", SHORT_DISCOVER_TIMEOUT, raising=False
    )


def _cold_gate(
    tmp_path: Path,
    policy_path: Path,
    *,
    delay_seconds: float = COLD_DELAY_SECONDS,
    crash: bool = False,
    proxy_mode: str | None = "__default__",
    db_name: str = "cold.db",
) -> Any:
    """Build a gate fronting a freshly generated slow or crashing stdio upstream.
    `proxy_mode="__default__"` keeps the production pinned default; pass `None`
    for the pre-fix mirroring behaviour the Part 2 regression needs."""
    upstream = write_slow_upstream(tmp_path, delay_seconds=delay_seconds, crash=crash)
    kwargs: dict[str, Any] = {}
    if proxy_mode != "__default__":
        kwargs["proxy_mode"] = proxy_mode
    return build_gate(
        upstream,
        policy_path=policy_path,
        db_path=tmp_path / db_name,
        transport="http",
        **kwargs,
    )


def _serve(gate: Any, port: int, *, warm_up: bool) -> None:
    """Serve on a background thread. `warm_up=True` is the production path (warm
    then serve in one loop); `warm_up=False` serves cold for the Part 2 race."""
    thread = threading.Thread(
        target=lambda: run_http(gate, host="127.0.0.1", port=port, warm_up=warm_up),
        daemon=True,
    )
    thread.start()
    _await_listening("127.0.0.1", port)


async def _read_home(mcp_url: str, front_mode: str) -> Any:
    transport = StreamableHttpTransport(
        mcp_url, headers={"Authorization": f"Bearer {DEV_TOKEN}"}
    )
    async with Client(transport, mode=front_mode) as client:
        return await client.call_tool(
            "wiki.read_page", {"title": "home"}, raise_on_error=False
        )


# --- Part 2: the era-collision regression ---------------------------------


def test_without_the_pin_a_cold_upstream_collides_on_mixed_eras(
    cold_upstream_env: None, policy_path: Path, tmp_path: Path
) -> None:
    """Fails without Part 2. With mirroring on and no warm-up, two concurrent
    fronts of different eras hit the one cold shared stdio transport with
    different options and one gets the StdioTransport collision error."""
    gate = _cold_gate(
        tmp_path, policy_path, proxy_mode=None, db_name="collide.db"
    )  # pre-fix: mirror the front era onto the backend
    port = _free_port()
    _serve(gate, port, warm_up=False)
    mcp_url = f"http://127.0.0.1:{port}/mcp/"

    async def both() -> list[Any]:
        return await asyncio.gather(
            _read_home(mcp_url, "auto"),
            _read_home(mcp_url, "legacy"),
            return_exceptions=True,
        )

    results = asyncio.run(both())

    # At least one leg must have failed with the shared-transport collision.
    messages = [str(r) for r in results if isinstance(r, BaseException)]
    assert messages, f"expected a collision, both succeeded: {results}"
    assert any(_STDIO_COLLISION_TEXT in m for m in messages), messages


def test_with_the_pin_a_cold_upstream_serves_both_front_eras(
    cold_upstream_env: None, policy_path: Path, tmp_path: Path
) -> None:
    """Proves the Part 2 fix: with the pinned mode a legacy front and an auto
    front each succeed on a cold upstream, because the shared transport only
    ever sees the one pinned era. Run sequentially so each pays its own cost."""
    gate = _cold_gate(tmp_path, policy_path, db_name="pinned.db")  # default = pinned
    port = _free_port()
    _serve(gate, port, warm_up=False)
    mcp_url = f"http://127.0.0.1:{port}/mcp/"

    legacy = asyncio.run(_read_home(mcp_url, "legacy"))
    assert legacy.is_error is False
    assert "Welcome to the demo wiki." in legacy.content[0].text

    auto = asyncio.run(_read_home(mcp_url, "auto"))
    assert auto.is_error is False
    assert "Welcome to the demo wiki." in auto.content[0].text


def test_the_pinned_mode_is_legacy() -> None:
    """Pin down the chosen value so a change is deliberate. `legacy` is chosen
    because it does no backend discover probe, so it cannot be timeout-sensitive
    on a cold child."""
    assert BACKEND_PROXY_MODE == "legacy"


# --- Part 1: warm the upstream at boot ------------------------------------


def _capture_logs() -> io.StringIO:
    buffer = io.StringIO()
    observability.configure_logging(stream=buffer)
    return buffer


def test_warm_up_serves_before_the_first_request_and_logs_the_duration(
    cold_upstream_env: None, policy_path: Path, tmp_path: Path
) -> None:
    """Fails without Part 1. The production path emits one `upstream_ready` line
    with a duration and tool count before the listener accepts, so the first
    real call does not pay the cold-spawn cost."""
    buffer = _capture_logs()
    gate = _cold_gate(tmp_path, policy_path, db_name="warm.db")

    port = _free_port()
    _serve(gate, port, warm_up=True)  # warms then serves in one loop
    mcp_url = f"http://127.0.0.1:{port}/mcp/"

    # By the time the socket accepts, warm-up has already run. Flush, then assert.
    def _ready_lines() -> list[dict]:
        lines = [json.loads(x) for x in buffer.getvalue().splitlines() if x.strip()]
        return [line for line in lines if line.get("event") == "upstream_ready"]

    deadline = time.time() + 5.0
    while not _ready_lines() and time.time() < deadline:
        time.sleep(0.05)

    ready = _ready_lines()
    assert len(ready) == 1, buffer.getvalue()
    assert ready[0]["tool_count"] == 3
    assert isinstance(ready[0]["duration_ms"], int)
    assert ready[0]["duration_ms"] >= 0

    first_started = time.monotonic()
    result = asyncio.run(_read_home(mcp_url, "auto"))
    first_elapsed = time.monotonic() - first_started

    assert result.is_error is False
    # The child is already up, so the first request cannot be waiting on a fresh
    # ~2 s spawn. Generous bound to stay robust on a busy host.
    assert first_elapsed < COLD_DELAY_SECONDS, first_elapsed


def test_an_unreachable_upstream_refuses_to_boot(
    monkeypatch: pytest.MonkeyPatch, policy_path: Path, tmp_path: Path
) -> None:
    """Fails without Part 1. An upstream that crashes on start makes warm-up
    fail, so the gate refuses to boot with an actionable message rather than
    serving and failing later."""
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(TOKENS))

    gate = _cold_gate(
        tmp_path, policy_path, delay_seconds=0.0, crash=True, db_name="dead.db"
    )

    with pytest.raises(UpstreamUnavailableError) as excinfo:
        asyncio.run(warm_up_upstream(gate))

    message = str(excinfo.value)
    assert "refusing to boot" in message
    assert "warm-up failed" in message


def test_warm_up_uses_the_pinned_options_so_it_cannot_itself_collide(
    cold_upstream_env: None, policy_path: Path, tmp_path: Path
) -> None:
    """The warm-up connection must adopt the same pinned era as real requests,
    or it would be the first half of a mismatch. With the pin, a real auto front
    and a real legacy front both succeed against the now-warm shared transport."""
    gate = _cold_gate(tmp_path, policy_path, db_name="warm-pin.db")

    port = _free_port()
    _serve(gate, port, warm_up=True)  # warm-up spawns the child under the pin
    mcp_url = f"http://127.0.0.1:{port}/mcp/"

    async def both() -> list[Any]:
        return await asyncio.gather(
            _read_home(mcp_url, "auto"),
            _read_home(mcp_url, "legacy"),
            return_exceptions=True,
        )

    results = asyncio.run(both())

    failures = [str(r) for r in results if isinstance(r, BaseException)]
    assert not any(_STDIO_COLLISION_TEXT in m for m in failures), failures
    successes = [r for r in results if not isinstance(r, BaseException)]
    assert len(successes) == 2, results
    assert all(r.is_error is False for r in successes)
    assert all("Welcome to the demo wiki." in r.content[0].text for r in successes)
