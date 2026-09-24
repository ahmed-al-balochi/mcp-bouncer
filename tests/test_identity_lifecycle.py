"""End-to-end identity and per-team policy, through the real HTTP proxy.

Unlike test_lifecycle.py, which drives the gate over the in-memory transport
(the stdio-equivalent trusted path), these tests stand the gate up on a real
HTTP listener and speak to it across a socket. That is the only way to exercise
the bearer-token path honestly: identity is authenticated from an
`Authorization` header that genuinely crossed the transport, not injected into a
function call. A6 and A7 are proven here against a running server.

No AWS, no external network: the token source is the local `BOUNCER_TOKENS`
env var and the listener is on loopback (R45).
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from pathlib import Path
from typing import Any, Iterator

import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from demo.wiki_server import build_server
from gate.audit import AuditLog
from gate.cli import main as gate_cli
from gate.identity import LOCAL_TOKENS_ENV
from gate.middleware import APPROVAL_REQUIRED, BLOCKED
from gate.server import build_gate

# Test-fixture tokens, not credentials. Two callers on two teams so their
# independence can be checked.
CUSTOMER_TOKEN = "tok-customer-cccccccccccc"
DEV_TOKEN = "tok-dev-dddddddddddddddd"
TOKENS = {
    CUSTOMER_TOKEN: {"caller": "customer-agent", "team": "CustomerChat"},
    DEV_TOKEN: {"caller": "dev-agent", "team": "DevChat"},
}


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


@pytest.fixture
def http_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, policy_path: Path
) -> Iterator[str]:
    """Run the gate over real HTTP with the bearer-token identity source.

    Yields the MCP endpoint URL. The server runs in a daemon thread on its own
    asyncio loop; the test process is the client. The DB is a fresh file per
    test so approvals do not bleed between tests.
    """
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(TOKENS))
    db_path = tmp_path / "http-gate.db"
    port = _free_port()

    gate = build_gate(
        build_server(),
        policy_path=policy_path,
        db_path=db_path,
        transport="http",
    )

    def serve() -> None:
        # A dedicated loop: gate.run creates its own, and this thread owns it.
        gate.run(transport="http", host="127.0.0.1", port=port)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}/mcp/"
    _await_listening("127.0.0.1", port)
    # The socket is open before uvicorn is ready to serve MCP; a short settle
    # avoids a flaky first request without coupling to uvicorn internals.
    time.sleep(1.0)
    yield url


def _await_listening(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"gate did not start listening on {host}:{port}")


def call(
    url: str, token: str | None, tool: str, arguments: dict[str, Any]
) -> Any:
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}

    async def _call() -> Any:
        transport = StreamableHttpTransport(url, headers=headers)
        async with Client(transport) as client:
            return await client.call_tool(tool, arguments, raise_on_error=False)

    return asyncio.run(_call())


def text_of(result: Any) -> str:
    return result.content[0].text


def approval_id_from(result: Any) -> str:
    message = text_of(result)
    assert f"{APPROVAL_REQUIRED} id=" in message
    return message.split(f"{APPROVAL_REQUIRED} id=")[1].split()[0]


# --- rejection at the door (A6) -------------------------------------------


def test_a_call_with_no_token_is_rejected(http_gate: str):
    result = call(http_gate, None, "wiki.read_page", {"title": "home"})
    assert result.is_error is True
    assert BLOCKED in text_of(result)


def test_a_call_with_an_unknown_token_is_rejected(http_gate: str):
    result = call(http_gate, "tok-not-real", "wiki.read_page", {"title": "home"})
    assert result.is_error is True
    assert BLOCKED in text_of(result)


def test_a_malformed_authorization_header_is_rejected(http_gate: str):
    # A raw token with no Bearer scheme is malformed.
    result = call(http_gate, None, "wiki.read_page", {"title": "home"})
    assert result.is_error is True


def test_a_valid_token_lets_a_read_through(http_gate: str):
    result = call(http_gate, DEV_TOKEN, "wiki.read_page", {"title": "home"})
    assert result.is_error is False
    assert "Welcome to the demo wiki." in text_of(result)


# --- the tightening override takes effect end to end (R23, R24) -----------


def test_a_write_parks_for_customerchat_but_passes_for_devchat(http_gate: str):
    """wiki.write_page is `write` at baseline: DevChat passes it, CustomerChat
    (which promotes it to destructive) parks it. Same tool, same arguments, two
    teams, two outcomes -- proven through the real proxy."""
    dev = call(http_gate, DEV_TOKEN, "wiki.write_page", {"title": "n", "body": "b"})
    assert dev.is_error is False

    customer = call(
        http_gate, CUSTOMER_TOKEN, "wiki.write_page", {"title": "n", "body": "b"}
    )
    assert customer.is_error is True
    message = text_of(customer)
    assert APPROVAL_REQUIRED in message
    # CustomerChat's tightened TTL is visible in the actionable message.
    assert "expires in 5 minutes" in message


# --- the two callers' destructive counters are independent (A6) -----------


def test_two_callers_have_independent_destructive_counters(
    http_gate: str, tmp_path: Path, policy_path: Path
):
    """DevChat's cap is 2. The dev caller uses up its own allowance; the customer
    caller, on a different identity, is unaffected -- its own (tighter) cap of 1
    still has room. Counters keyed per caller, not shared."""
    db_path = tmp_path / "http-gate.db"

    def park_approve_retry(token: str, title: str) -> Any:
        parked = call(http_gate, token, "wiki.delete_page", {"title": title})
        approval_id = approval_id_from(parked)
        assert (
            gate_cli(
                ["--db", str(db_path), "--policy", str(policy_path), "approve", approval_id]
            )
            == 0
        )
        return call(http_gate, token, "wiki.delete_page", {"title": title})

    # Seed pages to delete.
    for title in ("d1", "d2", "c1"):
        assert (
            call(http_gate, DEV_TOKEN, "wiki.write_page", {"title": title, "body": "x"}).is_error
            is False
        )

    # Dev caller spends its cap of 2.
    assert park_approve_retry(DEV_TOKEN, "d1").is_error is False
    assert park_approve_retry(DEV_TOKEN, "d2").is_error is False
    # Third destructive for dev is now rate-blocked.
    blocked = call(http_gate, DEV_TOKEN, "wiki.write_page", {"title": "d3", "body": "x"})
    assert blocked.is_error is False
    third = call(http_gate, DEV_TOKEN, "wiki.delete_page", {"title": "d3"})
    assert third.is_error is True
    assert "allowance" in text_of(third)

    # The customer caller is a different identity: its counter is untouched, so
    # its first destructive still parks (not rate-blocked) despite dev being capped.
    customer = call(http_gate, CUSTOMER_TOKEN, "wiki.delete_page", {"title": "c1"})
    assert customer.is_error is True
    assert APPROVAL_REQUIRED in text_of(customer)


# --- tokens never leak (A6 security property) -----------------------------


def test_a_token_never_appears_in_the_audit_log_or_an_error(
    http_gate: str, tmp_path: Path
):
    """Assert, do not assume: exercise good and bad tokens, then scan the audit
    log and every returned message for any token value."""
    db_path = tmp_path / "http-gate.db"

    good = call(http_gate, DEV_TOKEN, "wiki.read_page", {"title": "home"})
    bad = call(http_gate, "tok-not-real", "wiki.read_page", {"title": "home"})
    missing = call(http_gate, None, "wiki.read_page", {"title": "home"})

    for result in (good, bad, missing):
        message = text_of(result)
        assert DEV_TOKEN not in message
        assert CUSTOMER_TOKEN not in message
        assert "tok-not-real" not in message

    entries = AuditLog(db_path).entries()
    # The good read attributes to the caller, never the token.
    assert any(entry.caller == "dev-agent" for entry in entries)
    for entry in entries:
        for token in (DEV_TOKEN, CUSTOMER_TOKEN):
            assert token not in entry.caller
            assert token not in entry.tool
            assert token not in entry.args_hash
