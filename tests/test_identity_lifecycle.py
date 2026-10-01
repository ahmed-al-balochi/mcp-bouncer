"""End-to-end identity and per-team policy, through the real HTTP proxy.
Unlike test_lifecycle.py, these speak to a real HTTP listener over a socket, the
only honest way to exercise the bearer-token path, with no AWS or external network.
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
from fastmcp.exceptions import ClientError, MCPError

from demo.wiki_server import build_server
from gate.audit import AuditLog
from gate.cli import main as gate_cli
from gate.identity import LOCAL_TOKENS_ENV
from gate.middleware import APPROVAL_REQUIRED
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
    loop; the DB is a fresh file per test so approvals do not bleed across tests.
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


# HTTP auth is enforced on the whole session before the
# session manager, so a request without a valid token cannot even initialize:
# the client raises during setup rather than returning an error ToolResult.
SESSION_REJECTED = (MCPError, ClientError)


def initialize_rejected(url: str, token: str | None) -> bool:
    """True iff a session with this token cannot initialize or list tools.
    Exercises the two session operations, initialize and tools/list,
    because the point is that the catalogue is unreachable without a token.
    """
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}

    async def _run() -> Any:
        transport = StreamableHttpTransport(url, headers=headers)
        async with Client(transport) as client:
            # Entering the context performs initialize; list_tools reads the
            # catalogue. Either failing before returning is a rejection.
            return await client.list_tools()

    try:
        asyncio.run(_run())
        return False
    except SESSION_REJECTED:
        return True


def text_of(result: Any) -> str:
    return result.content[0].text


def approval_id_from(result: Any) -> str:
    message = text_of(result)
    assert f"{APPROVAL_REQUIRED} id=" in message
    return message.split(f"{APPROVAL_REQUIRED} id=")[1].split()[0]


# --- rejection at the door (the SESSION, not just the call) --


def test_a_session_with_no_token_cannot_initialize_or_list_tools(http_gate: str):
    """No Authorization header: the session never initializes, so the catalogue
    is unreachable. This is stronger than the old "the tool call is blocked":
    an unauthenticated client cannot even discover what tools exist."""
    assert initialize_rejected(http_gate, None) is True


def test_a_session_with_an_unknown_token_cannot_initialize_or_list_tools(
    http_gate: str,
):
    assert initialize_rejected(http_gate, "tok-not-real") is True


def test_a_malformed_authorization_header_is_rejected(http_gate: str):
    """A `Basic` scheme and an empty `Bearer ` are both malformed: neither is a
    valid bearer token, so the session is rejected exactly as a missing one is,
    and the client cannot tell the three cases apart (oracle-safe)."""

    def rejected_with_raw_header(raw: str) -> bool:
        async def _run() -> Any:
            transport = StreamableHttpTransport(
                http_gate, headers={"Authorization": raw}
            )
            async with Client(transport) as client:
                return await client.list_tools()

        try:
            asyncio.run(_run())
            return False
        except SESSION_REJECTED:
            # Rejected server-side: the verifier returned no identity, 401.
            return True
        except (RuntimeError, ValueError):
            # Rejected client-side: an empty Bearer is an illegal header value,
            # so the client refuses to transmit it. Either way, no session.
            return True

    # Wrong scheme: server-side rejection.
    assert rejected_with_raw_header("Basic dXNlcjpwYXNz") is True
    # Empty bearer token: rejected (client refuses the illegal header value).
    assert rejected_with_raw_header("Bearer ") is True
    # A bare token with no scheme is also malformed and refused.
    assert rejected_with_raw_header(DEV_TOKEN) is True


def test_a_valid_token_initializes_lists_tools_and_reads(http_gate: str):
    """The positive path across a real socket: a valid token establishes the
    session, lists the catalogue, and a read tool call returns the upstream
    content with the correct caller in force."""
    # Session + catalogue listing succeed.
    assert initialize_rejected(http_gate, DEV_TOKEN) is False

    # And a read call runs.
    result = call(http_gate, DEV_TOKEN, "wiki.read_page", {"title": "home"})
    assert result.is_error is False
    assert "Welcome to the demo wiki." in text_of(result)


def test_the_read_call_records_the_authenticated_caller(
    http_gate: str, tmp_path: Path
):
    """The caller resolved from the same Authorization header the session
    verifier accepted is the one attributed in the audit log, proving the header
    reaches on_call_tool even with the auth middleware installed."""
    db_path = tmp_path / "http-gate.db"
    result = call(http_gate, DEV_TOKEN, "wiki.read_page", {"title": "home"})
    assert result.is_error is False

    entries = AuditLog(db_path).entries()
    reads = [e for e in entries if e.tool == "wiki.read_page"]
    assert reads, "the read was not audited"
    assert reads[-1].caller == "dev-agent"


# --- the tightening override takes effect end to end -----------


def test_a_write_parks_for_customerchat_but_passes_for_devchat(http_gate: str):
    """wiki.write_page is `write` at baseline: DevChat passes it, CustomerChat
    (which promotes it to destructive) parks it. Same tool, same arguments, two
    teams, two outcomes, proven through the real proxy."""
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


# --- the two callers' destructive counters are independent -----------


def test_two_callers_have_independent_destructive_counters(
    http_gate: str, tmp_path: Path, policy_path: Path
):
    """DevChat's cap is 2. The dev caller uses up its own allowance; the customer
    caller, on a different identity, is unaffected. Its own (tighter) cap of 1
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


# --- tokens never leak (security property) -----------------------------


def test_a_token_never_appears_in_the_audit_log_or_an_error(
    http_gate: str, tmp_path: Path
):
    """Assert, do not assume: exercise good and bad tokens, then scan the audit
    log and every message a caller could see (error text or raised exception)
    for any token value."""
    db_path = tmp_path / "http-gate.db"

    good = call(http_gate, DEV_TOKEN, "wiki.read_page", {"title": "home"})
    assert good.is_error is False

    # Bad and missing tokens are now rejected at the session layer, so they
    # surface as raised exceptions rather than error ToolResults. The exception
    # text a caller sees must not carry the token either.
    seen_messages: list[str] = [text_of(good)]

    def capture(token: str | None) -> None:
        try:
            call(http_gate, token, "wiki.read_page", {"title": "home"})
        except SESSION_REJECTED as error:
            seen_messages.append(str(error))

    capture("tok-not-real")
    capture(None)

    for message in seen_messages:
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


def test_the_token_source_is_read_once_at_boot_over_http(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, policy_path: Path
) -> None:
    """The session verifier and the per-call resolver share one token table.
    Building them independently read the source twice, so a rotation between the
    reads could leave them inconsistent. Counting loads pins that there is one.
    """
    import gate.identity as identity_module

    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(TOKENS))
    loads: list[int] = []
    real_load = identity_module._load_tokens

    def counting_load(*args: Any, **kwargs: Any) -> Any:
        loads.append(1)
        return real_load(*args, **kwargs)

    monkeypatch.setattr(identity_module, "_load_tokens", counting_load)
    build_gate(
        build_server(),
        policy_path=policy_path,
        db_path=tmp_path / "once.db",
        transport="http",
    )
    assert len(loads) == 1


def test_the_per_call_check_blocks_even_if_the_session_layer_never_ran(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, policy_path: Path
) -> None:
    """Defence in depth: on_call_tool authenticates on its own.
    The in-memory transport reaches the middleware without the HTTP app, so the
    session verifier never runs. Without this test it could wave such calls through.
    """
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(TOKENS))
    db_path = tmp_path / "depth.db"
    gate = build_gate(
        build_server(), policy_path=policy_path, db_path=db_path, transport="http"
    )

    async def call() -> Any:
        async with Client(gate) as client:
            return await client.call_tool(
                "wiki.read_page", {"title": "home"}, raise_on_error=False
            )

    result = asyncio.run(call())
    assert result.is_error
    rows = AuditLog(db_path).entries()
    # Rejected before classification: attributed to no one, recorded as a block.
    assert [(row.caller, row.tool, row.decision) for row in rows] == [
        ("<unreadable>", "wiki.read_page", "block")
    ]
