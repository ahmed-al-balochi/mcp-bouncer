"""Structured logging: what it records, and what it must never record.
Sentinel argument and token values are pushed through real decision and rejection
paths, and the captured log is searched for either. No AWS, no external network.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import socket
import threading
import time
from pathlib import Path
from typing import Any, Iterator

import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from demo.wiki_server import build_server
from gate import observability
from gate.identity import LOCAL_TOKENS_ENV
from gate.server import build_gate

# Deliberately distinctive so a substring search cannot miss them and cannot
# collide with anything the framework emits.
SENTINEL_ARG = "SENTINEL-ARGUMENT-VALUE-zzzz"
SENTINEL_TOKEN = "tok-SENTINEL-TOKEN-VALUE-qqqqqqqq"


@pytest.fixture
def captured_logs() -> Iterator[io.StringIO]:
    """Route the bouncer logger through the JSON formatter into a buffer.
    Uses the module's own configure_logging so the formatter under test runs,
    then restores the logger's handlers afterwards.
    """
    buffer = io.StringIO()
    logger = logging.getLogger(observability.ROOT_LOGGER_NAME)
    saved_handlers = logger.handlers
    saved_level = logger.level
    saved_propagate = logger.propagate
    observability.configure_logging(stream=buffer, level="DEBUG")
    try:
        yield buffer
    finally:
        logger.handlers = saved_handlers
        logger.setLevel(saved_level)
        logger.propagate = saved_propagate


def _lines(buffer: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]


# --- the in-memory (trusted) decision path --------------------------------


def _call(gate: Any, tool: str, arguments: dict[str, Any]) -> Any:
    async def _run() -> Any:
        async with Client(gate) as client:
            return await client.call_tool(tool, arguments, raise_on_error=False)

    return asyncio.run(_run())


def test_the_allowed_path_logs_a_decision_without_arguments(
    captured_logs: io.StringIO, policy_path: Path, db_path: Path
):
    gate = build_gate(
        build_server(), policy_path=policy_path, db_path=db_path, default_caller="agent-1"
    )
    result = _call(gate, "wiki.write_page", {"title": "notes", "body": SENTINEL_ARG})
    assert result.is_error is False

    dump = captured_logs.getvalue()
    assert SENTINEL_ARG not in dump, "argument value leaked into the log"

    decisions = [entry for entry in _lines(captured_logs) if entry.get("event") == "decision"]
    assert decisions, "no decision was logged on the allowed path"
    record = decisions[-1]
    # It logged the fields an operator needs...
    assert record["caller"] == "agent-1"
    assert record["tool"] == "wiki.write_page"
    assert record["classification"] == "write"
    assert record["decision"] == "pass"
    # ...and a hash stands in for the arguments.
    assert record["args_hash"]
    assert SENTINEL_ARG not in record["args_hash"]


def test_the_parked_path_logs_a_decision_without_arguments(
    captured_logs: io.StringIO, policy_path: Path, db_path: Path
):
    gate = build_gate(
        build_server(), policy_path=policy_path, db_path=db_path, default_caller="agent-1"
    )
    result = _call(gate, "wiki.delete_page", {"title": SENTINEL_ARG})
    assert result.is_error is True  # parked

    dump = captured_logs.getvalue()
    assert SENTINEL_ARG not in dump
    decisions = [entry for entry in _lines(captured_logs) if entry.get("event") == "decision"]
    assert decisions[-1]["decision"] == "approve"
    assert decisions[-1]["classification"] == "destructive"


# --- the rejected (HTTP, untrusted) path ----------------------------------


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


def test_an_authentication_rejection_logs_no_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, policy_path: Path
):
    """Push a real bad token across a real socket and prove it is not in the log.
    The token is rejected at the session layer, so the client raises.
    The rejection is logged by shape ("unrecognised bearer token"), not the token.
    """
    monkeypatch.setenv(
        LOCAL_TOKENS_ENV,
        json.dumps({"tok-real-aaaaaaaaaaaa": {"caller": "dev-agent", "team": "DevChat"}}),
    )
    db_path = tmp_path / "reject-gate.db"
    port = _free_port()

    buffer = io.StringIO()
    logger = logging.getLogger(observability.ROOT_LOGGER_NAME)
    saved = (logger.handlers, logger.level, logger.propagate)
    observability.configure_logging(stream=buffer, level="DEBUG")

    gate = build_gate(
        build_server(), policy_path=policy_path, db_path=db_path, transport="http"
    )
    thread = threading.Thread(
        target=lambda: gate.run(transport="http", host="127.0.0.1", port=port),
        daemon=True,
    )
    thread.start()
    _await_listening("127.0.0.1", port)
    time.sleep(1.0)

    try:
        raised = False

        async def _run() -> Any:
            transport = StreamableHttpTransport(
                f"http://127.0.0.1:{port}/mcp/",
                headers={"Authorization": f"Bearer {SENTINEL_TOKEN}"},
            )
            async with Client(transport) as client:
                # `initialize` happens on context entry; the session is rejected
                # there because the token is unknown.
                return await client.list_tools()

        try:
            asyncio.run(_run())
        except Exception:
            raised = True

        assert raised, "an unknown token must be rejected at the session layer"

        dump = buffer.getvalue()
        assert SENTINEL_TOKEN not in dump, "a bearer token leaked into the log"
        assert SENTINEL_ARG not in dump, "an argument value leaked into the log"
        # The rejection was recorded, by shape, without the credential.
        assert "unrecognised bearer token" in dump, "the rejection was not logged"
    finally:
        logger.handlers, logger.level, logger.propagate = saved


# --- boot configuration is redacted ---------------------------------------


def test_boot_config_logs_identifiers_but_no_secret_payload(captured_logs: io.StringIO):
    observability.log_boot(
        {
            "transport": "http",
            "store": "dynamodb",
            "identity_source": "secretsmanager",
            "tokens_secret": "arn:aws:secretsmanager:region:acct:secret:name",
        }
    )
    boots = [entry for entry in _lines(captured_logs) if entry.get("event") == "boot"]
    assert boots, "boot was not logged"
    record = boots[-1]
    # The secret ID is an identifier and is allowed; a token map never reaches
    # this helper, so there is nothing here to assert absent that could arrive.
    assert record["tokens_secret"].startswith("arn:aws:secretsmanager:")
    assert record["store"] == "dynamodb"


# --- logging must never change a call's outcome ---------------------------


def test_a_logging_failure_does_not_change_an_allowed_calls_outcome(
    monkeypatch: pytest.MonkeyPatch, policy_path: Path, db_path: Path
):
    """Break the log emit, then confirm an allowed call still succeeds and a
    parked call still parks. A logging fault must not turn a pass into an error,
    nor, in the dangerous direction, a block into a pass."""

    def explode(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("logging subsystem is down")

    # Patch the underlying logger.log so even the choke point's own call raises;
    # the choke point's try/except is what must absorb it.
    monkeypatch.setattr(observability._logger, "log", explode)

    gate = build_gate(
        build_server(), policy_path=policy_path, db_path=db_path, default_caller="agent-1"
    )

    allowed = _call(gate, "wiki.read_page", {"title": "home"})
    assert allowed.is_error is False, "a logging failure turned an allowed call into an error"

    parked = _call(gate, "wiki.delete_page", {"title": "home"})
    assert parked.is_error is True, "a logging failure turned a blocked call into a pass"


# --- fail-closed lines are attributable to a team -------------------


def _fail_closed_lines(buffer: io.StringIO) -> list[dict[str, Any]]:
    return [entry for entry in _lines(buffer) if entry.get("event") == "fail_closed"]


def test_a_fail_closed_block_names_the_callers_team(
    captured_logs: io.StringIO,
    monkeypatch: pytest.MonkeyPatch,
    policy_path: Path,
    db_path: Path,
):
    """A fail-closed block is grouped by team, so the team must be on the line.
    The failure is injected after the caller is identified. A fail-closed block
    writes no decision line, so the rate's denominator counts both events.
    """
    from gate import policy

    def explode(*_args: Any, **_kwargs: Any) -> str:
        raise RuntimeError("classifier is broken")

    monkeypatch.setattr(policy, "classify", explode)
    gate = build_gate(
        build_server(),
        policy_path=policy_path,
        db_path=db_path,
        default_caller="agent-1",
        team="CustomerChat",
    )

    result = _call(gate, "wiki.read_page", {"title": SENTINEL_ARG})
    assert result.is_error is True

    lines = _fail_closed_lines(captured_logs)
    assert len(lines) == 1
    assert lines[0]["team"] == "CustomerChat"
    assert lines[0]["caller"] == "agent-1"
    assert lines[0]["tool"] == "wiki.read_page"
    assert SENTINEL_ARG not in captured_logs.getvalue()
    assert not [e for e in _lines(captured_logs) if e.get("event") == "decision"]


def test_a_fail_closed_block_before_identification_is_unattributed(
    captured_logs: io.StringIO,
    monkeypatch: pytest.MonkeyPatch,
    policy_path: Path,
    db_path: Path,
):
    """If identity itself fails, there is no team to name, and none is guessed:
    the field is present and null, so the block counts as unattributed."""
    from gate.middleware import GateMiddleware

    def explode(_self: Any) -> Any:
        raise RuntimeError("identity source is broken")

    monkeypatch.setattr(GateMiddleware, "_resolve_identity", explode)
    gate = build_gate(
        build_server(),
        policy_path=policy_path,
        db_path=db_path,
        default_caller="agent-1",
        team="CustomerChat",
    )

    result = _call(gate, "wiki.read_page", {"title": "home"})
    assert result.is_error is True

    lines = _fail_closed_lines(captured_logs)
    assert len(lines) == 1
    assert "team" in lines[0]
    assert lines[0]["team"] is None
