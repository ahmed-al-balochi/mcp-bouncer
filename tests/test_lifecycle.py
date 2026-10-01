"""End-to-end, through a real FastMCP proxy in front of the real demo server.
Every call goes over the MCP protocol via an in-memory transport, so the gate is
exercised as a proxy and not as a function call.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Mapping

import pytest
from fastmcp import Client, FastMCP

from demo.wiki_server import build_server
from gate import policy
from gate.approvals import ApprovalStore
from gate.audit import AuditLog
from gate.cli import main as gate_cli
from gate.middleware import APPROVAL_REQUIRED, BLOCKED
from gate.server import build_gate

CALLER = "agent-1"


@pytest.fixture
def upstream() -> FastMCP:
    return build_server()


@pytest.fixture
def gate(upstream: FastMCP, db_path: Path, policy_path: Path) -> Any:
    return build_gate(
        upstream, policy_path=policy_path, db_path=db_path, default_caller=CALLER
    )


def call(gate: Any, tool: str, arguments: Mapping[str, Any]) -> Any:
    async def _call() -> Any:
        async with Client(gate) as client:
            return await client.call_tool(tool, dict(arguments), raise_on_error=False)

    return asyncio.run(_call())


def text_of(result: Any) -> str:
    return result.content[0].text


def approval_id_from(result: Any) -> str:
    message = text_of(result)
    assert f"{APPROVAL_REQUIRED} id=" in message
    return message.split(f"{APPROVAL_REQUIRED} id=")[1].split()[0]


def park_approve_and_retry(gate: Any, db_path: Path, policy_path: Path, title: str) -> Any:
    parked = call(gate, "wiki.delete_page", {"title": title})
    approval_id = approval_id_from(parked)
    assert gate_cli(["--db", str(db_path), "--policy", str(policy_path), "approve", approval_id]) == 0
    return call(gate, "wiki.delete_page", {"title": title})


def test_a_read_passes_through_to_the_upstream_server(gate: Any):
    result = call(gate, "wiki.read_page", {"title": "home"})
    assert result.is_error is False
    assert "Welcome to the demo wiki." in text_of(result)


def test_a_write_passes_through(gate: Any):
    assert call(gate, "wiki.write_page", {"title": "notes", "body": "hello"}).is_error is False
    assert "hello" in text_of(call(gate, "wiki.read_page", {"title": "notes"}))


def test_an_unclassified_tool_is_blocked_by_the_gate(gate: Any):
    result = call(gate, "wiki.rename_page", {"title": "home", "to": "index"})
    assert result.is_error is True
    message = text_of(result)
    assert BLOCKED in message
    assert "matches no entry in policy.yaml" in message


def test_a_destructive_call_is_parked_with_the_command_to_release_it(
    gate: Any, db_path: Path
):
    result = call(gate, "wiki.delete_page", {"title": "home"})

    assert result.is_error is True
    approval_id = approval_id_from(result)
    assert f"bouncer approve {approval_id}" in text_of(result)

    parked = ApprovalStore(db_path, ttl_minutes=10).list_pending()
    assert [(record.id, record.tool, record.caller) for record in parked] == [
        (approval_id, "wiki.delete_page", CALLER)
    ]

    # Parked means parked: the page is still there.
    assert call(gate, "wiki.read_page", {"title": "home"}).is_error is False


def test_approval_releases_the_call_exactly_once(
    gate: Any, db_path: Path, policy_path: Path
):
    released = park_approve_and_retry(gate, db_path, policy_path, "home")
    assert released.is_error is False
    assert "deleted home" in text_of(released)

    # The page really is gone upstream, so the call ran once.
    assert call(gate, "wiki.read_page", {"title": "home"}).is_error is True

    replay = call(gate, "wiki.delete_page", {"title": "home"})
    assert replay.is_error is True
    assert APPROVAL_REQUIRED in text_of(replay)


def test_an_approval_does_not_release_a_call_with_different_arguments(
    gate: Any, db_path: Path, policy_path: Path
):
    parked_home = call(gate, "wiki.delete_page", {"title": "home"})
    approval_id = approval_id_from(parked_home)
    assert gate_cli(["--db", str(db_path), "--policy", str(policy_path), "approve", approval_id]) == 0

    other = call(gate, "wiki.delete_page", {"title": "runbook"})
    assert other.is_error is True
    assert approval_id_from(other) != approval_id
    assert call(gate, "wiki.read_page", {"title": "runbook"}).is_error is False


def test_a_denied_call_stays_blocked(gate: Any, db_path: Path, policy_path: Path):
    parked = call(gate, "wiki.delete_page", {"title": "home"})
    approval_id = approval_id_from(parked)
    assert gate_cli(["--db", str(db_path), "--policy", str(policy_path), "deny", approval_id]) == 0

    retry = call(gate, "wiki.delete_page", {"title": "home"})
    assert retry.is_error is True
    assert approval_id_from(retry) != approval_id
    assert call(gate, "wiki.read_page", {"title": "home"}).is_error is False


def test_the_fourth_destructive_call_in_the_hour_is_blocked(
    gate: Any, db_path: Path, policy_path: Path
):
    for title in ("alpha", "beta", "gamma", "delta"):
        assert call(gate, "wiki.write_page", {"title": title, "body": "x"}).is_error is False

    for title in ("alpha", "beta", "gamma"):
        assert park_approve_and_retry(gate, db_path, policy_path, title).is_error is False

    blocked = call(gate, "wiki.delete_page", {"title": "delta"})
    assert blocked.is_error is True
    message = text_of(blocked)
    assert BLOCKED in message
    assert f"bouncer reset {CALLER}" in message

    assert gate_cli(["--db", str(db_path), "--policy", str(policy_path), "reset", CALLER]) == 0
    assert park_approve_and_retry(gate, db_path, policy_path, "delta").is_error is False


def test_a_poisoned_policy_engine_blocks_everything_including_reads(
    gate: Any, monkeypatch: pytest.MonkeyPatch
):
    def explode(*_args: Any, **_kwargs: Any) -> str:
        raise RuntimeError("classifier is broken")

    monkeypatch.setattr(policy, "classify", explode)

    for tool, arguments in (
        ("wiki.read_page", {"title": "home"}),
        ("wiki.write_page", {"title": "home", "body": "x"}),
        ("wiki.delete_page", {"title": "home"}),
    ):
        result = call(gate, tool, arguments)
        assert result.is_error is True, tool
        assert BLOCKED in text_of(result)
        assert "no fail-open path" in text_of(result)


def test_every_decision_is_recorded_in_the_audit_log(
    gate: Any, db_path: Path, policy_path: Path
):
    call(gate, "wiki.read_page", {"title": "home"})
    call(gate, "wiki.rename_page", {"title": "home"})
    park_approve_and_retry(gate, db_path, policy_path, "home")

    entries = AuditLog(db_path).entries()
    recorded = [(entry.tool, entry.classification, entry.decision) for entry in entries]
    assert recorded == [
        ("wiki.read_page", "read", "pass"),
        ("wiki.rename_page", "unknown", "block"),
        ("wiki.delete_page", "destructive", "approve"),
        ("wiki.delete_page", "destructive", "pass"),
    ]
    assert all(entry.caller == CALLER for entry in entries)
    assert gate_cli(["--db", str(db_path), "--policy", str(policy_path), "log"]) == 0
