"""A team's tightened approval TTL is enforced, not just advertised.
CustomerChat sets a 5-minute TTL against a 10-minute baseline. These park a call
as a team caller, approve via the store, and measure the stored grant's lifetime.
"""

from __future__ import annotations

import asyncio
import sqlite3
import time
from pathlib import Path
from typing import Any, Mapping

import pytest
from fastmcp import Client, FastMCP

from demo.wiki_server import build_server
from gate.cli import main as gate_cli
from gate.middleware import APPROVAL_REQUIRED
from gate.server import build_gate

CUSTOMER = "customer-agent"
DEV = "dev-agent"


@pytest.fixture
def upstream() -> FastMCP:
    return build_server()


def _gate(upstream: FastMCP, db_path: Path, policy_path: Path, caller: str, team: str) -> Any:
    # In-memory / stdio trust model: --caller and --team ARE the identity, so we
    # can drive a specific team without standing up HTTP and tokens.
    return build_gate(
        upstream,
        policy_path=policy_path,
        db_path=db_path,
        default_caller=caller,
        team=team,
    )


def _call(gate: Any, tool: str, arguments: Mapping[str, Any]) -> Any:
    async def _run() -> Any:
        async with Client(gate) as client:
            return await client.call_tool(tool, dict(arguments), raise_on_error=False)

    return asyncio.run(_run())


def _text(result: Any) -> str:
    return result.content[0].text


def _approval_id(result: Any) -> str:
    message = _text(result)
    assert f"{APPROVAL_REQUIRED} id=" in message, message
    return message.split(f"{APPROVAL_REQUIRED} id=")[1].split()[0]


def _grant_expires_at(db_path: Path, caller: str) -> float:
    connection = sqlite3.connect(db_path)
    try:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT expires_at FROM grants WHERE caller = ?", (caller,)
        ).fetchone()
    finally:
        connection.close()
    assert row is not None, "expected a grant row for the caller"
    return float(row["expires_at"])


def _park_and_measure(
    upstream: FastMCP, db_path: Path, policy_path: Path, caller: str, team: str
) -> float:
    """Park a delete as `team`, approve via the CLI, return expires_at - approve_time."""
    gate = _gate(upstream, db_path, policy_path, caller, team)

    parked = _call(gate, "wiki.delete_page", {"title": "home"})
    assert parked.is_error is True
    approval_id = _approval_id(parked)

    approve_moment = time.time()
    assert (
        gate_cli(
            ["--db", str(db_path), "--policy", str(policy_path), "approve", approval_id]
        )
        == 0
    )
    return _grant_expires_at(db_path, caller) - approve_moment


def test_customerchat_grant_lives_the_team_tightened_five_minutes(
    upstream: FastMCP, db_path: Path, policy_path: Path
):
    """CustomerChat (approval_ttl_minutes: 5): the stored grant lives ~5 minutes.
    On the unfixed code it was written with the 10-minute baseline, so this
    measured ~600 s and failed, which was the bug found live.
    """
    lifetime = _park_and_measure(upstream, db_path, policy_path, CUSTOMER, "CustomerChat")
    # ~300 s, allowing a little test slack, and nowhere near the 600 s baseline.
    assert 295.0 <= lifetime <= 305.0, lifetime


def test_devchat_grant_still_lives_the_baseline_ten_minutes(
    upstream: FastMCP, db_path: Path, policy_path: Path
):
    """Control: DevChat did not tighten the TTL, so its grant still lives ~10 min.
    This proves the fix is per-team, not a blanket clamp to the tightest value:
    if it were, this would drop to ~300 s and fail.
    """
    lifetime = _park_and_measure(upstream, db_path, policy_path, DEV, "DevChat")
    assert 595.0 <= lifetime <= 605.0, lifetime


def test_customerchat_message_still_advertises_five_minutes(
    upstream: FastMCP, db_path: Path, policy_path: Path
):
    """The advertised TTL and the enforced TTL now agree for CustomerChat.
    The message always said 5 minutes; this guards that half so a regression
    cannot silently drift it from the stored grant the two tests above check.
    """
    gate = _gate(upstream, db_path, policy_path, CUSTOMER, "CustomerChat")
    parked = _call(gate, "wiki.delete_page", {"title": "home"})
    assert "expires in 5 minutes" in _text(parked)


def test_cli_approve_prints_the_team_tightened_lifetime_not_the_baseline(
    upstream: FastMCP, db_path: Path, policy_path: Path, capsys: pytest.CaptureFixture[str]
):
    """`bouncer approve` states the grant's real lifetime (5 min for CustomerChat).
    The CLI is built with the baseline TTL because it does not know the team.
    Before the fix it printed "within 10 minutes" for a grant written to live 5.
    """
    gate = _gate(upstream, db_path, policy_path, CUSTOMER, "CustomerChat")
    parked = _call(gate, "wiki.delete_page", {"title": "home"})
    approval_id = _approval_id(parked)

    capsys.readouterr()  # drop anything captured so far
    assert (
        gate_cli(
            ["--db", str(db_path), "--policy", str(policy_path), "approve", approval_id]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "within 5 minutes" in out, out
    assert "within 10 minutes" not in out, out


def test_cli_approve_prints_the_baseline_lifetime_for_an_untightened_team(
    upstream: FastMCP, db_path: Path, policy_path: Path, capsys: pytest.CaptureFixture[str]
):
    """Control: for DevChat (no TTL override) the CLI still prints 10 minutes."""
    gate = _gate(upstream, db_path, policy_path, DEV, "DevChat")
    parked = _call(gate, "wiki.delete_page", {"title": "home"})
    approval_id = _approval_id(parked)

    capsys.readouterr()
    assert (
        gate_cli(
            ["--db", str(db_path), "--policy", str(policy_path), "approve", approval_id]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "within 10 minutes" in out, out
