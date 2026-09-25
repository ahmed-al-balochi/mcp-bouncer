"""End-to-end: a team's tightened approval TTL is ENFORCED, not just advertised.

Bug D5.2 / R26 (owner-approved fix option a, DECISIONS D5.5). CustomerChat sets
`approval_ttl_minutes: 5`; the baseline is 10. The gate advertised "expires in 5
minutes" in its message, but the stored grant lived 10 minutes because the store
was constructed once with the baseline TTL and whichever process ran `approve`
(the CLI, which does not know the caller's team) wrote the expiry from that
baseline. This drove the bug behaviourally on the live AWS table.

These tests drive the gate as a real proxy over the in-memory transport (like
tests/test_lifecycle.py), park a destructive call as a team caller, approve it
through the store exactly as the operator CLI does, and then MEASURE the stored
grant's expiry the way D5.2 measured it live: `expires_at` minus the approve
moment. A CustomerChat grant must sit at ~5 minutes; a DevChat/baseline grant at
~10. The DevChat control is not vacuous -- it dies if the fix wrongly clamped
every grant to the tighter value.

A note on the clock: `build_gate` constructs its store internally through the
factory with the real `time.time`, so there is no fake-clock seam through the
proxy. Rather than assert on wall-clock waiting (flaky, and 5 real minutes long),
we assert on the stored expiry the fix writes -- the exact quantity the bug was
about (grant lifetime), read straight from the store. The store-level tests in
tests/test_approvals.py cover the fake-clock "consume refused past the short TTL"
behaviour deterministically across both backends.
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

    On the unfixed code the grant was written with the 10-minute baseline, so
    this measured ~600 s and the assertion fails -- exactly the bug found live.
    """
    lifetime = _park_and_measure(upstream, db_path, policy_path, CUSTOMER, "CustomerChat")
    # ~300 s, allowing a couple of seconds of test execution slack. Crucially it
    # is nowhere near the 600 s baseline.
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

    The message always said 5 minutes; the point of the fix is that the stored
    grant now matches it (checked by the two tests above). This guards the
    message half so a regression cannot silently drift the two apart again.
    """
    gate = _gate(upstream, db_path, policy_path, CUSTOMER, "CustomerChat")
    parked = _call(gate, "wiki.delete_page", {"title": "home"})
    assert "expires in 5 minutes" in _text(parked)


def test_cli_approve_prints_the_team_tightened_lifetime_not_the_baseline(
    upstream: FastMCP, db_path: Path, policy_path: Path, capsys: pytest.CaptureFixture[str]
):
    """`bouncer approve` states the grant's REAL lifetime (5 min for CustomerChat).

    The CLI is constructed with the baseline TTL (10) because it does not know
    the caller's team. Before the fix it printed "within 10 minutes" for a
    CustomerChat grant that it had just written to live 5. Now it prints the
    grant's own lifetime, read from the approval the store returns.
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
