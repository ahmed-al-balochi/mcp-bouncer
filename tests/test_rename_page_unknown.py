"""The demo upstream's `wiki.rename_page` is a real tool the gate denies as
`unknown`. The upstream advertises a working tool policy.yaml has not
classified, so the gate must block it before it runs, over the in-memory transport.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Mapping

import pytest
from fastmcp import Client, FastMCP

from demo.wiki_server import build_server
from gate.audit import AuditLog
from gate.middleware import BLOCKED
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


def tool_names(gate: Any) -> list[str]:
    async def _list() -> list[str]:
        async with Client(gate) as client:
            return [tool.name for tool in await client.list_tools()]

    return asyncio.run(_list())


def text_of(result: Any) -> str:
    return result.content[0].text


def test_the_gate_catalogue_advertises_rename_page(gate: Any):
    """A client talking to the gate sees rename_page, so it is a real, reachable
    tool. That is the precondition for the honest 'unknown tool denied' case."""
    assert "wiki.rename_page" in tool_names(gate)


def test_calling_rename_page_through_the_gate_is_blocked_as_unknown(
    gate: Any, db_path: Path
):
    """FAILS if rename_page is ever classified: the call would pass and the page
    would be renamed. The tool is real, so the ONLY reason it does not run is the
    gate denying it as unknown."""
    result = call(
        gate, "wiki.rename_page", {"title": "home", "new_title": "index"}
    )

    assert result.is_error is True
    message = text_of(result)
    assert BLOCKED in message
    assert "matches no entry in policy.yaml" in message

    # The audit row records the gate's verdict: unclassified, blocked.
    entries = AuditLog(db_path).entries()
    assert [(e.tool, e.classification, e.decision) for e in entries] == [
        ("wiki.rename_page", "unknown", "block")
    ]

    # The upstream tool never ran: the original page is still readable under its
    # old title through the gate, and the new title does not exist. If the call
    # had reached the upstream, "home" would be gone and "index" would read back.
    original = call(gate, "wiki.read_page", {"title": "home"})
    assert original.is_error is False
    assert "Welcome to the demo wiki." in text_of(original)

    renamed = call(gate, "wiki.read_page", {"title": "index"})
    assert renamed.is_error is True


def test_the_upstream_rename_page_works_without_the_gate(upstream: FastMCP):
    """Unit level, no gate: the tool itself renames a page. So the denial above
    is the gate's doing, not a tool that was broken to begin with."""

    async def _rename_then_read() -> tuple[Any, Any, Any]:
        async with Client(upstream) as client:
            renamed = await client.call_tool(
                "wiki.rename_page",
                {"title": "home", "new_title": "index"},
                raise_on_error=False,
            )
            new = await client.call_tool(
                "wiki.read_page", {"title": "index"}, raise_on_error=False
            )
            old = await client.call_tool(
                "wiki.read_page", {"title": "home"}, raise_on_error=False
            )
            return renamed, new, old

    renamed, new, old = asyncio.run(_rename_then_read())

    assert renamed.is_error is False
    assert "renamed home to index" in renamed.content[0].text
    # The body moved to the new title...
    assert new.is_error is False
    assert "Welcome to the demo wiki." in new.content[0].text
    # ...and the old title is gone.
    assert old.is_error is True
