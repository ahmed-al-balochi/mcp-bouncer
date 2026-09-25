"""A stdio MCP upstream that delays its own start-up, used to reproduce the
cold-spawn era-collision (bug D5.3/D5.8) deterministically in a unit test.

Why this exists as a real spawned script rather than an in-memory server:

    The collision is a property of fastmcp's ONE shared ``StdioTransport`` with
    ``keep_alive=True`` that the proxy spawns lazily on the first request. An
    in-memory ``FastMCP`` upstream is not spawned and has no ``StdioTransport``,
    so it cannot reproduce the bug at all. The bug only lives on the stdio
    (script-path / command) transport, which is exactly the deployed path (R35),
    so the regression test must drive that path.

Why the delay is BAKED into a generated launcher rather than read from an env var:

    fastmcp spawns the child through the MCP SDK's ``stdio_client``, which does
    NOT inherit the parent's arbitrary environment -- only a small safe allowlist
    (``mcp.client.stdio.DEFAULT_INHERITED_ENV_VARS``: PATH, HOME, ...). So a
    ``SLOW_UPSTREAM_DELAY`` env var set in the test would never reach the child.
    The delay therefore has to be part of the script the child runs. `write_slow_upstream`
    generates a tiny self-contained launcher (in the test's ``tmp_path``) whose
    delay and crash flag are literals, and that launcher calls ``run`` here.

Why a sleep before serving reproduces it:

    In production the trigger is a cold child on 0.25 vCPU Fargate whose Python +
    fastmcp import takes longer than the client's ``DISCOVER_TIMEOUT_SECONDS``
    (10 s), so the modern ``server/discover`` probe times out and the front
    falls back to the legacy handshake. The two eras then ask the one shared
    stdio transport for different ``TransportOptions`` and ``StdioTransport``
    refuses. A test cannot wait 10 s, so it shrinks the timeout to ~1 s and bakes
    a ~2 s delay: the same ordering, in a fraction of the wall-clock time.
"""

from __future__ import annotations

import time
from pathlib import Path


def run(*, delay_seconds: float = 0.0, crash: bool = False) -> None:
    """Sleep, then either crash (never serve) or serve a tiny wiki over stdio.

    The sleep happens BEFORE importing/building fastmcp, so the child is
    demonstrably not answering for the whole delay -- mimicking a slow cold
    interpreter + import, which is what makes the modern probe time out.
    """
    time.sleep(max(0.0, delay_seconds))

    # A crash seam: exit WITHOUT serving MCP, so the proxy's warm-up connection
    # fails to initialise. This exercises the refuse-to-boot path for an upstream
    # that IS a valid script (so create_proxy builds a transport) but cannot
    # actually be reached -- distinct from a bad path, which create_proxy rejects
    # earlier.
    if crash:
        raise SystemExit(17)

    from fastmcp import FastMCP

    server: FastMCP = FastMCP(name="slow-wiki")
    pages = {"home": "Welcome to the demo wiki."}

    @server.tool(name="wiki.read_page")
    def read_page(title: str) -> str:
        """Return the body of a page."""
        if title not in pages:
            raise ValueError(f"no such page: {title}")
        return pages[title]

    @server.tool(name="wiki.write_page")
    def write_page(title: str, body: str) -> str:
        """Create or overwrite a page."""
        pages[title] = body
        return f"wrote {title} ({len(body)} characters)"

    @server.tool(name="wiki.delete_page", annotations={"destructiveHint": True})
    def delete_page(title: str) -> str:
        """Delete a page permanently."""
        if title not in pages:
            raise ValueError(f"no such page: {title}")
        del pages[title]
        return f"deleted {title}"

    server.run(transport="stdio")


def write_slow_upstream(
    directory: Path, *, delay_seconds: float = 0.0, crash: bool = False
) -> Path:
    """Write a self-contained launcher script into ``directory`` and return it.

    The launcher puts the tests package's parent on ``sys.path`` (the child
    inherits PATH but not this process's ``sys.path``) and calls ``run`` with the
    delay and crash flag baked in as literals, so no environment inheritance is
    needed. Returns the script path to hand to ``build_gate`` as the upstream.
    """
    tests_parent = Path(__file__).resolve().parent.parent  # the project root
    script = directory / "slow_upstream_launcher.py"
    script.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(tests_parent)!r})\n"
        "from tests.slow_upstream import run\n"
        f"run(delay_seconds={float(delay_seconds)!r}, crash={bool(crash)!r})\n"
    )
    return script
