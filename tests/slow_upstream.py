"""A stdio MCP upstream that delays its start-up to reproduce the cold-spawn
era-collision in a test. It must be a real spawned script on the stdio transport,
the deployed path, with the delay baked into the launcher it runs.
"""

from __future__ import annotations

import time
from pathlib import Path


def run(*, delay_seconds: float = 0.0, crash: bool = False) -> None:
    """Sleep, then either crash (never serve) or serve a tiny wiki over stdio.
    The sleep happens before importing fastmcp, so the child is not answering
    for the whole delay, mimicking a slow cold interpreter and import.
    """
    time.sleep(max(0.0, delay_seconds))

    # Crash seam: exit without serving MCP so the proxy's warm-up connection
    # fails. This is a valid script that cannot be reached, distinct from a bad
    # path that create_proxy rejects earlier.
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
    """Write a self-contained launcher into ``directory`` and return its path.
    It puts the project root on sys.path (the child does not inherit it) and
    calls ``run`` with the delay and crash flag baked in as literals.
    """
    tests_parent = Path(__file__).resolve().parent.parent  # project root
    script = directory / "slow_upstream_launcher.py"
    script.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(tests_parent)!r})\n"
        "from tests.slow_upstream import run\n"
        f"run(delay_seconds={float(delay_seconds)!r}, crash={bool(crash)!r})\n"
    )
    return script
