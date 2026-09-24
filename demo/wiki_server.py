"""A toy upstream MCP server, so the gate has something real to sit in front of.

`delete_page` carries `destructiveHint: true`. The gate reads that hint but does
not depend on it: policy.yaml already classifies the tool as destructive, and the
hint is only allowed to escalate.
"""

from __future__ import annotations

from fastmcp import FastMCP

SEED_PAGES = {
    "home": "Welcome to the demo wiki.",
    "runbook": "1. Read the alarm. 2. Do not delete the wiki.",
}


def build_server() -> FastMCP:
    """Build a wiki server with its own fresh page store."""
    pages: dict[str, str] = dict(SEED_PAGES)
    server: FastMCP = FastMCP(name="demo-wiki")

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

    return server


mcp = build_server()

if __name__ == "__main__":
    mcp.run(transport="stdio")
