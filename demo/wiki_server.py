"""A toy upstream MCP server, so the gate has something real to sit in front of.

`delete_page` carries `destructiveHint: true`, which the gate only lets escalate.
`rename_page` is absent from policy.yaml, so the gate denies it as `unknown`.
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

    # No annotations, on purpose: this tool is deliberately unclassified in
    # policy.yaml so the gate denies it as `unknown` (see the module docstring).
    @server.tool(name="wiki.rename_page")
    def rename_page(title: str, new_title: str) -> str:
        """Rename a page, moving its body to the new title."""
        if title not in pages:
            raise ValueError(f"no such page: {title}")
        if new_title in pages:
            raise ValueError(f"page already exists: {new_title}")
        pages[new_title] = pages.pop(title)
        return f"renamed {title} to {new_title}"

    return server


mcp = build_server()

if __name__ == "__main__":
    mcp.run(transport="stdio")
