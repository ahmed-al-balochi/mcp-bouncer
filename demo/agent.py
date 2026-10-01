"""A minimal MCP client for driving the demo by hand.

It connects to the gate over HTTP, calls one tool, and prints the outcome. Over
HTTP the gate requires a bearer token, since the listener crosses a network.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Sequence

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

TOKEN_ENV = "BOUNCER_DEMO_TOKEN"


async def call(url: str, token: str, tool: str, arguments: dict) -> int:
    transport = StreamableHttpTransport(url, headers={"Authorization": f"Bearer {token}"})
    async with Client(transport) as client:
        result = await client.call_tool(tool, arguments, raise_on_error=False)
    print(f"error: {result.is_error}")
    for item in result.content:
        print(getattr(item, "text", item))
    return 1 if result.is_error else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent",
        description="Call one tool through the gate, as the agent would.",
    )
    parser.add_argument("tool", help="tool name, e.g. wiki.delete_page")
    parser.add_argument(
        "arguments",
        nargs="?",
        default="{}",
        help='tool arguments as JSON, e.g. \'{"title": "home"}\'',
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8000/mcp",
        help="the gate's MCP endpoint (default: %(default)s)",
    )
    parser.add_argument(
        "--token",
        default=None,
        help=(
            "bearer token identifying this agent to the gate"
            f" (default: ${TOKEN_ENV})"
        ),
    )
    args = parser.parse_args(argv)

    token = args.token or os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        parser.error(
            "the gate requires a bearer token over HTTP; pass --token or set "
            f"${TOKEN_ENV}. The token must be one the running gate knows. See "
            "the README's demo section."
        )

    try:
        arguments = json.loads(args.arguments)
    except json.JSONDecodeError as error:
        parser.error(f"arguments must be valid JSON: {error}")
    if not isinstance(arguments, dict):
        parser.error("arguments must be a JSON object, e.g. '{\"title\": \"home\"}'")
    return asyncio.run(call(args.url, token, args.tool, arguments))


if __name__ == "__main__":
    sys.exit(main())
