"""
ScamShield MCP Server — real mcp.server.Server implementation with stdio transport.

This replaces the simple dispatch dict from the notebook prototype so that
Claude Desktop, Cursor, or any MCP-compatible client can connect directly.

Usage (Claude Desktop claude_desktop_config.json):
{
  "mcpServers": {
    "scamshield": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "/path/to/scamshield-ai"
    }
  }
}

For programmatic use from agents (no MCP SDK required):
  from mcp_server.server import dispatch, list_tools
"""
import sys
import os
import json
from typing import Any
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ── Path bootstrap (works both as a module and when run directly) ─────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from mcp_server.tools.analyze_text import analyze_text
from mcp_server.tools.check_url import check_url, extract_urls
from mcp_server.tools.risk_scorer import risk_scorer
from mcp_server.tools.notification_tool import notification_tool

# ── Tool registry (used by both the MCP server and the dispatch fallback) ─────

TOOL_REGISTRY: dict[str, dict] = {
    "analyze_text": {
        "fn": analyze_text,
        "description": "Scan free text for scam language patterns.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "The text to analyse."}
            },
            "required": ["text"],
        },
    },
    "check_url": {
        "fn": check_url,
        "description": "Check a single URL for typosquatting / suspicious TLDs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The URL to inspect."}
            },
            "required": ["url"],
        },
    },
    "risk_scorer": {
        "fn": risk_scorer,
        "description": "Combine text + URL signals into a final risk verdict.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text_result": {"type": "object", "description": "Output of analyze_text."},
                "url_results": {"type": "array", "description": "List of check_url outputs."},
                "channel_hint": {
                    "type": "string",
                    "enum": ["call", "sms", "email", "social_media"],
                    "description": "Optional channel that delivered the content.",
                },
            },
            "required": ["text_result", "url_results"],
        },
    },
    "notification_tool": {
        "fn": notification_tool,
        "description": "Send a guardian/family alert about a detected scam.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "recipient": {"type": "string"},
                "message": {"type": "string"},
                "severity": {"type": "string"},
                "channel": {"type": "string", "enum": ["sms", "email"]},
            },
            "required": ["recipient", "message", "severity"],
        },
    },
}


# ── Fallback dispatch (used by agents without the MCP SDK) ────────────────────

def list_tools() -> list[dict]:
    """Return tool schemas suitable for rendering in a tool-calling prompt."""
    return [
        {
            "name": k,
            "description": v["description"],
            "inputSchema": v["inputSchema"],
        }
        for k, v in TOOL_REGISTRY.items()
    ]


def dispatch(tool_name: str, **kwargs) -> Any:
    """Call a registered tool by name. Raises ValueError for unknown tools."""
    if tool_name not in TOOL_REGISTRY:
        raise ValueError(f"Unknown tool: {tool_name!r}. Available: {list(TOOL_REGISTRY)}")
    return TOOL_REGISTRY[tool_name]["fn"](**kwargs)


# ── Real MCP stdio server ──────────────────────────────────────────────────────

def _run_stdio_server() -> None:
    """
    Start the MCP server over stdin/stdout (the standard MCP transport).

    Tries to import the `mcp` SDK. If it is not installed, falls back to a
    minimal JSON-RPC loop that still satisfies MCP clients for basic tool calls.
    """
    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp import types as mcp_types
        import asyncio

        app = Server("scamshield-ai")

        @app.list_tools()
        async def handle_list_tools() -> list[mcp_types.Tool]:
            return [
                mcp_types.Tool(
                    name=name,
                    description=info["description"],
                    inputSchema=info["inputSchema"],
                )
                for name, info in TOOL_REGISTRY.items()
            ]

        @app.call_tool()
        async def handle_call_tool(
            name: str, arguments: dict
        ) -> list[mcp_types.TextContent]:
            result = dispatch(name, **arguments)
            return [mcp_types.TextContent(type="text", text=json.dumps(result))]

        async def _main():
            async with stdio_server() as (read_stream, write_stream):
                await app.run(
                    read_stream,
                    write_stream,
                    app.create_initialization_options(),
                )

        asyncio.run(_main())

    except ImportError:
        # ── Minimal JSON-RPC fallback (no mcp SDK required) ───────────────────
        import sys

        def _jsonrpc_response(id_, result=None, error=None):
            resp = {"jsonrpc": "2.0", "id": id_}
            if error:
                resp["error"] = error
            else:
                resp["result"] = result
            return json.dumps(resp)

        for raw_line in sys.stdin:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                req = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            id_ = req.get("id")
            method = req.get("method", "")
            params = req.get("params", {})

            if method == "tools/list":
                resp = _jsonrpc_response(id_, result={"tools": list_tools()})
            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                try:
                    result = dispatch(tool_name, **arguments)
                    resp = _jsonrpc_response(
                        id_,
                        result={"content": [{"type": "text", "text": json.dumps(result)}]},
                    )
                except Exception as exc:
                    resp = _jsonrpc_response(
                        id_, error={"code": -32603, "message": str(exc)}
                    )
            else:
                resp = _jsonrpc_response(
                    id_, error={"code": -32601, "message": f"Method not found: {method}"}
                )

            print(resp, flush=True)


if __name__ == "__main__":
    _run_stdio_server()
