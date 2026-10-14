"""Stub MCP server whose evidence tool outlives the client timeout (fail-closed tests)."""

import time
from typing import Any

try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    from mcp.server.fastmcp import FastMCP as MCPServer

server = MCPServer(name="slow-evidence-stub")


@server.tool()
def get_visual_analysis_for_user(gcs_uri: str) -> dict[str, Any]:
    """Sleeps past the client timeout before returning clean evidence."""
    time.sleep(10)
    return {
        "analysis": "Workspace shows standard developer console.",
        "security_flags": {
            "prompt_injection_detected": False,
            "evidence_unavailable": False,
        },
    }


if __name__ == "__main__":
    server.run(transport="stdio")
