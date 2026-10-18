"""
How the agent reaches its tools: one scoped MCP toolset per agent, each an
allow-list of tool names. Locally the toolset spawns the MCP server over stdio; in
the cloud it calls the MCP tool service on Cloud Run over Streamable HTTP with a
Google ID token minted from the agent's own identity.
"""

import os
import sys
from typing import Any
from urllib.parse import urlsplit

from google.adk.tools.mcp_tool.mcp_session_manager import (
    StdioConnectionParams,
    StreamableHTTPConnectionParams,
)
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from mcp import StdioServerParameters

from adk_agent.settings import LOCAL_MODE, REPO_ROOT

os.environ["ADK_ALLOW_CONFIG_STDIO_MCP_SERVERS"] = "true"


# Per-request MCP timeout. ADK's stdio default is 5s for both connecting and each
# tool call, which a Gemini vision call or a cold MCP subprocess can exceed.
MCP_TOOL_TIMEOUT_SECONDS = float(os.getenv("MCP_TOOL_TIMEOUT_SECONDS", "90"))

# Where the tools run. Unset: an MCP server child process over stdio (local dev, tests).
# Set (the cloud): the MCP tool service on Cloud Run, e.g. https://<service>/mcp, which
# runs as its own service account; this agent's identity can only invoke it.
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "").strip()


class ScopedMcpToolset(McpToolset):
    """Scoped MCP toolset exposing designated tools over stdio JSON-RPC."""

    def __init__(self, *args: Any, toolset_name: str = "mcp_toolset", **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._toolset_name = toolset_name

    @property
    def name(self) -> str:
        if isinstance(self.tool_filter, list) and len(self.tool_filter) == 1:
            return self.tool_filter[0]
        return self._toolset_name


class McpIdTokenProvider:
    """
    Authorization headers for the MCP tool service: a Google ID token whose audience is
    the service URL, minted from this service's own identity (the metadata server on
    Cloud Run). The token is cached until it nears expiry, so MCP sessions, which ADK
    pools per header set, are reused for the token's hour instead of reopened per call.
    """

    def __init__(self, audience: str):
        self.audience = audience
        self._credentials = None

    def __call__(self, _readonly_context: Any = None) -> dict[str, str]:
        if LOCAL_MODE:
            return {}
        import google.auth.transport.requests
        from google.oauth2 import id_token

        request = google.auth.transport.requests.Request()
        if self._credentials is None:
            self._credentials = id_token.fetch_id_token_credentials(
                self.audience, request=request
            )
        if not self._credentials.valid:
            self._credentials.refresh(request)
        return {"Authorization": f"Bearer {self._credentials.token}"}


def mcp_audience(server_url: str) -> str:
    """Cloud Run accepts ID tokens whose audience is the service's base URL."""
    parts = urlsplit(server_url)
    return f"{parts.scheme}://{parts.netloc}"


_mcp_header_provider = (
    McpIdTokenProvider(mcp_audience(MCP_SERVER_URL)) if MCP_SERVER_URL else None
)


def mcp_connection_params(
    timeout: float | None = None, server_args: list[str] | None = None
) -> StdioConnectionParams | StreamableHTTPConnectionParams:
    """Streamable HTTP to MCP_SERVER_URL when set, else a stdio MCP server process."""
    timeout = timeout or MCP_TOOL_TIMEOUT_SECONDS
    if MCP_SERVER_URL and not server_args:
        return StreamableHTTPConnectionParams(
            url=MCP_SERVER_URL, timeout=timeout, sse_read_timeout=timeout
        )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(REPO_ROOT), os.environ.get("PYTHONPATH", "")) if p
    )
    return StdioConnectionParams(
        server_params=StdioServerParameters(
            command=sys.executable,
            args=server_args or ["-m", "adk_agent.mcp_server"],
            env=env,
        ),
        timeout=timeout,
    )


def create_mcp_toolset(
    tool_names: list[str],
    toolset_name: str = "mcp_toolset",
    timeout: float | None = None,
    server_args: list[str] | None = None,
) -> ScopedMcpToolset:
    """
    Instantiates one MCP toolset (one MCP connection) scoped to an agent's tools.
    The tool_filter is the agent's allow-list: tools not named here are never exposed to it.
    timeout overrides MCP_TOOL_TIMEOUT_SECONDS; server_args lets tests launch a stub server.
    """
    params = mcp_connection_params(timeout=timeout, server_args=server_args)
    return ScopedMcpToolset(
        connection_params=params,
        tool_filter=list(tool_names),
        toolset_name=toolset_name,
        header_provider=_mcp_header_provider
        if isinstance(params, StreamableHTTPConnectionParams)
        else None,
    )


# The default-deny callback's own connection to the tool service. Attached to no agent,
# so no model sees auto_escalate_unresolved_alert.
default_deny_mcp = create_mcp_toolset(
    ["auto_escalate_unresolved_alert"], toolset_name="default_deny_mcp"
)
