"""
The MCP tool service split: the agent reaches its tools over Streamable HTTP with a
Google ID token when MCP_SERVER_URL is set, and the server admits only the allowed
caller. Locally (no URL) the agent keeps spawning a stdio MCP server.
"""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from google.adk.tools.mcp_tool.mcp_session_manager import (
    StdioConnectionParams,
    StreamableHTTPConnectionParams,
)
from starlette.testclient import TestClient

import adk_agent.agent as ag
from adk_agent.mcp_server import server

REPO_ROOT = Path(__file__).resolve().parents[4]
MCP_URL = "https://cymbal-cyber-mcp-123.us-east1.run.app/mcp"
AGENT_SA = "cymbal-adk-agent-sa@proj.iam.gserviceaccount.com"


def test_stdio_without_server_url(monkeypatch):
    monkeypatch.setattr(ag, "MCP_SERVER_URL", "")
    toolset = ag.create_mcp_toolset(["create_rich_ticket_id"])
    assert isinstance(toolset._connection_params, StdioConnectionParams)
    assert toolset.header_provider is None


def test_streamable_http_with_server_url(monkeypatch):
    provider = ag.McpIdTokenProvider(ag.mcp_audience(MCP_URL))
    monkeypatch.setattr(ag, "MCP_SERVER_URL", MCP_URL)
    monkeypatch.setattr(ag, "_mcp_header_provider", provider)
    toolset = ag.create_mcp_toolset(["create_rich_ticket_id"])
    params = toolset._connection_params
    assert isinstance(params, StreamableHTTPConnectionParams)
    assert params.url == MCP_URL
    assert params.timeout == ag.MCP_TOOL_TIMEOUT_SECONDS
    assert params.sse_read_timeout == ag.MCP_TOOL_TIMEOUT_SECONDS
    assert toolset.header_provider is provider


def test_audience_is_the_service_base_url():
    assert ag.mcp_audience(MCP_URL) == "https://cymbal-cyber-mcp-123.us-east1.run.app"


def test_id_token_is_minted_for_the_service_and_cached(monkeypatch):
    from google.oauth2 import id_token

    creds = MagicMock(valid=True, token="tok-1")
    fetch = MagicMock(return_value=creds)
    monkeypatch.setattr(id_token, "fetch_id_token_credentials", fetch)
    monkeypatch.setattr(ag, "LOCAL_MODE", False)
    provider = ag.McpIdTokenProvider("https://mcp.example")

    assert provider() == {"Authorization": "Bearer tok-1"}
    assert provider() == {"Authorization": "Bearer tok-1"}
    fetch.assert_called_once()
    assert fetch.call_args.args[0] == "https://mcp.example"
    creds.refresh.assert_not_called()

    creds.valid = False
    provider()
    creds.refresh.assert_called_once()


def test_no_token_in_local_mode(monkeypatch):
    monkeypatch.setattr(ag, "LOCAL_MODE", True)
    assert ag.McpIdTokenProvider("https://mcp.example")() == {}


def test_default_deny_toolset_is_attached_to_no_agent():
    """No model is ever offered the platform-only escalation tool."""
    for agent in (
        ag.bq_investigation_agent,
        ag.visual_analysis_agent,
        ag.soc_ticketing_agent,
    ):
        for toolset in agent.tools:
            assert "auto_escalate_unresolved_alert" not in (toolset.tool_filter or [])
    assert ag.default_deny_mcp.tool_filter == ["auto_escalate_unresolved_alert"]


@pytest.mark.parametrize(
    "header, claims, expected",
    [
        ("", None, 401),
        ("Basic abc", None, 401),
        ("Bearer bad", ValueError("bad signature"), 401),
        ("Bearer t", {"email": "someone@else.com", "email_verified": True}, 403),
        ("Bearer t", {"email": AGENT_SA, "email_verified": False}, 403),
        ("Bearer t", {"email": AGENT_SA, "email_verified": True}, 200),
    ],
)
def test_caller_check(monkeypatch, header, claims, expected):
    from google.oauth2 import id_token

    def verify(token, request, audience):
        assert audience == "https://mcp.example"
        if isinstance(claims, Exception):
            raise claims
        return claims

    monkeypatch.setattr(id_token, "verify_oauth2_token", verify)
    middleware = server.CallerAuthMiddleware(
        None, audience="https://mcp.example", allowed_caller=AGENT_SA
    )
    assert middleware.check(header)[0] == expected


def test_http_app_refuses_to_start_without_caller_check(monkeypatch):
    monkeypatch.setenv("LOCAL_MODE", "false")
    monkeypatch.delenv("MCP_EXPECTED_AUDIENCE", raising=False)
    monkeypatch.delenv("MCP_ALLOWED_CALLER", raising=False)
    with pytest.raises(RuntimeError):
        server.build_http_app()


def test_http_app_rejects_requests_without_a_token(monkeypatch):
    monkeypatch.setenv("LOCAL_MODE", "false")
    monkeypatch.setenv("MCP_EXPECTED_AUDIENCE", "https://mcp.example")
    monkeypatch.setenv("MCP_ALLOWED_CALLER", AGENT_SA)
    with TestClient(server.build_http_app()) as client:
        response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1})
    assert response.status_code == 401


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def http_mcp_server(tmp_path):
    """The real MCP server over Streamable HTTP, as Cloud Run runs it (LOCAL_MODE)."""
    port = _free_port()
    env = {
        **os.environ,
        "LOCAL_MODE": "true",
        "PORT": str(port),
        "LOCAL_QUEUE_DIR": str(tmp_path),
        "PYTHONPATH": str(REPO_ROOT),
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "adk_agent.mcp_server", "--http"],
        env=env,
        cwd=tmp_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            break
        except OSError:
            if proc.poll() is not None:
                pytest.fail("MCP HTTP server exited during startup")
            time.sleep(0.3)
    else:
        proc.kill()
        pytest.fail("MCP HTTP server did not start")
    yield f"http://127.0.0.1:{port}/mcp"
    proc.terminate()
    proc.wait(timeout=10)


@pytest.mark.asyncio
async def test_agent_toolset_calls_tools_over_http(http_mcp_server, monkeypatch):
    """The agent's scoped toolset lists only its filtered tools and calls them over HTTP."""
    monkeypatch.setattr(ag, "MCP_SERVER_URL", http_mcp_server)
    monkeypatch.setattr(ag, "_mcp_header_provider", None)
    toolset = ag.create_mcp_toolset(
        ["create_rich_ticket_id", "generate_signed_url"], toolset_name="soc_mcp"
    )
    try:
        tools = await toolset.get_tools()
        assert {t.name for t in tools} == {
            "create_rich_ticket_id",
            "generate_signed_url",
        }
        (ticket_tool,) = [t for t in tools if t.name == "create_rich_ticket_id"]
        result = await ticket_tool.run_async(
            args={"user_id": "u.lewis"}, tool_context=MagicMock()
        )
        payload = result.get("structuredContent") or result
        assert payload["ticket_id"].startswith("SOC-TICKET-u.lewis-")
    finally:
        await toolset.close()
