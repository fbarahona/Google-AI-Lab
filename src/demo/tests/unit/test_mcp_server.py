"""
Unit Tests for Cymbal Cyber Local MCP Server.
============================================
Validates tool registration, JSON-RPC schemas, and tool execution over MCP.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from adk_agent.mcp_server.server import mcp_server


@pytest.mark.asyncio
async def test_mcp_server_initialization_and_tool_registration():
    """Verify that mcp_server initializes properly and registers all 10 tools."""
    assert mcp_server.name == "cymbal-cyber-mcp"
    tools = await mcp_server.list_tools()
    tool_names = {t.name for t in tools}

    expected_tools = {
        "get_entity_behavioral_profile",
        "execute_sql",
        "get_table_schema",
        "get_visual_analysis_for_user",
        "get_gcs_uri_for_user",
        "generate_signed_url",
        "create_rich_ticket_id",
        "dispatch_to_soc_ticketing_system",
        "log_false_positive",
        "escalate_to_human",
    }
    assert expected_tools.issubset(tool_names)


@pytest.mark.asyncio
async def test_mcp_server_call_get_entity_behavioral_profile(monkeypatch):
    """Verify calling get_entity_behavioral_profile via MCP server in local mode."""
    monkeypatch.setenv("LOCAL_MODE", "true")
    res = await mcp_server.call_tool(
        "get_entity_behavioral_profile",
        {
            "entity_type": "user",
            "entity_id": "u.lewis",
            "window_to_investigate": "24 HOUR",
        },
    )
    assert not res.is_error
    assert len(res.content) > 0
    content_text = res.content[0].text
    metrics = json.loads(content_text)
    assert "total_access_events_24h" in metrics
    assert "total_login_failures_24h" in metrics


@pytest.mark.asyncio
async def test_mcp_server_call_execute_sql_sandboxed(monkeypatch):
    """Verify executing sandboxed read-only SQL via MCP server."""
    monkeypatch.setenv("LOCAL_MODE", "true")
    res = await mcp_server.call_tool(
        "execute_sql",
        {"query": "SELECT * FROM `user_access_events` LIMIT 5"},
    )
    assert not res.is_error
    content_text = res.content[0].text
    assert "LOCAL_SIMULATION_SUCCESS" in content_text


@pytest.mark.asyncio
async def test_mcp_server_call_execute_sql_blocks_destructive(monkeypatch):
    """Verify that destructive SQL operations are blocked by MCP server tool execution."""
    monkeypatch.setenv("LOCAL_MODE", "true")
    res = await mcp_server.call_tool(
        "execute_sql",
        {"query": "DROP TABLE user_access_events"},
    )
    assert not res.is_error
    content_text = res.content[0].text
    assert "Tool execution was blocked" in content_text
    assert "Destructive SQL operation 'DROP' is strictly forbidden" in content_text


@pytest.mark.asyncio
async def test_mcp_server_call_get_table_schema(monkeypatch):
    """Verify table schema discovery tool over MCP."""
    monkeypatch.setenv("LOCAL_MODE", "true")
    res = await mcp_server.call_tool(
        "get_table_schema",
        {"dataset_id": "Cymbal_Cyber", "table_id": "user_access_events"},
    )
    assert not res.is_error
    content_text = res.content[0].text
    assert "LOCAL_SIMULATION" in content_text


@pytest.mark.asyncio
async def test_mcp_server_call_create_rich_ticket_id():
    """Verify ticket ID generation over MCP."""
    res = await mcp_server.call_tool(
        "create_rich_ticket_id",
        {"user_id": "u.lewis"},
    )
    assert not res.is_error
    content_text = res.content[0].text
    assert "SOC-TICKET-u.lewis-" in content_text


@pytest.mark.asyncio
async def test_mcp_server_call_visual_analysis(monkeypatch):
    """Verify visual forensic analysis over MCP in local mode."""
    monkeypatch.setenv("LOCAL_MODE", "true")
    res = await mcp_server.call_tool(
        "get_visual_analysis_for_user",
        {"gcs_uri": "gs://cymbal-cyber-screenshots_demo/u.lewis.png"},
    )
    assert not res.is_error
    content_text = res.content[0].text
    assert "Forensic" in content_text


@pytest.mark.asyncio
async def test_mcp_server_call_dispatch_to_soc():
    """Verify ticket dispatch over MCP."""
    mock_service = MagicMock()
    mock_service.create_and_dispatch_ticket.return_value = "DISPATCHED_TO_QUEUES"

    with patch("adk_agent.tools.get_soc_service", return_value=mock_service):
        res = await mcp_server.call_tool(
            "dispatch_to_soc_ticketing_system",
            {
                "ticket_id": "SOC-TICKET-TEST-12345",
                "alert_payload": json.dumps(
                    {"user_id": "u.lewis", "threat_score": 100}
                ),
                "agent_reason": "Confirmed malicious indicators",
                "structured_report": "Forensic investigation report",
                "severity": "HIGH",
            },
        )
        assert not res.is_error
        assert "DISPATCHED_TO_QUEUES" in res.content[0].text
