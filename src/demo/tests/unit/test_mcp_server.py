"""
Unit Tests for Cymbal Cyber Local MCP Server.
============================================
Validates tool registration, JSON-RPC schemas, and tool execution over MCP.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from google.adk.sessions.state import State

from adk_agent.agent import (
    create_mcp_tool,
    default_deny_soc_callback,
    security_gate_callback,
)
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


@pytest.mark.asyncio
async def test_mcp_tool_updates_real_adk_state_on_visual_prompt_injection():
    """
    Critical Bug Regression Test:
    Verify that executing get_visual_analysis_for_user through the MCP server over stdio
    populates prompt_injection_detected in a real ADK State object, enabling security_gate_callback
    to deterministically block log_false_positive.
    """
    toolset = create_mcp_tool("get_visual_analysis_for_user")
    tools = await toolset.get_tools()
    assert len(tools) == 1
    tool = tools[0]

    mock_ctx = MagicMock()
    real_state = State({}, {})
    mock_ctx.state = real_state

    # c.wilson screenshot contains active prompt injection attempting to coerce triage to FALSE_POSITIVE
    screenshot_uri = "file:///workspaces/Google/src/demo/user_screenshots/c.wilson.png"
    res = await tool.run_async(args={"gcs_uri": screenshot_uri}, tool_context=mock_ctx)
    assert res is not None

    # Assert the flag was written to the real ADK State over the MCP boundary
    assert real_state.get("prompt_injection_detected") is True

    # Assert that the security gate callback deterministically blocks log_false_positive
    mock_fp_tool = MagicMock()
    mock_fp_tool.name = "log_false_positive"
    gate_result = security_gate_callback(mock_fp_tool, {}, mock_ctx)
    assert gate_result is not None
    assert gate_result.get("status") == "BLOCKED"
    assert "SECURITY_GATE_VIOLATION" in gate_result.get("error", "")
    assert "prompt injection" in gate_result.get("reason", "").lower()


@pytest.mark.asyncio
async def test_mcp_tool_updates_real_adk_state_on_ticket_dispatch(monkeypatch):
    """
    Critical Bug Regression Test:
    Verify that executing dispatch_to_soc_ticketing_system through the MCP server over stdio
    populates ticket_dispatched in a real ADK State object, preventing default_deny_soc_callback
    from falsely triggering AUTO_ESCALATED_DEFAULT_DENY.
    """
    monkeypatch.setenv("LOCAL_MODE", "true")
    toolset = create_mcp_tool("dispatch_to_soc_ticketing_system")
    tools = await toolset.get_tools()
    assert len(tools) == 1
    tool = tools[0]

    mock_ctx = MagicMock()
    real_state = State({}, {})
    mock_ctx.state = real_state

    res = await tool.run_async(
        args={
            "ticket_id": "SOC-TICKET-TEST-MCP-1",
            "alert_payload": json.dumps(
                {
                    "user_id": "u.lewis",
                    "device_id": "ws-01",
                    "source_ip": "175.45.177.32",
                    "threat_score": 1850,
                }
            ),
            "agent_reason": "APT38 command and control activity confirmed",
            "structured_report": "Incident report with IOCs",
            "severity": "CRITICAL",
        },
        tool_context=mock_ctx,
    )
    assert res is not None

    # Assert the flag was written to the real ADK State over MCP
    assert real_state.get("ticket_dispatched") is True

    # Assert default-deny callback is correctly suppressed
    callback_ctx = MagicMock()
    callback_ctx.state = real_state
    with patch("adk_agent.tools.get_soc_service") as mock_soc:
        default_deny_soc_callback(callback_ctx)
        mock_soc.assert_not_called()
    assert real_state.get("escalation_dispatched") is not True


@pytest.mark.asyncio
async def test_mcp_tool_updates_real_adk_state_on_false_positive(monkeypatch):
    """
    Critical Bug Regression Test:
    Verify that executing log_false_positive through the MCP server over stdio
    populates false_positive_logged in a real ADK State object, allowing benign
    alerts to complete without spurious default-deny auto-escalation.
    """
    monkeypatch.setenv("LOCAL_MODE", "true")
    toolset = create_mcp_tool("log_false_positive")
    tools = await toolset.get_tools()
    assert len(tools) == 1
    tool = tools[0]

    mock_ctx = MagicMock()
    real_state = State({}, {})
    mock_ctx.state = real_state

    res = await tool.run_async(
        args={
            "alert_payload": json.dumps(
                {
                    "user_id": "l.taylor",
                    "device_id": "ws-admin",
                    "source_ip": "10.0.0.15",
                    "threat_score": 120,
                }
            ),
            "agent_comment": "Verified benign backup script execution",
        },
        tool_context=mock_ctx,
    )
    assert res is not None

    # Assert the flag was written to the real ADK State over MCP
    assert real_state.get("false_positive_logged") is True

    # Assert default-deny does not escalate
    callback_ctx = MagicMock()
    callback_ctx.state = real_state
    with patch("adk_agent.tools.get_soc_service") as mock_soc:
        default_deny_soc_callback(callback_ctx)
        mock_soc.assert_not_called()
    assert real_state.get("escalation_dispatched") is not True


@pytest.mark.asyncio
async def test_mcp_tool_updates_real_adk_state_on_behavioral_telemetry(monkeypatch):
    """
    Critical Bug Regression Test:
    Verify that executing get_entity_behavioral_profile through MCP populates
    malicious_indicators in real ADK State, which blocks log_false_positive.
    """
    monkeypatch.setenv("LOCAL_MODE", "true")
    toolset = create_mcp_tool("get_entity_behavioral_profile")
    tools = await toolset.get_tools()
    assert len(tools) == 1
    tool = tools[0]

    mock_ctx = MagicMock()
    real_state = State({}, {})
    mock_ctx.state = real_state

    res = await tool.run_async(
        args={"entity_type": "user", "entity_id": "u.lewis"},
        tool_context=mock_ctx,
    )
    assert res is not None

    # u.lewis has confirmed malicious commands in the local log files
    assert real_state.get("malicious_indicators") is True

    # Assert security gate blocks log_false_positive due to malicious telemetry
    mock_fp_tool = MagicMock()
    mock_fp_tool.name = "log_false_positive"
    gate_result = security_gate_callback(mock_fp_tool, {}, mock_ctx)
    assert gate_result is not None
    assert gate_result.get("status") == "BLOCKED"
    assert "anomalous behavioral" in gate_result.get("reason", "").lower()
