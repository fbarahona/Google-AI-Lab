"""
Fail-closed regression tests for the forensic evidence tools:
1. MCP errors, ADK error dicts and unstructured responses mark evidence unavailable
2. A tool call that outlives the MCP timeout blocks log_false_positive
3. Cloud mode only accepts gs:// URIs inside the screenshots bucket
4. The gate requires telemetry and visual evidence to have been gathered
"""

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from google.adk.sessions.state import State

from adk_agent.agent import (
    create_mcp_toolset,
    security_gate_callback,
    sync_mcp_security_state_callback,
)
from adk_agent.tools import (
    SCREENSHOTS_BUCKET,
    get_gcs_uri_for_user,
    get_visual_analysis_for_user,
)

EVIDENCE_TOOLS = [
    "get_entity_behavioral_profile",
    "get_visual_analysis_for_user",
    "get_gcs_uri_for_user",
]
STUB_SERVER = Path(__file__).parent / "fixtures" / "slow_mcp_server.py"


def _tool(name: str) -> MagicMock:
    tool = MagicMock()
    tool.name = name
    return tool


def _ctx(state: dict | None = None) -> MagicMock:
    ctx = MagicMock()
    ctx.state = State(state or {}, {})
    return ctx


def _gate(ctx: MagicMock) -> dict | None:
    return security_gate_callback(_tool("log_false_positive"), {}, ctx)


# ==============================================================================
# 1. STATE SYNC FAILS CLOSED
# ==============================================================================


@pytest.mark.parametrize("tool_name", EVIDENCE_TOOLS)
def test_mcp_is_error_response_marks_evidence_unavailable(tool_name):
    ctx = _ctx()
    response = {
        "content": [{"type": "text", "text": "Error executing tool"}],
        "isError": True,
    }
    sync_mcp_security_state_callback(_tool(tool_name), {}, ctx, response)
    assert ctx.state.get("evidence_unavailable") is True


@pytest.mark.parametrize("tool_name", EVIDENCE_TOOLS)
def test_adk_error_dict_marks_evidence_unavailable(tool_name):
    """ADK converts MCP timeouts and transport failures into {"error": ...}."""
    ctx = _ctx()
    response = {"error": "Unexpected error during MCP tool execution: timed out"}
    sync_mcp_security_state_callback(_tool(tool_name), {}, ctx, response)
    assert ctx.state.get("evidence_unavailable") is True


def test_response_without_security_flags_marks_evidence_unavailable():
    ctx = _ctx()
    response = {"content": [{"type": "text", "text": "gs://bucket/u.lewis.png"}]}
    sync_mcp_security_state_callback(_tool("get_gcs_uri_for_user"), {}, ctx, response)
    assert ctx.state.get("evidence_unavailable") is True


def test_clean_structured_evidence_does_not_mark_unavailable():
    ctx = _ctx()
    payload = {
        "analysis": "standard developer console",
        "security_flags": {
            "prompt_injection_detected": False,
            "evidence_unavailable": False,
        },
    }
    response = {
        "content": [{"type": "text", "text": json.dumps(payload)}],
        "structuredContent": payload,
    }
    sync_mcp_security_state_callback(
        _tool("get_visual_analysis_for_user"), {}, ctx, response
    )
    assert not ctx.state.get("evidence_unavailable")
    assert ctx.state.get("visual_evidence_collected") is True


def test_non_evidence_tool_error_does_not_mark_evidence_unavailable():
    ctx = _ctx()
    response = {"content": [{"type": "text", "text": "boom"}], "isError": True}
    sync_mcp_security_state_callback(
        _tool("dispatch_to_soc_ticketing_system"), {}, ctx, response
    )
    assert not ctx.state.get("evidence_unavailable")


def test_collected_flag_only_from_owning_tool():
    """Another tool reporting clean evidence must not count as visual evidence."""
    ctx = _ctx()
    payload = {"security_flags": {"evidence_unavailable": False}}
    sync_mcp_security_state_callback(
        _tool("get_gcs_uri_for_user"),
        {},
        ctx,
        {"structuredContent": payload, "content": []},
    )
    assert not ctx.state.get("visual_evidence_collected")
    assert not ctx.state.get("telemetry_evidence_collected")


# ==============================================================================
# 2. TIMEOUT THROUGH A REAL MCP SUBPROCESS
# ==============================================================================


@pytest.mark.asyncio
async def test_timed_out_evidence_tool_blocks_false_positive():
    toolset = create_mcp_toolset(
        ["get_visual_analysis_for_user"],
        timeout=2,
        server_args=[str(STUB_SERVER)],
    )
    try:
        tools = await toolset.get_tools()
        assert len(tools) == 1
        ctx = _ctx({"telemetry_evidence_collected": True})

        start = time.monotonic()
        args = {"gcs_uri": f"gs://{SCREENSHOTS_BUCKET}/u.lewis.png"}
        res = await tools[0].run_async(args=args, tool_context=ctx)
        sync_mcp_security_state_callback(tools[0], args, ctx, res)
        assert time.monotonic() - start < 9  # timed out, did not wait for the tool

        assert ctx.state.get("evidence_unavailable") is True
        assert not ctx.state.get("visual_evidence_collected")
        gate = _gate(ctx)
        assert gate is not None and gate["status"] == "BLOCKED"
    finally:
        await toolset.close()


def test_default_mcp_timeout_is_raised_above_adk_default():
    toolset = create_mcp_toolset(["get_visual_analysis_for_user"])
    assert toolset._connection_params.timeout == 90


# ==============================================================================
# 3. CLOUD MODE SCREENSHOT URI ALLOW-LIST
# ==============================================================================


@pytest.mark.parametrize(
    "uri",
    [
        "file:///nonexistent.png",
        "file://c.wilson.png",
        "gs://some-other-bucket/c.wilson.png",
        f"gs://{SCREENSHOTS_BUCKET}/../c.wilson.png",
        f"gs://{SCREENSHOTS_BUCKET}/",
        f"gs://other/file://{SCREENSHOTS_BUCKET}/c.wilson.png",
    ],
)
def test_cloud_mode_rejects_disallowed_uris(monkeypatch, uri):
    monkeypatch.setenv("LOCAL_MODE", "false")
    with patch("adk_agent.tools.get_genai_client") as mock_client:
        res = get_visual_analysis_for_user(uri)
        mock_client.assert_not_called()
    assert res["security_flags"]["evidence_unavailable"] is True
    assert "analysis" not in res


@pytest.mark.asyncio
async def test_cloud_mode_rejects_file_uri_over_mcp(monkeypatch):
    from adk_agent.mcp_server.server import mcp_server

    monkeypatch.setenv("LOCAL_MODE", "false")
    res = await mcp_server.call_tool(
        "get_visual_analysis_for_user", {"gcs_uri": "file://c.wilson.png"}
    )
    body = json.loads(res.content[0].text)
    assert body["security_flags"]["evidence_unavailable"] is True
    assert "analysis" not in body


def test_cloud_mode_accepts_screenshots_bucket_uri(monkeypatch):
    monkeypatch.setenv("LOCAL_MODE", "false")
    client = MagicMock()
    client.models.generate_content.return_value.text = "Benign developer activity."
    with patch("adk_agent.tools.get_genai_client", return_value=client):
        res = get_visual_analysis_for_user(f"gs://{SCREENSHOTS_BUCKET}/u.lewis.png")
    client.models.generate_content.assert_called_once()
    assert res["security_flags"]["evidence_unavailable"] is False
    assert res["analysis"] == "Benign developer activity."


def test_cloud_mode_empty_gemini_answer_is_unavailable(monkeypatch):
    monkeypatch.setenv("LOCAL_MODE", "false")
    client = MagicMock()
    client.models.generate_content.return_value.text = ""
    ctx = _ctx()
    with patch("adk_agent.tools.get_genai_client", return_value=client):
        get_visual_analysis_for_user(
            f"gs://{SCREENSHOTS_BUCKET}/u.lewis.png", tool_context=ctx
        )
    assert ctx.state.get("evidence_unavailable") is True
    assert not ctx.state.get("visual_evidence_collected")


def test_local_mode_still_reads_file_uri_ocr(monkeypatch):
    monkeypatch.setenv("LOCAL_MODE", "true")
    res = get_visual_analysis_for_user("file://c.wilson.png")
    assert res["security_flags"]["evidence_unavailable"] is False
    assert res["security_flags"]["prompt_injection_detected"] is True


# ==============================================================================
# 4. SCREENSHOT URI LOOKUP
# ==============================================================================


def test_gcs_uri_lookup_bigquery_error_fails_closed(monkeypatch):
    monkeypatch.setenv("LOCAL_MODE", "false")
    with patch("adk_agent.tools.get_bq_client", side_effect=RuntimeError("denied")):
        res = get_gcs_uri_for_user("u.lewis")
    assert res["security_flags"]["evidence_unavailable"] is True
    assert "gcs_uri" not in res


def test_gcs_uri_lookup_returns_structured_uri(monkeypatch):
    monkeypatch.setenv("LOCAL_MODE", "false")
    row = MagicMock()
    row.gcs_uri = f"gs://{SCREENSHOTS_BUCKET}/u.lewis.png"
    bq = MagicMock()
    bq.query.return_value.result.return_value = [row]
    with patch("adk_agent.tools.get_bq_client", return_value=bq):
        res = get_gcs_uri_for_user("u.lewis")
    assert res == {
        "gcs_uri": f"gs://{SCREENSHOTS_BUCKET}/u.lewis.png",
        "security_flags": {"evidence_unavailable": False},
    }


def test_gcs_uri_lookup_local_mode_skips_bigquery(monkeypatch):
    monkeypatch.setenv("LOCAL_MODE", "true")
    with patch("adk_agent.tools.get_bq_client") as mock_bq:
        res = get_gcs_uri_for_user("u.lewis")
        mock_bq.assert_not_called()
    assert res["gcs_uri"] == f"gs://{SCREENSHOTS_BUCKET}/u.lewis.png"
    assert res["security_flags"]["evidence_unavailable"] is False


# ==============================================================================
# 5. GATE REQUIRES GATHERED EVIDENCE
# ==============================================================================


@pytest.mark.parametrize(
    "state",
    [
        {},
        {"telemetry_evidence_collected": True},
        {"visual_evidence_collected": True},
    ],
)
def test_gate_blocks_false_positive_when_evidence_not_gathered(state):
    gate = _gate(_ctx(state))
    assert gate is not None
    assert gate["status"] == "BLOCKED"
    assert "not successfully gathered" in gate["reason"]


def test_gate_permits_false_positive_with_all_evidence():
    ctx = _ctx(
        {"telemetry_evidence_collected": True, "visual_evidence_collected": True}
    )
    assert _gate(ctx) is None
