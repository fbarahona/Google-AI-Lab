"""
Evidence bookkeeping: MCP tools run out of process, so the structured security flags
they return are copied into ADK session state here, where the security gate reads
them. Only structured fields are read, never free text, and evidence tools fail
closed on any error or malformed response.
"""

import json
import re
from typing import Any

from google.adk.tools import BaseTool, ToolContext

from adk_agent.logging_utils import log_agent_event

# Flags that only tighten the security gate; any MCP tool may raise them.
_EVIDENCE_FLAGS = (
    "prompt_injection_detected",
    "malicious_indicators",
    "evidence_unavailable",
)

# Tools whose output is forensic evidence. They fail closed: an error, a timeout,
# or a response without structured security_flags marks evidence unavailable.
_EVIDENCE_TOOLS = frozenset(
    {
        "get_entity_behavioral_profile",
        "get_visual_analysis_for_user",
        "get_gcs_uri_for_user",
    }
)

# Positive evidence flags: set only by the tool that gathered that evidence, and
# only from a structured response reporting the evidence as available. The gate
# requires both before log_false_positive, so skipping a tool also fails closed.
_COLLECTED_FLAG_BY_TOOL = {
    "get_entity_behavioral_profile": "telemetry_evidence_collected",
    "get_visual_analysis_for_user": "visual_evidence_collected",
}

# Lifecycle flags that suppress default-deny escalation; each may only be set
# by the tool that performs that resolution action.
_LIFECYCLE_FLAG_BY_TOOL = {
    "dispatch_to_soc_ticketing_system": "ticket_dispatched",
    "escalate_to_human": "escalation_dispatched",
    "log_false_positive": "false_positive_logged",
}

# Evidence tools and the argument naming the user they investigated.
_USER_ARG_BY_TOOL = {
    "get_entity_behavioral_profile": "entity_id",
    "get_gcs_uri_for_user": "user",
}

# Must match soc_ticketing.report_parser.EVIDENCE_APPENDIX_HEADING.
EVIDENCE_APPENDIX_HEADING = "## Investigation Evidence"
_EVIDENCE_SOURCES = (
    ("google_search_results", "OSINT & Threat Intelligence"),
    ("bigquery_investigation_results", "Behavioral Telemetry (BigQuery)"),
    ("visual_analysis_results", "Visual Forensics"),
)


def append_investigation_evidence(report: str, state: Any) -> str:
    """
    Appends each investigation sub-agent's full output to a ticket report.

    Headings inside the sub-agent text are demoted to level 4 so the console can
    split the appendix on its own level-3 headings. Idempotent.
    """
    report = report or ""
    if state is None or EVIDENCE_APPENDIX_HEADING in report:
        return report
    blocks = []
    for key, title in _EVIDENCE_SOURCES:
        text = str(state.get(key) or "").strip()
        if text:
            text = re.sub(r"(?m)^\s{0,3}#{1,6}\s+", "#### ", text)
            blocks.append(f"### {title}\n{text}")
    if not blocks:
        return report
    return (
        f"{report.rstrip()}\n\n---\n"
        f"{EVIDENCE_APPENDIX_HEADING} (captured from the agent session)\n\n"
        + "\n\n".join(blocks)
        + "\n"
    )


def sync_mcp_security_state_callback(
    tool: BaseTool,
    args: dict[str, Any],
    tool_context: ToolContext,
    tool_response: Any,
) -> None:
    """
    Synchronizes security and lifecycle flags from MCP tool responses back into ADK session state.

    MCP tools execute out-of-process in a separate MCP server without direct access to ADK session state.
    This callback reads only the structured fields (security_flags, status) every tool returns,
    never free text, which can carry attacker-controlled content such as screenshot OCR.
    It deterministically sets the ADK session state flags:
    - prompt_injection_detected
    - malicious_indicators
    - evidence_unavailable
    - ticket_dispatched
    - escalation_dispatched
    - false_positive_logged
    """
    state = getattr(tool_context, "state", None)
    if state is None:
        return None

    payload: dict[str, Any] = {}

    if isinstance(tool_response, dict):
        if "security_flags" in tool_response or "status" in tool_response:
            payload = tool_response
        elif "structuredContent" in tool_response and isinstance(
            tool_response["structuredContent"], dict
        ):
            payload = tool_response["structuredContent"]

        content_list = tool_response.get("content")
        if isinstance(content_list, list):
            for item in content_list:
                if isinstance(item, dict) and "text" in item:
                    item_text = str(item["text"])
                    if not payload and item_text.strip().startswith("{"):
                        try:
                            data = json.loads(item_text)
                            if isinstance(data, dict):
                                payload = data
                        except Exception:
                            pass
    elif isinstance(tool_response, str) and tool_response.strip().startswith("{"):
        try:
            data = json.loads(tool_response)
            if isinstance(data, dict):
                payload = data
        except Exception:
            pass

    tool_name = getattr(tool, "name", "")

    # 0. Evidence tools fail closed on MCP errors, ADK error dicts (timeouts and
    #    transport failures) and responses missing the structured contract.
    sec_flags = payload.get("security_flags")
    if tool_name in _EVIDENCE_TOOLS:
        is_error = isinstance(tool_response, dict) and bool(
            tool_response.get("isError")
            or tool_response.get("is_error")
            or tool_response.get("error")
        )
        if is_error or payload.get("error") or not isinstance(sec_flags, dict):
            log_agent_event(
                f"MCP state sync: evidence_unavailable=True (failed or unstructured response from {tool_name})"
            )
            state["evidence_unavailable"] = True
        elif not sec_flags.get("evidence_unavailable"):
            collected_flag = _COLLECTED_FLAG_BY_TOOL.get(tool_name)
            if collected_flag:
                state[collected_flag] = True

    # The user the evidence tools ran for, for tickets with no alert to name one
    # (ADK playground). Taken from the call's own arguments, never from tool output.
    if tool_name in _USER_ARG_BY_TOOL and isinstance(sec_flags, dict):
        if tool_name != "get_entity_behavioral_profile" or str(
            args.get("entity_type", "")
        ).lower() in ("user", "user_id"):
            user = args.get(_USER_ARG_BY_TOOL[tool_name])
            if user and not state.get("investigated_user"):
                state["investigated_user"] = str(user)

    # 1. Update state from structured security_flags. Evidence flags only ever
    #    tighten the security gate, so any tool may raise them; lifecycle flags
    #    are accepted only from the tool that owns that resolution action.
    if isinstance(sec_flags, dict):
        for flag in _EVIDENCE_FLAGS:
            if sec_flags.get(flag):
                log_agent_event(f"MCP state sync: {flag}=True (from {tool_name})")
                state[flag] = True
        owned_flag = _LIFECYCLE_FLAG_BY_TOOL.get(tool_name)
        if owned_flag and sec_flags.get(owned_flag):
            log_agent_event(f"MCP state sync: {owned_flag}=True (from {tool_name})")
            state[owned_flag] = True

    # 2. Update state from lifecycle status, again only from the owning tool
    status = str(payload.get("status", "")).upper()
    if tool_name == "dispatch_to_soc_ticketing_system" and status == "DISPATCHED":
        state["ticket_dispatched"] = True
    elif tool_name == "escalate_to_human" and status in {
        "ESCALATED",
        "ESCALATED_PENDING_REVIEW",
    }:
        state["escalation_dispatched"] = True
    elif tool_name == "log_false_positive" and status == "RESOLVED_FALSE_POSITIVE":
        state["false_positive_logged"] = True

    return None


def mcp_tool_error_callback(
    tool: BaseTool,
    args: dict[str, Any],
    tool_context: ToolContext,
    error: Exception,
) -> dict[str, Any]:
    """
    Converts an exception raised by an MCP tool into an error response.

    ADK runs after_tool_callback on the response returned here, so the state sync sees
    the error and evidence tools fail closed with evidence_unavailable. Only reached if
    ADK's graceful MCP error handling lets the exception propagate.
    """
    log_agent_event(f"MCP tool {getattr(tool, 'name', '')} raised: {error}")
    return {"error": f"MCP tool execution failed: {error}"}
