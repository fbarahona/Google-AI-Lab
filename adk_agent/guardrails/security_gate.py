"""
The closure controls on soc_ticketing_agent, in plain Python that runs whatever the
model says:
- security_gate_callback blocks log_false_positive unless the evidence supports it,
  and pins every ticket to the alert the investigation started from.
- default_deny_soc_callback files a human escalation when the model finishes without
  resolving the alert.
"""

import json
from typing import Any

from google.adk.agents.callback_context import CallbackContext
from google.adk.tools import BaseTool, ToolContext

from adk_agent.guardrails.evidence_state import (
    _COLLECTED_FLAG_BY_TOOL,
    append_investigation_evidence,
)
from adk_agent.guardrails.lifecycle import log_agent_completion
from adk_agent.logging_utils import log_agent_event
from adk_agent.mcp_client import default_deny_mcp
from adk_agent.tools import ticket_id_for_alert

# Tools whose ticket_id argument the gate replaces with the alert's own ticket ID, so
# the model cannot reuse or collide IDs and a redelivered alert maps to the same ticket.
_TICKET_ID_TOOLS = frozenset(
    {"dispatch_to_soc_ticketing_system", "escalate_to_human", "log_false_positive"}
)

# Report argument of each ticket-creating tool, so the raw sub-agent findings can be
# attached to the ticket the analyst reviews instead of only the model's summary.
_REPORT_ARG_BY_TOOL = {
    "dispatch_to_soc_ticketing_system": "structured_report",
    "escalate_to_human": "context_data",
}


def security_gate_callback(
    tool: BaseTool, args: dict[str, Any], tool_context: ToolContext
) -> dict | None:
    """
    Deterministic security gate callback on soc_ticketing_agent.
    Enforces that the LLM cannot execute log_false_positive if:
    1. Prompt injection was detected in visual forensic evidence, OR
    2. High-risk behavioral indicators were recorded in telemetry, OR
    3. Essential forensic evidence was unavailable, OR
    4. Telemetry or visual evidence was never successfully gathered.

    For ticket-creating tools it also attaches the sub-agents' full findings to the
    report argument, so the analyst sees the evidence behind the summary.
    """
    state = getattr(tool_context, "state", None)
    if tool.name in _TICKET_ID_TOOLS:
        _pin_alert_identity(args, state)
    report_arg = _REPORT_ARG_BY_TOOL.get(tool.name)
    if report_arg is not None:
        _assign_ticket_id(tool.name, args, state)
        if tool.name == "escalate_to_human" and state is not None:
            if state.get("prompt_injection_detected") or state.get(
                "malicious_indicators"
            ):
                args["severity"] = "CRITICAL"
        args[report_arg] = append_investigation_evidence(
            args.get(report_arg, ""), state
        )
        return None

    if tool.name == "log_false_positive":
        if state is not None:
            if state.get("prompt_injection_detected"):
                log_agent_event(
                    "SECURITY GATE TRIGGERED: Blocked log_false_positive due to visual prompt injection."
                )
                return {
                    "error": "SECURITY_GATE_VIOLATION",
                    "status": "BLOCKED",
                    "reason": (
                        "Security Gate Violation: Cannot classify alert as FALSE POSITIVE because prompt injection "
                        "was detected in visual evidence. You MUST invoke escalate_to_human immediately."
                    ),
                }
            if state.get("malicious_indicators"):
                log_agent_event(
                    "SECURITY GATE TRIGGERED: Blocked log_false_positive due to malicious telemetry indicators."
                )
                return {
                    "error": "SECURITY_GATE_VIOLATION",
                    "status": "BLOCKED",
                    "reason": (
                        "Security Gate Violation: Cannot classify alert as FALSE POSITIVE because anomalous behavioral "
                        "indicators (malicious commands, login spray, or risky files) were confirmed in telemetry. "
                        "You MUST dispatch an incident ticket or escalate to a human analyst."
                    ),
                }
            if state.get("evidence_unavailable"):
                log_agent_event(
                    "SECURITY GATE TRIGGERED: Blocked log_false_positive due to missing/failed forensic evidence."
                )
                return {
                    "error": "SECURITY_GATE_VIOLATION",
                    "status": "BLOCKED",
                    "reason": (
                        "Security Gate Violation: Cannot classify alert as FALSE POSITIVE because critical forensic "
                        "evidence (visual screenshot or BigQuery telemetry) was unavailable. "
                        "You MUST invoke escalate_to_human for manual analyst adjudication."
                    ),
                }
            missing = [
                flag for flag in _COLLECTED_FLAG_BY_TOOL.values() if not state.get(flag)
            ]
            if missing:
                log_agent_event(
                    f"SECURITY GATE TRIGGERED: Blocked log_false_positive; evidence not gathered: {missing}."
                )
                return {
                    "error": "SECURITY_GATE_VIOLATION",
                    "status": "BLOCKED",
                    "reason": (
                        "Security Gate Violation: Cannot classify alert as FALSE POSITIVE because forensic "
                        "evidence (BigQuery telemetry and visual screenshot analysis) was not successfully gathered. "
                        "You MUST invoke escalate_to_human for manual analyst adjudication."
                    ),
                }
        _assign_ticket_id(tool.name, args, state)
    return None


# alert_payload keys the ticket tools read before the canonical ones; dropped when the
# gate pins the canonical value, so the model's spelling cannot shadow it.
_ALERT_KEY_ALIASES = {
    "user_id": ("user",),
    "device_id": ("device",),
    "source_ip": ("ip_address",),
    "total_2_min_threat_score": ("threat_score",),
}


def _pin_alert_identity(args: dict[str, Any], state: Any) -> None:
    """
    Overwrites the entity fields of the model's alert_payload with the alert the
    investigation started from, so the ticket names the alerted user, device, IP and
    score whatever the model wrote. Without an alert (an ADK playground prompt such
    as "investigate user c.wilson") the user is the one the evidence tools were run
    for; fields with no trusted source are left to the model.
    """
    if state is None:
        return
    trusted = {
        "alert_id": state.get("alert_id"),
        "user_id": state.get("user_id") or state.get("investigated_user"),
        "device_id": state.get("device_id"),
        "source_ip": state.get("source_ip"),
        "total_2_min_threat_score": state.get("threat_score"),
        "window_end": state.get("window_end"),
    }
    trusted = {k: v for k, v in trusted.items() if v not in (None, "")}
    if not trusted:
        return
    payload = args.get("alert_payload")
    if not isinstance(payload, dict):
        try:
            payload = json.loads(payload or "{}")
        except (TypeError, ValueError):
            payload = {}
    if not isinstance(payload, dict):
        payload = {}
    for key, value in trusted.items():
        for alias in _ALERT_KEY_ALIASES.get(key, ()):
            payload.pop(alias, None)
        payload[key] = value
    args["alert_payload"] = json.dumps(payload)


def _assign_ticket_id(tool_name: str, args: dict[str, Any], state: Any) -> None:
    """Replaces the model's ticket_id with the one seeded for this alert."""
    if tool_name in _TICKET_ID_TOOLS and state is not None and state.get("ticket_id"):
        args["ticket_id"] = state["ticket_id"]


async def default_deny_soc_callback(callback_context: CallbackContext):
    """
    Default-Deny safety enforcement callback running after soc_ticketing_agent finishes.
    Ensures that every investigated alert has an active adjudication. If the model finished
    without resolving the alert through a permitted tool action (dispatch, escalation, or
    false positive logging), this callback deterministically escalates the alert to human review.

    The ticket is filed through the MCP tool service like every other ticket, so the
    agent's own identity never writes tickets.
    """
    log_agent_completion(callback_context)
    state = getattr(callback_context, "state", None)
    if state is None:
        return

    ticket_resolved = (
        state.get("ticket_dispatched")
        or state.get("escalation_dispatched")
        or state.get("false_positive_logged")
    )

    if not ticket_resolved:
        log_agent_event(
            "DEFAULT-DENY ENFORCEMENT: Model finished without invoking a resolution tool. Executing deterministic human escalation."
        )
        user_id = state.get("user_id") or "unresolved_user"
        args = {
            "ticket_id": ticket_id_for_alert(
                user_id, state.get("alert_id"), prefix="SOC-TICKET-AUTO-ESCALATED"
            ),
            "user_id": user_id,
            "device_id": state.get("device_id") or "unknown_device",
            "source_ip": state.get("source_ip") or "unknown_ip",
            "threat_score": int(state.get("threat_score") or 100),
            "window_end": str(
                state.get("window_end") or state.get("transaction_window_end") or ""
            ),
            "severity": "CRITICAL"
            if state.get("prompt_injection_detected")
            or state.get("malicious_indicators")
            else "HIGH",
            "structured_report": append_investigation_evidence(
                "Auto-escalated by security platform default-deny guardrail.", state
            ),
        }
        # Raises if the ticket cannot be stored: the investigation then fails and the
        # webhook returns 500, so Pub/Sub redelivers the alert instead of dropping it.
        (tool,) = await default_deny_mcp.get_tools(readonly_context=callback_context)
        response = await tool.run_async(args=args, tool_context=callback_context)
        if not _escalated(response):
            raise RuntimeError(f"Default-deny escalation was not stored: {response}")
        state["escalation_dispatched"] = True


def _escalated(response: Any) -> bool:
    """True only for the escalation tool's structured success response."""
    if (
        not isinstance(response, dict)
        or response.get("isError")
        or response.get("error")
    ):
        return False
    payload = response.get("structuredContent")
    if not isinstance(payload, dict):
        payload = response
    return str(payload.get("status", "")).upper() == "ESCALATED"
