"""
Investigation lifecycle hooks: the orchestrator resets every security flag and seeds
the alert identity at the start of each alert, so nothing leaks between alerts;
sub-agents log when they start and finish.
"""

import json
import re

from google.adk.agents.callback_context import CallbackContext

from adk_agent.logging_utils import log_agent_event
from adk_agent.tools import alert_id_from_payload, ticket_id_for_alert


def before_sub_agent_starts(callback_context: CallbackContext):
    """Logs the activation of any agent."""
    log_agent_event(
        f"Agent triggered: {callback_context.agent_name}", callback_context.agent_name
    )


def log_agent_completion(callback_context: CallbackContext):
    """Logs completion status of sub-agents."""
    output = getattr(callback_context, "output", None) or getattr(
        callback_context, "result", None
    )
    log_agent_event(
        f"Completed execution. Output summary: {str(output)[:150]}...",
        callback_context.agent_name,
    )


def before_orchestrator_starts(callback_context: CallbackContext):
    """
    Initializes and seeds session state for the orchestrator workflow:
    1. Resets invocation flags to prevent cross-alert state bleeding across invocations.
    2. Parses incoming alert JSON payload into state (user_id, device_id, source_ip, score)
       if not already present.
    """
    log_agent_event(f"Investigation session started: {callback_context.agent_name}")
    state = getattr(callback_context, "state", None)
    if state is not None:
        # Reset invocation flags
        state["prompt_injection_detected"] = False
        state["malicious_indicators"] = False
        state["evidence_unavailable"] = False
        state["telemetry_evidence_collected"] = False
        state["visual_evidence_collected"] = False
        state["ticket_dispatched"] = False
        state["escalation_dispatched"] = False
        state["false_positive_logged"] = False

        # Clear alert identity fields so prior alert attributes cannot leak across turns
        state["user_id"] = None
        state["device_id"] = None
        state["source_ip"] = None
        state["threat_score"] = None
        state["window_end"] = None
        state["ticket_id"] = None
        state["alert_id"] = None
        state["investigated_user"] = None

        # Seed alert fields from user_content
        user_content = getattr(callback_context, "user_content", None)
        raw_text = ""
        if user_content:
            parts = (
                getattr(user_content, "parts", [])
                if hasattr(user_content, "parts")
                else (user_content if isinstance(user_content, list) else [])
            )
            for p in parts:
                p_text = getattr(p, "text", "") if hasattr(p, "text") else str(p)
                if p_text:
                    raw_text += p_text

        if raw_text:
            try:
                match = re.search(r"(\{.*\})", raw_text, re.DOTALL)
                if match:
                    data = json.loads(match.group(1))
                    if isinstance(data, dict):
                        if "user_id" in data:
                            state["user_id"] = data["user_id"]
                        if "device_id" in data:
                            state["device_id"] = data["device_id"]
                        if "source_ip" in data:
                            state["source_ip"] = data["source_ip"]
                        if "total_2_min_threat_score" in data:
                            state["threat_score"] = data["total_2_min_threat_score"]
                        elif "threat_score" in data:
                            state["threat_score"] = data["threat_score"]
                        if "window_end" in data:
                            state["window_end"] = data["window_end"]
                        if state.get("user_id"):
                            state["alert_id"] = alert_id_from_payload(data)
                            state["ticket_id"] = ticket_id_for_alert(
                                state["user_id"], state["alert_id"]
                            )
            except Exception:
                pass
