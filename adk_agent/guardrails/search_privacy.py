"""
Data minimization for google_search_agent. google_search is a Gemini built-in tool,
so no ADK tool callback sees its queries: the preventive control limits what the
model can see (before_model), and the detective control audits the queries it ran
(after_model).
"""

from typing import Any

from google.adk.agents.callback_context import CallbackContext
from google.adk.models import LlmRequest, LlmResponse
from google.genai import types

from adk_agent.logging_utils import log_agent_event
from adk_agent.privacy_guard import (
    extract_public_ips,
    validate_search_query_privacy,
)

NO_PUBLIC_IP_RESULT = "No external public IP address present in alert; no suspicious foreign IPs identified."


def _content_text(content: Any) -> str:
    """Concatenated text parts of a genai Content (or "" when there are none)."""
    parts = getattr(content, "parts", None) or []
    return "".join(getattr(p, "text", None) or "" for p in parts)


def search_input_minimization_callback(
    callback_context: CallbackContext, llm_request: LlmRequest
) -> LlmResponse | None:
    """
    Deterministic privacy control for google_search_agent (before_model_callback).

    google_search is a Gemini built-in tool: Gemini writes and runs the queries itself,
    so no ADK tool callback ever sees them. The control therefore limits what the search
    model can see. The conversation (which carries the alert's user, device and internal
    IPs) is replaced by a message naming only the alert's public IPs; with none, the
    model is not called and no search happens.
    """
    alert_text = _content_text(getattr(callback_context, "user_content", None))
    state = getattr(callback_context, "state", None)
    source_ip = str(state.get("source_ip") or "") if state is not None else ""
    public_ips = extract_public_ips(f"{source_ip} {alert_text}")

    if not public_ips:
        log_agent_event(
            "PRIVACY CONTROL: no public IP in alert; search skipped",
            callback_context.agent_name,
        )
        return LlmResponse(
            content=types.Content(
                role="model", parts=[types.Part(text=NO_PUBLIC_IP_RESULT)]
            )
        )

    log_agent_event(
        f"PRIVACY CONTROL: search model limited to public IPs {public_ips}",
        callback_context.agent_name,
    )
    llm_request.contents = [
        types.Content(
            role="user",
            parts=[
                types.Part(
                    text=(
                        "Research these external public IP addresses from a security "
                        f"alert: {', '.join(public_ips)}"
                    )
                )
            ],
        )
    ]
    return None


def search_query_audit_callback(
    callback_context: CallbackContext, llm_response: LlmResponse
) -> LlmResponse | None:
    """
    Detective control for google_search_agent (after_model_callback): checks the queries
    Gemini actually ran (grounding metadata) against the privacy rules. A violation is
    logged and its search results are withheld from the rest of the investigation.
    """
    metadata = getattr(llm_response, "grounding_metadata", None)
    queries = list(getattr(metadata, "web_search_queries", None) or [])
    state = getattr(callback_context, "state", None)
    for query in queries:
        is_safe, reason = validate_search_query_privacy(query, state=state)
        if not is_safe:
            log_agent_event(
                f"PRIVACY_GATE_VIOLATION: search query breached privacy rules: {reason}",
                callback_context.agent_name,
            )
            return LlmResponse(
                content=types.Content(
                    role="model",
                    parts=[
                        types.Part(
                            text=(
                                "OSINT results withheld: a search query breached the "
                                "privacy rules. No external intelligence available."
                            )
                        )
                    ],
                )
            )
    return None
