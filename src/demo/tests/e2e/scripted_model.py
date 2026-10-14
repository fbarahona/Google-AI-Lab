"""
Deterministic stand-in for Gemini used by the end-to-end pipeline test.

It routes on the tools each agent exposes, so every agent, callback, MCP server and
the ticketing service run for real; only the model's choices are scripted. The SOC
policy "try_fp" always tries to close the alert as a false positive first, to prove
the security gate does not depend on the model behaving.
"""

import json
from collections.abc import AsyncGenerator

from google.adk.models._capabilities import LlmCapabilities
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types

ALERT_PREFIX = "Investigate incoming continuous security alert: "

REPORT = (
    "### Security Incident Report\n**1. Alert Overview:** scripted\n"
    "**6. Recommended Response Actions:**\n1. Isolate host.\n"
)


def _call(name: str, args: dict) -> LlmResponse:
    return LlmResponse(
        content=types.Content(
            role="model",
            parts=[types.Part(function_call=types.FunctionCall(name=name, args=args))],
        )
    )


def _text(text: str) -> LlmResponse:
    return LlmResponse(
        content=types.Content(role="model", parts=[types.Part(text=text)])
    )


def _history(req: LlmRequest) -> tuple[list[str], list[tuple[str, dict]], str]:
    calls, responses, user_text = [], [], ""
    for content in req.contents or []:
        for part in content.parts or []:
            if part.function_call:
                calls.append(part.function_call.name)
            if part.function_response:
                responses.append(
                    (part.function_response.name, part.function_response.response)
                )
            if part.text and content.role == "user":
                user_text += part.text
    return calls, responses, user_text


def alert_from(text: str) -> dict:
    start = text.find(ALERT_PREFIX)
    if start < 0:
        return {}
    brace = text.index("{", start)
    return json.JSONDecoder().raw_decode(text[brace:])[0]


class ScriptedLlm(BaseLlm):
    """soc_policy: "dispatch" (genuine threat), "try_fp", or "silent" (resolves nothing)."""

    soc_policy: str = "dispatch"
    skip_visual: bool = False

    @property
    def capabilities(self) -> LlmCapabilities:
        return LlmCapabilities(output_schema_and_tools=False)

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        tools = set(llm_request.tools_dict)
        calls, responses, user_text = _history(llm_request)
        alert = alert_from(user_text)
        user = alert.get("user_id", "unknown")

        if "get_entity_behavioral_profile" in tools:
            if not responses:
                yield _call(
                    "get_entity_behavioral_profile",
                    {"entity_type": "user", "entity_id": user},
                )
            else:
                yield _text(
                    f"Telemetry for {user}: {json.dumps(responses[-1][1])[:600]}"
                )
            return

        if "get_gcs_uri_for_user" in tools:
            if self.skip_visual:
                yield _text("Visual analysis skipped.")
            elif not responses:
                yield _call("get_gcs_uri_for_user", {"user": user})
            elif len(responses) == 1:
                payload = responses[0][1]
                content = payload.get("structuredContent", payload)
                uri = content.get("gcs_uri") or json.dumps(payload)
                yield _call("get_visual_analysis_for_user", {"gcs_uri": uri})
            else:
                yield _text(f"Visual findings: {json.dumps(responses[-1][1])[:800]}")
            return

        if "dispatch_to_soc_ticketing_system" in tools:
            # A colliding, model-made ID: the security gate must replace it.
            model_ticket_id = f"SOC-TICKET-{user}-1718000000"
            if self.soc_policy == "silent":
                yield _text("I have reviewed the findings.")
            elif self.soc_policy == "dispatch":
                if not responses:
                    yield _call(
                        "dispatch_to_soc_ticketing_system",
                        {
                            "ticket_id": model_ticket_id,
                            "alert_payload": json.dumps(alert),
                            "agent_reason": "Scripted: genuine threat",
                            "structured_report": REPORT,
                            "severity": "critical",
                            "mitre_tactics": ["Credential Access"],
                        },
                    )
                else:
                    yield _text("Ticket dispatched.")
            else:
                gate_blocked = any(
                    "SECURITY_GATE_VIOLATION" in json.dumps(r) for _, r in responses
                )
                if not responses:
                    yield _call(
                        "log_false_positive",
                        {
                            "alert_payload": json.dumps(alert),
                            "agent_comment": "Scripted FP",
                        },
                    )
                elif gate_blocked and "escalate_to_human" not in calls:
                    yield _call(
                        "escalate_to_human",
                        {
                            "ticket_id": model_ticket_id,
                            "alert_payload": json.dumps(alert),
                            "agent_reason_for_escalation": "Gate blocked FP",
                            "context_data": REPORT,
                        },
                    )
                else:
                    yield _text("Done.")
            return

        # google_search_agent (its built-in search tool is removed for the test).
        yield _text(f"OSINT (scripted): no live search for {alert.get('source_ip')}.")
