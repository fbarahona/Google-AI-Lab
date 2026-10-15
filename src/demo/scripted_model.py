"""
Deterministic stand-in for Gemini, used by the end-to-end pipeline test and by the
local demo runner (src/demo/local_runner.py) when no live model is requested.

It routes on the tools each agent exposes, so every agent, callback, MCP server and
the ticketing service run for real; only the model's choices are scripted. The SOC
policy "try_fp" always tries to close the alert as a false positive first, to prove
the security gate does not depend on the model behaving.
"""

import json
import re
from collections.abc import AsyncGenerator
from typing import Any

from google.adk.models._capabilities import LlmCapabilities
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types

ALERT_PREFIX = "Investigate incoming continuous security alert: "

# Profile metrics in the order the report lists them, with their labels.
PROFILE_METRICS = (
    ("total_login_failures_24h", "Login failures"),
    ("suspicious_user_agent_logins_24h", "Logins from suspicious user agents"),
    ("distinct_public_source_ips_24h", "Distinct public source IPs"),
    ("high_privilege_requests_24h", "High-privilege requests"),
    ("malicious_commands_24h", "Malicious commands"),
    ("malicious_dns_queries_24h", "Malicious DNS queries"),
    ("risky_file_transfers_24h", "Risky file transfers"),
    ("distinct_destination_ips_24h", "Distinct destination IPs"),
)
# (metric, tactic, technique, evidence) rows for the MITRE section.
MITRE_RULES = (
    (
        "total_login_failures_24h",
        "Credential Access",
        "T1110 Brute Force",
        "repeated login failures",
    ),
    (
        "suspicious_user_agent_logins_24h",
        "Initial Access",
        "T1078 Valid Accounts",
        "logins from scripted or unusual user agents",
    ),
    (
        "malicious_commands_24h",
        "Execution",
        "T1059.001 PowerShell",
        "encoded or known-malicious command lines",
    ),
    (
        "high_privilege_requests_24h",
        "Privilege Escalation",
        "T1068 Exploitation for Privilege Escalation",
        "root/admin permission requests",
    ),
    (
        "malicious_dns_queries_24h",
        "Command and Control",
        "T1071.004 Application Layer Protocol: DNS",
        "lookups of known-bad domains",
    ),
    (
        "risky_file_transfers_24h",
        "Exfiltration",
        "T1048 Exfiltration Over Alternative Protocol",
        "executable or script file transfers",
    ),
)
_QUOTED = re.compile(
    r"\[(?P<agent>\w+)\] said:\s*<<<BEGIN_QUOTED_AGENT_CONTENT>>>\s*(?P<text>.*?)"
    r"\s*<<<END_QUOTED_AGENT_CONTENT>>>",
    re.DOTALL,
)


def _payload(response: dict) -> dict:
    """The structured result of an MCP tool response (or the response itself)."""
    return response.get("structuredContent") or response


def _agent_said(user_text: str) -> dict[str, str]:
    """The last thing each investigation agent said, from the quoted transcript."""
    return {m["agent"]: m["text"] for m in _QUOTED.finditer(user_text)}


def telemetry_summary(user: str, profile: dict[str, Any]) -> str:
    if "error" in profile:
        return f"Telemetry for {user} unavailable: {profile['error']}"
    lines = [f"Behavioral profile for `{user}` (last 24h):"]
    lines += [
        f"- {label}: {profile[key]}" for key, label in PROFILE_METRICS if key in profile
    ]
    flags = profile.get("security_flags", {})
    lines.append(
        "- Malicious indicators confirmed: "
        + ("yes" if flags.get("malicious_indicators") else "no")
    )
    return "\n".join(lines)


def _profile_from(said: str) -> dict[str, int]:
    """Metric values back out of telemetry_summary's bullet list."""
    by_label = {label: key for key, label in PROFILE_METRICS}
    profile = {}
    for label, value in re.findall(r"^- (.+?): (\d+)$", said, re.MULTILINE):
        if label in by_label:
            profile[by_label[label]] = int(value)
    return profile


def fp_rationale(user_text: str) -> str:
    """The scripted false-positive argument, citing the telemetry it rests on."""
    said = _agent_said(user_text)
    profile = _profile_from(said.get("bq_investigation_agent", ""))
    if not profile:
        return "Closing as a false positive: no telemetry findings were returned."
    findings = ", ".join(
        f"{profile[key]} {label.lower()}"
        for key, label in PROFILE_METRICS
        if key in profile
    )
    return (
        f"Closing as a false positive. Telemetry (24h): {findings}. "
        "The score comes from routine administrative activity rather than "
        "confirmed malicious indicators. Scripted local model; the security gate "
        "makes the final call."
    )


def build_report(alert: dict[str, Any], user_text: str, verdict: str) -> str:
    """
    A deterministic incident report in the same six sections the live model writes,
    filled from the alert and what the investigation agents actually returned.
    """
    said = _agent_said(user_text)
    telemetry = said.get("bq_investigation_agent", "No telemetry findings returned.")
    visual = said.get("visual_analysis_agent", "No visual findings returned.")
    osint = said.get("google_search_agent", "No threat intelligence returned.")
    profile = _profile_from(telemetry)

    mitre = [
        f"- **{tactic}**: {technique} ({profile[key]} {evidence})"
        for key, tactic, technique, evidence in MITRE_RULES
        if profile.get(key)
    ] or ["- No technique is supported by the telemetry."]

    actions = []
    if profile.get("malicious_commands_24h") or profile.get("risky_file_transfers_24h"):
        actions.append(f"Isolate host `{alert.get('device_id')}` from the network.")
    if profile.get("total_login_failures_24h") or profile.get(
        "suspicious_user_agent_logins_24h"
    ):
        actions.append(
            f"Disable `{alert.get('user_id')}`, revoke sessions and rotate credentials."
        )
    if profile.get("malicious_dns_queries_24h"):
        actions.append("Block the queried malicious domains at DNS and the proxy.")
    actions.append(f"Block source IP `{alert.get('source_ip')}` at the perimeter.")
    actions.append("Collect a memory image and EDR timeline before remediation.")

    return "\n".join(
        [
            "### Security Incident Report",
            "**1. Alert Overview:**",
            f"- User: `{alert.get('user_id')}`",
            f"- Device: `{alert.get('device_id')}`",
            f"- Origin IP: `{alert.get('source_ip')}`",
            f"- Threat Score: {alert.get('total_2_min_threat_score')} "
            f"(window ending {alert.get('window_end')})",
            f"- Verdict: {verdict}",
            "- Source: scripted local model. The tools, telemetry and security gate "
            "are real; run with `--live-model` for Gemini-written analysis.",
            "",
            "**2. Behavioral Findings:**",
            telemetry,
            "",
            "**3. Visual Forensics:**",
            visual,
            "",
            "**4. External Threat Intelligence:**",
            osint,
            "",
            "**5. MITRE ATT&CK Mapping:**",
            *mitre,
            "",
            "**6. Recommended Response Actions:**",
            *(f"{i}. {a}" for i, a in enumerate(actions, 1)),
        ]
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
                yield _text(telemetry_summary(user, _payload(responses[-1][1])))
            return

        if "get_gcs_uri_for_user" in tools:
            if self.skip_visual:
                yield _text("Visual analysis skipped.")
            elif not responses:
                yield _call("get_gcs_uri_for_user", {"user": user})
            elif len(responses) == 1:
                content = _payload(responses[0][1])
                uri = content.get("gcs_uri") or json.dumps(responses[0][1])
                yield _call("get_visual_analysis_for_user", {"gcs_uri": uri})
            else:
                result = _payload(responses[-1][1])
                yield _text(
                    result.get("analysis")
                    or f"Visual evidence unavailable: {result.get('error', result)}"
                )
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
                            "agent_reason": "Genuine threat: telemetry confirms "
                            "malicious activity",
                            "structured_report": build_report(
                                alert, user_text, "GENUINE THREAT"
                            ),
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
                            "agent_comment": fp_rationale(user_text),
                        },
                    )
                elif gate_blocked and "escalate_to_human" not in calls:
                    yield _call(
                        "escalate_to_human",
                        {
                            "ticket_id": model_ticket_id,
                            "alert_payload": json.dumps(alert),
                            "agent_reason_for_escalation": "Security gate blocked "
                            "the false-positive closure; analyst review required",
                            "context_data": build_report(
                                alert,
                                user_text,
                                "ESCALATED: the security gate blocked closing "
                                "this alert as a false positive",
                            ),
                        },
                    )
                else:
                    yield _text("Done.")
            return

        # google_search_agent (its built-in search tool is removed for the test).
        yield _text(f"OSINT (scripted): no live search for {alert.get('source_ip')}.")
