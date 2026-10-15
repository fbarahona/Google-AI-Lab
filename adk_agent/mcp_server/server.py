"""
Cymbal Cyber Local MCP Server
=============================
Implements a standards-compliant Model Context Protocol (MCP) server
exposing BigQuery behavioral telemetry investigation, multimodal
visual forensics, and SOC incident ticketing tools.

Two transports:
- stdio (default): a child process of the agent, for local development and tests.
- Streamable HTTP (`--http` or MCP_TRANSPORT=streamable-http): the cloud deployment,
  its own Cloud Run service running as its own service account. That identity, not
  the agent's, holds the evidence reads and ticket writes; the agent's identity can
  only invoke this service. Every request must carry a Google ID token for this
  service, minted by the one allowed caller (MCP_ALLOWED_CALLER).

The server deliberately exposes no free-form SQL or schema-discovery tools: any MCP
client that connects without a tool_filter only gets the fixed, parameterized
investigation and ticketing operations below.

Every tool returns the dict its adk_agent.tools function returns, unchanged: the
structured security_flags in it are what the agent's state sync reads.
"""

import logging
import os
import sys
from typing import Any

try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    from mcp.server.fastmcp import FastMCP as MCPServer

from adk_agent import tools

logger = logging.getLogger("cymbal-cyber-mcp")

# Initialize Server
mcp_server = MCPServer(
    name="cymbal-cyber-mcp",
    description="Cymbal Cyber Security Operations Center (SOC) Investigation and Response MCP Server",
)


# Tool 1: BigQuery Entity Behavioral Profile
@mcp_server.tool()
def get_entity_behavioral_profile(
    entity_type: str,
    entity_id: str,
    window_to_investigate: str = "24 HOUR",
) -> dict[str, Any]:
    """Retrieves 24-hour behavioral profile metrics for an entity (user, device, IP)."""
    return tools.get_entity_behavioral_profile(
        entity_type=entity_type,
        entity_id=entity_id,
        window_to_investigate=window_to_investigate,
    )


# Tool 2: Visual Screenshot Analysis
@mcp_server.tool()
def get_visual_analysis_for_user(gcs_uri: str) -> dict[str, Any]:
    """Performs multimodal inspection of a desktop screenshot using Gemini or local OCR."""
    return tools.get_visual_analysis_for_user(gcs_uri=gcs_uri)


# Tool 3: GCS URI Resolution
@mcp_server.tool()
def get_gcs_uri_for_user(user: str) -> dict[str, Any]:
    """Queries BigQuery user_screenshots_view to retrieve the GCS URI of a user's desktop screenshot."""
    return tools.get_gcs_uri_for_user(user=user)


# Tool 4: Signed URL Generation
@mcp_server.tool()
def generate_signed_url(gcs_uri: str) -> dict[str, Any]:
    """Generates a secure signed URL for a GCS object to allow human SOC analyst viewing."""
    return tools.generate_signed_url(gcs_uri=gcs_uri)


# Tool 5: Rich Ticket ID Generation
@mcp_server.tool()
def create_rich_ticket_id(user_id: str) -> dict[str, Any]:
    """Generates a standardized, readable ticket ID."""
    return tools.create_rich_ticket_id(user_id=user_id)


# Tool 6: SOC Ticket Dispatch
@mcp_server.tool()
def dispatch_to_soc_ticketing_system(
    ticket_id: str,
    alert_payload: str,
    agent_reason: str,
    structured_report: str,
    severity: str = "HIGH",
    screenshot_url: str = "",
    mitre_tactics: list[str] | None = None,
    indicators_of_compromise: list[str] | None = None,
) -> dict[str, Any]:
    """Passes a confirmed or suspected threat incident ticket directly to the SOC Ticketing System.

    mitre_tactics: MITRE ATT&CK tactics supported by the evidence.
    indicators_of_compromise: IPs, domains and file hashes observed in the evidence.
    """
    return tools.dispatch_to_soc_ticketing_system(
        ticket_id=ticket_id,
        alert_payload=alert_payload,
        agent_reason=agent_reason,
        structured_report=structured_report,
        severity=severity,
        screenshot_url=screenshot_url,
        mitre_tactics=mitre_tactics,
        indicators_of_compromise=indicators_of_compromise,
    )


# Tool 7: False Positive Logging
@mcp_server.tool()
def log_false_positive(
    alert_payload: str, agent_comment: str, ticket_id: str = ""
) -> dict[str, Any]:
    """Closes the alert as a False Positive and archives it for analyst review."""
    return tools.log_false_positive(
        alert_payload=alert_payload,
        agent_comment=agent_comment,
        ticket_id=ticket_id,
    )


# Tool 8: Human Escalation
@mcp_server.tool()
def escalate_to_human(
    ticket_id: str,
    alert_payload: str,
    agent_reason_for_escalation: str,
    context_data: str,
    severity: str = "HIGH",
) -> dict[str, Any]:
    """Dispatches an incident ticket to the SOC ticketing queue for human analyst adjudication."""
    return tools.escalate_to_human(
        ticket_id=ticket_id,
        alert_payload=alert_payload,
        agent_reason_for_escalation=agent_reason_for_escalation,
        context_data=context_data,
        severity=severity,
    )


# Platform tool: the default-deny callback's escalation. No agent's tool_filter lists it,
# so no model is ever offered it; the ticket decision is fixed server-side.
@mcp_server.tool()
def auto_escalate_unresolved_alert(
    ticket_id: str,
    user_id: str,
    device_id: str,
    source_ip: str,
    threat_score: int,
    window_end: str,
    severity: str,
    structured_report: str,
) -> dict[str, Any]:
    """Platform-only: files the default-deny escalation ticket for an unresolved alert."""
    return tools.auto_escalate_unresolved_alert(
        ticket_id=ticket_id,
        user_id=user_id,
        device_id=device_id,
        source_ip=source_ip,
        threat_score=threat_score,
        window_end=window_end,
        severity=severity,
        structured_report=structured_report,
    )


def _local_mode() -> bool:
    return os.getenv("LOCAL_MODE", "false").lower() in ("true", "1")


class CallerAuthMiddleware:
    """
    Admits only requests whose Google ID token was minted for this service by the
    allowed caller. Cloud Run IAM already rejects callers without run.invoker; this
    re-checks the token in the app so a misconfigured invoker binding (or a second
    invoker) still cannot reach the tools. Off only in LOCAL_MODE.
    """

    def __init__(self, app, audience: str, allowed_caller: str):
        self.app = app
        self.audience = audience
        self.allowed_caller = allowed_caller

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode("latin-1")
        status, reason = self.check(auth)
        if status != 200:
            await _send_json(send, status, {"error": reason})
            return
        await self.app(scope, receive, send)

    def check(self, auth_header: str) -> tuple[int, str]:
        """Returns (200, caller) for an admitted token, else (401|403, reason)."""
        if not auth_header.startswith("Bearer "):
            return 401, "Missing bearer token."
        token = auth_header.split(" ", 1)[1].strip()
        try:
            from google.auth.transport import requests as google_requests
            from google.oauth2 import id_token

            claims = id_token.verify_oauth2_token(
                token, google_requests.Request(), audience=self.audience
            )
        except Exception as exc:
            logger.warning("MCP caller rejected: invalid ID token (%s)", exc)
            return 401, "Invalid ID token."
        caller = claims.get("email")
        if not claims.get("email_verified") or caller != self.allowed_caller:
            logger.warning("MCP caller rejected: %s is not the allowed caller", caller)
            return 403, "Caller is not allowed to use these tools."
        return 200, caller


async def _send_json(send, status: int, body: dict[str, Any]) -> None:
    import json

    payload = json.dumps(body).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": payload})


def build_http_app():
    """
    The Streamable HTTP app Cloud Run serves: stateless JSON responses, so any
    instance can answer any request and the service scales horizontally.
    Refuses to start in the cloud without the caller check configured.
    """
    app = mcp_server.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        host="0.0.0.0",
    )
    if _local_mode():
        return app
    audience = os.getenv("MCP_EXPECTED_AUDIENCE", "")
    allowed_caller = os.getenv("MCP_ALLOWED_CALLER", "")
    if not audience or not allowed_caller:
        raise RuntimeError(
            "MCP_EXPECTED_AUDIENCE and MCP_ALLOWED_CALLER must be set outside LOCAL_MODE."
        )
    return CallerAuthMiddleware(app, audience=audience, allowed_caller=allowed_caller)


def main():
    """CLI entrypoint: stdio by default, Streamable HTTP with --http."""
    if "--http" in sys.argv or os.getenv("MCP_TRANSPORT") == "streamable-http":
        import uvicorn

        logging.basicConfig(level=logging.INFO)
        uvicorn.run(
            build_http_app(),
            host="0.0.0.0",
            port=int(os.getenv("PORT", "8080")),
            proxy_headers=True,
            forwarded_allow_ips="*",
        )
        return
    mcp_server.run(transport="stdio")


if __name__ == "__main__":
    main()
