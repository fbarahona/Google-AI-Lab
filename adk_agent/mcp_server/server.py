"""
Cymbal Cyber Local MCP Server
=============================
Implements a standards-compliant Model Context Protocol (MCP) server
exposing BigQuery behavioral telemetry investigation, multimodal
visual forensics, and SOC incident ticketing tools over stdio and SSE.

The server deliberately exposes no free-form SQL or schema-discovery tools: any MCP
client that connects without a tool_filter only gets the fixed, parameterized
investigation and ticketing operations below.
"""

import logging
import sys
from typing import Any

try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    from mcp.server.fastmcp import FastMCP as MCPServer

from adk_agent.tools import (
    create_rich_ticket_id as soc_create_rich_ticket_id,
)
from adk_agent.tools import (
    dispatch_to_soc_ticketing_system as soc_dispatch_to_soc_ticketing_system,
)
from adk_agent.tools import (
    escalate_to_human as soc_escalate_to_human,
)
from adk_agent.tools import (
    generate_signed_url as vis_generate_signed_url,
)
from adk_agent.tools import (
    get_entity_behavioral_profile as bq_get_entity_behavioral_profile,
)
from adk_agent.tools import (
    get_gcs_uri_for_user as vis_get_gcs_uri_for_user,
)
from adk_agent.tools import (
    get_visual_analysis_for_user as vis_get_visual_analysis_for_user,
)
from adk_agent.tools import (
    log_false_positive as soc_log_false_positive,
)

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
    return bq_get_entity_behavioral_profile(
        entity_type=entity_type,
        entity_id=entity_id,
        window_to_investigate=window_to_investigate,
    )


# Tool 2: Visual Screenshot Analysis
@mcp_server.tool()
def get_visual_analysis_for_user(gcs_uri: str) -> dict[str, Any]:
    """Performs multimodal inspection of a desktop screenshot using Gemini or local OCR."""
    res = vis_get_visual_analysis_for_user(gcs_uri=gcs_uri)
    if isinstance(res, dict):
        return res
    is_injection = (
        "prompt injection detected" in res.lower()
        or "security alert: prompt injection" in res.lower()
    )
    is_unavailable = "evidence unavailable" in res.lower() or res.lstrip().startswith(
        "Error:"
    )
    if is_unavailable:
        return {
            "error": res,
            "security_flags": {
                "prompt_injection_detected": False,
                "evidence_unavailable": True,
            },
        }
    return {
        "analysis": res,
        "security_flags": {
            "prompt_injection_detected": is_injection,
            "evidence_unavailable": is_unavailable,
        },
    }


# Tool 3: GCS URI Resolution
@mcp_server.tool()
def get_gcs_uri_for_user(user: str) -> dict[str, Any]:
    """Queries BigQuery user_screenshots_view to retrieve the GCS URI of a user's desktop screenshot."""
    return vis_get_gcs_uri_for_user(user=user)


# Tool 4: Signed URL Generation
@mcp_server.tool()
def generate_signed_url(gcs_uri: str) -> str:
    """Generates a secure signed URL for a GCS object to allow human SOC analyst viewing."""
    return vis_generate_signed_url(gcs_uri=gcs_uri)


# Tool 5: Rich Ticket ID Generation
@mcp_server.tool()
def create_rich_ticket_id(user_id: str) -> str:
    """Generates a standardized, readable ticket ID."""
    return soc_create_rich_ticket_id(user_id=user_id)


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
    res = soc_dispatch_to_soc_ticketing_system(
        ticket_id=ticket_id,
        alert_payload=alert_payload,
        agent_reason=agent_reason,
        structured_report=structured_report,
        severity=severity,
        screenshot_url=screenshot_url,
        mitre_tactics=mitre_tactics,
        indicators_of_compromise=indicators_of_compromise,
    )
    if isinstance(res, dict):
        return res
    return {
        "status": "DISPATCHED",
        "ticket_id": ticket_id,
        "message": res,
        "security_flags": {"ticket_dispatched": True},
    }


# Tool 7: False Positive Logging
@mcp_server.tool()
def log_false_positive(
    alert_payload: str, agent_comment: str, ticket_id: str = ""
) -> dict[str, Any]:
    """Closes the alert as a False Positive and archives it for analyst review."""
    res = soc_log_false_positive(
        alert_payload=alert_payload,
        agent_comment=agent_comment,
        ticket_id=ticket_id,
    )
    if isinstance(res, dict):
        return res
    is_success = "successfully logged" in res.lower()
    return {
        "status": "RESOLVED_FALSE_POSITIVE" if is_success else "ERROR",
        "message": res,
        "security_flags": {
            "false_positive_logged": is_success,
            "evidence_unavailable": not is_success,
        },
    }


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
    res = soc_escalate_to_human(
        ticket_id=ticket_id,
        alert_payload=alert_payload,
        agent_reason_for_escalation=agent_reason_for_escalation,
        context_data=context_data,
        severity=severity,
    )
    if isinstance(res, dict):
        return res
    return {
        "status": "ESCALATED_PENDING_REVIEW",
        "ticket_id": ticket_id,
        "message": res,
        "security_flags": {"escalation_dispatched": True},
    }


def main():
    """Main CLI entrypoint for stdio and SSE transport."""
    transport = "stdio"
    if "--sse" in sys.argv:
        transport = "sse"
    mcp_server.run(transport=transport)


if __name__ == "__main__":
    main()
