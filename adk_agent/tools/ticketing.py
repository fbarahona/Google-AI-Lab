"""
Resolution actions: dispatch a ticket, escalate to a human, close a false positive,
and the default-deny escalation. Report text is masked before it is stored; a ticket
that cannot be stored raises, so it is never reported as dispatched.
"""

import json
import logging
import re
from typing import Any

from google.adk.tools import ToolContext

from adk_agent.privacy_guard import mask_pii
from adk_agent.tools import clients
from adk_agent.tools.clients import _clean_list, _set_state
from adk_agent.tools.ticket_ids import (
    alert_id_from_payload,
    normalize_severity,
    ticket_id_for_alert,
)
from src.demo.soc_ticketing.models import SocTicket

logger = logging.getLogger(__name__)


def _parse_alert_payload_to_row(alert_payload_str: str) -> dict:
    """Parses JSON string payload to match BigQuery adk_threat_assessment schema."""
    row = {
        "transaction_window_end": None,
        "user_id": None,
        "device_id": None,
        "source_ip": None,
        "total_2_min_threat_score": None,
        "alert_payload": alert_payload_str,
        "agent_decision": None,
        "agent_reason": None,
        "human_decision": None,
        "human_reason": None,
    }
    try:
        data = (
            json.loads(alert_payload_str)
            if isinstance(alert_payload_str, str)
            else alert_payload_str
        )
        row["user_id"] = data.get("user") or data.get("user_id")
        row["device_id"] = data.get("device") or data.get("device_id")
        row["source_ip"] = data.get("ip_address") or data.get("source_ip")
        row["total_2_min_threat_score"] = data.get("threat_score") or data.get(
            "total_2_min_threat_score"
        )
        row["transaction_window_end"] = data.get("window_end") or data.get(
            "transaction_window_end"
        )
    except Exception as e:
        logger.warning("Error parsing alert payload: %s", e)
    return row


def dispatch_to_soc_ticketing_system(
    ticket_id: str,
    alert_payload: str,
    agent_reason: str,
    structured_report: str,
    severity: str = "HIGH",
    screenshot_url: str = "",
    mitre_tactics: list[str] | None = None,
    indicators_of_compromise: list[str] | None = None,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """
    Passes a confirmed or suspected threat incident ticket directly to the SOC Ticketing System.
    Stores the ticket in BigQuery and the GCS escalation queue for SOC analysts to review.
    Raises if the ticket could not be stored, so a lost ticket is never reported as dispatched.

    Args:
        mitre_tactics: MITRE ATT&CK tactics supported by the evidence.
        indicators_of_compromise: IPs, domains and hashes observed in the evidence.
    """
    row = _parse_alert_payload_to_row(alert_payload)
    user_id = row.get("user_id") or "unknown_user"
    source_ip = row.get("source_ip")
    iocs = _clean_list(indicators_of_compromise)
    if source_ip and source_ip not in iocs:
        iocs.insert(0, source_ip)

    ticket = SocTicket(
        ticket_id=ticket_id,
        transaction_window_end=row.get("transaction_window_end"),
        user_id=user_id,
        device_id=row.get("device_id") or "unknown_device",
        source_ip=source_ip or "unknown_ip",
        threat_score=row.get("total_2_min_threat_score") or 100,
        severity=normalize_severity(severity),
        status="ESCALATED",
        agent_decision="PERCEIVED_THREAT",
        agent_reason=mask_pii(agent_reason),
        screenshot_url=screenshot_url or None,
        structured_report=mask_pii(structured_report),
        mitre_tactics=_clean_list(mitre_tactics),
        indicators_of_compromise=iocs,
    )

    res = clients.get_soc_service().create_and_dispatch_ticket(ticket)
    _set_state(tool_context, "ticket_dispatched", True)
    return {
        "status": "DISPATCHED",
        "ticket_id": ticket.ticket_id,
        "message": res,
        "security_flags": {"ticket_dispatched": True},
    }


def log_false_positive(
    alert_payload: str,
    agent_comment: str,
    ticket_id: str = "",
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """
    Closes the alert as a False Positive. The closure is archived as a resolved ticket
    marked as closed by the agent, so analysts can review it in the console archive.
    """
    logger.info("Logging false positive: %s", agent_comment)
    try:
        row = _parse_alert_payload_to_row(alert_payload)
        user_id = row.get("user_id") or "unknown_user"
        try:
            data = json.loads(alert_payload) if isinstance(alert_payload, str) else {}
        except Exception:
            data = {}
        ticket = SocTicket(
            ticket_id=ticket_id
            or ticket_id_for_alert(
                user_id, alert_id_from_payload(data if isinstance(data, dict) else {})
            ),
            transaction_window_end=row.get("transaction_window_end"),
            user_id=user_id,
            device_id=row.get("device_id") or "unknown_device",
            source_ip=row.get("source_ip") or "unknown_ip",
            threat_score=row.get("total_2_min_threat_score") or 0,
            severity="LOW",
            status="RESOLVED",
            agent_decision="FALSE_POSITIVE",
            agent_reason=mask_pii(agent_comment),
            structured_report=(
                "### Closed as False Positive by the agent\n"
                "No analyst has reviewed this closure.\n\n"
                f"**Agent rationale:** {mask_pii(agent_comment)}"
            ),
        )
        clients.get_soc_service().record_auto_closed_false_positive(ticket)
    except Exception as e:
        logger.error("Exception during false positive logging: %s", e)
        _set_state(tool_context, "evidence_unavailable", True)
        return {
            "status": "ERROR",
            "error": f"Failed to log false positive: {e}",
            "security_flags": {
                "evidence_unavailable": True,
                "false_positive_logged": False,
            },
        }

    _set_state(tool_context, "false_positive_logged", True)
    return {
        "status": "RESOLVED_FALSE_POSITIVE",
        "ticket_id": ticket.ticket_id,
        "message": f"Successfully logged alert as a False Positive (ticket {ticket.ticket_id} archived for analyst review).",
        "security_flags": {
            "false_positive_logged": True,
            "evidence_unavailable": False,
        },
    }


def escalate_to_human(
    ticket_id: str,
    alert_payload: str,
    agent_reason_for_escalation: str,
    context_data: str,
    severity: str = "HIGH",
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """
    Dispatches the incident ticket to the SOC ticketing queue for human analyst adjudication.
    Returns immediately with escalation confirmation without blocking the agent runner.
    Raises if the ticket could not be stored.
    """
    row = _parse_alert_payload_to_row(alert_payload)

    user_id = row.get("user_id") or "unknown_user"
    screenshot_url = None
    if context_data:
        m_url = re.search(
            r"https://storage\.googleapis\.com/[^\s\)\"\']+", context_data
        )
        if m_url:
            screenshot_url = m_url.group(0)

    ticket = SocTicket(
        ticket_id=ticket_id,
        transaction_window_end=row.get("transaction_window_end"),
        user_id=user_id,
        device_id=row.get("device_id") or "unknown_device",
        source_ip=row.get("source_ip") or "unknown_ip",
        threat_score=row.get("total_2_min_threat_score") or 100,
        severity=normalize_severity(severity),
        status="ESCALATED",
        agent_decision="PERCEIVED_THREAT",
        agent_reason=mask_pii(agent_reason_for_escalation),
        screenshot_url=screenshot_url,
        structured_report=mask_pii(context_data),
    )
    result = clients.get_soc_service().create_and_dispatch_ticket(ticket)
    _set_state(tool_context, "escalation_dispatched", True)
    logger.info(
        "Escalated ticket %s to human analyst: %s",
        ticket_id,
        agent_reason_for_escalation,
    )
    return {
        "status": "ESCALATED_PENDING_REVIEW",
        "ticket_id": ticket_id,
        "message": (
            f"Incident successfully escalated to Human SOC Analyst: Ticket ID '{ticket_id}'. "
            f"Status: ESCALATED_PENDING_REVIEW. Queue Result: {result}"
        ),
        "security_flags": {"escalation_dispatched": True},
    }


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
    """
    Files the default-deny ticket for an alert the model left unresolved.

    Called only by the agent's default-deny callback, never offered to a model: no
    agent's tool_filter lists it. The decision is fixed here, so the caller cannot
    label the ticket anything but AUTO_ESCALATED_DEFAULT_DENY. Raises if the ticket
    cannot be stored, so the investigation fails and Pub/Sub redelivers the alert.
    """
    ticket = SocTicket(
        ticket_id=ticket_id,
        transaction_window_end=window_end or None,
        user_id=user_id or "unresolved_user",
        device_id=device_id or "unknown_device",
        source_ip=source_ip or "unknown_ip",
        threat_score=threat_score or 100,
        severity=normalize_severity(severity),
        status="ESCALATED",
        agent_decision="AUTO_ESCALATED_DEFAULT_DENY",
        agent_reason=(
            "Deterministic Default-Deny: Model terminated turn without resolving alert "
            "through a permitted tool action."
        ),
        structured_report=mask_pii(structured_report),
    )
    clients.get_soc_service().create_and_dispatch_ticket(ticket)
    logger.warning("Default-deny escalation filed ticket %s", ticket_id)
    return {
        "status": "ESCALATED",
        "ticket_id": ticket_id,
        "security_flags": {"escalation_dispatched": True},
    }
