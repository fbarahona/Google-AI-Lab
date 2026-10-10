"""
Data models for the SOC Ticketing System.
"""
from datetime import datetime, timezone
from typing import Optional, List, Literal
from pydantic import BaseModel, Field


class SocTicket(BaseModel):
    """Schema for incident tickets passed to the SOC Ticketing System."""
    ticket_id: str = Field(..., description="Unique SOC incident ticket ID.")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Ticket creation timestamp (ISO 8601 UTC)."
    )
    user_id: str = Field(..., description="Entity or user under investigation.")
    device_id: str = Field(..., description="Endpoint or device identifier.")
    source_ip: str = Field(..., description="Originating public or internal IP address.")
    threat_score: int = Field(..., description="Aggregated risk or anomaly score.")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(
        "HIGH",
        description="Incident severity level."
    )
    status: Literal["OPEN", "UNDER_INVESTIGATION", "ESCALATED", "RESOLVED", "FALSE_POSITIVE"] = Field(
        "OPEN",
        description="Lifecycle status in SOC ticketing system."
    )
    agent_decision: str = Field(..., description="Autonomous assessment by ADK agents.")
    agent_reason: str = Field(..., description="Detailed rationale provided by ADK.")
    mitre_tactics: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK tactics.")
    indicators_of_compromise: List[str] = Field(default_factory=list, description="Extracted IoCs (IPs, hashes, domains).")
    screenshot_url: Optional[str] = Field(None, description="Signed URL to multimodal desktop evidence.")
    structured_report: str = Field(..., description="Full forensic markdown report from ADK.")
    human_decision: Optional[str] = Field(None, description="Adjudication verdict by human SOC analyst.")
    human_comment: Optional[str] = Field(None, description="Analyst review notes.")
    adjudicated_at: Optional[str] = Field(None, description="Timestamp of human resolution.")

