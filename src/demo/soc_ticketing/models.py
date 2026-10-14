"""
Data models for the SOC Ticketing System.
"""

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

# agent_decision for tickets scripted by the console's demo controls. The console
# badges them and every dashboard metric leaves them out.
SIMULATED_DECISION = "SIMULATED"

# agent_decision for alerts the agent closed as false positive on its own. They are
# archived as RESOLVED with no analyst verdict, so analysts can review the closure.
AUTO_CLOSED_FP_DECISION = "FALSE_POSITIVE_AUTO_CLOSED"


class SocTicket(BaseModel):
    """Schema for incident tickets passed to the SOC Ticketing System."""

    ticket_id: str = Field(..., description="Unique SOC incident ticket ID.")
    alert_id: str | None = Field(
        None, description="Reference to the detection alert_id (user_id|window_end)."
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="Ticket creation timestamp (ISO 8601 UTC).",
    )
    transaction_window_end: str | None = Field(
        None,
        description="Aggregation window end timestamp from continuous query alert.",
    )
    user_id: str = Field(..., description="Entity or user under investigation.")
    device_id: str = Field(..., description="Endpoint or device identifier.")
    source_ip: str = Field(
        ..., description="Originating public or internal IP address."
    )
    threat_score: int = Field(..., description="Aggregated risk or anomaly score.")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(
        "HIGH", description="Incident severity level."
    )
    status: Literal[
        "OPEN", "UNDER_INVESTIGATION", "ESCALATED", "RESOLVED", "FALSE_POSITIVE"
    ] = Field("OPEN", description="Lifecycle status in SOC ticketing system.")
    category: Literal[
        "Risky Domain/URL",
        "Malware",
        "Data Leak",
        "Botnet",
        "PUP",
        "Recon",
        "Policy Violation",
    ] = Field("Risky Domain/URL", description="Incident category classification.")
    sla_status: Literal["Within SLA", "Approaching SLA", "Breached SLA"] = Field(
        "Within SLA", description="Service Level Agreement deadline status."
    )
    geo_country: str | None = Field(
        None, description="Country of origin detected via OSINT/GeoIP."
    )
    geo_lat: float | None = Field(None, description="Latitude for threat mapping.")
    geo_lon: float | None = Field(None, description="Longitude for threat mapping.")
    agent_decision: str = Field(..., description="Autonomous assessment by ADK agents.")
    agent_reason: str = Field(..., description="Detailed rationale provided by ADK.")
    mitre_tactics: list[str] = Field(
        default_factory=list, description="Associated MITRE ATT&CK tactics."
    )
    indicators_of_compromise: list[str] = Field(
        default_factory=list, description="Extracted IoCs (IPs, hashes, domains)."
    )
    screenshot_url: str | None = Field(
        None, description="Signed URL to multimodal desktop evidence."
    )
    structured_report: str = Field(
        ..., description="Full forensic markdown report from ADK."
    )
    human_decision: str | None = Field(
        None, description="Adjudication verdict by human SOC analyst."
    )
    human_comment: str | None = Field(None, description="Analyst review notes.")
    adjudicated_at: str | None = Field(
        None, description="Timestamp of human resolution."
    )


class DetectionAlert(BaseModel):
    """
    Standard Alert Contract schema published by any detection engine
    (scheduled detector, Dataflow, or Continuous Query) to cymbal_cyber_alerts.
    """

    alert_id: str = Field(
        ..., description="Unique key: user_id|window_end used for deduplication."
    )
    schema_version: int = Field(1, description="Alert contract schema version.")
    engine: Literal["scheduled", "dataflow", "cq"] = Field(
        "scheduled", description="Detection engine identifier."
    )
    user_id: str = Field(..., description="Target user identifier.")
    device_id: str = Field(..., description="Endpoint device identifier.")
    source_ip: str = Field(
        ..., description="Internal or external IP under observation."
    )
    window_start: str = Field(
        ..., description="Closed window start timestamp (ISO 8601)."
    )
    window_end: str = Field(..., description="Closed window end timestamp (ISO 8601).")
    total_2_min_threat_score: int = Field(
        ..., description="Calculated aggregate threat score."
    )
    high_privilege_request_count: int = Field(
        0, description="Count of privilege escalation requests."
    )
    malicious_command_count: int = Field(
        0, description="Count of suspicious/malicious commands executed."
    )
    malicious_dns_count: int = Field(
        0, description="Count of anomalous or high-risk DNS queries."
    )
    detected_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="Detection timestamp (ISO 8601).",
    )
