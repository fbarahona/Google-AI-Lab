"""Sample adjudicated tickets so a fresh local console archive is not empty."""

from datetime import UTC, datetime, timedelta
from typing import Any

from src.demo.soc_ticketing.models import SIMULATED_DECISION
from src.demo.soc_ticketing.service.schema import SCREENSHOTS_DIR


class SeedHistoryMixin:
    """Demo seed history for SocTicketingService; never written to disk."""

    def _generate_seed_history(self) -> list[dict[str, Any]]:
        """Sample adjudicated tickets for an empty local archive, marked SIMULATED."""
        now = datetime.now(UTC)
        screenshots_dir = str(SCREENSHOTS_DIR)
        samples = [
            {
                "ticket_id": "SOC-TICKET-g.harris-1791600100",
                "created_at": (now - timedelta(days=2, hours=3)).isoformat(),
                "user_id": "g.harris",
                "device_id": "ws-hr-05",
                "source_ip": "175.45.176.10",
                "threat_score": 2400,
                "severity": "CRITICAL",
                "status": "RESOLVED",
                "category": "Malware",
                "sla_status": "Within SLA",
                "geo_country": "North Korea",
                "geo_lat": 39.0392,
                "geo_lon": 125.7625,
                "agent_decision": "PERCEIVED_THREAT",
                "agent_reason": "C2 beaconing and unauthorized PowerShell script execution detected from known Lazarus Group IP.",
                "mitre_tactics": ["Command and Control", "Execution", "Initial Access"],
                "indicators_of_compromise": ["175.45.176.10", "c2-server-1.xyz"],
                "screenshot_url": f"{screenshots_dir}/g.harris.png",
                "structured_report": "### Security Incident Report\n* **User:** g.harris\n* **Verdict:** Genuine Threat\n* **Evidence:** Visual terminal confirmed Mimikatz execution.",
                "human_decision": "Genuine Threat",
                "human_comment": "Confirmed credential theft and lateral movement attempt. Workstation isolated and credentials revoked.",
                "adjudicated_at": (now - timedelta(days=2, hours=2)).isoformat(),
            },
            {
                "ticket_id": "SOC-TICKET-l.taylor-1791580220",
                "created_at": (now - timedelta(days=3, hours=5)).isoformat(),
                "user_id": "l.taylor",
                "device_id": "ws-hr-01",
                "source_ip": "74.125.70.93",
                "threat_score": 120,
                "severity": "LOW",
                "status": "RESOLVED",
                "category": "Policy Violation",
                "sla_status": "Within SLA",
                "geo_country": "United States",
                "geo_lat": 37.7749,
                "geo_lon": -122.4194,
                "agent_decision": "FALSE_POSITIVE",
                "agent_reason": "Automated IT backup script triggering threshold; no hostile foreign IPs or escalation detected.",
                "mitre_tactics": ["Discovery"],
                "indicators_of_compromise": ["74.125.70.93"],
                "screenshot_url": f"{screenshots_dir}/l.taylor.png",
                "structured_report": "### Security Incident Report\n* **User:** l.taylor\n* **Verdict:** False Positive\n* **Evidence:** Standard maintenance script.",
                "human_decision": "False Positive",
                "human_comment": "Scheduled maintenance routine verified with DevOps team.",
                "adjudicated_at": (
                    now - timedelta(days=3, hours=4, minutes=40)
                ).isoformat(),
            },
            {
                "ticket_id": "SOC-TICKET-r.patel-1791550180",
                "created_at": (now - timedelta(days=4, hours=1)).isoformat(),
                "user_id": "r.patel",
                "device_id": "srv-web-prod-02",
                "source_ip": "194.26.135.68",
                "threat_score": 1950,
                "severity": "CRITICAL",
                "status": "RESOLVED",
                "category": "Risky Domain/URL",
                "sla_status": "Within SLA",
                "geo_country": "Russia",
                "geo_lat": 55.7558,
                "geo_lon": 37.6173,
                "agent_decision": "PERCEIVED_THREAT",
                "agent_reason": "High-risk domain connection to 'my-payload-downloader.ru' and multiple login failures.",
                "mitre_tactics": ["Initial Access", "Command and Control"],
                "indicators_of_compromise": [
                    "194.26.135.68",
                    "my-payload-downloader.ru",
                ],
                "screenshot_url": f"{screenshots_dir}/r.patel.png",
                "structured_report": "### Security Incident Report\n* **User:** r.patel\n* **Origin:** Moscow, Russia\n* **Domain:** my-payload-downloader.ru",
                "human_decision": "Genuine Threat",
                "human_comment": "Blocked external IP at perimeter firewall. Domain sinkholed.",
                "adjudicated_at": (now - timedelta(days=4)).isoformat(),
            },
            {
                "ticket_id": "SOC-TICKET-c.wilson-1791510400",
                "created_at": (now - timedelta(days=6, hours=8)).isoformat(),
                "user_id": "c.wilson",
                "device_id": "ws-finance-03",
                "source_ip": "74.125.10.15",
                "threat_score": 280,
                "severity": "MEDIUM",
                "status": "RESOLVED",
                "category": "Data Leak",
                "sla_status": "Approaching SLA",
                "geo_country": "United States",
                "geo_lat": 40.7128,
                "geo_lon": -74.0060,
                "agent_decision": "FALSE_POSITIVE",
                "agent_reason": "Elevated outbound file transfer volume during quarter-end financial reconciliation.",
                "mitre_tactics": ["Collection"],
                "indicators_of_compromise": ["74.125.10.15"],
                "screenshot_url": f"{screenshots_dir}/c.wilson.png",
                "structured_report": "### Security Incident Report\n* **User:** c.wilson\n* **Type:** Financial data transfer",
                "human_decision": "False Positive",
                "human_comment": "Approved quarterly financial ledger sync with authorized external auditor.",
                "adjudicated_at": (now - timedelta(days=6, hours=4)).isoformat(),
            },
            {
                "ticket_id": "SOC-TICKET-temp-contractor-1791480050",
                "created_at": (now - timedelta(days=8, hours=2)).isoformat(),
                "user_id": "temp_contractor",
                "device_id": "ws-dev-11",
                "source_ip": "185.220.101.5",
                "threat_score": 1400,
                "severity": "HIGH",
                "status": "RESOLVED",
                "category": "Botnet",
                "sla_status": "Within SLA",
                "geo_country": "Germany",
                "geo_lat": 52.5200,
                "geo_lon": 13.4050,
                "agent_decision": "PERCEIVED_THREAT",
                "agent_reason": "Connection originating from known Tor exit node with port scanning activity.",
                "mitre_tactics": ["Reconnaissance"],
                "indicators_of_compromise": ["185.220.101.5"],
                "screenshot_url": f"{screenshots_dir}/temp_contractor.png",
                "structured_report": "### Security Incident Report\n* **User:** temp_contractor\n* **IP:** Tor exit node",
                "human_decision": "Genuine Threat",
                "human_comment": "Contractor VPN session terminated. Tor IP added to dynamic blocklist.",
                "adjudicated_at": (now - timedelta(days=8, hours=1)).isoformat(),
            },
        ]
        for sample in samples:
            sample["ticket_id"] = sample["ticket_id"].replace(
                "SOC-TICKET-", "SIM-TICKET-", 1
            )
            sample["agent_decision"] = SIMULATED_DECISION
        return samples
