"""
Demo data actions triggered from the SOC console (scenario injection, benign log
streaming).

In the cloud the telemetry is published to the raw-logs Pub/Sub topic, so it takes
the real path: BigQuery subscription, scheduled detector, agent, ticket. Injection
also writes a scripted ticket marked SIMULATED so there is something to show before
the agent's ticket arrives; the console badges it and keeps it out of the metrics.
"""

import logging
import os
import time

from src.demo.soc_ticketing.models import SIMULATED_DECISION, SocTicket
from src.demo.soc_ticketing.ticketing_service import SocTicketingService

logger = logging.getLogger("SocConsole")

DEFAULT_RAW_LOGS_TOPIC = "cymbal_cyber_raw_logs"


def _write_events(svc: SocTicketingService, acc_events, net_events) -> int:
    """Writes telemetry and returns how many events were written. Raises on failure."""
    from src.demo.data_generator.sinks import LocalSink, PubSubSink

    if svc.is_cloud_enabled():
        topic = os.getenv("RAW_LOGS_TOPIC", DEFAULT_RAW_LOGS_TOPIC)
        sink = PubSubSink(project_id=svc.project_id, topic_id=topic)
    else:
        sink = LocalSink(output_dir=os.path.join(svc.queue_dir, "telemetry"))
    return sink.write_events(acc_events, net_events)


def build_simulated_report(
    threat_type: str, user_id: str, device_id: str, source_ip: str, score: int
) -> tuple[str, str]:
    """Returns (agent_reason, structured_report) in the agent's report format."""
    severity = "CRITICAL" if threat_type == "malicious" else "LOW"
    if threat_type == "malicious":
        reason = "APT attack: Mimikatz credential theft and unauthorized connection to North Korea C2."
        behavior = (
            "* Multiple `mimikatz` and `powershell -enc` executions within a 2-minute window.\n"
            "* High-privilege requests to domain admin resources from a standard HR account.\n"
            f"* Outbound connections to `{source_ip}` with beacon-like periodicity."
        )
        visual = (
            "* Desktop screenshot shows a terminal running credential dumping tooling."
        )
        osint = f"* `{source_ip}` is in an address range registered to North Korea."
        mitre = (
            "* **Credential Access (T1003):** Mimikatz credential dumping.\n"
            "* **Execution (T1059.001):** Encoded PowerShell.\n"
            "* **Command and Control (T1071):** Beaconing to foreign infrastructure."
        )
        actions = (
            f"1. Isolate endpoint `{device_id}` from the network immediately.\n"
            f"2. Disable `{user_id}`, reset the password and revoke active sessions and tokens.\n"
            f"3. Block `{source_ip}` at the perimeter firewall, proxy and DNS resolver.\n"
            "4. Reset credentials of every account that logged on to the host in the last 7 days.\n"
            "5. Capture memory and disk images before reimaging, then hunt for the same IoCs fleet-wide."
        )
    else:
        reason = "IT maintenance backup script execution triggering threshold; verified benign routine."
        behavior = (
            "* Burst of file reads and archive writes from a scheduled backup script.\n"
            "* No privilege escalation, malicious commands or suspicious DNS lookups."
        )
        visual = "* Desktop screenshot shows the backup utility progress window; no attacker tooling."
        osint = f"* `{source_ip}` belongs to a known cloud provider range with no abuse reports."
        mitre = (
            "* **Discovery (T1083):** File enumeration consistent with backup activity."
        )
        actions = (
            f"1. Confirm with the owner of `{user_id}` that the backup job was scheduled.\n"
            "2. Close the ticket as False Positive.\n"
            "3. Add the backup service window to the detection allow-list to reduce noise."
        )

    report = (
        "### Security Incident Report\n"
        "**1. Alert Overview:**\n"
        f"* **User:** `{user_id}`\n"
        f"* **Device:** `{device_id}`\n"
        f"* **Origin IP:** `{source_ip}`\n"
        f"* **Threat Score:** `{score}`\n"
        f"* **Severity:** `{severity}`\n"
        f"* **Verdict:** {reason}\n"
        "* **Source:** Scripted by the console's demo controls. The agent did not "
        "produce this report and no threat intelligence was looked up.\n\n"
        f"**2. Behavioral Findings:**\n{behavior}\n\n"
        f"**3. Visual Forensics:**\n{visual}\n\n"
        f"**4. External Threat Intelligence:**\n{osint}\n\n"
        f"**5. MITRE ATT&CK Mapping:**\n{mitre}\n\n"
        f"**6. Recommended Response Actions:**\n{actions}\n"
    )
    return reason, report


def inject_threat_scenario(
    svc: SocTicketingService, threat_type: str, user_id: str, screenshots_dir: str
) -> str:
    """Injects a threat scenario's telemetry plus a simulated ticket.

    Returns a status message. Raises if the telemetry could not be written, in which
    case no simulated ticket is created either.
    """
    from src.demo.data_generator.log_generator import SyntheticLogEngine

    eng = SyntheticLogEngine(project_id=svc.project_id, dataset_id=svc.dataset_id)
    acc_events, net_events = eng.inject_threat(threat_type=threat_type, user_id=user_id)
    written = _write_events(svc, acc_events, net_events)

    is_malicious = threat_type == "malicious"
    score = 1950 if is_malicious else 120
    dev_id = acc_events[0].get("device_id", "ws-hr-05") if acc_events else "ws-hr-05"
    src_ip = (
        acc_events[0].get("source_ip", "175.45.176.10")
        if acc_events
        else "175.45.176.10"
    )
    reason, report = build_simulated_report(threat_type, user_id, dev_id, src_ip, score)
    ticket = SocTicket(
        ticket_id=f"SIM-TICKET-{user_id}-{int(time.time())}",
        user_id=user_id,
        device_id=dev_id,
        source_ip=src_ip,
        threat_score=score,
        severity="CRITICAL" if is_malicious else "LOW",
        status="ESCALATED",
        category="Malware" if is_malicious else "Policy Violation",
        agent_decision=SIMULATED_DECISION,
        agent_reason=reason,
        mitre_tactics=["Command and Control", "Execution", "Credential Access"]
        if is_malicious
        else ["Discovery"],
        indicators_of_compromise=[src_ip],
        structured_report=report,
        screenshot_url=f"{screenshots_dir}/{user_id}.png",
    )
    svc.create_and_dispatch_ticket(ticket)

    if svc.is_cloud_enabled():
        return (
            f"Published {written} events for {user_id} and added a simulated ticket. "
            "The detector runs every 5 minutes; the agent's own ticket follows."
        )
    return (
        f"Wrote {written} events for {user_id} and added a simulated ticket. "
        "Run `uv run python -m src.demo.local_runner` for the agent's investigation."
    )


def stream_benign_logs(svc: SocTicketingService, batch_size: int = 50) -> str:
    """Streams a batch of benign activity logs. Returns a status message; raises on failure."""
    from src.demo.data_generator.log_generator import SyntheticLogEngine

    eng = SyntheticLogEngine(project_id=svc.project_id, dataset_id=svc.dataset_id)
    acc_events, net_events = eng.generate_benign_batch(count=batch_size)
    written = _write_events(svc, acc_events, net_events)
    return f"Streamed {written} benign events."
