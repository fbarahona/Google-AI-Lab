"""
Demo data actions triggered from the SOC console (scenario injection, benign log
streaming). These write telemetry and a simulated ticket so the console has
something to show without waiting for the detector and agent pipeline.
"""

import logging
import time

try:
    from .models import SocTicket
    from .ticketing_service import SocTicketingService
except ImportError:
    from models import SocTicket
    from ticketing_service import SocTicketingService

logger = logging.getLogger("SocConsole")


def _write_events(svc: SocTicketingService, acc_events, net_events) -> None:
    from demo.data_generator.sinks import BigQuerySink, LocalSink

    if svc.bq_client is not None:
        try:
            sink = BigQuerySink(project_id=svc.project_id, dataset_id=svc.dataset_id)
            sink.write_events(acc_events, net_events)
        except Exception as e:
            logger.warning("Could not write events to BigQuery sink: %s", e)
    else:
        LocalSink(output_dir=svc.queue_dir).write_events(acc_events, net_events)


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
        osint = f"* `{source_ip}` geolocates to North Korea and appears in public C2 blocklists."
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
        f"* **Verdict:** {reason}\n\n"
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
    """Injects a threat scenario's telemetry and a simulated ticket. Returns the ticket id."""
    from demo.data_generator.log_generator import SyntheticLogEngine

    eng = SyntheticLogEngine(project_id=svc.project_id, dataset_id=svc.dataset_id)
    acc_events, net_events = eng.inject_threat(threat_type=threat_type, user_id=user_id)
    _write_events(svc, acc_events, net_events)

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
        ticket_id=f"SOC-TICKET-{user_id}-{int(time.time())}",
        user_id=user_id,
        device_id=dev_id,
        source_ip=src_ip,
        threat_score=score,
        severity="CRITICAL" if is_malicious else "LOW",
        status="ESCALATED",
        category="Malware" if is_malicious else "Policy Violation",
        agent_decision="PERCEIVED_THREAT" if is_malicious else "FALSE_POSITIVE",
        agent_reason=reason,
        mitre_tactics=["Command and Control", "Execution", "Credential Access"]
        if is_malicious
        else ["Discovery"],
        indicators_of_compromise=[src_ip],
        structured_report=report,
        screenshot_url=f"{screenshots_dir}/{user_id}.png",
    )
    svc.create_and_dispatch_ticket(ticket)
    return ticket.ticket_id


def stream_benign_logs(svc: SocTicketingService, batch_size: int = 50) -> None:
    """Streams a batch of benign activity logs."""
    from demo.data_generator.log_generator import SyntheticLogEngine

    eng = SyntheticLogEngine(project_id=svc.project_id, dataset_id=svc.dataset_id)
    acc_events, net_events = eng.generate_benign_batch(count=batch_size)
    _write_events(svc, acc_events, net_events)
