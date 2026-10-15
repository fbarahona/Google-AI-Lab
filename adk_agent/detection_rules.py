"""
Detection rules shared by every Python path that classifies telemetry.

The BigQuery UDFs in src/demo/terraform/bigquery.tf (is_malicious_command,
is_malicious_domain, calculate_threat_score) are the source of truth in the cloud.
The constants below are the same rules for the local paths: the behavioral profile
tool in LOCAL_MODE and the local demo runner. test_detection_rules.py parses
bigquery.tf and fails if the two drift apart.
"""

import re
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

# is_malicious_command UDF
MALICIOUS_COMMAND_REGEX = r"(?i)(powershell -enc|IEX|DownloadString|mimikatz|payload)"
# is_malicious_domain UDF
MALICIOUS_DOMAIN_REGEX = r"(?i)(\.ru$|\.xyz$|bad-domain|payload-downloader|c2-server|apt-group-data-exfil\.org$)"
# calculate_threat_score UDF and the behavioral profile query
SUSPICIOUS_USER_AGENT_REGEX = r"^(python-requests|curl|Go-http-client)"
BENIGN_COMMAND_REGEX = r"^(ipconfig|ping|ls -la|df -h|hostname)"
RISKY_FILE_TYPES = ("exe", "dll", "ps1", "bat", "vbs")
HIGH_PRIVILEGE_LEVELS = ("root", "admin")

# calculate_threat_score weights
SCORE_POLICY_VIOLATION = 50
SCORE_MALICIOUS_DNS = 60
SCORE_HIGH_PRIVILEGE = 35
SCORE_SUSPICIOUS_USER_AGENT = 20
SCORE_RISKY_FILE_TRANSFER = 40
SCORE_MALICIOUS_COMMAND = 100
SCORE_OTHER_COMMAND = 10

_MALICIOUS_COMMAND = re.compile(MALICIOUS_COMMAND_REGEX)
_MALICIOUS_DOMAIN = re.compile(MALICIOUS_DOMAIN_REGEX)
_SUSPICIOUS_USER_AGENT = re.compile(SUSPICIOUS_USER_AGENT_REGEX)
_BENIGN_COMMAND = re.compile(BENIGN_COMMAND_REGEX)

# Phrases that mark text in a desktop screenshot as an attempt to steer the triage
# agent. Matched case-insensitively against the OCR or vision output.
# Incident correlation (threat_detector MERGE): a scored window within this many
# minutes of the user's latest recorded window joins that incident instead of opening
# a new one, so one attack produces one published alert and one agent run.
INCIDENT_GAP_MINUTES = 30

PROMPT_INJECTION_KEYWORDS = (
    "ai triage",
    "classify as",
    "instruction override",
    "system notice to ai",
    "override instruction",
    "authorized red team",
    "authorized pentest",
    "suppress all critical",
    "do not dispatch",
    "do not alert",
)


def is_malicious_command(command_line: str | None) -> bool:
    return bool(command_line) and bool(_MALICIOUS_COMMAND.search(command_line))


def is_malicious_domain(network_domain: str | None) -> bool:
    return bool(network_domain) and bool(_MALICIOUS_DOMAIN.search(network_domain))


def is_suspicious_user_agent(user_agent: str | None) -> bool:
    return bool(user_agent) and bool(_SUSPICIOUS_USER_AGENT.search(user_agent))


def is_risky_file_type(file_type: str | None) -> bool:
    return file_type in RISKY_FILE_TYPES


def is_high_privilege(permission_level: str | None) -> bool:
    return permission_level in HIGH_PRIVILEGE_LEVELS


def contains_prompt_injection(text: str | None) -> bool:
    lowered = (text or "").lower()
    return any(keyword in lowered for keyword in PROMPT_INJECTION_KEYWORDS)


def threat_score(event: dict[str, Any]) -> int:
    """Python port of the calculate_threat_score UDF for one access or network event."""
    event_type = event.get("event_type")
    command_line = event.get("command_line")
    score = 0
    if event_type == "policy_violation":
        score += SCORE_POLICY_VIOLATION
    elif event_type == "dns_query" and is_malicious_domain(event.get("network_domain")):
        score += SCORE_MALICIOUS_DNS
    if is_high_privilege(event.get("permission_level_requested")):
        score += SCORE_HIGH_PRIVILEGE
    if is_suspicious_user_agent(event.get("user_agent")):
        score += SCORE_SUSPICIOUS_USER_AGENT
    if event_type == "file_transfer" and is_risky_file_type(event.get("file_type")):
        score += SCORE_RISKY_FILE_TRANSFER
    if is_malicious_command(command_line):
        score += SCORE_MALICIOUS_COMMAND
    elif command_line is not None and not _BENIGN_COMMAND.search(command_line):
        score += SCORE_OTHER_COMMAND
    return score


def correlate_windows(
    window_ends: list[datetime],
    open_incident: tuple[str, datetime] | None = None,
    *,
    alert_id_for: Callable[[datetime], str],
    window: timedelta = timedelta(minutes=2),
    gap_minutes: int = INCIDENT_GAP_MINUTES,
) -> list[tuple[str, str, str]]:
    """
    Python twin of the detector MERGE's incident correlation, for one user's
    qualifying windows in a batch. Returns (alert_id, incident_id, status) per window,
    oldest first. status is NEW for the window that opens an incident and CORRELATED
    for the rest. open_incident is the user's latest recorded (incident_id, window_end).
    """
    if not window_ends:
        return []
    ordered = sorted(window_ends)
    gap = timedelta(minutes=gap_minutes)
    batch_incident = alert_id_for(ordered[0])
    rows = []
    for end in ordered:
        alert_id = alert_id_for(end)
        joins_open = (
            open_incident is not None and open_incident[1] >= end - window - gap
        )
        incident_id = open_incident[0] if joins_open else batch_incident
        status = (
            "NEW" if not joins_open and alert_id == batch_incident else "CORRELATED"
        )
        rows.append((alert_id, incident_id, status))
    return rows
