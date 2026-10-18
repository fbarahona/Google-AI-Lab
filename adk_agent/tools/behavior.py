"""
Behavioral profile of a user, device or IP: a parameterized BigQuery query in the
cloud, the same filters and detection rules over the synthetic log files in
LOCAL_MODE. Fails closed in the cloud when the query cannot run.
"""

import glob
import json
import logging
import os
from pathlib import Path
from typing import Any

from google.adk.tools import ToolContext
from google.cloud import bigquery

from adk_agent import detection_rules as rules
from adk_agent.settings import DATASET_ID, REPO_ROOT
from adk_agent.tools import clients
from adk_agent.tools.clients import _set_state
from adk_agent.tools.sql_guard import (
    ALLOWED_INTERVAL_WINDOWS,
    DEFAULT_MAX_BYTES_BILLED,
    normalize_entity_type,
    sanitize_entity_value,
    validate_safe_sql_query,
)

logger = logging.getLogger(__name__)


def build_event_logs_query(
    entity_type: str, entity_id: str, window_to_investigate: str = "24 HOUR"
) -> tuple[str, bigquery.QueryJobConfig]:
    """
    Generates a secure, parameterized SQL query and QueryJobConfig to construct
    a behavioral profile for an entity in the Cymbal_Cyber dataset.

    Validates entity_type and interval window against strict allowlists (as SQL syntax
    cannot be parameterized), and sanitizes and binds entity_id as a named parameter (@entity_id)
    inside a BigQuery QueryJobConfig to eliminate SQL injection vulnerabilities.

    Returns:
        tuple[str, bigquery.QueryJobConfig]: The parameterized SQL string and the job configuration
        containing the scalar query parameter.
    """
    clean_type = normalize_entity_type(entity_type)
    clean_id = sanitize_entity_value(entity_id, field_name="entity_id")

    clean_window = (window_to_investigate or "24 HOUR").strip().upper()
    if clean_window not in ALLOWED_INTERVAL_WINDOWS:
        raise ValueError(
            f"Invalid window '{window_to_investigate}'. Must be one of {sorted(ALLOWED_INTERVAL_WINDOWS)}."
        )

    # Derive partition interval in days so each CTE prunes DAY partitions (cost); the tables do not require a partition filter
    window_partition_days_map = {
        "1 HOUR": 1,
        "2 HOUR": 1,
        "6 HOUR": 1,
        "12 HOUR": 1,
        "24 HOUR": 1,
        "48 HOUR": 2,
        "7 DAY": 7,
        "30 DAY": 30,
    }
    partition_days = window_partition_days_map.get(clean_window, 1)

    logger.info(
        "Building %s parameterized SQL threat profile for %s: %s",
        clean_window,
        clean_type,
        clean_id,
    )

    # network_events has no device_id: device and user traffic is found through the
    # internal IPs their VPN sessions were assigned (the detector joins the same way).
    session_ips = "source_ip IN (SELECT assigned_internal_ip FROM FlaggedSessions)"
    if clean_type == "device":
        access_filter = "device_id = @entity_id"
        network_filter = session_ips
    elif clean_type == "ip":
        access_filter = "source_ip = @entity_id"
        network_filter = "source_ip = @entity_id"
    else:
        access_filter = "user_id = @entity_id"
        network_filter = f"(user_id = @entity_id OR {session_ips})"

    query_sql = rf"""
    WITH
    FlaggedSessions AS (
        SELECT DISTINCT assigned_internal_ip
        FROM `{DATASET_ID}.user_access_events`
        WHERE DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL {partition_days} DAY)
          AND event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {clean_window})
          AND event_type = 'login_success'
          AND {access_filter}
    ),
    AccessMetrics AS (
        SELECT
          COUNT(*) AS total_access_events_24h,
          COUNTIF(event_type = 'login_failure') AS total_login_failures_24h,
          COUNT(DISTINCT source_ip) AS distinct_public_source_ips_24h,
          COUNTIF(REGEXP_CONTAINS(user_agent, r'{rules.SUSPICIOUS_USER_AGENT_REGEX}')) AS suspicious_user_agent_logins_24h,
          COUNT(DISTINCT user_agent) AS distinct_user_agents_used_24h
        FROM `{DATASET_ID}.user_access_events`
        WHERE DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL {partition_days} DAY)
          AND event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {clean_window})
          AND {access_filter}
    ),
    NetworkMetrics AS (
        SELECT
          COUNT(*) AS total_network_events_24h,
          COUNTIF(permission_level_requested IN {rules.HIGH_PRIVILEGE_LEVELS!r}) AS high_privilege_requests_24h,
          COUNTIF(file_type IN {rules.RISKY_FILE_TYPES!r}) AS risky_file_transfers_24h,
          COUNTIF(`{DATASET_ID}.is_malicious_command`(command_line)) AS malicious_commands_24h,
          COUNTIF(`{DATASET_ID}.is_malicious_domain`(network_domain)) AS malicious_dns_queries_24h,
          COUNT(DISTINCT destination_ip) AS distinct_destination_ips_24h,
          COUNT(DISTINCT file_hash_sha256) AS distinct_files_transferred_24h
        FROM `{DATASET_ID}.network_events`
        WHERE DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL {partition_days} DAY)
          AND event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {clean_window})
          AND {network_filter}
    )
    SELECT *
    FROM AccessMetrics
    CROSS JOIN NetworkMetrics;
    """

    validate_safe_sql_query(query_sql, allowed_dataset=DATASET_ID)

    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("entity_id", "STRING", clean_id)
        ],
        maximum_bytes_billed=DEFAULT_MAX_BYTES_BILLED,
    )

    return query_sql.strip(), job_config


def local_logs_dir() -> Path:
    """Where LOCAL_MODE reads synthetic telemetry (LOCAL_LOGS_DIR, else the repo's)."""
    return Path(os.getenv("LOCAL_LOGS_DIR") or REPO_ROOT / "local_demo_data" / "logs")


def _read_jsonl(logs_dir: Path, combined_name: str, pattern: str) -> list[dict]:
    files = [logs_dir / combined_name]
    if not files[0].exists():
        files = sorted(Path(p) for p in glob.glob(str(logs_dir / pattern)))
    events = []
    for path in files:
        try:
            with open(path, encoding="utf-8") as f:
                events.extend(json.loads(line) for line in f if line.strip())
        except (OSError, ValueError) as e:
            logger.warning("Error reading local telemetry %s: %s", path, e)
    return events


def _compute_profile_from_local_logs(
    entity_type: str, entity_id: str
) -> dict[str, Any]:
    """
    LOCAL_MODE version of build_event_logs_query: the same filters and the same
    detection rules, over the synthetic log files instead of BigQuery. The time
    window is not applied; the local files hold only the current demo's events.
    """
    clean_type = normalize_entity_type(entity_type)
    logs_dir = local_logs_dir()
    access_events = _read_jsonl(
        logs_dir, "user_access_events.jsonl", "access_events*.jsonl"
    )
    network_events = _read_jsonl(
        logs_dir, "network_events.jsonl", "network_events*.jsonl"
    )

    access_field = {"user": "user_id", "device": "device_id", "ip": "source_ip"}[
        clean_type
    ]
    entity_access = [ev for ev in access_events if ev.get(access_field) == entity_id]
    session_ips = {
        ev.get("assigned_internal_ip")
        for ev in entity_access
        if ev.get("event_type") == "login_success" and ev.get("assigned_internal_ip")
    }
    if clean_type == "ip":
        entity_network = [
            ev for ev in network_events if ev.get("source_ip") == entity_id
        ]
    elif clean_type == "device":
        entity_network = [
            ev for ev in network_events if ev.get("source_ip") in session_ips
        ]
    else:
        entity_network = [
            ev
            for ev in network_events
            if ev.get("user_id") == entity_id or ev.get("source_ip") in session_ips
        ]

    user_agents = [ev.get("user_agent") for ev in entity_access if ev.get("user_agent")]
    return {
        "total_access_events_24h": len(entity_access),
        "total_login_failures_24h": sum(
            ev.get("event_type") == "login_failure" for ev in entity_access
        ),
        "distinct_public_source_ips_24h": len(
            {ev["source_ip"] for ev in entity_access if ev.get("source_ip")}
        ),
        "suspicious_user_agent_logins_24h": sum(
            rules.is_suspicious_user_agent(ua) for ua in user_agents
        ),
        "distinct_user_agents_used_24h": len(set(user_agents)),
        "total_network_events_24h": len(entity_network),
        "high_privilege_requests_24h": sum(
            rules.is_high_privilege(ev.get("permission_level_requested"))
            for ev in entity_network
        ),
        "risky_file_transfers_24h": sum(
            rules.is_risky_file_type(ev.get("file_type")) for ev in entity_network
        ),
        "malicious_commands_24h": sum(
            rules.is_malicious_command(ev.get("command_line")) for ev in entity_network
        ),
        "malicious_dns_queries_24h": sum(
            rules.is_malicious_domain(ev.get("network_domain")) for ev in entity_network
        ),
        "distinct_destination_ips_24h": len(
            {ev["destination_ip"] for ev in entity_network if ev.get("destination_ip")}
        ),
        "distinct_files_transferred_24h": len(
            {
                ev["file_hash_sha256"]
                for ev in entity_network
                if ev.get("file_hash_sha256")
            }
        ),
    }


def get_entity_behavioral_profile(
    entity_type: str,
    entity_id: str,
    window_to_investigate: str = "24 HOUR",
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """
    Retrieves the 24-hour behavioral profile and correlated anomaly metrics for an entity
    (user, device, or IP) by executing a strictly parameterized BigQuery query.

    Fails closed in cloud mode on query or permission errors so that infrastructure
    failures are not disguised as benign baseline activity.
    In LOCAL_MODE=true, dynamically computes metrics from local synthetic logs.

    Args:
        entity_type: Type of entity to investigate ('user', 'device', or 'ip').
        entity_id: The specific identifier (e.g., 'u.lewis', 'ws-hr-05', '175.45.177.32').
        window_to_investigate: Investigation lookback window (e.g. '24 HOUR', '12 HOUR').
        tool_context: ADK ToolContext used to record security state flags.

    Returns:
        dict: Correlated behavioral metrics including login failure counts, suspicious user agents,
              high privilege executions, risky file transfers, and C2 domain queries.
    """
    sql, job_config = build_event_logs_query(
        entity_type, entity_id, window_to_investigate
    )
    is_local_mode = os.getenv("LOCAL_MODE", "false").lower() == "true"

    if is_local_mode:
        res = _compute_profile_from_local_logs(entity_type, entity_id)
    else:
        try:
            bq = clients.get_bq_client()
            query_job = bq.query(sql, job_config=job_config)
            rows = list(query_job.result())
            if rows:
                res = dict(rows[0].items())
            else:
                res = {
                    "total_access_events_24h": 0,
                    "total_login_failures_24h": 0,
                    "distinct_public_source_ips_24h": 0,
                    "suspicious_user_agent_logins_24h": 0,
                    "distinct_user_agents_used_24h": 0,
                    "total_network_events_24h": 0,
                    "high_privilege_requests_24h": 0,
                    "risky_file_transfers_24h": 0,
                    "malicious_commands_24h": 0,
                    "malicious_dns_queries_24h": 0,
                    "distinct_destination_ips_24h": 0,
                    "distinct_files_transferred_24h": 0,
                }
        except Exception as e:
            logger.error(
                "BigQuery query failed for %s (%s). Failing closed with evidence_unavailable.",
                entity_id,
                e,
            )
            _set_state(tool_context, "evidence_unavailable", True)
            return {
                "status": "ERROR",
                "error": f"BigQuery telemetry query failed: {e}",
                "message": (
                    "CRITICAL INFRASTRUCTURE FAILURE: BigQuery telemetry unavailable. "
                    "Evidence cannot be verified. Security policy prohibits closing alert as FALSE POSITIVE. "
                    "You MUST invoke escalate_to_human immediately."
                ),
                "security_flags": {
                    "evidence_unavailable": True,
                    "malicious_indicators": False,
                },
            }

    # Update state flag on malicious indicators to enforce deterministic security gate
    has_malicious = (
        res.get("total_login_failures_24h", 0) > 5
        or res.get("malicious_commands_24h", 0) > 0
        or res.get("risky_file_transfers_24h", 0) > 0
        or res.get("malicious_dns_queries_24h", 0) > 0
    )
    if has_malicious:
        logger.info(
            "Setting state['malicious_indicators'] = True for entity: %s", entity_id
        )
        _set_state(tool_context, "malicious_indicators", True)
    _set_state(tool_context, "telemetry_evidence_collected", True)

    res["security_flags"] = {
        "malicious_indicators": bool(has_malicious),
        "evidence_unavailable": False,
    }

    return res
