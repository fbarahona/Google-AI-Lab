"""
Tools for the Cymbal Cyber ADK Multi-Agent Framework.
Includes BigQuery queries, GCS signed URLs, multimodal visual analysis with Gemini,
and SOC ticketing dispatch.

Every tool returns a dict with the same shape whether it runs in the MCP server or
in-process: a result field (or "error") plus "security_flags" for the flags the
agent's security gate reads. When a ToolContext is passed, the same flags are also
written to session state.
"""

import glob
import hashlib
import json
import logging
import os
import re
import time
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import google.auth
from dotenv import load_dotenv
from google import genai
from google.adk.tools import ToolContext
from google.auth import impersonated_credentials
from google.cloud import bigquery, storage
from google.genai import types

from adk_agent import detection_rules as rules
from src.demo.soc_ticketing.models import SocTicket
from src.demo.soc_ticketing.ticketing_service import SocTicketingService

load_dotenv()

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[1]

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Project configuration
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("PROJECT_ID", "local-demo")
LOCATION = os.getenv("GOOGLE_CLOUD_LOCATION", "us-east1")
DATASET_ID = os.getenv("BIGQUERY_DATASET", "Cymbal_Cyber")
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
BIGQUERY_ADK_THREAT_ASSESSMENT = f"{PROJECT_ID}.{DATASET_ID}.adk_threat_assessment"
GCS_ESCALATION_BUCKET = os.getenv(
    "ESCALATION_BUCKET", f"cymbal-cyber-adk-escalations-bucket_{PROJECT_ID}"
)
SCREENSHOTS_BUCKET = os.getenv(
    "SCREENSHOTS_BUCKET", f"cymbal-cyber-screenshots_{PROJECT_ID}"
)
AGENT_SERVICE_ACCOUNT_NAME = os.getenv("AGENT_SERVICE_ACCOUNT", "cymbal-adk-agent-sa")
GCS_SIGNER_SERVICE_ACCOUNT = os.getenv(
    "GCS_SIGNER_SA",
    f"{AGENT_SERVICE_ACCOUNT_NAME}@{PROJECT_ID}.iam.gserviceaccount.com",
)

# Initialize GenAI Client
_genai_client = None


def get_genai_client():
    global _genai_client
    if _genai_client is None:
        _genai_client = genai.Client(
            vertexai=True, project=PROJECT_ID, location=LOCATION
        )
    return _genai_client


# Initialize BigQuery Client
_bq_client = None


def get_bq_client():
    """BigQuery client on Application Default Credentials (the service's SA in the cloud)."""
    global _bq_client
    if _bq_client is None:
        _bq_client = bigquery.Client(project=PROJECT_ID)
    return _bq_client


# Initialize SOC Ticketing Service
_soc_service = None


def get_soc_service():
    global _soc_service
    if _soc_service is None:
        _soc_service = SocTicketingService(
            project_id=PROJECT_ID,
            dataset_id=DATASET_ID,
            escalation_bucket=GCS_ESCALATION_BUCKET,
        )
    return _soc_service


def _set_state(tool_context: ToolContext | None, key: str, value: Any) -> None:
    if tool_context is not None and getattr(tool_context, "state", None) is not None:
        tool_context.state[key] = value


def _clean_list(values: list[str] | None) -> list[str]:
    return [str(v).strip() for v in values or [] if v and str(v).strip()]


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


# --- Security & SQL Injection Prevention ---
# Accepted entity_type spellings, normalised once so the cloud query and the local
# log scan always agree on what was asked for.
ENTITY_TYPE_ALIASES = {
    "user": "user",
    "user_id": "user",
    "device": "device",
    "device_id": "device",
    "ip": "ip",
    "source_ip": "ip",
}
ALLOWED_ENTITY_TYPES = set(ENTITY_TYPE_ALIASES)
ALLOWED_INTERVAL_WINDOWS = {
    "1 HOUR",
    "2 HOUR",
    "6 HOUR",
    "12 HOUR",
    "24 HOUR",
    "48 HOUR",
    "7 DAY",
    "30 DAY",
}
DEFAULT_MAX_BYTES_BILLED = int(
    os.getenv("BQ_MAX_BYTES_BILLED", "1073741824")
)  # 1 GB default scan ceiling
DESTRUCTIVE_SQL_TOKENS = {
    "DROP",
    "ALTER",
    "DELETE",
    "UPDATE",
    "INSERT",
    "TRUNCATE",
    "GRANT",
    "REVOKE",
    "MERGE",
}


def validate_dataset_sandboxing(
    sql: str, allowed_dataset: str, allow_metadata: bool = False
) -> None:
    """
    Validates that a SQL query strictly references the designated allowed dataset
    and does not access unauthorized tenant or project datasets.

    Raises:
        ValueError: If unauthorized cross-dataset references are detected.
    """
    if not sql or not allowed_dataset:
        return

    clean_sql = re.sub(r"--.*$", "", sql, flags=re.MULTILINE)
    clean_sql = re.sub(r"/\*.*?\*/", "", clean_sql, flags=re.DOTALL)

    # Extract CTE names from WITH clauses so local aliases are not mistaken for external tables
    cte_names = set(
        re.findall(r"(?:WITH|,)\s*([a-zA-Z0-9_]+)\s+AS\s*\(", clean_sql, re.IGNORECASE)
    )

    # Match tables in FROM, JOIN, or TABLE clauses
    table_candidates = re.findall(
        r"\b(?:FROM|JOIN)\s+(?:TABLE\s+)?([`'\"a-zA-Z0-9_\-\.]+)",
        clean_sql,
        re.IGNORECASE,
    )

    # Match backticked table/function qualifiers `dataset.table` or `project.dataset.table`
    backticked_candidates = re.findall(r"`([a-zA-Z0-9_\-\.]+)`", clean_sql)

    all_candidates = set(table_candidates) | set(backticked_candidates)

    for item in all_candidates:
        ident = item.strip("`'\" \t\n")
        if (
            not ident
            or ident.startswith("(")
            or ident.upper() == "UNNEST"
            or ident in cte_names
        ):
            continue
        if "." in ident:
            parts = ident.split(".")
            if len(parts) >= 2:
                dataset_name = parts[-2]
                if allow_metadata and "information_schema" in dataset_name.lower():
                    continue
                if dataset_name.lower() != allowed_dataset.lower():
                    raise ValueError(
                        f"Cross-dataset reference forbidden: query references dataset '{dataset_name}', "
                        f"but only '{allowed_dataset}' is permitted."
                    )


def validate_safe_sql_query(
    sql: str, allow_metadata: bool = False, allowed_dataset: str | None = None
) -> None:
    """
    Defense-in-depth pre-execution guardrail validating that SQL queries intended
    for read-only forensic analysis do not contain destructive DML/DDL operations,
    do not access unauthorized system metadata (INFORMATION_SCHEMA), and only reference
    authorized datasets in the GCP project.

    While standard tool methods use parameterized query templates, this validator
    serves as a secondary defense boundary against future dynamic SQL queries or
    custom analyst query extensions. Raises ValueError if violations are detected.
    """
    if not sql:
        return

    # Block unauthorized access to BigQuery INFORMATION_SCHEMA metadata views
    if "information_schema" in sql.lower() and not allow_metadata:
        raise ValueError("Access to INFORMATION_SCHEMA is restricted.")

    upper_sql = sql.upper()
    for token in DESTRUCTIVE_SQL_TOKENS:
        if re.search(rf"\b{token}\b", upper_sql):
            raise ValueError(
                f"Security Policy Violation: Destructive SQL operation '{token}' is strictly forbidden."
            )

    # Sandbox dataset references if an allowed dataset is enforced
    if allowed_dataset:
        validate_dataset_sandboxing(sql, allowed_dataset, allow_metadata=allow_metadata)


ENTITY_SAFE_PATTERN = re.compile(r"^[a-zA-Z0-9\._\-:@]+$")
SQL_INJECTION_DANGEROUS_PATTERNS = [
    re.compile(r"['\";\\]"),
    re.compile(r"--"),
    re.compile(r"/\*|\*/"),
    re.compile(
        r"\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|EXEC|EXECUTE)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(OR|AND)\b\s+['\"0-9\w]", re.IGNORECASE),
]


def sanitize_entity_value(value: str, field_name: str = "entity_id") -> str:
    """
    Validates and sanitizes entity values (user IDs, device IDs, IP addresses)
    to prevent SQL injection vulnerabilities.

    Raises:
        ValueError: If value contains illegal characters or SQL injection patterns.
    """
    if value is None or not isinstance(value, str):
        raise ValueError(f"{field_name} must be a non-empty string.")

    trimmed = value.strip()
    if not trimmed:
        raise ValueError(f"{field_name} cannot be empty or whitespace.")

    for pattern in SQL_INJECTION_DANGEROUS_PATTERNS:
        if pattern.search(trimmed):
            raise ValueError(
                f"SQL Injection attempt or illegal characters detected in {field_name}: {trimmed!r}"
            )

    if not ENTITY_SAFE_PATTERN.match(trimmed):
        raise ValueError(
            f"{field_name} contains invalid characters: {trimmed!r}. "
            "Only alphanumeric characters, dots, hyphens, underscores, colons, and '@' are permitted."
        )

    return trimmed


def _clean_ticket_user(user_id: str | None) -> str:
    """Sanitizes user_id for use in a ticket ID, preventing JSON object bleed."""
    if not user_id:
        return "unknown_user"
    try:
        return sanitize_entity_value(user_id, field_name="user_id")
    except ValueError:
        match = re.match(r"^[a-zA-Z0-9\._-]+", str(user_id))
        return match.group(0) if match else "invalid_id"


def ticket_id_for_alert(
    user_id: str | None, alert_id: str | None, prefix: str = "SOC-TICKET"
) -> str:
    """
    Ticket ID for one detection alert: the same alert always maps to the same ticket,
    so Pub/Sub redeliveries overwrite rather than duplicate, and two alerts for one
    user never collide. Without an alert_id the suffix is random.
    """
    if alert_id:
        suffix = hashlib.sha256(alert_id.encode("utf-8")).hexdigest()[:10]
    else:
        suffix = uuid.uuid4().hex[:10]
    return f"{prefix}-{_clean_ticket_user(user_id)}-{suffix}"


def alert_id_from_payload(data: dict[str, Any]) -> str | None:
    """The alert contract's alert_id, or user_id|window_end when it is missing."""
    if data.get("alert_id"):
        return str(data["alert_id"])
    user = data.get("user_id") or data.get("user")
    window_end = data.get("window_end") or data.get("transaction_window_end")
    return f"{user}|{window_end}" if user and window_end else None


def normalize_severity(severity: str | None, default: str = "HIGH") -> str:
    sev = str(severity or "").strip().upper()
    return sev if sev in SEVERITIES else default


def create_rich_ticket_id(user_id: str) -> dict[str, str]:
    """
    Generates a standardized, readable ticket ID that is unique per call.
    During an investigation the security gate replaces it with the alert's own ticket ID.
    """
    return {
        "ticket_id": f"SOC-TICKET-{_clean_ticket_user(user_id)}-{int(time.time())}-{uuid.uuid4().hex[:6]}"
    }


def normalize_entity_type(entity_type: str) -> str:
    """Maps an accepted entity_type spelling to "user", "device" or "ip"."""
    if not entity_type or not isinstance(entity_type, str):
        raise ValueError("entity_type must be a non-empty string.")
    clean_type = ENTITY_TYPE_ALIASES.get(entity_type.strip().lower())
    if clean_type is None:
        raise ValueError(
            f"Invalid entity_type '{entity_type}'. Must be one of {sorted(ALLOWED_ENTITY_TYPES)}."
        )
    return clean_type


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


def read_png_text_chunks(file_path: str) -> dict[str, str]:
    """Reads embedded tEXt chunks from a PNG file without external image libraries."""
    import struct

    texts: dict[str, str] = {}
    if not os.path.exists(file_path):
        return texts
    try:
        with open(file_path, "rb") as f:
            header = f.read(8)
            if header != b"\x89PNG\r\n\x1a\n":
                return texts
            while True:
                chunk_len_bytes = f.read(4)
                if len(chunk_len_bytes) < 4:
                    break
                chunk_len = struct.unpack(">I", chunk_len_bytes)[0]
                chunk_type = f.read(4)
                chunk_data = f.read(chunk_len)
                f.read(4)  # CRC
                if chunk_type == b"tEXt":
                    parts = chunk_data.split(b"\x00", 1)
                    if len(parts) == 2:
                        k = parts[0].decode("latin-1", errors="ignore")
                        v = parts[1].decode("latin-1", errors="ignore")
                        texts[k] = v
                elif chunk_type == b"IEND":
                    break
    except Exception as e:
        logger.debug("Could not read PNG chunks from %s: %s", file_path, e)
    return texts


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
            bq = get_bq_client()
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


def _is_allowed_screenshot_uri(uri: str) -> bool:
    """True only for an object inside the screenshots bucket, with no path traversal."""
    prefix = f"gs://{SCREENSHOTS_BUCKET}/"
    if not uri or not uri.startswith(prefix):
        return False
    object_name = uri[len(prefix) :]
    return bool(object_name) and ".." not in object_name


def _visual_evidence_unavailable(
    err_msg: str, tool_context: ToolContext | None
) -> dict[str, Any]:
    """Fail-closed visual analysis result: marks evidence unavailable, returns no analysis."""
    _set_state(tool_context, "evidence_unavailable", True)
    return {
        "error": err_msg,
        "security_flags": {
            "evidence_unavailable": True,
            "prompt_injection_detected": False,
        },
    }


def get_visual_analysis_for_user(
    gcs_uri: str, tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """
    Performs multimodal inspection of a desktop screenshot using Gemini.
    Performs OCR on terminals, identifies command prompts, and evaluates suspicious UI activity.
    Detects adversarial prompt injection attempts and sets state['prompt_injection_detected'].

    The URI is model-chosen, so in cloud mode only gs:// objects in SCREENSHOTS_BUCKET are
    accepted. file:// URIs and the local OCR fallback are LOCAL_MODE-only.
    """
    is_local_mode = os.getenv("LOCAL_MODE", "false").lower() == "true"
    if is_local_mode:
        uri_ok = bool(gcs_uri) and (
            gcs_uri.startswith("gs://") or gcs_uri.startswith("file://")
        )
    else:
        uri_ok = _is_allowed_screenshot_uri(gcs_uri)
    if not uri_ok:
        return _visual_evidence_unavailable(
            f"Cannot perform visual analysis. Invalid or disallowed screenshot URI: {gcs_uri}. Visual evidence unavailable.",
            tool_context,
        )

    logger.info("Sending screenshot %s to visual analysis...", gcs_uri)
    prompt_text = """
    You are a Senior Level 3 SOC Analyst conducting a digital forensics investigation.
    This screenshot represents the visual evidence from the target workstation at the time of the alert.
    1. Perform OCR on any open terminal, PowerShell, command prompt, or code editors.
    2. Note any malicious commands, script executions (e.g. mimikatz, powershell -enc, IEX, curl, payload downloads).
    3. Note any popups, suspicious URLs in browser tabs, or unexpected background utilities.
    4. Provide a clear forensic conclusion: Does this visual evidence confirm a Genuine Threat or indicate Benign Activity?
    """

    visual_text = ""

    if is_local_mode:
        # Local forensic inspection: Extract OCR metadata from local screenshot file
        filename = gcs_uri.split("/")[-1].replace(".png", "")
        file_path_candidate = (
            gcs_uri.replace("file://", "") if gcs_uri.startswith("file://") else ""
        )
        repo_screenshot = (
            REPO_ROOT / "local_demo_data" / "user_screenshots" / f"{filename}.png"
        )
        if file_path_candidate and os.path.exists(file_path_candidate):
            local_path = file_path_candidate
        elif repo_screenshot.exists():
            local_path = str(repo_screenshot)
        else:
            # Same as the cloud path, where a missing object fails the vision call:
            # no screenshot is missing evidence, never a benign verdict.
            logger.error("No local screenshot found for %s", gcs_uri)
            return _visual_evidence_unavailable(
                f"Error: No desktop screenshot found for {gcs_uri}. Visual evidence unavailable.",
                tool_context,
            )
        ocr_chunks = read_png_text_chunks(local_path)
        if "forensic_ocr_text" in ocr_chunks:
            visual_text = (
                f"Forensic Desktop OCR Output:\n{ocr_chunks['forensic_ocr_text']}"
            )
        else:
            visual_text = f"Forensic inspection of desktop {filename}.png: Workspace shows standard developer console. No malicious tools."
    else:
        try:
            client = get_genai_client()
            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=[
                    types.Part.from_uri(file_uri=gcs_uri, mime_type="image/png"),
                    types.Part.from_text(text=prompt_text),
                ],
            )
            visual_text = (response.text or "").strip()
        except Exception as e:
            logger.error(
                "Error during multimodal visual analysis for %s: %s", gcs_uri, e
            )
            return _visual_evidence_unavailable(
                f"Error: Multimodal visual analysis service unavailable for {gcs_uri}: {e}. Visual evidence unavailable.",
                tool_context,
            )
        if not visual_text:
            logger.error("Multimodal visual analysis returned no text for %s", gcs_uri)
            return _visual_evidence_unavailable(
                f"Error: Multimodal visual analysis returned an empty result for {gcs_uri}. Visual evidence unavailable.",
                tool_context,
            )

    # Deterministic prompt injection scan; it does not depend on the model noticing.
    is_injection = rules.contains_prompt_injection(visual_text)
    if is_injection:
        logger.warning("PROMPT INJECTION DETECTED in visual evidence for %s", gcs_uri)
        _set_state(tool_context, "prompt_injection_detected", True)
        visual_text = f"[SECURITY ALERT: PROMPT INJECTION DETECTED IN DESKTOP SCREENSHOT]\n{visual_text}"
    _set_state(tool_context, "visual_evidence_collected", True)

    return {
        "analysis": visual_text,
        "security_flags": {
            "prompt_injection_detected": is_injection,
            "evidence_unavailable": False,
        },
    }


def get_gcs_uri_for_user(user: str) -> dict[str, Any]:
    """
    Queries BigQuery user_screenshots_view to retrieve the GCS URI of the user's desktop screenshot.
    Uses parameterized query and strict sanitization to prevent SQL injection.

    Returns {"gcs_uri": ..., "security_flags": {...}}. In cloud mode a BigQuery failure fails
    closed with evidence_unavailable; LOCAL_MODE skips BigQuery and uses the bucket path.
    """
    logger.info("Searching for screenshot GCS URI for user: %s", user)
    clean_user = sanitize_entity_value(user, field_name="user")
    default_uri = f"gs://{SCREENSHOTS_BUCKET}/{clean_user}.png"
    if os.getenv("LOCAL_MODE", "false").lower() == "true":
        return {
            "gcs_uri": default_uri,
            "security_flags": {"evidence_unavailable": False},
        }
    sql = f"""
        SELECT gcs_uri
        FROM `{PROJECT_ID}.{DATASET_ID}.user_screenshots_view`
        WHERE user_id = @user_id
        LIMIT 1;
    """
    validate_safe_sql_query(sql, allowed_dataset=DATASET_ID)
    try:
        from google.cloud import bigquery

        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("user_id", "STRING", clean_user)
            ],
            maximum_bytes_billed=DEFAULT_MAX_BYTES_BILLED,
        )
        bq = get_bq_client()
        results = list(bq.query(sql, job_config=job_config).result())
    except Exception as e:
        logger.error("Error querying GCS URI: %s", e)
        return {
            "error": f"Screenshot lookup failed: {e}. Visual evidence unavailable.",
            "security_flags": {"evidence_unavailable": True},
        }
    if not results:
        # A missing object makes the vision call fail closed, so the default path is safe.
        logger.info("No join match in view, using default URI: %s", default_uri)
        return {
            "gcs_uri": default_uri,
            "security_flags": {"evidence_unavailable": False},
        }
    return {
        "gcs_uri": results[0].gcs_uri,
        "security_flags": {"evidence_unavailable": False},
    }


def generate_signed_url(gcs_uri: str) -> dict[str, Any]:
    """
    Generates a secure signed URL for a GCS object to allow authorized human SOC viewing.
    Only objects inside SCREENSHOTS_BUCKET (with no path traversal) may be signed.
    Returns {"signed_url": ...}, or {"error": ...} if signing fails or the URI is invalid,
    so a signing failure never produces a misleading success result or unauthenticated link.
    """
    if not _is_allowed_screenshot_uri(gcs_uri):
        return {
            "error": (
                f"Invalid GCS URI provided: {gcs_uri!r}. "
                f"Only objects in gs://{SCREENSHOTS_BUCKET}/ are permitted."
            )
        }

    try:
        source_credentials, _ = google.auth.default()
        try:
            target_credentials = impersonated_credentials.Credentials(
                source_credentials=source_credentials,
                target_principal=GCS_SIGNER_SERVICE_ACCOUNT,
                target_scopes=["https://www.googleapis.com/auth/devstorage.read_only"],
                lifetime=300,
            )
            storage_client = storage.Client(credentials=target_credentials)
        except Exception as imp_err:
            logger.error(
                "Impersonation of signer SA (%s) failed: %s",
                GCS_SIGNER_SERVICE_ACCOUNT,
                imp_err,
            )
            return {
                "error": f"Failed to obtain impersonated signing credentials for {GCS_SIGNER_SERVICE_ACCOUNT}: {imp_err}"
            }

        bucket_name, object_name = gcs_uri.replace("gs://", "").split("/", 1)
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(object_name)

        url = blob.generate_signed_url(
            version="v4",
            expiration=timedelta(minutes=30),
            service_account_email=GCS_SIGNER_SERVICE_ACCOUNT,
        )
        return {"signed_url": url}
    except Exception as e:
        logger.error(
            "Could not generate impersonated signed URL for %s: %s", gcs_uri, e
        )
        return {"error": f"Failed to generate signed URL: {e}"}


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
        agent_reason=agent_reason,
        screenshot_url=screenshot_url or None,
        structured_report=structured_report,
        mitre_tactics=_clean_list(mitre_tactics),
        indicators_of_compromise=iocs,
    )

    res = get_soc_service().create_and_dispatch_ticket(ticket)
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
            agent_reason=agent_comment,
            structured_report=(
                "### Closed as False Positive by the agent\n"
                "No analyst has reviewed this closure.\n\n"
                f"**Agent rationale:** {agent_comment}"
            ),
        )
        get_soc_service().record_auto_closed_false_positive(ticket)
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
        agent_reason=agent_reason_for_escalation,
        screenshot_url=screenshot_url,
        structured_report=context_data,
    )
    result = get_soc_service().create_and_dispatch_ticket(ticket)
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
        structured_report=structured_report,
    )
    get_soc_service().create_and_dispatch_ticket(ticket)
    logger.warning("Default-deny escalation filed ticket %s", ticket_id)
    return {
        "status": "ESCALATED",
        "ticket_id": ticket_id,
        "security_flags": {"escalation_dispatched": True},
    }
