"""
Tools for the Cymbal Cyber ADK Multi-Agent Framework.
Includes BigQuery queries, GCS signed URLs, multimodal visual analysis with Gemini,
and SOC ticketing dispatch.
"""

import os
import json
import time
import re
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

import google.auth
from google.auth import impersonated_credentials
from google.cloud import bigquery, storage
from google import genai
from google.genai import types
from google.adk.tools import ToolContext

# Integrations fallback
try:
    from google.adk.integrations.bigquery.bigquery_toolset import BigQueryToolset
except ImportError:
    from google.adk.tools.bigquery import BigQueryToolset

try:
    from ..soc_ticketing.models import SocTicket
    from ..soc_ticketing.ticketing_service import SocTicketingService
except (ImportError, ValueError):
    try:
        from soc_ticketing.models import SocTicket
        from soc_ticketing.ticketing_service import SocTicketingService
    except ImportError:
        from src.demo.soc_ticketing.models import SocTicket
        from src.demo.soc_ticketing.ticketing_service import SocTicketingService

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Project configuration
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "local-demo")
LOCATION = os.getenv("GOOGLE_CLOUD_LOCATION", "us-east1")
DATASET_ID = os.getenv("BIGQUERY_DATASET", "Cymbal_Cyber")
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
BIGQUERY_ADK_THREAT_ASSESSMENT = f"{PROJECT_ID}.{DATASET_ID}.adk_threat_assessment"
GCS_ESCALATION_BUCKET = os.getenv(
    "ESCALATION_BUCKET",
    f"cymbal-cyber-adk-escalations-bucket_{PROJECT_ID}"
)
GCS_SIGNER_SERVICE_ACCOUNT = os.getenv(
    "GCS_SIGNER_SA",
    f"bq-continuous-query-sa@{PROJECT_ID}.iam.gserviceaccount.com"
)

# Initialize GenAI Client
_genai_client = None


def get_genai_client():
    global _genai_client
    if _genai_client is None:
        _genai_client = genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)
    return _genai_client


# Initialize BigQuery Client
_bq_client = None


def get_bq_client():
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
            escalation_bucket=GCS_ESCALATION_BUCKET
        )
    return _soc_service


bigquery_toolset = BigQueryToolset()


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
        "human_reason": None
    }
    try:
        data = json.loads(alert_payload_str) if isinstance(alert_payload_str, str) else alert_payload_str
        row["user_id"] = data.get("user") or data.get("user_id")
        row["device_id"] = data.get("device") or data.get("device_id")
        row["source_ip"] = data.get("ip_address") or data.get("source_ip")
        row["total_2_min_threat_score"] = data.get("threat_score") or data.get("total_2_min_threat_score")
        row["transaction_window_end"] = data.get("window_end") or data.get("transaction_window_end")
    except Exception as e:
        logger.warning("Error parsing alert payload: %s", e)
    return row


# --- Security & SQL Injection Prevention ---
ALLOWED_ENTITY_TYPES = {"user", "user_id", "device", "device_id", "ip", "source_ip"}
ALLOWED_INTERVAL_WINDOWS = {"1 HOUR", "2 HOUR", "6 HOUR", "12 HOUR", "24 HOUR", "48 HOUR", "7 DAY", "30 DAY"}

ENTITY_SAFE_PATTERN = re.compile(r"^[a-zA-Z0-9\._\-:@]+$")
SQL_INJECTION_DANGEROUS_PATTERNS = [
    re.compile(r"['\";\\]"),
    re.compile(r"--"),
    re.compile(r"/\*|\*/"),
    re.compile(r"\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|EXEC|EXECUTE)\b", re.IGNORECASE),
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


def create_rich_ticket_id(user_id: str) -> str:
    """
    Generates a standardized, readable ticket ID.
    Sanitizes user_id to prevent JSON object bleed.
    """
    if not user_id:
        clean_user = "unknown_user"
    else:
        try:
            clean_user = sanitize_entity_value(user_id, field_name="user_id")
        except ValueError:
            match = re.match(r"^[a-zA-Z0-9\._-]+", str(user_id))
            clean_user = match.group(0) if match else "invalid_id"

    timestamp = int(time.time())
    return f"SOC-TICKET-{clean_user}-{timestamp}"


def build_event_logs_query(
    entity_type: str,
    entity_id: str,
    window_to_investigate: str = "24 HOUR"
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
    if not entity_type or not isinstance(entity_type, str):
        raise ValueError("entity_type must be a non-empty string.")

    clean_type = entity_type.strip().lower()
    if clean_type not in ALLOWED_ENTITY_TYPES:
        raise ValueError(
            f"Invalid entity_type '{entity_type}'. Must be one of {sorted(ALLOWED_ENTITY_TYPES)}."
        )

    clean_id = sanitize_entity_value(entity_id, field_name="entity_id")

    clean_window = (window_to_investigate or "24 HOUR").strip().upper()
    if clean_window not in ALLOWED_INTERVAL_WINDOWS:
        raise ValueError(
            f"Invalid window '{window_to_investigate}'. Must be one of {sorted(ALLOWED_INTERVAL_WINDOWS)}."
        )

    logger.info("Building %s parameterized SQL threat profile for %s: %s", clean_window, clean_type, clean_id)

    if clean_type in {"device", "device_id"}:
        access_filter = "device_id = @entity_id"
        network_filter = "device_id = @entity_id"
    elif clean_type in {"ip", "source_ip"}:
        access_filter = "source_ip = @entity_id"
        network_filter = "source_ip = @entity_id"
    else:
        access_filter = "user_id = @entity_id"
        network_filter = "(user_id = @entity_id OR source_ip IN (SELECT assigned_internal_ip FROM FlaggedSessions))"

    query_sql = rf"""
    WITH
    FlaggedSessions AS (
        SELECT DISTINCT assigned_internal_ip
        FROM `{DATASET_ID}.user_access_events`
        WHERE event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {clean_window})
          AND event_type = 'login_success'
          AND {access_filter}
    ),
    AccessMetrics AS (
        SELECT
          COUNT(*) AS total_access_events_24h,
          COUNTIF(event_type = 'login_failure') AS total_login_failures_24h,
          COUNT(DISTINCT source_ip) AS distinct_public_source_ips_24h,
          COUNTIF(REGEXP_CONTAINS(user_agent, r'^(python-requests|curl|Go-http-client)')) AS suspicious_user_agent_logins_24h,
          COUNT(DISTINCT user_agent) AS distinct_user_agents_used_24h
        FROM `{DATASET_ID}.user_access_events`
        WHERE event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {clean_window})
          AND {access_filter}
    ),
    NetworkMetrics AS (
        SELECT
          COUNT(*) AS total_network_events_24h,
          COUNTIF(permission_level_requested IN ('root', 'admin')) AS high_privilege_requests_24h,
          COUNTIF(file_type IN ('exe', 'dll', 'ps1', 'bat', 'vbs')) AS risky_file_transfers_24h,
          COUNTIF(REGEXP_CONTAINS(command_line, r'(?i)(powershell -enc|IEX|DownloadString|mimikatz|payload)')) AS malicious_commands_24h,
          COUNTIF(REGEXP_CONTAINS(network_domain, r'(\.ru|\.xyz|\.org|bad-domain|payload-downloader|c2-server)')) AS malicious_dns_queries_24h,
          COUNT(DISTINCT destination_ip) AS distinct_destination_ips_24h,
          COUNT(DISTINCT file_hash_sha256) AS distinct_files_transferred_24h
        FROM `{DATASET_ID}.network_events`
        WHERE event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {clean_window})
          AND {network_filter}
    )
    SELECT *
    FROM AccessMetrics
    CROSS JOIN NetworkMetrics;
    """

    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("entity_id", "STRING", clean_id)
        ]
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


def _compute_profile_from_local_logs(entity_type: str, entity_id: str) -> dict[str, Any]:
    """Computes exact behavioral profile metrics dynamically from local synthetic log files."""
    logs_dir = os.path.join(os.getcwd(), "local_demo_data", "logs")
    access_file = os.path.join(logs_dir, "user_access_events.jsonl")
    network_file = os.path.join(logs_dir, "network_events.jsonl")

    total_access = 0
    login_failures = 0
    source_ips = set()
    suspicious_ua = 0
    user_agents = set()

    total_network = 0
    high_priv = 0
    risky_files = 0
    mal_cmds = 0
    mal_dns = 0
    dest_ips = set()
    files_transferred = set()

    clean_id = (entity_id or "").strip().lower()

    if os.path.exists(access_file):
        try:
            with open(access_file, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    ev = json.loads(line)
                    ev_user = str(ev.get("user_id") or "").lower()
                    ev_dev = str(ev.get("device_id") or "").lower()
                    ev_ip = str(ev.get("source_ip") or "").lower()

                    matches = (
                        (entity_type == "user" and ev_user == clean_id) or
                        (entity_type == "device" and ev_dev == clean_id) or
                        (entity_type == "ip" and ev_ip == clean_id)
                    )
                    if matches:
                        total_access += 1
                        if ev.get("event_type") == "login_failure":
                            login_failures += 1
                        if ev.get("source_ip"):
                            source_ips.add(ev["source_ip"])
                        ua = str(ev.get("user_agent") or "")
                        if ua:
                            user_agents.add(ua)
                            if re.search(r"^(python-requests|curl|Go-http-client)", ua, re.IGNORECASE):
                                suspicious_ua += 1
        except Exception as e:
            logger.warning("Error reading local access logs: %s", e)

    if os.path.exists(network_file):
        try:
            with open(network_file, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    ev = json.loads(line)
                    ev_user = str(ev.get("user_id") or "").lower()
                    ev_ip = str(ev.get("source_ip") or "").lower()

                    matches = (
                        (entity_type == "user" and ev_user == clean_id) or
                        (entity_type == "ip" and ev_ip == clean_id)
                    )
                    if matches:
                        total_network += 1
                        if ev.get("permission_level_requested") in ("root", "admin"):
                            high_priv += 1
                        ft = str(ev.get("file_type") or "").lower()
                        if ft in ("exe", "dll", "ps1", "bat", "vbs"):
                            risky_files += 1
                        cmd = str(ev.get("command_line") or "")
                        if re.search(r"(?i)(powershell -enc|IEX|DownloadString|mimikatz|payload)", cmd):
                            mal_cmds += 1
                        domain = str(ev.get("network_domain") or "")
                        if re.search(r"(\.ru|\.xyz|bad-domain|payload-downloader|c2-server)", domain):
                            mal_dns += 1
                        if ev.get("destination_ip"):
                            dest_ips.add(ev["destination_ip"])
                        fh = ev.get("file_hash_sha256")
                        if fh:
                            files_transferred.add(fh)
        except Exception as e:
            logger.warning("Error reading local network logs: %s", e)

    return {
        "total_access_events_24h": total_access,
        "total_login_failures_24h": login_failures,
        "distinct_public_source_ips_24h": len(source_ips),
        "suspicious_user_agent_logins_24h": suspicious_ua,
        "distinct_user_agents_used_24h": len(user_agents),
        "total_network_events_24h": total_network,
        "high_privilege_requests_24h": high_priv,
        "risky_file_transfers_24h": risky_files,
        "malicious_commands_24h": mal_cmds,
        "malicious_dns_queries_24h": mal_dns,
        "distinct_destination_ips_24h": len(dest_ips),
        "distinct_files_transferred_24h": len(files_transferred)
    }


def get_entity_behavioral_profile(
    entity_type: str,
    entity_id: str,
    window_to_investigate: str = "24 HOUR",
    tool_context: Optional[ToolContext] = None
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
    sql, job_config = build_event_logs_query(entity_type, entity_id, window_to_investigate)
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
                    "distinct_files_transferred_24h": 0
                }
        except Exception as e:
            logger.error("BigQuery query failed for %s (%s). Failing closed with evidence_unavailable.", entity_id, e)
            if tool_context and hasattr(tool_context, "state") and tool_context.state is not None:
                tool_context.state["evidence_unavailable"] = True
            return {
                "status": "ERROR",
                "error": f"BigQuery telemetry query failed: {e}",
                "message": (
                    "CRITICAL INFRASTRUCTURE FAILURE: BigQuery telemetry unavailable. "
                    "Evidence cannot be verified. Security policy prohibits closing alert as FALSE POSITIVE. "
                    "You MUST invoke escalate_to_human immediately."
                )
            }

    # Update state flag on malicious indicators to enforce deterministic security gate
    if (
        res.get("total_login_failures_24h", 0) > 5 or
        res.get("malicious_commands_24h", 0) > 0 or
        res.get("risky_file_transfers_24h", 0) > 0 or
        res.get("malicious_dns_queries_24h", 0) > 0
    ):
        logger.info("Setting state['malicious_indicators'] = True for entity: %s", entity_id)
        if tool_context and hasattr(tool_context, "state") and tool_context.state is not None:
            tool_context.state["malicious_indicators"] = True

    return res


def get_visual_analysis_for_user(gcs_uri: str, tool_context: Optional[ToolContext] = None) -> str:
    """
    Performs multimodal inspection of a desktop screenshot using Gemini.
    Performs OCR on terminals, identifies command prompts, and evaluates suspicious UI activity.
    Detects adversarial prompt injection attempts and sets state['prompt_injection_detected'].
    """
    if not gcs_uri or (not gcs_uri.startswith("gs://") and not gcs_uri.startswith("file://")):
        if tool_context and hasattr(tool_context, "state") and tool_context.state is not None:
            tool_context.state["evidence_unavailable"] = True
        return f"Cannot perform visual analysis. Invalid or missing GCS URI: {gcs_uri}. Visual evidence unavailable."

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
    is_local_mode = os.getenv("LOCAL_MODE", "false").lower() == "true"

    if is_local_mode or "file://" in gcs_uri:
        # Local forensic inspection: Extract OCR metadata from local screenshot file
        filename = gcs_uri.split("/")[-1].replace(".png", "")
        local_path = os.path.join(os.getcwd(), "src", "demo", "user_screenshots", f"{filename}.png")
        ocr_chunks = read_png_text_chunks(local_path)
        if "forensic_ocr_text" in ocr_chunks:
            visual_text = f"Forensic Desktop OCR Output:\n{ocr_chunks['forensic_ocr_text']}"
        else:
            visual_text = f"Forensic inspection of desktop {filename}.png: Workspace shows standard developer console. No malicious tools."
    else:
        try:
            client = get_genai_client()
            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=[
                    types.Part.from_uri(file_uri=gcs_uri, mime_type="image/png"),
                    types.Part.from_text(text=prompt_text)
                ]
            )
            visual_text = (response.text or "").strip()
        except Exception as e:
            logger.error("Error during multimodal visual analysis for %s: %s", gcs_uri, e)
            if tool_context and hasattr(tool_context, "state") and tool_context.state is not None:
                tool_context.state["evidence_unavailable"] = True
            return f"Error: Multimodal visual analysis service unavailable for {gcs_uri}: {e}. Visual evidence unavailable."

    # Deterministic Prompt Injection Keyword Scanner
    INJECTION_KEYWORDS = [
        "ai triage", "classify as", "instruction override", "system notice to ai",
        "override instruction", "authorized red team", "authorized pentest",
        "suppress all critical", "do not dispatch", "do not alert"
    ]
    if any(kw in visual_text.lower() for kw in INJECTION_KEYWORDS):
        logger.warning("PROMPT INJECTION DETECTED in visual evidence for %s", gcs_uri)
        if tool_context and hasattr(tool_context, "state") and tool_context.state is not None:
            tool_context.state["prompt_injection_detected"] = True
        visual_text = f"[SECURITY ALERT: PROMPT INJECTION DETECTED IN DESKTOP SCREENSHOT]\n{visual_text}"

    return visual_text


def get_gcs_uri_for_user(user: str) -> str:
    """
    Queries BigQuery user_screenshots_view to retrieve the GCS URI of the user's desktop screenshot.
    Uses parameterized query and strict sanitization to prevent SQL injection.
    """
    logger.info("Searching for screenshot GCS URI for user: %s", user)
    clean_user = sanitize_entity_value(user, field_name="user")
    sql = f"""
        SELECT t2.gcs_uri
        FROM `{PROJECT_ID}.{DATASET_ID}.user_access_events` AS t1
        JOIN `{PROJECT_ID}.{DATASET_ID}.user_screenshots_view` AS t2 ON t1.user_id = t2.user_id
        WHERE t1.user_id = @user_id
        LIMIT 1;
    """
    try:
        from google.cloud import bigquery
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("user_id", "STRING", clean_user)
            ]
        )
        bq = get_bq_client()
        results = list(bq.query(sql, job_config=job_config).result())
        if not results:
            fallback_uri = f"gs://cymbal-cyber-screenshots_{PROJECT_ID}/{clean_user}.png"
            logger.info("No join match in view, using default URI: %s", fallback_uri)
            return fallback_uri
        return results[0].gcs_uri
    except Exception as e:
        logger.error("Error querying GCS URI: %s", e)
        return f"gs://cymbal-cyber-screenshots_{PROJECT_ID}/{clean_user}.png"


def generate_signed_url(gcs_uri: str) -> str:
    """
    Generates a secure signed URL for a GCS object to allow authorized human SOC viewing.
    Returns an explicit error message if signing fails or the URI is invalid, ensuring
    that a signing failure never produces a misleading success result or unauthenticated link.
    """
    if not gcs_uri or not gcs_uri.startswith("gs://"):
        return f"Error: Invalid GCS URI provided: {gcs_uri!r}"

    try:
        source_credentials, _ = google.auth.default()
        try:
            target_credentials = impersonated_credentials.Credentials(
                source_credentials=source_credentials,
                target_principal=GCS_SIGNER_SERVICE_ACCOUNT,
                target_scopes=["https://www.googleapis.com/auth/devstorage.read_only"],
                lifetime=300
            )
            storage_client = storage.Client(credentials=target_credentials)
        except Exception as imp_err:
            logger.error("Impersonation of signer SA (%s) failed: %s", GCS_SIGNER_SERVICE_ACCOUNT, imp_err)
            return f"Error: Failed to obtain impersonated signing credentials for {GCS_SIGNER_SERVICE_ACCOUNT}: {imp_err}"

        bucket_name, object_name = gcs_uri.replace("gs://", "").split("/", 1)
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(object_name)

        return blob.generate_signed_url(
            version="v4",
            expiration=timedelta(minutes=30),
            service_account_email=GCS_SIGNER_SERVICE_ACCOUNT
        )
    except Exception as e:
        logger.error("Could not generate impersonated signed URL for %s: %s", gcs_uri, e)
        return f"Error: Failed to generate signed URL: {e}"


def dispatch_to_soc_ticketing_system(
    ticket_id: str,
    alert_payload: str,
    agent_reason: str,
    structured_report: str,
    severity: str = "HIGH",
    screenshot_url: str = "",
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Passes a confirmed or suspected threat incident ticket directly to the SOC Ticketing System.
    Stores the ticket in BigQuery and the GCS escalation queue for SOC analysts to review.
    """
    row = _parse_alert_payload_to_row(alert_payload)
    user_id = row.get("user_id") or "unknown_user"
    device_id = row.get("device_id") or "unknown_device"
    source_ip = row.get("source_ip") or "unknown_ip"
    threat_score = row.get("total_2_min_threat_score") or 100

    ticket = SocTicket(
        ticket_id=ticket_id,
        user_id=user_id,
        device_id=device_id,
        source_ip=source_ip,
        threat_score=threat_score,
        severity=severity.upper() if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "HIGH",
        status="ESCALATED",
        agent_decision="PERCEIVED_THREAT",
        agent_reason=agent_reason,
        screenshot_url=screenshot_url or None,
        structured_report=structured_report,
        mitre_tactics=["Initial Access", "Command and Control", "Privilege Escalation"],
        indicators_of_compromise=[source_ip]
    )

    soc_service = get_soc_service()
    res = soc_service.create_and_dispatch_ticket(ticket)
    if tool_context and hasattr(tool_context, "state") and tool_context.state is not None:
        tool_context.state["ticket_dispatched"] = True
    return res


def log_false_positive(
    alert_payload: str,
    agent_comment: str,
    tool_context: Optional[ToolContext] = None
) -> str:
    """Logs the alert as an autonomously resolved False Positive in BigQuery."""
    logger.info("Logging false positive: %s", agent_comment)
    try:
        row_data = _parse_alert_payload_to_row(alert_payload)
        row_data["agent_decision"] = "FALSE_POSITIVE"
        row_data["agent_reason"] = agent_comment
        row_data["human_decision"] = None
        row_data["human_reason"] = None

        bq = get_bq_client()
        errors = bq.insert_rows_json(BIGQUERY_ADK_THREAT_ASSESSMENT, [row_data])
        if errors:
            logger.error("Failed to insert false positive to BigQuery: %s", errors)
            if tool_context and hasattr(tool_context, "state") and tool_context.state is not None:
                tool_context.state["evidence_unavailable"] = True
            return f"Failed to log false positive in BigQuery. Errors: {errors}"

        if tool_context and hasattr(tool_context, "state") and tool_context.state is not None:
            tool_context.state["false_positive_logged"] = True
        return "Successfully logged alert as a False Positive in BigQuery."
    except Exception as e:
        logger.error("Exception during false positive logging: %s", e)
        if tool_context and hasattr(tool_context, "state") and tool_context.state is not None:
            tool_context.state["evidence_unavailable"] = True
        return f"Error logging false positive: {e}"


def escalate_to_human(
    ticket_id: str,
    alert_payload: str,
    agent_reason_for_escalation: str,
    context_data: str,
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Dispatches the incident ticket to the SOC ticketing queue for human analyst adjudication.
    Returns immediately with escalation confirmation without blocking the agent runner.
    """
    soc_service = get_soc_service()
    row = _parse_alert_payload_to_row(alert_payload)

    ticket = SocTicket(
        ticket_id=ticket_id,
        user_id=row.get("user_id") or "unknown_user",
        device_id=row.get("device_id") or "unknown_device",
        source_ip=row.get("source_ip") or "unknown_ip",
        threat_score=row.get("total_2_min_threat_score") or 100,
        severity="HIGH",
        status="ESCALATED",
        agent_decision="PERCEIVED_THREAT",
        agent_reason=agent_reason_for_escalation,
        structured_report=context_data
    )
    result = soc_service.create_and_dispatch_ticket(ticket)
    if tool_context and hasattr(tool_context, "state") and tool_context.state is not None:
        tool_context.state["escalation_dispatched"] = True
    logger.info("Escalated ticket %s to human analyst: %s", ticket_id, agent_reason_for_escalation)
    return (
        f"Incident successfully escalated to Human SOC Analyst: Ticket ID '{ticket_id}'. "
        f"Status: ESCALATED_PENDING_REVIEW. Queue Result: {result}"
    )

