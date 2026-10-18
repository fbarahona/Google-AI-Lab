"""
Tools for the Cymbal Cyber ADK Multi-Agent Framework.
Includes BigQuery queries, GCS signed URLs, multimodal visual analysis with Gemini,
and SOC ticketing dispatch.

Every tool returns a dict with the same shape whether it runs in the MCP server or
in-process: a result field (or "error") plus "security_flags" for the flags the
agent's security gate reads. When a ToolContext is passed, the same flags are also
written to session state.

Modules, by the data each one touches:
- clients: configuration, cloud clients, session-state helper
- sql_guard: SQL-injection and dataset-sandbox controls
- ticket_ids: deterministic ticket IDs, severity
- behavior: behavioral profiles (BigQuery, or local logs in LOCAL_MODE)
- visual: screenshot evidence, prompt-injection scan, signed URLs
- ticketing: dispatch, escalation, false-positive closure, default-deny

This package re-exports every name, so `from adk_agent import tools` and
`tools.<name>` work as they did when this was one module. To fake a cloud client in
a test, patch it on adk_agent.tools.clients, where the tools look it up.
"""

from adk_agent.settings import DATASET_ID, MODEL_NAME, PROJECT_ID, REPO_ROOT
from adk_agent.tools.behavior import (
    _compute_profile_from_local_logs,
    _read_jsonl,
    build_event_logs_query,
    get_entity_behavioral_profile,
    local_logs_dir,
)
from adk_agent.tools.clients import (
    AGENT_SERVICE_ACCOUNT_NAME,
    BIGQUERY_ADK_THREAT_ASSESSMENT,
    GCS_ESCALATION_BUCKET,
    GCS_SIGNER_SERVICE_ACCOUNT,
    LOCATION,
    SCREENSHOTS_BUCKET,
    SEVERITIES,
    _clean_list,
    _set_state,
    get_bq_client,
    get_genai_client,
    get_soc_service,
)
from adk_agent.tools.sql_guard import (
    ALLOWED_ENTITY_TYPES,
    ALLOWED_INTERVAL_WINDOWS,
    DEFAULT_MAX_BYTES_BILLED,
    DESTRUCTIVE_SQL_TOKENS,
    ENTITY_SAFE_PATTERN,
    ENTITY_TYPE_ALIASES,
    SQL_INJECTION_DANGEROUS_PATTERNS,
    normalize_entity_type,
    sanitize_entity_value,
    validate_dataset_sandboxing,
    validate_safe_sql_query,
)
from adk_agent.tools.ticket_ids import (
    _clean_ticket_user,
    alert_id_from_payload,
    create_rich_ticket_id,
    normalize_severity,
    ticket_id_for_alert,
)
from adk_agent.tools.ticketing import (
    _parse_alert_payload_to_row,
    auto_escalate_unresolved_alert,
    dispatch_to_soc_ticketing_system,
    escalate_to_human,
    log_false_positive,
)
from adk_agent.tools.visual import (
    _is_allowed_screenshot_uri,
    _visual_evidence_unavailable,
    generate_signed_url,
    get_gcs_uri_for_user,
    get_visual_analysis_for_user,
    read_png_text_chunks,
)

__all__ = [
    "AGENT_SERVICE_ACCOUNT_NAME",
    "ALLOWED_ENTITY_TYPES",
    "ALLOWED_INTERVAL_WINDOWS",
    "BIGQUERY_ADK_THREAT_ASSESSMENT",
    "DATASET_ID",
    "DEFAULT_MAX_BYTES_BILLED",
    "DESTRUCTIVE_SQL_TOKENS",
    "ENTITY_SAFE_PATTERN",
    "ENTITY_TYPE_ALIASES",
    "GCS_ESCALATION_BUCKET",
    "GCS_SIGNER_SERVICE_ACCOUNT",
    "LOCATION",
    "MODEL_NAME",
    "PROJECT_ID",
    "REPO_ROOT",
    "SCREENSHOTS_BUCKET",
    "SEVERITIES",
    "SQL_INJECTION_DANGEROUS_PATTERNS",
    "_clean_list",
    "_clean_ticket_user",
    "_compute_profile_from_local_logs",
    "_is_allowed_screenshot_uri",
    "_parse_alert_payload_to_row",
    "_read_jsonl",
    "_set_state",
    "_visual_evidence_unavailable",
    "alert_id_from_payload",
    "auto_escalate_unresolved_alert",
    "build_event_logs_query",
    "create_rich_ticket_id",
    "dispatch_to_soc_ticketing_system",
    "escalate_to_human",
    "generate_signed_url",
    "get_bq_client",
    "get_entity_behavioral_profile",
    "get_gcs_uri_for_user",
    "get_genai_client",
    "get_soc_service",
    "get_visual_analysis_for_user",
    "local_logs_dir",
    "log_false_positive",
    "normalize_entity_type",
    "normalize_severity",
    "read_png_text_chunks",
    "sanitize_entity_value",
    "ticket_id_for_alert",
    "validate_dataset_sandboxing",
    "validate_safe_sql_query",
]
