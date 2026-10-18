"""
Screenshot evidence: URI resolution, multimodal analysis with the deterministic
prompt-injection scan, and signed URLs for the analyst.

The URI is model-chosen, so in the cloud only objects in SCREENSHOTS_BUCKET are
accepted, and every failure fails closed as evidence unavailable.
"""

import logging
import os
from datetime import timedelta
from typing import Any

import google.auth
from google.adk.tools import ToolContext
from google.auth import impersonated_credentials
from google.cloud import storage
from google.genai import types

from adk_agent import detection_rules as rules
from adk_agent.privacy_guard import mask_pii
from adk_agent.settings import DATASET_ID, MODEL_NAME, PROJECT_ID, REPO_ROOT
from adk_agent.tools import clients
from adk_agent.tools.clients import (
    GCS_SIGNER_SERVICE_ACCOUNT,
    SCREENSHOTS_BUCKET,
    _set_state,
)
from adk_agent.tools.sql_guard import (
    DEFAULT_MAX_BYTES_BILLED,
    sanitize_entity_value,
    validate_safe_sql_query,
)

logger = logging.getLogger(__name__)


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
            client = clients.get_genai_client()
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

    # Deterministic prompt injection scan on the raw text, before masking can alter it;
    # it does not depend on the model noticing.
    is_injection = rules.contains_prompt_injection(visual_text)

    # Mask third-party personal data captured from desktop backgrounds or open windows
    visual_text = mask_pii(visual_text)
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
        bq = clients.get_bq_client()
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
