# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import base64
import contextlib
import json
import logging
import os
import time
from collections import OrderedDict
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from a2a.server.tasks import InMemoryTaskStore
from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from google.adk.cli.fast_api import get_fast_api_app
from google.adk.runners import Runner
from google.genai import types

from adk_agent.app_utils import services
from adk_agent.app_utils.a2a import attach_a2a_routes

logger = logging.getLogger("CymbalCyberADK.Webhook")

load_dotenv()
allow_origins = (
    os.getenv("ALLOW_ORIGINS", "").split(",") if os.getenv("ALLOW_ORIGINS") else None
)


def _should_enable_cloud_telemetry() -> bool:
    """Disables Cloud Trace exporter in local mode or CI environments lacking GCP ADC."""
    if os.getenv("LOCAL_MODE", "false").lower() in ("true", "1"):
        return False
    if os.getenv("OTEL_TO_CLOUD", "").lower() in ("false", "0"):
        return False
    try:
        import google.auth
        google.auth.default()
        return True
    except Exception:
        return False


otel_to_cloud = _should_enable_cloud_telemetry()

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    from adk_agent.agent import app as adk_app
    from adk_agent.agent import root_agent

    runner = Runner(
        app=adk_app,
        session_service=services.get_session_service(),
        artifact_service=services.get_artifact_service(),
        auto_create_session=True,
    )
    app.state.runner = runner
    app.state.agent_app_name = adk_app.name
    await attach_a2a_routes(
        app,
        agent=root_agent,
        runner=runner,
        task_store=InMemoryTaskStore(),
        rpc_path=f"/a2a/{adk_app.name}",
    )
    yield


app: FastAPI = get_fast_api_app(
    agents_dir=AGENT_DIR,
    web=True,
    artifact_service_uri=services.ARTIFACT_SERVICE_URI,
    allow_origins=allow_origins,
    session_service_uri=services.SESSION_SERVICE_URI,
    otel_to_cloud=otel_to_cloud,
    lifespan=lifespan,
)
app.title = "google"
app.description = "API for interacting with the Agent google"


def extract_pubsub_payload(raw_body: Any) -> dict[str, Any]:
    """
    Decodes and extracts the alert payload from incoming Pub/Sub push requests.
    Handles:
    - Standard wrapped Pub/Sub envelope: {"message": {"data": "<base64>", "attributes": ...}}
    - Raw/unwrapped JSON payloads (Pub/Sub no_wrapper configuration)
    - Raw strings and byte payloads
    Raises ValueError if payload contains invalid or non-JSON binary data.
    """
    if isinstance(raw_body, bytes):
        try:
            raw_body = json.loads(raw_body.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"Malformed request body: payload is not valid JSON ({exc})") from exc
    elif isinstance(raw_body, str):
        try:
            raw_body = json.loads(raw_body)
        except Exception as exc:
            raise ValueError(f"Malformed request body: payload is not valid JSON ({exc})") from exc

    if not isinstance(raw_body, dict):
        raise ValueError("Malformed request body: root must be a JSON object")

    # Wrapped Pub/Sub push message
    if "message" in raw_body and isinstance(raw_body["message"], dict):
        msg = raw_body["message"]
        data = msg.get("data")
        payload = {}
        if data:
            try:
                decoded_bytes = base64.b64decode(data)
                decoded_text = decoded_bytes.decode("utf-8")
                payload = json.loads(decoded_text)
            except Exception as exc:
                raise ValueError(f"Malformed Pub/Sub message data: payload is not valid JSON ({exc})") from exc
        if not isinstance(payload, dict):
            raise ValueError("Malformed Pub/Sub message data: inner JSON must be an object")
        attrs = msg.get("attributes")
        if isinstance(attrs, dict):
            for k, v in attrs.items():
                if k not in payload:
                    payload[k] = v
        return payload

    return raw_body


MAX_DEDUP_CACHE_SIZE = int(os.getenv("MAX_DEDUP_CACHE_SIZE", "1000"))
_IN_PROGRESS_MESSAGES: OrderedDict[str, float] = OrderedDict()
_COMPLETED_MESSAGES: OrderedDict[str, float] = OrderedDict()
_DEDUP_TTL_SECONDS = 900.0  # 15 minutes deduplication window


def _cleanup_expired_messages():
    """Removes expired entries from memory dedup tables and enforces maximum capacity."""
    now = time.time()
    for store in (_IN_PROGRESS_MESSAGES, _COMPLETED_MESSAGES):
        expired = [k for k, ts in store.items() if now - ts > _DEDUP_TTL_SECONDS]
        for k in expired:
            store.pop(k, None)
        while len(store) > MAX_DEDUP_CACHE_SIZE:
            store.popitem(last=False)


def _record_completed_message(message_id: str):
    """Records completed message, evicting expired entries and enforcing capacity ceiling."""
    _cleanup_expired_messages()
    _COMPLETED_MESSAGES[message_id] = time.time()
    _COMPLETED_MESSAGES.move_to_end(message_id)
    while len(_COMPLETED_MESSAGES) > MAX_DEDUP_CACHE_SIZE:
        _COMPLETED_MESSAGES.popitem(last=False)


def _record_in_progress_message(message_id: str):
    """Records in-progress message, evicting expired entries and enforcing capacity ceiling."""
    _cleanup_expired_messages()
    _IN_PROGRESS_MESSAGES[message_id] = time.time()
    _IN_PROGRESS_MESSAGES.move_to_end(message_id)
    while len(_IN_PROGRESS_MESSAGES) > MAX_DEDUP_CACHE_SIZE:
        _IN_PROGRESS_MESSAGES.popitem(last=False)


def get_alert_status_info(alert_id: str) -> dict[str, Any] | None:
    """
    Checks BigQuery `alerts` table for the alert_id status.
    Returns dict with status, updated_at timestamp, or None if not found.
    """
    if os.getenv("LOCAL_MODE", "false").lower() == "true" or not alert_id:
        return None
    try:
        from google.cloud import bigquery

        from adk_agent.tools import DATASET_ID, PROJECT_ID, get_bq_client
        bq = get_bq_client()
        query = f"""
            SELECT status, updated_at
            FROM `{PROJECT_ID}.{DATASET_ID}.alerts`
            WHERE alert_id = @alert_id
            LIMIT 1
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("alert_id", "STRING", alert_id),
            ],
            maximum_bytes_billed=100 * 1024 * 1024,
        )
        rows = list(bq.query(query, job_config=job_config).result())
        if rows:
            return {"status": rows[0]["status"], "updated_at": rows[0]["updated_at"]}
        return None
    except Exception as e:
        logger.warning("Could not query alerts.status for alert_id %s: %s", alert_id, e)
        return None


def update_alert_status(
    alert_id: str,
    new_status: str,
    alert_data: dict[str, Any] | None = None,
):
    """
    Updates alerts.status to INVESTIGATING, DONE, or NEW with timestamp audit.
    If alert_data is provided, uses MERGE to ensure Continuous Query and Dataflow
    alerts are inserted into the alerts table if they do not already exist.
    """
    if os.getenv("LOCAL_MODE", "false").lower() == "true" or not alert_id:
        return
    try:
        from google.cloud import bigquery

        from adk_agent.tools import DATASET_ID, PROJECT_ID, get_bq_client
        bq = get_bq_client()

        if alert_data:
            user_id = alert_data.get("user_id") or (alert_id.split("|")[0] if "|" in alert_id else "unknown")
            engine = alert_data.get("engine") or "cq"
            device_id = alert_data.get("device_id") or "endpoint-unknown"
            source_ip = alert_data.get("source_ip") or "0.0.0.0"
            window_start = alert_data.get("window_start") or ""
            window_end = alert_data.get("window_end") or (alert_id.split("|")[1] if "|" in alert_id else "")
            threat_score = int(alert_data.get("total_2_min_threat_score") or alert_data.get("threat_score") or 0)
            high_priv = alert_data.get("high_privilege_request_count")
            malicious_cmd = alert_data.get("malicious_command_count")
            malicious_dns = alert_data.get("malicious_dns_count")
            payload_str = json.dumps(alert_data)

            query = f"""
                MERGE `{PROJECT_ID}.{DATASET_ID}.alerts` T
                USING (SELECT @alert_id AS alert_id) S
                ON T.alert_id = S.alert_id
                WHEN MATCHED THEN
                  UPDATE SET status = @new_status, updated_at = CURRENT_TIMESTAMP()
                WHEN NOT MATCHED THEN
                  INSERT (
                    alert_id, engine, user_id, device_id, source_ip,
                    window_start, window_end, total_2_min_threat_score,
                    high_privilege_request_count, malicious_command_count, malicious_dns_count,
                    status, detected_at, updated_at, payload
                  )
                  VALUES (
                    @alert_id, @engine, @user_id, @device_id, @source_ip,
                    COALESCE(SAFE.PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%E*SZ', @window_start), TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 2 MINUTE)),
                    COALESCE(SAFE.PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%E*SZ', @window_end), CURRENT_TIMESTAMP()),
                    @threat_score,
                    @high_priv_count, @malicious_cmd_count, @malicious_dns_count,
                    @new_status, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), PARSE_JSON(@payload)
                  )
            """
            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("new_status", "STRING", new_status),
                    bigquery.ScalarQueryParameter("alert_id", "STRING", alert_id),
                    bigquery.ScalarQueryParameter("engine", "STRING", engine),
                    bigquery.ScalarQueryParameter("user_id", "STRING", user_id),
                    bigquery.ScalarQueryParameter("device_id", "STRING", device_id),
                    bigquery.ScalarQueryParameter("source_ip", "STRING", source_ip),
                    bigquery.ScalarQueryParameter("window_start", "STRING", window_start),
                    bigquery.ScalarQueryParameter("window_end", "STRING", window_end),
                    bigquery.ScalarQueryParameter("threat_score", "INT64", threat_score),
                    bigquery.ScalarQueryParameter("high_priv_count", "INT64", high_priv),
                    bigquery.ScalarQueryParameter("malicious_cmd_count", "INT64", malicious_cmd),
                    bigquery.ScalarQueryParameter("malicious_dns_count", "INT64", malicious_dns),
                    bigquery.ScalarQueryParameter("payload", "STRING", payload_str),
                ],
                maximum_bytes_billed=100 * 1024 * 1024,
            )
        else:
            query = f"""
                UPDATE `{PROJECT_ID}.{DATASET_ID}.alerts`
                SET status = @new_status, updated_at = CURRENT_TIMESTAMP()
                WHERE alert_id = @alert_id
            """
            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("new_status", "STRING", new_status),
                    bigquery.ScalarQueryParameter("alert_id", "STRING", alert_id),
                ],
                maximum_bytes_billed=100 * 1024 * 1024,
            )
        bq.query(query, job_config=job_config).result()
        logger.info("Updated alert_id '%s' status to '%s' in BigQuery.", alert_id, new_status)
    except Exception as e:
        logger.warning("Could not update alerts.status for alert_id %s: %s", alert_id, e)


async def _run_agent_investigation(
    runner: Runner,
    app_name: str,
    user_id: str,
    session_id: str,
    prompt_text: str,
) -> str:
    """Runs autonomous multi-agent forensic investigation asynchronously."""
    session = await runner.session_service.get_session(
        app_name=app_name, user_id=user_id, session_id=session_id
    )
    if not session:
        session = await runner.session_service.create_session(
            app_name=app_name, user_id=user_id, session_id=session_id
        )

    content = types.Content(
        role="user",
        parts=[types.Part.from_text(text=prompt_text)],
    )

    outputs = []
    async for event in runner.run_async(
        user_id=user_id,
        session_id=session.id,
        new_message=content,
    ):
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    outputs.append(part.text)

    logger.info("Pub/Sub agent investigation completed for session %s", session_id)
    return "\n".join(outputs)


def verify_incoming_oidc_token(request: Request) -> dict[str, Any]:
    """
    Validates Google-issued OpenID Connect (OIDC) JWT bearer tokens for Pub/Sub push
    and Cloud Scheduler endpoints to guarantee caller identity authenticity.
    Bypassed in local simulation mode (LOCAL_MODE=true) or when authentication is disabled.
    """
    if os.getenv("LOCAL_MODE", "false").lower() in ("true", "1") or os.getenv("DISABLE_AUTH", "false").lower() in ("true", "1"):
        return {"email": "local-dev@internal", "local": True}

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or malformed Authorization header. Google OIDC bearer token required.",
        )

    token = auth_header.split(" ", 1)[1].strip()
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token

        claims = None
        expected_audience = os.getenv("EXPECTED_OIDC_AUDIENCE")
        if expected_audience:
            candidate_audiences = [expected_audience]
            clean_aud = expected_audience.replace("https://", "").replace("http://", "")
            if "/" in clean_aud:
                parts = expected_audience.split("/")
                root_uri = f"{parts[0]}//{parts[2]}"
                candidate_audiences.append(root_uri)
            else:
                candidate_audiences.append(f"{expected_audience.rstrip('/')}/apps/adk_agent/trigger/pubsub")
                candidate_audiences.append(f"{expected_audience.rstrip('/')}/trigger/pubsub")

            last_exc = None
            for aud in candidate_audiences:
                try:
                    claims = id_token.verify_oauth2_token(
                        token,
                        google_requests.Request(),
                        audience=aud,
                    )
                    break
                except Exception as e:
                    last_exc = e
            if not claims and last_exc:
                raise last_exc
        else:
            # Fallback: derive candidate audiences accounting for Cloud Run TLS termination / proxy headers
            host = request.headers.get("x-forwarded-host") or request.headers.get("host")
            proto = request.headers.get("x-forwarded-proto", "https")
            candidate_audiences = []
            if host:
                candidate_audiences.append(f"{proto}://{host}{request.url.path}")
                candidate_audiences.append(f"https://{host}{request.url.path}")
                candidate_audiences.append(f"{proto}://{host}")
                candidate_audiences.append(f"https://{host}")

            raw_url = str(request.url).split("?")[0]
            candidate_audiences.append(raw_url)
            if raw_url.startswith("http://"):
                candidate_audiences.append("https://" + raw_url[7:])

            last_exc = None
            for aud in candidate_audiences:
                try:
                    claims = id_token.verify_oauth2_token(
                        token,
                        google_requests.Request(),
                        audience=aud,
                    )
                    break
                except Exception as e:
                    last_exc = e

            if not claims:
                raise last_exc or ValueError("OIDC token verification failed for all candidate audiences.")

        # Verify caller email is verified by Google
        if not claims.get("email_verified"):
            logger.warning("Inbound OIDC JWT rejected: email_verified claim is not true.")
            raise HTTPException(
                status_code=403,
                detail="Invalid OIDC bearer token: caller email is not verified.",
            )

        # Verify caller email matches authorized invoker service account
        expected_invoker = os.getenv("EXPECTED_INVOKER_EMAIL")
        if not expected_invoker:
            proj = os.getenv("GOOGLE_CLOUD_PROJECT")
            invoker_id = os.getenv("INVOKER_SA_NAME", "pubsub-invoker-sa")
            if proj and proj not in ("local-demo", "test-proj"):
                expected_invoker = f"{invoker_id}@{proj}.iam.gserviceaccount.com"

        if expected_invoker:
            caller_email = claims.get("email")
            if caller_email != expected_invoker:
                logger.warning(
                    "Inbound OIDC JWT rejected: caller email '%s' does not match expected invoker '%s'.",
                    caller_email,
                    expected_invoker,
                )
                raise HTTPException(
                    status_code=403,
                    detail="Forbidden: caller service account is not authorized.",
                )

        return claims
    except Exception as exc:
        logger.warning("Inbound OIDC JWT validation failed: %s", exc)
        raise HTTPException(
            status_code=403,
            detail="Invalid OIDC bearer token.",
        ) from exc


@app.post("/apps/adk_agent/trigger/pubsub")
@app.post("/trigger/pubsub")
async def handle_pubsub_trigger(
    request: Request,
    background_tasks: BackgroundTasks,
    sync: bool = True,
    caller_claims: dict[str, Any] = Depends(verify_incoming_oidc_token),
):
    """
    Webhook receiving Pub/Sub push notifications for BigQuery Continuous Query security alerts.
    Unwraps base64 alert data, deduplicates at-least-once deliveries, tracks in-flight executions,
    and executes synchronously (default) so Cloud Run does not throttle CPU mid-investigation.
    """
    try:
        raw_body = await request.json()
    except Exception:
        body_bytes = await request.body()
        raw_body = body_bytes

    try:
        alert_data = extract_pubsub_payload(raw_body)
    except ValueError as err:
        logger.warning("Rejected malformed Pub/Sub payload: %s", err)
        raise HTTPException(
            status_code=400,
            detail="Malformed Pub/Sub payload",
        ) from err
    user_id = alert_data.get("user_id") or "pubsub-automator"
    session_id = f"pubsub-{user_id}-{int(time.time())}"
    prompt_text = f"Investigate incoming continuous security alert: {json.dumps(alert_data)}"

    # 1. Runner Readiness: Check first! If unready, return 503 so Pub/Sub retries without marking dedup
    runner: Runner = getattr(app.state, "runner", None)
    app_name: str = getattr(app.state, "agent_app_name", "adk_agent")

    if not runner:
        logger.warning("Runner not yet initialized in app.state; returning 503 to trigger Pub/Sub retry.")
        return JSONResponse(
            status_code=503,
            content={
                "status": "SERVICE_UNAVAILABLE",
                "message": "ADK Agent Runner is initializing; please retry.",
                "session_id": session_id,
            },
        )

    # 2. Extract alert_id contract attribute or construct from payload
    alert_id = None
    if isinstance(raw_body, dict):
        msg_obj = raw_body.get("message")
        if isinstance(msg_obj, dict):
            attrs = msg_obj.get("attributes") or {}
            alert_id = attrs.get("alert_id")
    if not alert_id:
        alert_id = alert_data.get("alert_id")
    if not alert_id:
        window_end = alert_data.get("window_end") or alert_data.get("transaction_window_end") or ""
        if window_end and user_id:
            alert_id = f"{user_id}|{window_end}"

    message_id = alert_id or request.headers.get("ce-id") or request.headers.get("x-goog-pubsub-message-id") or f"{user_id}-{int(time.time())}"

    # 3. Fast-path in-memory and durable BigQuery alerts.status checks
    _cleanup_expired_messages()

    if message_id in _COMPLETED_MESSAGES:
        logger.info("Duplicate Pub/Sub message already completed in-memory (%s); returning 200 DUPLICATE_ACK.", message_id)
        return JSONResponse(
            status_code=200,
            content={
                "status": "DUPLICATE_ACK",
                "message": "Alert previously completed.",
                "alert_id": alert_id,
            },
        )

    # Durable BigQuery alerts table status check
    if alert_id:
        status_info = await asyncio.to_thread(get_alert_status_info, alert_id)
        if status_info:
            current_status = status_info.get("status")
            updated_at = status_info.get("updated_at")

            # If already DONE: skip and ACK immediately
            if current_status == "DONE":
                logger.info("Alert '%s' is marked DONE in BigQuery alerts table; returning 200 DUPLICATE_ACK.", alert_id)
                _record_completed_message(message_id)
                return JSONResponse(
                    status_code=200,
                    content={
                        "status": "DUPLICATE_ACK",
                        "message": "Alert already investigated and completed.",
                        "alert_id": alert_id,
                    },
                )

            # If currently INVESTIGATING: check if fresh or timed out (>10 min)
            if current_status == "INVESTIGATING":
                is_stale = False
                if updated_at:
                    try:
                        if isinstance(updated_at, datetime):
                            elapsed = (datetime.now(UTC) - updated_at).total_seconds()
                        else:
                            elapsed = 0
                        if elapsed > 600:
                            is_stale = True
                    except Exception:
                        pass

                if not is_stale:
                    logger.warning("Alert '%s' currently INVESTIGATING in BigQuery (< 10 min ago); returning 409 to trigger Pub/Sub retry.", alert_id)
                    return JSONResponse(
                        status_code=409,
                        content={
                            "status": "IN_PROGRESS",
                            "message": "Investigation currently in progress; please retry.",
                            "alert_id": alert_id,
                        },
                    )
                else:
                    logger.warning("Alert '%s' was INVESTIGATING but timed out (> 10 min); re-attempting.", alert_id)

    if message_id in _IN_PROGRESS_MESSAGES:
        logger.warning("Pub/Sub message currently in-progress in-memory (%s); returning 409.", message_id)
        return JSONResponse(
            status_code=409,
            content={
                "status": "IN_PROGRESS",
                "message": "Investigation currently in progress; please retry.",
                "message_id": message_id,
            },
        )

    # Transition status to INVESTIGATING
    _record_in_progress_message(message_id)
    if alert_id:
        await asyncio.to_thread(update_alert_status, alert_id, "INVESTIGATING", alert_data)

    # 4. Synchronous Execution by Default (with guaranteed state cleanup in finally)
    try:
        output = await _run_agent_investigation(
            runner=runner,
            app_name=app_name,
            user_id=user_id,
            session_id=session_id,
            prompt_text=prompt_text,
        )

        # Mark as DONE on successful investigation
        if alert_id:
            await asyncio.to_thread(update_alert_status, alert_id, "DONE", alert_data)
        _record_completed_message(message_id)

        return JSONResponse(
            status_code=200,
            content={
                "status": "COMPLETED",
                "session_id": session_id,
                "alert_id": alert_id,
                "output": output,
            },
        )
    except Exception as exc:
        logger.error("Pub/Sub agent investigation failed for session %s: %s", session_id, exc)
        # On failure: reset status back to RETRY_PENDING so Pub/Sub retries are not rejected with 409
        # while preventing the scheduled threat detector from republishing the alert prematurely.
        if alert_id:
            try:
                await asyncio.to_thread(update_alert_status, alert_id, "RETRY_PENDING", alert_data)
            except Exception as reset_err:
                logger.warning("Could not reset alert status to RETRY_PENDING on failure: %s", reset_err)
        raise HTTPException(
            status_code=500,
            detail="Internal server error during alert investigation.",
        ) from exc
    finally:
        _IN_PROGRESS_MESSAGES.pop(message_id, None)


def get_app_port() -> int:
    """Resolves the application listening port, defaulting to Cloud Run standard 8080."""
    return int(os.getenv("PORT", 8080))


# Main execution
if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
