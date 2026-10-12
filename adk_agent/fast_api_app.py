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
from collections.abc import AsyncIterator
from typing import Any, Dict, Optional

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


def extract_pubsub_payload(raw_body: Any) -> Dict[str, Any]:
    """
    Decodes and extracts the alert payload from incoming Pub/Sub push requests.
    Handles:
    - Standard wrapped Pub/Sub envelope: {"message": {"data": "<base64>", "attributes": ...}}
    - Raw/unwrapped JSON payloads (Pub/Sub no_wrapper configuration)
    - Raw strings and byte payloads
    """
    if isinstance(raw_body, bytes):
        try:
            raw_body = json.loads(raw_body.decode("utf-8"))
        except Exception:
            raw_body = {"raw_text": raw_body.decode("utf-8", errors="replace")}
    elif isinstance(raw_body, str):
        try:
            raw_body = json.loads(raw_body)
        except Exception:
            raw_body = {"raw_text": raw_body}

    if not isinstance(raw_body, dict):
        return {"raw_payload": raw_body}

    # Wrapped Pub/Sub push message
    if "message" in raw_body and isinstance(raw_body["message"], dict):
        msg = raw_body["message"]
        data = msg.get("data")
        if data:
            try:
                decoded = base64.b64decode(data).decode("utf-8")
                return json.loads(decoded)
            except Exception:
                try:
                    return json.loads(data)
                except Exception:
                    return {"raw_message_data": data}

    return raw_body


_IN_PROGRESS_MESSAGES: Dict[str, float] = {}
_COMPLETED_MESSAGES: Dict[str, float] = {}
_DEDUP_TTL_SECONDS = 900.0  # 15 minutes deduplication window


def _cleanup_expired_messages():
    """Removes expired entries from memory dedup tables."""
    now = time.time()
    for store in (_IN_PROGRESS_MESSAGES, _COMPLETED_MESSAGES):
        expired = [k for k, ts in store.items() if now - ts > _DEDUP_TTL_SECONDS]
        for k in expired:
            store.pop(k, None)


def get_alert_status_info(alert_id: str) -> Optional[Dict[str, Any]]:
    """
    Checks BigQuery `alerts` table for the alert_id status.
    Returns dict with status, updated_at timestamp, or None if not found.
    """
    if os.getenv("LOCAL_MODE", "false").lower() == "true" or not alert_id:
        return None
    try:
        from google.cloud import bigquery
        from adk_agent.tools import get_bq_client, PROJECT_ID, DATASET_ID
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
            ]
        )
        rows = list(bq.query(query, job_config=job_config).result())
        if rows:
            return {"status": rows[0]["status"], "updated_at": rows[0]["updated_at"]}
        return None
    except Exception as e:
        logger.warning("Could not query alerts.status for alert_id %s: %s", alert_id, e)
        return None


def update_alert_status(alert_id: str, new_status: str):
    """
    Updates alerts.status to INVESTIGATING or DONE with timestamp audit.
    """
    if os.getenv("LOCAL_MODE", "false").lower() == "true" or not alert_id:
        return
    try:
        from google.cloud import bigquery
        from adk_agent.tools import get_bq_client, PROJECT_ID, DATASET_ID
        bq = get_bq_client()
        query = f"""
            UPDATE `{PROJECT_ID}.{DATASET_ID}.alerts`
            SET status = @new_status, updated_at = CURRENT_TIMESTAMP()
            WHERE alert_id = @alert_id
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("new_status", "STRING", new_status),
                bigquery.ScalarQueryParameter("alert_id", "STRING", alert_id),
            ]
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


def verify_incoming_oidc_token(request: Request) -> Dict[str, Any]:
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
        from google.oauth2 import id_token
        from google.auth.transport import requests as google_requests

        expected_audience = os.getenv("EXPECTED_OIDC_AUDIENCE") or str(request.url).split("?")[0]
        claims = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            audience=expected_audience,
        )
        return claims
    except Exception as exc:
        logger.warning("Inbound OIDC JWT validation failed: %s", exc)
        raise HTTPException(
            status_code=403,
            detail=f"Invalid OIDC bearer token: {exc}",
        )


@app.post("/apps/adk_agent/trigger/pubsub")
@app.post("/trigger/pubsub")
async def handle_pubsub_trigger(
    request: Request,
    background_tasks: BackgroundTasks,
    sync: bool = True,
    caller_claims: Dict[str, Any] = Depends(verify_incoming_oidc_token),
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

    alert_data = extract_pubsub_payload(raw_body)
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
        status_info = get_alert_status_info(alert_id)
        if status_info:
            current_status = status_info.get("status")
            updated_at = status_info.get("updated_at")

            # If already DONE: skip and ACK immediately
            if current_status == "DONE":
                logger.info("Alert '%s' is marked DONE in BigQuery alerts table; returning 200 DUPLICATE_ACK.", alert_id)
                _COMPLETED_MESSAGES[message_id] = time.time()
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
                            elapsed = (datetime.now(timezone.utc) - updated_at).total_seconds()
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
    _IN_PROGRESS_MESSAGES[message_id] = time.time()
    if alert_id:
        update_alert_status(alert_id, "INVESTIGATING")

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
            update_alert_status(alert_id, "DONE")
        _COMPLETED_MESSAGES[message_id] = time.time()

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
        # On failure: do NOT mark DONE so retries or DLQ can take over
        raise HTTPException(
            status_code=500,
            detail=f"Agent investigation failed: {exc}",
        )
    finally:
        _IN_PROGRESS_MESSAGES.pop(message_id, None)


# Main execution
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
