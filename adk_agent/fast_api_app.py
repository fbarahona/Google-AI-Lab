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


def is_alert_durably_assessed(user_id: str, window_end: Optional[str]) -> bool:
    """Checks BigQuery adk_threat_assessment to determine if this alert was already evaluated."""
    if os.getenv("LOCAL_MODE", "false").lower() == "true":
        return False
    if not user_id or not window_end:
        return False
    try:
        from google.cloud import bigquery
        from adk_agent.tools import get_bq_client, PROJECT_ID, DATASET_ID
        bq = get_bq_client()
        query = f"""
            SELECT 1 FROM `{PROJECT_ID}.{DATASET_ID}.adk_threat_assessment`
            WHERE user_id = @user_id
              AND transaction_window_end = TIMESTAMP(@window_end)
            LIMIT 1
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("user_id", "STRING", user_id),
                bigquery.ScalarQueryParameter("window_end", "STRING", window_end),
            ]
        )
        results = list(bq.query(query, job_config=job_config).result())
        return len(results) > 0
    except Exception:
        return False


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

    # 2. Extract deduplication identifier (messageId, header, or user:window_end)
    message_id = None
    if isinstance(raw_body, dict):
        msg_obj = raw_body.get("message")
        if isinstance(msg_obj, dict):
            message_id = msg_obj.get("messageId") or msg_obj.get("message_id")
    if not message_id:
        message_id = request.headers.get("ce-id") or request.headers.get("x-goog-pubsub-message-id")
    if not message_id:
        window_end = alert_data.get("window_end") or alert_data.get("transaction_window_end") or ""
        if window_end:
            message_id = f"{user_id}:{window_end}"

    # 3. Deduplication Check: Check completed first, then in-progress, then durable BigQuery store
    _cleanup_expired_messages()
    if message_id:
        if message_id in _COMPLETED_MESSAGES:
            logger.info("Duplicate Pub/Sub message already completed (%s); returning 200 DUPLICATE_ACK.", message_id)
            return JSONResponse(
                status_code=200,
                content={
                    "status": "DUPLICATE_ACK",
                    "message": "Alert previously completed.",
                    "message_id": message_id,
                },
            )

        window_end = alert_data.get("window_end") or alert_data.get("transaction_window_end")
        if is_alert_durably_assessed(user_id, window_end):
            logger.info("Alert previously recorded in BigQuery adk_threat_assessment (%s, %s); acknowledging with 200.", user_id, window_end)
            _COMPLETED_MESSAGES[message_id] = time.time()
            return JSONResponse(
                status_code=200,
                content={
                    "status": "DUPLICATE_ACK",
                    "message": "Alert previously assessed in BigQuery.",
                    "message_id": message_id,
                },
            )

        if message_id in _IN_PROGRESS_MESSAGES:
            logger.warning("Pub/Sub message currently in-progress (%s); returning 409 to trigger Pub/Sub retry.", message_id)
            return JSONResponse(
                status_code=409,
                content={
                    "status": "IN_PROGRESS",
                    "message": "Investigation currently in progress; please retry.",
                    "message_id": message_id,
                },
            )

        # Mark as currently executing
        _IN_PROGRESS_MESSAGES[message_id] = time.time()

    # 4. Synchronous Execution by Default (with guaranteed state cleanup in finally)
    try:
        if sync:
            output = await _run_agent_investigation(
                runner=runner,
                app_name=app_name,
                user_id=user_id,
                session_id=session_id,
                prompt_text=prompt_text,
            )
            # Record completed ID ONLY on success!
            if message_id:
                _COMPLETED_MESSAGES[message_id] = time.time()

            return JSONResponse(
                status_code=200,
                content={
                    "status": "COMPLETED",
                    "session_id": session_id,
                    "output": output,
                },
            )
        else:
            # Optional background path
            background_tasks.add_task(
                _run_agent_investigation,
                runner=runner,
                app_name=app_name,
                user_id=user_id,
                session_id=session_id,
                prompt_text=prompt_text,
            )
            return JSONResponse(
                status_code=200,
                content={
                    "status": "ACK",
                    "message": "Continuous query alert received and investigation started in background.",
                    "session_id": session_id,
                    "user_id": user_id,
                },
            )
    except Exception as exc:
        logger.error("Pub/Sub agent investigation failed for session %s: %s", session_id, exc)
        # On failure: do NOT add to _COMPLETED_MESSAGES so retries can run!
        raise HTTPException(
            status_code=500,
            detail=f"Agent investigation failed: {exc}",
        )
    finally:
        # Always remove from in-progress store
        if message_id:
            _IN_PROGRESS_MESSAGES.pop(message_id, None)


_SCAN_LOCK = asyncio.Lock()


@app.post("/apps/adk_agent/trigger/scan")
@app.post("/trigger/scan")
async def handle_scheduled_scan(
    caller_claims: Dict[str, Any] = Depends(verify_incoming_oidc_token),
):
    """
    Cloud Scheduler trigger endpoint. Runs periodic threat scanning (every 2 minutes)
    to query BigQuery for newly emerging unassessed threats and dispatch investigations.
    Uses an in-memory lock to skip overlapping passes if an earlier scan is still in-flight.
    """
    if _SCAN_LOCK.locked():
        logger.warning("Overlapping Cloud Scheduler scan requested while previous pass active; skipping.")
        return JSONResponse(
            status_code=200,
            content={
                "status": "SKIPPED_OVERLAPPING_PASS",
                "message": "Previous threat scan pass is still executing; skipping overlapping run.",
            },
        )

    async with _SCAN_LOCK:
        logger.info("Executing Cloud Scheduler threat scan pass...")
        try:
            from adk_agent.threat_scanner import BigQueryThreatScanner
            from adk_agent.tools import PROJECT_ID, DATASET_ID
            scanner = BigQueryThreatScanner(project_id=PROJECT_ID, dataset_id=DATASET_ID)
            threats = scanner.find_new_threat_events()
            results = []
            for threat in threats:
                logger.info(
                    "Discovered unassessed threat for user: %s (score: %s)",
                    threat.get("user_id"),
                    threat.get("total_2_min_threat_score"),
                )
                res = await scanner.investigate_threat(threat)
                results.append({
                    "user_id": threat.get("user_id"),
                    "threat_score": threat.get("total_2_min_threat_score"),
                    "response": res,
                })

            return JSONResponse(
                status_code=200,
                content={
                    "status": "SCAN_COMPLETE",
                    "threats_discovered": len(threats),
                    "investigations": results,
                },
            )
        except Exception as exc:
            logger.error("Scheduled threat scan pass failed: %s", exc)
            return JSONResponse(
                status_code=500,
                content={"status": "ERROR", "detail": str(exc)},
            )


# Main execution
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
