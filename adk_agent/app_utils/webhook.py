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

"""
The Pub/Sub push webhook: unwraps the alert, deduplicates redeliveries (in memory
and through alerts.status), runs the investigation synchronously so Cloud Run keeps
CPU for it, and records the outcome. Routes are registered in fast_api_app.py
behind the OIDC dependency.
"""

import asyncio
import json
import logging
import time
from datetime import UTC, datetime

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from google.adk.runners import Runner
from google.genai import errors as genai_errors
from google.genai import types

from adk_agent.app_utils.alert_status import (
    get_alert_status_info,
    update_alert_status,
)
from adk_agent.app_utils.dedup import (
    _COMPLETED_MESSAGES,
    _IN_PROGRESS_MESSAGES,
    _cleanup_expired_messages,
    _record_completed_message,
    _record_in_progress_message,
)
from adk_agent.app_utils.pubsub import (
    _parse_timestamp,
    extract_pubsub_payload,
    session_id_for_alert,
)

logger = logging.getLogger("CymbalCyberADK.Webhook")


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


def _is_model_rate_limited(exc: BaseException) -> bool:
    """True when the run failed on a Gemini 429 (RESOURCE_EXHAUSTED), however wrapped."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, genai_errors.APIError) and exc.code == 429:
            return True
        exc = exc.__cause__ or exc.__context__
    return False


async def handle_pubsub_trigger(request: Request):
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
    prompt_text = (
        f"Investigate incoming continuous security alert: {json.dumps(alert_data)}"
    )

    # 1. Extract alert_id contract attribute or construct from payload
    alert_id = None
    pubsub_msg_id = None
    if isinstance(raw_body, dict):
        msg_obj = raw_body.get("message")
        if isinstance(msg_obj, dict):
            attrs = msg_obj.get("attributes") or {}
            alert_id = attrs.get("alert_id")
            pubsub_msg_id = msg_obj.get("messageId") or msg_obj.get("message_id")
    if not alert_id:
        alert_id = alert_data.get("alert_id")
    if not alert_id:
        window_end = (
            alert_data.get("window_end")
            or alert_data.get("transaction_window_end")
            or ""
        )
        if window_end and user_id:
            alert_id = f"{user_id}|{window_end}"

    message_id = (
        alert_id
        or pubsub_msg_id
        or request.headers.get("ce-id")
        or request.headers.get("x-goog-pubsub-message-id")
        or f"{user_id}-{int(time.time())}"
    )
    session_id = session_id_for_alert(user_id, alert_id)

    # 2. Runner readiness, before any dedup bookkeeping: if unready, return 503 so
    #    Pub/Sub retries.
    runner: Runner = getattr(request.app.state, "runner", None)
    app_name: str = getattr(request.app.state, "agent_app_name", "adk_agent")

    if not runner:
        logger.warning(
            "Runner not yet initialized in app.state; returning 503 to trigger Pub/Sub retry."
        )
        return JSONResponse(
            status_code=503,
            content={
                "status": "SERVICE_UNAVAILABLE",
                "message": "ADK Agent Runner is initializing; please retry.",
                "session_id": session_id,
            },
        )

    # 3. Fast-path in-memory and durable BigQuery alerts.status checks
    _cleanup_expired_messages()

    if message_id in _COMPLETED_MESSAGES:
        logger.info(
            "Duplicate Pub/Sub message already completed in-memory (%s); returning 200 DUPLICATE_ACK.",
            message_id,
        )
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
                logger.info(
                    "Alert '%s' is marked DONE in BigQuery alerts table; returning 200 DUPLICATE_ACK.",
                    alert_id,
                )
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
                # An unreadable timestamp counts as stale, so a stuck alert is retried
                # rather than refused forever.
                started = _parse_timestamp(updated_at)
                is_stale = (
                    started is None
                    or (datetime.now(UTC) - started).total_seconds() > 600
                )

                if not is_stale:
                    logger.warning(
                        "Alert '%s' currently INVESTIGATING in BigQuery (< 10 min ago); returning 409 to trigger Pub/Sub retry.",
                        alert_id,
                    )
                    return JSONResponse(
                        status_code=409,
                        content={
                            "status": "IN_PROGRESS",
                            "message": "Investigation currently in progress; please retry.",
                            "alert_id": alert_id,
                        },
                    )
                else:
                    logger.warning(
                        "Alert '%s' was INVESTIGATING but timed out (> 10 min); re-attempting.",
                        alert_id,
                    )

    if message_id in _IN_PROGRESS_MESSAGES:
        logger.warning(
            "Pub/Sub message currently in-progress in-memory (%s); returning 409.",
            message_id,
        )
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
        await asyncio.to_thread(
            update_alert_status, alert_id, "INVESTIGATING", alert_data
        )

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
        rate_limited = _is_model_rate_limited(exc)
        if rate_limited:
            # Vertex AI capacity, not a bug: the model already retried with backoff.
            # Answer 429 so Pub/Sub redelivers on its retry policy's backoff.
            logger.warning(
                "Pub/Sub agent investigation for session %s (alert %s) hit Vertex AI "
                "429 RESOURCE_EXHAUSTED after model retries; Pub/Sub will redeliver.",
                session_id,
                alert_id,
            )
        else:
            # logger.exception keeps the traceback: the 500 in the request log carries
            # no error detail, so this line is the only record of what failed.
            logger.exception(
                "Pub/Sub agent investigation failed for session %s (alert %s): %s: %s",
                session_id,
                alert_id,
                type(exc).__name__,
                exc,
            )
        # On failure: reset status back to RETRY_PENDING so Pub/Sub retries are not rejected with 409
        # while preventing the scheduled threat detector from republishing the alert prematurely.
        if alert_id:
            try:
                await asyncio.to_thread(
                    update_alert_status, alert_id, "RETRY_PENDING", alert_data
                )
            except Exception as reset_err:
                logger.warning(
                    "Could not reset alert status to RETRY_PENDING on failure: %s",
                    reset_err,
                )
        if rate_limited:
            return JSONResponse(
                status_code=429,
                content={
                    "status": "RATE_LIMITED",
                    "message": "Model capacity exhausted; Pub/Sub will retry.",
                    "alert_id": alert_id,
                },
            )
        raise HTTPException(
            status_code=500,
            detail="Internal server error during alert investigation.",
        ) from exc
    finally:
        _IN_PROGRESS_MESSAGES.pop(message_id, None)
