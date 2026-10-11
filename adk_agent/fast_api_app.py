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

import base64
import contextlib
import json
import logging
import os
import time
from collections.abc import AsyncIterator
from typing import Any, Dict

from a2a.server.tasks import InMemoryTaskStore
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
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
otel_to_cloud = True

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


async def _run_agent_investigation(
    runner: Runner,
    app_name: str,
    user_id: str,
    session_id: str,
    prompt_text: str,
) -> str:
    """Runs autonomous multi-agent forensic investigation asynchronously."""
    try:
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
    except Exception as exc:
        logger.error("Failed to execute agent investigation for session %s: %s", session_id, exc)
        return f"Investigation failed: {exc}"


@app.post("/apps/adk_agent/trigger/pubsub")
@app.post("/trigger/pubsub")
async def handle_pubsub_trigger(
    request: Request,
    background_tasks: BackgroundTasks,
    sync: bool = False,
):
    """
    Webhook receiving Pub/Sub push notifications for BigQuery Continuous Query security alerts.
    Unwraps base64 alert data and triggers multi-agent forensic investigation.
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

    runner: Runner = getattr(app.state, "runner", None)
    app_name: str = getattr(app.state, "agent_app_name", "adk_agent")

    if not runner:
        logger.warning("Runner not yet initialized in app.state; alert acknowledged.")
        return JSONResponse(
            status_code=202,
            content={
                "status": "ACCEPTED",
                "message": "Alert received; runner initializing.",
                "session_id": session_id,
                "alert": alert_data,
            },
        )

    if sync:
        output = await _run_agent_investigation(
            runner=runner,
            app_name=app_name,
            user_id=user_id,
            session_id=session_id,
            prompt_text=prompt_text,
        )
        return JSONResponse(
            status_code=200,
            content={
                "status": "COMPLETED",
                "session_id": session_id,
                "output": output,
            },
        )

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
            "message": "Continuous query alert received and investigation started.",
            "session_id": session_id,
            "user_id": user_id,
        },
    )


# Main execution
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
