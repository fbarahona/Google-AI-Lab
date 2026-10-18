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

import contextlib
import logging
import os
from collections.abc import AsyncIterator

from a2a.server.tasks import InMemoryTaskStore
from dotenv import load_dotenv
from fastapi import Depends, FastAPI
from google.adk.cli.fast_api import get_fast_api_app
from google.adk.runners import Runner

from adk_agent.app_utils import services
from adk_agent.app_utils.a2a import attach_a2a_routes

# Re-exported so `from adk_agent.fast_api_app import X` keeps working for code and
# tests written before the webhook pieces moved to adk_agent.app_utils.
from adk_agent.app_utils.alert_status import (  # noqa: F401
    get_alert_status_info,
    update_alert_status,
)
from adk_agent.app_utils.dedup import (  # noqa: F401
    _COMPLETED_MESSAGES,
    _DEDUP_TTL_SECONDS,
    _IN_PROGRESS_MESSAGES,
    MAX_DEDUP_CACHE_SIZE,
    _cleanup_expired_messages,
    _record_completed_message,
    _record_in_progress_message,
)
from adk_agent.app_utils.oidc import verify_incoming_oidc_token
from adk_agent.app_utils.pubsub import (  # noqa: F401
    _parse_timestamp,
    extract_pubsub_payload,
    session_id_for_alert,
)
from adk_agent.app_utils.webhook import (  # noqa: F401
    _run_agent_investigation,
    handle_pubsub_trigger,
)
from adk_agent.logging_utils import setup_logging

logger = logging.getLogger("CymbalCyberADK.Webhook")

load_dotenv()
# Without this the app's loggers had no handler, so INFO lines were dropped and
# errors reached Cloud Logging only as unstructured stderr text.
setup_logging()
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


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.lower() in ("true", "1")


# The ADK developer surface (web UI, /run, session and builder APIs) executes agents as
# the service account with no OIDC check, so it is on only for local development unless
# ADK_DEV_UI=true opts in. In the cloud the service exposes just the Pub/Sub webhook.
_LOCAL_MODE = _env_flag("LOCAL_MODE", False)
ADK_DEV_UI_ENABLED = _env_flag("ADK_DEV_UI", _LOCAL_MODE)
A2A_ENABLED = _env_flag("ENABLE_A2A", ADK_DEV_UI_ENABLED)

# Routes served when the developer surface is off.
WEBHOOK_ROUTES = frozenset({"/trigger/pubsub", "/apps/adk_agent/trigger/pubsub"})

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
    if not A2A_ENABLED:
        yield
        return
    await attach_a2a_routes(
        app,
        agent=root_agent,
        runner=runner,
        task_store=InMemoryTaskStore(),
        rpc_path=f"/a2a/{adk_app.name}",
    )
    if adk_app.name != "adk_agent":
        await attach_a2a_routes(
            app,
            agent=root_agent,
            runner=runner,
            task_store=InMemoryTaskStore(),
            rpc_path="/a2a/adk_agent",
        )
    yield


app: FastAPI = get_fast_api_app(
    agents_dir=AGENT_DIR,
    web=ADK_DEV_UI_ENABLED,
    artifact_service_uri=services.ARTIFACT_SERVICE_URI,
    allow_origins=allow_origins,
    session_service_uri=services.SESSION_SERVICE_URI,
    otel_to_cloud=otel_to_cloud,
    lifespan=lifespan,
)
app.title = "Cymbal Cyber ADK Agent"
app.description = (
    "Pub/Sub alert intake and investigation API for the Cymbal Cyber SOC agents"
)

# The Pub/Sub webhook, authenticated by the OIDC dependency on both paths.
app.post("/trigger/pubsub", dependencies=[Depends(verify_incoming_oidc_token)])(
    handle_pubsub_trigger
)
app.post(
    "/apps/adk_agent/trigger/pubsub",
    dependencies=[Depends(verify_incoming_oidc_token)],
)(handle_pubsub_trigger)


def restrict_to_webhook_routes(fastapi_app: FastAPI) -> None:
    """Drops every route except the Pub/Sub webhook (including /docs and /openapi.json)."""
    fastapi_app.router.routes = [
        route
        for route in fastapi_app.router.routes
        if getattr(route, "path", None) in WEBHOOK_ROUTES
    ]
    fastapi_app.openapi_url = None
    fastapi_app.docs_url = None
    fastapi_app.redoc_url = None


if not ADK_DEV_UI_ENABLED:
    restrict_to_webhook_routes(app)


def get_app_port() -> int:
    """Resolves the application listening port, defaulting to Cloud Run standard 8080."""
    return int(os.getenv("PORT", 8080))


# Main execution
if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
