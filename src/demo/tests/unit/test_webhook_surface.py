"""
The agent service exposes only the Pub/Sub webhook in the cloud: the ADK developer
surface (web UI, /run, session and builder APIs, A2A, OpenAPI docs) runs agents with
no OIDC check, so it must be off unless explicitly enabled.

Each case imports the app in a fresh interpreter, because the surface is fixed at
import time from the environment.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]

PROBE = """
import json
from starlette.testclient import TestClient
import adk_agent.fast_api_app as f

client = TestClient(f.app)
status = {p: client.get(p).status_code for p in
          ("/dev-ui/", "/run", "/list-apps", "/docs", "/openapi.json",
           "/.well-known/agent-card.json")}
status["POST /run"] = client.post("/run", json={}).status_code
status["POST /trigger/pubsub"] = client.post("/trigger/pubsub", json={}).status_code
print("PROBE" + json.dumps({"dev": f.ADK_DEV_UI_ENABLED, "a2a": f.A2A_ENABLED,
                            "status": status}))
"""


def _probe(**env: str) -> dict:
    full_env = {
        **os.environ,
        "GOOGLE_CLOUD_PROJECT": "dummy",
        "OTEL_TO_CLOUD": "false",
        "ADK_DEV_UI": "",
        "ENABLE_A2A": "",
        **env,
    }
    out = subprocess.run(
        [sys.executable, "-c", PROBE],
        cwd=REPO_ROOT,
        env=full_env,
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    ).stdout
    line = next(x for x in out.splitlines() if x.startswith("PROBE"))
    return json.loads(line[len("PROBE") :])


def test_cloud_mode_serves_only_the_webhook():
    result = _probe(LOCAL_MODE="false")
    assert result["dev"] is False
    assert result["a2a"] is False
    status = result["status"]
    for path in (
        "/dev-ui/",
        "/run",
        "/list-apps",
        "/docs",
        "/openapi.json",
        "/.well-known/agent-card.json",
    ):
        assert status[path] == 404, (path, status)
    assert status["POST /run"] == 404
    # The webhook is still routed; the request fails OIDC instead of 404.
    assert status["POST /trigger/pubsub"] in (401, 403)


@pytest.mark.parametrize(
    "env", [{"LOCAL_MODE": "true"}, {"LOCAL_MODE": "false", "ADK_DEV_UI": "true"}]
)
def test_dev_surface_on_locally_or_when_opted_in(env):
    result = _probe(**env)
    assert result["dev"] is True
    assert result["status"]["/list-apps"] == 200
