"""
Pytest global configuration and fixtures.
Disables OpenTelemetry cloud export during automated testing when ADC may be unauthenticated.
"""

import os

os.environ["OTEL_SDK_DISABLED"] = "true"
os.environ["OTEL_TO_CLOUD"] = "false"

try:
    from httpx2._alias import alias_httpx

    alias_httpx()
except ImportError:
    pass


import pytest


@pytest.fixture(autouse=True)
def _isolated_ticket_queue(tmp_path_factory, monkeypatch):
    """Keeps tickets written by tests (including MCP subprocesses) out of the repo."""
    if "LOCAL_QUEUE_DIR" not in os.environ:
        monkeypatch.setenv(
            "LOCAL_QUEUE_DIR", str(tmp_path_factory.mktemp("escalations"))
        )
