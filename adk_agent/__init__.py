"""
ADK Multi-Agent Package for Cymbal Cyber.

Importing the package (or a submodule such as adk_agent.tools, which the MCP server
does) does not build the agents. They are created on first access to an attribute
below, so tool code, the detector job and tests stay free of agent side effects.
"""

import importlib
from typing import Any

try:
    from httpx2._alias import alias_httpx

    alias_httpx()
except (ImportError, RuntimeError):
    # RuntimeError: httpx was imported before this package; keep the real httpx.
    pass

_AGENT_EXPORTS = (
    "app",
    "bq_investigation_agent",
    "decision_agent",
    "google_search_agent",
    "investigation_team",
    "orchestrator_agent",
    "root_agent",
    "soc_ticketing_agent",
    "visual_analysis_agent",
)

__all__ = list(_AGENT_EXPORTS)


def __getattr__(name: str) -> Any:
    if name in _AGENT_EXPORTS:
        return getattr(importlib.import_module(".agent", __name__), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
