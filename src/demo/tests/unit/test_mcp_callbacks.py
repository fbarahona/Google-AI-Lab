"""
MCP state sync runs through ADK's tool callbacks, not a toolset wrapper:
1. Every MCP-backed agent has the after-tool and on-tool-error callbacks attached
2. A real ADK run over stdio MCP writes security flags into session state
3. A tool that raises still fails closed through on_tool_error_callback
"""

from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from google.adk.agents import Agent
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types

from adk_agent.agent import (
    bq_investigation_agent,
    create_mcp_toolset,
    mcp_tool_error_callback,
    soc_ticketing_agent,
    sync_mcp_security_state_callback,
    visual_analysis_agent,
)

C_WILSON_PNG = (
    Path(__file__).resolve().parents[4]
    / "local_demo_data"
    / "user_screenshots"
    / "c.wilson.png"
)


class _CallToolOnceLlm(BaseLlm):
    """Asks for one tool call, then answers with text once the tool result is back."""

    model: str = "fake-model"
    tool_name: str
    tool_args: dict

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        last_parts = llm_request.contents[-1].parts or []
        if any(p.function_response for p in last_parts):
            part = types.Part(text="done")
        else:
            part = types.Part(
                function_call=types.FunctionCall(
                    name=self.tool_name, args=self.tool_args
                )
            )
        yield LlmResponse(content=types.Content(role="model", parts=[part]))


async def _run_agent(agent: Agent) -> dict:
    runner = InMemoryRunner(agent=agent, app_name="test")
    session = await runner.session_service.create_session(app_name="test", user_id="u")
    async for _ in runner.run_async(
        user_id="u",
        session_id=session.id,
        new_message=types.Content(role="user", parts=[types.Part(text="go")]),
    ):
        pass
    session = await runner.session_service.get_session(
        app_name="test", user_id="u", session_id=session.id
    )
    return session.state


@pytest.mark.parametrize(
    "agent", [bq_investigation_agent, visual_analysis_agent, soc_ticketing_agent]
)
def test_mcp_agents_have_state_sync_callbacks(agent):
    assert agent.after_tool_callback is sync_mcp_security_state_callback
    assert agent.on_tool_error_callback is mcp_tool_error_callback


@pytest.mark.asyncio
async def test_adk_run_over_mcp_syncs_prompt_injection_into_session_state(
    monkeypatch,
):
    monkeypatch.setenv("LOCAL_MODE", "true")
    assert C_WILSON_PNG.exists()
    toolset = create_mcp_toolset(["get_visual_analysis_for_user"])
    agent = Agent(
        name="visual_probe",
        model=_CallToolOnceLlm(
            tool_name="get_visual_analysis_for_user",
            tool_args={"gcs_uri": f"file://{C_WILSON_PNG}"},
        ),
        tools=[toolset],
        after_tool_callback=sync_mcp_security_state_callback,
        on_tool_error_callback=mcp_tool_error_callback,
    )
    try:
        state = await _run_agent(agent)
    finally:
        await toolset.close()

    assert state.get("prompt_injection_detected") is True
    assert state.get("visual_evidence_collected") is True


@pytest.mark.asyncio
async def test_raising_evidence_tool_fails_closed_through_error_callback():
    def get_visual_analysis_for_user(gcs_uri: str) -> dict:
        raise RuntimeError("vision backend down")

    agent = Agent(
        name="raising_probe",
        model=_CallToolOnceLlm(
            tool_name="get_visual_analysis_for_user",
            tool_args={"gcs_uri": "gs://bucket/u.lewis.png"},
        ),
        tools=[get_visual_analysis_for_user],
        after_tool_callback=sync_mcp_security_state_callback,
        on_tool_error_callback=mcp_tool_error_callback,
    )
    state = await _run_agent(agent)

    assert state.get("evidence_unavailable") is True
    assert not state.get("visual_evidence_collected")
