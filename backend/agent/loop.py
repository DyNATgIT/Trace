"""The tool loop: LLM <-> tools, streaming events to the UI.

Identical for real LLMs (Ollama/OpenAI) and the MockLLM — the graph is the
context, the loop is the contract.
"""
from __future__ import annotations

import json

from .prompts import system_prompt
from .tools import TOOLS, RunCtx, execute_tool


def run_agent(ctx: RunCtx, llm, max_steps: int):
    """Generator of UI events for one agent run (investigator / auditor / consultant)."""
    messages = [
        {"role": "system", "content": system_prompt(ctx.role)},
        {"role": "user", "content": ctx.task},
    ]
    yield {"type": "role", "role": ctx.role}

    for _step in range(1, max_steps + 1):
        try:
            resp = llm.chat(messages, TOOLS)
        except Exception as e:  # noqa: BLE001
            yield {"type": "error", "text": f"LLM error: {e}"}
            return

        if resp.content:
            yield {"type": "thought", "text": resp.content}

        if not resp.tool_calls:
            yield {"type": "final", "text": resp.content or "(agent produced no output)"}
            return

        messages.append({
            "role": "assistant",
            "content": resp.content or None,
            "tool_calls": [
                {"id": tc.id, "type": "function", "function": {"name": tc.name, "arguments": json.dumps(tc.args, default=str)}}
                for tc in resp.tool_calls
            ],
        })

        for tc in resp.tool_calls:
            yield {"type": "tool_call", "id": tc.id, "name": tc.name, "args": tc.args}
            data = execute_tool(tc.name, tc.args, ctx)
            ctx.results.append((tc.name, data))
            yield {"type": "tool_result", "id": tc.id, "ok": bool(data.get("ok")), "data": data}
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": json.dumps(data, default=str)[:6000],
            })

    yield {"type": "final", "text": "Step limit reached — stopping."}
