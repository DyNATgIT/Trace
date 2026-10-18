"""LLM clients.

One OpenAI-compatible client serves both Ollama (http://localhost:11434/v1)
and any hosted OpenAI-compatible endpoint. The deterministic MockLLM
(lives in agent/mock.py) plugs into the same loop with zero infrastructure.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from .config import cfg


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict = field(default_factory=dict)


@dataclass
class LLMResponse:
    content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLMError(RuntimeError):
    pass


class OpenAICompatLLM:
    def __init__(self, base_url: str, model: str, api_key: str = ""):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key

    @classmethod
    def for_mode(cls, mode: str) -> "OpenAICompatLLM":
        if mode == "ollama":
            return cls(cfg.ollama_base_url, cfg.ollama_model)
        return cls(cfg.openai_base_url, cfg.openai_model, cfg.openai_api_key)

    def chat(self, messages: list[dict], tools: list[dict] | None) -> LLMResponse:
        payload: dict[str, Any] = {"model": self.model, "messages": messages, "stream": False}
        if tools:
            payload["tools"] = tools
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            r = httpx.post(f"{self.base_url}/chat/completions", json=payload, headers=headers, timeout=180)
        except httpx.HTTPError as e:
            raise LLMError(f"cannot reach LLM endpoint {self.base_url}: {e}") from e
        if r.status_code != 200:
            raise LLMError(f"LLM returned {r.status_code}: {r.text[:300]}")
        data = r.json()
        try:
            msg = data["choices"][0]["message"]
        except (KeyError, IndexError) as e:
            raise LLMError(f"unexpected LLM response shape: {str(data)[:300]}") from e

        tcs: list[ToolCall] = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function", {})
            raw = fn.get("arguments") or "{}"
            if isinstance(raw, str):
                try:
                    args = json.loads(raw)
                except json.JSONDecodeError:
                    args = {}
            else:
                args = raw
            tcs.append(ToolCall(id=tc.get("id") or f"call_{i}", name=fn.get("name") or "unknown", args=args or {}))
        return LLMResponse(content=msg.get("content"), tool_calls=tcs)


def make_llm(mode: str, role: str, ctx) -> "OpenAICompatLLM | object":
    """Factory used by the orchestrator. Mock mode returns a scripted agent."""
    if mode == "mock":
        from .agent.mock import MockLLM

        return MockLLM(role, ctx)
    return OpenAICompatLLM.for_mode(mode)
