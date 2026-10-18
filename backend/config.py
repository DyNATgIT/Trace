"""Runtime configuration (env-driven, see .env.example)."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Config:
    # FalkorDB
    falkordb_host: str = os.getenv("FALKORDB_HOST", "localhost")
    falkordb_port: int = int(os.getenv("FALKORDB_PORT", "6381"))
    falkordb_password: str | None = os.getenv("FALKORDB_PASSWORD") or None

    # LLM
    llm_mode: str = os.getenv("LLM_MODE", "auto")  # auto | ollama | openai | mock
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
    openai_base_url: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    # App
    app_host: str = os.getenv("APP_HOST", "0.0.0.0")
    app_port: int = int(os.getenv("APP_PORT", "8000"))
    max_agent_steps: int = int(os.getenv("MAX_AGENT_STEPS", "20"))
    max_auditor_steps: int = int(os.getenv("MAX_AUDITOR_STEPS", "8"))

    # Graphs (FalkorDB multigraph: one isolated graph per concern / user)
    main_graph: str = "bank"
    case_graph: str = "cases"

    @staticmethod
    def memory_graph(user: str) -> str:
        return f"mem_{user}"


cfg = Config()


def resolve_llm_mode() -> str:
    """auto: Ollama if reachable, else OpenAI-compatible if key set, else mock."""
    if cfg.llm_mode != "auto":
        return cfg.llm_mode
    try:
        import httpx

        root = cfg.ollama_base_url.rstrip("/")
        if root.endswith("/v1"):
            root = root[:-3]
        r = httpx.get(f"{root}/api/tags", timeout=2)
        if r.status_code == 200:
            return "ollama"
    except Exception:
        pass
    if cfg.openai_api_key:
        return "openai"
    return "mock"
