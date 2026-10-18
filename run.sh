#!/usr/bin/env bash
# TRACE — one-command local run
# 1) starts FalkorDB in Docker   2) installs deps  3) seeds the graph  4) runs the app
set -e
cd "$(dirname "$0")"

info() { printf '\033[1;36m[trace]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[trace]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[trace]\033[0m %s\n' "$*"; exit 1; }

[ -f .env ] || { cp .env.example .env; info "created .env from .env.example"; }
set -a; . ./.env; set +a

# --- 1) FalkorDB -----------------------------------------------------------
DB_HOST="${FALKORDB_HOST:-localhost}"
DB_PORT="${FALKORDB_PORT:-6381}"

db_reachable() {
  python3 - <<EOF
import sys, time
try:
    import falkordb
except ImportError:
    sys.exit(2)
client = falkordb.FalkorDB(host="$DB_HOST", port=int("$DB_PORT"))
g = client.select_graph("healthcheck")
for i in range(30):
    try:
        g.query("RETURN 1")
        sys.exit(0)
    except Exception:
        time.sleep(1)
sys.exit(1)
EOF
}

if [ "${FALKORDB_EXTERNAL:-0}" != "1" ]; then
  if command -v docker >/dev/null 2>&1; then
    info "starting FalkorDB in Docker (port ${DB_PORT})..."
    docker compose up -d falkordb 2>/dev/null || docker run -d --rm --name trace-falkordb \
      -p "${DB_PORT}:6379" -v trace-falkordb-data:/data falkordb/falkordb:latest
  else
    warn "Docker not found. Assuming FalkorDB is already running at ${DB_HOST}:${DB_PORT}"
    warn "(Docker option:  docker run -p ${DB_PORT}:6379 falkordb/falkordb:latest)"
    warn "(No-Docker option: use FalkorDB Cloud and set FALKORDB_HOST/PORT in .env, FALKORDB_EXTERNAL=1)"
  fi
fi

info "waiting for FalkorDB at ${DB_HOST}:${DB_PORT} ..."
if ! db_reachable; then
  die "FalkorDB is not reachable at ${DB_HOST}:${DB_PORT}. Start it (docker compose up -d) and re-run."
fi
info "FalkorDB is up."

# --- 2) deps ----------------------------------------------------------------
if ! python3 -c "import fastapi, falkordb, httpx, dotenv" >/dev/null 2>&1; then
  info "installing python dependencies..."
  python3 -m pip install -q -r requirements.txt
fi

# --- 3) seed ----------------------------------------------------------------
info "seeding the bank + knowledge graph (deterministic, ~2s)..."
python3 -m backend.data.seed

# --- 4) run ------------------------------------------------------------------
LLM_NOTE=""
case "${LLM_MODE:-auto}" in
  auto)
    if python3 - <<'EOF' >/dev/null 2>&1
import httpx
r = httpx.get("http://localhost:11434/api/tags", timeout=2)
exit(0 if r.status_code == 200 else 1)
EOF
    then LLM_NOTE="Ollama (LLM_MODE=ollama)"
    elif [ -n "${OPENAI_API_KEY:-}" ]; then LLM_NOTE="OpenAI-compatible (LLM_MODE=openai)"
    else LLM_NOTE="built-in MOCK (deterministic demo, no model needed)"
    fi
    info "LLM mode resolved to: $LLM_NOTE"
    ;;
  *) LLM_NOTE="$LLM_MODE"; info "LLM mode: $LLM_NOTE";;
esac

if [ "$LLM_NOTE" = "built-in MOCK (deterministic demo, no model needed)" ]; then
  warn "No Ollama/OpenAI detected — the agent will run in MOCK mode (fully deterministic)."
  warn "For the real LLM agent:  ollama pull ${OLLAMA_MODEL:-qwen2.5:7b}   (then restart this script)"
fi

info "starting TRACE on http://localhost:${APP_PORT:-8000}  (Ctrl-C to stop)"
exec python3 -m uvicorn backend.server:app --host "${APP_HOST:-0.0.0.0}" --port "${APP_PORT:-8000}"
