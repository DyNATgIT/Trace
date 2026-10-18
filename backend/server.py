"""TRACE API server.

GET  /                       single-page UI
GET  /api/health             db + llm status
POST /api/chat               SSE stream of agent events
GET  /api/cases              case list
GET  /api/case/{cid}         full case file (flags, actions, audit, citations)
GET  /api/graph/around/...   neighborhood for the graph view
GET  /api/memories           memory for a user
"""
from __future__ import annotations

import asyncio
import json
import queue
import re
import threading
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from .agent.orchestrator import handle_message
from .config import cfg, resolve_llm_mode
from .db import DB

app = FastAPI(title="TRACE — graph-native fraud investigation agent")
WEB_HTML = Path(__file__).parent.parent / "web" / "index.html"

_db: DB | None = None
_state = {"llm_mode": None}


def get_db() -> DB:
    global _db
    if _db is None:
        _db = DB()
    return _db


def llm_info() -> dict:
    if _state["llm_mode"] is None:
        _state["llm_mode"] = resolve_llm_mode()
    m = _state["llm_mode"]
    model = {"ollama": cfg.ollama_model, "openai": cfg.openai_model, "mock": "mock-plan-v1 (deterministic)"}[m]
    return {"mode": m, "model": model}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return WEB_HTML.read_text()


@app.get("/api/health")
def health() -> dict:
    return {"db": get_db().health(), "llm": llm_info()}


@app.post("/api/chat")
async def chat(req: Request) -> StreamingResponse:
    body = await req.json()
    user = re.sub(r"[^a-z0-9]", "", (body.get("user") or "demo").lower())[:24] or "demo"
    message = (body.get("message") or "").strip()
    if not message:
        return JSONResponse({"error": "empty message"}, status_code=400)

    async def gen():
        q: queue.Queue = queue.Queue()

        def worker() -> None:
            try:
                for ev in handle_message(get_db(), user, message):
                    q.put(ev)
            except Exception as e:  # noqa: BLE001
                q.put({"type": "error", "text": f"{type(e).__name__}: {str(e)[:300]}"})
            finally:
                q.put(None)

        threading.Thread(target=worker, daemon=True).start()
        while True:
            ev = await asyncio.to_thread(q.get)
            if ev is None:
                break
            yield f"data: {json.dumps(ev, default=str)}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/cases")
def cases() -> dict:
    res = get_db().query(
        cfg.case_graph,
        "MATCH (c:Case) RETURN c.id AS id, c.subject AS subject, c.status AS status, c.risk_score AS risk, c.audit_verdict AS verdict, c.updated AS updated ORDER BY c.updated DESC LIMIT 30",
    )
    return {"cases": [dict(zip(res["columns"], row)) for row in res["rows"]]}


def _case_detail(db: DB, cid: str) -> dict:
    out: dict = {"id": cid, "flags": [], "actions": [], "audit": [], "cited": [], "subject": None}
    r = db.query(cfg.case_graph, "MATCH (c:Case {id: $id}) RETURN c", {"id": cid})
    if not r["rows"]:
        return out
    node = r["rows"][0][0]
    out.update({k: v for k, v in node.items() if not k.startswith("__")})
    r = db.query(cfg.case_graph, "MATCH (c:Case {id: $id})-[:SUBJECT_IS]->(a:Account) RETURN a.name AS n", {"id": cid})
    out["subject"] = r["rows"][0][0] if r["rows"] else out.get("subject")
    r = db.query(cfg.case_graph, "MATCH (c:Case {id: $id})-[f:FLAGS]->(a:Account) RETURN a.name AS account, f.reason AS reason, f.ts AS ts ORDER BY f.ts", {"id": cid})
    out["flags"] = [dict(zip(r["columns"], row)) for row in r["rows"]]
    r = db.query(
        cfg.case_graph,
        "MATCH (c:Case {id: $id})-[t:TOOK]->(a:Action) OPTIONAL MATCH (a)-[:CITES]->(p:Policy) "
        "RETURN a.type AS type, a.target AS target, a.reason AS reason, a.by AS by, a.ts AS ts, t.ts AS took_ts, p.code AS cited_policy ORDER BY t.ts",
        {"id": cid},
    )
    out["actions"] = [dict(zip(r["columns"], row)) for row in r["rows"]]
    r = db.query(cfg.case_graph, "MATCH (c:Case {id: $id})-[:AUDIT]->(an:AuditNote) RETURN an.verdict AS verdict, an.text AS text, an.ts AS ts ORDER BY an.ts", {"id": cid})
    out["audit"] = [dict(zip(r["columns"], row)) for row in r["rows"]]
    r = db.query(cfg.case_graph, "MATCH (c:Case {id: $id})-[:CITES]->(p:Policy) RETURN p.code AS code, p.name AS name", {"id": cid})
    out["cited"] = [dict(zip(r["columns"], row)) for row in r["rows"]]
    return out


@app.get("/api/case/{cid}")
def case_detail(cid: str) -> dict:
    return _case_detail(get_db(), cid)


ALLOWED_LABELS = {"Account", "Merchant", "Device", "Ip", "Txn", "Policy", "Runbook", "Team", "Incident", "Case", "Action"}


def _nb_query(gname: str, label: str, direction: str) -> str:
    """direction 'out': (n)-[r]->(m)   direction 'in': (n)<-[r]-(m)"""
    arrow = "]->(m)" if direction == "out" else "]<-(m)"
    return f"MATCH (n:{label} {{name: $name}})-[r{arrow} RETURN type(r) AS rel, m.name AS to_name, labels(m) AS to_labels LIMIT 60"


@app.get("/api/graph/around/{label}/{name}")
def around(label: str, name: str) -> dict:
    if label not in ALLOWED_LABELS:
        return JSONResponse({"error": "unknown label"}, status_code=400)
    if not re.match(r"^[A-Z0-9][A-Z0-9._-]{0,31}$", name):
        return JSONResponse({"error": "invalid name"}, status_code=400)
    db = get_db()
    gname = cfg.case_graph if label in ("Case", "Action") else cfg.main_graph

    nodes: dict[str, dict] = {name: {"name": name, "labels": [label]}}
    edges: list[dict] = []
    neighbors: list[dict] = []

    def add_edge(src: str, dst: str, rel: str) -> None:
        if src != dst and src in nodes and dst in nodes:
            edges.append({"from": src, "to": dst, "rel": rel})

    def add_node(nm: str, labels_list) -> None:
        if nm and nm not in nodes:
            lbl = labels_list[0] if isinstance(labels_list, list) and labels_list else "Node"
            nodes[nm] = {"name": nm, "labels": [lbl]}

    # depth 1 (both directions)
    for d in ("out", "in"):
        res = db.query(gname, _nb_query(gname, label, d), {"name": name})
        for row in res["rows"]:
            rel, to_name, to_labels = row
            if not to_name or to_name == name:
                continue
            add_node(to_name, to_labels)
            if d == "out":
                add_edge(name, to_name, rel)
            else:
                add_edge(to_name, name, rel)
            if len(neighbors) < 24 and to_name not in [x["name"] for x in neighbors]:
                neighbors.append({"name": to_name, "label": (to_labels[0] if isinstance(to_labels, list) and to_labels else "Node")})

    # depth 2 from a bounded set of neighbors
    for nb in neighbors[:16]:
        for d in ("out", "in"):
            res = db.query(gname, _nb_query(gname, nb["label"], d), {"name": nb["name"]})
            for row in res["rows"]:
                rel, to_name, to_labels = row
                if not to_name:
                    continue
                add_node(to_name, to_labels)
                if d == "out":
                    add_edge(nb["name"], to_name, rel)
                else:
                    add_edge(to_name, nb["name"], rel)
                if len(nodes) > 180:
                    break
            if len(nodes) > 180:
                break
        if len(nodes) > 180:
            break

    seen: set[tuple] = set()
    uniq_edges = []
    for e in edges:
        key = (e["from"], e["to"], e["rel"])
        if key not in seen:
            seen.add(key)
            uniq_edges.append(e)
    return {"center": nodes[name], "nodes": list(nodes.values()), "edges": uniq_edges[:400]}


@app.get("/api/memories")
def memories(user: str = "demo") -> dict:
    gname = cfg.memory_graph(re.sub(r"[^a-z0-9]", "", user.lower()) or "demo")
    res = get_db().query(
        gname,
        "MATCH (m:Memory) RETURN m.kind AS kind, m.title AS title, m.content AS content, m.ts AS ts, m.case AS case, m.confidence AS confidence ORDER BY m.ts DESC LIMIT 100",
    )
    return {"memories": [dict(zip(res["columns"], row)) for row in res["rows"]]}
