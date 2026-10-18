"""Agent tools — the only way agents touch FalkorDB.

`cypher` is strictly read-only (guard below); all writes flow through the
purpose-built tools (case_set, case_flag, act, audit_note, memory_write),
which is what makes the case graph an auditable, shared state channel.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from ..config import cfg
from ..db import DB

LABELS = {"Account", "Merchant", "Device", "Ip", "Txn", "Policy", "Runbook", "Team", "Incident", "Case", "Action", "Memory"}
REL_TYPES = {"MADE", "ON_DEVICE", "FROM_IP", "AT", "FUNDS", "FLAGS", "TOOK", "CITES", "SUBJECT_IS", "PRESCRIBES", "OWNED_BY", "APPLIED", "AUDIT"}
SAFE_NAME = re.compile(r"^[A-Z0-9][A-Z0-9._-]{0,31}$")

_READ_ONLY_FIRST = re.compile(r"^\s*(MATCH|CALL|UNWIND|RETURN|WITH)\b", re.I)
_FORBIDDEN = re.compile(r"\b(CREATE|DELETE|SET|REMOVE|MERGE|FOREACH|CALL\s+db\.|DETACH)\b", re.I)
_ALLOWED_CALL = re.compile(r"^\s*CALL\s+algo\.(pageRank|SPpaths|wcc)\b", re.I)


@dataclass
class RunCtx:
    """Per-agent-run context. `results` records (tool, data) in call order —
    the MockLLM drives its plan off this, and it doubles as the run trace."""

    db: DB
    user: str
    role: str
    case_id: str | None
    subject: str | None
    task: str
    mode: str
    results: list[tuple[str, dict]] = field(default_factory=list)


# --------------------------------------------------------------------------- schemas
def _f(name: str, desc: str, params: dict, required: list[str]) -> dict:
    return {"type": "function", "function": {"name": name, "description": desc, "parameters": {"type": "object", "properties": params, "required": required}}}


TOOLS = [
    _f(
        "cypher",
        "Run a READ-ONLY Cypher query. graph: 'bank' (payments + knowledge) or 'cases' (case state). MATCH/CALL only — no writes.",
        {
            "query": {"type": "string", "description": "Cypher query"},
            "purpose": {"type": "string", "description": "one line: why this query"},
            "graph": {"type": "string", "enum": ["bank", "cases"], "description": "default bank"},
        },
        ["query"],
    ),
    _f(
        "algo",
        "Graph algorithms. name='pagerank' (label, rel) ranks nodes by flow (e.g. FUNDS hubs); name='sppaths' finds the shortest connecting path between two nodes of the same label.",
        {
            "name": {"type": "string", "enum": ["pagerank", "sppaths"]},
            "label": {"type": "string", "description": "node label, e.g. Account"},
            "rel": {"type": "string", "description": "relationship type for pagerank, e.g. FUNDS"},
            "node": {"type": "string", "description": "sppaths: source node name"},
            "node2": {"type": "string", "description": "sppaths: target node name"},
            "rels": {"type": "array", "items": {"type": "string"}, "description": "sppaths: relationship types to traverse"},
            "max_len": {"type": "integer", "description": "sppaths: max hops (default 12)"},
        },
        ["name"],
    ),
    _f(
        "memory_search",
        "Search this user's persistent memory (previous sessions). Returns ranked memory entries.",
        {"query": {"type": "string"}, "kind": {"type": "string", "enum": ["episodic", "semantic", "procedural"]}},
        ["query"],
    ),
    _f(
        "memory_write",
        "Persist a memory for future sessions. kind: episodic (what happened), semantic (a learned fact/signal), procedural (how to do something).",
        {"kind": {"type": "string", "enum": ["episodic", "semantic", "procedural"]},
         "title": {"type": "string"}, "content": {"type": "string"},
         "confidence": {"type": "number", "description": "0..1"}},
        ["kind", "title", "content"],
    ),
    _f(
        "case_set",
        "Update the current case node (shared state visible to all agents). risk_score 0-100.",
        {
            "hypothesis": {"type": "string"},
            "risk_score": {"type": "integer"},
            "summary": {"type": "string"},
            "status": {"type": "string", "enum": ["open", "investigating", "concluded"]},
        },
        [],
    ),
    _f(
        "case_flag",
        "Flag suspect accounts on the current case (creates FLAGS edges with the reason + cited policy).",
        {
            "accounts": {"type": "array", "items": {"type": "string"}, "description": "account names"},
            "reason": {"type": "string"},
            "policy": {"type": "string", "description": "policy code, e.g. POL-102"},
        },
        ["accounts", "reason"],
    ),
    _f(
        "act",
        "Take a case action. type: freeze | escalate | flag | clear. MUST cite the policy that authorizes it.",
        {
            "type": {"type": "string", "enum": ["freeze", "escalate", "flag", "clear"]},
            "target": {"type": "string", "description": "account name or 'case <id>'"},
            "reason": {"type": "string"},
            "policy": {"type": "string", "description": "citing policy code"},
        },
        ["type", "target", "reason", "policy"],
    ),
    _f(
        "audit_note",
        "Auditor only: attach an audit note + verdict to the case.",
        {"text": {"type": "string"}, "verdict": {"type": "string", "enum": ["approved", "needs_review"]}},
        ["text", "verdict"],
    ),
    _f(
        "finish",
        "End the run. Provide the final answer/report to the user.",
        {"summary": {"type": "string"}},
        ["summary"],
    ),
]

TOOL_NAMES = {t["function"]["name"] for t in TOOLS}


# --------------------------------------------------------------------------- executors
def _rows_or_error(res: dict) -> dict:
    out = {"ok": True, "columns": res["columns"], "rows": res["rows"][:50], "ms": res["ms"]}
    if not res["rows"]:
        out["note"] = "no rows"
    return out


def tool_cypher(args: dict, ctx: RunCtx) -> dict:
    q = (args.get("query") or "").strip().rstrip(";")
    if not q:
        return {"ok": False, "error": "empty query"}
    if not _READ_ONLY_FIRST.match(q):
        return {"ok": False, "error": "query must start with MATCH/CALL/UNWIND/RETURN/WITH (read-only)"}
    if _FORBIDDEN.search(q):
        return {"ok": False, "error": "write keywords are not allowed in the read-only cypher tool; use the purpose-built tools"}
    if re.match(r"^\s*CALL\b", q, re.I) and not _ALLOWED_CALL.match(q):
        return {"ok": False, "error": "only CALL algo.pageRank / algo.SPpaths / algo.wcc are permitted"}
    graph = "bank" if (args.get("graph") or "bank") == "bank" else "cases"
    gname = cfg.main_graph if graph == "bank" else cfg.case_graph
    res = ctx.db.query(gname, q)
    return _rows_or_error(res)


def tool_algo(args: dict, ctx: RunCtx) -> dict:
    name = (args.get("name") or "").lower()
    label = args.get("label") or "Account"
    if label not in LABELS:
        return {"ok": False, "error": f"unknown label {label}"}
    try:
        if name == "pagerank":
            rel = args.get("rel")
            rel_lit = f"'{rel}'" if rel in REL_TYPES else "null"
            label_lit = f"'{label}'"
            q = f"CALL algo.pageRank({label_lit}, {rel_lit}) YIELD node, score RETURN node.name AS name, round(score, 4) AS score ORDER BY score DESC LIMIT 15"
            return _rows_or_error(ctx.db.query(cfg.main_graph, q))
        if name == "sppaths":
            n1, n2 = args.get("node") or "", args.get("node2") or ""
            if not SAFE_NAME.match(n1) or not SAFE_NAME.match(n2):
                return {"ok": False, "error": "node names must match [A-Z0-9._-]+"}
            rels = [r for r in (args.get("rels") or []) if r in REL_TYPES] or ["MADE", "ON_DEVICE", "FROM_IP", "AT"]
            max_len = max(2, min(20, int(args.get("max_len") or 12)))
            rels_lit = json.dumps(rels)
            q = (
                f"MATCH (a:{label} {{name: '{n1}'}}), (b:{label} {{name: '{n2}'}}) "
                f"CALL algo.SPpaths({{'sourceNode': a, 'targetNode': b, 'relTypes': {rels_lit}, 'relDirection': 'both', 'maxLen': {max_len}}}) "
                f"YIELD path, pathWeight "
                f"RETURN [n IN nodes(path) | n.name] AS path_nodes, [r IN relationships(path) | type(r)] AS path_rels, pathWeight AS weight LIMIT 3"
            )
            res = ctx.db.query(cfg.main_graph, q)
            if not res["rows"]:
                # graceful fallback to plain Cypher shortestPath
                q2 = (
                    f"MATCH p = shortestPath((a:{label} {{name: '{n1}'}})-[*..{max_len}]-(b:{label} {{name: '{n2}'}})) "
                    f"RETURN [n IN nodes(p) | n.name] AS path_nodes, [r IN relationships(p) | type(r)] AS path_rels LIMIT 3"
                )
                res = ctx.db.query(cfg.main_graph, q2)
                res["note"] = "algo.SPpaths returned no path; fell back to Cypher shortestPath"
            return _rows_or_error(res)
        return {"ok": False, "error": f"unknown algorithm '{name}'"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:300]}


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).strip()


def tool_memory_search(args: dict, ctx: RunCtx) -> dict:
    gname = cfg.memory_graph(ctx.user)
    res = ctx.db.query(gname, "MATCH (m:Memory) RETURN m.kind AS kind, m.title AS title, m.content AS content, m.ts AS ts, m.case AS case, m.confidence AS confidence ORDER BY m.ts DESC LIMIT 300")
    qwords = [w for w in _norm(args.get("query", "")).split() if len(w) > 2]
    kind = args.get("kind")
    scored = []
    all_rows: list = []
    for row in res["rows"]:
        kind_, title, content, ts, case, conf = row
        if kind and kind_ != kind:
            continue
        all_rows.append(row)
        text = _norm(title + " " + content)
        score = sum(2.0 if w in _norm(title).split() else 1.0 for w in qwords if w in text.split())
        if score:
            scored.append((score, ts, row))
    scored.sort(key=lambda x: (-x[0], -x[1]))
    if scored:
        top = [{"kind": r[0], "title": r[1], "content": r[2], "ts": r[3], "case": r[4], "score": round(s, 1)} for s, _, r in scored[:5]]
        return {"ok": True, "results": top, "note": f"{len(top)} of {len(all_rows)} memories matched"}
    # recency fallback: no keyword hits -> most recent memories (a "what do you remember?" style query)
    top = [{"kind": r[0], "title": r[1], "content": r[2], "ts": r[3], "case": r[4], "score": 0} for r in all_rows[:5]]
    return {"ok": True, "results": top, "note": f"no keyword matches — returning {len(top)} most recent memories" if top else "no matching memories"}


def tool_memory_write(args: dict, ctx: RunCtx) -> dict:
    gname = cfg.memory_graph(ctx.user)
    q = (
        "CREATE (m:Memory {kind: $kind, title: $title, content: $content, ts: $ts, case: $case, confidence: $conf}) "
        "RETURN m.title AS title"
    )
    ctx.db.execute(gname, q, {
        "kind": args.get("kind") or "semantic",
        "title": (args.get("title") or "untitled")[:140],
        "content": (args.get("content") or "")[:900],
        "ts": round(time.time(), 3),
        "case": ctx.case_id,
        "conf": float(args.get("confidence") or 0.8),
    })
    return {"ok": True, "stored": args.get("title"), "graph": gname}


def _require_case(ctx: RunCtx) -> str | None:
    if not ctx.case_id:
        raise ValueError("no active case for this run")
    return ctx.case_id


def tool_case_set(args: dict, ctx: RunCtx) -> dict:
    cid = _require_case(ctx)
    sets, params = [], {"id": cid, "updated": round(time.time(), 3)}
    for k in ("hypothesis", "summary", "status"):
        if args.get(k) is not None:
            sets.append(f"c.{k} = ${k}")
            params[k] = str(args[k])[:600]
    if args.get("risk_score") is not None:
        sets.append("c.risk_score = $risk_score")
        params["risk_score"] = max(0, min(100, int(args["risk_score"])))
    sets.append("c.updated = $updated")
    q = f"MATCH (c:Case {{id: $id}}) SET {', '.join(sets)} RETURN c.id AS id"
    ctx.db.execute(cfg.case_graph, q, params)
    return {"ok": True, "case": cid, "updated": [s.split(" = ")[0] for s in sets]}


def tool_case_flag(args: dict, ctx: RunCtx) -> dict:
    cid = _require_case(ctx)
    ts = round(time.time(), 3)
    flagged = []
    for acct in args.get("accounts") or []:
        if not SAFE_NAME.match(acct or ""):
            continue
        ctx.db.execute(
            cfg.case_graph,
            "MATCH (c:Case {id: $id}), (a:Account {name: $a}) MERGE (c)-[f:FLAGS]->(a) SET f.reason = $reason, f.ts = $ts RETURN a.name AS n",
            {"id": cid, "a": acct, "reason": str(args.get("reason") or "")[:400], "ts": ts},
        )
        flagged.append(acct)
    policy = args.get("policy")
    if policy:
        ctx.db.execute(cfg.case_graph, "MATCH (c:Case {id: $id}), (p:Policy {code: $p}) MERGE (c)-[:CITES]->(p)", {"id": cid, "p": policy})
    return {"ok": True, "case": cid, "flagged": flagged, "cited_policy": policy}


def tool_act(args: dict, ctx: RunCtx) -> dict:
    cid = _require_case(ctx)
    ts = round(time.time(), 3)
    policy = args.get("policy") or ""
    q = (
        "MATCH (c:Case {id: $id}) "
        "CREATE (ac:Action {type: $type, target: $target, reason: $reason, by: $by, ts: $ts}) "
        "CREATE (c)-[:TOOK {ts: $ts, by: $by}]->(ac) "
        "RETURN ac.type AS type, ac.target AS target"
    )
    params = {"id": cid, "type": args.get("type"), "target": str(args.get("target") or "")[:80],
              "reason": str(args.get("reason") or "")[:500], "by": ctx.role, "ts": ts}
    res = ctx.db.execute(cfg.case_graph, q, params)
    if policy:
        ctx.db.execute(cfg.case_graph, "MATCH (ac:Action {target: $t, type: $ty}), (p:Policy {code: $p}) CREATE (ac)-[:CITES]->(p)", {"t": params["target"], "ty": params["type"], "p": policy})
    return {"ok": True, "action": {"type": args.get("type"), "target": params["target"], "policy": policy or None, "case": cid}}


def tool_audit_note(args: dict, ctx: RunCtx) -> dict:
    cid = _require_case(ctx)
    ts = round(time.time(), 3)
    q = (
        "MATCH (c:Case {id: $id}) "
        "CREATE (an:AuditNote {text: $text, verdict: $verdict, ts: $ts}) "
        "CREATE (c)-[:AUDIT]->(an) "
        "SET c.status = 'audited', c.audit_verdict = $verdict, c.updated = $ts "
        "RETURN an.verdict AS verdict"
    )
    ctx.db.execute(cfg.case_graph, q, {"id": cid, "text": str(args.get("text") or "")[:900], "verdict": args.get("verdict") or "needs_review", "ts": ts})
    return {"ok": True, "case": cid, "verdict": args.get("verdict")}


def tool_finish(args: dict, ctx: RunCtx) -> dict:
    return {"ok": True, "finished": True, "summary": (args.get("summary") or "")[:4000]}


EXECUTORS = {
    "cypher": tool_cypher,
    "algo": tool_algo,
    "memory_search": tool_memory_search,
    "memory_write": tool_memory_write,
    "case_set": tool_case_set,
    "case_flag": tool_case_flag,
    "act": tool_act,
    "audit_note": tool_audit_note,
    "finish": tool_finish,
}


def execute_tool(name: str, args: dict, ctx: RunCtx) -> dict:
    if name not in EXECUTORS:
        return {"ok": False, "error": f"unknown tool '{name}'"}
    try:
        return EXECUTORS[name](args or {}, ctx)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:300]}"}
