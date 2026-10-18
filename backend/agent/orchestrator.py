"""Orchestrator: routes a chat message to the right agent flow.

- message names an account + asks to investigate  -> INVESTIGATOR -> AUDITOR
  (two agents that coordinate ONLY through the case graph)
- anything else (policies, memory, incidents, cases) -> CONSULTANT
"""
from __future__ import annotations

import re
import time

from ..config import cfg, resolve_llm_mode
from ..db import DB
from ..llm import make_llm
from .loop import run_agent
from .tools import RunCtx

ACCT_RE = re.compile(r"\b([A-E]-\d{3,6})\b")
CASE_RE = re.compile(r"\b(C-\d{2,6})\b")
INVESTIGATE_RE = re.compile(
    r"\b(investigat\w*|review|look into|examine|trace|flag|check|why|suspect\w*|fraud|ring|case|explain|what happened|is .* suspicious)\b", re.I
)


def _now() -> float:
    return round(time.time(), 3)


def _find_case(db: DB, subject: str) -> str | None:
    res = db.query(
        cfg.case_graph,
        "MATCH (c:Case)-[:SUBJECT_IS]->(a:Account {name: $n}) RETURN c.id AS id ORDER BY c.updated DESC LIMIT 1",
        {"n": subject},
    )
    return res["rows"][0][0] if res["rows"] else None


def _new_case_id(db: DB) -> str:
    res = db.query(cfg.case_graph, "MATCH (c:Case) RETURN count(c) AS n")
    return f"C-{(res['rows'][0][0] if res['rows'] else 0) + 1:04d}"


def _create_case(db: DB, subject: str) -> str:
    cid = _new_case_id(db)
    now = _now()
    db.execute(
        cfg.case_graph,
        "CREATE (c:Case {id: $id, subject: $s, status: 'open', risk_score: 0, created: $now, updated: $now})",
        {"id": cid, "s": subject, "now": now},
    )
    db.execute(cfg.case_graph, "MATCH (c:Case {id: $id}), (a:Account {name: $s}) CREATE (c)-[:SUBJECT_IS]->(a)", {"id": cid, "s": subject})
    return cid


def _case_props(db: DB, case_id: str) -> dict:
    res = db.query(cfg.case_graph, "MATCH (c:Case {id: $id}) RETURN c", {"id": case_id})
    row = res["rows"][0][0] if res["rows"] else {}
    return {k: v for k, v in (row or {}).items() if not k.startswith("__")}


def _auto_memory(db: DB, user: str, case_id: str, subject: str, case: dict) -> None:
    """Guaranteed episodic memory per concluded case (dedup on case id)."""
    g = cfg.memory_graph(user)
    res = db.query(g, "MATCH (m:Memory) WHERE m.case = $c AND m.kind = 'episodic' RETURN count(m) AS n", {"c": case_id})
    if res["rows"] and res["rows"][0][0]:
        return
    risk = case.get("risk_score")
    title = f"Case {case_id}: {subject} -> risk {risk}"
    content = (
        f"Investigated {subject}. Case {case_id}: status={case.get('status')}, risk={risk}, "
        f"hypothesis={case.get('hypothesis') or 'n/a'}. Verdict: {case.get('audit_verdict') or 'pending'}."
    )
    db.execute(
        g,
        "CREATE (m:Memory {kind: 'episodic', title: $t, content: $c2, ts: $now, case: $c, confidence: 0.9})",
        {"t": title[:140], "c2": content[:900], "now": _now(), "c": case_id},
    )


def handle_message(db: DB, user: str, message: str):
    """Generator of SSE events for one chat message."""
    mode = resolve_llm_mode()
    m = ACCT_RE.search(message)
    cm = CASE_RE.search(message)
    subject = m.group(1) if m else None
    wants_investigation = bool(cm) or bool(m and INVESTIGATE_RE.search(message))

    if subject and wants_investigation:
        case_id = _find_case(db, subject) or _create_case(db, subject)
        yield {"type": "meta", "case_id": case_id, "subject": subject, "mode": mode}

        ctx = RunCtx(db=db, user=user, role="investigator", case_id=case_id, subject=subject, task=message, mode=mode)
        for ev in run_agent(ctx, make_llm(mode, "investigator", ctx), cfg.max_agent_steps):
            yield ev
        yield {"type": "case_update", "case_id": case_id}

        ctx2 = RunCtx(db=db, user=user, role="auditor", case_id=case_id, subject=subject, task=f"Audit {case_id}", mode=mode)
        for ev in run_agent(ctx2, make_llm(mode, "auditor", ctx2), cfg.max_auditor_steps):
            yield ev

        _auto_memory(db, user, case_id, subject, _case_props(db, case_id))
        yield {"type": "case_update", "case_id": case_id}
        yield {"type": "done", "case_id": case_id}
    else:
        ctx = RunCtx(db=db, user=user, role="consultant", case_id=cm.group(1) if cm else None, subject=subject, task=message, mode=mode)
        yield {"type": "meta", "case_id": ctx.case_id, "subject": subject, "mode": mode}
        for ev in run_agent(ctx, make_llm(mode, "consultant", ctx), 10):
            yield ev
        yield {"type": "done"}
