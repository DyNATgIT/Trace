"""End-to-end smoke test WITHOUT a live FalkorDB.

A stateful FakeDB answers the exact queries the mock agents issue and records
all writes, so we can assert on the case graph / memory graph state after a
full investigation+audit run — the same code path a real DB exercises.

Run:  python3 tests/test_smoke.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.agent.orchestrator import handle_message  # noqa: E402
from backend.config import cfg  # noqa: E402
from backend.data.generate import RING_A, RING_B  # noqa: E402

POLICY_ROWS = [
    ["POL-101", "Card Testing Response", "5+ failed authorizations from one IP within 1 hour", "Freeze + block IP + escalate to card-security."],
    ["POL-102", "Device Reuse Review", "3+ distinct accounts on one device", "Review; freeze and link into one case if high-value/funding overlap."],
    ["POL-103", "Mule Chain Protocol", "funding chain 2+ hops reaching an external account within 24h", "Freeze the chain, file SAR."],
    ["POL-104", "High Value Velocity", "$3,000+ completed retail spend within 24h", "Manual review before freeze."],
    ["POL-200", "Escalation Gate", "case risk score >= 70", "Escalate to fraud-ops; every action must cite its policy."],
    ["POL-210", "Customer Communication", "any account freeze", "Notify customer within 24h."],
]



class FakeDB:
    """Stateful stand-in for DB: canned bank answers + real state for cases/memory."""

    def __init__(self):
        self.cases: dict[str, dict] = {}
        self.flags: dict[str, list] = {}
        self.actions: dict[str, list] = []
        self.audits: dict[str, list] = {}
        self.cited: dict[str, list] = {}
        self.memories: dict[str, list] = {}
        self.writes: list[tuple[str, str]] = []

    # ------------------------------------------------------------------ query
    def query(self, gname: str, q: str, params=None, timeout_ms=None):
        params = params or {}
        self.writes.append((gname, q))

        def ok(rows, columns):
            return {"columns": columns, "rows": rows, "ms": 0.4}

        subj = params.get("n") or params.get("a") or (re.search(r"name: '([A-E]-\d+)'", q) or [None, None])[1]
        ring_a = subj in RING_A
        ring_b = subj in RING_B

        if gname == cfg.main_graph:
            if "OPTIONAL MATCH (t)-[:ON_DEVICE]" in q:
                if ring_a:
                    return ok([[11, 9432.77, 857.52, 1399.99, 11, 11]], ["txns", "total_spend", "avg_txn", "max_txn", "device_txns", "ip_txns"])
                if ring_b:
                    return ok([[7, 402.11, 57.44, 179.99, 7, 7]], ["txns", "total_spend", "avg_txn", "max_txn", "device_txns", "ip_txns"])
                return ok([[14, 2210.4, 157.89, 399.5, 14, 14]], ["txns", "total_spend", "avg_txn", "max_txn", "device_txns", "ip_txns"])
            if "WHERE t.status = 'FAILED' RETURN count(t) AS failed" in q:
                return ok([[5]] if ring_b else [[0]], ["failed"])
            if "dd.name AS device" in q:
                if ring_a:
                    members = [a for a in RING_A if a != subj]
                    return ok([[a, ["D-901", "D-902", "D-903"][i % 3], 3 + i % 3] for i, a in enumerate(members[:7])], ["account", "device", "shared_txns"])
                if ring_b:
                    members = [a for a in RING_B if a != subj]
                    return ok([[a, f"D-90{4 + i % 3}", 2 + i % 2] for i, a in enumerate(members[:7])], ["account", "device", "shared_txns"])
                return ok([], ["account", "device", "shared_txns"])
            if "ip.name AS ip" in q:
                if ring_a:
                    members = [a for a in RING_A if a != subj]
                    return ok([[a, "185.220.101.14" if i % 2 else "185.220.101.15", 2 + i % 2] for i, a in enumerate(members[:5])], ["account", "ip", "shared_txns"])
                if ring_b:
                    members = [a for a in RING_B if a != subj]
                    return ok([[a, "91.215.85.6" if i % 2 else "91.215.85.7", 2] for i, a in enumerate(members[:5])], ["account", "ip", "shared_txns"])
                return ok([], ["account", "ip", "shared_txns"])
            if "m1.name AS hop1" in q:
                if ring_a:
                    return ok(
                        [["A-1200", "E-9002", "external", 512.4, 1450.2], ["A-1201", "E-9003", "external", 480.0, 990.5]],
                        ["hop1", "hop2", "hop2_tier", "in_amt", "out_amt"],
                    )
                return ok([], ["hop1", "hop2", "hop2_tier", "in_amt", "out_amt"])
            if "fails >= 3" in q:
                if ring_b:
                    return ok([["91.215.85.6", 30, 6.0], ["91.215.85.7", 30, 6.0]], ["ip", "fails", "span_hours"])
                return ok([], ["ip", "fails", "span_hours"])
            if "algo.pageRank" in q:
                return ok([["E-9001", 0.131], ["A-1200", 0.094], ["A-1201", 0.091], ["A-1202", 0.09], ["A-1203", 0.089], ["A-1204", 0.088]], ["name", "score"])
            if "algo.SPpaths" in q or "shortestPath" in q:
                if ring_a:
                    return ok([[["A-1042", "TXN-00045", "D-901", "TXN-00052", "A-1043"], ["MADE", "ON_DEVICE", "ON_DEVICE", "MADE"], None]], ["path_nodes", "path_rels", "weight"])
                return ok([], ["path_nodes", "path_rels", "weight"])
            if "p.code AS code, p.name AS name, p.threshold AS threshold" in q:
                return ok(POLICY_ROWS, ["code", "name", "threshold", "summary"])
            if "p.threshold AS threshold, p.summary AS summary, r.name AS runbook" in q:
                rows = [r + [None, None] for r in POLICY_ROWS]
                return ok(rows, ["code", "name", "threshold", "summary", "runbook", "team"])
            if "i:Incident" in q:
                return ok(
                    [["INC-2026-014", "2026-03-12", "Device ring of 9 accounts draining electronics merchants.", "POL-102"],
                     ["INC-2026-027", "2026-06-02", "Card-testing burst targeting travel merchants.", "POL-101"],
                     ["INC-2026-031", "2026-07-19", "Mule chain to 2 external accounts; SAR filed.", "POL-103"]],
                    ["incident", "date", "summary", "policy"],
                )
            return ok([], [])

        if gname == cfg.case_graph:
            if "SUBJECT_IS" in q and "RETURN c.id" in q:
                subj = params.get("n")
                for c in self.cases.values():
                    if c.get("subject") == subj:
                        return ok([[c["id"]]], ["id"])
                return ok([], ["id"])
            if "count(c) AS n" in q:
                return ok([[len(self.cases)]], ["n"])
            if "c.id AS id, c.subject AS subject" in q:
                return ok([[c["id"], c["subject"], c["status"], c["risk_score"], c.get("audit_verdict")] for c in self.cases.values()], ["id", "subject", "status", "risk", "verdict"])
            if q.strip().endswith("RETURN c"):
                cid = params.get("id")
                c = self.cases.get(cid)
                if c:
                    return ok([[{"__node__": True, **c}]], ["c"])
                return ok([], ["c"])
            if "FLAGS]->(a:Account) RETURN a.name" in q:
                cid = params.get("id")
                return ok([[f["account"], f["reason"]] for f in self.flags.get(cid, [])], ["account", "reason"])
            if "OPTIONAL MATCH (a)-[:CITES]->(p:Policy)" in q:
                cid = params.get("id")
                return ok([[a["type"], a["target"], a["reason"], a.get("cited")] for a in self.actions.get(cid, [])], ["type", "target", "reason", "cited_policy"])
            if "count(DISTINCT b) AS linked_accounts" in q:
                target = params.get("name")
                linked = 7 if (target in RING_A or target in RING_B) else 0
                return ok([[linked, 2 if linked else 0]], ["linked_accounts", "shared_devices"])
            if "c.id AS id, c.subject AS subject" in q:
                return ok([[c["id"], c["subject"], c["status"], c["risk_score"], c.get("audit_verdict")] for c in self.cases.values()], ["id", "subject", "status", "risk", "verdict"])
            return ok([], [])

        # memory graphs
        if "WHERE m.case" in q:
            n = sum(1 for m in self.memories.get(gname, []) if m.get("case") == params.get("c") and m.get("kind") == "episodic")
            return ok([[n]], ["n"])
        if "RETURN m.kind AS kind" in q:
            return ok([[m["kind"], m["title"], m["content"], m["ts"], m.get("case"), m.get("confidence")] for m in self.memories.get(gname, [])], ["kind", "title", "content", "ts", "case", "confidence"])
        return ok([], [])

    # ----------------------------------------------------------------- execute
    def execute(self, gname: str, q: str, params=None) -> None:
        params = params or {}
        self.writes.append((gname, q))
        if gname == cfg.case_graph:
            if "CREATE (c:Case" in q:
                self.cases[params["id"]] = {
                    "id": params["id"], "subject": params["s"], "status": "open", "risk_score": 0,
                    "created": params["now"], "updated": params["now"], "hypothesis": None, "summary": None,
                }
            elif "SUBJECT_IS" in q and "CREATE" in q:
                if params["id"] in self.cases:
                    self.cases[params["id"]]["subject"] = params["s"]
            elif "SET" in q and "c.risk_score" in q:
                c = self.cases.get(params["id"])
                if c:
                    for k in ("hypothesis", "summary", "status"):
                        if k in params:
                            c[k] = params[k]
                    if "risk_score" in params:
                        c["risk_score"] = params["risk_score"]
                    c["updated"] = params.get("updated")
            elif "FLAGS" in q and "MERGE" in q:
                self.flags.setdefault(params["id"], []).append({"account": params["a"], "reason": params["reason"], "ts": params["ts"]})
            elif "CREATE (ac:Action" in q:
                self.actions.setdefault(params["id"], []).append({
                    "type": params["type"], "target": params["target"], "reason": params["reason"],
                    "by": params["by"], "ts": params["ts"], "cited": None,
                })
            elif "CITES" in q and params.get("p"):
                if "ac:Action" in q:  # action-level citation
                    for cid2 in self.actions:
                        for a in self.actions[cid2]:
                            if a["target"] == params.get("t") and a["type"] == params.get("ty"):
                                a["cited"] = params["p"]
                else:  # case-level citation
                    self.cited.setdefault(params.get("id") or "", []).append(params["p"])
            elif "CREATE (an:AuditNote" in q:
                self.audits.setdefault(params["id"], []).append({"verdict": params["verdict"], "text": params["text"], "ts": params["ts"]})
                if params["id"] in self.cases:
                    self.cases[params["id"]]["status"] = "audited"
                    self.cases[params["id"]]["audit_verdict"] = params["verdict"]
        else:
            if "CREATE (m:Memory" in q:
                self.memories.setdefault(gname, []).append({
                    "kind": params["kind"], "title": params["t"], "content": params["c2"],
                    "ts": params["now"], "case": params.get("c"), "confidence": params.get("conf"),
                })

    def health(self):
        return {"ok": True, "fake": True}


# --------------------------------------------------------------------------- tests
def run_case(label: str, fdb: FakeDB, user: str, message: str) -> list:
    events = list(handle_message(fdb, user, message))
    kinds = [e["type"] for e in events]
    print(f"--- {label}")
    print(f"    events: {len(events)}  kinds: {sorted(set(kinds))}")
    finals = [e["text"][:110].replace("\n", " ⏎ ") for e in events if e["type"] == "final"]
    for f in finals:
        print(f"    final[{len(finals)}]: {f}")
    return events


def main() -> int:
    failures: list[str] = []

    def check(name: str, cond: bool, detail: str = ""):
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
        if not cond:
            failures.append(name)

    fdb = FakeDB()

    # ---- 1. full investigation + audit of the device ring
    ev = run_case("investigate A-1042 (ring A)", fdb, "demo", "Investigate account A-1042")
    kinds = [e["type"] for e in ev]
    check("investigation streams role events", kinds.count("role") == 2, f"roles={kinds.count('role')}")
    check("investigation has tool calls", kinds.count("tool_call") >= 12, f"tool_calls={kinds.count('tool_call')}")
    cases = list(fdb.cases)
    check("a case was created", len(cases) == 1, f"cases={cases}")
    cid = cases[0] if cases else None
    c = fdb.cases.get(cid, {})
    check("case risk >= 70 for ring", (c.get("risk_score") or 0) >= 70, f"risk={c.get('risk_score')}")
    check("case flagged >= 5 accounts", len(fdb.flags.get(cid, [])) >= 5, f"flags={len(fdb.flags.get(cid, []))}")
    acts = fdb.actions.get(cid, [])
    check("freeze action taken", any(a["type"] == "freeze" for a in acts), f"actions={[a['type'] for a in acts]}")
    check("all actions policy-cited", all(a.get("cited") for a in acts) and len(acts) > 0, f"actions={[(a['type'], a.get('cited')) for a in acts]}")
    check("escalation to fraud-ops", any(a["type"] == "escalate" for a in acts))
    check("audit note written (auditor agent)", len(fdb.audits.get(cid, [])) == 1, f"audits={fdb.audits.get(cid)}")
    check("audit verdict approved", fdb.audits.get(cid, [{}])[0].get("verdict") == "approved", f"verdict={fdb.audits.get(cid, [{}])[0].get('verdict')}")
    check("case status audited", c.get("status") == "audited", f"status={c.get('status')}")
    mems = fdb.memories.get(f"mem_{ 'demo' }", [])
    check("episodic memory persisted", any(m["kind"] == "episodic" for m in mems), f"mems={[(m['kind']) for m in mems]}")
    check("semantic memory persisted", any(m["kind"] == "semantic" for m in mems))

    # ---- 2. card-testing ring
    ev = run_case("investigate A-1100 (ring B / card testing)", fdb, "demo", "Investigate A-1100 — why so many failed transactions?")
    c2 = list(fdb.cases.values())[1]
    check("second case created", list(fdb.cases)[1] != cid, f"cases={list(fdb.cases)}")
    check("ring B risk >= 70", (c2.get("risk_score") or 0) >= 70, f"risk={c2.get('risk_score')}")
    acts2 = fdb.actions.get(c2["id"], [])
    check("ring B freeze cites POL-101", any(a["type"] == "freeze" and a.get("cited") == "POL-101" for a in acts2), f"actions={[(a['type'], a.get('cited')) for a in acts2]}")

    # ---- 3. innocent account
    ev = run_case("investigate A-1001 (innocent)", fdb, "demo", "Investigate A-1001")
    c3 = list(fdb.cases.values())[2]
    check("innocent risk < 50", (c3.get("risk_score") or 0) < 50, f"risk={c3.get('risk_score')}")
    acts3 = fdb.actions.get(c3["id"], [])
    check("innocent -> clear, no freeze", any(a["type"] == "clear" for a in acts3) and not any(a["type"] == "freeze" for a in acts3), f"actions={[a['type'] for a in acts3]}")
    check("innocent case not flagged", len(fdb.flags.get(c3["id"], [])) == 0)

    # ---- 4. cross-session memory (same user, "new session")
    ev = run_case("memory recall (same user)", fdb, "demo", "What do you remember from previous investigations?")
    text = " ".join(e["text"] for e in ev if e["type"] == "final")
    check("recall mentions a previous case", "C-00" in text, f"final={text[:120]}")

    # ---- 5. tenant isolation: another user has no memory
    ev = run_case("other user has empty memory", fdb, "fraudops", "What do you remember from previous investigations?")
    text = " ".join(e["text"] for e in ev if e["type"] == "final")
    check("fraudops memory is empty (isolation)", "empty" in text.lower(), f"final={text[:120]}")

    # ---- 6. consultant: policy question
    ev = run_case("policy question (consultant)", fdb, "demo", "Which policy applies when 3 accounts share one device?")
    text = " ".join(e["text"] for e in ev if e["type"] == "final")
    check("policy answer cites POL-102", "POL-102" in text, f"final={text[:150]}")

    # ---- 7. consultant: incidents
    ev = run_case("incident question (consultant)", fdb, "demo", "What similar incidents happened before, and which policies were applied?")
    text = " ".join(e["text"] for e in ev if e["type"] == "final")
    check("incident answer cites INC-2026-014", "INC-2026-014" in text, f"final={text[:150]}")

    # ---- 8. read-only guard
    from backend.agent.tools import RunCtx, execute_tool
    ctx = RunCtx(db=fdb, user="demo", role="consultant", case_id=None, subject=None, task="t", mode="mock")
    bad = execute_tool("cypher", {"query": "MATCH (a:Account) DETACH DELETE a"}, ctx)
    check("write query blocked by read-only guard", not bad.get("ok"), f"res={bad}")
    bad2 = execute_tool("cypher", {"query": "CREATE (x:Evil)"}, ctx)
    check("CREATE blocked", not bad2.get("ok"))

    print()
    if failures:
        print(f"SMOKE TEST FAILED: {len(failures)} failure(s): {failures}")
        return 1
    print("ALL SMOKE TESTS PASSED ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
