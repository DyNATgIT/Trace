"""Deterministic mock agents.

Same tool loop, same tools, same graph — but the "LLM" is a scripted plan
that reasons off the actual tool results. Guarantees a full end-to-end demo
with zero model infrastructure, and doubles as a regression oracle for the
tool layer. Swap in Ollama/OpenAI via LLM_MODE for the real agent.
"""
from __future__ import annotations

import re

from ..llm import LLMResponse, ToolCall


class MockLLM:
    def __init__(self, role: str, ctx):
        self.role = role
        self.ctx = ctx
        self._plan: dict | None = None

    # ------------------------------------------------------------- helpers
    def _call(self, name: str, args: dict, thought: str) -> LLMResponse:
        return LLMResponse(content=thought, tool_calls=[ToolCall(id=f"mock_{len(self.ctx.results)}", name=name, args=args)])

    def _rows(self, i: int) -> list:
        if i < len(self.ctx.results):
            return self.ctx.results[i][1].get("rows") or []
        return []

    def _uniq(self, rows: list, col: int = 0) -> list:
        out = []
        for r in rows:
            if col < len(r) and r[col] and r[col] not in out:
                out.append(r[col])
        return out

    def chat(self, messages, tools) -> LLMResponse:
        if self.role == "investigator":
            return self._investigate()
        if self.role == "auditor":
            return self._audit()
        return self._consult()

    # ------------------------------------------------------- investigator
    def _investigate(self) -> LLMResponse:
        r = self.ctx.results
        n = self.ctx.subject

        if len(r) == 0:
            return self._call(
                "cypher",
                {
                    "query": (
                        f"MATCH (a:Account {{name: '{n}'}})-[:MADE]->(t:Txn) "
                        "OPTIONAL MATCH (t)-[:ON_DEVICE]->(d:Device) "
                        "OPTIONAL MATCH (t)-[:FROM_IP]->(i:Ip) "
                        "RETURN count(t) AS txns, round(sum(t.amount), 2) AS total_spend, round(avg(t.amount), 2) AS avg_txn, "
                        "max(t.amount) AS max_txn, count(d) AS device_txns, count(i) AS ip_txns"
                    ),
                    "purpose": "90-day profile: volume, spend, device/IP footprint",
                },
                f"Start with the 90-day profile of {n}: volume, spend, and footprint. One account rarely tells the whole story — the neighbors do.",
            )
        if len(r) == 1:
            return self._call(
                "cypher",
                {"query": f"MATCH (a:Account {{name: '{n}'}})-[:MADE]->(t:Txn) WHERE t.status = 'FAILED' RETURN count(t) AS failed", "purpose": "failed-authorization count"},
                "Now the failure rate — the key discriminator between card testing and normal usage.",
            )
        if len(r) == 2:
            return self._call(
                "cypher",
                {
                    "query": (
                        f"MATCH (a:Account {{name: '{n}'}})-[:MADE]->(t:Txn)-[:ON_DEVICE]->(dd:Device)<-[:ON_DEVICE]-(t2:Txn)<-[:MADE]-(b:Account) "
                        f"WHERE b.name <> '{n}' RETURN b.name AS account, dd.name AS device, count(t2) AS shared_txns "
                        "ORDER BY shared_txns DESC LIMIT 12"
                    ),
                    "purpose": "other accounts sharing this account's devices",
                },
                "Follow the hardware: who else transacts from the same devices?",
            )
        if len(r) == 3:
            return self._call(
                "cypher",
                {
                    "query": (
                        f"MATCH (a:Account {{name: '{n}'}})-[:MADE]->(t:Txn)-[:FROM_IP]->(ip:Ip)<-[:FROM_IP]-(t2:Txn)<-[:MADE]-(b:Account) "
                        f"WHERE b.name <> '{n}' RETURN b.name AS account, ip.name AS ip, count(t2) AS shared_txns "
                        "ORDER BY shared_txns DESC LIMIT 12"
                    ),
                    "purpose": "other accounts sharing this account's IPs",
                },
                "Same question on the network layer: shared IPs (weaker signal — residential lines are shared legitimately).",
            )
        if len(r) == 4:
            return self._call(
                "cypher",
                {
                    "query": (
                        f"MATCH (s:Account {{name: '{n}'}})-[f1:FUNDS]->(m1:Account)-[f2:FUNDS]->(x:Account) "
                        "RETURN m1.name AS hop1, x.name AS hop2, x.tier AS hop2_tier, f1.amount AS in_amt, f2.amount AS out_amt LIMIT 15"
                    ),
                    "purpose": "2-hop funding chains (mule pattern)",
                },
                "Follow the money: 2-hop funding chains. Chains that exit to tier=external within a day are the mule signature.",
            )
        if len(r) == 5:
            return self._call(
                "cypher",
                {
                    "query": (
                        f"MATCH (a:Account {{name: '{n}'}})-[:MADE]->(t0:Txn)-[:FROM_IP]->(ip:Ip) "
                        "WITH DISTINCT ip "
                        "MATCH (ip)<-[:FROM_IP]-(t:Txn) WHERE t.status = 'FAILED' "
                        "WITH ip, count(t) AS fails, min(t.time) AS first_t, max(t.time) AS last_t "
                        "WHERE fails >= 3 RETURN ip.name AS ip, fails, round((last_t - first_t) * 24, 1) AS span_hours "
                        "ORDER BY fails DESC LIMIT 8"
                    ),
                    "purpose": "failed-authorization bursts on this account's own IPs (card-testing signature)",
                },
                "Check the card-testing signature: failed-authorization bursts on this account's own IPs.",
            )
        if len(r) == 6:
            return self._call(
                "algo",
                {"name": "pagerank", "label": "Account", "rel": "FUNDS"},
                "Run PageRank over the FUNDS flow — graph algorithm as a tool — to surface hub accounts (seeders/mules).",
            )
        if len(r) == 7:
            top = self._uniq(self._rows(2))
            if top:
                return self._call(
                    "algo",
                    {"name": "sppaths", "label": "Account", "node": n, "node2": top[0], "rels": ["MADE", "ON_DEVICE", "FROM_IP", "AT", "FUNDS"], "max_len": 8},
                    f"Show the concrete shortest path from {n} to the most-linked suspect {top[0]} — the evidence the auditor will re-verify.",
                )
            return self._call(
                "cypher",
                {"query": "MATCH (p:Policy) RETURN p.code AS code, p.name AS name, p.threshold AS threshold, p.summary AS summary", "purpose": "policy library"},
                "No linked suspects surfaced. Load the policy library to document the negative finding against thresholds.",
            )
        if len(r) == 8:
            self._plan = self._compute_plan(n)
            p = self._plan
            return self._call(
                "case_set",
                {"hypothesis": p["hypothesis"], "risk_score": p["risk"], "summary": p["summary"], "status": "concluded"},
                "Evidence is in. Record hypothesis, risk score and summary on the case node — shared state the auditor will read from the graph.",
            )
        k = len(r) - 9
        post = self._plan["post"]
        if k < len(post):
            step = post[k]
            return self._call(step["tool"], step["args"], step["thought"])
        return LLMResponse(content=self._plan["final"])

    def _compute_plan(self, n: str) -> dict:
        r = self.ctx.results
        prof = (self._rows(0) or [{}])[0]
        failed = int((self._rows(1) or [[0]])[0][0])
        dev_accounts = self._uniq(self._rows(2))
        ip_accounts = self._uniq(self._rows(3))
        funds = self._rows(4)
        ct = self._rows(5)
        pr = self._rows(6)

        txns = max(1, int(prof.get("txns") or 1))
        total_spend = float(prof.get("total_spend") or 0)
        fail_ratio = failed / txns
        external_exit = next((row for row in funds if len(row) > 2 and row[2] == "external"), None)
        mule = next((row for row in funds if len(row) > 0 and row[0]), None)
        pr_top = pr[0][0] if pr else None

        risk = 15
        if dev_accounts:
            risk += 30
        if external_exit:
            risk += 30
        if ct and (dev_accounts or fail_ratio > 0.3):
            risk += 15
        if fail_ratio > 0.3:
            risk += 15
        if total_spend > 3000 and dev_accounts:
            risk += 5
        risk = min(95, risk)

        ring = bool(dev_accounts) or bool(ct)
        is_ct = bool(ct) and fail_ratio > 0.25
        policy_main = "POL-101" if is_ct else ("POL-102" if dev_accounts else None)
        incident = "INC-2026-027" if is_ct else ("INC-2026-014" if dev_accounts else ("INC-2026-031" if external_exit else None))

        if ring:
            pattern = (
                f"coordinated ring around {n}: {len(dev_accounts)} accounts share its devices"
                + (f" and {len(ip_accounts)} share its IPs" if ip_accounts else "")
                + (f"; funding exits to {external_exit[1]} (tier=external) via {external_exit[0]}" if external_exit else "")
                + (f"; card-testing burst of {ct[0][1]} failed auths in {ct[0][2]}h on {ct[0][0]}" if is_ct else "")
            )
            hypothesis = (
                f"{pattern.capitalize()}. Matches {policy_main} threshold"
                + (", POL-103 mule-chain threshold" if external_exit else "")
                + "."
            )
            summary = (
                f"{n}: {txns} txns, ${total_spend:,.2f} total, {failed} failed ({fail_ratio:.0%}). "
                f"Shared devices expose {len(dev_accounts)} linked accounts. "
                + (f"Funding chain reaches external account {external_exit[1]}. " if external_exit else "")
                + f"Risk {risk}/100."
            )
        else:
            hypothesis = (
                f"No ring signals for {n}: no shared devices, failure rate {fail_ratio:.0%} within normal band"
                + (f", funding activity {funds[0][0]} -> {funds[0][1]} looks like ordinary transfers" if funds else "")
                + "."
            )
            summary = f"{n}: {txns} txns, ${total_spend:,.2f} total, {failed} failed. Unique device/IP footprint. Risk {risk}/100 — below action gate."

        post: list[dict] = []
        if ring:
            flags = (dev_accounts or ip_accounts)[:8]
            reason = (
                f"links {n} to {len(flags)} accounts via shared devices/IPs"
                + (" and funding chain to external account" if external_exit else "")
            )
            post.append({
                "tool": "case_flag",
                "args": {"accounts": flags, "reason": reason, "policy": policy_main or "POL-102"},
                "thought": f"Flag the linked accounts on the case, citing {policy_main or 'POL-102'} — flags are shared state, not chat messages.",
            })
            if risk >= 70:
                post.append({
                    "tool": "act",
                    "args": {"type": "freeze", "target": n, "reason": f"Risk {risk}/100: {summary}", "policy": policy_main or "POL-102"},
                    "thought": f"Risk {risk} >= 70 gate (POL-200) and {policy_main or 'POL-102'} authorizes it: freeze {n}.",
                })
                if external_exit:
                    post.append({
                        "tool": "act",
                        "args": {"type": "freeze", "target": external_exit[1], "reason": f"External exit of mule chain ({mule[0]} -> {external_exit[1]})", "policy": "POL-103"},
                        "thought": f"POL-103 mule-chain protocol: also freeze the external exit {external_exit[1]}.",
                    })
                post.append({
                    "tool": "act",
                    "args": {"type": "escalate", "target": f"case {self.ctx.case_id}", "reason": f"Risk {risk}/100, {len(flags)} linked accounts, external exit involved" if external_exit else f"Risk {risk}/100, {len(flags)} linked accounts", "policy": "POL-200"},
                    "thought": "Escalate per POL-200 escalation gate — fraud-ops takes it from the case graph.",
                })
        else:
            post.append({
                "tool": "act",
                "args": {"type": "clear", "target": n, "reason": f"Risk {risk}/100 is below the POL-200 action gate; no shared infrastructure found", "policy": "POL-200"},
                "thought": "Below the action gate — record a clear decision on the case (still policy-cited, still auditable).",
            })

        post.append({
            "tool": "memory_write",
            "args": {
                "kind": "episodic",
                "title": f"Case {self.ctx.case_id}: {n} -> risk {risk}, {'ring confirmed' if ring else 'cleared'}",
                "content": f"Investigated {n} on {self.ctx.user}'s session. {summary} Flags: {', '.join((dev_accounts or ip_accounts)[:8]) or 'none'}. Actions: freeze/escalate per {policy_main or 'POL-200'}.",
                "confidence": 0.9,
            },
            "thought": "Write episodic memory — the next session starts with this context instead of a blank slate.",
        })
        if ring:
            sig = (
                "Card-testing burst (5+ failed auths/IP in <1h) followed by successful harvest purchases"
                if is_ct
                else "Device sharing (3+ accounts, one device) + funding chain to external account within 1 day"
            )
            post.append({
                "tool": "memory_write",
                "args": {
                    "kind": "semantic",
                    "title": "Reusable signal: " + ("card testing = failed burst then harvest" if is_ct else "device reuse + external exit = ring"),
                    "content": f"Learned from case {self.ctx.case_id}: {sig} is the strongest single indicator in this dataset. IP sharing alone is weak (legitimate sharing).",
                    "confidence": 0.85,
                },
                "thought": "Write semantic memory: the detection signal itself, reusable across cases and users' agents.",
            })

        if ring:
            actions_txt = "\n".join(
                [f"- **FREEZE {n}** — citing {policy_main or 'POL-102'} (threshold met, risk {risk}/100)"]
                + ([f"- **FREEZE {external_exit[1]}** — citing POL-103 (external exit of mule chain via {mule[0]})"] if external_exit else [])
                + [f"- **ESCALATE case {self.ctx.case_id} to fraud-ops** — citing POL-200 (risk >= 70)"]
            )
            findings = [
                f"{txns} txns / ${total_spend:,.2f} total / {failed} failed ({fail_ratio:.0%})",
                f"shared devices expose {len(dev_accounts)} linked accounts: {', '.join(dev_accounts[:5])}" if dev_accounts else "no shared devices",
            ]
            if is_ct:
                findings.append(f"card-testing burst: {ct[0][1]} failed auths in {ct[0][2]}h from {ct[0][0]}")
            if external_exit:
                findings.append(f"funding chain: {n} -> {mule[0]} -> {external_exit[1]} (external) within 1 day")
            if pr_top:
                findings.append(f"PageRank over FUNDS: top hub is {pr_top}")
            final = (
                f"## Investigation complete — {n}\n\n"
                f"**Risk score: {risk}/100 — ring suspected**\n\n"
                f"**Findings**\n" + "\n".join(f"- {x}" for x in findings) + "\n\n"
                f"**Actions taken** (every one policy-cited)\n{actions_txt}\n\n"
                f"**Hypothesis (recorded on case {self.ctx.case_id})**: {hypothesis}\n\n"
                f"**Sources**: {', '.join(filter(None, [policy_main, 'POL-103' if external_exit else None, 'POL-200']))}"
                + (f"; precedent {incident} (similar pattern, historical incident node)" if incident else "")
                + "\n\nMemory saved — a future session will open with this context. The auditor will now re-derive everything from the case graph alone."
            )
        else:
            final = (
                f"## Investigation complete — {n}\n\n"
                f"**Risk score: {risk}/100 — below action gate (POL-200)**\n\n"
                f"**Findings**\n- {txns} txns / ${total_spend:,.2f} total / {failed} failed ({fail_ratio:.0%})\n"
                f"- unique device/IP footprint, no funding chain to external accounts\n\n"
                f"**Actions taken**\n- **CLEAR {n}** — citing POL-200 (risk below gate; no freeze)\n\n"
                f"**Sources**: POL-200\n\nMemory saved. The auditor will verify the negative finding from the case graph."
            )
        return {"hypothesis": hypothesis, "risk": risk, "summary": summary, "post": post, "final": final, "ring": ring}

    # ---------------------------------------------------------------- auditor
    def _audit(self) -> LLMResponse:
        r = self.ctx.results
        cid = self.ctx.case_id

        if len(r) == 0:
            return self._call(
                "cypher",
                {"query": f"MATCH (c:Case {{id: '{cid}'}}) RETURN c", "graph": "cases", "purpose": "read case state from the graph"},
                "I did not see the investigation — only the graph. Read the case node first.",
            )
        if len(r) == 1:
            return self._call(
                "cypher",
                {"query": f"MATCH (c:Case {{id: '{cid}'}})-[f:FLAGS]->(a:Account) RETURN a.name AS account, f.reason AS reason", "graph": "cases", "purpose": "flags + reasons"},
                "Now the flagged accounts and the reasons recorded on the FLAGS edges.",
            )
        if len(r) == 2:
            return self._call(
                "cypher",
                {
                    "query": (
                        f"MATCH (c:Case {{id: '{cid}'}})-[t:TOOK]->(a:Action) OPTIONAL MATCH (a)-[:CITES]->(p:Policy) "
                        "RETURN a.type AS type, a.target AS target, a.reason AS reason, p.code AS cited_policy"
                    ),
                    "graph": "cases",
                    "purpose": "actions + policy citations",
                },
                "And the actions — every one must cite an authorizing policy.",
            )
        if len(r) == 3:
            flags = self._uniq(self._rows(1))
            target = flags[0] if flags else self.ctx.subject
            if target:
                return self._call(
                    "cypher",
                    {
                        "query": (
                            f"MATCH (a:Account {{name: '{target}'}})-[:MADE]->(t:Txn)-[:ON_DEVICE]->(d:Device)<-[:ON_DEVICE]-(t2:Txn)<-[:MADE]-(b:Account) "
                            f"WHERE b.name <> '{target}' RETURN count(DISTINCT b) AS linked_accounts, count(DISTINCT d) AS shared_devices"
                        ),
                        "purpose": f"spot-check flagged account {target} against the bank graph",
                    },
                    f"Spot-check {target} directly against the bank graph — I do not trust the case's numbers without checking at least one.",
                )
            return self._verdict_step(spot_rows=[])
        if len(r) == 4:
            self._audit_data = self._verdict_data()
            spot = self._rows(3)
            target = self._uniq(self._rows(1))
            target = target[0] if target else self.ctx.subject
            spot_txt = f"{spot[0][0]} linked accounts via {spot[0][1]} shared devices" if spot else "no shared-device links"
            verdict = self._audit_data["verdict"]
            return self._call(
                "audit_note",
                {"text": self._audit_data["text"], "verdict": verdict},
                f"Verdict: {verdict}. Spot-check of {target}: {spot_txt}. Record it on the case node.",
            )
        return LLMResponse(content=self._audit_data["final"])

    def _verdict_data(self) -> dict:
        case_node = ((self._rows(0) or [{}])[0])
        if isinstance(case_node, dict) and "__node__" in case_node:
            pass
        elif isinstance(case_node, dict):
            case_node = case_node
        flags = self._rows(1)
        actions = self._rows(2)
        risk = case_node.get("risk_score") if isinstance(case_node, dict) else None
        freeze_taken = any(a[0] == "freeze" for a in actions if a)
        cited_ok = all(len(a) > 3 and a[3] for a in actions) if actions else True
        spot = self._rows(3)
        spot_linked = int(spot[0][0]) if spot and spot[0] and spot[0][0] is not None else 0
        subject = self.ctx.subject
        consistent = True
        if spot:
            if risk is not None and risk >= 70 and spot_linked == 0 and self._uniq(self._rows(1)):
                consistent = False
        approved = (
            risk is not None
            and (risk >= 70) == freeze_taken
            and cited_ok
            and consistent
        )
        verdict = "approved" if approved else "needs_review"
        target = (self._uniq(self._rows(1)) or [subject] or ["?"])[0]
        spot_txt = f"{spot_linked} linked accounts via {spot[0][1]} shared devices" if spot else "no shared-device links"
        text = (
            f"Case {self.ctx.case_id} audited from graph state only. risk_score={risk}, hypothesis recorded, "
            f"{len(flags)} flags, {len(actions)} actions — all policy-cited: {cited_ok}. "
            f"Spot-check {target}: {spot_txt} — consistent with flags: {consistent}. "
            f"Verdict {verdict}: case is reproducible from the shared graph state." if approved else
            f"Case {self.ctx.case_id}: risk={risk}, {len(actions)} actions, citations complete: {cited_ok}, "
            f"spot-check {target}: {spot_txt}. Verdict {verdict}: see note."
        )
        final = (
            f"## Audit opinion — case {self.ctx.case_id}\n\n**Verdict: {verdict.upper()}**\n\n"
            f"- Read case state from the `cases` graph (risk score, hypothesis, flags, actions) — I never saw the investigation chat.\n"
            f"- Verified every action cites an authorizing policy: **{'yes' if cited_ok else 'NO'}**.\n"
            f"- Spot-checked {target} against the `bank` graph: {spot_txt}.\n"
            f"- Consistency between recorded risk ({risk}) and taken actions (freeze: {freeze_taken}): **{'yes' if (risk is not None and (risk >= 70) == freeze_taken) else 'NO'}**.\n\n"
            f"The case file is {'fully reproducible from graph state — audit passed.' if approved else 'not fully reproducible — see the audit note on the case node.'}"
        )
        return {"verdict": verdict, "text": text, "final": final, "risk": risk, "cited_ok": cited_ok}

    def _verdict_step(self, spot_rows: list) -> LLMResponse:
        self._audit_data = self._verdict_data()
        return self._call(
            "audit_note",
            {"text": self._audit_data["text"], "verdict": self._audit_data["verdict"]},
            f"Record verdict {self._audit_data['verdict']} on the case node.",
        )

    # -------------------------------------------------------------- consultant
    def _consult(self) -> LLMResponse:
        r = self.ctx.results
        task = self.ctx.task

        if len(r) == 0:
            return self._call("memory_search", {"query": task}, "First, check my memory — I may have learned this in an earlier session.")
        if len(r) == 1:
            if re.search(r"incident|past|before|similar", task, re.I):
                return self._call(
                    "cypher",
                    {"query": "MATCH (i:Incident) OPTIONAL MATCH (i)-[:APPLIED]->(p:Policy) RETURN i.name AS incident, i.date AS date, i.summary AS summary, p.code AS policy", "purpose": "historical incidents + policies applied"},
                    "Pull the incident history — precedents live in the graph, not in my head.",
                )
            if re.search(r"polic|threshold|rule|applies", task, re.I) or re.search(r"device reuse|card test|mule|velocity|escalat", task, re.I):
                return self._call(
                    "cypher",
                    {
                        "query": (
                            "MATCH (p:Policy) OPTIONAL MATCH (p)-[:PRESCRIBES]->(r:Runbook) OPTIONAL MATCH (p)-[:OWNED_BY]->(t:Team) "
                            "RETURN p.code AS code, p.name AS name, p.threshold AS threshold, p.summary AS summary, r.name AS runbook, t.name AS team"
                        ),
                        "purpose": "policy library with runbooks and owning teams",
                    },
                    "Ground the answer in the policy library.",
                )
            return self._call(
                "cypher",
                {"query": "MATCH (c:Case) RETURN c.id AS id, c.subject AS subject, c.status AS status, c.risk_score AS risk, c.audit_verdict AS verdict ORDER BY c.updated DESC LIMIT 10", "graph": "cases", "purpose": "case log"},
                "Pull the case log from the shared case graph.",
            )
        mems = r[0][1].get("results") or []
        rows = r[1][1].get("rows") or []
        cols = r[1][1].get("columns") or []

        if re.search(r"remember|learn|previous|last session|earlier", task, re.I) or (mems and not rows):
            if mems:
                items = "\n".join(f"- [{m['kind']}] **{m['title']}** — {m['content'][:200]}" for m in mems[:4])
                src = ", ".join(m["title"] for m in mems[:4])
            else:
                items = "- (memory is empty — no previous sessions for this user yet)"
                src = "memory graph (empty)"
            return LLMResponse(content=f"## What I remember\n\n{items}\n\n**Sources**: {src} (persistent memory graph, FalkorDB multigraph — isolated per user)")
        if rows and cols:
            if cols[0] == "code":
                relevant = [row for row in rows if any(re.search(c, " ".join(str(x) for x in row), re.I) for c in re.findall(r"[a-z]{5,}", task.lower()))] or rows[:3]
                items = "\n".join(
                    f"- **{row[0]} {row[1]}** — threshold: {row[2]}. {row[3]}" + (f" Runbook: {row[4]}. Owner: {row[5]}." if len(row) > 5 and row[4] else "")
                    for row in relevant
                )
                src = ", ".join(row[0] for row in relevant)
                return LLMResponse(content=f"## Answer\n\n{items}\n\n**Sources**: {src} (policy graph)")
            items = "\n".join("- " + " | ".join(str(x) for x in row if x is not None) for row in rows[:8])
            src = cols[0]
            return LLMResponse(content=f"## Answer\n\n{items}\n\n**Sources**: {src} graph")
        return LLMResponse(content="## Answer\n\nI found nothing in memory or the graph that answers this. Try asking about policies, incidents, or a specific account.")
