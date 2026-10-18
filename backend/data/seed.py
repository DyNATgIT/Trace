"""Seed FalkorDB with the synthetic bank + knowledge graph.

Idempotent: wipes and rebuilds the `bank` graph every run.
Uses batched UNWIND imports (the pattern from FalkorDB's import docs) and
creates range indexes on the keys the agent queries by.
"""
from __future__ import annotations

from ..config import cfg
from ..db import DB
from .generate import generate

BATCH = 100


def _clear(db: DB, name: str) -> None:
    db.execute(name, "MATCH (n) DETACH DELETE n")


def _batched(rows: list[dict], fn) -> None:
    for i in range(0, len(rows), BATCH):
        fn(rows[i : i + BATCH])


def _nodes(db: DB, graph: str, label: str, rows: list[dict], cols: list[tuple[str, str]]) -> None:
    mapping = ", ".join(f"{c}: row.{k}" for k, c in cols)
    q = f"UNWIND $rows AS row CREATE (n:{label} {{{mapping}}})"
    _batched(rows, lambda chunk: db.execute(graph, q, {"rows": chunk}))


def _rels(db: DB, graph: str, rel: str, rows: list[dict], src: tuple[str, str], dst: tuple[str, str], props: list[str] | None = None) -> None:
    """src/dst: (label, key_property). rows must contain the keys under the names given in row refs."""
    prop_map = f" {{{', '.join(f'{p}: row.{p}' for p in props)}}}" if props else ""
    q = (
        f"UNWIND $rows AS row "
        f"MATCH (a:{src[0]} {{{src[1]}: row.{src[1]}}}), (b:{dst[0]} {{{dst[1]}: row.{dst[1]}}}) "
        f"CREATE (a)-[r:{rel}{prop_map}]->(b)"
    )
    _batched(rows, lambda chunk: db.execute(graph, q, {"rows": chunk}))


def seed(force: bool = True) -> dict:
    db = DB()
    ds = generate(seed=42)
    G = cfg.main_graph

    if force:
        _clear(db, G)

    # ---- entities -------------------------------------------------------------
    _nodes(db, G, "Account", ds.accounts, [("name", "name"), ("tier", "tier"), ("opened", "opened")])
    _nodes(db, G, "Merchant", ds.merchants, [("name", "name"), ("category", "category")])
    _nodes(db, G, "Device", ds.devices, [("name", "name"), ("kind", "kind")])
    _nodes(db, G, "Ip", ds.ips, [("name", "name")])
    _nodes(db, G, "Txn", ds.txns, [("id", "id"), ("time", "time"), ("amount", "amount"), ("status", "status")])

    # ---- payment relationships (Txn keyed by id) --------------------------------
    _rels(db, G, "MADE", ds.made, ("Account", "account"), ("Txn", "txn"))
    _rels(db, G, "ON_DEVICE", ds.on_device, ("Txn", "txn"), ("Device", "device"))
    _rels(db, G, "FROM_IP", ds.from_ip, ("Txn", "txn"), ("Ip", "ip"))
    _rels(db, G, "AT", ds.at, ("Txn", "txn"), ("Merchant", "merchant"))
    _rels(db, G, "FUNDS", ds.funds, ("Account", "from"), ("Account", "to"), props=["amount", "time"])

    # ---- knowledge layer (company brain) ------------------------------------------
    _nodes(db, G, "Policy", ds.policies, [("name", "name"), ("code", "code"), ("threshold", "threshold"), ("summary", "summary")])
    _nodes(db, G, "Runbook", ds.runbooks, [("name", "name"), ("steps", "steps")])
    _nodes(db, G, "Team", ds.teams, [("name", "name")])
    _nodes(db, G, "Incident", ds.incidents, [("name", "name"), ("date", "date"), ("summary", "summary")])
    _rels(db, G, "PRESCRIBES", ds.policy_runbook, ("Policy", "p"), ("Runbook", "r"))
    _rels(db, G, "OWNED_BY", ds.policy_team, ("Policy", "p"), ("Team", "t"))
    _rels(db, G, "APPLIED", ds.incident_policy, ("Incident", "i"), ("Policy", "p"))

    # ---- indexes --------------------------------------------------------------------
    for _, name, label, prop in [
        ("bank", "idx_account_name", "Account", "name"),
        ("bank", "idx_merchant_name", "Merchant", "name"),
        ("bank", "idx_device_name", "Device", "name"),
        ("bank", "idx_ip_name", "Ip", "name"),
        ("bank", "idx_txn_id", "Txn", "id"),
        ("bank", "idx_policy_code", "Policy", "code"),
    ]:
        try:
            db.execute(G, f"CREATE RANGE INDEX {name} IF NOT EXISTS FOR (n:{label}) ON (n.{prop})")
        except Exception as e:  # noqa: BLE001
            print(f"  (index {name} skipped: {str(e)[:80]})")

    stats = db.query(G, "MATCH (n) RETURN labels(n) AS l, count(*) AS c")
    counts = {row[0][0]: row[1] for row in stats["rows"]}
    return {"graphs": [G], "nodes": counts, "stats": ds.stats()}


if __name__ == "__main__":
    import json

    print("seeding FalkorDB...")
    out = seed()
    print(json.dumps(out, indent=2))
    print("done.")
