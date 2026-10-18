"""FalkorDB access layer.

All Cypher in the app goes through `DB.query`, which converts FalkorDB's
Node/Path/Edge objects into plain JSON-safe dicts so the agent (and the
frontend) can reason over results without knowing about driver types.
"""
from __future__ import annotations

import time
from typing import Any

import falkordb

from .config import cfg


def _convert_value(v: Any) -> Any:
    """Convert FalkorDB result values to JSON-safe structures."""
    if v is None or isinstance(v, (bool, int, str)):
        return v
    if isinstance(v, falkordb.Node):
        d = {"__node__": True, "id": v.id, "labels": list(v.labels or [])}
        d.update(_convert_props(v.properties))
        return d
    if isinstance(v, falkordb.Edge):
        d = {"__edge__": True, "id": getattr(v, "id", None), "type": getattr(v, "type", None) or getattr(v, "relationship_type", None)}
        d.update(_convert_props(v.properties))
        return d
    if isinstance(v, falkordb.Path):
        return {
            "__path__": True,
            "nodes": [_convert_value(n) for n in v.nodes],
            "edges": [_convert_value(e) for e in v.edges],
        }
    if isinstance(v, list):
        return [_convert_value(x) for x in v]
    if isinstance(v, dict):
        return {k: _convert_value(x) for k, x in v.items()}
    if isinstance(v, float):
        return round(v, 6)
    return str(v)


def _convert_props(props: Any) -> dict:
    out = {}
    for k, v in (props or {}).items():
        out[k] = _convert_value(v)
    return out


class DB:
    def __init__(self, host: str | None = None, port: int | None = None):
        self._client = falkordb.FalkorDB(
            host=host or cfg.falkordb_host,
            port=port or cfg.falkordb_port,
            password=cfg.falkordb_password,
        )
        self._graphs: dict[str, falkordb.Graph] = {}

    # -- graphs (multigraph: each name is fully isolated) --------------------
    def graph(self, name: str) -> falkordb.Graph:
        if name not in self._graphs:
            self._graphs[name] = self._client.select_graph(name)
        return self._graphs[name]

    def main(self) -> falkordb.Graph:
        return self.graph(cfg.main_graph)

    def cases(self) -> falkordb.Graph:
        return self.graph(cfg.case_graph)

    def memory(self, user: str) -> falkordb.Graph:
        return self.graph(cfg.memory_graph(user))

    # -- query ----------------------------------------------------------------
    def query(self, graph_name: str, q: str, params: dict | None = None, timeout_ms: int = 10000) -> dict:
        """Run a query; returns {'columns', 'rows', 'ms'} with JSON-safe rows."""
        t0 = time.time()
        res = self.graph(graph_name).query(q, params, timeout=timeout_ms)
        ms = (time.time() - t0) * 1000
        rows = [_convert_value(r) for r in res.result_set]
        return {"columns": [str(c) for c in res.header], "rows": rows, "ms": round(ms, 1)}

    def execute(self, graph_name: str, q: str, params: dict | None = None) -> None:
        """Write query (seed scripts / tool layer)."""
        self.graph(graph_name).query(q, params)

    # -- helpers ----------------------------------------------------------------
    def health(self) -> dict:
        try:
            self.query(cfg.main_graph, "RETURN 1 AS ok")
            return {"ok": True, "host": cfg.falkordb_host, "port": cfg.falkordb_port}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)[:200], "host": cfg.falkordb_host, "port": cfg.falkordb_port}
