"""The posture graph: policy -> NIST 800-53 -> MITRE ATT&CK.

Backs the Blast Radius view. NetworkX is used rather than a graph database
because the whole graph is a few thousand edges built from one SQL query -- it
fits in memory many times over, and a service would add operational weight for
no capability.

Every node carries the UUID that backs it where one exists, so clicking a node
in the UI resolves to the same OSCAL object a citation would.
"""
from __future__ import annotations

import sqlite3
from typing import Any

import networkx as nx


def build_graph(conn: sqlite3.Connection, run_id: str) -> nx.DiGraph:
    """Build the full posture graph for a run."""
    graph = nx.DiGraph()

    rows = conn.execute(
        """SELECT c.id AS control_id, c.scuba_id, c.product, c.group_name, c.criticality,
                  c.statement, f.uuid AS finding_uuid, f.oscal_status,
                  r.uuid AS risk_uuid, r.score, r.unverified
           FROM controls c
           LEFT JOIN findings f ON f.control_id = c.id AND f.run_id = ?
           LEFT JOIN risks    r ON r.control_id = c.id AND r.run_id = ?
           WHERE f.uuid IS NOT NULL OR r.uuid IS NOT NULL""",
        (run_id, run_id),
    ).fetchall()

    for row in rows:
        graph.add_node(
            f"policy:{row['scuba_id']}",
            kind="policy",
            label=row["scuba_id"],
            product=row["product"],
            group=row["group_name"],
            criticality=row["criticality"],
            status=row["oscal_status"] or "unverified",
            finding_uuid=row["finding_uuid"],
            risk_uuid=row["risk_uuid"],
            risk_score=row["score"],
            statement=row["statement"],
        )

    links = conn.execute(
        """SELECT l.target_type, l.target_id, l.target_name, c.scuba_id
           FROM control_links l JOIN controls c ON c.id = l.control_id"""
    ).fetchall()

    for link in links:
        policy_node = f"policy:{link['scuba_id']}"
        if policy_node not in graph:
            continue  # control not assessed in this run
        kind = "nist" if link["target_type"] == "nist80053" else "attack"
        target_node = f"{kind}:{link['target_id']}"
        if target_node not in graph:
            graph.add_node(
                target_node,
                kind=kind,
                label=link["target_id"],
                title=link["target_name"] or "",
            )
        graph.add_edge(policy_node, target_node, rel=kind)

    return graph


def blast_radius(
    conn: sqlite3.Connection, run_id: str, *, focus: str | None = None, failing_only: bool = True
) -> dict[str, Any]:
    """Return nodes and edges for the graph view.

    `focus` accepts a policy ID, a NIST control or an ATT&CK technique and
    narrows the graph to that node's immediate neighbourhood. Without a focus,
    the default is failing policies only -- the full 126-policy graph is
    unreadable and, more importantly, buries the failures among the passes.
    """
    graph = build_graph(conn, run_id)

    if focus:
        key = focus.strip().upper()
        matches = [
            n
            for n, d in graph.nodes(data=True)
            if d.get("label", "").upper() == key or n.upper().endswith(f":{key}")
        ]
        if not matches:
            return {"focus": focus, "nodes": [], "edges": [], "error": f"no node matching {focus}"}
        keep: set[str] = set()
        for node in matches:
            keep.add(node)
            keep.update(graph.predecessors(node))
            keep.update(graph.successors(node))
        subgraph = graph.subgraph(keep)
    elif failing_only:
        failing = {
            n
            for n, d in graph.nodes(data=True)
            if d.get("kind") == "policy" and d.get("status") == "not-satisfied"
        }
        keep = set(failing)
        for node in failing:
            keep.update(graph.successors(node))
        subgraph = graph.subgraph(keep)
    else:
        subgraph = graph

    return {
        "focus": focus,
        "node_count": subgraph.number_of_nodes(),
        "edge_count": subgraph.number_of_edges(),
        "nodes": [{"id": n, **d} for n, d in sorted(subgraph.nodes(data=True))],
        "edges": [
            {"source": u, "target": v, **d} for u, v, d in sorted(subgraph.edges(data=True))
        ],
    }
