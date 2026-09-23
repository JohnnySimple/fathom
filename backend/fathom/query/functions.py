"""The typed query layer.

This is a security boundary, not a convenience wrapper. The analyst has no
database handle, no filesystem access and no raw JSON -- it has these functions
and nothing else. Three properties are enforced here rather than requested of
the model:

1. **Every returned fact carries its OSCAL UUID.** A fact the model cannot cite
   is a fact it should not state, so the citation travels with the data instead
   of being reconstructed afterwards.
2. **Counts are computed in SQL, never by the model.** `posture_summary` returns
   totals the verifier can recompute identically.
3. **Nothing tenant-identifying is reachable.** Aliasing happened at parse time;
   there is no query here that could return a real tenant ID even if asked.

The verifier calls these same functions to re-check the model's claims, so
"grounded" means grounded in exactly the bytes the model was shown.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

MAX_ROWS = 50


class QueryLayer:
    """Read-only, typed access to one compiled run."""

    def __init__(self, conn: sqlite3.Connection, run_id: str) -> None:
        self.conn = conn
        self.run_id = run_id

    # ---------------------------------------------------------------- helpers
    def _rows(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def _one(self, sql: str, params: tuple = ()) -> dict[str, Any] | None:
        row = self.conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------ tools
    def posture_summary(self) -> dict[str, Any]:
        """Overall posture for the run: counts by state, criticality and product.

        Every number here is produced by SQL. The model may narrate these
        figures but may not compute its own, and the verifier recomputes each
        one before an answer quoting it is released.
        """
        run = self._one("SELECT * FROM runs WHERE id = ?", (self.run_id,))
        if not run:
            return {"error": f"unknown run {self.run_id}"}

        by_state = {
            r["state"]: r["n"]
            for r in self._rows(
                "SELECT state, COUNT(*) n FROM findings WHERE run_id=? GROUP BY state",
                (self.run_id,),
            )
        }
        shall_failures = self._one(
            """SELECT COUNT(*) n FROM findings
               WHERE run_id=? AND criticality='SHALL' AND oscal_status='not-satisfied'""",
            (self.run_id,),
        )
        should_failures = self._one(
            """SELECT COUNT(*) n FROM findings
               WHERE run_id=? AND criticality='SHOULD' AND oscal_status='not-satisfied'""",
            (self.run_id,),
        )
        unverified = self._one(
            "SELECT COUNT(*) n FROM risks WHERE run_id=? AND unverified=1", (self.run_id,)
        )

        per_product = self._rows(
            """SELECT product,
                      COUNT(*) total,
                      SUM(oscal_status='satisfied') passed,
                      SUM(oscal_status='not-satisfied') failed,
                      SUM(criticality='SHALL' AND oscal_status='not-satisfied') shall_failed
               FROM findings WHERE run_id=? GROUP BY product ORDER BY product""",
            (self.run_id,),
        )

        return {
            "run_id": self.run_id,
            "tenant_alias": run["tenant_alias"],
            "scanned_at": run["started_at"],
            "scubagear_version": run["scuba_version"],
            "oscal_artifacts_all_valid": bool(run["all_valid"]),
            "findings_total": sum(by_state.values()),
            "passed": by_state.get("pass", 0),
            "failed_shall": shall_failures["n"] if shall_failures else 0,
            "failed_should": should_failures["n"] if should_failures else 0,
            "unverified_manual": unverified["n"] if unverified else 0,
            "by_product": per_product,
            "note": (
                "unverified_manual policies have no automated check. They are "
                "neither passing nor failing and must not be described as either."
            ),
        }

    def list_findings(
        self,
        product: str | None = None,
        state: str | None = None,
        criticality: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        """List findings, each with the UUID required to cite it."""
        sql = [
            """SELECT f.uuid AS finding_uuid, f.policy_id, f.product, f.state,
                      f.oscal_status, f.criticality, c.statement, c.group_name,
                      f.observation_uuid, r.uuid AS risk_uuid, r.score AS risk_score
               FROM findings f
               JOIN controls c ON c.id = f.control_id
               LEFT JOIN risks r ON r.finding_uuid = f.uuid
               WHERE f.run_id = ?"""
        ]
        params: list[Any] = [self.run_id]
        if product:
            sql.append("AND f.product = ?")
            params.append(product.upper())
        if state:
            sql.append("AND f.state = ?")
            params.append(state.lower())
        if criticality:
            sql.append("AND f.criticality = ?")
            params.append(criticality.upper())
        sql.append("ORDER BY r.score DESC NULLS LAST, f.policy_id LIMIT ?")
        params.append(min(limit, MAX_ROWS))

        rows = self._rows(" ".join(sql), tuple(params))
        return {"count": len(rows), "findings": rows}

    def get_control(self, policy_id: str) -> dict[str, Any]:
        """Full detail for one SCuBA policy, including this run's result."""
        control = self._one(
            "SELECT * FROM controls WHERE UPPER(scuba_id) = UPPER(?) OR id = LOWER(?)",
            (policy_id.strip(), policy_id.strip()),
        )
        if not control:
            return {"error": f"no such policy: {policy_id}"}

        links = self._rows(
            """SELECT target_type, target_id, target_name FROM control_links
               WHERE control_id = ? ORDER BY target_type, target_id""",
            (control["id"],),
        )
        finding = self._one(
            """SELECT uuid AS finding_uuid, state, oscal_status, observation_uuid
               FROM findings WHERE run_id = ? AND control_id = ?""",
            (self.run_id, control["id"]),
        )
        risk = self._one(
            """SELECT uuid AS risk_uuid, status, score, score_breakdown, unverified
               FROM risks WHERE run_id = ? AND control_id = ?""",
            (self.run_id, control["id"]),
        )
        if risk and risk.get("score_breakdown"):
            risk["score_breakdown"] = json.loads(risk["score_breakdown"])

        return {
            "policy_id": control["scuba_id"],
            "oscal_control_id": control["id"],
            "product": control["product"],
            "group": control["group_name"],
            "statement": control["statement"],
            "criticality": control["criticality"],
            "rationale": control["rationale"],
            "nist_800_53": [l["target_id"] for l in links if l["target_type"] == "nist80053"],
            "attack_techniques": [
                {"id": l["target_id"], "name": l["target_name"]}
                for l in links
                if l["target_type"] == "attack"
            ],
            "result": finding
            or {"note": "no automated verdict for this policy in this run"},
            "risk": risk,
        }

    def controls_for_concept(self, text: str, limit: int = 10) -> dict[str, Any]:
        """Map a natural-language concept to relevant controls via full-text search.

        This is the one place where retrieval informs the answer, and it is
        deliberately limited to *control text* -- the requirement side. Posture
        facts never come from search; they come from the tables above. That
        split is what stops a semantically-similar chunk from being mistaken for
        evidence about this tenant.
        """
        query = _fts_query(text)
        if not query:
            return {"count": 0, "controls": [], "query": text}
        try:
            rows = self._rows(
                """SELECT f.control_id, f.scuba_id, f.statement, f.group_name,
                          c.product, c.criticality
                   FROM controls_fts f JOIN controls c ON c.id = f.control_id
                   WHERE controls_fts MATCH ?
                   ORDER BY rank LIMIT ?""",
                (query, min(limit, MAX_ROWS)),
            )
        except sqlite3.OperationalError:
            return {"count": 0, "controls": [], "query": text, "note": "unparseable search"}

        for row in rows:
            finding = self._one(
                """SELECT uuid AS finding_uuid, state, oscal_status
                   FROM findings WHERE run_id=? AND control_id=?""",
                (self.run_id, row["control_id"]),
            )
            row["result"] = finding or {"note": "not assessed in this run"}
        return {"count": len(rows), "controls": rows, "query": text}

    def nist_impact(self, policy_ids: list[str]) -> dict[str, Any]:
        """Which 800-53 controls are put at risk by the given failing policies."""
        if not policy_ids:
            return {"count": 0, "nist_controls": []}
        # Compared via UPPER() on both sides: uppercasing a policy ID in Python
        # would corrupt its version suffix (MS.AAD.3.1v1 -> MS.AAD.3.1V1).
        marks = ",".join("UPPER(?)" for _ in policy_ids)
        rows = self._rows(
            f"""SELECT l.target_id AS nist_control, l.target_name AS title,
                       c.scuba_id AS policy_id, f.uuid AS finding_uuid, f.oscal_status
                FROM control_links l
                JOIN controls c ON c.id = l.control_id
                LEFT JOIN findings f ON f.control_id = c.id AND f.run_id = ?
                WHERE l.target_type = 'nist80053' AND UPPER(c.scuba_id) IN ({marks})
                ORDER BY l.target_id""",
            (self.run_id, *[p.strip().upper() for p in policy_ids]),
        )
        grouped: dict[str, dict[str, Any]] = {}
        for row in rows:
            entry = grouped.setdefault(
                row["nist_control"],
                {"nist_control": row["nist_control"], "title": row["title"], "impacted_by": []},
            )
            entry["impacted_by"].append(
                {
                    "policy_id": row["policy_id"],
                    "finding_uuid": row["finding_uuid"],
                    "status": row["oscal_status"],
                }
            )
        return {"count": len(grouped), "nist_controls": sorted(grouped.values(), key=lambda g: g["nist_control"])}

    def attack_exposure(self, technique: str) -> dict[str, Any]:
        """Which failing policies leave a given ATT&CK technique unmitigated."""
        key = technique.strip().upper()
        # GROUP BY policy: a technique and its sub-techniques are separate link
        # rows, so an ungrouped query counts one policy several times and
        # inflates every figure the model would then quote.
        rows = self._rows(
            """SELECT c.scuba_id AS policy_id,
                      GROUP_CONCAT(DISTINCT l.target_id) AS technique_ids,
                      c.statement, c.criticality, c.product,
                      f.uuid AS finding_uuid, f.oscal_status, r.score AS risk_score
               FROM control_links l
               JOIN controls c ON c.id = l.control_id
               LEFT JOIN findings f ON f.control_id = c.id AND f.run_id = ?
               LEFT JOIN risks r ON r.control_id = c.id AND r.run_id = ?
               WHERE l.target_type='attack'
                 AND (UPPER(l.target_id) = ? OR UPPER(l.target_id) LIKE ?
                      OR UPPER(l.target_name) LIKE ?)
               GROUP BY c.scuba_id
               ORDER BY f.oscal_status, c.scuba_id""",
            (self.run_id, self.run_id, key, f"{key}.%", f"%{key}%"),
        )
        failing = [r for r in rows if r["oscal_status"] == "not-satisfied"]
        return {
            "technique_query": technique,
            "matched_policies": len(rows),
            "failing_policies": len(failing),
            "exposed_by": failing,
            "all_matches": rows,
        }

    def diff_runs(self, other_run_id: str) -> dict[str, Any]:
        """Compare this run with another, policy by policy."""
        current = {
            r["policy_id"]: r
            for r in self._rows(
                "SELECT policy_id, state, oscal_status, uuid FROM findings WHERE run_id=?",
                (self.run_id,),
            )
        }
        other = {
            r["policy_id"]: r
            for r in self._rows(
                "SELECT policy_id, state, oscal_status, uuid FROM findings WHERE run_id=?",
                (other_run_id,),
            )
        }
        if not other:
            return {"error": f"unknown or empty run {other_run_id}"}

        changed, fixed, regressed = [], [], []
        for policy_id in sorted(set(current) | set(other)):
            a, b = other.get(policy_id), current.get(policy_id)
            if not a or not b or a["oscal_status"] == b["oscal_status"]:
                continue
            entry = {
                "policy_id": policy_id,
                "from": a["oscal_status"],
                "to": b["oscal_status"],
                "finding_uuid": b["uuid"],
            }
            changed.append(entry)
            (fixed if b["oscal_status"] == "satisfied" else regressed).append(entry)

        return {
            "from_run": other_run_id,
            "to_run": self.run_id,
            "changed": len(changed),
            "fixed": fixed,
            "regressed": regressed,
            "only_in_current": sorted(set(current) - set(other)),
            "only_in_other": sorted(set(other) - set(current)),
        }

    def draft_poam(self, policy_ids: list[str] | None = None) -> dict[str, Any]:
        """Return the POA&M items already compiled for this run.

        Deliberately a read, not a generator. POA&M items were produced by the
        deterministic compiler from SHALL-level failures; the analyst may
        summarize them but cannot conjure new ones.
        """
        sql = """SELECT p.uuid AS poam_uuid, p.policy_id, p.title, p.status,
                        p.risk_uuid, p.finding_uuid, r.score AS risk_score,
                        r.score_breakdown
                 FROM poam_items p LEFT JOIN risks r ON r.uuid = p.risk_uuid
                 WHERE p.run_id = ?"""
        params: list[Any] = [self.run_id]
        if policy_ids:
            marks = ",".join("UPPER(?)" for _ in policy_ids)
            sql += f" AND UPPER(p.policy_id) IN ({marks})"
            params.extend(p.strip() for p in policy_ids)
        sql += " ORDER BY r.score DESC NULLS LAST, p.policy_id"

        rows = self._rows(sql, tuple(params))
        for row in rows:
            if row.get("score_breakdown"):
                row["score_breakdown"] = json.loads(row["score_breakdown"])
        return {"count": len(rows), "poam_items": rows}

    def resolve_uuid(self, uuid: str) -> dict[str, Any] | None:
        """Resolve any OSCAL UUID to the object it identifies.

        The verifier's primary tool: a citation that does not resolve here is a
        citation to something that does not exist.
        """
        # The run itself is citable. Aggregate claims ("14 SHALL policies are
        # failing") describe the whole run and have no single finding to point
        # at, so the run UUID is the honest citation for them.
        if uuid == self.run_id:
            row = self._one("SELECT * FROM runs WHERE id=?", (uuid,))
            if row:
                return {"kind": "run", "uuid": uuid, "policy_id": None, **row}

        for kind, sql in (
            ("finding", "SELECT * FROM findings WHERE uuid=? AND run_id=?"),
            ("observation", "SELECT * FROM observations WHERE uuid=? AND run_id=?"),
            ("risk", "SELECT * FROM risks WHERE uuid=? AND run_id=?"),
            ("poam-item", "SELECT * FROM poam_items WHERE uuid=? AND run_id=?"),
        ):
            if row := self._one(sql, (uuid, self.run_id)):
                return {"kind": kind, **row}
        return None


# Dropped before search. Without this, "What is the weather in Accra?" matches
# ten controls on the word "the" and an out-of-scope question looks answerable.
_STOPWORDS = frozenset("""
and are but can did does for from had has have how into its not our out she that
the their them then there these they this was were what when where which who why
will with you your are does his her him are about would could should
""".split())


def _fts_query(text: str) -> str:
    """Turn free text into a safe FTS5 OR-query.

    User text reaches SQLite's FTS parser, so every token is quoted and
    non-alphanumerics are dropped. This is both an injection guard and a
    usability fix: unquoted punctuation makes FTS5 raise rather than match.
    """
    words = [
        w
        for w in "".join(c if c.isalnum() else " " for c in text.lower()).split()
        if len(w) > 2 and w not in _STOPWORDS
    ]
    return " OR ".join(f'"{w}"' for w in words[:12])


# Tool schemas advertised to the model. Kept beside the implementation so a
# signature change cannot silently drift from what the model is told.
TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "posture_summary",
        "description": "Overall security posture for the current scan: totals by state, "
        "criticality and product. Use this for any question about counts or overall status.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "list_findings",
        "description": "List findings, optionally filtered by product (AAD, EXO, DEFENDER, "
        "SHAREPOINT, TEAMS, POWERPLATFORM), state (pass, fail, warning) or criticality "
        "(SHALL, SHOULD). Each finding includes the finding_uuid needed to cite it.",
        "parameters": {
            "type": "object",
            "properties": {
                "product": {"type": "string"},
                "state": {"type": "string", "enum": ["pass", "fail", "warning"]},
                "criticality": {"type": "string", "enum": ["SHALL", "SHOULD"]},
                "limit": {"type": "integer"},
            },
            "required": [],
        },
    },
    {
        "name": "get_control",
        "description": "Full detail for one SCuBA policy by ID (e.g. MS.AAD.1.1v1): statement, "
        "rationale, NIST 800-53 mappings, ATT&CK techniques, and this run's result.",
        "parameters": {
            "type": "object",
            "properties": {"policy_id": {"type": "string"}},
            "required": ["policy_id"],
        },
    },
    {
        "name": "controls_for_concept",
        "description": "Find controls related to a concept such as 'phishing', 'legacy "
        "authentication' or 'guest access'. Searches control text only, never tenant results.",
        "parameters": {
            "type": "object",
            "properties": {"text": {"type": "string"}, "limit": {"type": "integer"}},
            "required": ["text"],
        },
    },
    {
        "name": "nist_impact",
        "description": "Given SCuBA policy IDs, return the NIST 800-53 rev5 controls they map "
        "to and whether each is currently satisfied. Use for ATO and audit questions.",
        "parameters": {
            "type": "object",
            "properties": {"policy_ids": {"type": "array", "items": {"type": "string"}}},
            "required": ["policy_ids"],
        },
    },
    {
        "name": "attack_exposure",
        "description": "Given a MITRE ATT&CK technique ID (e.g. T1110) or name (e.g. 'password "
        "spraying'), return the policies that mitigate it and which of those are failing.",
        "parameters": {
            "type": "object",
            "properties": {"technique": {"type": "string"}},
            "required": ["technique"],
        },
    },
    {
        "name": "draft_poam",
        "description": "Return the compiled POA&M items for this run, ordered by risk score. "
        "Optionally filter to specific policy IDs.",
        "parameters": {
            "type": "object",
            "properties": {"policy_ids": {"type": "array", "items": {"type": "string"}}},
            "required": [],
        },
    },
    {
        "name": "diff_runs",
        "description": "Compare the current run against another run ID, reporting fixed and "
        "regressed policies.",
        "parameters": {
            "type": "object",
            "properties": {"other_run_id": {"type": "string"}},
            "required": ["other_run_id"],
        },
    },
]
