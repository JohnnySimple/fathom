"""SQLite store for everything the query layer needs to answer questions.

Deliberately a single local file. The specification calls for SQLite with
Postgres only "if needed", and nothing here needs more: the largest table is one
row per policy per run, and the compiler is stateless.

The tables mirror the OSCAL artifacts rather than replacing them. The artifacts
on disk remain the authoritative evidence; these rows are an index over them, so
every UUID stored here resolves back into a real node in a validated document.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from fathom import config
from fathom.compiler.pipeline import CompileResult
from fathom.store import blobs

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id              TEXT PRIMARY KEY,
    tenant_alias    TEXT NOT NULL,
    scuba_version   TEXT NOT NULL,
    baseline_version TEXT,
    started_at      TEXT NOT NULL,
    source_sha256   TEXT NOT NULL,
    report_uuid     TEXT,
    products        TEXT NOT NULL,
    all_valid       INTEGER NOT NULL DEFAULT 0,
    warnings        TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS controls (
    id           TEXT PRIMARY KEY,           -- OSCAL control id, e.g. ms.aad.1.1v1
    scuba_id     TEXT NOT NULL,              -- original, e.g. MS.AAD.1.1v1
    product      TEXT NOT NULL,
    group_number INTEGER NOT NULL,
    group_name   TEXT NOT NULL,
    statement    TEXT NOT NULL,
    criticality  TEXT NOT NULL,
    rationale    TEXT
);

CREATE TABLE IF NOT EXISTS control_links (
    control_id  TEXT NOT NULL REFERENCES controls(id),
    target_type TEXT NOT NULL,               -- 'nist80053' | 'attack'
    target_id   TEXT NOT NULL,
    target_name TEXT,
    PRIMARY KEY (control_id, target_type, target_id)
);

CREATE TABLE IF NOT EXISTS observations (
    uuid          TEXT PRIMARY KEY,
    run_id        TEXT NOT NULL REFERENCES runs(id),
    control_id    TEXT NOT NULL REFERENCES controls(id),
    policy_id     TEXT NOT NULL,
    method        TEXT NOT NULL,
    state         TEXT NOT NULL,
    details       TEXT,
    evidence_sha256 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    uuid             TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL REFERENCES runs(id),
    control_id       TEXT NOT NULL REFERENCES controls(id),
    policy_id        TEXT NOT NULL,
    product          TEXT NOT NULL,
    state            TEXT NOT NULL,          -- normalized ScubaGear state
    oscal_status     TEXT NOT NULL,          -- satisfied | not-satisfied
    criticality      TEXT NOT NULL,
    observation_uuid TEXT NOT NULL REFERENCES observations(uuid)
);

CREATE TABLE IF NOT EXISTS risks (
    uuid             TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL REFERENCES runs(id),
    policy_id        TEXT NOT NULL,
    control_id       TEXT NOT NULL REFERENCES controls(id),
    finding_uuid     TEXT REFERENCES findings(uuid),
    status           TEXT NOT NULL,
    score            REAL,
    score_breakdown  TEXT,
    unverified       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS poam_items (
    uuid         TEXT PRIMARY KEY,
    run_id       TEXT NOT NULL REFERENCES runs(id),
    policy_id    TEXT NOT NULL,
    risk_uuid    TEXT REFERENCES risks(uuid),
    finding_uuid TEXT REFERENCES findings(uuid),
    title        TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS artifacts (
    run_id            TEXT NOT NULL REFERENCES runs(id),
    model_type        TEXT NOT NULL,
    oscal_version     TEXT NOT NULL,
    sha256            TEXT NOT NULL,
    valid             INTEGER NOT NULL,
    validation_report TEXT NOT NULL,
    bytes             INTEGER NOT NULL,
    PRIMARY KEY (run_id, model_type)
);

CREATE TABLE IF NOT EXISTS qa_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT REFERENCES runs(id),
    question        TEXT NOT NULL,
    answer          TEXT NOT NULL,
    claims_json     TEXT NOT NULL,
    verifier_result TEXT NOT NULL,
    mode            TEXT NOT NULL,
    latency_ms      INTEGER NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS simulations (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                TEXT NOT NULL REFERENCES runs(id),
    patch_json            TEXT NOT NULL,
    flipped_controls_json TEXT NOT NULL,
    engine                TEXT NOT NULL,
    created_at            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_run   ON findings(run_id, state);
CREATE INDEX IF NOT EXISTS idx_findings_ctl   ON findings(control_id);
CREATE INDEX IF NOT EXISTS idx_risks_run      ON risks(run_id, status);
CREATE INDEX IF NOT EXISTS idx_links_target   ON control_links(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_obs_run        ON observations(run_id);

-- Full-text index over control text. This is what `controls_for_concept`
-- searches, so a question about "phishing" can reach the right controls without
-- a vector database. The specification allows Azure AI Search; FTS5 is the
-- documented local fallback and needs no service to run.
CREATE VIRTUAL TABLE IF NOT EXISTS controls_fts USING fts5(
    control_id UNINDEXED,
    scuba_id,
    statement,
    rationale,
    group_name,
    attack_names,
    tokenize = 'porter'
);
"""


def connect(path: Path | None = None) -> sqlite3.Connection:
    """Open a connection.

    `check_same_thread=False` is required because FastAPI runs a sync dependency
    in a worker thread while an `async def` endpoint runs on the event loop, so
    one request legitimately touches its connection from two threads. It is safe
    here because a connection is never shared *between* requests -- each request
    opens and closes its own via the `db` dependency -- and SQLite serializes
    writes to the file regardless.
    """
    config.ensure_dirs()
    conn = sqlite3.connect(path or config.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def session(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    conn = connect(path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def load_controls(conn: sqlite3.Connection, bundle: Any) -> None:
    """Upsert the control catalog and its mappings.

    Controls are run-independent -- they describe the baseline, not the tenant --
    so they are replaced wholesale rather than duplicated per run.
    """
    from fathom.ingest.nist_ids import to_oscal_id
    from fathom.ingest.sources import load_nist_control_titles

    titles = load_nist_control_titles()

    for policy in bundle.policies:
        conn.execute(
            """INSERT INTO controls (id, scuba_id, product, group_number, group_name,
                                     statement, criticality, rationale)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 statement=excluded.statement, rationale=excluded.rationale,
                 criticality=excluded.criticality, group_name=excluded.group_name""",
            (
                policy.oscal_control_id,
                policy.id,
                policy.product,
                int(policy.group_number),
                policy.group_name,
                policy.statement,
                policy.criticality.value,
                policy.rationale,
            ),
        )
        for nist_id in policy.nist_controls:
            oscal_id = to_oscal_id(nist_id)
            conn.execute(
                """INSERT OR REPLACE INTO control_links
                   (control_id, target_type, target_id, target_name) VALUES (?,?,?,?)""",
                (
                    policy.oscal_control_id,
                    "nist80053",
                    nist_id,
                    titles.get(oscal_id or "", ""),
                ),
            )
        for technique in policy.attack_techniques:
            conn.execute(
                """INSERT OR REPLACE INTO control_links
                   (control_id, target_type, target_id, target_name) VALUES (?,?,?,?)""",
                (policy.oscal_control_id, "attack", technique.id, technique.name),
            )

    conn.execute("DELETE FROM controls_fts")
    for policy in bundle.policies:
        conn.execute(
            """INSERT INTO controls_fts
               (control_id, scuba_id, statement, rationale, group_name, attack_names)
               VALUES (?,?,?,?,?,?)""",
            (
                policy.oscal_control_id,
                policy.id,
                policy.statement,
                policy.rationale or "",
                policy.group_name,
                " ".join(f"{t.id} {t.name}" for t in policy.attack_techniques),
            ),
        )


def persist_compile(conn: sqlite3.Connection, result: CompileResult, bundle: Any) -> None:
    """Persist a compiled run: rows for querying, blobs for evidence."""
    from datetime import datetime, timezone

    init_db(conn)
    load_controls(conn, bundle)

    meta = result.run.metadata
    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT INTO runs (id, tenant_alias, scuba_version, baseline_version, started_at,
                             source_sha256, report_uuid, products, all_valid, warnings, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(id) DO UPDATE SET
             all_valid=excluded.all_valid, warnings=excluded.warnings""",
        (
            result.run_id,
            meta.tenant_alias,
            meta.tool_version,
            meta.baseline_version,
            meta.timestamp_zulu.isoformat(),
            meta.source_sha256,
            meta.report_uuid,
            json.dumps(sorted({c.product for c in result.compiled})),
            int(result.all_valid),
            json.dumps(result.warnings),
            now,
        ),
    )

    # A re-compile of the same run replaces its rows rather than duplicating.
    for table in ("poam_items", "risks", "findings", "observations", "artifacts"):
        conn.execute(f"DELETE FROM {table} WHERE run_id = ?", (result.run_id,))

    for digest, payload in result.evidence_blobs.items():
        blobs.put(payload)

    for entry in result.compiled:
        conn.execute(
            """INSERT INTO observations
               (uuid, run_id, control_id, policy_id, method, state, details, evidence_sha256)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                entry.observation_uuid,
                result.run_id,
                entry.catalog_control_id,
                entry.policy_id,
                "EXAMINE" if entry.is_manual else "TEST",
                entry.state.value,
                None,
                entry.evidence_sha256,
            ),
        )

    for entry in result.compiled:
        if entry.finding_uuid:
            conn.execute(
                """INSERT INTO findings (uuid, run_id, control_id, policy_id, product,
                                         state, oscal_status, criticality, observation_uuid)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    entry.finding_uuid,
                    result.run_id,
                    entry.catalog_control_id,
                    entry.policy_id,
                    entry.product,
                    entry.state.value,
                    "satisfied" if entry.state.is_satisfied else "not-satisfied",
                    entry.criticality.value,
                    entry.observation_uuid,
                ),
            )

    ar = result.artifacts["assessment-results"].document["assessment-results"]["results"][0]
    risk_status = {r["uuid"]: r["status"] for r in ar["risks"]}

    for entry in result.compiled:
        if not entry.risk_uuid:
            continue
        conn.execute(
            """INSERT INTO risks (uuid, run_id, policy_id, control_id, finding_uuid,
                                  status, score, score_breakdown, unverified)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                entry.risk_uuid,
                result.run_id,
                entry.policy_id,
                entry.catalog_control_id,
                entry.finding_uuid,
                risk_status.get(entry.risk_uuid, "open"),
                entry.risk_score.score if entry.risk_score else None,
                json.dumps(entry.risk_score.as_dict()) if entry.risk_score else None,
                int(entry.finding_uuid is None),
            ),
        )

    poam = result.artifacts["poam"].document["plan-of-action-and-milestones"]
    by_policy = {c.policy_id: c for c in result.compiled}
    for item in poam["poam-items"]:
        policy_id = next(
            (p["value"] for p in item.get("props", []) if p["name"] == "policy-id"), None
        )
        if not policy_id:
            continue  # the "nothing outstanding" placeholder item
        entry = by_policy.get(policy_id)
        conn.execute(
            """INSERT INTO poam_items (uuid, run_id, policy_id, risk_uuid, finding_uuid, title)
               VALUES (?,?,?,?,?,?)""",
            (
                item["uuid"],
                result.run_id,
                policy_id,
                entry.risk_uuid if entry else None,
                entry.finding_uuid if entry else None,
                item["title"],
            ),
        )

    for model, artifact in result.artifacts.items():
        blobs.put(artifact.raw)
        conn.execute(
            """INSERT INTO artifacts
               (run_id, model_type, oscal_version, sha256, valid, validation_report, bytes)
               VALUES (?,?,?,?,?,?,?)""",
            (
                result.run_id,
                model,
                config.OSCAL_VERSION,
                artifact.sha256,
                int(artifact.valid),
                json.dumps(artifact.validation.as_dict()),
                len(artifact.raw),
            ),
        )
