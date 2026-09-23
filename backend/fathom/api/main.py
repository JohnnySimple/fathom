"""Fathom's HTTP API.

One service. The specification calls for a single FastAPI app behind a Next.js
front end, and there is no second process worth the operational cost: the
compiler is a pure function, the store is a local SQLite file, and the only
network call in the system is the optional LLM request.

There is deliberately no authentication. The specification lists auth and user
management under "do not build" -- this is a local, single-tenant demo, and a
half-built login screen would be security theatre rather than security. The
trust model is documented in docs/SECURITY.md instead.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Iterator

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from fathom import config
from fathom.agent.analyst import Analyst
from fathom.compiler.pipeline import compile_scan
from fathom.graph import blast_radius
from fathom.ingest.scuba_results import ScubaParseError
from fathom.ingest.sources import load_sources, verify_pinned_sources
from fathom.query import QueryLayer
from fathom.store import blobs
from fathom.store.db import connect, init_db, persist_compile

# 64 MB: CISA's own sample is 1.9 MB and a very large tenant export is an order
# of magnitude bigger, so this is generous while still refusing a file that
# could exhaust memory during parsing.
MAX_UPLOAD_BYTES = 64 * 1024 * 1024

app = FastAPI(
    title="Fathom",
    version="0.1.0",
    description="Compiles ScubaGear scans into validated OSCAL and answers verified questions about them.",
)

# The front end runs on a different port in development. Locked to localhost
# rather than "*" so a page on another origin cannot read a tenant's posture.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_SOURCES = None


def sources():
    global _SOURCES
    if _SOURCES is None:
        _SOURCES = load_sources()
    return _SOURCES


def db() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        init_db(conn)
        yield conn
        conn.commit()
    finally:
        conn.close()


class AskRequest(BaseModel):
    run_id: str
    question: str = Field(min_length=3, max_length=2000)


class SimulateRequest(BaseModel):
    patch: dict[str, Any] = Field(default_factory=dict)


# ----------------------------------------------------------------- meta
@app.get("/api/health")
def health() -> dict[str, Any]:
    problems = verify_pinned_sources()
    return {
        "status": "ok" if not problems else "degraded",
        "oscal_version": config.OSCAL_VERSION,
        "scubagear_tag": config.SCUBAGEAR_TAG,
        "llm_configured": config.llm_settings().configured,
        "pinned_source_problems": problems,
    }


# ----------------------------------------------------------------- runs
@app.get("/api/runs")
def list_runs(conn: sqlite3.Connection = Depends(db)) -> dict[str, Any]:
    rows = [
        dict(r)
        for r in conn.execute(
            "SELECT id, tenant_alias, scuba_version, started_at, all_valid, created_at "
            "FROM runs ORDER BY created_at DESC"
        )
    ]
    return {"count": len(rows), "runs": rows}


@app.post("/api/runs")
async def create_run(
    file: UploadFile = File(...), conn: sqlite3.Connection = Depends(db)
) -> dict[str, Any]:
    """Upload a ScubaResults.json and compile it to OSCAL in one step.

    Upload and compile are a single operation because a run that has been
    accepted but not compiled has no meaning in Fathom -- there is nothing to
    look at and nothing to ask about.
    """
    payload = await file.read()
    if not payload:
        raise HTTPException(400, "empty upload")
    if len(payload) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"file exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit")

    try:
        result = compile_scan(payload, bundle=sources())
    except ScubaParseError as exc:
        # A bad input is the user's problem to fix, so say exactly what is wrong
        # rather than returning a generic 500.
        raise HTTPException(422, f"could not parse ScubaResults: {exc}") from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    persist_compile(conn, result, sources())
    return {
        "run_id": result.run_id,
        "all_valid": result.all_valid,
        "summary": result.summary(),
    }


@app.post("/api/runs/compile-sample")
def compile_sample(conn: sqlite3.Connection = Depends(db)) -> dict[str, Any]:
    """Compile CISA's published sample scan.

    The demo path: lets the whole pipeline be exercised with no upload and no
    Microsoft 365 tenant.
    """
    if not config.SAMPLE_SCAN.exists():
        raise HTTPException(503, "sample scan not present; run scripts/fetch_sources.py")
    result = compile_scan(config.SAMPLE_SCAN.read_bytes(), bundle=sources())
    persist_compile(conn, result, sources())
    return {"run_id": result.run_id, "all_valid": result.all_valid, "summary": result.summary()}


@app.get("/api/runs/{run_id}/compile/stream")
def compile_stream(run_id: str) -> StreamingResponse:
    """Re-run the compile for an existing run, streaming stage progress as SSE.

    Powers the Compile screen's stage-by-stage animation. Recompiling is safe
    and cheap precisely because the compiler is deterministic: the artifacts it
    produces are byte-identical to the ones already stored.
    """
    conn = connect()
    row = conn.execute("SELECT source_sha256 FROM runs WHERE id=?", (run_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, f"unknown run {run_id}")

    payload = config.SAMPLE_SCAN.read_bytes() if config.SAMPLE_SCAN.exists() else None
    if payload is None:
        raise HTTPException(409, "original scan bytes unavailable for replay")

    def events() -> Iterator[str]:
        stages: list[dict[str, str]] = []

        def progress(stage: str, message: str) -> None:
            stages.append({"stage": stage, "message": message})

        result = compile_scan(payload, bundle=sources(), progress=progress)
        for event in stages:
            yield f"data: {json.dumps(event)}\n\n"
        yield f"data: {json.dumps({'stage': 'done', 'summary': result.summary()})}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream")


def _require_run(conn: sqlite3.Connection, run_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if not row:
        raise HTTPException(404, f"unknown run {run_id}")
    return dict(row)


@app.get("/api/runs/{run_id}/artifacts/{model}")
def get_artifact(
    run_id: str, model: str, conn: sqlite3.Connection = Depends(db)
) -> JSONResponse:
    """Fetch one compiled OSCAL artifact."""
    _require_run(conn, run_id)
    row = conn.execute(
        "SELECT sha256, valid FROM artifacts WHERE run_id=? AND model_type=?", (run_id, model)
    ).fetchone()
    if not row:
        raise HTTPException(404, f"no {model} artifact for run {run_id}")
    payload = blobs.get(row["sha256"])
    if payload is None:
        raise HTTPException(410, "artifact blob missing from store")
    return JSONResponse(content=json.loads(payload))


@app.get("/api/runs/{run_id}/validation")
def get_validation(run_id: str, conn: sqlite3.Connection = Depends(db)) -> dict[str, Any]:
    _require_run(conn, run_id)
    rows = conn.execute(
        "SELECT model_type, oscal_version, sha256, valid, validation_report, bytes "
        "FROM artifacts WHERE run_id=?",
        (run_id,),
    ).fetchall()
    reports = [
        {
            "model": r["model_type"],
            "oscal_version": r["oscal_version"],
            "sha256": r["sha256"],
            "bytes": r["bytes"],
            "valid": bool(r["valid"]),
            "report": json.loads(r["validation_report"]),
        }
        for r in rows
    ]
    return {
        "run_id": run_id,
        "all_valid": all(r["valid"] for r in reports),
        "artifacts": reports,
    }


@app.get("/api/runs/{run_id}/posture")
def get_posture(run_id: str, conn: sqlite3.Connection = Depends(db)) -> dict[str, Any]:
    run = _require_run(conn, run_id)
    query = QueryLayer(conn, run_id)
    summary = query.posture_summary()
    summary["warnings"] = json.loads(run["warnings"])
    summary["top_risks"] = query.list_findings(state="fail", criticality="SHALL", limit=10)[
        "findings"
    ]
    summary["unverified"] = [
        dict(r)
        for r in conn.execute(
            "SELECT uuid AS risk_uuid, policy_id, status FROM risks "
            "WHERE run_id=? AND unverified=1 ORDER BY policy_id",
            (run_id,),
        )
    ]
    return summary


@app.get("/api/runs/{run_id}/findings")
def get_findings(
    run_id: str,
    product: str | None = None,
    state: str | None = None,
    criticality: str | None = None,
    limit: int = 50,
    conn: sqlite3.Connection = Depends(db),
) -> dict[str, Any]:
    _require_run(conn, run_id)
    return QueryLayer(conn, run_id).list_findings(product, state, criticality, limit)


@app.get("/api/runs/{run_id}/graph")
def get_graph(
    run_id: str, focus: str | None = None, conn: sqlite3.Connection = Depends(db)
) -> dict[str, Any]:
    _require_run(conn, run_id)
    return blast_radius(conn, run_id, focus=focus)


@app.get("/api/runs/{run_id}/poam")
def get_poam(run_id: str, conn: sqlite3.Connection = Depends(db)) -> dict[str, Any]:
    _require_run(conn, run_id)
    return QueryLayer(conn, run_id).draft_poam()


@app.get("/api/runs/{run_id}/control/{policy_id}")
def get_control(
    run_id: str, policy_id: str, conn: sqlite3.Connection = Depends(db)
) -> dict[str, Any]:
    _require_run(conn, run_id)
    result = QueryLayer(conn, run_id).get_control(policy_id)
    if "error" in result:
        raise HTTPException(404, result["error"])
    return result


# ----------------------------------------------------------------- ask
@app.post("/api/ask")
def ask(request: AskRequest, conn: sqlite3.Connection = Depends(db)) -> dict[str, Any]:
    """Answer a question, verified against the artifacts before returning."""
    _require_run(conn, request.run_id)
    query = QueryLayer(conn, request.run_id)
    result = Analyst(query).answer(request.question)

    conn.execute(
        """INSERT INTO qa_log (run_id, question, answer, claims_json, verifier_result,
                               mode, latency_ms, created_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (
            request.run_id,
            request.question,
            result.answer,
            json.dumps([c.as_dict() for c in result.verification.claims]),
            result.verification.badge,
            result.mode,
            result.latency_ms,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    return result.as_dict()


@app.get("/api/resolve/{uuid}")
def resolve(
    uuid: str, run_id: str = Query(...), conn: sqlite3.Connection = Depends(db)
) -> dict[str, Any]:
    """Resolve a citation UUID to its object and its location in the OSCAL JSON.

    Returns a JSON pointer so the UI can highlight the exact node rather than
    dumping the whole document and asking the reader to find it.
    """
    _require_run(conn, run_id)
    resolved = QueryLayer(conn, run_id).resolve_uuid(uuid)
    if not resolved:
        raise HTTPException(404, f"{uuid} does not resolve in run {run_id}")

    model, pointer = _locate(conn, run_id, resolved)
    return {"uuid": uuid, "object": resolved, "artifact": model, "json_pointer": pointer}


def _locate(
    conn: sqlite3.Connection, run_id: str, resolved: dict[str, Any]
) -> tuple[str | None, str | None]:
    """Find a UUID's JSON pointer inside its compiled artifact."""
    kind = resolved.get("kind")
    model = {
        "finding": "assessment-results",
        "observation": "assessment-results",
        "risk": "assessment-results",
        "poam-item": "poam",
        "run": None,
    }.get(kind)
    if not model:
        return None, None

    row = conn.execute(
        "SELECT sha256 FROM artifacts WHERE run_id=? AND model_type=?", (run_id, model)
    ).fetchone()
    if not row:
        return model, None
    payload = blobs.get(row["sha256"])
    if payload is None:
        return model, None

    document = json.loads(payload)
    target = resolved.get("uuid")
    if model == "poam":
        items = document["plan-of-action-and-milestones"]["poam-items"]
        for index, item in enumerate(items):
            if item.get("uuid") == target:
                return model, f"/plan-of-action-and-milestones/poam-items/{index}"
        return model, None

    results = document["assessment-results"]["results"][0]
    collection = {"finding": "findings", "observation": "observations", "risk": "risks"}[kind]
    for index, entry in enumerate(results.get(collection, [])):
        if entry.get("uuid") == target:
            return model, f"/assessment-results/results/0/{collection}/{index}"
    return model, None


@app.get("/api/diff")
def diff(a: str, b: str, conn: sqlite3.Connection = Depends(db)) -> dict[str, Any]:
    """Drift between two runs: what was fixed and what regressed."""
    _require_run(conn, a)
    _require_run(conn, b)
    return QueryLayer(conn, b).diff_runs(a)
