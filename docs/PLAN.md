# Implementation plan

Priorities follow the specification: P0 is the must-have chain, P1 the
should-haves, P2 the nice-to-haves. Status reflects this repository.

## Phase 0 — Pinned sources — **done** (P0)

Fetch and hash-lock every CISA and NIST input.
`scripts/fetch_sources.py`, `data/pinned/SOURCES.lock.json`.
**Done when:** `fathom sources` verifies 20 sources. ✅

## Phase 1 — Parse — **done** (P0)

Baseline markdown → `Policy`; ScubaResults.json → `ScanRun`; NIST mapping CSV.
`backend/fathom/ingest/`.
**Done when:** 126 policies parse, 92 results normalize, tenant IDs aliased,
CISA's two mapping sources cross-check clean. ✅ (17 tests)

## Phase 2 — Compile and validate — **done** (P0)

Five OSCAL artifacts with UUIDv5, validated against NIST's schemas.
`backend/fathom/compiler/`, `backend/fathom/validation/`.
**Done when:** all five validate, recompiles are byte-identical, manual checks
produce no finding. ✅ (14 tests)

## Phase 3 — Store and query — **done** (P0)

SQLite + content-addressed blobs; the typed query layer.
`backend/fathom/store/`, `backend/fathom/query/`.
**Done when:** every listed finding resolves by UUID; FTS concept search works
without a vector store. ✅ (12 tests)

## Phase 4 — Analyst and verifier — **done** (P0)

Tool-calling agent, claim verifier, grounded offline mode.
`backend/fathom/agent/`.
**Done when:** the adversarial suite passes, including the demo trap. ✅ (12 tests)

## Phase 5 — API and UI — **done** (P0)

FastAPI; Next.js Compile/Posture/Ask screens with citation click-through.
**Done when:** a citation chip opens the exact JSON node. ✅ (10 tests)

## Phase 6 — What-If (OPA) — **not started** (P1)

Patch the recorded provider config, re-run CISA's Rego in OPA, report flipped
controls. `backend/fathom/simulate/`, `POST /api/runs/{id}/simulate`.

De-risked already: `AADConfig.rego` reads exactly eight `input.*` keys and all
eight are present in `ScubaResults.Raw`, so no input shaping is needed. The
remaining work is bundling `Utils/*.rego` and mapping OPA's output back to
policy IDs. Requires the `opa` binary.

## Phase 7 — Blast Radius UI — **partly done** (P1)

`GET /api/runs/{id}/graph` works and returns the focused subgraph; the React
Flow screen is not built.

## Phase 8 — Eval scoreboard — **not started** (P1)

A 40-question gold set with deterministically computed answers, scored on
citation validity, numeric accuracy and correct refusal. The verifier already
produces every signal this needs.

## Phase 9 — Drift and reports — **not started** (P2)

`diff_runs` and `GET /api/diff` work; a second run and the Jinja report
exporters are not built.
