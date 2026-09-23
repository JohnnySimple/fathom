# Fathom

Fathom compiles ScubaGear scans into validated OSCAL and lets anyone question
their Microsoft 365 security posture, with every answer verified against the
artifacts.

The architectural rule the whole project turns on:

> **The AI never writes an artifact and never decides pass or fail.**

Compilation is deterministic and hash-pinned. The analyst reads through a typed
query layer and cannot reach the data any other way. Every factual sentence it
produces is re-checked against those same artifacts before you see it, and
unsupported claims are removed.

```
ScubaResults.json
      │  deterministic — no model involved
      ▼
  parse ──► normalize ──► compile OSCAL (UUIDv5) ──► validate (NIST schemas)
                                                            │
                                                            ▼
                                            SQLite + content-addressed blobs
                                                            │
                                                  typed query layer
                                                       │        ▲
                                                       ▼        │ re-resolve
                                                     LLM ──► verifier ──► answer + citations
```

## What works today

| | |
|---|---|
| Pinned sources | 20 CISA/NIST files, SHA-256 locked |
| Policies parsed | 126, across all six SCuBA baselines |
| Sample scan compiled | 92 assessed policies from CISA's published report |
| OSCAL artifacts | Catalog, Profile, Assessment Plan, Assessment Results, POA&M |
| Schema validation | All five valid against **NIST OSCAL 1.2.3** |
| Reproducibility | Byte-identical recompiles, asserted on bytes |
| Tests | 65 passing |

Compiling CISA's sample yields 57 satisfied, 14 failing SHALL, 12 failing
SHOULD, and **9 policies deliberately left unverified** — manual checks that
Fathom refuses to call passing or failing, because OSCAL has no "unknown" and
guessing either way would fabricate a security claim.

## Quick start

Requires Python 3.11+ and Node 20+.

```bash
git clone <repo> && cd fathom

# 1. Fetch pinned CISA + NIST sources (~9 MB, writes SOURCES.lock.json)
python3 scripts/fetch_sources.py

# 2. Backend
python3 -m venv .venv
.venv/bin/pip install -e "backend[dev]"
.venv/bin/fathom sources          # verify the pinned inputs

# 3. Compile CISA's published sample scan — no M365 tenant needed
.venv/bin/fathom compile --sample
.venv/bin/fathom posture
.venv/bin/fathom ask "Which failing policies expose us to phishing?"

# 4. Tests
.venv/bin/python -m pytest backend/tests -q

# 5. Run it
.venv/bin/fathom serve            # API on :8000
cd frontend && npm install && npm run dev   # UI on :3000
```

No API key is needed for any of the above. See
[Running with an LLM](#running-with-an-llm).

## The demo workflow

1. **Compile** — drop in a `ScubaResults.json`, or compile CISA's sample. Five
   artifacts appear with a green *valid against NIST OSCAL schemas* badge and an
   expandable validation log.
2. **Posture** — satisfied / failing SHALL / failing SHOULD / unverified, broken
   down by product, with the top risks ranked by a deterministic score.
3. **Ask** — "Which failing requirements leave us open to phishing?" The answer
   arrives as verified claims with citation chips. Click one to see the exact
   node highlighted in the OSCAL JSON.
4. **The trap** — ask *"Confirm we are fully compliant with MFA requirements."*
   The verifier blocks the false claim and shows why it was removed.

## Why the answers can be trusted

The verifier assumes the model is unreliable and re-checks its finished prose
against the query layer. Four checks, all deterministic:

| Check | Catches |
|---|---|
| Citation resolution | Invented or stale UUIDs |
| Status consistency | "This passes" over a failing control |
| Numeric grounding | Figures the model derived rather than read |
| Uncited factual sentences | Assertions with nothing behind them |

Failing claims are **removed**, not struck through — a visibly crossed-out
false claim is still one the eye absorbs. Judgements are allowed but must be
prefixed `Interpretation:` and are labelled as such in the UI.

Getting this right required tuning against false positives, which matter as much
as false negatives: a verifier that rejects true statements trains people to
ignore it. Two real cases are pinned by tests — `"not-satisfied"` contains the
substring `"satisfied"`, and requirement text legitimately contains words like
`"enabled"`.

## Risk score

Deterministic and explainable; the model may narrate it but never computes it.

```
risk = w_criticality × (1 + n_high_impact_techniques) × s_privilege
       w = 3 (SHALL) | 1 (SHOULD)
       s = 1.5 when the policy concerns admins or privileged roles, else 1.0
```

Sub-techniques collapse onto their parent, so a policy mapped to four
sub-techniques of one technique does not outscore one mapped to four distinct
techniques. The high-impact list is committed data, not model output —
[docs/DATA_PROVENANCE.md](docs/DATA_PROVENANCE.md).

## Running with an LLM

Fathom runs fully offline. The deterministic pipeline never makes a network
call, and with no model configured the analyst answers in **grounded mode**:
tools still run, templates render the results, and the verifier still checks
every claim. It is less fluent, never less correct.

For natural-language answers, configure Azure OpenAI per `.env.example`:

```bash
export AZURE_OPENAI_ENDPOINT=https://<resource>.openai.azure.com
export AZURE_OPENAI_API_KEY=...
export AZURE_OPENAI_DEPLOYMENT=gpt-4o
```

If the endpoint fails mid-question, Fathom falls back to grounded mode and says
so in the response `mode`.

## Layout

```
backend/fathom/
  ingest/      parsers: baselines, ScubaResults, NIST mappings  (deterministic)
  compiler/    the five OSCAL artifacts, UUIDv5, pure           (deterministic)
  validation/  NIST JSON Schema gate                            (deterministic)
  store/       SQLite index + content-addressed blobs
  query/       the typed query layer — the AI's only data access
  agent/       analyst, prompts, and the claim verifier          (probabilistic)
  api/         FastAPI
  risk.py graph.py cli.py models.py config.py
frontend/      Next.js 15 — Compile & Posture, Ask
scripts/       fetch_sources.py — pin and hash upstream inputs
data/pinned/   fetched CISA + NIST sources (gitignored; lockfile committed)
data/fathom/   Fathom's own editorial data, labelled as such
docs/          MAPPING.md · SECURITY.md · DATA_PROVENANCE.md · PLAN.md
```

## Documentation

- [OSCAL mapping decisions](docs/MAPPING.md) — including why manual checks
  produce no finding, and how policy version drift is reconciled
- [Trust model](docs/SECURITY.md)
- [Data provenance](docs/DATA_PROVENANCE.md) — real CISA output vs. fixtures
- [Implementation plan](docs/PLAN.md) — what is built and what is not

## Not built yet

What-If (OPA re-running CISA's Rego), the Blast Radius graph screen, the
40-question eval scoreboard, drift, and report export. The graph API and
`diff_runs` already work; see [docs/PLAN.md](docs/PLAN.md).

Deliberately out of scope, per the specification: authentication, an OSCAL
editor, multi-tenant views, fine-tuning, and running ScubaGear live.
