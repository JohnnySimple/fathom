# Where Fathom's data comes from

Fathom makes claims about security posture, so the provenance of every input is
tracked explicitly. Nothing in the pipeline is invented, and nothing is a mock.

## Real upstream sources

All fetched by `scripts/fetch_sources.py` at a pinned version and recorded with
their SHA-256 in `data/pinned/SOURCES.lock.json`.

| Source | Origin | Pin |
|---|---|---|
| SCuBA baselines (6 products, 126 policies) | `cisagov/ScubaGear` | `v1.8.0` |
| SCuBA → NIST 800-53 mapping CSV | `cisagov/ScubaGear` | `v1.8.0` |
| CISA Rego policies (AAD, EXO + utils) | `cisagov/ScubaGear` | `v1.8.0` |
| **Sample scan** `ScubaResults_fa5589b7-d528-4f80.json` | `cisagov/ScubaGear` | `v1.8.0` |
| OSCAL JSON Schemas (5 models) | `usnistgov/OSCAL` release assets | `v1.2.3` |
| NIST 800-53 rev5 HIGH baseline catalog | `usnistgov/oscal-content` | `main` |

## REAL SCUBAGEAR OUTPUT

`data/pinned/scubagear/samples/ScubaResults_fa5589b7-d528-4f80.json` is
**CISA's own published sample report**, committed to the ScubaGear repository.
It is genuine ScubaGear output from a throwaway test tenant, not a fixture
Fathom authored. Its tenant identifiers are aliased on ingest regardless.

Everything shown in the demo — 92 assessed policies, 14 SHALL failures, 9
unverified manual checks — is that real file, compiled.

## DEMO / TEST FIXTURE

There are currently **no fabricated scan fixtures**. CISA's published sample
covers the entire pipeline, so nothing needed inventing. Should a fixture become
necessary (for example a second run to demonstrate drift), it belongs in
`data/fixtures/`, must carry a `FATHOM SYNTHETIC` marker in its metadata, and
must be labelled as synthetic wherever it is displayed.

## Fathom's own editorial content

One file is Fathom's judgement rather than an upstream fact, and is labelled as
such inside the file itself:

- `data/fathom/high_impact_techniques.json` — the 14 ATT&CK techniques treated
  as "high impact" by the risk score. The specification's formula references
  high-impact techniques without enumerating them, so Fathom commits an explicit
  list rather than letting the value float. Every entry is a real ATT&CK
  technique that CISA's baselines actually reference — asserted by
  `test_high_impact_list_contains_no_invented_techniques`.

## Known upstream inconsistency

CISA's sample scan reports three policy versions (`MS.AAD.3.2v2`,
`MS.AAD.3.5v2`, `MS.EXO.2.2v3`) that do not exist in the baseline markdown at
the same `v1.8.0` tag — they appear only in later baselines. Fathom reconciles
by version stem and reports the drift rather than hiding it. See
[MAPPING.md](MAPPING.md#policy-version-reconciliation).
