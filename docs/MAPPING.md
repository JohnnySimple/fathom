# OSCAL mapping decisions

Every decision here is one an auditor could challenge, so each records what
Fathom does and why the alternatives were rejected.

## Identifiers

| SCuBA | OSCAL | Note |
|---|---|---|
| Baseline document (AAD, EXO, …) | Catalog `group`, class `scuba-product` | One catalog, one group per product |
| Policy group ("Legacy Authentication") | Nested `group`, class `scuba-policy-group` | Preserves the baseline's own structure |
| `MS.AAD.1.1v1` | Control `ms.aad.1.1v1` | OSCAL IDs must be tokens; the original is kept verbatim in a `label` prop |
| Criticality, product, baseline group | Props under `https://github.com/fathom/ns/oscal` | OSCAL-sanctioned vendor extension |
| CISA 800-53 and ATT&CK mappings | Control `links` **and** namespaced props | Links for humans, props for the posture graph |

Control titles are the policy's **first sentence**; the complete statement,
including implementation guidance and markdown links, is preserved in the
control's `statement` part. A SCuBA statement can run several hundred words, and
a title that long is unusable in any OSCAL consumer.

## Verdicts

This is the table that matters. ScubaGear reports four outcomes and two
modifiers; OSCAL's objective status allows exactly `satisfied` or
`not-satisfied`.

| ScubaGear | Observation | Finding | Risk | POA&M |
|---|---|---|---|---|
| Pass | TEST | satisfied | — | — |
| Fail, SHALL | TEST | not-satisfied | open, scored | **yes** |
| Warning (SHOULD failure) | TEST | not-satisfied | open, scored | no |
| N/A, no automated check | EXAMINE | **none** | investigating | no |
| Omitted via YAML config | EXAMINE | **none** | deviation-approved | no |

**The two "none" rows are the point of the project.** OSCAL has no "unknown"
objective status. A manual check nobody performed is neither satisfied nor
not-satisfied, so Fathom emits the evidence and an open risk and declines to
state a conclusion. Recording it as `satisfied` would manufacture compliance;
recording it as `not-satisfied` would manufacture failure. In CISA's sample scan
this affects 9 of 92 policies — enough to change how a package reads.

A tenant risk acceptance (a ScubaGear config annotation) moves the risk to
`deviation-requested` and is quoted in `remarks`. It never changes the finding:
the control still failed.

## Determinism

- Every UUID is a UUIDv5 over `(namespace, kind, run_id, policy_id)`. Recompiling
  yields identical UUIDs, so citations stay valid across runs.
- The run ID is derived from the SHA-256 of the uploaded scan, so re-uploading
  the same file updates the same run rather than creating a duplicate.
- `metadata.last-modified` is the **scan's** timestamp, never `now()`. A
  compiler that stamps the current time cannot produce byte-identical output.
- JSON is serialized with sorted keys and fixed indentation.

Verified by `test_recompiling_is_byte_identical`, which asserts on bytes.

## Evidence

Each observation carries `relevant-evidence` pointing at
`./evidence/<sha256>.json` — the normalized ScubaGear output for that policy,
stored content-addressed. The hash is also a prop on the observation, so
evidence can be proven unmodified.

## Policy version reconciliation

CISA's published sample scan, shipped *inside* the ScubaGear `v1.8.0` tag,
reports `MS.AAD.3.2v2`, `MS.AAD.3.5v2` and `MS.EXO.2.2v3`. The baseline markdown
in that same tag defines only `v1`, `v1` and `v2`. The upstream repository is
internally inconsistent at the pinned tag.

Fathom resolves the assessed policy to the highest-versioned catalog control
sharing its stem, and records the discrepancy in three places: a warning on the
compile result, `assessed-policy-version` / `catalog-policy-version` props on
the observation, and the Compile screen.

The alternatives were to drop the three findings (losing real results) or to
synthesize catalog controls for them (fabricating requirement text). Both are
worse than a visible, documented reconciliation.

## What Fathom does not emit

- **Component Definition** — nothing in a ScubaGear scan describes components.
- **SSP** — the Assessment Plan's required `import-ssp` resolves to a
  back-matter resource stating plainly that no SSP was supplied, rather than
  pointing at a document nobody wrote.
- **FedRAMP-specific conventions** — the artifacts are standard OSCAL; no
  FedRAMP compliance is claimed.
