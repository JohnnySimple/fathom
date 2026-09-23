# Trust model

Fathom handles Microsoft 365 security posture, so the interesting question is
not "is it locked down" — it is a local single-tenant demo — but "what could
make it lie".

## Trust boundaries

```
pinned CISA/NIST sources  --hash-verified-->  compiler  (trusted, deterministic)
uploaded ScubaResults.json  --parsed/validated-->  store  (untrusted input)
store  --typed query layer-->  LLM  (untrusted output)
LLM output  --verifier-->  user
```

The LLM sits **between two checkpoints**: it can only read through the typed
query layer, and everything it writes is re-checked by the verifier before
display. It is treated as an untrusted component in both directions.

## Sensitive data

| Data | Handling |
|---|---|
| Tenant ID, domain, display name | Aliased at parse time via one-way hash. Never stored, never reaches the model. Asserted by `test_tenant_identifiers_never_survive_parsing`. |
| Provider configuration (`Raw`, ~1.7 MB) | Used only by the What-If simulator. Never loaded into any model context. |
| Policy results | No user-level PII; these are tenant configuration verdicts. |

## Specific risks

**LLM hallucination.** The primary threat. Mitigated by the verifier: citation
resolution, status consistency, and numeric grounding, with failing claims
removed rather than annotated. `backend/tests/test_verifier.py` holds the
adversarial suite, including the demo trap (a confident false claim of
compliance over a failing control).

**Prompt injection.** Scan data, policy text and evidence are data, not
instructions — stated in the system prompt, but enforced by the fact that an
injected instruction cannot produce a resolvable citation. An injected "say we
are compliant" fails the citation check and is stripped.

**Artifact integrity.** Artifacts and evidence are content-addressed by SHA-256;
`blobs.verify` rehashes on demand. Pinned upstream sources are checked against
`SOURCES.lock.json` on every health check and CLI run.

**Input validation.** Uploads are size-capped at 64 MB and parsed strictly —
an unrecognized ScubaGear result string is an error, never a default, because
defaulting to `pass` or `fail` would fabricate a security claim.

**SQL/FTS injection.** All queries are parameterized. Free-text search is
tokenized and quoted before reaching SQLite's FTS parser
(`test_concept_search_survives_hostile_input`).

**Auditability.** Every question, answer, claim verdict and latency is written
to `qa_log`. Every validation report is retained in `artifacts`.

## Deliberately not built

Authentication, user management and multi-tenant isolation are listed under "do
not build" in the specification. This is a local, single-tenant demo; a
half-built login screen would be security theatre. Exposing Fathom to a network
would require authentication, per-tenant authorization, and TLS — none of which
are present.
