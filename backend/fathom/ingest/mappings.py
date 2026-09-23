"""Load CISA's published SCuBA -> NIST 800-53 mapping.

Fathom only ever asserts a control mapping that CISA published. Nothing here is
inferred, and nothing model-generated is allowed into this table -- an invented
800-53 mapping in an ATO package is exactly the failure mode Fathom exists to
prevent.

The mapping appears in two independent places upstream: this CSV, and an inline
`_NIST SP 800-53 ... Mapping:_` bullet in each baseline. Fathom loads both and
cross-checks them, which turns a duplicated source into a free integrity test.
"""
from __future__ import annotations

import csv
from pathlib import Path


def load_nist_mapping(csv_path: Path) -> dict[str, list[str]]:
    """Parse the mapping CSV into {policy_id: [800-53 control IDs]}.

    The control column packs multiple IDs into one quoted, comma-separated
    cell, e.g. `"AC-2(12), AC-2(13)"`.
    """
    mapping: dict[str, list[str]] = {}
    with csv_path.open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            policy_id = (row.get("scuba-control-id") or "").strip()
            if not policy_id:
                continue
            raw = (row.get("nist-800-53-control-id") or "").strip()
            controls = sorted({c.strip() for c in raw.split(",") if c.strip()})
            mapping[policy_id] = controls
    if not mapping:
        raise ValueError(f"no rows parsed from {csv_path}")
    return mapping


def cross_check(
    csv_mapping: dict[str, list[str]], baseline_mapping: dict[str, list[str]]
) -> list[str]:
    """Report policies where the CSV and the baseline text disagree.

    Returned as warnings rather than raised: a disagreement means CISA's own
    sources drifted, which is worth surfacing to the user but is not a reason
    to refuse to compile. The CSV wins, since it is the machine-readable
    artifact CISA publishes for this purpose.
    """
    warnings: list[str] = []
    for policy_id in sorted(set(csv_mapping) & set(baseline_mapping)):
        from_csv, from_md = set(csv_mapping[policy_id]), set(baseline_mapping[policy_id])
        if from_csv != from_md:
            warnings.append(
                f"{policy_id}: NIST mapping differs between CSV {sorted(from_csv)} "
                f"and baseline {sorted(from_md)}"
            )
    return warnings
