"""Load and reconcile every pinned upstream source into one bundle.

`SourceBundle` is the compiler's view of the requirement side: policies, their
NIST mappings, and their ATT&CK techniques, all from pinned CISA and NIST
sources with verified hashes.

It also owns *policy version reconciliation*, which real data forces on us.
CISA's published sample scan -- shipped inside the ScubaGear v1.8.0 tag --
reports `MS.AAD.3.2v2`, `MS.AAD.3.5v2` and `MS.EXO.2.2v3`, but the baseline
markdown in that same tag only defines `v1`, `v1` and `v2`. The upstream repo is
internally inconsistent at the pinned tag.

Three ways to handle that, only one of them honest:

  - drop the assessed policy      -> silently loses 3 real findings
  - synthesize a catalog control  -> fabricates requirement text
  - resolve by version-stem and record the drift  <- what Fathom does

The third keeps every finding, never invents requirement text, and leaves the
discrepancy visible in the compile report and in a prop on the finding.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from fathom import config
from fathom.ingest.baseline_md import parse_all_baselines
from fathom.ingest.mappings import cross_check, load_nist_mapping
from fathom.models import Policy

_POLICY_ID = re.compile(r"^(?P<stem>MS\.[A-Z0-9]+\.\d+\.\d+)v(?P<version>\d+)$")


def split_policy_id(policy_id: str) -> tuple[str, int] | None:
    """Split `MS.AAD.3.2v2` into (`MS.AAD.3.2`, 2)."""
    m = _POLICY_ID.match(policy_id.strip())
    if not m:
        return None
    return m.group("stem"), int(m.group("version"))


@dataclass
class PolicyResolution:
    """How an assessed policy ID was matched to a catalog control."""

    policy: Policy
    exact: bool
    assessed_id: str

    @property
    def version_drift(self) -> bool:
        return not self.exact


@dataclass
class SourceBundle:
    policies: list[Policy]
    nist_mapping: dict[str, list[str]]
    warnings: list[str] = field(default_factory=list)
    _by_id: dict[str, Policy] = field(default_factory=dict, repr=False)
    _by_stem: dict[str, list[Policy]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self._by_id = {p.id: p for p in self.policies}
        self._by_stem = {}
        for policy in self.policies:
            if parts := split_policy_id(policy.id):
                self._by_stem.setdefault(parts[0], []).append(policy)

    def resolve(self, assessed_id: str) -> PolicyResolution | None:
        """Find the catalog policy for an assessed policy ID.

        Exact match first. Failing that, fall back to the highest-versioned
        policy sharing the same stem -- the requirement is the same control,
        reworded across baseline revisions.
        """
        if policy := self._by_id.get(assessed_id):
            return PolicyResolution(policy=policy, exact=True, assessed_id=assessed_id)

        parts = split_policy_id(assessed_id)
        if not parts:
            return None
        candidates = self._by_stem.get(parts[0])
        if not candidates:
            return None
        best = max(candidates, key=lambda p: split_policy_id(p.id)[1])  # type: ignore[index]
        return PolicyResolution(policy=best, exact=False, assessed_id=assessed_id)

    def by_product(self, product: str) -> list[Policy]:
        return [p for p in self.policies if p.product == product.upper()]


def verify_pinned_sources() -> list[str]:
    """Check pinned files against SOURCES.lock.json.

    A hash mismatch means the compiler's inputs changed without a deliberate
    re-pin, which would break the determinism guarantee, so it is reported as an
    error string rather than tolerated.
    """
    import hashlib

    if not config.SOURCES_LOCK.exists():
        return ["SOURCES.lock.json missing -- run: python scripts/fetch_sources.py"]

    lock = json.loads(config.SOURCES_LOCK.read_text())
    problems: list[str] = []
    for rel, meta in sorted(lock["sources"].items()):
        path = config.PINNED / rel
        if not path.exists():
            problems.append(f"missing pinned source: {rel}")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != meta["sha256"]:
            problems.append(f"hash mismatch for pinned source: {rel}")
    return problems


def load_sources(products: list[str] | None = None) -> SourceBundle:
    """Load baselines and mappings for the given products."""
    products = products or config.ALL_PRODUCTS
    policies = parse_all_baselines(config.BASELINE_DIR, [p.lower() for p in products])
    nist_mapping = load_nist_mapping(config.NIST_MAPPING_CSV)

    baseline_mapping = {p.id: sorted(set(p.nist_controls)) for p in policies}
    warnings = cross_check(nist_mapping, baseline_mapping)

    # CISA's CSV is the authoritative machine-readable mapping; prefer it and
    # fall back to the baseline text where the CSV has no row.
    for policy in policies:
        policy.nist_controls = nist_mapping.get(policy.id) or sorted(set(policy.nist_controls))

    return SourceBundle(policies=policies, nist_mapping=nist_mapping, warnings=warnings)


def load_nist_control_titles() -> dict[str, str]:
    """Map OSCAL 800-53 control IDs (e.g. `ac-2.12`) to their official titles.

    Keyed by OSCAL ID, so callers must run CISA notation through
    `nist_ids.to_oscal_id` first. Used for human-readable link text in the
    posture graph; Fathom links to these controls but never restates their
    requirements.
    """
    if not config.NIST_CATALOG.exists():
        return {}
    catalog = json.loads(config.NIST_CATALOG.read_text(encoding="utf-8"))
    titles: dict[str, str] = {}

    def walk(controls: list[dict]) -> None:
        for control in controls:
            if (cid := control.get("id")) and (title := control.get("title")):
                titles[cid.lower()] = title
            walk(control.get("controls", []))

    for group in catalog.get("catalog", {}).get("groups", []):
        walk(group.get("controls", []))
    walk(catalog.get("catalog", {}).get("controls", []))
    return titles
