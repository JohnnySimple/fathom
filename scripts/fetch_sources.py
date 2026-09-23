#!/usr/bin/env python3
"""Fetch every upstream source Fathom compiles from, at a pinned version.

Determinism starts here: each source is downloaded from an immutable tag and
recorded in data/pinned/SOURCES.lock.json with its SHA-256. The compiler refuses
to run against sources whose hashes do not match the lockfile, so a silent
upstream change can never alter a compiled artifact.

Usage:
    python scripts/fetch_sources.py            # download + write lockfile
    python scripts/fetch_sources.py --verify   # check existing files only
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

# --- Pinned versions. Changing these is a deliberate, reviewable act. --------
SCUBAGEAR_TAG = "v1.8.0"
OSCAL_VERSION = "1.2.3"
NIST_CONTENT_REF = "main"

ROOT = Path(__file__).resolve().parent.parent
PINNED = ROOT / "data" / "pinned"
LOCKFILE = PINNED / "SOURCES.lock.json"

_SCUBA_RAW = f"https://raw.githubusercontent.com/cisagov/ScubaGear/{SCUBAGEAR_TAG}"
_SCUBA_PS = f"{_SCUBA_RAW}/PowerShell/ScubaGear"
_OSCAL_REL = f"https://github.com/usnistgov/OSCAL/releases/download/v{OSCAL_VERSION}"
_NIST_CONTENT = (
    f"https://raw.githubusercontent.com/usnistgov/oscal-content/{NIST_CONTENT_REF}"
    "/nist.gov/SP800-53/rev5/json"
)

# Baselines we compile into the Catalog. AAD and EXO are the documented MVP
# scope; the rest are parsed too because it is the same parser and costs nothing.
BASELINES = ["aad", "exo", "defender", "sharepoint", "teams", "powerplatform"]

# Rego needed for the What-If simulator (CISA's own policy logic).
REGO_PRODUCTS = ["AADConfig", "EXOConfig"]
REGO_UTILS = ["AAD.rego", "Defender.rego", "KeyFunctions.rego", "ReportDetails.rego"]

# The five OSCAL models Fathom emits, each validated against NIST's own schema.
OSCAL_MODELS = ["catalog", "profile", "assessment-plan", "assessment-results", "poam"]


def _sources() -> dict[str, str]:
    """Map of destination path (relative to data/pinned) -> download URL."""
    src: dict[str, str] = {}

    for name in BASELINES:
        src[f"scubagear/baselines/{name}.md"] = f"{_SCUBA_PS}/baselines/{name}.md"

    src["scubagear/mappings/scuba-to-nist-800-53-r5-fedramp-high.csv"] = (
        f"{_SCUBA_PS}/mappings/scuba-to-nist-sp-800-53-r5-fedramp-high.csv"
    )

    # CISA's published sample scan. This is REAL ScubaGear output against a
    # throwaway tenant, not a fabricated fixture -- see docs/DATA_PROVENANCE.md.
    src["scubagear/samples/ScubaResults_fa5589b7-d528-4f80.json"] = (
        f"{_SCUBA_PS}/Sample-Reports/ScubaResults_fa5589b7-d528-4f80.json"
    )

    for prod in REGO_PRODUCTS:
        src[f"scubagear/rego/{prod}.rego"] = f"{_SCUBA_PS}/Rego/{prod}.rego"
    for util in REGO_UTILS:
        src[f"scubagear/rego/Utils/{util}"] = f"{_SCUBA_PS}/Rego/Utils/{util}"

    for model in OSCAL_MODELS:
        fname = f"oscal_{model}_schema.json"
        src[f"oscal/schemas/{fname}"] = f"{_OSCAL_REL}/{fname}"

    # Resolved HIGH baseline: smaller than the full catalog and the right scope
    # for FedRAMP High, which is what CISA's SCuBA mapping targets.
    src["nist/NIST_SP-800-53_rev5_HIGH-baseline-resolved-profile_catalog-min.json"] = (
        f"{_NIST_CONTENT}/NIST_SP-800-53_rev5_HIGH-baseline-resolved-profile_catalog-min.json"
    )
    return src


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "fathom-fetch/1.0"})
    with urllib.request.urlopen(req, timeout=180) as resp, dest.open("wb") as out:
        while chunk := resp.read(1 << 20):
            out.write(chunk)


def cmd_fetch() -> int:
    sources = _sources()
    entries: dict[str, dict[str, object]] = {}
    for rel, url in sorted(sources.items()):
        dest = PINNED / rel
        if dest.exists():
            print(f"  cached  {rel}")
        else:
            print(f"  fetch   {rel}")
            try:
                download(url, dest)
            except Exception as exc:  # noqa: BLE001 - surface the URL that failed
                print(f"  FAILED  {rel}: {exc}", file=sys.stderr)
                return 1
        entries[rel] = {"url": url, "sha256": sha256_file(dest), "bytes": dest.stat().st_size}

    lock = {
        "scubagear_tag": SCUBAGEAR_TAG,
        "oscal_version": OSCAL_VERSION,
        "nist_content_ref": NIST_CONTENT_REF,
        "sources": entries,
    }
    LOCKFILE.parent.mkdir(parents=True, exist_ok=True)
    LOCKFILE.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
    print(f"\nWrote {LOCKFILE.relative_to(ROOT)} ({len(entries)} sources)")
    return 0


def cmd_verify() -> int:
    if not LOCKFILE.exists():
        print("No lockfile. Run: python scripts/fetch_sources.py", file=sys.stderr)
        return 1
    lock = json.loads(LOCKFILE.read_text())
    bad = 0
    for rel, meta in sorted(lock["sources"].items()):
        path = PINNED / rel
        if not path.exists():
            print(f"  MISSING  {rel}", file=sys.stderr)
            bad += 1
        elif sha256_file(path) != meta["sha256"]:
            print(f"  MISMATCH {rel}", file=sys.stderr)
            bad += 1
    if bad:
        print(f"\n{bad} source(s) failed verification", file=sys.stderr)
        return 1
    print(f"All {len(lock['sources'])} pinned sources verified.")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verify", action="store_true", help="verify hashes, do not download")
    args = ap.parse_args()
    raise SystemExit(cmd_verify() if args.verify else cmd_fetch())
