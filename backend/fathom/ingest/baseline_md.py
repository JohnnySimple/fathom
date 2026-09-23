"""Parse CISA SCuBA baseline markdown into Fathom `Policy` objects.

The baselines are the requirement side of the pipeline: they define what each
policy demands, why it exists, which NIST 800-53 controls it maps to, and which
ATT&CK techniques it defends against. Everything Fathom later asserts about a
requirement traces back to text parsed here.

Document shape (stable across ScubaGear releases):

    ## 1. Legacy Authentication          <- numbered group
    ### Policies                         <- only headings under here are policies
    #### MS.AAD.1.1v1                    <- policy ID, exact
    Legacy authentication SHALL be blocked.
    <!--Policy: MS.AAD.1.1v1; Criticality: SHALL -->
    - _Rationale:_ ...
    - _Last modified:_ June 2023
    - _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ CM-7
    - _MITRE ATT&CK TTP Mapping:_
      - [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
        - [T1110.001: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

The `### Policies` restriction matters: each baseline repeats `#### MS.AAD.1.1v1
Instructions` headings inside its Implementation section, and parsing those
would double-count every policy.
"""
from __future__ import annotations

import re
from pathlib import Path

from fathom.models import AttackTechnique, Criticality, Policy

_GROUP = re.compile(r"^##\s+(\d+)\.\s+(.+?)\s*$")
_SUBSECTION = re.compile(r"^###\s+(.+?)\s*$")
# A policy heading is a bare ID: "#### MS.AAD.1.1v1" but never
# "#### MS.AAD.1.1v1 Instructions".
_POLICY = re.compile(r"^####\s+(MS\.[A-Z0-9]+\.\d+\.\d+v\d+)\s*$")
_CRITICALITY = re.compile(r"<!--\s*Policy:\s*[^;]+;\s*Criticality:\s*(SHALL|SHOULD)", re.I)
_BULLET = re.compile(r"^-\s+_([^:]+):_\s*(.*)$")
# Indented list item: "  - [T1110: Brute Force](https://attack.mitre.org/...)"
_TTP = re.compile(r"^(\s+)-\s+\[(T\d{4}(?:\.\d{3})?):\s*([^\]]+)\]\((https?://[^)]+)\)")


class BaselineParseError(ValueError):
    """Raised when a baseline does not match the expected structure."""


def _parse_attack_block(lines: list[str], start: int) -> tuple[list[AttackTechnique], int]:
    """Consume the indented technique list following an ATT&CK mapping bullet.

    Sub-techniques are nested one level deeper than their parent, so indentation
    width -- not ID shape -- establishes parentage. A mapping of "- None" yields
    an empty list.
    """
    techniques: list[AttackTechnique] = []
    base_indent: int | None = None
    last_parent: str | None = None
    i = start

    while i < len(lines):
        line = lines[i]
        if line.strip() and not line.startswith((" ", "\t")):
            break  # dedented back to policy level; block is over
        match = _TTP.match(line)
        if not match:
            if not line.strip() or line.strip().startswith("-"):
                i += 1
                continue
            break
        indent = len(match.group(1))
        tid, name, url = match.group(2), match.group(3), match.group(4)
        if base_indent is None:
            base_indent = indent
        parent = last_parent if indent > base_indent else None
        techniques.append(AttackTechnique(id=tid, name=name.strip(), url=url, parent_id=parent))
        if indent == base_indent:
            last_parent = tid
        i += 1

    return techniques, i


def parse_baseline(path: Path, product: str) -> list[Policy]:
    """Parse one baseline markdown file into its policies."""
    lines = path.read_text(encoding="utf-8").splitlines()
    policies: list[Policy] = []

    group_number = group_name = ""
    in_policies_section = False
    i = 0

    while i < len(lines):
        line = lines[i]

        if m := _GROUP.match(line):
            group_number, group_name = m.group(1), m.group(2)
            in_policies_section = False
            i += 1
            continue

        if m := _SUBSECTION.match(line):
            in_policies_section = m.group(1).strip().lower() == "policies"
            i += 1
            continue

        m = _POLICY.match(line)
        if not (m and in_policies_section):
            i += 1
            continue

        policy_id = m.group(1)
        i += 1

        # Statement: the prose between the heading and the first metadata line.
        statement_parts: list[str] = []
        while i < len(lines):
            nxt = lines[i]
            if nxt.startswith(("<!--", "- _", "#")):
                break
            if nxt.strip():
                statement_parts.append(nxt.strip())
            i += 1
        statement = " ".join(statement_parts).strip()

        criticality: Criticality | None = None
        rationale = last_modified = note = None
        nist_controls: list[str] = []
        techniques: list[AttackTechnique] = []

        while i < len(lines):
            nxt = lines[i]
            if nxt.startswith("#"):
                break
            if cm := _CRITICALITY.search(nxt):
                criticality = Criticality[cm.group(1).upper()]
                i += 1
                continue
            if bm := _BULLET.match(nxt):
                label, value = bm.group(1).strip().lower(), bm.group(2).strip()
                if label == "rationale":
                    rationale = value
                elif label in ("last modified", "last_modified"):
                    last_modified = value
                elif label == "note":
                    note = value
                elif label.startswith("nist sp 800-53"):
                    nist_controls = [c.strip() for c in value.split(",") if c.strip()]
                elif label.startswith("mitre att&ck"):
                    techniques, i = _parse_attack_block(lines, i + 1)
                    continue
                i += 1
                continue
            i += 1

        if criticality is None:
            # The criticality comment is the only machine-readable source for
            # SHALL vs SHOULD. Guessing from the statement text would be a
            # silent correctness risk, so refuse instead.
            raise BaselineParseError(f"{path.name}: {policy_id} has no Criticality comment")
        if not statement:
            raise BaselineParseError(f"{path.name}: {policy_id} has no statement")

        policies.append(
            Policy(
                id=policy_id,
                product=product,
                group_number=group_number,
                group_name=group_name,
                statement=statement,
                criticality=criticality,
                rationale=rationale,
                last_modified=last_modified,
                note=note,
                attack_techniques=techniques,
                nist_controls=nist_controls,
            )
        )

    if not policies:
        raise BaselineParseError(f"{path.name}: no policies found")
    return policies


def parse_all_baselines(baseline_dir: Path, products: list[str]) -> list[Policy]:
    """Parse the given products' baselines, sorted for deterministic output."""
    policies: list[Policy] = []
    for product in products:
        path = baseline_dir / f"{product.lower()}.md"
        if not path.exists():
            raise BaselineParseError(f"missing baseline: {path}")
        policies.extend(parse_baseline(path, product.upper()))
    return sorted(policies, key=lambda p: (p.product, int(p.group_number), p.id))
