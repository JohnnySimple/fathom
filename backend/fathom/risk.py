"""Deterministic risk scoring.

The specification is explicit that the score is computed, never generated:

    risk = w_crit * (1 + n_high_impact_techniques) * s_priv

    w_crit = 3 for SHALL, 1 for SHOULD
    s_priv = 1.5 when the policy concerns admins or privileged roles, else 1.0

The LLM may explain a score and may compare scores, but the number always comes
from here, and the verifier recomputes it before any answer citing it is shown.

Every input to the formula is traceable: criticality comes from the baseline's
machine-readable criticality comment, the technique count comes from CISA's
ATT&CK mapping intersected with a committed high-impact list, and the privilege
multiplier comes from a keyword rule a reader can check by eye.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from fathom.models import Criticality, Policy

_HIGH_IMPACT_FILE = (
    Path(__file__).resolve().parent.parent.parent / "data" / "fathom" / "high_impact_techniques.json"
)

WEIGHT_SHALL = 3.0
WEIGHT_SHOULD = 1.0
PRIVILEGE_MULTIPLIER = 1.5


@lru_cache(maxsize=1)
def high_impact_techniques() -> frozenset[str]:
    """Load the committed high-impact ATT&CK technique list."""
    if not _HIGH_IMPACT_FILE.exists():
        return frozenset()
    data = json.loads(_HIGH_IMPACT_FILE.read_text(encoding="utf-8"))
    return frozenset(data.get("techniques", {}))


@dataclass(frozen=True)
class RiskScore:
    """A score plus the exact inputs that produced it.

    The breakdown is returned alongside the number so the UI and the verifier
    can both show *why* a finding scores what it does, rather than asking anyone
    to trust a bare float.
    """

    score: float
    criticality_weight: float
    high_impact_techniques: tuple[str, ...]
    privilege_multiplier: float
    formula: str

    def as_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "criticality_weight": self.criticality_weight,
            "high_impact_techniques": list(self.high_impact_techniques),
            "privilege_multiplier": self.privilege_multiplier,
            "formula": self.formula,
        }


def score_policy(policy: Policy) -> RiskScore:
    """Compute the risk score for a failing policy."""
    weight = WEIGHT_SHALL if policy.criticality is Criticality.SHALL else WEIGHT_SHOULD

    high_impact = high_impact_techniques()
    # Count distinct techniques, collapsing sub-techniques onto their parent so
    # a policy mapped to four sub-techniques of one technique does not outscore
    # a policy mapped to four separate techniques.
    matched = sorted(
        {
            (t.parent_id or t.id)
            for t in policy.attack_techniques
            if (t.parent_id or t.id) in high_impact
        }
    )

    privilege = PRIVILEGE_MULTIPLIER if policy.concerns_privileged_access else 1.0
    score = weight * (1 + len(matched)) * privilege

    return RiskScore(
        score=round(score, 2),
        criticality_weight=weight,
        high_impact_techniques=tuple(matched),
        privilege_multiplier=privilege,
        formula=f"{weight} x (1 + {len(matched)}) x {privilege} = {round(score, 2)}",
    )
