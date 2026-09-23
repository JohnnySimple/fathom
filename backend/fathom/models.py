"""Fathom's normalized internal representation.

This is the single vocabulary that sits between ScubaGear's output and OSCAL.
Parsers produce these; the compiler consumes them. Nothing here is OSCAL-shaped
on purpose -- keeping the internal model independent means a ScubaGear schema
change touches only the parsers, and an OSCAL version bump touches only the
compiler.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Criticality(str, Enum):
    """How binding a SCuBA policy is.

    ScubaGear encodes this as "Shall", "Should", "Shall/Not-Implemented" or
    "Should/Not-Implemented". The "/Not-Implemented" suffix means the policy has
    no automated check -- it is carried separately on `ControlResult.is_manual`
    rather than being folded into this enum, because bindingness and
    checkability are independent facts.
    """

    SHALL = "SHALL"
    SHOULD = "SHOULD"


class ResultState(str, Enum):
    """Normalized ScubaGear outcome.

    ScubaGear emits Pass / Fail / Warning / N/A, and can additionally mark a
    control omitted via YAML config or flagged as an incorrect result. Warning
    is a SHOULD-level failure, not a separate severity -- but it is kept
    distinct here so the compiler can decline to raise a POA&M item for it.
    """

    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    NOT_APPLICABLE = "not-applicable"
    OMITTED = "omitted"
    ERROR = "error"

    @property
    def is_automated_verdict(self) -> bool:
        """True when ScubaGear actually evaluated a policy and reached a verdict.

        Only these states may become an OSCAL finding with a target status.
        Everything else becomes an observation plus a manual-verification risk,
        because OSCAL has no "unknown" objective status and inventing one would
        be a fabricated pass or a fabricated failure.
        """
        return self in (ResultState.PASS, ResultState.FAIL, ResultState.WARNING)

    @property
    def is_satisfied(self) -> bool:
        return self is ResultState.PASS


class AttackTechnique(BaseModel):
    """A MITRE ATT&CK technique referenced by a SCuBA baseline."""

    id: str = Field(description="e.g. T1110 or T1110.003")
    name: str
    url: str
    parent_id: str | None = Field(
        default=None, description="Set for sub-techniques, e.g. T1110 for T1110.003"
    )

    @property
    def is_subtechnique(self) -> bool:
        return self.parent_id is not None


class Policy(BaseModel):
    """One SCuBA policy, parsed from a CISA baseline markdown document.

    This is the requirement side: what the tenant is supposed to do. It becomes
    an OSCAL control in the Fathom catalog.
    """

    id: str = Field(description="Original SCuBA ID, e.g. MS.AAD.1.1v1")
    product: str = Field(description="Baseline product key, e.g. AAD")
    group_number: str = Field(description="e.g. '1'")
    group_name: str = Field(description="e.g. 'Legacy Authentication'")
    statement: str = Field(description="The requirement text, HTML stripped")
    criticality: Criticality
    rationale: str | None = None
    last_modified: str | None = None
    note: str | None = None
    attack_techniques: list[AttackTechnique] = Field(default_factory=list)
    nist_controls: list[str] = Field(
        default_factory=list,
        description="800-53 rev5 control IDs from CISA's published mapping only",
    )

    @property
    def oscal_control_id(self) -> str:
        """OSCAL control IDs are lowercase tokens; the original is kept in a prop."""
        return self.id.lower()

    @property
    def concerns_privileged_access(self) -> bool:
        """Drives the privilege multiplier in the risk score.

        Deliberately keyword-based and therefore auditable: a reader can check
        the rule in one line rather than trusting a model's judgement.
        """
        haystack = f"{self.group_name} {self.statement}".lower()
        return any(
            kw in haystack
            for kw in ("privileged", "admin", "global administrator", "role assignment")
        )


class Annotation(BaseModel):
    """Risk-acceptance metadata a tenant attached to a failing policy.

    Sourced from ScubaGear's YAML config and echoed into
    ScubaResults.AnnotatedFailedPolicies. Preserving this is what keeps the
    risk-acceptance trail intact through to OSCAL.
    """

    comment: str | None = None
    remediation_date: str | None = None
    marked_incorrect: bool = False


class ControlResult(BaseModel):
    """ScubaGear's verdict on one policy for one scan run.

    This is the evidence side: what the tenant actually does.
    """

    policy_id: str
    product: str
    group_number: str
    group_name: str
    requirement: str = Field(description="Requirement text as reported, HTML stripped")
    state: ResultState
    criticality: Criticality
    is_manual: bool = Field(
        default=False,
        description="True when ScubaGear has no automated check for this policy",
    )
    details: str = Field(default="", description="ScubaGear's finding detail, HTML stripped")
    original_state: ResultState | None = Field(
        default=None, description="Pre-omission verdict, when config omitted the policy"
    )
    omission_rationale: str | None = None
    annotation: Annotation | None = None


class RunMetadata(BaseModel):
    """Provenance for a single scan, with tenant identifiers aliased.

    The real tenant ID and domain never enter this object -- aliasing happens at
    parse time, before anything is stored, so no downstream component (least of
    all the LLM) can leak them.
    """

    report_uuid: str
    tenant_alias: str = Field(description="Stable pseudonym, e.g. tenant-a1b2c3d4")
    tenant_display_alias: str
    tool: str = "ScubaGear"
    tool_version: str
    baseline_version: str | None = None
    timestamp_zulu: datetime
    products_assessed: list[str] = Field(default_factory=list)
    source_sha256: str = Field(description="Hash of the exact uploaded ScubaResults file")


class ScanRun(BaseModel):
    """A parsed scan: metadata, per-policy verdicts, and the raw provider export."""

    metadata: RunMetadata
    results: list[ControlResult] = Field(default_factory=list)
    raw_provider_keys: list[str] = Field(
        default_factory=list,
        description="Top-level keys present in ScubaResults.Raw; the What-If "
        "simulator feeds these to CISA's Rego as `input`",
    )

    def by_product(self, product: str) -> list[ControlResult]:
        return [r for r in self.results if r.product == product]
