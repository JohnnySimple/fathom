"""Compile a scan run into OSCAL Assessment Results.

This module owns the decision that the whole project turns on: how a ScubaGear
verdict becomes an OSCAL claim, without ever inventing one.

    ScubaGear verdict          OSCAL representation
    -------------------------  ----------------------------------------------
    Pass                       observation (TEST) + finding, satisfied
    Fail   (SHALL)             observation (TEST) + finding, not-satisfied
                               + risk, open, scored        -> POA&M item
    Warning (SHOULD failure)   observation (TEST) + finding, not-satisfied
                               + risk, open, scored        -> no POA&M item
    N/A with no automated      observation (EXAMINE) + risk, investigating
    check (manual)             NO FINDING
    Omitted via YAML config    observation (EXAMINE) + risk, deviation-approved
                               NO FINDING

The two "no finding" rows are the important ones. OSCAL's objective status
allows exactly `satisfied` or `not-satisfied` -- there is no "unknown". A manual
check that nobody performed is neither, so Fathom emits the evidence and an open
question, and declines to state a conclusion. Forcing these into `satisfied`
would manufacture compliance; forcing them into `not-satisfied` would
manufacture failure. Both are lies an ATO package cannot afford.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from fathom.compiler.common import FATHOM_NS, dumps, metadata, prop
from fathom.compiler.ids import fathom_uuid
from fathom.ingest.sources import SourceBundle
from fathom.models import Criticality, ResultState, ScanRun
from fathom.risk import RiskScore, score_policy

ASSESSMENT_PLAN_HREF = "./assessment-plan.json"
ATTACK_SYSTEM = "https://attack.mitre.org"


@dataclass
class CompiledFinding:
    """A finding plus everything Fathom derived alongside it.

    Returned from the compiler so the store can persist the same UUIDs the OSCAL
    document uses. Citation stability depends on these being one and the same.
    """

    policy_id: str
    catalog_control_id: str
    product: str
    state: ResultState
    criticality: Criticality
    is_manual: bool
    observation_uuid: str
    finding_uuid: str | None
    risk_uuid: str | None
    risk_score: RiskScore | None
    evidence_sha256: str
    version_drift: bool


def _evidence_blob(result, run_id: str) -> tuple[str, bytes]:
    """Serialize a control result as content-addressed evidence.

    The blob is exactly what ScubaGear reported for this policy, normalized.
    Hashing it means a finding's evidence can be proven unmodified later.
    """
    import hashlib

    payload = json.dumps(
        {
            "run_id": run_id,
            "policy_id": result.policy_id,
            "product": result.product,
            "scubagear_result": result.state.value,
            "criticality": result.criticality.value,
            "automated_check": not result.is_manual,
            "details": result.details,
            "requirement": result.requirement,
        },
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), payload


def build_assessment_results(
    run: ScanRun,
    bundle: SourceBundle,
    *,
    run_id: str,
) -> tuple[dict, list[CompiledFinding], dict[str, bytes]]:
    """Compile a scan into Assessment Results.

    Returns the OSCAL document, the per-policy compilation record, and the
    evidence blobs to persist keyed by SHA-256.
    """
    collected = run.metadata.timestamp_zulu.isoformat()
    observations: list[dict] = []
    findings: list[dict] = []
    risks: list[dict] = []
    compiled: list[CompiledFinding] = []
    blobs: dict[str, bytes] = {}

    for result in sorted(run.results, key=lambda r: r.policy_id):
        resolution = bundle.resolve(result.policy_id)
        if resolution is None:
            # Never silently drop an assessed policy: a missing catalog control
            # is a pinning error that must be fixed, not absorbed.
            raise ValueError(
                f"{result.policy_id} has no catalog control; re-pin baselines "
                f"(see scripts/fetch_sources.py)"
            )
        policy = resolution.policy
        control_id = policy.oscal_control_id

        evidence_sha, payload = _evidence_blob(result, run_id)
        blobs[evidence_sha] = payload

        observation_uuid = fathom_uuid("observation", run_id, result.policy_id)
        method = "TEST" if not result.is_manual else "EXAMINE"

        observation_props = [
            prop("scubagear-result", result.state.value),
            prop("policy-id", result.policy_id),
            prop("product", result.product),
            prop("criticality", result.criticality.value),
            prop("automated-check", "false" if result.is_manual else "true"),
            prop("evidence-sha256", evidence_sha),
        ]
        if resolution.version_drift:
            # Surfaced, never hidden: the scan reported a policy version the
            # pinned baseline does not define.
            observation_props.append(prop("assessed-policy-version", result.policy_id))
            observation_props.append(prop("catalog-policy-version", policy.id))

        observation = {
            "uuid": observation_uuid,
            "title": f"{result.policy_id} -- ScubaGear result: {result.state.value}",
            "description": result.details or f"ScubaGear reported {result.state.value}.",
            "methods": [method],
            "types": ["control-objective"],
            "props": observation_props,
            "collected": collected,
            "relevant-evidence": [
                {
                    "href": f"./evidence/{evidence_sha}.json",
                    "description": (
                        f"Normalized ScubaGear output for {result.policy_id}, "
                        f"SHA-256 {evidence_sha}."
                    ),
                }
            ],
        }
        observations.append(observation)

        finding_uuid: str | None = None
        risk_uuid: str | None = None
        risk_score: RiskScore | None = None

        if result.state.is_automated_verdict:
            finding_uuid = fathom_uuid("finding", run_id, result.policy_id)
            satisfied = result.state.is_satisfied
            finding: dict = {
                "uuid": finding_uuid,
                "title": f"{result.policy_id} -- {policy.statement}",
                "description": result.details
                or ("Policy satisfied." if satisfied else "Policy not satisfied."),
                "target": {
                    "type": "statement-id",
                    "target-id": f"{control_id}_smt",
                    "status": {"state": "satisfied" if satisfied else "not-satisfied"},
                },
                "props": [
                    prop("policy-id", result.policy_id),
                    prop("criticality", result.criticality.value),
                    prop("product", result.product),
                ],
                "related-observations": [{"observation-uuid": observation_uuid}],
            }

            if not satisfied:
                risk_score = score_policy(policy)
                risk_uuid = fathom_uuid("risk", run_id, result.policy_id)
                finding["related-risks"] = [{"risk-uuid": risk_uuid}]
                risks.append(
                    _failure_risk(
                        risk_uuid=risk_uuid,
                        observation_uuid=observation_uuid,
                        result=result,
                        policy=policy,
                        score=risk_score,
                    )
                )
            findings.append(finding)
        else:
            # Manual, N/A or omitted: evidence and an open question, no verdict.
            risk_uuid = fathom_uuid("risk", run_id, result.policy_id)
            risks.append(
                _unverified_risk(
                    risk_uuid=risk_uuid,
                    observation_uuid=observation_uuid,
                    result=result,
                    policy=policy,
                )
            )

        compiled.append(
            CompiledFinding(
                policy_id=result.policy_id,
                catalog_control_id=control_id,
                product=result.product,
                state=result.state,
                criticality=result.criticality,
                is_manual=result.is_manual,
                observation_uuid=observation_uuid,
                finding_uuid=finding_uuid,
                risk_uuid=risk_uuid,
                risk_score=risk_score,
                evidence_sha256=evidence_sha,
                version_drift=resolution.version_drift,
            )
        )

    control_ids = sorted({c.catalog_control_id for c in compiled})
    document = {
        "assessment-results": {
            "uuid": fathom_uuid("assessment-results", run_id),
            "metadata": metadata(
                f"ScubaGear Assessment Results for {run.metadata.tenant_alias}",
                last_modified=collected,
                version=run_id,
                tool_version=run.metadata.tool_version,
                extra_props=[
                    prop("tenant-alias", run.metadata.tenant_alias),
                    prop("scan-report-uuid", run.metadata.report_uuid),
                    prop("source-sha256", run.metadata.source_sha256),
                ],
            ),
            "import-ap": {"href": ASSESSMENT_PLAN_HREF},
            "results": [
                {
                    "uuid": fathom_uuid("result", run_id),
                    "title": f"ScubaGear scan {run.metadata.report_uuid}",
                    "description": (
                        f"Automated SCuBA conformance assessment of {len(compiled)} policies "
                        f"across {len(set(c.product for c in compiled))} Microsoft 365 products, "
                        f"performed by {run.metadata.tool} {run.metadata.tool_version}."
                    ),
                    "start": collected,
                    "reviewed-controls": {
                        "control-selections": [
                            {"include-controls": [{"control-id": c} for c in control_ids]}
                        ]
                    },
                    "observations": observations,
                    "risks": risks,
                    "findings": findings,
                }
            ],
        }
    }
    return document, compiled, blobs


def _failure_risk(*, risk_uuid, observation_uuid, result, policy, score: RiskScore) -> dict:
    """Build a risk for a policy that ScubaGear evaluated and found wanting."""
    props = [
        prop("policy-id", result.policy_id),
        prop("risk-score", str(score.score)),
        prop("risk-formula", score.formula),
        prop("criticality", result.criticality.value),
    ]

    status = "open"
    remarks = None
    if result.annotation and result.annotation.comment:
        # A documented risk acceptance changes the status but never the finding:
        # the control still failed.
        status = "deviation-requested"
        remarks = f"Tenant risk acceptance on record: {result.annotation.comment}"
        if result.annotation.remediation_date:
            props.append(prop("remediation-date", result.annotation.remediation_date))

    risk: dict = {
        "uuid": risk_uuid,
        "title": f"{result.policy_id} not satisfied",
        "description": (
            f"{policy.statement} ScubaGear reported {result.state.value} for this "
            f"{result.criticality.value} policy."
        ),
        "statement": policy.rationale
        or f"Failure to meet {result.policy_id} weakens the tenant's security posture.",
        "status": status,
        "props": props,
        "related-observations": [{"observation-uuid": observation_uuid}],
    }
    if remarks:
        risk["remarks"] = remarks

    # ATT&CK techniques are threats, and OSCAL models them natively. OSCAL
    # requires `threat-id.id` to be a URI, so the canonical MITRE URL is the
    # identifier; the bare technique ID is duplicated into a prop so the posture
    # graph can match on "T1566" without parsing URLs.
    if policy.attack_techniques:
        risk["threat-ids"] = [
            {"system": ATTACK_SYSTEM, "id": t.url, "href": t.url}
            for t in policy.attack_techniques
        ]
        props.extend(prop("attack-technique", t.id) for t in policy.attack_techniques)
    return risk


def _unverified_risk(*, risk_uuid, observation_uuid, result, policy) -> dict:
    """Build a risk recording that a policy's state is genuinely unknown."""
    if result.state is ResultState.OMITTED:
        status = "deviation-approved"
        statement = (
            f"{result.policy_id} was omitted from evaluation by tenant configuration. "
            "The tenant has accepted this risk; no assessment conclusion is available."
        )
        title = f"{result.policy_id} omitted from evaluation"
    else:
        status = "investigating"
        statement = (
            f"{result.policy_id} has no automated check in ScubaGear "
            f"{'and requires manual verification' if result.is_manual else 'for this tenant'}. "
            "Fathom records no pass or fail because none was determined."
        )
        title = f"{result.policy_id} requires manual verification"

    props = [
        prop("policy-id", result.policy_id),
        prop("criticality", result.criticality.value),
        prop("verification-required", "manual" if result.is_manual else "none"),
    ]
    risk: dict = {
        "uuid": risk_uuid,
        "title": title,
        "description": policy.statement,
        "statement": statement,
        "status": status,
        "props": props,
        "related-observations": [{"observation-uuid": observation_uuid}],
    }
    if result.omission_rationale:
        risk["remarks"] = f"Omission rationale: {result.omission_rationale}"
    elif result.annotation and result.annotation.comment:
        risk["remarks"] = f"Tenant annotation: {result.annotation.comment}"
    return risk


__all__ = ["build_assessment_results", "CompiledFinding", "dumps", "FATHOM_NS"]
