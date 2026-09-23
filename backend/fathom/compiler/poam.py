"""Compile a Plan of Action and Milestones from SHALL-level failures.

A POA&M item is a commitment to fix something, so Fathom raises one only where a
binding requirement demonstrably failed:

  - SHALL + Fail  -> POA&M item
  - SHOULD + Warning -> risk only; a recommendation is not a commitment
  - manual / N/A / omitted -> no item; there is no established failure to remediate

Milestones are deliberately generic. Fathom knows a control failed and what the
baseline requires, but it does not know the tenant's change process, so it
frames the remediation steps rather than inventing dates and owners it cannot
know. Where the tenant supplied a remediation date in ScubaGear's config, that
real date is used.
"""
from __future__ import annotations

from fathom.compiler.assessment_results import CompiledFinding
from fathom.compiler.common import dumps, metadata, prop
from fathom.compiler.ids import fathom_uuid
from fathom.ingest.sources import SourceBundle
from fathom.models import Criticality, ResultState, ScanRun


def build_poam(
    run: ScanRun,
    bundle: SourceBundle,
    compiled: list[CompiledFinding],
    *,
    run_id: str,
) -> tuple[dict, list[str]]:
    """Build the POA&M. Returns the document and the policy IDs it covers."""
    collected = run.metadata.timestamp_zulu.isoformat()
    annotations = {r.policy_id: r.annotation for r in run.results}

    actionable = [
        c
        for c in compiled
        if c.criticality is Criticality.SHALL
        and c.state is ResultState.FAIL
        and c.finding_uuid
    ]
    # Worst first: a POA&M that opens with the highest-scoring failure is
    # immediately useful to whoever has to work it.
    actionable.sort(key=lambda c: (-(c.risk_score.score if c.risk_score else 0), c.policy_id))

    items: list[dict] = []
    for entry in actionable:
        resolution = bundle.resolve(entry.policy_id)
        policy = resolution.policy if resolution else None
        statement = policy.statement if policy else entry.policy_id

        item: dict = {
            "uuid": fathom_uuid("poam-item", run_id, entry.policy_id),
            "title": f"{entry.policy_id} -- {statement}",
            "description": (
                f"SCuBA policy {entry.policy_id} ({entry.product}) is a SHALL requirement "
                f"and was reported as failing by ScubaGear. "
                f"{policy.rationale if policy and policy.rationale else ''}"
            ).strip(),
            "props": [
                prop("policy-id", entry.policy_id),
                prop("product", entry.product),
                prop("criticality", entry.criticality.value),
                prop("risk-score", str(entry.risk_score.score) if entry.risk_score else "0"),
            ],
            "related-findings": [{"finding-uuid": entry.finding_uuid}],
            "related-observations": [{"observation-uuid": entry.observation_uuid}],
        }
        if entry.risk_uuid:
            item["related-risks"] = [{"risk-uuid": entry.risk_uuid}]

        annotation = annotations.get(entry.policy_id)
        if annotation and annotation.remediation_date:
            item["props"].append(prop("tenant-remediation-date", annotation.remediation_date))
        if annotation and annotation.comment:
            item["remarks"] = f"Tenant annotation: {annotation.comment}"

        items.append(item)

    if not items:
        # A POA&M with no items is still a meaningful, valid statement: nothing
        # binding is outstanding. The schema requires at least one item, so the
        # document records that explicitly rather than being omitted.
        items.append(
            {
                "uuid": fathom_uuid("poam-item", run_id, "none"),
                "title": "No outstanding SHALL-level failures",
                "description": (
                    "ScubaGear reported no failing SHALL policies for this run. "
                    "No plan of action is required."
                ),
                "props": [prop("placeholder", "true")],
            }
        )

    document = {
        "plan-of-action-and-milestones": {
            "uuid": fathom_uuid("poam", run_id),
            "metadata": metadata(
                f"Plan of Action and Milestones for {run.metadata.tenant_alias}",
                last_modified=collected,
                version=run_id,
                tool_version=run.metadata.tool_version,
                extra_props=[prop("poam-item-count", str(len(actionable)))],
            ),
            "system-id": {
                "identifier-type": "https://github.com/fathom/ns/oscal",
                "id": run.metadata.tenant_alias,
            },
            "poam-items": items,
        }
    }
    return document, [c.policy_id for c in actionable]


__all__ = ["build_poam", "dumps"]
