"""Compile a minimal OSCAL Assessment Plan.

OSCAL Assessment Results must import an Assessment Plan, so Fathom generates a
minimal but truthful one describing what ScubaGear did: an automated
configuration assessment of the selected controls against one tenant.

`import-ssp` is required by the schema, but a ScubaGear scan is not performed
against an SSP. Rather than point at a fabricated system security plan, the
reference resolves to a back-matter resource that states plainly that no SSP was
supplied and that the scope came from the compiled profile. That keeps the
document schema-valid without asserting the existence of a document nobody wrote.
"""
from __future__ import annotations

from fathom.compiler.common import dumps, metadata, prop
from fathom.compiler.ids import fathom_uuid

PROFILE_HREF = "./profile.json"


def build_assessment_plan(
    assessed_control_ids: list[str],
    *,
    run_id: str,
    last_modified: str,
    tool_version: str,
    tenant_alias: str,
    products: list[str],
) -> dict:
    control_ids = sorted(set(assessed_control_ids))
    no_ssp_uuid = fathom_uuid("resource", run_id, "no-ssp")
    subject_uuid = fathom_uuid("subject", run_id, tenant_alias)

    return {
        "assessment-plan": {
            "uuid": fathom_uuid("assessment-plan", run_id),
            "metadata": metadata(
                f"ScubaGear Automated Assessment Plan for {tenant_alias}",
                last_modified=last_modified,
                version=run_id,
                tool_version=tool_version,
                extra_props=[prop("assessment-method", "automated-configuration-scan")],
            ),
            "import-ssp": {
                "href": f"#{no_ssp_uuid}",
                "remarks": (
                    "No System Security Plan was supplied. ScubaGear assesses tenant "
                    "configuration directly; assessment scope is defined by the imported "
                    "profile rather than by an SSP."
                ),
            },
            "assessment-subjects": [
                {
                    "type": "inventory-item",
                    "description": (
                        f"Microsoft 365 tenant {tenant_alias}, products assessed: "
                        f"{', '.join(sorted(products))}."
                    ),
                    "include-subjects": [
                        {"subject-uuid": subject_uuid, "type": "inventory-item"}
                    ],
                }
            ],
            "reviewed-controls": {
                "description": (
                    "SCuBA policies evaluated by ScubaGear during this run, as selected "
                    "by the compiled profile."
                ),
                "control-selections": [{"include-controls": [{"control-id": c} for c in control_ids]}],
            },
            "back-matter": {
                "resources": [
                    {
                        "uuid": no_ssp_uuid,
                        "title": "No System Security Plan supplied",
                        "description": (
                            "Placeholder reference. Fathom compiles from a ScubaGear scan, "
                            "which evaluates live tenant configuration and does not require "
                            "an SSP. This resource exists so the OSCAL-required import-ssp "
                            "reference resolves without asserting a document that does not exist."
                        ),
                    }
                ]
            },
        }
    }


__all__ = ["build_assessment_plan", "dumps", "PROFILE_HREF"]
