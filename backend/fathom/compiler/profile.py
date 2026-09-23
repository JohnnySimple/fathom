"""Compile an OSCAL Profile selecting the controls a scan actually assessed.

The catalog says what SCuBA requires; the profile says what this particular scan
looked at. They differ in practice -- CISA's sample scan assesses 92 of the 126
policies defined across the baselines -- and an auditor needs that distinction
to be explicit rather than inferred from which findings happen to exist.
"""
from __future__ import annotations

from fathom.compiler.common import dumps, metadata, prop
from fathom.compiler.ids import fathom_uuid

CATALOG_HREF = "./catalog.json"


def build_profile(
    assessed_control_ids: list[str],
    *,
    run_id: str,
    last_modified: str,
    tool_version: str,
    tenant_alias: str,
) -> dict:
    """Build a Profile importing the Fathom catalog and selecting assessed controls."""
    control_ids = sorted(set(assessed_control_ids))
    return {
        "profile": {
            "uuid": fathom_uuid("profile", run_id),
            "metadata": metadata(
                f"SCuBA Assessment Scope for {tenant_alias}",
                last_modified=last_modified,
                version=run_id,
                tool_version=tool_version,
                extra_props=[prop("assessed-control-count", str(len(control_ids)))],
            ),
            "imports": [{"href": CATALOG_HREF, "include-controls": [{"with-ids": control_ids}]}],
            "merge": {"as-is": True},
        }
    }


__all__ = ["build_profile", "dumps", "CATALOG_HREF"]
