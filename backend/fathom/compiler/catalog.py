"""Compile SCuBA baselines into an OSCAL Catalog.

The catalog is the requirement side of the ATO package: every SCuBA policy
becomes an OSCAL control, and the baseline's own structure is preserved rather
than flattened.

    catalog
      group  aad                    <- one per product
        group  aad-1                <- one per baseline policy group
          control  ms.aad.1.1v1     <- one per policy

OSCAL control IDs must be tokens, so `MS.AAD.1.1v1` is lowercased to
`ms.aad.1.1v1`. The original casing is preserved verbatim in a `label` prop, per
OSCAL convention, so nothing about CISA's identifier is lost.

Mappings are emitted twice on purpose: as namespaced props for machine
consumption (the posture graph reads these) and as links for human navigation.
"""
from __future__ import annotations

from fathom.compiler.common import ATTACK_BASE, FATHOM_NS, dumps, link, metadata, prop
from fathom.compiler.ids import fathom_uuid
from fathom.ingest.nist_ids import to_oscal_id
from fathom.ingest.text import requirement_sentence
from fathom.models import Policy

# Human-facing product names. ScubaGear's own abbreviations are the keys.
PRODUCT_TITLES = {
    "AAD": "Microsoft Entra ID (Azure Active Directory)",
    "DEFENDER": "Microsoft 365 Defender",
    "EXO": "Exchange Online",
    "POWERPLATFORM": "Microsoft Power Platform",
    "SHAREPOINT": "SharePoint Online and OneDrive",
    "TEAMS": "Microsoft Teams",
}

NIST_CATALOG_URI = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/"
    "SP800-53/rev5/json/NIST_SP-800-53_rev5_HIGH-baseline-resolved-profile_catalog-min.json"
)


def _control(policy: Policy, nist_titles: dict[str, str]) -> dict:
    """Build one OSCAL control from one SCuBA policy."""
    props = [
        # `label` is an OSCAL-defined prop, so it carries no Fathom namespace.
        prop("label", policy.id, ns=None),
        prop("product", policy.product),
        prop("criticality", policy.criticality.value),
        prop("baseline-group", f"{policy.group_number}. {policy.group_name}"),
    ]
    if policy.last_modified:
        props.append(prop("baseline-last-modified", policy.last_modified))

    links: list[dict] = []
    for control_id in policy.nist_controls:
        oscal_id = to_oscal_id(control_id)
        if not oscal_id:
            continue
        title = nist_titles.get(oscal_id, "")
        props.append(prop("nist-800-53-r5", control_id))
        links.append(
            link(
                f"{NIST_CATALOG_URI}#{oscal_id}",
                "nist-800-53-r5",
                f"{control_id} {title}".strip(),
            )
        )

    for technique in policy.attack_techniques:
        props.append(prop("attack-technique", technique.id))
        links.append(link(technique.url, "mitre-attack", f"{technique.id} {technique.name}"))

    # Title is the normative first sentence; the complete statement, including
    # implementation guidance, is preserved verbatim in the statement part.
    parts = [
        {"id": f"{policy.oscal_control_id}_smt", "name": "statement", "prose": policy.statement}
    ]
    if policy.rationale:
        parts.append(
            {
                "id": f"{policy.oscal_control_id}_rationale",
                "name": "rationale",
                "ns": FATHOM_NS,
                "prose": policy.rationale,
            }
        )
    if policy.note:
        parts.append(
            {"id": f"{policy.oscal_control_id}_gdn", "name": "guidance", "prose": policy.note}
        )

    return {
        "id": policy.oscal_control_id,
        "title": requirement_sentence(policy.statement),
        "props": props,
        "links": links,
        "parts": parts,
    }


def build_catalog(
    policies: list[Policy],
    *,
    last_modified: str,
    tool_version: str,
    baseline_version: str | None,
    nist_titles: dict[str, str] | None = None,
) -> dict:
    """Build the full OSCAL Catalog document."""
    titles = nist_titles or {}
    products = sorted({p.product for p in policies})
    groups = []

    for product in products:
        product_policies = [p for p in policies if p.product == product]
        subgroups = []
        # Numeric sort: baseline group "10" must follow "9", not "1".
        group_keys = sorted(
            {(int(p.group_number), p.group_name) for p in product_policies}
        )
        for number, name in group_keys:
            controls = [
                _control(p, titles)
                for p in sorted(product_policies, key=lambda p: p.id)
                if int(p.group_number) == number
            ]
            subgroups.append(
                {
                    "id": f"{product.lower()}-{number}",
                    "class": "scuba-policy-group",
                    "title": name,
                    "controls": controls,
                }
            )
        groups.append(
            {
                "id": product.lower(),
                "class": "scuba-product",
                "title": PRODUCT_TITLES.get(product, product),
                "props": [prop("product", product)],
                "groups": subgroups,
            }
        )

    extra = [prop("scuba-baseline-version", baseline_version)] if baseline_version else []

    return {
        "catalog": {
            "uuid": fathom_uuid("catalog", ",".join(products), str(len(policies))),
            "metadata": metadata(
                "SCuBA Secure Configuration Baselines",
                last_modified=last_modified,
                version=baseline_version or "1",
                tool_version=tool_version,
                extra_props=extra,
            ),
            "groups": groups,
        }
    }


__all__ = ["build_catalog", "dumps", "PRODUCT_TITLES", "NIST_CATALOG_URI"]
