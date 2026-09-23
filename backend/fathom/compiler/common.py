"""Shared OSCAL scaffolding: metadata, props, links, and serialization."""
from __future__ import annotations

import json
from typing import Any

from fathom import config

# OSCAL sanctions vendor extension via namespaced props. Every Fathom-specific
# fact lives under this namespace so a consumer can tell our additions from
# NIST-defined fields at a glance.
FATHOM_NS = "https://github.com/fathom/ns/oscal"

ATTACK_BASE = "https://attack.mitre.org/techniques/"


def prop(name: str, value: str, *, ns: str | None = FATHOM_NS, klass: str | None = None) -> dict:
    """Build an OSCAL prop. Namespaced by default."""
    out: dict[str, Any] = {"name": name, "value": value}
    if ns:
        out["ns"] = ns
    if klass:
        out["class"] = klass
    return out


def link(href: str, rel: str, text: str | None = None) -> dict:
    out: dict[str, Any] = {"href": href, "rel": rel}
    if text:
        out["text"] = text
    return out


def metadata(
    title: str,
    *,
    last_modified: str,
    version: str,
    tool_version: str,
    extra_props: list[dict] | None = None,
) -> dict:
    """Build OSCAL metadata.

    `last_modified` is passed in rather than read from the clock: a compiler
    that stamps `now()` cannot produce byte-identical output. Fathom uses the
    scan's own timestamp, which makes the artifact a faithful record of when the
    evidence was collected rather than when the file happened to be written.
    """
    props = [
        prop("compiled-by", "fathom"),
        prop("scubagear-tag", config.SCUBAGEAR_TAG),
        prop("scubagear-tool-version", tool_version),
    ]
    props.extend(extra_props or [])
    return {
        "title": title,
        "last-modified": last_modified,
        "version": version,
        "oscal-version": config.OSCAL_VERSION,
        "props": props,
    }


def dumps(document: dict) -> bytes:
    """Serialize an OSCAL document deterministically.

    Sorted keys and a fixed separator/indent mean the same logical document
    always produces the same bytes, which is what makes the SHA-256 of an
    artifact a meaningful identity rather than an accident of dict ordering.
    """
    return (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False).rstrip() + "\n"
    ).encode("utf-8")
