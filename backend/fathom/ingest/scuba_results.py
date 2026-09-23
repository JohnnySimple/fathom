"""Parse ScubaResults.json into a normalized `ScanRun`.

This is the evidence side of the pipeline. Three properties of ScubaGear's real
output drive the implementation and are easy to get wrong:

1. The file is written by PowerShell and carries a UTF-8 BOM. `json.load` with
   the default encoding raises on it; `utf-8-sig` is required.
2. `Requirement` and `Details` contain presentation HTML that must be stripped
   before the text is used as OSCAL content.
3. Manual checks are signalled by a "/Not-Implemented" suffix on `Criticality`,
   not by `Result`. Criticality and checkability are separate facts, so they are
   normalized into separate fields.

Tenant identifiers are aliased here, at the edge, before anything is stored.
Nothing downstream ever sees the real tenant ID or domain.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from fathom.ingest.text import strip_html
from fathom.models import (
    Annotation,
    ControlResult,
    Criticality,
    ResultState,
    RunMetadata,
    ScanRun,
)

# ScubaGear's result vocabulary -> Fathom's normalized enum. Unknown strings are
# an error rather than a silent default: mapping an unrecognized verdict to
# "pass" or "fail" would fabricate a security claim.
_RESULT_MAP: dict[str, ResultState] = {
    "pass": ResultState.PASS,
    "fail": ResultState.FAIL,
    "warning": ResultState.WARNING,
    "n/a": ResultState.NOT_APPLICABLE,
    "na": ResultState.NOT_APPLICABLE,
    "not applicable": ResultState.NOT_APPLICABLE,
    "3rd party": ResultState.NOT_APPLICABLE,
    "third party": ResultState.NOT_APPLICABLE,
    "omit": ResultState.OMITTED,
    "omitted": ResultState.OMITTED,
    "error": ResultState.ERROR,
}

# ScubaGear writes the literal string "N/A" into annotation fields that have no
# value, so an unset field is not distinguishable by truthiness alone.
_EMPTY_SENTINELS = {"", "n/a", "none", "null"}


class ScubaParseError(ValueError):
    """Raised when ScubaResults.json does not match the expected structure."""


def _blank(value: Any) -> bool:
    return value is None or (isinstance(value, str) and value.strip().lower() in _EMPTY_SENTINELS)


def _clean(value: Any) -> str | None:
    """Strip HTML and collapse ScubaGear's 'N/A' placeholders to None."""
    if _blank(value):
        return None
    text = strip_html(str(value))
    return text or None


def _normalize_result(raw: Any, policy_id: str) -> ResultState:
    key = strip_html(str(raw)).strip().lower()
    if key not in _RESULT_MAP:
        raise ScubaParseError(f"{policy_id}: unrecognized Result {raw!r}")
    return _RESULT_MAP[key]


def _normalize_criticality(raw: Any, policy_id: str) -> tuple[Criticality, bool]:
    """Split "Shall/Not-Implemented" into (SHALL, is_manual=True)."""
    text = strip_html(str(raw)).strip()
    head, _, suffix = text.partition("/")
    key = head.strip().upper()
    if key not in ("SHALL", "SHOULD"):
        raise ScubaParseError(f"{policy_id}: unrecognized Criticality {raw!r}")
    is_manual = "not-implemented" in suffix.strip().lower()
    return Criticality[key], is_manual


def alias_tenant(tenant_id: str) -> str:
    """Derive a stable, non-reversible pseudonym for a tenant.

    Stable so that two scans of the same tenant compare cleanly in a drift
    report; non-reversible so that the alias itself leaks nothing. The real
    tenant ID is never persisted.
    """
    digest = hashlib.sha256(f"fathom-tenant:{tenant_id}".encode()).hexdigest()
    return f"tenant-{digest[:8]}"


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def parse_scuba_results(payload: bytes) -> ScanRun:
    """Parse raw ScubaResults.json bytes into a normalized `ScanRun`."""
    try:
        document = json.loads(payload.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScubaParseError(f"not valid JSON: {exc}") from exc

    if not isinstance(document, dict) or "Results" not in document:
        raise ScubaParseError("missing top-level 'Results'; is this a ScubaResults file?")

    meta = document.get("MetaData") or {}
    raw = document.get("Raw") or {}
    annotations = document.get("AnnotatedFailedPolicies") or {}

    tenant_id = str(meta.get("TenantId", "unknown"))
    timestamp = meta.get("TimestampZulu")
    if not timestamp:
        raise ScubaParseError("MetaData.TimestampZulu is required")

    metadata = RunMetadata(
        report_uuid=str(meta.get("ReportUUID", "")),
        tenant_alias=alias_tenant(tenant_id),
        # Display name is aliased too: agency tenant names are themselves
        # identifying.
        tenant_display_alias=alias_tenant(str(meta.get("DisplayName", tenant_id))).replace(
            "tenant-", "org-"
        ),
        tool=str(meta.get("Tool", "ScubaGear")),
        tool_version=str(meta.get("ToolVersion", "unknown")),
        baseline_version=(str(raw["baseline_version"]) if raw.get("baseline_version") else None),
        timestamp_zulu=datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")),
        products_assessed=sorted(str(p) for p in meta.get("ProductsAssessed", [])),
        source_sha256=sha256_bytes(payload),
    )

    results: list[ControlResult] = []
    for product, groups in sorted((document["Results"] or {}).items()):
        if not isinstance(groups, list):
            raise ScubaParseError(f"Results.{product} is not a list of groups")
        for group in groups:
            group_number = str(group.get("GroupNumber", ""))
            group_name = str(group.get("GroupName", ""))
            for control in group.get("Controls", []):
                policy_id = str(control.get("Control ID", "")).strip()
                if not policy_id:
                    raise ScubaParseError(f"Results.{product} has a control with no Control ID")

                criticality, is_manual = _normalize_criticality(
                    control.get("Criticality"), policy_id
                )
                state = _normalize_result(control.get("Result"), policy_id)

                # A policy omitted via YAML config keeps its pre-omission
                # verdict so the risk-acceptance trail stays auditable.
                omission = _clean(control.get("OmittedEvaluationResult"))
                original_state: ResultState | None = None
                if omission:
                    original_raw = control.get("OriginalResult")
                    if not _blank(original_raw):
                        original_state = _normalize_result(original_raw, policy_id)
                    state = ResultState.OMITTED

                annotation = None
                if entry := annotations.get(policy_id):
                    comment = _clean(entry.get("Comment"))
                    remediation = _clean(entry.get("RemediationDate"))
                    incorrect = bool(entry.get("IncorrectResult"))
                    if comment or remediation or incorrect:
                        annotation = Annotation(
                            comment=comment,
                            remediation_date=remediation,
                            marked_incorrect=incorrect,
                        )

                results.append(
                    ControlResult(
                        policy_id=policy_id,
                        product=str(product).upper(),
                        group_number=group_number,
                        group_name=group_name,
                        requirement=strip_html(control.get("Requirement")),
                        state=state,
                        criticality=criticality,
                        is_manual=is_manual,
                        details=strip_html(control.get("Details")),
                        original_state=original_state,
                        omission_rationale=_clean(control.get("OmittedEvaluationDetails")),
                        annotation=annotation,
                    )
                )

    if not results:
        raise ScubaParseError("no control results found")

    return ScanRun(
        metadata=metadata,
        results=sorted(results, key=lambda r: r.policy_id),
        raw_provider_keys=sorted(str(k) for k in raw),
    )


def parse_scuba_results_file(path: Path) -> ScanRun:
    return parse_scuba_results(path.read_bytes())


def extract_provider_config(payload: bytes) -> dict[str, Any]:
    """Return ScubaResults.Raw -- the provider settings CISA's Rego evaluates.

    Kept separate from `parse_scuba_results` because this is bulk configuration
    data (megabytes) used only by the What-If simulator, and it must never be
    loaded into a context the LLM can read.
    """
    document = json.loads(payload.decode("utf-8-sig"))
    return document.get("Raw") or {}
