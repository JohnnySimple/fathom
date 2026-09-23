"""Orchestrate the full compile: parse -> compile -> validate.

One call takes raw ScubaResults bytes to five validated OSCAL artifacts. The
pipeline is a pure function of its inputs plus the pinned sources, so the same
upload always yields the same `CompileResult`, including the same artifact
hashes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from fathom import config
from fathom.compiler.assessment_plan import build_assessment_plan
from fathom.compiler.assessment_results import CompiledFinding, build_assessment_results
from fathom.compiler.catalog import build_catalog
from fathom.compiler.common import dumps
from fathom.compiler.ids import run_id_for
from fathom.compiler.poam import build_poam
from fathom.compiler.profile import build_profile
from fathom.ingest.scuba_results import parse_scuba_results
from fathom.ingest.sources import SourceBundle, load_nist_control_titles, load_sources
from fathom.models import ScanRun
from fathom.validation.schema import ValidationReport, validate_model

# Compile order matters for the UI's stage-by-stage animation and mirrors the
# dependency order: later artifacts reference earlier ones.
MODEL_ORDER = ["catalog", "profile", "assessment-plan", "assessment-results", "poam"]

ProgressFn = Callable[[str, str], None]


@dataclass
class Artifact:
    model: str
    document: dict
    raw: bytes
    sha256: str
    validation: ValidationReport

    @property
    def valid(self) -> bool:
        return self.validation.valid


@dataclass
class CompileResult:
    run_id: str
    run: ScanRun
    artifacts: dict[str, Artifact]
    compiled: list[CompiledFinding]
    evidence_blobs: dict[str, bytes] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def all_valid(self) -> bool:
        return all(a.valid for a in self.artifacts.values())

    def summary(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "tenant_alias": self.run.metadata.tenant_alias,
            "all_valid": self.all_valid,
            "artifacts": {
                name: {
                    "sha256": art.sha256,
                    "bytes": len(art.raw),
                    "valid": art.valid,
                    "issues": len(art.validation.issues),
                }
                for name, art in self.artifacts.items()
            },
            "warnings": self.warnings,
        }


def _artifact(model: str, document: dict) -> Artifact:
    import hashlib

    raw = dumps(document)
    return Artifact(
        model=model,
        document=document,
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
        validation=validate_model(model, document),
    )


def compile_scan(
    payload: bytes,
    *,
    products: list[str] | None = None,
    bundle: SourceBundle | None = None,
    progress: ProgressFn | None = None,
) -> CompileResult:
    """Compile raw ScubaResults bytes into validated OSCAL artifacts."""

    def emit(stage: str, message: str) -> None:
        if progress:
            progress(stage, message)

    emit("parse", "Parsing ScubaResults.json")
    run = parse_scuba_results(payload)
    run_id = run_id_for(run.metadata.source_sha256)

    emit("sources", "Loading pinned CISA and NIST sources")
    bundle = bundle or load_sources(products or config.ALL_PRODUCTS)
    warnings = list(bundle.warnings)

    # Version drift between the scan and the pinned baselines is reported up
    # front rather than buried in a prop, because it changes how a reader should
    # read the catalog.
    drift = []
    for result in run.results:
        resolution = bundle.resolve(result.policy_id)
        if resolution and resolution.version_drift:
            drift.append(f"{result.policy_id} -> catalog control {resolution.policy.id}")
    if drift:
        warnings.append(
            f"{len(drift)} assessed policy version(s) not present in the pinned "
            f"baselines; resolved to the nearest catalog version: {', '.join(sorted(drift))}"
        )

    last_modified = run.metadata.timestamp_zulu.isoformat()
    artifacts: dict[str, Artifact] = {}

    emit("catalog", "Compiling OSCAL Catalog from SCuBA baselines")
    artifacts["catalog"] = _artifact(
        "catalog",
        build_catalog(
            bundle.policies,
            last_modified=last_modified,
            tool_version=run.metadata.tool_version,
            baseline_version=run.metadata.baseline_version,
            nist_titles=load_nist_control_titles(),
        ),
    )

    emit("assessment-results", "Compiling Assessment Results")
    ar_document, compiled, blobs = build_assessment_results(run, bundle, run_id=run_id)
    assessed_control_ids = sorted({c.catalog_control_id for c in compiled})

    emit("profile", "Compiling OSCAL Profile for assessed scope")
    artifacts["profile"] = _artifact(
        "profile",
        build_profile(
            assessed_control_ids,
            run_id=run_id,
            last_modified=last_modified,
            tool_version=run.metadata.tool_version,
            tenant_alias=run.metadata.tenant_alias,
        ),
    )

    emit("assessment-plan", "Compiling Assessment Plan")
    artifacts["assessment-plan"] = _artifact(
        "assessment-plan",
        build_assessment_plan(
            assessed_control_ids,
            run_id=run_id,
            last_modified=last_modified,
            tool_version=run.metadata.tool_version,
            tenant_alias=run.metadata.tenant_alias,
            products=sorted({c.product for c in compiled}),
        ),
    )

    artifacts["assessment-results"] = _artifact("assessment-results", ar_document)

    emit("poam", "Compiling POA&M from SHALL-level failures")
    poam_document, _ = build_poam(run, bundle, compiled, run_id=run_id)
    artifacts["poam"] = _artifact("poam", poam_document)

    emit("validate", "Validating against NIST OSCAL schemas")
    for model in MODEL_ORDER:
        report = artifacts[model].validation
        emit("validate", report.summary())

    return CompileResult(
        run_id=run_id,
        run=run,
        artifacts={m: artifacts[m] for m in MODEL_ORDER},
        compiled=compiled,
        evidence_blobs=blobs,
        warnings=warnings,
    )
