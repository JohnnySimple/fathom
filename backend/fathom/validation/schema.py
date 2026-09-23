"""Validate compiled artifacts against NIST's own OSCAL JSON Schemas.

This is the objective-proof step: the claim "Fathom emits valid OSCAL" is only
worth making because it is mechanically checked against the schema NIST
publishes for the pinned OSCAL version, not against our own idea of the shape.

Validation is a gate, not a report. `CompileResult` carries the outcome and the
store refuses to mark an invalid artifact as servable evidence.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema.protocols import Validator
from jsonschema.validators import validator_for

from fathom import config

# Fathom model name -> OSCAL schema file stem.
# OSCAL's schemas are authored against XSD regex semantics and use Unicode
# property escapes, which Python's `re` cannot compile. Exactly two appear
# across all five schemas, both in the OSCAL "token" pattern. They are
# translated rather than the pattern being dropped, so token-shaped IDs are
# still genuinely enforced. The map is a whitelist: an unrecognized class raises
# instead of being silently ignored, so a future OSCAL release cannot quietly
# weaken validation.
_UNICODE_CLASS_EQUIVALENTS = {
    r"\p{L}": r"[^\W\d_]",  # any letter
    r"\p{N}": r"\d",         # any number
}
_UNICODE_CLASS = re.compile(r"\\p\{[A-Za-z]+\}")

SCHEMA_FILES = {
    "catalog": "oscal_catalog_schema.json",
    "profile": "oscal_profile_schema.json",
    "assessment-plan": "oscal_assessment-plan_schema.json",
    "assessment-results": "oscal_assessment-results_schema.json",
    "poam": "oscal_poam_schema.json",
}


@dataclass
class ValidationIssue:
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path or '<root>'}: {self.message}"


@dataclass
class ValidationReport:
    model: str
    valid: bool
    validator: str
    oscal_version: str
    issues: list[ValidationIssue] = field(default_factory=list)
    skipped_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "valid": self.valid,
            "validator": self.validator,
            "oscal_version": self.oscal_version,
            "issues": [{"path": i.path, "message": i.message} for i in self.issues],
            "skipped_reason": self.skipped_reason,
        }

    def summary(self) -> str:
        if self.skipped_reason:
            return f"{self.model}: skipped ({self.skipped_reason})"
        status = "VALID" if self.valid else f"INVALID ({len(self.issues)} issue(s))"
        return f"{self.model}: {status} [{self.validator}]"


def _pythonize_patterns(node: Any) -> Any:
    """Rewrite XSD-style Unicode escapes in every `pattern` to Python syntax."""
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str) and "\\p{" in value:
                translated = value
                for xsd, py in _UNICODE_CLASS_EQUIVALENTS.items():
                    translated = translated.replace(xsd, py)
                if leftover := _UNICODE_CLASS.search(translated):
                    raise ValueError(
                        f"unsupported Unicode class {leftover.group()} in OSCAL pattern "
                        f"{value!r}; add a translation to _UNICODE_CLASS_EQUIVALENTS"
                    )
                out[key] = translated
            else:
                out[key] = _pythonize_patterns(value)
        return out
    if isinstance(node, list):
        return [_pythonize_patterns(v) for v in node]
    return node


@lru_cache(maxsize=8)
def _validator(model: str) -> Validator:
    """Build a validator for the draft the schema itself declares.

    NIST publishes the OSCAL schemas as draft-07 and relies on fragment-only
    `$id` values in its subschemas. Forcing a newer draft changes how those
    resolve and makes every internal `$ref` fail, so the draft is read from the
    document rather than assumed.
    """
    filename = SCHEMA_FILES.get(model)
    if not filename:
        raise KeyError(f"no OSCAL schema registered for model {model!r}")
    path: Path = config.OSCAL_SCHEMA_DIR / filename
    if not path.exists():
        raise FileNotFoundError(
            f"missing OSCAL schema {path}; run: python scripts/fetch_sources.py"
        )
    schema = _pythonize_patterns(json.loads(path.read_text(encoding="utf-8")))
    return validator_for(schema)(schema)


def validate_model(model: str, document: dict, *, max_issues: int = 25) -> ValidationReport:
    """Validate one compiled document against its OSCAL schema."""
    try:
        validator = _validator(model)
    except FileNotFoundError as exc:
        return ValidationReport(
            model=model,
            valid=False,
            validator="jsonschema",
            oscal_version=config.OSCAL_VERSION,
            skipped_reason=str(exc),
        )

    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    issues = [
        ValidationIssue(path="/".join(str(p) for p in err.absolute_path), message=err.message)
        for err in errors[:max_issues]
    ]
    if len(errors) > max_issues:
        issues.append(
            ValidationIssue(path="", message=f"... and {len(errors) - max_issues} more issue(s)")
        )

    return ValidationReport(
        model=model,
        valid=not errors,
        validator=f"jsonschema/{type(validator).__name__} vs OSCAL {config.OSCAL_VERSION}",
        oscal_version=config.OSCAL_VERSION,
        issues=issues,
    )
