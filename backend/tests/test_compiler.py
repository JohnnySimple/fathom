"""Compiler and validation tests.

These carry the project's central claim: that Fathom emits real OSCAL,
reproducibly, without fabricating security conclusions.
"""
from __future__ import annotations

import copy

import pytest

from fathom.compiler.ids import fathom_uuid
from fathom.compiler.pipeline import MODEL_ORDER, compile_scan
from fathom.models import Criticality, ResultState
from fathom.validation.schema import validate_model


def test_all_five_artifacts_validate_against_nist_schemas(result):
    for model in MODEL_ORDER:
        report = result.artifacts[model].validation
        assert report.valid, f"{model} invalid: {[str(i) for i in report.issues]}"


def test_recompiling_is_byte_identical(payload, bundle, result):
    """Determinism is the compiler's headline guarantee, so it is asserted on bytes."""
    again = compile_scan(payload, bundle=bundle)
    assert again.run_id == result.run_id
    for model in MODEL_ORDER:
        assert again.artifacts[model].raw == result.artifacts[model].raw
        assert again.artifacts[model].sha256 == result.artifacts[model].sha256


def test_uuids_are_stable_across_processes():
    """Citations must survive a restart, so UUIDv5 seeds are fixed, never random."""
    assert fathom_uuid("finding", "run", "MS.AAD.1.1v1") == fathom_uuid(
        "finding", "run", "MS.AAD.1.1v1"
    )
    assert fathom_uuid("a", "bc") != fathom_uuid("ab", "c")


@pytest.mark.parametrize(
    ("name", "mutate", "expect"),
    [
        ("bad uuid", lambda d: d["catalog"].update(uuid="nope"), "does not match"),
        ("missing metadata", lambda d: d["catalog"].pop("metadata"), "required property"),
        ("extra field", lambda d: d["catalog"].update(bogus=1), "Additional properties"),
        (
            "non-token control id",
            lambda d: d["catalog"]["groups"][0]["groups"][0]["controls"][0].update(
                id="MS.AAD 1.1v1"
            ),
            "",
        ),
    ],
)
def test_validator_rejects_malformed_oscal(result, name, mutate, expect):
    """Guards against a vacuous pass: the validator must actually reject things."""
    document = copy.deepcopy(result.artifacts["catalog"].document)
    mutate(document)
    report = validate_model("catalog", document)
    assert not report.valid, f"{name} was wrongly accepted"
    if expect:
        assert any(expect in i.message for i in report.issues)


def test_manual_checks_produce_no_finding(result):
    """OSCAL has only satisfied/not-satisfied. A manual check is neither.

    This is the guarantee that separates Fathom from a tool that quietly turns
    'nobody checked' into 'compliant'.
    """
    manual = [c for c in result.compiled if not c.state.is_automated_verdict]
    assert len(manual) == 9
    assert all(c.finding_uuid is None for c in manual)
    assert all(c.risk_uuid is not None for c in manual)


def test_finding_counts_reconcile_with_the_scan(result):
    states = {}
    for entry in result.compiled:
        states[entry.state] = states.get(entry.state, 0) + 1
    assert states[ResultState.PASS] == 57
    assert states[ResultState.FAIL] == 14
    assert states[ResultState.WARNING] == 12
    assert states[ResultState.NOT_APPLICABLE] == 9

    results = result.artifacts["assessment-results"].document["assessment-results"]["results"][0]
    assert len(results["observations"]) == 92           # one per assessed policy
    assert len(results["findings"]) == 83               # 57 + 14 + 12, manual excluded
    assert len(results["risks"]) == 35                  # 26 failures + 9 unverified
    satisfied = [f for f in results["findings"] if f["target"]["status"]["state"] == "satisfied"]
    assert len(satisfied) == 57


def test_poam_covers_exactly_the_shall_failures(result):
    items = result.artifacts["poam"].document["plan-of-action-and-milestones"]["poam-items"]
    shall_failures = [
        c
        for c in result.compiled
        if c.criticality is Criticality.SHALL and c.state is ResultState.FAIL
    ]
    assert len(items) == len(shall_failures) == 14
    # A SHOULD-level warning is a recommendation, not a commitment.
    covered = {
        p["value"] for i in items for p in i.get("props", []) if p["name"] == "policy-id"
    }
    assert all(c.criticality is Criticality.SHALL for c in result.compiled if c.policy_id in covered)


def test_every_finding_references_a_real_observation(result):
    results = result.artifacts["assessment-results"].document["assessment-results"]["results"][0]
    observation_uuids = {o["uuid"] for o in results["observations"]}
    for finding in results["findings"]:
        for reference in finding.get("related-observations", []):
            assert reference["observation-uuid"] in observation_uuids


def test_every_finding_targets_a_real_catalog_statement(result):
    catalog = result.artifacts["catalog"].document["catalog"]
    statement_ids = set()

    def walk(group):
        for control in group.get("controls", []):
            for part in control.get("parts", []):
                statement_ids.add(part.get("id"))
        for child in group.get("groups", []):
            walk(child)

    for group in catalog["groups"]:
        walk(group)

    results = result.artifacts["assessment-results"].document["assessment-results"]["results"][0]
    for finding in results["findings"]:
        assert finding["target"]["target-id"] in statement_ids


def test_policy_version_drift_is_reported_not_hidden(result):
    """CISA's sample reports policy versions absent from the pinned baselines."""
    drifted = [c for c in result.compiled if c.version_drift]
    assert {c.policy_id for c in drifted} == {"MS.AAD.3.2v2", "MS.AAD.3.5v2", "MS.EXO.2.2v3"}
    assert any("not present in the pinned baselines" in w for w in result.warnings)


def test_evidence_blob_per_assessed_policy(result):
    assert len(result.evidence_blobs) == 92
    for entry in result.compiled:
        assert entry.evidence_sha256 in result.evidence_blobs
