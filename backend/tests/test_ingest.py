"""Parser tests, against CISA's real published data rather than mocks."""
from __future__ import annotations

import pytest

from fathom import config
from fathom.ingest.baseline_md import BaselineParseError, parse_baseline
from fathom.ingest.mappings import cross_check, load_nist_mapping
from fathom.ingest.nist_ids import to_oscal_id
from fathom.ingest.scuba_results import ScubaParseError, alias_tenant, parse_scuba_results
from fathom.ingest.text import requirement_sentence, strip_html
from fathom.models import Criticality, ResultState


def test_parses_every_policy_in_every_baseline(bundle):
    # 126 is independently verifiable: it is the number of "_Rationale:_"
    # bullets across the six baseline files.
    assert len(bundle.policies) == 126


def test_policy_headings_in_implementation_sections_are_not_parsed():
    """Each baseline repeats '#### MS.AAD.1.1v1 Instructions' under Implementation."""
    policies = parse_baseline(config.BASELINE_DIR / "aad.md", "AAD")
    assert len(policies) == 30
    assert len({p.id for p in policies}) == 30


def test_attack_subtechnique_parentage():
    policies = parse_baseline(config.BASELINE_DIR / "aad.md", "AAD")
    legacy_auth = next(p for p in policies if p.id == "MS.AAD.1.1v1")
    techniques = {t.id: t.parent_id for t in legacy_auth.attack_techniques}
    assert techniques["T1110"] is None
    assert techniques["T1110.003"] == "T1110"


def test_missing_criticality_is_an_error_not_a_guess(tmp_path):
    """Guessing SHALL vs SHOULD from prose would be a silent correctness risk."""
    path = tmp_path / "fake.md"
    path.write_text("## 1. Group\n### Policies\n#### MS.FAKE.1.1v1\nSomething SHALL happen.\n")
    with pytest.raises(BaselineParseError, match="Criticality"):
        parse_baseline(path, "FAKE")


def test_scuba_results_file_has_utf8_bom(payload):
    """ScubaGear is PowerShell-written; plain utf-8 decoding fails on the BOM."""
    assert payload[:3] == b"\xef\xbb\xbf"


def test_parses_bom_encoded_results(payload):
    run = parse_scuba_results(payload)
    assert len(run.results) == 92


def test_html_is_stripped_from_requirements(payload):
    run = parse_scuba_results(payload)
    assert not any("<div" in r.requirement for r in run.results)
    assert not any("policy-indicators" in r.requirement for r in run.results)


def test_manual_checks_are_split_from_criticality(payload):
    """'Shall/Not-Implemented' means a binding policy with no automated check."""
    run = parse_scuba_results(payload)
    manual = [r for r in run.results if r.is_manual]
    assert len(manual) == 9
    assert all(r.state is ResultState.NOT_APPLICABLE for r in manual)
    assert any(r.criticality is Criticality.SHALL for r in manual)


def test_tenant_identifiers_never_survive_parsing(payload):
    run = parse_scuba_results(payload)
    serialized = run.metadata.model_dump_json()
    assert "ca08493a" not in serialized          # real tenant GUID in the sample
    assert "tqhjy" not in serialized.lower()      # real tenant display name/domain
    assert run.metadata.tenant_alias.startswith("tenant-")


def test_tenant_alias_is_stable_and_not_reversible():
    assert alias_tenant("abc") == alias_tenant("abc")
    assert alias_tenant("abc") != alias_tenant("abd")
    assert "abc" not in alias_tenant("abc")


def test_unknown_result_string_is_rejected():
    """Mapping an unrecognized verdict to pass or fail would fabricate a claim."""
    import json

    doc = {
        "MetaData": {"TimestampZulu": "2026-01-01T00:00:00Z", "ToolVersion": "1.8.0"},
        "Results": {
            "AAD": [
                {
                    "GroupNumber": "1",
                    "GroupName": "G",
                    "Controls": [
                        {"Control ID": "MS.AAD.1.1v1", "Result": "Probably Fine",
                         "Criticality": "Shall", "Requirement": "x", "Details": "y"}
                    ],
                }
            ]
        },
    }
    with pytest.raises(ScubaParseError, match="unrecognized Result"):
        parse_scuba_results(json.dumps(doc).encode())


def test_nist_csv_and_baseline_text_agree(bundle):
    """CISA publishes the mapping twice; disagreement means upstream drift."""
    mapping = load_nist_mapping(config.NIST_MAPPING_CSV)
    baseline = {p.id: sorted(set(p.nist_controls)) for p in bundle.policies}
    assert cross_check(mapping, baseline) == []


@pytest.mark.parametrize(
    ("cisa", "oscal"),
    [("CM-7", "cm-7"), ("AC-2(12)", "ac-2.12"), ("IA-5c", "ia-5"), ("IA-2(1)", "ia-2.1")],
)
def test_nist_id_translation(cisa, oscal):
    assert to_oscal_id(cisa) == oscal


def test_strip_html_and_requirement_sentence():
    assert strip_html("<b>Hi</b> <i>there</i>") == "Hi there"
    statement = "Phishing-resistant MFA SHALL be enforced. The methods **FIDO2** and others apply."
    assert requirement_sentence(statement) == "Phishing-resistant MFA SHALL be enforced."
