"""Query layer and risk scoring tests."""
from __future__ import annotations

from fathom.ingest.sources import load_sources
from fathom.models import Criticality
from fathom.risk import high_impact_techniques, score_policy


def test_risk_formula_matches_the_specification(bundle):
    """risk = w_crit * (1 + n_high_impact) * s_priv."""
    policy = next(p for p in bundle.policies if p.id == "MS.AAD.7.2v1")
    score = score_policy(policy)
    assert policy.criticality is Criticality.SHALL
    assert score.criticality_weight == 3.0
    assert score.privilege_multiplier == 1.5           # privileged-role policy
    expected = 3.0 * (1 + len(score.high_impact_techniques)) * 1.5
    assert score.score == round(expected, 2)


def test_risk_score_is_pure(bundle):
    policy = bundle.policies[0]
    assert score_policy(policy).score == score_policy(policy).score


def test_high_impact_list_contains_no_invented_techniques(bundle):
    """Every entry must be a technique CISA's baselines actually reference."""
    present = {(t.parent_id or t.id) for p in bundle.policies for t in p.attack_techniques}
    assert high_impact_techniques() <= present


def test_subtechniques_do_not_inflate_the_score(bundle):
    """Four sub-techniques of one technique must not outscore four techniques."""
    policy = next(p for p in bundle.policies if p.id == "MS.AAD.1.1v1")
    score = score_policy(policy)
    # T1110 + three sub-techniques, plus T1078 + one sub-technique -> 2 parents.
    assert score.high_impact_techniques == ("T1078", "T1110")


def test_posture_counts_are_computed_not_guessed(query):
    summary = query.posture_summary()
    assert summary["findings_total"] == 83
    assert summary["passed"] == 57
    assert summary["failed_shall"] == 14
    assert summary["failed_should"] == 12
    assert summary["unverified_manual"] == 9
    assert summary["oscal_artifacts_all_valid"] is True


def test_every_listed_finding_is_citable(query):
    for finding in query.list_findings(limit=50)["findings"]:
        assert query.resolve_uuid(finding["finding_uuid"]) is not None


def test_policy_id_lookup_is_case_insensitive(query):
    """`"MS.AAD.3.1v1".upper()` corrupts the version suffix; lookups must not."""
    for variant in ("MS.AAD.3.1v1", "ms.aad.3.1v1", "Ms.Aad.3.1V1"):
        assert query.get_control(variant)["policy_id"] == "MS.AAD.3.1v1"


def test_nist_impact_resolves_mappings(query):
    impact = query.nist_impact(["MS.AAD.3.1v1"])
    controls = {c["nist_control"] for c in impact["nist_controls"]}
    assert {"IA-2(1)", "IA-2(2)", "IA-2(8)"} <= controls


def test_attack_exposure_counts_each_policy_once(query):
    """Sub-technique link rows must not multiply a policy's appearances."""
    exposure = query.attack_exposure("T1566")
    policy_ids = [row["policy_id"] for row in exposure["all_matches"]]
    assert len(policy_ids) == len(set(policy_ids))
    assert exposure["failing_policies"] == len(exposure["exposed_by"])


def test_concept_search_ignores_stopwords(query):
    """Otherwise an out-of-scope question matches controls on the word 'the'."""
    assert query.controls_for_concept("What is the weather in Accra?")["count"] == 0
    assert query.controls_for_concept("phishing resistant MFA")["count"] > 0


def test_concept_search_survives_hostile_input(query):
    for hostile in ['"; DROP TABLE controls; --', "NEAR(", "*", "() OR 1=1"]:
        assert isinstance(query.controls_for_concept(hostile)["count"], int)


def test_unknown_uuid_does_not_resolve(query):
    assert query.resolve_uuid("deadbeef-0000-4000-8000-000000000000") is None
