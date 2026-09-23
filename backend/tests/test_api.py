"""End-to-end API tests: the documented demo workflow, exercised over HTTP."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from fathom import config


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "api.db")
    monkeypatch.setattr(config, "BLOB_DIR", tmp_path / "blobs")
    from fathom.api.main import app

    return TestClient(app)


@pytest.fixture
def run_id(client):
    return client.post("/api/runs/compile-sample").json()["run_id"]


def test_health_reports_pinned_sources(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["oscal_version"] == config.OSCAL_VERSION
    assert body["pinned_source_problems"] == []


def test_full_demo_workflow(client, run_id):
    """Upload -> validated OSCAL -> posture -> ask -> cited answer -> exact JSON node."""
    validation = client.get(f"/api/runs/{run_id}/validation").json()
    assert validation["all_valid"] is True
    assert len(validation["artifacts"]) == 5

    posture = client.get(f"/api/runs/{run_id}/posture").json()
    assert posture["failed_shall"] == 14
    assert posture["unverified_manual"] == 9

    answer = client.post(
        "/api/ask", json={"run_id": run_id, "question": "What is on the POA&M?"}
    ).json()
    assert answer["verification"]["rejected_count"] == 0
    citation = answer["verification"]["claims"][0]["citations"][0]

    resolved = client.get(f"/api/resolve/{citation}", params={"run_id": run_id}).json()
    artifact = client.get(f"/api/runs/{run_id}/artifacts/{resolved['artifact']}").json()

    node = artifact
    for segment in resolved["json_pointer"].strip("/").split("/"):
        node = node[int(segment)] if segment.isdigit() else node[segment]
    assert node["uuid"] == citation


def test_uploading_the_same_scan_is_idempotent(client, run_id):
    """The run ID is content-addressed, so re-uploading must not duplicate."""
    payload = config.SAMPLE_SCAN.read_bytes()
    again = client.post("/api/runs", files={"file": ("s.json", payload, "application/json")})
    assert again.json()["run_id"] == run_id
    assert client.get("/api/runs").json()["count"] == 1


def test_malformed_upload_is_rejected_with_a_reason(client):
    response = client.post(
        "/api/runs", files={"file": ("x.json", b"{not json", "application/json")}
    )
    assert response.status_code == 422
    assert "could not parse" in response.json()["detail"]


def test_non_scuba_json_is_rejected(client):
    response = client.post(
        "/api/runs", files={"file": ("x.json", b'{"hello":"world"}', "application/json")}
    )
    assert response.status_code == 422


def test_empty_upload_is_rejected(client):
    assert client.post("/api/runs", files={"file": ("x.json", b"", "text/plain")}).status_code == 400


def test_unknown_run_is_404(client):
    assert client.get("/api/runs/nope/posture").status_code == 404


def test_unresolvable_citation_is_404(client, run_id):
    response = client.get(
        "/api/resolve/deadbeef-0000-4000-8000-000000000000", params={"run_id": run_id}
    )
    assert response.status_code == 404


def test_graph_focus_returns_the_blast_radius(client, run_id):
    body = client.get(f"/api/runs/{run_id}/graph", params={"focus": "MS.AAD.3.1v1"}).json()
    kinds = {n["kind"] for n in body["nodes"]}
    assert {"nist", "attack"} <= kinds


def test_out_of_scope_question_is_refused(client, run_id):
    body = client.post(
        "/api/ask", json={"run_id": run_id, "question": "What is the weather in Accra?"}
    ).json()
    assert body["refused"] is True
