"""Shared fixtures.

The compile is expensive (it parses 126 policies and emits ~900 KB of OSCAL) and
completely deterministic, so it runs once per session and is reused.
"""
from __future__ import annotations

import pytest

from fathom import config
from fathom.compiler.pipeline import compile_scan
from fathom.ingest.sources import load_sources
from fathom.store.db import init_db, persist_compile

pytestmark = pytest.mark.skipif(
    not config.SAMPLE_SCAN.exists(), reason="pinned sources not fetched"
)


@pytest.fixture(autouse=True)
def _offline_llm(monkeypatch):
    """Force grounded mode for the whole suite.

    Once a developer has a working .env, config picks it up and every test that
    touches the analyst starts calling Azure -- turning a deterministic suite
    into a slow, billable one whose results depend on what the model felt like
    saying. Fathom's own logic is what these tests are for; live-model
    behaviour is checked separately by `scripts/check_llm.py`.
    """
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)


@pytest.fixture(scope="session")
def bundle():
    return load_sources()


@pytest.fixture(scope="session")
def payload() -> bytes:
    if not config.SAMPLE_SCAN.exists():
        pytest.skip("run scripts/fetch_sources.py first")
    return config.SAMPLE_SCAN.read_bytes()


@pytest.fixture(scope="session")
def result(payload, bundle):
    return compile_scan(payload, bundle=bundle)


@pytest.fixture
def conn(result, bundle, tmp_path, monkeypatch):
    """A populated database in a temp directory, isolated per test."""
    import sqlite3

    monkeypatch.setattr(config, "BLOB_DIR", tmp_path / "blobs")
    connection = sqlite3.connect(tmp_path / "test.db")
    connection.row_factory = sqlite3.Row
    init_db(connection)
    persist_compile(connection, result, bundle)
    connection.commit()
    yield connection
    connection.close()


@pytest.fixture
def query(conn, result):
    from fathom.query import QueryLayer

    return QueryLayer(conn, result.run_id)
