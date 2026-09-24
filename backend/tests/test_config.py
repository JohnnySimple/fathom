"""Configuration loading.

Both behaviours here were real bugs: the .env file was never read, and the
endpoint form the Azure portal hands you produced a 404 indistinguishable from
a bad API key.
"""
from __future__ import annotations

import subprocess
import sys

from fathom import config
from fathom.config import _normalize_azure_endpoint


def test_env_file_is_loaded_into_the_process(tmp_path):
    """A .env is inert unless something parses it; config.py must do that.

    Run in a subprocess with a clean environment so the assertion is about the
    file being read, not about a variable the test runner happened to inherit.
    """
    env_file = config.ROOT / ".env"
    if not env_file.exists():
        import pytest

        pytest.skip("no .env in this checkout")

    script = (
        "import os; from fathom import config; "
        "print(bool(os.getenv('AZURE_OPENAI_ENDPOINT')))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
        cwd=tmp_path,  # also proves the lookup is not relative to the CWD
    )
    assert result.stdout.strip() == "True", result.stderr


def test_exported_variables_win_over_the_env_file(monkeypatch):
    """CI and containers set real variables; the file must not clobber them."""
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "from-the-environment")
    assert config.llm_settings().deployment == "from-the-environment"


def test_portal_endpoint_form_is_normalized():
    bare = "https://r.openai.azure.com"
    for given in (f"{bare}/openai/v1", f"{bare}/openai/v1/", f"{bare}/", bare):
        assert _normalize_azure_endpoint(given) == bare


def test_blank_endpoint_is_none():
    assert _normalize_azure_endpoint("") is None
    assert _normalize_azure_endpoint(None) is None


def test_unconfigured_llm_reports_not_configured(monkeypatch):
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "")
    assert config.llm_settings().configured is False
