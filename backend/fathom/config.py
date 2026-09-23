"""Filesystem layout and runtime settings.

Everything is path-based and local. There is no cloud dependency in the
deterministic pipeline -- only the optional LLM call reaches the network.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# backend/fathom/config.py -> repo root
ROOT = Path(__file__).resolve().parent.parent.parent

PINNED = ROOT / "data" / "pinned"
FIXTURES = ROOT / "data" / "fixtures"
ARTIFACTS = ROOT / "artifacts"

BASELINE_DIR = PINNED / "scubagear" / "baselines"
REGO_DIR = PINNED / "scubagear" / "rego"
SAMPLE_DIR = PINNED / "scubagear" / "samples"
NIST_MAPPING_CSV = (
    PINNED / "scubagear" / "mappings" / "scuba-to-nist-800-53-r5-fedramp-high.csv"
)
NIST_CATALOG = (
    PINNED / "nist" / "NIST_SP-800-53_rev5_HIGH-baseline-resolved-profile_catalog-min.json"
)
OSCAL_SCHEMA_DIR = PINNED / "oscal" / "schemas"
SOURCES_LOCK = PINNED / "SOURCES.lock.json"

DB_PATH = ARTIFACTS / "fathom.db"
BLOB_DIR = ARTIFACTS / "blobs"

# Pinned versions, mirrored from scripts/fetch_sources.py and recorded in every
# artifact's metadata so any output can be traced to its exact inputs.
OSCAL_VERSION = "1.2.3"
SCUBAGEAR_TAG = "v1.8.0"

# Documented MVP scope: Entra ID and Exchange Online first.
MVP_PRODUCTS = ["AAD", "EXO"]
ALL_PRODUCTS = ["AAD", "DEFENDER", "EXO", "POWERPLATFORM", "SHAREPOINT", "TEAMS"]

SAMPLE_SCAN = SAMPLE_DIR / "ScubaResults_fa5589b7-d528-4f80.json"


@dataclass(frozen=True)
class LLMSettings:
    """Azure OpenAI configuration, per the project specification.

    When unset, the analyst runs in grounded-offline mode: it still answers via
    the typed query layer and the verifier still runs, but narration is
    templated rather than generated. The specification requires the demo to
    survive an LLM outage, so this is a supported mode, not a stub.
    """

    endpoint: str | None = None
    api_key: str | None = None
    deployment: str = "gpt-4o"
    api_version: str = "2024-10-21"

    @property
    def configured(self) -> bool:
        return bool(self.endpoint and self.api_key)


def llm_settings() -> LLMSettings:
    return LLMSettings(
        endpoint=os.getenv("AZURE_OPENAI_ENDPOINT") or None,
        api_key=os.getenv("AZURE_OPENAI_API_KEY") or None,
        deployment=os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),
        api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-10-21"),
    )


def opa_binary() -> str:
    return os.getenv("FATHOM_OPA_BIN", "opa")


def ensure_dirs() -> None:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    BLOB_DIR.mkdir(parents=True, exist_ok=True)
    FIXTURES.mkdir(parents=True, exist_ok=True)
