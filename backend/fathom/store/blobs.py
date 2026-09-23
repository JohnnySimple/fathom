"""Content-addressed blob storage.

Artifacts and evidence are stored under their own SHA-256. Two consequences
matter: re-compiling identical input writes nothing new, and any stored bytes
can be proven unmodified by rehashing them. Auditability comes for free.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from fathom import config


def put(payload: bytes) -> str:
    """Store bytes and return their SHA-256."""
    digest = hashlib.sha256(payload).hexdigest()
    path = _path(digest)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        # Write-then-rename so a crash can never leave a truncated blob at a
        # name that claims to be its hash.
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(payload)
        tmp.rename(path)
    return digest


def get(digest: str) -> bytes | None:
    path = _path(digest)
    return path.read_bytes() if path.exists() else None


def verify(digest: str) -> bool:
    """Confirm stored bytes still hash to their name."""
    payload = get(digest)
    return payload is not None and hashlib.sha256(payload).hexdigest() == digest


def _path(digest: str) -> Path:
    if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
        raise ValueError(f"not a SHA-256 hex digest: {digest!r}")
    # Two-level fan-out keeps directory listings sane.
    return config.BLOB_DIR / digest[:2] / digest[2:4] / f"{digest}.json"
