"""Deterministic identifiers.

OSCAL requires a UUID on nearly every object. Random UUIDs would make every
recompile produce a different document, which breaks three things at once:
byte-identical reproducibility, citation stability (an answer citing a UUID
would go stale the moment anything recompiled), and diffing between runs.

So every UUID is a UUIDv5 derived from a fixed Fathom namespace and a stable
seed tuple. Same inputs, same UUIDs, forever.
"""
from __future__ import annotations

import uuid

# UUIDv5 of "fathom.oscal" under the standard DNS namespace. Fixed for all time:
# changing it would invalidate every citation Fathom has ever emitted.
FATHOM_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "fathom.oscal")


def fathom_uuid(*parts: str) -> str:
    """Derive a stable UUIDv5 from the given seed parts.

    Parts are joined with a separator that cannot occur in a policy ID or run
    ID, so ("a", "bc") and ("ab", "c") can never collide.
    """
    seed = "\x1f".join(str(p) for p in parts)
    return str(uuid.uuid5(FATHOM_NAMESPACE, seed))


def run_id_for(source_sha256: str) -> str:
    """Derive a run ID from the scan file's content hash.

    Content-addressed on purpose: re-uploading the same scan yields the same run
    ID and therefore the same artifacts, rather than a duplicate run.
    """
    return fathom_uuid("run", source_sha256)
