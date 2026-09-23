"""Translate CISA's 800-53 control notation into OSCAL catalog IDs.

CISA writes control references the way SP 800-53 prints them; NIST's OSCAL
catalog uses lowercase dotted tokens. The two never coincide for enhancements,
so a naive lookup silently finds nothing:

    CISA        OSCAL      meaning
    CM-7        cm-7       base control
    AC-2(12)    ac-2.12    control enhancement
    IA-5c       ia-5       statement part c of IA-5 -- not a separate control

The statement-part case matters: `IA-5c` is a *part* of IA-5, and OSCAL has no
control with that ID. Resolving it to `ia-5` links to the real control and keeps
the original notation for display, rather than dropping the mapping.
"""
from __future__ import annotations

import re

_ENHANCEMENT = re.compile(r"^(?P<base>[A-Z]{2})-(?P<num>\d+)\((?P<enh>\d+)\)$")
_STATEMENT_PART = re.compile(r"^(?P<base>[A-Z]{2})-(?P<num>\d+)(?P<part>[a-z]+)$")
_BASE = re.compile(r"^(?P<base>[A-Z]{2})-(?P<num>\d+)$")


def to_oscal_id(cisa_id: str) -> str | None:
    """Return the OSCAL catalog control ID, or None if unparseable."""
    text = cisa_id.strip().upper()
    if m := _ENHANCEMENT.match(text):
        return f"{m.group('base').lower()}-{m.group('num')}.{m.group('enh')}"
    if m := _BASE.match(text):
        return f"{m.group('base').lower()}-{m.group('num')}"
    if m := _STATEMENT_PART.match(cisa_id.strip()):
        # Lowercase suffix only -- "IA-5c" is a part, "IA-5C" is not valid.
        return f"{m.group('base').lower()}-{m.group('num')}"
    return None


def family(cisa_id: str) -> str | None:
    """Return the control family prefix, e.g. 'AC' for AC-2(12)."""
    text = cisa_id.strip().upper()
    return text[:2] if len(text) >= 2 and text[:2].isalpha() else None
