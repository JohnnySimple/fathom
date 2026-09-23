"""Shared deterministic text normalization.

ScubaGear embeds presentation HTML inside data fields (the `Requirement` field
carries a `<div class='policy-indicators'>` block of badge links). That markup
must be stripped before the text becomes an OSCAL control title, and it must be
stripped the same way every time or the output stops being byte-identical.
"""
from __future__ import annotations

import html
import re

_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def strip_html(value: str | None) -> str:
    """Remove HTML tags and collapse whitespace, deterministically."""
    if not value:
        return ""
    text = _TAG.sub(" ", value)
    text = html.unescape(text)
    return _WS.sub(" ", text).strip()


_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_MD_EMPHASIS = re.compile(r"[*_`]{1,3}")
# Sentence end, but not inside a policy ID ("MS.AAD.1.1v1") or a version.
_SENTENCE_END = re.compile(r"(?<=[a-z0-9)\"'])\.(?=\s+[A-Z(])")


def markdown_to_text(value: str) -> str:
    """Flatten markdown emphasis and links to their visible text."""
    return _WS.sub(" ", _MD_EMPHASIS.sub("", _MD_LINK.sub(r"\1", value or ""))).strip()


def requirement_sentence(statement: str) -> str:
    """Return the normative first sentence of a policy statement.

    SCuBA statements often open with the requirement and then continue for a
    paragraph of implementation detail and markdown links. The first sentence is
    the requirement; the remainder is guidance. Answers quote this so each claim
    stays a single, citable sentence, and OSCAL control titles use it so a title
    is a title rather than a page of prose. The full text is never discarded --
    it remains the control's statement part.
    """
    text = markdown_to_text(statement)
    if not text:
        return ""
    parts = _SENTENCE_END.split(text, maxsplit=1)
    first = parts[0].strip()
    if not first.endswith((".", "!", "?")):
        first += "."
    return first
