"""The claim verifier.

This is the component that makes Fathom's answers trustworthy, and it works by
assuming the model is unreliable. It takes the model's finished prose, splits it
into atomic claims, and independently re-checks each one against the query layer
-- the same authoritative source the model was supposed to read from.

Four checks, in order of how often they catch something real:

1. **Citation resolution.** Every UUID in a factual sentence must resolve to a
   real object in this run. Invented or stale UUIDs fail here.
2. **Status consistency.** If a sentence says a policy passes, the cited
   finding's OSCAL status must actually be `satisfied`. This is the check that
   catches a confident "you are fully compliant" over a failing control.
3. **Numeric grounding.** Every number in a factual sentence must appear in the
   tool output the model was given. The model may quote figures; it may not
   derive them.
4. **Uncited factual sentences.** A factual sentence with no citation is
   unsupported by construction.

Failing claims are removed from the answer rather than annotated, because a
struck-through false claim is still a claim the reader's eye absorbs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from fathom.query import QueryLayer

UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
# Sentence split that tolerates "MS.AAD.1.1v1" and "v1.8.0" without breaking on
# their dots. A following "[" is explicitly NOT a sentence start: a trailing
# citation belongs to the sentence it follows, and splitting there would orphan
# the citation and leave the claim itself uncited.
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z\"'])")
_NUMBER_RE = re.compile(r"(?<![\w.])(\d+(?:\.\d+)?)(?![\w.]*[a-zA-Z])")

# Digits that are part of a name, not a quantity. Without masking these, the
# numeric check fires on "NIST 800-53" and "MS.AAD.1.1v1" and rejects perfectly
# true sentences -- a verifier that cries wolf is worse than none, because the
# real rejections stop being believed. Ordered most-specific first.
_IDENTIFIER_PATTERNS = [
    UUID_RE,
    re.compile(r"\bMS\.[A-Z0-9]+\.\d+\.\d+v\d+\b", re.I),      # MS.AAD.1.1v1
    re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),                       # T1110.003
    re.compile(r"\b(?:SP\s*)?800-\d+[a-z]?\b", re.I),             # 800-53
    re.compile(r"\bRev\.?\s*\d+\b", re.I),                       # Rev. 5
    re.compile(r"\b[A-Z]{2}-\d+(?:\(\d+\))?[a-z]?(?![\w-])"),     # AC-2(12), IA-5c
    re.compile(r"\bv?\d+\.\d+\.\d+\b"),                         # v1.8.0, 1.2.3
    re.compile(r"\bOSCAL\s+\d+(?:\.\d+)*\b", re.I),
]


def _mask_identifiers(sentence: str) -> str:
    """Blank out identifier-embedded digits before numeric grounding."""
    masked = sentence
    for pattern in _IDENTIFIER_PATTERNS:
        masked = pattern.sub(" ", masked)
    return masked

# Only unambiguous assertions about a policy's *assessed status* belong here.
# Words like "enabled", "implemented" and "in place" were tried and removed:
# they occur constantly inside quoted requirement text ("Domain impersonation
# protection SHOULD be enabled"), where they describe what the policy demands
# rather than what the tenant does. Including them made the verifier reject
# truthful statements of failure, and a verifier with false positives trains
# people to ignore it.
_SATISFIED_WORDS = {
    "passes", "passing", "passed", "satisfied", "compliant", "conformant", "conforms",
}
_NOT_SATISFIED_WORDS = {
    "fails", "failing", "failed", "not satisfied", "not-satisfied", "non-compliant",
    "noncompliant", "not compliant", "not met", "unmet",
}
_INTERPRETATION_PREFIX = "interpretation:"

# "not compliant", "not fully compliant", "is not currently satisfied", "no
# longer passing" -- up to three words between the negator and the status term.
# Phrasing that explicitly declines to assign a status. This is the *correct*
# way to describe a policy with no automated check, so it must not be read as
# asserting one -- "neither satisfied nor not-satisfied" contains both status
# words and would otherwise be rejected for saying exactly the right thing.
_DECLINES_STATUS = re.compile(
    r"neither\s+satisfied\s+nor\s+not[-\s]?satisfied"
    r"|no\s+automated\s+check"
    r"|not\s+(?:be\s+)?(?:automatically\s+)?verified(?:\s+either\s+way)?"
    r"|cannot\s+be\s+(?:confirmed|verified|determined)"
    r"|could\s+not\s+be\s+(?:confirmed|verified|determined)"
    r"|requires?\s+manual\s+(?:review|verification)"
    r"|unverified",
    re.I,
)

_NEGATED_STATUS = re.compile(
    r"\b(?:not|never|no longer|isn't|is not|aren't|are not|fails to be)\s+"
    r"(?:\w+\s+){0,3}?(?:compliant|satisfied|conformant|passing|passes|met)\b"
)

# Numbers that carry no factual weight and would otherwise create noise.
_TRIVIAL_NUMBERS = {0.0, 1.0, 2.0}


class ClaimVerdict(str, Enum):
    CONFIRMED = "confirmed"
    INTERPRETATION = "interpretation"
    UNCITED = "unsupported-no-citation"
    BAD_UUID = "unsupported-unresolvable-citation"
    STATUS_CONFLICT = "contradicted-by-evidence"
    BAD_NUMBER = "unsupported-number"


@dataclass
class Claim:
    text: str
    citations: list[str] = field(default_factory=list)
    verdict: ClaimVerdict = ClaimVerdict.CONFIRMED
    reason: str | None = None
    resolved: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.verdict in (ClaimVerdict.CONFIRMED, ClaimVerdict.INTERPRETATION)

    def as_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "citations": self.citations,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "resolved": [
                {"uuid": r.get("uuid"), "kind": r.get("kind"), "policy_id": r.get("policy_id")}
                for r in self.resolved
            ],
        }


@dataclass
class VerificationResult:
    claims: list[Claim]
    verified_answer: str
    regenerate: bool = False

    @property
    def confirmed(self) -> int:
        return sum(1 for c in self.claims if c.verdict is ClaimVerdict.CONFIRMED)

    @property
    def factual_total(self) -> int:
        return sum(1 for c in self.claims if c.verdict is not ClaimVerdict.INTERPRETATION)

    @property
    def rejected(self) -> list[Claim]:
        return [c for c in self.claims if not c.ok]

    @property
    def badge(self) -> str:
        return f"{self.confirmed}/{self.factual_total} claims confirmed"

    def as_dict(self) -> dict[str, Any]:
        return {
            "badge": self.badge,
            "confirmed": self.confirmed,
            "factual_total": self.factual_total,
            "rejected_count": len(self.rejected),
            "claims": [c.as_dict() for c in self.claims],
        }


def collect_numbers(value: Any, into: set[float]) -> None:
    """Recursively gather every number the tools actually returned."""
    if isinstance(value, bool):
        return
    if isinstance(value, (int, float)):
        into.add(float(value))
    elif isinstance(value, str):
        for match in _NUMBER_RE.finditer(value):
            into.add(float(match.group(1)))
    elif isinstance(value, dict):
        for item in value.values():
            collect_numbers(item, into)
    elif isinstance(value, list):
        into.add(float(len(value)))
        for item in value:
            collect_numbers(item, into)


_RULE_LINE = re.compile(r"^\s*([-*_])\s*\1\s*\1[\s\-*_]*$")
_LIST_START = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+|#{1,6}\s+)")
_MD_NOISE = re.compile(r"(\*\*|__|[`*_#>]|^\s*[-*+]\s+|^\s*\d+[.)]\s+)")


def segment_claims(answer: str) -> list[tuple[str, int, bool]]:
    """Split an answer into atomic claims, tolerating markdown.

    A chat model asked for a security summary returns headings, horizontal
    rules, bold runs and numbered lists. Splitting that on sentence boundaries
    alone produces one enormous "claim" spanning a whole list, so a single bad
    line condemns a dozen good ones -- and splitting purely on newlines does the
    opposite, orphaning the continuation line that carries the citation.

    So the text is first grouped into chunks: a list item or heading starts a
    new chunk, and its indented continuation lines stay with it. Each chunk is
    then flattened, stripped of markdown, and sentence-split.
    """
    # Each chunk records whether it is a list item. That flag governs citation
    # inheritance later: a bullet is one unit of meaning, a prose paragraph is
    # not.
    chunks: list[tuple[list[str], bool]] = []
    for line in answer.splitlines():
        if not line.strip() or _RULE_LINE.match(line):
            chunks.append(([], False))  # blank line or rule ends the current chunk
            continue
        if _LIST_START.match(line) or not chunks or not chunks[-1][0]:
            chunks.append(([line], bool(_LIST_START.match(line))))
        else:
            chunks[-1][0].append(line)

    claims: list[tuple[str, int, bool]] = []
    index = 0
    for lines, is_item in chunks:
        if not lines:
            continue
        flat = " ".join(part.strip() for part in lines)
        flat = _MD_NOISE.sub("", flat).strip()
        if not flat:
            continue
        for sentence in _SENTENCE_SPLIT.split(flat):
            if sentence.strip():
                claims.append((sentence.strip(), index, is_item))
        index += 1
    return claims


def _is_factual(sentence: str) -> bool:
    """Whether a sentence asserts something about the tenant.

    Questions, suggestions and explicit interpretation are exempt from citation.
    """
    stripped = sentence.strip()
    if not stripped or stripped.endswith("?"):
        return False
    if stripped.lower().startswith(_INTERPRETATION_PREFIX):
        return False
    # A lead-in announcing what follows ("Here are the facts:") asserts nothing
    # about the tenant. Requiring a citation for it produces a rejection that
    # makes the verifier look wrong rather than making the answer safer.
    if stripped.endswith(":") and not UUID_RE.search(stripped):
        return False
    return True


def _status_words(sentence: str) -> tuple[bool, bool]:
    """Detect whether a sentence asserts satisfaction, failure, or neither.

    Negative phrases are matched and consumed first. Every positive term is a
    substring of its own negation -- "not-satisfied" contains "satisfied",
    "non-compliant" contains "compliant" -- so checking positives against the
    raw sentence flags a correct statement of failure as a false claim of
    success. Removing the negative spans first also handles the mixed case
    ("A is not-satisfied but B is satisfied") correctly.
    """
    lowered = sentence.lower()

    # An explicit refusal to assign a status is not a status assertion.
    if _DECLINES_STATUS.search(lowered):
        return False, False

    says_failing = False
    remainder = lowered

    # Negations first, longest phrase first. The regex catches hedged forms a
    # fixed phrase list misses: "not fully compliant" does not contain the
    # substring "not compliant", so without this it reads as a claim of
    # compliance -- precisely backwards.
    for match in reversed(list(_NEGATED_STATUS.finditer(remainder))):
        says_failing = True
        remainder = remainder[: match.start()] + " " + remainder[match.end() :]
    for phrase in sorted(_NOT_SATISFIED_WORDS, key=len, reverse=True):
        if phrase in remainder:
            says_failing = True
            remainder = remainder.replace(phrase, " ")

    says_satisfied = any(w in remainder for w in _SATISFIED_WORDS)
    return says_satisfied, says_failing


def verify_answer(
    answer: str,
    *,
    query: QueryLayer,
    tool_outputs: list[Any],
) -> VerificationResult:
    """Split an answer into claims and verify each against the query layer."""
    allowed_numbers: set[float] = set()
    for output in tool_outputs:
        collect_numbers(output, allowed_numbers)

    segmented = segment_claims(answer)

    # A model routinely writes a bullet as "MS.AAD.7.2v1 is not-satisfied. This
    # exposes T1098 [uuid]." -- one list item, the citation on its second
    # sentence. A bullet is a single unit of meaning, so its sentences inherit
    # the UUIDs cited anywhere within it.
    #
    # Strictly list items only. Allowing inheritance across a prose paragraph
    # would let any uncited sentence borrow its neighbour's citation, which
    # silently disables the uncited-claim check -- the opposite of the point.
    # Verification is not weakened either way: an inherited UUID is still
    # resolved and still status-checked against what it resolves to.
    chunk_citations: dict[int, list[str]] = {}
    for sentence, chunk, is_item in segmented:
        if not is_item:
            continue
        if found := UUID_RE.findall(sentence):
            chunk_citations.setdefault(chunk, []).extend(found)

    claims: list[Claim] = []

    for sentence, chunk, _is_item in segmented:
        own = UUID_RE.findall(sentence)
        citations = own or chunk_citations.get(chunk, [])
        claim = Claim(text=sentence, citations=list(dict.fromkeys(citations)))

        if not _is_factual(sentence):
            claim.verdict = ClaimVerdict.INTERPRETATION
            claims.append(claim)
            continue

        if not citations:
            claim.verdict = ClaimVerdict.UNCITED
            claim.reason = "factual sentence with no OSCAL citation"
            claims.append(claim)
            continue

        # 1. Every cited UUID must resolve inside this run.
        unresolved: list[str] = []
        for uuid in citations:
            resolved = query.resolve_uuid(uuid)
            if resolved is None:
                unresolved.append(uuid)
            else:
                claim.resolved.append(resolved)
        if unresolved:
            claim.verdict = ClaimVerdict.BAD_UUID
            claim.reason = f"citation(s) do not resolve in this run: {', '.join(unresolved)}"
            claims.append(claim)
            continue

        # 2. Asserted status must match the cited evidence.
        says_satisfied, says_failing = _status_words(sentence)
        declines = bool(_DECLINES_STATUS.search(sentence.lower()))
        conflict = None
        for resolved in claim.resolved:
            status = resolved.get("oscal_status")
            if declines and status is not None:
                # Calling a policy unverifiable when ScubaGear did reach a
                # verdict is its own misstatement -- usually one that buries a
                # real failure behind "needs manual review".
                conflict = (
                    f"{resolved.get('policy_id')} was verified and is {status}, but the "
                    f"sentence describes it as unverified"
                )
                continue
            if status is None:
                # Unverified policies are neither; claiming either is a conflict.
                if resolved.get("kind") == "risk" and resolved.get("unverified"):
                    if says_satisfied or says_failing:
                        conflict = (
                            f"{resolved.get('policy_id')} has no automated check and is "
                            f"neither passing nor failing"
                        )
                continue
            if says_satisfied and status == "not-satisfied":
                conflict = (
                    f"{resolved.get('policy_id')} is {status}, but the sentence asserts "
                    f"it is satisfied"
                )
            elif says_failing and status == "satisfied" and not says_satisfied:
                conflict = (
                    f"{resolved.get('policy_id')} is {status}, but the sentence asserts "
                    f"it is failing"
                )
        if conflict:
            claim.verdict = ClaimVerdict.STATUS_CONFLICT
            claim.reason = conflict
            claims.append(claim)
            continue

        # 3. Every number must have come from a tool.
        ungrounded = [
            m.group(1)
            for m in _NUMBER_RE.finditer(_strip_uuids(sentence))
            if float(m.group(1)) not in allowed_numbers
            and float(m.group(1)) not in _TRIVIAL_NUMBERS
        ]
        if ungrounded:
            claim.verdict = ClaimVerdict.BAD_NUMBER
            claim.reason = f"number(s) not present in tool output: {', '.join(ungrounded)}"
            claims.append(claim)
            continue

        claims.append(claim)

    kept = [c.text for c in claims if c.ok]
    verified_answer = " ".join(kept).strip()

    # If nothing survived but the model did say something, the answer is not
    # salvageable by editing -- it needs regenerating once.
    regenerate = bool(segmented) and not kept

    return VerificationResult(
        claims=claims, verified_answer=verified_answer, regenerate=regenerate
    )


def _strip_uuids(sentence: str) -> str:
    """Remove UUIDs and other identifiers before number extraction."""
    return _mask_identifiers(sentence)
