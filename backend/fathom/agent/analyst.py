"""The analyst: a single tool-calling agent over the typed query layer.

One agent, one loop, no framework. The specification calls for tool calling over
a fixed set of typed functions and explicitly rules out a multi-agent setup, and
nothing here needs more than the provider's native tool-calling API.

Two execution modes, both of which go through the verifier:

  - **live**: Azure OpenAI drives the tool loop and writes the prose.
  - **grounded**: no LLM is configured or reachable. Fathom routes the question
    to tools by keyword and renders the results through fixed templates.

Grounded mode is not a stub. The specification requires the demo to survive an
LLM outage, and because every factual sentence Fathom emits is verified against
the query layer anyway, a templated answer is exactly as trustworthy as a
generated one -- it is simply less fluent. The mode is always reported to the
caller so nobody mistakes one for the other.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from fathom import config
from fathom.agent.prompts import REFUSAL_SUGGESTIONS, SYSTEM_PROMPT
from fathom.agent.verifier import VerificationResult, verify_answer
from fathom.ingest.text import requirement_sentence
from fathom.query import TOOL_SPECS, QueryLayer

MAX_TOOL_ROUNDS = 5


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]
    result: Any

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "arguments": self.arguments}


@dataclass
class AnswerResult:
    question: str
    answer: str
    raw_answer: str
    mode: str
    verification: VerificationResult
    tool_calls: list[ToolCall] = field(default_factory=list)
    regenerated: bool = False
    latency_ms: int = 0
    refused: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "question": self.question,
            "answer": self.answer,
            "raw_answer": self.raw_answer,
            "mode": self.mode,
            "refused": self.refused,
            "regenerated": self.regenerated,
            "latency_ms": self.latency_ms,
            "verification": self.verification.as_dict(),
            "tool_calls": [t.as_dict() for t in self.tool_calls],
        }


class Analyst:
    def __init__(self, query: QueryLayer, settings=None) -> None:
        self.query = query
        self.settings = settings or config.llm_settings()
        self._dispatch: dict[str, Callable[..., Any]] = {
            "posture_summary": lambda **kw: query.posture_summary(),
            "list_findings": query.list_findings,
            "get_control": query.get_control,
            "controls_for_concept": query.controls_for_concept,
            "nist_impact": query.nist_impact,
            "attack_exposure": query.attack_exposure,
            "list_unverified": lambda **kw: query.list_unverified(),
            "draft_poam": query.draft_poam,
            "diff_runs": query.diff_runs,
        }

    # ------------------------------------------------------------------ entry
    def answer(self, question: str) -> AnswerResult:
        started = time.monotonic()
        if self.settings.configured:
            try:
                result = self._answer_live(question)
            except Exception as exc:  # noqa: BLE001 - the demo must not die on this
                result = self._answer_grounded(question)
                result.mode = f"grounded ({_diagnose(exc)})"
        else:
            result = self._answer_grounded(question)
        result.latency_ms = int((time.monotonic() - started) * 1000)
        return result

    def _run_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        func = self._dispatch.get(name)
        if not func:
            return {"error": f"unknown tool {name}"}
        try:
            return func(**arguments)
        except TypeError as exc:
            return {"error": f"bad arguments for {name}: {exc}"}

    # ------------------------------------------------------------------- live
    def _answer_live(self, question: str) -> AnswerResult:
        from openai import AzureOpenAI

        client = AzureOpenAI(
            azure_endpoint=self.settings.endpoint,
            api_key=self.settings.api_key,
            api_version=self.settings.api_version,
        )
        tools = [
            {
                "type": "function",
                "function": {
                    "name": spec["name"],
                    "description": spec["description"],
                    "parameters": spec["parameters"],
                },
            }
            for spec in TOOL_SPECS
        ]
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": question},
        ]
        calls: list[ToolCall] = []

        for _ in range(MAX_TOOL_ROUNDS):
            response = client.chat.completions.create(
                model=self.settings.deployment,
                messages=messages,
                tools=tools,
                temperature=0,  # determinism matters more than variety here
            )
            message = response.choices[0].message
            if not message.tool_calls:
                raw = message.content or ""
                # Keep the assistant's reply in the transcript. Without it the
                # history ends on a `tool` message, and the regeneration nudge
                # below then puts `user` straight after `tool`. OpenAI tolerates
                # that; Mistral rejects it outright with
                # invalid_request_message_order.
                messages.append({"role": "assistant", "content": raw})
                break
            messages.append(message.model_dump(exclude_none=True))
            for call in message.tool_calls:
                try:
                    arguments = json.loads(call.function.arguments or "{}")
                except json.JSONDecodeError:
                    arguments = {}
                output = self._run_tool(call.function.name, arguments)
                calls.append(ToolCall(call.function.name, arguments, output))
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": json.dumps(output, default=str),
                    }
                )
        else:
            raw = "I could not complete this question within the tool-call budget."

        if not calls:
            # The model answered without consulting a single tool, so nothing it
            # said can be grounded. That is an out-of-scope question, and a
            # scoped refusal is a better answer than a stripped-empty one.
            return self._refuse(question)

        result = self._finalize(question, raw, calls, mode="live")

        # The specification allows exactly one regeneration before falling back
        # to structured results without narrative.
        if result.verification.regenerate:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Every claim in that answer failed verification. Rewrite it using "
                        "only facts from the tool results above, citing the exact UUIDs "
                        "they returned."
                    ),
                }
            )
            retry = client.chat.completions.create(
                model=self.settings.deployment, messages=messages, temperature=0
            )
            raw2 = retry.choices[0].message.content or ""
            result = self._finalize(question, raw2, calls, mode="live")
            result.regenerated = True
            if not result.verification.verified_answer:
                result = self._structured_fallback(question, calls)
        return result

    # --------------------------------------------------------------- grounded
    def _answer_grounded(self, question: str) -> AnswerResult:
        """Answer without an LLM by routing to tools and templating the result."""
        calls = self._route(question)
        if not calls:
            return self._refuse(question)
        sentences = [s for call in calls for s in _render(call)]
        if not sentences:
            return self._refuse(question)
        return self._finalize(question, " ".join(sentences), calls, mode="grounded")

    def _route(self, question: str) -> list[ToolCall]:
        """Keyword routing. Crude on purpose: it is a fallback, not the product."""
        # Normalize punctuation before matching: "POA&M" does not contain the
        # substring "poam", so raw matching silently misroutes the single most
        # likely question an ISSO will ask.
        lowered = question.lower()
        squashed = "".join(c if c.isalnum() or c.isspace() else "" for c in lowered)
        haystack = f"{lowered} {squashed}"
        calls: list[ToolCall] = []
        seen: set[tuple] = set()

        def call(name: str, **kwargs: Any) -> None:
            # Several keyword groups can select the same tool ("compliant" and
            # "fully" both want posture_summary); calling it twice would repeat
            # the whole answer back to the user.
            signature = (name, json.dumps(kwargs, sort_keys=True, default=str))
            if signature in seen:
                return
            seen.add(signature)
            calls.append(ToolCall(name, kwargs, self._run_tool(name, kwargs)))

        if any(w in haystack for w in ("poam", "plan of action", "remediat", "fix first")):
            call("draft_poam")
        if any(w in haystack for w in ("800-53", "80053", "nist", "ato", "auditor")):
            failing = self.query.list_findings(state="fail", limit=10)["findings"]
            call("nist_impact", policy_ids=[f["policy_id"] for f in failing])
        for technique, words in _CONCEPTS.items():
            if any(w in haystack for w in words):
                call("attack_exposure", technique=technique)
                break
        if any(w in haystack for w in ("summary", "posture", "overall", "how many", "compliant", "status")):
            call("posture_summary")
        if any(w in haystack for w in ("manual", "unverified", "not checked", "fully")):
            call("list_unverified")
            call("posture_summary")
        if any(w in haystack for w in ("fail", "failing", "worst", "top", "risk")):
            call("list_findings", state="fail", criticality="SHALL", limit=5)

        if not calls:
            found = self.query.controls_for_concept(question)
            if found["count"]:
                calls.append(ToolCall("controls_for_concept", {"text": question}, found))
        return calls

    @staticmethod
    def _cite(text: str, uuid: str) -> str:
        """Attach a citation inside the sentence it supports.

        Policy statements already end in a period, so naively appending
        " [uuid]." produces two sentences and strands the citation in the
        second, leaving the actual claim uncited.
        """
        return f"{text.rstrip().rstrip('.')} [{uuid}]."

    def _refuse(self, question: str) -> AnswerResult:
        # One sentence, so the whole refusal is labelled interpretation and none
        # of it is stripped for lacking a citation it could never have.
        text = (
            "Interpretation: I cannot answer that from this scan -- Fathom covers only the "
            "SCuBA policy results, NIST 800-53 mappings, ATT&CK exposure and POA&M for the "
            "compiled run, so you could instead ask: "
            + "; ".join(REFUSAL_SUGGESTIONS[:3])
        )
        verification = verify_answer(text, query=self.query, tool_outputs=[])
        return AnswerResult(
            question=question,
            answer=text,
            raw_answer=text,
            mode="grounded",
            verification=verification,
            refused=True,
        )

    def _structured_fallback(self, question: str, calls: list[ToolCall]) -> AnswerResult:
        text = (
            "Interpretation: the generated answer could not be verified against the "
            "artifacts, so it was withheld. The underlying tool results are shown instead."
        )
        verification = verify_answer(text, query=self.query, tool_outputs=[c.result for c in calls])
        return AnswerResult(
            question=question,
            answer=text,
            raw_answer=text,
            mode="structured-fallback",
            verification=verification,
            tool_calls=calls,
            regenerated=True,
        )

    # ----------------------------------------------------------------- shared
    def _finalize(
        self, question: str, raw: str, calls: list[ToolCall], *, mode: str
    ) -> AnswerResult:
        verification = verify_answer(
            raw, query=self.query, tool_outputs=[c.result for c in calls]
        )
        return AnswerResult(
            question=question,
            answer=verification.verified_answer or raw,
            raw_answer=raw,
            mode=mode,
            verification=verification,
            tool_calls=calls,
        )


def _diagnose(exc: Exception) -> str:
    """Turn a failed LLM call into something the reader can act on.

    Every failure used to read "LLM unavailable", which made a missing package,
    a rejected key and a genuine outage indistinguishable -- so the one that was
    a five-second fix looked like an Azure problem.
    """
    if isinstance(exc, ModuleNotFoundError):
        return (
            f"{exc.name} is not installed in this environment -- "
            f"run: pip install -e backend"
        )
    name = type(exc).__name__
    status = getattr(exc, "status_code", None)
    if name == "AuthenticationError" or status == 401:
        return "Azure rejected AZURE_OPENAI_API_KEY"
    if name == "PermissionDeniedError" or status == 403:
        return "Azure denied access to this deployment"
    if name == "NotFoundError" or status == 404:
        return (
            "deployment not found -- check AZURE_OPENAI_DEPLOYMENT names a real "
            "deployment, not just a model in the catalogue"
        )
    if name == "RateLimitError" or status == 429:
        return "Azure rate limit or quota exhausted"
    if name == "BadRequestError" or status == 400:
        return f"request rejected by the model: {str(exc)[:120]}"
    return f"LLM unavailable: {name}"


# Concept keywords -> ATT&CK technique, for grounded routing only. The live
# analyst uses `controls_for_concept` and the model's own judgement instead.
_CONCEPTS = {
    "T1566": ("phishing", "phish", "spear"),
    "T1110": ("password spray", "spraying", "brute force", "credential stuffing"),
    "T1078": ("valid account", "stolen credential", "account takeover"),
    "T1098": ("account manipulation", "persistence"),
    "T1528": ("token theft", "access token", "consent"),
    "T1562": ("impair defense", "disable logging", "audit"),
}


def _render(call: ToolCall) -> list[str]:
    """Template one tool result into cited sentences.

    Every sentence produced here carries a real UUID, so grounded answers face
    exactly the same verification as generated ones.
    """
    data = call.result
    if not isinstance(data, dict) or "error" in data:
        return []
    out: list[str] = []

    if call.name == "posture_summary":
        run_uuid = data["run_id"]
        out.append(
            Analyst._cite(
                f"This scan of {data['tenant_alias']} evaluated {data['findings_total']} "
                f"policies: {data['passed']} satisfied, {data['failed_shall']} failing SHALL "
                f"requirements and {data['failed_should']} failing SHOULD requirements",
                run_uuid,
            )
        )
        if data.get("unverified_manual"):
            out.append(
                Analyst._cite(
                    f"A further {data['unverified_manual']} policies have no automated check "
                    f"and were not verified either way",
                    run_uuid,
                )
            )
        out.append(
            "Interpretation: SHALL failures are binding requirements and should be triaged first."
        )

    elif call.name == "list_findings":
        for row in data.get("findings", [])[:5]:
            out.append(
                Analyst._cite(
                    f"{row['policy_id']} ({row['product']}) is {row['oscal_status']}: "
                    f"{requirement_sentence(row['statement'])}",
                    row["finding_uuid"],
                )
            )

    elif call.name == "attack_exposure":
        exposed = data.get("exposed_by", [])
        if not exposed:
            out.append(
                f"Interpretation: no failing policy in this run maps to "
                f"{data['technique_query']}."
            )
        for row in exposed[:5]:
            out.append(
                Analyst._cite(
                    f"{row['policy_id']} is not-satisfied and mitigates "
                    f"{row['technique_ids']}: {requirement_sentence(row['statement'])}",
                    row["finding_uuid"],
                )
            )

    elif call.name == "nist_impact":
        for row in data.get("nist_controls", [])[:6]:
            impacted = [i for i in row["impacted_by"] if i["status"] == "not-satisfied"]
            if not impacted:
                continue
            uuids = " ".join(f"[{i['finding_uuid']}]" for i in impacted if i["finding_uuid"])
            policies = ", ".join(i["policy_id"] for i in impacted)
            out.append(
                f"NIST 800-53 control {row['nist_control']} ({row['title']}) is affected by "
                f"failing policy {policies} {uuids}".rstrip() + "."
            )

    elif call.name == "list_unverified":
        for row in data.get("unverified", [])[:8]:
            out.append(
                Analyst._cite(
                    f"{row['policy_id']} ({row['product']}) has no automated check and was "
                    f"not verified either way: {requirement_sentence(row['statement'])}",
                    row["risk_uuid"],
                )
            )

    elif call.name == "draft_poam":
        for row in data.get("poam_items", [])[:5]:
            out.append(
                Analyst._cite(
                    f"POA&M item for {row['policy_id']} has risk score {row['risk_score']}",
                    row["poam_uuid"],
                )
            )

    elif call.name == "controls_for_concept":
        for row in data.get("controls", [])[:5]:
            result = row.get("result") or {}
            if uuid := result.get("finding_uuid"):
                out.append(
                    Analyst._cite(
                        f"{row['scuba_id']} is {result['oscal_status']}: "
                        f"{requirement_sentence(row['statement'])}",
                        uuid,
                    )
                )
    return out
