#!/usr/bin/env python3
"""Smoke-check the configured LLM against the demo questions.

Deliberately separate from the test suite: this makes real, billable calls and
its output depends on the model, so it reports rather than asserts. Use it after
changing model, deployment or prompt to see how much of each answer survives
verification.

    .venv/bin/python scripts/check_llm.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from fathom import config  # noqa: E402
from fathom.agent.analyst import Analyst  # noqa: E402
from fathom.query import QueryLayer  # noqa: E402
from fathom.store.db import session  # noqa: E402

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"

QUESTIONS = [
    "Which failing requirements leave us open to phishing, and which 800-53 "
    "controls does that put at risk for our ATO?",
    "Confirm we are fully compliant with MFA requirements.",
    "What are the top three things to fix first, and why?",
    "Which policies could not be automatically verified?",
    "How many SHALL requirements are failing?",
    "What is the weather in Accra?",
]


def main() -> int:
    settings = config.llm_settings()
    print(f"deployment : {settings.deployment}")
    print(f"endpoint   : {settings.endpoint}")
    print(f"configured : {settings.configured}\n")

    with session() as conn:
        row = conn.execute("SELECT id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
        if not row:
            print("No compiled run. Run: .venv/bin/fathom compile --sample", file=sys.stderr)
            return 1
        analyst = Analyst(QueryLayer(conn, row["id"]))

        confirmed = factual = 0
        for question in QUESTIONS:
            result = analyst.answer(question)
            verification = result.verification
            confirmed += verification.confirmed
            factual += verification.factual_total

            colour = GREEN if not verification.rejected else YELLOW
            print(f"{DIM}{'─' * 76}{RESET}")
            print(f"Q: {question}")
            print(
                f"   {colour}{verification.badge}{RESET}  {DIM}{result.mode} · "
                f"{result.latency_ms} ms · "
                f"{', '.join(t.name for t in result.tool_calls) or 'no tools'}{RESET}"
            )
            for claim in verification.rejected:
                print(f"   {RED}stripped{RESET} [{claim.verdict.value}] {claim.reason}")
                print(f"            {DIM}{claim.text[:96]}{RESET}")
            print(f"   {result.answer[:400] or '(nothing survived)'}")

        rate = (confirmed / factual * 100) if factual else 0.0
        colour = GREEN if rate >= 80 else YELLOW if rate >= 50 else RED
        print(f"\n{colour}Overall: {confirmed}/{factual} factual claims confirmed "
              f"({rate:.0f}%){RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
