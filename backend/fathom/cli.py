"""Fathom command line.

The whole pipeline is reachable without the web UI, which matters for two
reasons: the demo needs a fallback that cannot break, and a compiler you can run
in CI is a compiler you can trust.

    fathom sources --verify        check pinned inputs against the lockfile
    fathom compile --sample        compile CISA's published sample scan
    fathom compile scan.json       compile a real ScubaResults file
    fathom posture                 show the compiled posture
    fathom ask "..."               ask a verified question
    fathom export --out ./out      write the OSCAL artifacts to disk
    fathom serve                   run the API
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fathom import config
from fathom.agent.analyst import Analyst
from fathom.compiler.pipeline import compile_scan
from fathom.ingest.sources import load_sources, verify_pinned_sources
from fathom.query import QueryLayer
from fathom.store import blobs
from fathom.store.db import persist_compile, session

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def _tick(ok: bool) -> str:
    return f"{GREEN}OK{RESET}" if ok else f"{RED}FAIL{RESET}"


def _latest_run(conn) -> str | None:
    row = conn.execute("SELECT id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
    return row["id"] if row else None


def cmd_sources(args: argparse.Namespace) -> int:
    problems = verify_pinned_sources()
    if problems:
        for problem in problems:
            print(f"  {RED}{problem}{RESET}")
        print("\nRun: python scripts/fetch_sources.py")
        return 1
    bundle = load_sources()
    print(f"  {_tick(True)} pinned sources verified against SOURCES.lock.json")
    print(f"  {_tick(True)} {len(bundle.policies)} SCuBA policies parsed")
    print(
        f"  {_tick(not bundle.warnings)} NIST mapping cross-check "
        f"({len(bundle.warnings)} disagreement(s) between CISA's CSV and baseline text)"
    )
    return 0


def cmd_compile(args: argparse.Namespace) -> int:
    if args.sample:
        path = config.SAMPLE_SCAN
        print(f"{DIM}Compiling CISA's published sample scan{RESET}")
    else:
        path = Path(args.scan)
    if not path.exists():
        print(f"{RED}no such file: {path}{RESET}", file=sys.stderr)
        return 1

    bundle = load_sources()
    result = compile_scan(
        path.read_bytes(),
        bundle=bundle,
        progress=lambda stage, message: print(f"  {DIM}[{stage}]{RESET} {message}"),
    )

    print(f"\nRun {result.run_id}  tenant {result.run.metadata.tenant_alias}")
    for model, artifact in result.artifacts.items():
        print(
            f"  {_tick(artifact.valid)}  {model:20} {len(artifact.raw):>9,} B  "
            f"sha256 {artifact.sha256[:16]}"
        )
        for issue in artifact.validation.issues[:5]:
            print(f"        {RED}{issue}{RESET}")

    for warning in result.warnings:
        print(f"  {YELLOW}warning:{RESET} {warning}")

    with session() as conn:
        persist_compile(conn, result, bundle)
    print(f"\n{_tick(result.all_valid)}  all artifacts valid against NIST OSCAL "
          f"{config.OSCAL_VERSION} schemas")
    return 0 if result.all_valid else 2


def cmd_posture(args: argparse.Namespace) -> int:
    with session() as conn:
        run_id = args.run or _latest_run(conn)
        if not run_id:
            print("no compiled runs; try: fathom compile --sample", file=sys.stderr)
            return 1
        summary = QueryLayer(conn, run_id).posture_summary()
        print(f"Run {run_id}  tenant {summary['tenant_alias']}  "
              f"ScubaGear {summary['scubagear_version']}")
        print(f"  {summary['passed']} satisfied   "
              f"{RED}{summary['failed_shall']} SHALL failing{RESET}   "
              f"{YELLOW}{summary['failed_should']} SHOULD failing{RESET}   "
              f"{summary['unverified_manual']} unverified")
        print(f"\n  {'product':16}{'total':>7}{'pass':>7}{'fail':>7}{'SHALL fail':>12}")
        for row in summary["by_product"]:
            print(f"  {row['product']:16}{row['total']:>7}{row['passed']:>7}"
                  f"{row['failed']:>7}{row['shall_failed']:>12}")
        return 0


def cmd_ask(args: argparse.Namespace) -> int:
    with session() as conn:
        run_id = args.run or _latest_run(conn)
        if not run_id:
            print("no compiled runs; try: fathom compile --sample", file=sys.stderr)
            return 1
        result = Analyst(QueryLayer(conn, run_id)).answer(args.question)

        print(f"{DIM}mode: {result.mode}   tools: "
              f"{', '.join(t.name for t in result.tool_calls) or 'none'}{RESET}\n")
        print(result.answer or f"{YELLOW}(no claim survived verification){RESET}")

        verification = result.verification
        colour = GREEN if not verification.rejected else YELLOW
        print(f"\n{colour}Verifier: {verification.badge}{RESET}")
        for claim in verification.rejected:
            print(f"  {RED}stripped{RESET} [{claim.verdict.value}] {claim.reason}")
            print(f"           {DIM}{claim.text[:100]}{RESET}")
        return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Put a claim through the verifier and show the verdict.

    The analyst is only one source of claims. Being able to hand the verifier an
    arbitrary sentence makes it demonstrable on demand instead of only when a
    model happens to get something wrong -- which, encouragingly, is rare.
    """
    from fathom.agent.verifier import ClaimVerdict, verify_answer

    with session() as conn:
        run_id = args.run or _latest_run(conn)
        if not run_id:
            print("no compiled runs; try: fathom compile --sample", file=sys.stderr)
            return 1
        query = QueryLayer(conn, run_id)
        tools = [query.posture_summary(), query.list_findings(limit=50)]

        claims = [args.claim] if args.claim else _adversarial_suite(conn, run_id)

        for claim_text in claims:
            result = verify_answer(claim_text, query=query, tool_outputs=tools)
            for claim in result.claims:
                ok = claim.verdict in (ClaimVerdict.CONFIRMED, ClaimVerdict.INTERPRETATION)
                mark = f"{GREEN}ACCEPTED{RESET}" if ok else f"{RED}REJECTED{RESET}"
                print(f"  {mark}  {DIM}{claim.verdict.value}{RESET}")
                print(f"            {claim.text[:96]}")
                if claim.reason:
                    print(f"            {RED}-> {claim.reason}{RESET}")
                elif claim.resolved:
                    node = claim.resolved[0]
                    print(f"            {DIM}-> resolves to {node['kind']} "
                          f"{node.get('policy_id') or ''}{RESET}")
                print()
    return 0


def _adversarial_suite(conn, run_id: str) -> list[str]:
    """Claims built from this run's real data: some true, some false."""
    failing = conn.execute(
        "SELECT uuid, policy_id FROM findings "
        "WHERE run_id=? AND oscal_status='not-satisfied' ORDER BY policy_id LIMIT 1",
        (run_id,),
    ).fetchone()
    passing = conn.execute(
        "SELECT uuid, policy_id FROM findings "
        "WHERE run_id=? AND oscal_status='satisfied' ORDER BY policy_id LIMIT 1",
        (run_id,),
    ).fetchone()
    manual = conn.execute(
        "SELECT uuid, policy_id FROM risks WHERE run_id=? AND unverified=1 LIMIT 1",
        (run_id,),
    ).fetchone()

    # A single transposed character -- the exact failure seen from a live model.
    corrupted = failing["uuid"][:9] + ("0" if failing["uuid"][9] != "0" else "1") + failing["uuid"][10:]

    return [
        f"{failing['policy_id']} is not-satisfied [{failing['uuid']}].",
        f"{passing['policy_id']} is satisfied [{passing['uuid']}].",
        f"This tenant is fully compliant and {failing['policy_id']} is satisfied "
        f"[{failing['uuid']}].",
        f"{failing['policy_id']} is not-satisfied [{corrupted}].",
        f"{manual['policy_id']} is compliant [{manual['uuid']}].",
        f"There are 999 failing SHALL requirements [{run_id}].",
        "Every control in this tenant passed.",
    ]


def cmd_export(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with session() as conn:
        run_id = args.run or _latest_run(conn)
        if not run_id:
            print("no compiled runs", file=sys.stderr)
            return 1
        rows = conn.execute(
            "SELECT model_type, sha256 FROM artifacts WHERE run_id=?", (run_id,)
        ).fetchall()
        for row in rows:
            payload = blobs.get(row["sha256"])
            if payload is None:
                continue
            target = out / f"{row['model_type']}.json"
            target.write_bytes(payload)
            print(f"  wrote {target}  ({len(payload):,} B)")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("fathom.api.main:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fathom", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("sources", help="verify pinned upstream sources")
    p.add_argument("--verify", action="store_true", default=True)
    p.set_defaults(func=cmd_sources)

    p = sub.add_parser("compile", help="compile a ScubaResults.json into OSCAL")
    p.add_argument("scan", nargs="?", help="path to ScubaResults.json")
    p.add_argument("--sample", action="store_true", help="use CISA's published sample scan")
    p.set_defaults(func=cmd_compile)

    p = sub.add_parser("posture", help="show the compiled posture")
    p.add_argument("--run", help="run ID (defaults to most recent)")
    p.set_defaults(func=cmd_posture)

    p = sub.add_parser("ask", help="ask a verified question")
    p.add_argument("question")
    p.add_argument("--run", help="run ID (defaults to most recent)")
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("verify", help="put a claim through the verifier")
    p.add_argument("claim", nargs="?", help="claim to verify; omit to run the adversarial suite")
    p.add_argument("--run", help="run ID (defaults to most recent)")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("export", help="write OSCAL artifacts to a directory")
    p.add_argument("--out", default="./artifacts/export")
    p.add_argument("--run", help="run ID (defaults to most recent)")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("serve", help="run the API server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--reload", action="store_true")
    p.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    if args.command == "compile" and not args.sample and not args.scan:
        parser.error("compile requires a scan path or --sample")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
