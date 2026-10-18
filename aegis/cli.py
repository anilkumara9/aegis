"""Aegis CLI: aegis [repl] | scan | guard | respond | kb | hunt | emulate | watch | version."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, guard as guard_mod
from .guard import Policy


def _kb():
    from .kb import KB
    return KB.load()


def cmd_scan(args) -> int:
    from .scan import scan_file
    try:
        scan_file(args.trace, _kb(), as_json=args.json)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_guard(args) -> int:
    kb = _kb()
    if args.guard_cmd == "wrap":
        from .guard_wrap import wrap
        sep = args.cmd
        if sep and sep[0] == "--":
            sep = sep[1:]
        return wrap(sep, Policy(name="wrap-cli"), kb)
    if args.guard_cmd == "kill":
        guard_mod.kill_session(args.session)
        print(f"session {args.session} revoked.")
        return 0
    if args.guard_cmd == "status":
        print(f"session: {args.session}")
        print(f"revoked: {guard_mod.is_revoked(args.session)}")
        return 0
    if args.guard_cmd == "check":
        policy = Policy(name="check")
        sess = guard_mod.create_session(policy, kb)
        try:
            call_args = json.loads(args.args or "{}")
        except json.JSONDecodeError as e:
            print(f"error: bad --args JSON: {e}", file=sys.stderr)
            return 2
        verdict = sess.check_call(args.tool, call_args)
        print(f"decision: {verdict.decision}")
        if verdict.reason:
            print(f"reason: {verdict.reason}")
        for f in verdict.findings:
            print(f"  [{f.severity}] {f.technique_id} {f.technique_name}")
        return 0
    print("unknown guard subcommand", file=sys.stderr)
    return 2


def cmd_respond(args) -> int:
    if args.playbook == "timeline":
        from .respond import build_timeline
        print(build_timeline())
        return 0
    from .respond.playbooks import PLAYBOOKS, run_playbook
    if args.playbook not in PLAYBOOKS:
        print(f"unknown playbook '{args.playbook}'. Choose from: "
              f"{', '.join(PLAYBOOKS)}", file=sys.stderr)
        return 2
    print(run_playbook(args.playbook, detail=args.detail or ""))
    return 0


def cmd_kb(args) -> int:
    kb = _kb()
    results = kb.query(args.query, top_k=args.top_k)
    if not results:
        print("no matches.")
        return 0
    for t in results:
        print(f"\n## {t.id} [{t.severity}] {t.name}\n{t.description}")
        print(f"Indicators: {'; '.join(t.indicators[:4])}")
        print(f"Mitigations: {'; '.join(t.mitigations[:3])}")
    return 0


def cmd_hunt(args) -> int:
    from .skills import hunt
    print(hunt(args.path, _kb()))
    return 0


def cmd_emulate(args) -> int:
    from .emulate import EmulateError, emulate_dir
    try:
        print(emulate_dir(args.target, campaign=args.campaign, kb=_kb(),
                          as_json=args.as_json))
    except EmulateError as exc:
        print(f"emulate: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_graph(args) -> int:
    from .graph import run_graph
    return run_graph(args.target, json_mode=args.json, top=args.top)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis",
                                description="Aegis defensive guard agent")
    sub = p.add_subparsers(dest="command")

    rpl = sub.add_parser("repl", help="interactive terminal agent (default)")
    rpl.add_argument("--mode", default="",
                     help="dev|plan (default: dev; AEGIS_MODE env)")

    s = sub.add_parser("scan", help="analyze a tool-call trace")
    s.add_argument("trace", help="path to .jsonl trace file")
    s.add_argument("--json", action="store_true")

    g = sub.add_parser("guard", help="live guard interceptor")
    gs = g.add_subparsers(dest="guard_cmd", required=True)
    w = gs.add_parser("wrap", help="run a command through the guard")
    w.add_argument("cmd", nargs=argparse.REMAINDER)
    k = gs.add_parser("kill", help="kill-switch: revoke a session")
    k.add_argument("--session", required=True)
    st = gs.add_parser("status", help="session revocation status")
    st.add_argument("--session", required=True)
    c = gs.add_parser("check", help="screen a single tool call")
    c.add_argument("--tool", required=True)
    c.add_argument("--args", default="{}")

    r = sub.add_parser("respond", help="emit an incident runbook")
    r.add_argument("playbook")
    r.add_argument("detail", nargs="?", default="")

    kq = sub.add_parser("kb", help="query the technique knowledge base")
    kq.add_argument("query")
    kq.add_argument("--top-k", type=int, default=5)

    h = sub.add_parser("hunt", help="audit your own local codebase")
    h.add_argument("path")

    w = sub.add_parser("watch", help="continuous defensive monitoring (SOC-in-a-box)")
    w.add_argument("watch_args", nargs=argparse.REMAINDER,
                   help="--once|--interval|--triage|--schedule <dir> [...]")

    e = sub.add_parser("emulate", help="purple-team adversary campaign "
                       "emulation on your own local code")
    e.add_argument("--target", required=True,
                   help="local directory to emulate against (own assets only)")
    e.add_argument("--campaign", default="credential-theft",
                   help="credential-theft|supply-chain|insider-exfil")
    e.add_argument("--json", action="store_true", dest="as_json",
                   help="machine-readable JSON output")

    gr = sub.add_parser("graph", help="attack graph: ranked adversary paths "
                                      "for a local system")
    gr.add_argument("target", help="local directory to analyze "
                                  "(read-only; remote targets refused)")
    gr.add_argument("--json", action="store_true", help="emit JSON report")
    gr.add_argument("--top", type=int, default=5,
                    help="ranked paths to show (default 5)")

    sub.add_parser("version", help="print version")
    p.add_argument("--provider", default="", help="anthropic|openai|google|ollama|mock")
    p.add_argument("--model", default="", help="model name override")
    p.add_argument("--mode", default="", help="dev|plan (default: dev; AEGIS_MODE env)")
    return p


def main(argv=None) -> int:
    # `watch` owns its own argparse surface; intercept before the outer parser
    # because argparse subparsers do not forward leading-dash args to REMAINDER.
    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)
    if argv[:1] == ["watch"]:
        from .watch import main as watch_main
        return watch_main(argv[1:])
    parser = build_parser()
    args = parser.parse_args(argv)
    cmd = args.command or "repl"
    if cmd == "repl":
        from .repl import run_repl
        return run_repl(args.provider, args.model,
                        args.mode or os.environ.get("AEGIS_MODE", "dev"))
    if cmd == "scan":
        return cmd_scan(args)
    if cmd == "guard":
        return cmd_guard(args)
    if cmd == "respond":
        return cmd_respond(args)
    if cmd == "kb":
        return cmd_kb(args)
    if cmd == "hunt":
        return cmd_hunt(args)
    if cmd == "emulate":
        return cmd_emulate(args)
    if cmd == "graph":
        return cmd_graph(args)
    if cmd == "version":
        print(f"aegis {__version__}")
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
