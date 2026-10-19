"""Slash skills for the REPL: /hunt /guard /scan /respond /kb.

/hunt audits the user's OWN codebase/systems only — the target must be a
local directory that exists. URLs, hosts, and anything non-local are
refused. This is defensive auditing of own assets, never reconnaissance
of someone else's.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .detect import secrets as sec

# v0.7 Lane A: polyglot coding skills (lazy imports keep skills importable
# without the agent loop; tdd needs no skills import, so this is safe).
from . import polyglot
from . import repomap as repomap_mod
from . import tdd as tdd_mod
from .index import CodeIndex, query_index

# Static audit patterns: (kind, regex, kb_hint)
AUDIT_PATTERNS: list[tuple[str, str, str]] = [
    ("hardcoded_secret",
     r"(?i)(password|passwd|secret|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
     "credential_exfiltration"),
    ("dangerous_eval", r"\beval\s*\(", "privilege_escalation"),
    ("dangerous_exec", r"\bexec\s*\(", "privilege_escalation"),
    ("shell_true", r"shell\s*=\s*True", "privilege_escalation"),
    ("os_system", r"\bos\.system\s*\(", "privilege_escalation"),
    ("pickle_loads", r"pickle\.loads?\s*\(", "web_exploitation"),
    ("yaml_unsafe_load", r"yaml\.load\s*\(", "web_exploitation"),
    ("verify_false", r"verify\s*=\s*False", "network_attacks"),
    ("subprocess_untrusted", r"subprocess\.(run|call|Popen)\s*\([^)]*shell",
     "privilege_escalation"),
    ("sql_format", r"(?i)(execute|query)\s*\(.*%s.*%|f['\"].*SELECT",
     "web_exploitation"),
    ("debug_enabled", r"(?i)debug\s*=\s*True", "privilege_escalation"),
    ("weak_crypto", r"\b(md5|sha1|DES)\b", "algorithms"),
    ("jwt_none_alg", r"(?i)algorithms?\s*=\s*\[.*['\"]none['\"]", "web_exploitation"),
]

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist",
              "build", ".aegis"}
_MAX_FILE_BYTES = 200_000
_MAX_FINDINGS = 200


def _looks_remote(target: str) -> bool:
    t = target.strip().lower()
    return (t.startswith(("http://", "https://", "ssh://", "ftp://"))
            or re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/|$)", t) is not None
            or re.match(r"^\d{1,3}(\.\d{1,3}){3}", t) is not None)


def _resolve_local_dir(target: str, skill: str) -> tuple[Path | None, str]:
    """Validate a skill target is a local directory. Returns (path, error)."""
    target = (target or "").strip()
    if not target:
        return None, f"usage: {skill} <local-directory>"
    if _looks_remote(target):
        return None, (f"refused: {skill} only works on your OWN local systems. "
                       f"Give me a local directory path.")
    p = Path(target).expanduser()
    if not p.is_dir():
        return None, (f"refused: '{target}' is not a local directory. {skill} "
                       f"works on your own local code only — pass a directory "
                       f"that exists on this machine.")
    return p, ""


def _scan_dir(p: Path) -> tuple[list[dict], int]:
    """Pattern scan of a local dir. Returns (findings, files_scanned).

    Each finding: {kind, rel, lineno, line, hint}. Secrets are never
    returned in the clear.
    """
    findings: list[dict] = []
    files_scanned = 0
    compiled = [(k, re.compile(rx), hint) for k, rx, hint in AUDIT_PATTERNS]
    for root, dirs, files in os.walk(p):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            fp = Path(root) / fn
            try:
                if fp.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = fp.read_text(encoding="utf-8", errors="strict")
            except Exception:
                continue
            files_scanned += 1
            rel = str(fp.relative_to(p))
            for i, line in enumerate(text.splitlines(), 1):
                for kind, rx, hint in compiled:
                    if rx.search(line):
                        findings.append({"kind": kind, "rel": rel,
                                         "lineno": i,
                                         "line": line.strip()[:160],
                                         "hint": hint})
                        if len(findings) >= _MAX_FINDINGS:
                            break
                if len(findings) >= _MAX_FINDINGS:
                    break
            for hit in sec.find_secrets(text):
                findings.append({"kind": f"secret_material:{hit.kind}",
                                 "rel": rel, "lineno": 0, "line": "REDACTED",
                                 "hint": "credential_exfiltration"})
                if len(findings) >= _MAX_FINDINGS:
                    break
            if len(findings) >= _MAX_FINDINGS:
                break
        if len(findings) >= _MAX_FINDINGS:
            break
    return findings, files_scanned


def _kb_cite(kb, hint: str) -> str:
    if kb is None:
        return ""
    hits = kb.query(hint.replace("_", " "), top_k=1)
    if hits:
        return f" (see {hits[0].id} {hits[0].name})"
    return ""


def hunt(path: str, kb=None) -> str:
    """Audit a LOCAL directory. Returns a markdown report."""
    p, err = _resolve_local_dir(path, "/hunt")
    if p is None:
        return err
    findings, files_scanned = _scan_dir(p)
    lines = [f"# /hunt report: {p}",
             f"Files scanned: {files_scanned}. "
             f"Findings: {len(findings)} (pattern-based triage, not a proof).",
             ""]
    if findings:
        for f in findings:
            loc = f"{f['rel']}:{f['lineno']}" if f["lineno"] else f["rel"]
            lines.append(f"- [{f['kind']}] {loc}{_kb_cite(kb, f['hint'])}\n"
                         f"  `{f['line']}`")
        lines += ["",
                  "Next: investigate each finding, then `respond` playbooks if "
                  "anything is live-compromised. Re-run after fixes."]
    else:
        lines.append("No matches for the built-in audit patterns. This is a "
                     "triage pass, not a clean bill of health — consider a "
                     "deeper review for your threat model.")
    return "\n".join(lines)
    lines = [f"# /hunt report: {p}",
             f"Files scanned: {files_scanned}. "
             f"Findings: {len(findings)} (pattern-based triage, not a proof).",
             ""]
    if findings:
        lines.extend(findings)
        lines += ["",
                  "Next: investigate each finding, then `respond` playbooks if "
                  "anything is live-compromised. Re-run after fixes."]
    else:
        lines.append("No matches for the built-in audit patterns. This is a "
                     "triage pass, not a clean bill of health — consider a "
                     "deeper review for your threat model.")
    return "\n".join(lines)


# Attacker-phase mapping for /plan: pattern kind -> (phase, attacker thought)
_PLAN_PHASES: list[tuple[str, str, set[str]]] = [
    ("Phase 1 — Reconnaissance",
     "What can I learn without touching anything? Secrets in the repo, "
     "entry points, tech stack, debug flags left on.",
     {"hardcoded_secret", "debug_enabled"}),
    ("Phase 2 — Initial access",
     "Where is the front door? Injection points, unsafe deserialization, "
     "auth weaknesses, request forgery.",
     {"sql_format", "pickle_loads", "yaml_unsafe_load", "jwt_none_alg",
      "verify_false"}),
    ("Phase 3 — Execution & privilege escalation",
     "Once I'm in, how do I run code and get more power? Eval, shell, "
     "subprocess, weak crypto guarding secrets.",
     {"dangerous_eval", "dangerous_exec", "shell_true", "os_system",
      "subprocess_untrusted", "weak_crypto"}),
    ("Phase 4 — Persistence & exfiltration",
     "How do I stay, and what do I take? Stored secrets are the exfil "
     "shortcut; every hardcoded credential is a standing invitation.",
     set()),
]


def plan_attack_surface(path: str, kb=None) -> str:
    """Hacker-mindset attack plan for the user's OWN code (defensive).

    Read-only: scans the local directory and lays out how an attacker
    would think about it, phase by phase, so the defender can fix the
    highest-leverage issues first. Never touches anything outside the
    given local directory.
    """
    p, err = _resolve_local_dir(path, "/plan")
    if p is None:
        return err
    findings, files_scanned = _scan_dir(p)
    lines = [f"# /plan — attacker-mindset plan for YOUR code: {p}",
             "",
             "This is defensive planning: think like the attacker so you can "
             "fix like the defender. Phases below follow the attacker's "
             "decision order — the fix-first queue at the end is yours.",
             f"Files scanned: {files_scanned}. Signals: {len(findings)} "
             "(pattern-based triage, not a proof).",
             ""]
    by_kind: dict[str, list[dict]] = {}
    for f in findings:
        base = f["kind"].split(":")[0]
        by_kind.setdefault(base, []).append(f)
    secret_findings = [f for f in findings
                       if f["kind"].startswith("secret_material")]
    for phase, thought, kinds in _PLAN_PHASES:
        phase_hits = [f for k in kinds for f in by_kind.get(k, [])]
        if phase.startswith("Phase 4"):
            phase_hits = secret_findings
        lines.append(f"## {phase}")
        lines.append(f"*{thought}*")
        if not phase_hits:
            lines.append("No signals in this phase from the pattern scan — "
                         "do not read this as 'safe', only as 'unseen'.")
        else:
            for f in phase_hits[:12]:
                loc = (f"{f['rel']}:{f['lineno']}"
                       if f["lineno"] else f["rel"])
                lines.append(f"- [{f['kind']}] {loc}"
                             f"{_kb_cite(kb, f['hint'])}")
            if len(phase_hits) > 12:
                lines.append(f"- …and {len(phase_hits) - 12} more.")
        lines.append("")
    lines.append("## Fix-first queue (defender's cut list)")
    priority = (secret_findings
                + [f for k in ("hardcoded_secret",) for f in by_kind.get(k, [])]
                + [f for k, _, _ in
                    [(k, t, s) for _, t, s in _PLAN_PHASES for k in s]
                    for f in by_kind.get(k, [])])
    seen: set[tuple] = set()
    queue: list[dict] = []
    for f in priority:
        key = (f["kind"], f["rel"], f["lineno"])
        if key not in seen:
            seen.add(key)
            queue.append(f)
    if not queue:
        lines.append("Nothing pattern-matched — start with a manual review "
                     "of auth, input handling, and secret storage.")
    else:
        for i, f in enumerate(queue[:15], 1):
            loc = (f"{f['rel']}:{f['lineno']}" if f["lineno"] else f["rel"])
            lines.append(f"{i}. [{f['kind']}] {loc}{_kb_cite(kb, f['hint'])}")
    lines += ["",
              "Fix in queue order, re-run `/plan` after, and keep the guard "
              "on: planning is read-only, changes belong in dev mode."]
    return "\n".join(lines)


def emulate(path: str, campaign: str | None = None, kb=None) -> str:
    """Purple-team adversary emulation for the user's OWN code (defensive).

    Thin wrapper over aegis.emulate: chains KB techniques into a 5-stage
    campaign narrative grounded in the local scan, then verifies each stage
    against the detection stack. Returns a markdown report. Import is lazy
    to avoid a skills<->emulate import cycle.
    """
    from .emulate import EmulateError, emulate_dir
    try:
        return emulate_dir(path, campaign=campaign, kb=kb, as_json=False)
    except EmulateError as exc:
        return str(exc)


# ---------------------------------------------------------------------------
# v0.7 Lane A — polyglot coding skills: /build /test /fix /refactor
# /repomap /index. All operate on the user's OWN local directories only
# (same local-only rule as /hunt). /build and /test run the project's
# real toolchain; /fix and /refactor drive the agent loop (dev mode).
# ---------------------------------------------------------------------------

def _coding_target(target: str, skill: str) -> tuple[Path | None, str, str]:
    """Split '<dir> [extra]' for coding skills. Returns (dir, extra, error)."""
    target = (target or "").strip()
    if not target:
        return None, "", f"usage: {skill} <local-directory> [args]"
    first, _, extra = target.partition(" ")
    p, err = _resolve_local_dir(first, skill)
    if p is None:
        return None, "", err
    return p, extra.strip(), ""


def _render_run_results(title: str, results: "list") -> str:
    lines = [title, ""]
    if not results:
        lines.append("No toolchains detected — nothing to run.")
        return "\n".join(lines)
    for r in results:
        step = r.steps[0] if r.steps else None
        mark = "✓" if r.ok else "✗"
        lines.append(f"{mark} [{r.language}] {r.summary}")
        if step is not None:
            if step.skipped_missing:
                lines.append(f"  skipped: {step.skipped_missing}")
            else:
                lines.append(f"  $ {' '.join(step.argv)}"
                             f" (exit {step.returncode}"
                             f"{', TIMEOUT' if step.timed_out else ''})")
                if step.output.strip():
                    lines.append("  ```")
                    lines.extend(f"  {l}" for l in
                                 step.output.splitlines()[-25:])
                    lines.append("  ```")
        lines.append("")
    return "\n".join(lines).rstrip()


def build(path: str, kb=None) -> str:
    """Detect the toolchain and run the project's build. Real commands."""
    p, _, err = _coding_target(path, "/build")
    if p is None:
        return err
    results = polyglot.run_build(p)
    return _render_run_results(f"# /build: {p}", results)


def test_suite(path: str, kb=None) -> str:
    """Run the project's real test suite and summarize pass/fail."""
    p, _, err = _coding_target(path, "/test")
    if p is None:
        return err
    results = polyglot.run_tests(p)
    return _render_run_results(f"# /test: {p}", results)


def _require_dev(loop, skill: str) -> str:
    if loop is None:
        return (f"refused: {skill} needs a live agent session to drive "
                f"code changes.")
    if getattr(loop, "mode", "dev") != "dev":
        return (f"refused: {skill} writes code — switch to dev mode first "
                f"(/mode dev). Plan mode is read-only by guard design.")
    return ""


def fix(target: str, loop=None, kb=None) -> str:
    """Fix failing tests: run the suite, then drive the agent loop.

    Usage: /fix <local-directory> [error-file-or-text]
    Caps at 5 TDD rounds, then reports honestly "stuck" with what was
    tried. Never invents a fix: the test suite is the verdict.
    """
    denied = _require_dev(loop, "/fix")
    if denied:
        return denied
    p, extra, err = _coding_target(target, "/fix")
    if p is None:
        return err
    error_text = ""
    if extra:
        ep = Path(extra).expanduser()
        if ep.is_file():
            try:
                error_text = ep.read_text(encoding="utf-8",
                                          errors="replace")[:8000]
            except OSError:
                error_text = ""
        else:
            error_text = extra[:8000]
    # Baseline: run the suite ourselves. If an error was handed in, use it.
    baseline = polyglot.run_tests(p)
    failing = [r for r in baseline if not r.ok]
    base_note = " | ".join(r.summary for r in baseline) or "no results"
    if not failing:
        extra_note = (" (the supplied error did not reproduce locally)"
                      if error_text else "")
        return (f"# /fix: {p}\n\nSuite is already GREEN: {base_note}"
                f"{extra_note}\nNothing to fix.")
    task = (f"Fix the failing tests in {p}. Baseline: {base_note}."
            + (f" Reported error:\n{sec.redact(error_text)[0][:4000]}"
               if error_text else ""))
    res = tdd_mod.tdd_loop(loop, p, task, max_rounds=5)
    lines = [f"# /fix: {p}", "",
             f"Baseline: {base_note}", "",
             f"Result: **{res['status'].upper()}** — {res['summary']}", ""]
    if res["status"] == "stuck":
        lines.append("The loop is stuck: it tried, the suite stayed red, "
                     "and it stopped instead of inventing a fix. What was "
                     "tried is itemized per round in the session audit log "
                     "(event: tdd_step). Suggested next step: read the "
                     "failing test output above and fix by hand, then "
                     "/test again.")
    return "\n".join(lines)


def refactor(target: str, loop=None, kb=None) -> str:
    """Refactor for clarity, keep behavior: re-runs tests after.

    Usage: /refactor <local-directory> [relative-target]
    Baseline test run -> agent refactor turn -> test run again. A
    green->red transition is reported as a REGRESSION, not hidden.
    """
    denied = _require_dev(loop, "/refactor")
    if denied:
        return denied
    p, extra, err = _coding_target(target, "/refactor")
    if p is None:
        return err
    scope = extra or "the project"
    if extra:
        sp = (p / extra).resolve()
        try:
            sp.relative_to(p.resolve())
        except ValueError:
            return f"refused: target '{extra}' escapes {p}"
        if not sp.exists():
            return f"refused: target '{extra}' does not exist under {p}"
    before = polyglot.run_tests(p)
    before_ok = bool(before) and all(r.ok for r in before)
    before_note = " | ".join(r.summary for r in before) or "no test results"
    prompt = (
        f"Refactor {scope} in {p} for clarity and readability: better "
        f"names, smaller functions, remove duplication. Do NOT change "
        f"behavior, do NOT change public APIs, do NOT add features. "
        f"Use write/edit tools; keep the diff minimal. Do NOT run the "
        f"test suite yourself — I will run it after.")
    try:
        loop.run(prompt)
    except Exception as e:  # noqa: BLE001 - surfaced honestly below
        return (f"# /refactor: {p}\n\nRefactor turn raised "
                f"{type(e).__name__}: {e}\nNo post-refactor test run was "
                f"possible — inspect the tree before trusting it.")
    after = polyglot.run_tests(p)
    after_ok = bool(after) and all(r.ok for r in after)
    after_note = " | ".join(r.summary for r in after) or "no test results"
    lines = [f"# /refactor: {p} (scope: {scope})", "",
             f"Tests before: {before_note}",
             f"Tests after:  {after_note}", ""]
    if before_ok and after_ok:
        lines.append("**Refactor clean**: suite green before and after — "
                     "behavior preserved as far as the tests can tell.")
    elif not before_ok and not after_ok:
        lines.append("Suite was red before and is still red — the refactor "
                     "did not make things worse, but nothing is proven "
                     "green. Run /fix to chase the failures.")
    elif before_ok and not after_ok:
        lines.append("**REGRESSION**: suite was GREEN before the refactor "
                     "and is RED now. The refactor broke behavior — review "
                     "the diff and run /fix, or revert.")
    else:
        lines.append("Suite went from red to GREEN — the refactor fixed "
                     "whatever was failing (or the failures were flaky; "
                     "re-run /test to confirm).")
    return "\n".join(lines)


def repomap_cmd(path: str, kb=None) -> str:
    """Show the compact repo map for a local directory."""
    p, err = _resolve_local_dir(path or ".", "/repomap")
    if p is None:
        return err
    return repomap_mod.render_repo_map(p)


def index_cmd(target: str, kb=None) -> str:
    """Codebase index: stats, or ranked file retrieval for a query.

    Usage: /index <local-directory> [query]
    """
    p, extra, err = _coding_target(target or ".", "/index")
    if p is None:
        return err
    if not extra:
        idx = CodeIndex.load(p)
        fresh = False
        if idx is None:
            idx = CodeIndex.build(p)
            idx.save()
            fresh = True
        else:
            changed = idx.check()
            if changed:
                idx.save()
        st = idx.stats()
        lines = [f"# Code index: {st['root']}",
                 f"Files: {st['files']} | symbols: {st['symbols']} "
                 f"({'freshly built' if fresh else 'from cache, refreshed'})",
                 ""]
        for lang, n in sorted(st["languages"].items(),
                              key=lambda kv: (-kv[1], kv[0]))[:12]:
            lines.append(f"- {lang}: {n} files")
        lines += ["", "Query it: /index <dir> <keywords or symbol name>"]
        return "\n".join(lines)
    ranked = query_index(p, extra, top_k=10)
    lines = [f"# Index query '{extra}' in {p}", ""]
    if not ranked:
        lines.append("No indexed files matched.")
    else:
        for score, rel in ranked:
            lines.append(f"- {rel}  (score {score:.0f})")
    return "\n".join(lines)


SKILLS = {
    "/hunt": "Audit YOUR OWN local codebase for vulnerabilities: /hunt <dir>",
    "/plan": "Hacker-mindset attack plan for YOUR OWN code (read-only): /plan <dir>",
    "/emulate": "Purple-team adversary campaign emulation on YOUR OWN code: /emulate <dir> [campaign]",
    "/planexec": "Plan-then-execute a complex task: model proposes steps, guard screens, approved plan runs",
    "/build": "Detect toolchain and run the project build: /build <dir>",
    "/test": "Run the project's real test suite: /test <dir>",
    "/fix": "Fix failing tests via the agent loop (max 5 rounds): /fix <dir> [error-file-or-text]",
    "/refactor": "Refactor for clarity, re-run tests after: /refactor <dir> [target]",
    "/repomap": "Compact project intelligence map: /repomap <dir>",
    "/index": "Codebase index stats or ranked file search: /index <dir> [query]",
    "/mode": "Switch dev/plan mode: /mode <dev|plan>",
    "/guard": "Guard session status and kill-switch: /guard [status|kill]",
    "/scan": "Analyze a tool-call trace: /scan <trace.jsonl>",
    "/respond": "Emit an incident runbook: /respond <playbook> [detail]",
    "/kb": "Query the technique knowledge base: /kb <query>",
    "/sessions": "List saved conversation sessions",
    "/resume": "Resume a conversation: /resume <n|id>",
    "/rename": "Rename the current conversation: /rename <title>",
    "/help": "Show help",
    "/exit": "Exit (also /quit)",
}
