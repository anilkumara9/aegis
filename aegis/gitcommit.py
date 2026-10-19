"""`/commit` skill: real git commits from a real working tree. (v0.7 Lane C)

Company-grade rules, enforced in code:

- Inspect first: ``git status --porcelain`` + ``git diff --stat``.
- Stage explicit paths (or an explicit numbered selection) — NEVER a
  blind ``git add -A``; ``.gitignore`` is respected by git itself.
- The commit message is written FROM the actual staged diff
  (conventional-commit ``type(scope): subject`` + a body of real per-file
  stats). The operator approves (or edits) the message before anything
  is committed.
- Refuse on a clean tree; refuse/abort when the staged diff contains
  secret-shaped material (Aegis's own secret detection).
- Every diff shown to the operator or written to logs passes through
  secret redaction first — secret values are never echoed.
- Clean error outside a git repo, and when git is missing.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from .detect import secrets as sec

_DIFF_DISPLAY_LIMIT = 6000


class GitError(Exception):
    """A git invocation failed or git is unavailable."""


def git_available() -> bool:
    return shutil.which("git") is not None


def _git(repo: Path, *args: str, timeout: int = 30) -> str:
    if not git_available():
        raise GitError("git is not installed or not on PATH")
    try:
        r = subprocess.run(["git", "-C", str(repo), *args],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise GitError("git command timed out")
    if r.returncode != 0:
        detail = (r.stderr or r.stdout).strip()
        raise GitError(detail or f"git {' '.join(args)} failed")
    return r.stdout


def repo_root(path: Path | str) -> Path | None:
    """Top-level of the enclosing git repo, or None."""
    try:
        out = _git(Path(path), "rev-parse", "--show-toplevel").strip()
    except GitError:
        return None
    return Path(out) if out else None


def changed_files(repo: Path) -> list[dict]:
    """Parse ``git status --porcelain``. Each entry: {path, x, y}."""
    out = _git(repo, "status", "--porcelain=v1", "--untracked-files=normal")
    entries = []
    for line in out.splitlines():
        if len(line) < 4:
            continue
        x, y, rest = line[0], line[1], line[3:]
        # Rename entries look like "R  old -> new".
        if " -> " in rest:
            rest = rest.split(" -> ", 1)[1]
        # Quoted paths (spaces/unicode): strip the quotes git adds.
        if rest.startswith('"') and rest.endswith('"'):
            rest = rest[1:-1]
        entries.append({"path": rest, "x": x, "y": y,
                        "staged": x not in (" ", "?")})
    return entries


def diff_stat(repo: Path, staged: bool = True,
              paths: list[str] | None = None) -> str:
    args = ["diff", "--stat", "--no-color"]
    if staged:
        args.append("--cached")
    if paths:
        args += ["--", *paths]
    try:
        return _git(repo, *args).strip()
    except GitError:
        return ""


def _numstat(repo: Path,
             paths: list[str] | None = None) -> list[tuple[str, int, int]]:
    """Staged numstat: [(path, added, deleted)]. Binary files -> (0, 0)."""
    args = ["diff", "--cached", "--numstat", "--no-color"]
    if paths:
        args += ["--", *paths]
    out = _git(repo, *args)
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        a, d, p = parts
        try:
            rows.append((p, int(a), int(d)))
        except ValueError:
            rows.append((p, 0, 0))  # binary
    return rows


def _new_files(repo: Path, paths: list[str] | None = None) -> set[str]:
    args = ["diff", "--cached", "--diff-filter=A", "--name-only", "--no-color"]
    if paths:
        args += ["--", *paths]
    out = _git(repo, *args)
    return {l.strip() for l in out.splitlines() if l.strip()}


def _infer_type_scope(paths: list[str], new_files: set[str]) -> tuple[str, str]:
    lowers = [p.lower() for p in paths]
    if lowers and all(p.endswith(".md") or "/docs/" in p or p == "docs"
                      or p.startswith("docs/") for p in lowers):
        kind = "docs"
    elif lowers and all(p.startswith("tests/") or "/tests/" in p
                        for p in lowers):
        kind = "test"
    elif any(p in new_files for p in paths):
        kind = "feat"
    else:
        kind = "chore"
    dirs = {str(Path(p).parent) for p in paths}
    if len(dirs) == 1:
        d = next(iter(dirs))
        scope = Path(d).name if d != "." else "repo"
    else:
        prefix = Path(paths[0]).parent
        for p in paths[1:]:
            pp = Path(p).parent
            while prefix not in (pp, *pp.parents) and str(prefix) != ".":
                prefix = prefix.parent
        scope = prefix.name if str(prefix) != "." else "repo"
    return kind, scope


def build_message(repo: Path, staged_paths: list[str]) -> str:
    """Conventional-commit message derived from the real staged diff."""
    stats = _numstat(repo, staged_paths)
    by_path = {p: (a, d) for p, a, d in stats}
    paths = [p for p, _, _ in stats] or list(staged_paths)
    new = _new_files(repo, staged_paths)
    kind, scope = _infer_type_scope(paths, new)
    total_add = sum(by_path.get(p, (0, 0))[0] for p in paths)
    total_del = sum(by_path.get(p, (0, 0))[1] for p in paths)
    if len(paths) == 1:
        subject = f"update {paths[0]}"
    else:
        shown = ", ".join(paths[:3])
        more = f" +{len(paths) - 3} more" if len(paths) > 3 else ""
        subject = f"update {shown}{more}"
    body_lines = [f"- {p}: +{by_path.get(p, (0, 0))[0]} "
                  f"-{by_path.get(p, (0, 0))[1]}" for p in paths]
    summary = (f"{len(paths)} file(s) changed, "
               f"{total_add} insertion(s)(+), {total_del} deletion(s)(-)")
    return (f"{kind}({scope}): {subject}\n\n"
            + "\n".join(body_lines) + f"\n\n{summary}")


def staged_diff_text(repo: Path,
                     paths: list[str] | None = None) -> str:
    """Full staged diff, UNREDACTED — for secret scanning only."""
    args = ["diff", "--cached", "--no-color"]
    if paths:
        args += ["--", *paths]
    return _git(repo, *args)


def find_staged_secrets(diff_text: str) -> list[dict]:
    """Secret-shaped spans in the staged diff.

    Returns [{kind, file, line}] — kinds and locations only, never the
    secret values themselves.
    """
    hits = sec.find_secrets(diff_text or "")
    if not hits:
        return []
    line_starts = [0]
    for m in re.finditer("\n", diff_text):
        line_starts.append(m.end())

    def _loc(pos: int) -> int:
        import bisect
        return bisect.bisect_right(line_starts, pos)

    out = []
    seen: set[tuple[str, str, int]] = set()
    lines = diff_text.splitlines()
    for h in hits:
        ln = _loc(h.start)
        # Walk back to the nearest "+++ b/<file>" header.
        f = "?"
        for i in range(ln - 1, max(0, ln - 40), -1):
            if i - 1 < len(lines) and lines[i - 1].startswith("+++ b/"):
                f = lines[i - 1][6:]
                break
        key = (h.kind, f, ln)
        if key not in seen:
            seen.add(key)
            out.append({"kind": h.kind, "file": f, "line": ln})
    return out


def redacted_diff(diff_text: str,
                  limit: int = _DIFF_DISPLAY_LIMIT) -> str:
    """Diff safe for display/logs: secrets redacted, length capped."""
    text, _ = sec.redact(diff_text or "")
    if len(text) > limit:
        text = text[:limit] + "\n…(truncated)"
    return text


def prepare_commit(repo: Path | str,
                   paths: list[str]) -> dict:
    """Stage explicit paths and derive the commit message.

    Returns {"ok", "root", "staged", "stat", "diff_redacted", "message",
    "error"}. Stages files but never commits — call finalize_commit.
    """
    root = repo_root(Path(repo))
    if root is None:
        return {"ok": False,
                "error": f"not a git repo: {repo}"}
    wanted = [p.strip().strip('"') for p in (paths or []) if p.strip()]
    if not wanted:
        return {"ok": False,
                "error": "no files selected — pass explicit paths "
                         "(never blind `git add -A`)"}
    changes = {c["path"] for c in changed_files(root)}
    missing = [p for p in wanted if p not in changes]
    if missing:
        return {"ok": False,
                "error": "no such changed file(s): " + ", ".join(missing)}
    try:
        _git(root, "add", "--", *wanted)
    except GitError as e:
        return {"ok": False, "error": f"staging failed: {e}"}
    try:
        diff = staged_diff_text(root, wanted)
    except GitError as e:
        return {"ok": False, "error": f"could not read staged diff: {e}"}
    secrets = find_staged_secrets(diff)
    if secrets:
        kinds = sorted({s["kind"] for s in secrets})
        files = sorted({s["file"] for s in secrets})
        return {"ok": False,
                "error": ("refusing to commit: staged diff contains "
                          f"secret-shaped material ({', '.join(kinds)}) in "
                          f"{', '.join(files)}. Remove the secrets and retry.")}
    message = build_message(root, wanted)
    return {"ok": True, "root": str(root), "staged": wanted,
            "stat": diff_stat(root, staged=True, paths=wanted),
            "diff_redacted": redacted_diff(diff), "message": message}


def finalize_commit(repo: Path | str, message: str,
                    paths: list[str] | None = None) -> dict:
    """Create the commit. With paths, only those paths are committed
    (previously staged leftovers stay staged). Returns {"ok", "sha",
    "error"}."""
    root = repo_root(Path(repo))
    if root is None:
        return {"ok": False, "error": f"not a git repo: {repo}"}
    message = (message or "").strip()
    if not message:
        return {"ok": False, "error": "empty commit message — refusing"}
    try:
        args = ["commit", "-m", message]
        if paths:
            args += ["--", *paths]
        _git(root, *args)
        sha = _git(root, "rev-parse", "--short", "HEAD").strip()
    except GitError as e:
        return {"ok": False, "error": f"commit failed: {e}"}
    return {"ok": True, "sha": sha}


def commit_flow(repo: Path | str,
                paths: list[str] | None = None,
                select: Callable[[list[str]], list[str]] | None = None,
                approve: Callable[[str], bool] | None = None,
                on_text: Callable[[str], None] | None = None) -> dict:
    """Full flow: inspect -> stage explicit paths -> secret scan ->
    message from diff -> approval -> commit. Returns {"ok", ...}."""
    emit = on_text or (lambda s: None)
    root = repo_root(Path(repo))
    if root is None:
        return {"ok": False, "error": f"not a git repo: {repo}"}
    changes = changed_files(root)
    if not changes:
        return {"ok": False, "error": "nothing to commit: working tree clean"}
    wanted = list(paths or [])
    if not wanted and select is not None:
        try:
            wanted = list(select([c["path"] for c in changes]) or [])
        except Exception as e:
            return {"ok": False, "error": f"selection failed: {e}"}
    if not wanted:
        return {"ok": False,
                "error": ("no files selected — pass explicit paths, e.g. "
                          "`/commit aegis/agent.py`. Changed files: "
                          + ", ".join(c["path"] for c in changes[:10])),
                "changed": [c["path"] for c in changes]}
    prep = prepare_commit(root, wanted)
    if not prep["ok"]:
        return prep
    emit(prep["stat"])
    emit(prep["diff_redacted"])
    message = prep["message"]
    emit(f"proposed message:\n{message}")
    if approve is not None:
        try:
            ok = bool(approve(message))
        except Exception as e:
            return {"ok": False, "error": f"approval failed: {e}",
                    "message": message}
        if not ok:
            return {"ok": False, "error": "commit aborted by operator",
                    "message": message}
    fin = finalize_commit(root, message, paths=prep["staged"])
    if not fin["ok"]:
        return {"ok": False, "error": fin["error"], "message": message}
    return {"ok": True, "sha": fin["sha"], "message": message,
            "staged": prep["staged"]}


def commit_flow_repl(repo: Path | str, rest: str) -> str:
    """Interactive /commit for the REPL: numbered selection, redacted
    diff, message approval with an edit option."""
    root = repo_root(Path(repo))
    if root is None:
        return f"error: not a git repo: {repo}"
    changes = changed_files(root)
    if not changes:
        return "nothing to commit: working tree clean."
    print("changed files:")
    for i, c in enumerate(changes, 1):
        print(f"  {i:2d}. [{c['x']}{c['y']}] {c['path']}")
    tokens = (rest or "").split()
    if not tokens:
        try:
            pick = input("stage which? numbers/paths, space or comma "
                         "separated (Enter cancels): ").strip()
        except (EOFError, KeyboardInterrupt):
            return "cancelled."
        if not pick:
            return "cancelled."
        tokens = re.split(r"[,\s]+", pick)
    wanted: list[str] = []
    for t in tokens:
        if t.isdigit() and 1 <= int(t) <= len(changes):
            wanted.append(changes[int(t) - 1]["path"])
        elif t:
            wanted.append(t)
    prep = prepare_commit(root, wanted)
    if not prep["ok"]:
        return f"error: {prep['error']}"
    if prep["stat"]:
        print(prep["stat"])
    print(prep["diff_redacted"])
    message = prep["message"]
    print(f"\nproposed message:\n{message}\n")
    try:
        ans = input("commit with this message? [y/N/e(dit)] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return "cancelled."
    if ans == "e":
        try:
            new = input("new message (empty cancels): ").strip()
        except (EOFError, KeyboardInterrupt):
            return "cancelled."
        if not new:
            return "cancelled — nothing committed."
        message = new
    elif ans != "y":
        return "cancelled — nothing committed."
    fin = finalize_commit(root, message, paths=prep["staged"])
    if not fin["ok"]:
        return f"error: {fin['error']}"
    first = message.splitlines()[0]
    return f"committed {fin['sha']}: {first}"
