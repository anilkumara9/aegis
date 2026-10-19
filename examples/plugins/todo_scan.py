"""Aegis example plugin: todo_scan.

Scans the agent's working directory for TODO/FIXME/XXX/HACK markers and
returns file:line matches. Real and useful: it reads real files through
the tool context's cwd (never outside it), caps its output, and redacts
secret-shaped strings from the lines it echoes — a plugin must never
become a secret exfiltration path.

Install: copy this file to ~/.aegis/plugins/todo_scan.py
(or any dir listed in ~/.aegis/plugins.yaml), then restart the REPL.
The agent will see a `todo_scan` tool with the description below.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from aegis.detect import secrets as sec

_MARKER_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b\s*:?\s*(.*)")
_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv",
              "dist", "build", "target", ".aegis"}
_MAX_FILE_BYTES = 200_000
_MAX_MATCHES = 100


def _scan(root: Path):
    matches = []
    files = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            fp = Path(dirpath) / fn
            try:
                if fp.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = fp.read_text(encoding="utf-8", errors="strict")
            except Exception:
                continue
            files += 1
            rel = str(fp.relative_to(root))
            for i, line in enumerate(text.splitlines(), 1):
                m = _MARKER_RE.search(line)
                if m:
                    # Redact BEFORE echoing: a TODO line can sit next to
                    # a hardcoded key.
                    shown, _ = sec.redact(line.strip()[:160])
                    matches.append(
                        f"{rel}:{i}: [{m.group(1)}] {shown}")
                    if len(matches) >= _MAX_MATCHES:
                        return matches, files, True
    return matches, files, False


def run(args: dict, ctx) -> str:
    """Plugin entry point: run(args, ctx) -> str. ctx.cwd is the repo root."""
    sub = (args.get("path") or ".").strip() or "."
    root = (Path(ctx.cwd) / sub).resolve()
    try:
        root.relative_to(Path(ctx.cwd).resolve())
    except ValueError:
        return "error: path escapes the working directory"
    if not root.is_dir():
        return f"error: not a directory: {sub}"
    matches, files, truncated = _scan(root)
    lines = [f"todo_scan: {len(matches)} marker(s) in {files} files "
             f"under {root}"]
    lines.extend(f"- {m}" for m in matches)
    if truncated:
        lines.append(f"(truncated at {_MAX_MATCHES} matches)")
    if not matches:
        lines.append("No TODO/FIXME/XXX/HACK markers found.")
    return "\n".join(lines)


PLUGIN = {
    "name": "todo_scan",
    "description": ("Scan the working directory for TODO/FIXME/XXX/HACK "
                    "comment markers; returns file:line matches. "
                    "Args: {path: subdirectory to scan, default '.'}."),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string",
                     "description": "subdirectory of the working dir "
                                    "to scan (default '.')"},
        },
    },
    "run": run,
}
