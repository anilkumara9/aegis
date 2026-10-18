"""Unified diff previews for file write/edit approvals.

When the guard escalates a file modification for human approval, the
operator sees a diff of what would change BEFORE the approval prompt.
Plain ``+/-`` markers are always emitted so the output is readable on
dumb terminals; ANSI colors are added only when stdout is a TTY.
Read-only: never modifies the file.
"""

from __future__ import annotations

import difflib
import sys
from pathlib import Path

from .tools import safe_path

MAX_DIFF_LINES = 400

_C_GREEN = "\033[32m"
_C_RED = "\033[31m"
_C_CYAN = "\033[36m"
_C_RESET = "\033[0m"


def _resolve(cwd: Path, path: str) -> Path:
    return safe_path(Path(cwd).resolve(), path)


def _read(p: Path) -> str | None:
    if not p.is_file():
        return None
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def diff_for_write(path: str, content: str, cwd: Path,
                   color: bool | None = None) -> str:
    """Diff the CURRENT file vs ``content`` for the ``write`` tool.

    ``content`` is the would-be new file body. A missing file shows as
    all-added lines.
    """
    try:
        p = _resolve(cwd, path)
    except PermissionError as e:
        return f"(no diff: {e})"
    old = _read(p)
    if old is None:
        return _render(path, "", content or "", color,
                       header_note="(new file)")
    return _render(path, old, content or "", color)


def diff_for_edit(path: str, old_text: str, new_text: str, cwd: Path,
                  color: bool | None = None) -> str:
    """Diff the CURRENT file vs the ``edit``-tool result.

    ``edit`` replaces the first occurrence of ``old_text`` with
    ``new_text``; the preview shows exactly that change.
    """
    try:
        p = _resolve(cwd, path)
    except PermissionError as e:
        return f"(no diff: {e})"
    old = _read(p)
    if old is None:
        return f"(no diff: {path} does not exist — edit would fail)"
    old_text = old_text or ""
    if old_text and old_text not in old:
        return "(no diff: old_text not found — edit would fail)"
    new = old.replace(old_text, new_text or "", 1) if old_text else old
    return _render(path, old, new, color)


def _render(path: str, old: str, new: str, color: bool | None,
            header_note: str = "") -> str:
    diff = list(difflib.unified_diff(
        old.splitlines(), new.splitlines(),
        fromfile=f"a/{path}", tofile=f"b/{path}", lineterm=""))
    if not diff:
        return "(no changes)"
    truncated = len(diff) > MAX_DIFF_LINES
    diff = diff[:MAX_DIFF_LINES]
    use_color = sys.stdout.isatty() if color is None else color
    lines = [f"--- diff: {path} {header_note}".rstrip()]
    for line in diff:
        lines.append(_colorize(line, use_color))
    if truncated:
        lines.append(f"… (truncated at {MAX_DIFF_LINES} lines)")
    return "\n".join(lines)


def _colorize(line: str, use_color: bool) -> str:
    if not use_color:
        return line
    if line.startswith("@@"):
        return f"{_C_CYAN}{line}{_C_RESET}"
    if line.startswith("+") and not line.startswith("+++"):
        return f"{_C_GREEN}{line}{_C_RESET}"
    if line.startswith("-") and not line.startswith("---"):
        return f"{_C_RED}{line}{_C_RESET}"
    return line
