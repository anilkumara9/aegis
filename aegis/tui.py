"""Polished terminal UI: syntax highlighting, streaming markdown renderer.

Dumb-terminal friendly: plain ANSI colors only, no cursor movement, no
curses. Colors are disabled when NO_COLOR is set or stdout is not a tty.
Everything here is display-only — it never changes what the agent does.
"""

from __future__ import annotations

import os
import re
import sys

_COLOR: bool | None = None


def set_color(enabled: bool) -> None:
    """Force color on/off (tests use this)."""
    global _COLOR
    _COLOR = bool(enabled)


def _color_enabled() -> bool:
    global _COLOR
    if _COLOR is None:
        if os.environ.get("NO_COLOR"):
            _COLOR = False
        else:
            try:
                _COLOR = sys.stdout.isatty()
            except Exception:
                _COLOR = False
    return _COLOR


def _c(code: str) -> str:
    return f"\x1b[{code}m" if _color_enabled() else ""


def reset() -> str:
    return _c("0")


def bold(s: str) -> str:
    return f"{_c('1')}{s}{reset()}" if s else s


def dim(s: str) -> str:
    return f"{_c('2')}{s}{reset()}" if s else s


def green(s: str) -> str:
    return f"{_c('32')}{s}{reset()}" if s else s


def red(s: str) -> str:
    return f"{_c('31')}{s}{reset()}" if s else s


def yellow(s: str) -> str:
    return f"{_c('33')}{s}{reset()}" if s else s


def cyan(s: str) -> str:
    return f"{_c('36')}{s}{reset()}" if s else s


# -- syntax highlighting ------------------------------------------------
_KEYWORDS: dict[str, set[str]] = {
    "python": {
        "def", "class", "return", "import", "from", "as", "if", "elif",
        "else", "for", "while", "try", "except", "finally", "with",
        "raise", "assert", "lambda", "pass", "break", "continue", "in",
        "is", "not", "and", "or", "None", "True", "False", "yield",
        "async", "await", "global", "nonlocal", "del",
    },
    "javascript": {
        "function", "return", "const", "let", "var", "if", "else", "for",
        "while", "try", "catch", "finally", "throw", "new", "class",
        "extends", "import", "from", "export", "default", "async",
        "await", "typeof", "instanceof", "in", "of", "do", "switch",
        "case", "break", "continue", "this", "null", "undefined", "true",
        "false",
    },
    "bash": {
        "if", "then", "else", "elif", "fi", "for", "while", "do", "done",
        "case", "esac", "function", "return", "exit", "in", "select",
        "until", "export", "local", "readonly",
    },
}
_KEYWORDS["typescript"] = _KEYWORDS["javascript"] | {"interface", "type",
                                                     "enum", "implements"}
_KEYWORDS["js"] = _KEYWORDS["javascript"]
_KEYWORDS["ts"] = _KEYWORDS["typescript"]
_KEYWORDS["sh"] = _KEYWORDS["bash"]
_KEYWORDS["shell"] = _KEYWORDS["bash"]

_LINE_COMMENT = {
    "python": "#", "javascript": "//", "typescript": "//", "js": "//",
    "ts": "//", "bash": "#", "sh": "#", "shell": "#", "yaml": "#",
    "yml": "#", "go": "//", "rust": "//", "java": "//",
}

_STRING_RE = re.compile(
    r"('''.*?'''|\"\"\".*?\"\"\"|'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")",
    re.DOTALL)
_NUMBER_RE = re.compile(r"\b(\d[\d_]*(?:\.\d+)?)\b")


def highlight_code(code: str, lang: str = "") -> str:
    """Highlight a code block. Returns plain code when color is off."""
    if not _color_enabled() or not code:
        return code
    lang = (lang or "").lower()
    keywords = _KEYWORDS.get(lang, set())
    comment_mark = _LINE_COMMENT.get(lang)

    def highlight_segment(seg: str) -> str:
        # comments first (to end of line), then strings/keywords/numbers
        out_lines = []
        for line in seg.split("\n"):
            if comment_mark:
                idx = line.find(comment_mark)
                # avoid treating # inside strings precisely is overkill;
                # strings are handled after, so do comments on the raw line
                # only when the mark is not inside quotes (best effort)
                if idx != -1 and _not_in_string(line, idx):
                    line = (highlight_segment_inner(line[:idx])
                            + dim(line[idx:]))
                    out_lines.append(line)
                    continue
            out_lines.append(highlight_segment_inner(line))
        return "\n".join(out_lines)

    def highlight_segment_inner(seg: str) -> str:
        # strings -> yellow, then keywords -> cyan, numbers -> magenta
        parts: list[str] = []
        pos = 0
        for m in _STRING_RE.finditer(seg):
            parts.append(_highlight_words(seg[pos:m.start()], keywords))
            parts.append(yellow(m.group(0)))
            pos = m.end()
        parts.append(_highlight_words(seg[pos:], keywords))
        return "".join(parts)

    return highlight_segment(code)


def _not_in_string(line: str, idx: int) -> bool:
    in_s = in_d = False
    i = 0
    while i < idx:
        ch = line[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        i += 1
    return not (in_s or in_d)


def _highlight_words(seg: str, keywords: set[str]) -> str:
    if not keywords and not _color_enabled():
        return seg
    seg = _NUMBER_RE.sub(lambda m: f"{_c('35')}{m.group(1)}{reset()}", seg)
    if keywords:
        kw_re = re.compile(r"\b(" + "|".join(sorted(keywords)) + r")\b")
        seg = kw_re.sub(lambda m: f"{cyan(m.group(1))}", seg)
    return seg


# -- inline markdown ------------------------------------------------------
_INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")


def render_inline(text: str) -> str:
    """Render one line of markdown-ish text for the terminal."""
    if not _color_enabled():
        return text
    m = _HEADING_RE.match(text)
    if m:
        return bold(m.group(2))
    text = _INLINE_CODE_RE.sub(lambda m: yellow(m.group(1)), text)
    text = _BOLD_RE.sub(lambda m: bold(m.group(1)), text)
    return text


# -- streaming renderer ---------------------------------------------------
class StreamingRenderer:
    """Feeds streamed model text to the terminal with code highlighting.

    Buffers fenced code blocks until the closing fence, then emits them
    highlighted. Plain lines stream through immediately (inline-rendered).
    """

    def __init__(self, write=None):
        self._write = write or (lambda s: (sys.stdout.write(s),
                                           sys.stdout.flush()))
        self._partial = ""
        self._in_fence = False
        self._fence_lang = ""
        self._fence_lines: list[str] = []

    def feed(self, chunk: str) -> None:
        text = self._partial + (chunk or "")
        lines = text.split("\n")
        self._partial = lines.pop()
        for line in lines:
            self._emit_line(line)

    def _emit_line(self, line: str) -> None:
        if line.startswith("```"):
            if not self._in_fence:
                self._in_fence = True
                tag = line[3:].strip()
                self._fence_lang = tag.split()[0] if tag else ""
                self._fence_lines = []
            else:
                self._in_fence = False
                code = "\n".join(self._fence_lines)
                self._write(highlight_code(code, self._fence_lang) + "\n")
                self._fence_lines = []
            return
        if self._in_fence:
            self._fence_lines.append(line)
        else:
            self._write(render_inline(line) + "\n")

    def flush(self) -> None:
        if self._in_fence:
            rest = ([self._partial] if self._partial else [])
            code = "\n".join(self._fence_lines + rest)
            self._write(highlight_code(code, self._fence_lang) + "\n")
            self._in_fence = False
            self._fence_lines = []
            self._partial = ""
        elif self._partial:
            self._write(render_inline(self._partial) + "\n")
            self._partial = ""


# -- layout helpers -------------------------------------------------------
def panel(title: str, lines: list[str]) -> str:
    """A simple box-drawing panel. Display-only."""
    width = max([len(title)] + [len(l) for l in lines] + [0])
    top = f"╭─ {title} " + "─" * max(0, width - len(title) - 1) + "╮"
    body = "\n".join(f"│ {l}{' ' * (width - len(l))} │" for l in lines)
    bottom = "╰" + "─" * (width + 2) + "╯"
    return f"{top}\n{body}\n{bottom}"


def status_line(text: str) -> str:
    return dim(text)
