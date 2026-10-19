"""Polished terminal UI: syntax highlighting, streaming markdown renderer.

Dumb-terminal friendly: plain ANSI colors only, no cursor movement, no
curses. Colors are disabled when NO_COLOR is set or stdout is not a tty.
Everything here is display-only — it never changes what the agent does.
"""

from __future__ import annotations

import os
import re
import sys
import threading

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
_KEYWORDS["go"] = {
    "func", "return", "if", "else", "for", "range", "switch", "case",
    "default", "break", "continue", "go", "defer", "chan", "map",
    "struct", "interface", "type", "var", "const", "package", "import",
    "select", "fallthrough", "goto", "nil", "true", "false", "iota",
    "new", "make", "len", "cap", "append", "panic", "recover",
}
_KEYWORDS["rust"] = {
    "fn", "return", "let", "mut", "const", "static", "if", "else",
    "match", "for", "in", "while", "loop", "break", "continue",
    "struct", "enum", "impl", "trait", "type", "where", "use",
    "pub", "mod", "crate", "self", "Self", "super", "as", "ref",
    "move", "dyn", "async", "await", "try", "unsafe", "extern",
    "true", "false", "None", "Some", "Ok", "Err",
}
_KEYWORDS["java"] = {
    "class", "interface", "enum", "extends", "implements", "public",
    "private", "protected", "static", "final", "void", "int", "long",
    "double", "float", "boolean", "char", "byte", "short", "new",
    "return", "if", "else", "for", "while", "do", "switch", "case",
    "default", "break", "continue", "try", "catch", "finally",
    "throw", "throws", "import", "package", "this", "super", "null",
    "true", "false", "instanceof", "synchronized", "volatile",
    "abstract", "native", "transient", "assert", "var", "record",
    "sealed", "permits",
}
_KEYWORDS["c"] = {
    "int", "char", "float", "double", "void", "long", "short",
    "unsigned", "signed", "struct", "union", "enum", "typedef",
    "static", "const", "extern", "volatile", "register", "return",
    "if", "else", "for", "while", "do", "switch", "case", "default",
    "break", "continue", "goto", "sizeof", "NULL", "true", "false",
    "inline", "_Bool",
}
_KEYWORDS["cpp"] = _KEYWORDS["c"] | {
    "class", "public", "private", "protected", "new", "delete",
    "namespace", "using", "template", "typename", "virtual",
    "override", "final", "try", "catch", "throw", "this", "bool",
    "nullptr", "constexpr", "auto", "decltype", "operator",
    "friend", "mutable", "explicit", "noexcept", "concept",
    "requires", "co_await", "co_return", "co_yield",
}
_KEYWORDS["c++"] = _KEYWORDS["cpp"]
_KEYWORDS["golang"] = _KEYWORDS["go"]
_KEYWORDS["rs"] = _KEYWORDS["rust"]

_LINE_COMMENT = {
    "python": "#", "javascript": "//", "typescript": "//", "js": "//",
    "ts": "//", "bash": "#", "sh": "#", "shell": "#", "yaml": "#",
    "yml": "#", "go": "//", "rust": "//", "java": "//", "c": "//",
    "cpp": "//", "c++": "//",
}

# Languages with C-style /* ... */ block comments.
_BLOCK_COMMENT_LANGS = {
    "javascript", "js", "typescript", "ts", "go", "rust", "java",
    "c", "cpp", "c++",
}
_BLOCK_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

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
        # block comments first (may span lines), then per-line handling
        if lang in _BLOCK_COMMENT_LANGS and "/*" in seg:
            parts: list[str] = []
            pos = 0
            for m in _BLOCK_RE.finditer(seg):
                parts.append(_highlight_lines(seg[pos:m.start()],
                                              comment_mark, keywords))
                parts.append(dim(m.group(0)))
                pos = m.end()
            parts.append(_highlight_lines(seg[pos:], comment_mark, keywords))
            return "".join(parts)
        return _highlight_lines(seg, comment_mark, keywords)

    def _highlight_lines(seg: str, comment_mark: str | None,
                         keywords: set[str]) -> str:
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
_LIST_RE = re.compile(r"^(\s*)(?:[-*+]|\d+[.)])\s+(.*)$")
_QUOTE_RE = re.compile(r"^\s*>\s?(.*)$")
_HR_RE = re.compile(r"^\s*(?:---+\s*|\*\*\*+\s*|___+\s*)$")
_TABLE_SEP_RE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$")


def _render_inline_spans(text: str) -> str:
    text = _INLINE_CODE_RE.sub(lambda m: yellow(m.group(1)), text)
    text = _BOLD_RE.sub(lambda m: bold(m.group(1)), text)
    return text


def render_inline(text: str) -> str:
    """Render one line of markdown-ish text for the terminal."""
    if not _color_enabled():
        return text
    m = _HEADING_RE.match(text)
    if m:
        return bold(_render_inline_spans(m.group(2)))
    if _HR_RE.match(text):
        return dim("─" * 32)
    if _TABLE_SEP_RE.match(text):
        return dim(text)
    m = _QUOTE_RE.match(text)
    if m:
        return dim("▏ ") + _render_inline_spans(m.group(1))
    m = _LIST_RE.match(text)
    if m:
        return f"{m.group(1)}{dim('• ')}" + _render_inline_spans(m.group(2))
    return _render_inline_spans(text)


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


# -- secret-safe rendering ------------------------------------------------
def _redact(text: str) -> str:
    """Redact secret-shaped values before they reach the screen.

    Display paths must never echo secrets from tool output, args, or
    diffs. Never raises — worst case returns the text unchanged.
    """
    try:
        from .detect.secrets import redact
        redacted, _ = redact(text or "")
        return redacted
    except Exception:
        return text or ""


def spinner_wanted() -> bool:
    """True when a live spinner is appropriate (color + real TTY)."""
    return _color_enabled() and sys.stdout.isatty()


# -- tool execution cards -------------------------------------------------
class ToolCard:
    """One tool execution rendered as a card.

    Lifecycle: ``start()`` prints the header (tool name + redacted args)
    and begins a live spinner on TTYs; ``finish()`` stops the spinner and
    prints the verdict line (✓/✗ + elapsed ms) plus collapsible output.
    All displayed text passes through the secret redaction layer.

    The spinner is driven by ``tick()`` — a daemon thread calls it while
    the tool runs, or a caller can drive it manually (deterministic for
    tests/demos). Use as a context manager for exception safety.
    """

    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, name: str, args_summary: str = "", *,
                 write=None, spinner: bool = True,
                 max_output_lines: int = 12):
        self.name = name
        self.args_summary = args_summary
        self._write = write or (lambda s: (sys.stdout.write(s),
                                           sys.stdout.flush()))
        self._spinner_on = bool(spinner) and spinner_wanted()
        self._max_lines = max(1, int(max_output_lines))
        self._frame = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._finished = False
        self._started = False
        self._live_line = False  # cursor sits on an unterminated spinner line

    # -- plumbing ---------------------------------------------------------
    def _emit(self, s: str) -> None:
        with self._lock:
            try:
                self._write(s)
            except Exception:
                pass

    def _header(self) -> str:
        args = _redact(self.args_summary)
        return f"{cyan('⏺')} {bold(self.name)}{dim('(' + args + ')')}"

    def _spin_loop(self) -> None:
        while not self._stop.wait(0.08):
            self.tick()

    def _begin_spinner(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin_loop,
                                        daemon=True,
                                        name=f"toolcard-{self.name}")
        self._thread.start()

    def _halt_spinner(self) -> None:
        self._stop.set()
        t, self._thread = self._thread, None
        if t is not None and t is not threading.current_thread():
            t.join(timeout=1.0)

    # -- lifecycle --------------------------------------------------------
    def start(self) -> "ToolCard":
        self._emit("\n" + self._header())
        if self._spinner_on:
            self._emit(" " + dim(self.FRAMES[0]))
            self._live_line = True
            self._begin_spinner()
        else:
            self._emit("\n")
        self._started = True
        return self

    def _clear_live_line(self) -> None:
        if self._live_line:
            self._emit("\r\x1b[K")
            self._live_line = False

    def tick(self) -> None:
        """Advance one spinner frame (called by the spinner thread)."""
        if self._finished or not self._started or not _color_enabled():
            return
        self._frame = (self._frame + 1) % len(self.FRAMES)
        self._live_line = True
        self._emit("\r" + self._header() + dim(" … ")
                   + dim(self.FRAMES[self._frame]))

    def pause_for_approval(self, note: str = "awaiting approval") -> None:
        """Freeze the spinner while a permission prompt is on screen."""
        if self._finished:
            return
        self._halt_spinner()
        self._clear_live_line()
        self._emit(yellow("⏸") + f" {bold(self.name)}"
                   + dim(f" — {note}") + "\n")

    def resume(self) -> None:
        """Restart the spinner after an approval prompt."""
        if self._finished or not self._spinner_on:
            return
        self._emit(self._header() + " " + dim(self.FRAMES[self._frame]))
        self._live_line = True
        self._begin_spinner()

    def abort(self) -> None:
        """Stop without a verdict (interrupted / exceptional path)."""
        if self._finished:
            return
        self._finished = True
        self._halt_spinner()
        self._clear_live_line()
        self._emit(dim(f"  ⎿ {self.name} aborted") + "\n")

    def finish(self, verdict: str, duration_ms: float, output: str = "",
               *, expanded: bool = False) -> "ToolCard":
        """Print the verdict line and collapsible redacted output."""
        self._finished = True
        self._halt_spinner()
        self._clear_live_line()
        ms = f"{duration_ms:.0f}"
        ok = verdict in ("allow", "approved")
        if ok:
            verdict_str = green(f"✓ {verdict}") + dim(f" · {ms}ms")
        else:
            verdict_str = red(f"✗ {verdict}") + dim(f" · {ms}ms")
        self._emit(f"  ⎿ {verdict_str}\n")
        body = _redact(output or "")
        lines = body.splitlines()
        if not any(ln.strip() for ln in lines):
            return self
        if expanded or len(lines) <= self._max_lines:
            shown, hidden = lines, 0
        else:
            shown, hidden = lines[:self._max_lines], len(lines) - self._max_lines
        paint = (lambda s: dim(s)) if ok else red
        for ln in shown:
            self._emit(paint(f"  │ {ln}") + "\n")
        if hidden:
            self._emit(dim(f"  … +{hidden} more lines") + "\n")
        return self

    def __enter__(self) -> "ToolCard":
        return self.start()

    def __exit__(self, *exc) -> None:
        if not self._finished:
            self.abort()


# -- unified diff rendering -----------------------------------------------
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")


def render_diff(diff_text: str) -> str:
    """Render a unified diff with line numbers and red/green coloring.

    Keeps the ``+``/``-`` markers so it stays readable on dumb
    terminals; adds old/new line numbers per hunk. Secret-safe: the
    input is redacted before rendering. Non-diff text passes through.
    """
    text = _redact(diff_text or "")
    if "@@" not in text and not text.startswith("---"):
        return text
    out: list[str] = []
    old_no = new_no = 0
    for raw in text.splitlines():
        m = _HUNK_RE.match(raw)
        if m:
            old_no, new_no = int(m.group(1)), int(m.group(3))
            out.append(cyan(raw))
            continue
        if raw.startswith("+++") or raw.startswith("---"):
            out.append(dim(raw))
            continue
        if raw.startswith("+"):
            out.append(green(f"{'':>5} {new_no:>5} │ {raw}"))
            new_no += 1
        elif raw.startswith("-"):
            out.append(red(f"{old_no:>5} {'':>5} │ {raw}"))
            old_no += 1
        elif raw.startswith("\\"):
            out.append(dim(raw))  # "\ No newline at end of file"
        else:
            body = raw[1:] if raw.startswith(" ") else raw
            out.append(f"{dim(f'{old_no:>5} {new_no:>5} │')} {body}")
            old_no += 1
            new_no += 1
    return "\n".join(out)


# -- status bar: model / session / tokens / cost --------------------------
# $ per 1M tokens (input, output). Approximate public list prices — the
# bar always shows cost with "~" and unknown models honestly show "n/a".
MODEL_PRICES: dict[str, tuple[float, float]] = {
    "claude-opus-4": (15.0, 75.0),
    "claude-sonnet-4": (3.0, 15.0),
    "claude-haiku": (0.8, 4.0),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.0),
    "gpt-4.1": (2.0, 8.0),
    "o1": (15.0, 60.0),
    "o3": (2.0, 8.0),
    "gemini-2.5-pro": (1.25, 10.0),
    "gemini-2.0-flash": (0.10, 0.40),
    "gemini-1.5": (1.25, 5.00),
}

# Providers that never bill: cost is honestly $0.00, not "unknown".
_FREE_PROVIDERS = {"mock", "ollama", "local"}


def price_for_model(model: str) -> tuple[float, float] | None:
    """Longest-prefix price lookup; None when the model is unknown."""
    m = (model or "").lower()
    best: tuple[str, tuple[float, float]] | None = None
    for key, price in MODEL_PRICES.items():
        if key in m and (best is None or len(key) > len(best[0])):
            best = (key, price)
    return best[1] if best else None


class SessionStatus:
    """Live session counters for the status bar.

    Token totals are synced from the provider usage tracker (cumulative);
    sync() takes max() so re-syncs never double-count. Cost is an honest
    estimate: "~" prefix when tokens are estimated, "n/a" when the model
    has no known price, "$0.00" for free/local providers.
    """

    def __init__(self, model: str = "", session_id: str = "",
                 provider_name: str = ""):
        self.model = model or "?"
        self.session_id = session_id or ""
        self.provider_name = (provider_name or "").lower()
        self.input_tokens = 0
        self.output_tokens = 0
        self.estimated = False
        self.iterations = 0

    def sync(self, input_tokens: int, output_tokens: int,
             estimated: bool = False) -> None:
        self.input_tokens = max(self.input_tokens, int(input_tokens or 0))
        self.output_tokens = max(self.output_tokens, int(output_tokens or 0))
        self.estimated = self.estimated or bool(estimated)

    def bump_iteration(self) -> None:
        self.iterations += 1

    @staticmethod
    def _fmt(n: int) -> str:
        return f"{n / 1000:.1f}k" if n >= 1000 else str(n)

    def cost_str(self) -> str:
        if self.provider_name in _FREE_PROVIDERS:
            return "$0.00"
        price = price_for_model(self.model)
        if price is None:
            return "n/a"
        per_in, per_out = price
        cost = (self.input_tokens * per_in
                + self.output_tokens * per_out) / 1_000_000
        return f"~${cost:,.2f}"

    def render(self) -> str:
        tok = (f"{self._fmt(self.input_tokens)} in · "
               f"{self._fmt(self.output_tokens)} out")
        if self.estimated:
            tok = "~" + tok + " (est)"
        sid = self.session_id[:8] if self.session_id else "session"
        parts = [f"⏷ {self.model}", sid, tok, self.cost_str(),
                 f"iter {self.iterations}"]
        return dim(" · ".join(parts))


# -- task progress (plan-then-execute) ------------------------------------
PLAN_EVENT_CONTRACT = """
Plan-progress event contract (emitted by the reasoning lane, rendered here).

Each event is a plain dict:

  {"type": "plan", "title": str, "total": int}
      A plan was approved: <total> steps are about to run.

  {"type": "step", "index": int, "total": int, "label": str,
   "state": "start" | "ok" | "fail" | "denied" | "skipped",
   "detail": str = ""}
      index is 1-based. "detail" carries the failure/denial reason.

Renderers must tolerate missing keys and out-of-order events: render
defensively, never crash. Unknown states render as a neutral bullet.
"""


class TaskProgress:
    """Stateful renderer for plan-then-execute progress events.

    Consumes the PLAN_EVENT_CONTRACT dicts and prints a progress bar plus
    a per-step checklist. Line-based: no cursor movement, safe on dumb
    terminals and in captured logs.
    """

    BAR_WIDTH = 20

    def __init__(self, write=None):
        self._write = write or (lambda s: (sys.stdout.write(s),
                                           sys.stdout.flush()))
        self._total = 0
        self._done = 0
        self._title = ""

    def _emit(self, s: str) -> None:
        try:
            self._write(s)
        except Exception:
            pass

    def _bar(self, done: int, total: int) -> str:
        filled = int(self.BAR_WIDTH * done / total) if total else 0
        filled = max(0, min(self.BAR_WIDTH, filled))
        return "█" * filled + "░" * (self.BAR_WIDTH - filled)

    def handle(self, event: dict) -> None:
        if not isinstance(event, dict):
            return
        etype = str(event.get("type", "") or "")
        if etype == "plan":
            self._handle_plan(event)
        elif etype == "step":
            self._handle_step(event)

    def _handle_plan(self, event: dict) -> None:
        try:
            self._total = max(0, int(event.get("total", 0) or 0))
        except (TypeError, ValueError):
            self._total = 0
        self._done = 0
        self._title = str(event.get("title", "") or "plan")
        self._emit("\n" + bold("▸ " + self._title)
                   + dim(f" — {self._total} steps") + "\n")

    def _handle_step(self, event: dict) -> None:
        try:
            index = int(event.get("index", 0) or 0)
        except (TypeError, ValueError):
            index = 0
        try:
            total = int(event.get("total", 0) or 0) or self._total
        except (TypeError, ValueError):
            total = self._total
        label = str(event.get("label", "") or "")
        state = str(event.get("state", "") or "start")
        detail = str(event.get("detail", "") or "")
        if state == "start":
            bar = self._bar(max(0, index - 1), total)
            self._emit(f"  {dim('[' + bar + ']')} {dim(f'{index}/{total}')} "
                       f"{label} …\n")
        elif state == "ok":
            self._done = max(self._done, index)
            bar = self._bar(self._done, total)
            self._emit(f"  {green('✓')} {dim('[' + bar + ']')} {label}\n")
        elif state == "fail":
            suffix = dim(f" — {detail}") if detail else ""
            self._emit(f"  {red('✗')} {label}{suffix}\n")
        elif state == "denied":
            suffix = dim(f" — denied{': ' + detail if detail else ''}")
            self._emit(f"  {yellow('⊘')} {label}{suffix}\n")
        elif state == "skipped":
            self._emit(f"  {dim('○ ' + label + ' — skipped')}\n")
        else:
            self._emit(f"  {dim('•')} {label}\n")


# -- fuzzy filtering (slash palette) --------------------------------------
def fuzzy_score(query: str, text: str) -> int | None:
    """Subsequence match score (lower = tighter). None when no match."""
    q = query.strip().lower()
    if not q:
        return 0
    t = text.lower()
    score = 0
    pos = 0
    for ch in q:
        idx = t.find(ch, pos)
        if idx == -1:
            return None
        score += idx - pos
        pos = idx + 1
    if t.startswith(q):
        score -= len(q)  # prefix matches rank first
    return score


def fuzzy_filter(query: str, items: list, key=None) -> list:
    """Order items by fuzzy match quality; drop non-matches."""
    key = key or (lambda x: x)
    scored = []
    for item in items:
        s = fuzzy_score(query, str(key(item)))
        if s is not None:
            scored.append((s, item))
    scored.sort(key=lambda p: p[0])
    return [item for _, item in scored]
