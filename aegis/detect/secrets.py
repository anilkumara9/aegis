"""Secret detection and redaction.

Real secret-shaped patterns (API keys, tokens, private keys), applied at
EVERY return boundary: tool args before logging/display, tool outputs before
they reach the model or the audit log.

Adversarial handling:
- split tokens: "sk-" + "ant-xxx" broken across whitespace/newlines are
  caught by scanning a whitespace-collapsed view and mapping spans back;
- env-var indirection: $OPENAI_API_KEY / ${AWS_SECRET} are flagged as
  secret *references* (the value is not present, but the call is treated
  as secret-bearing for egress blocking);
- base64: blobs that decode to secret-shaped content are redacted whole.
"""

from __future__ import annotations

import base64
import math
import re
from dataclasses import dataclass

# Each entry: (kind, regex, group_to_redact or None for whole match).
# Named group "secret" marks the redactable span when only part matches.
SECRET_PATTERNS: list[tuple[str, str]] = [
    ("anthropic_key", r"sk-ant-[A-Za-z0-9\-_]{20,}"),
    ("openai_key", r"sk-(?!ant-)[A-Za-z0-9\-_]{20,}"),
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("github_token", r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"),
    ("github_pat", r"github_pat_[A-Za-z0-9_]{20,}"),
    ("gitlab_token", r"glpat-[A-Za-z0-9\-_]{20,}"),
    ("slack_token", r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    ("stripe_key", r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"),
    ("google_api_key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("private_key", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    ("jwt", r"eyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}"),
    ("bearer_token", r"(?i)bearer\s+(?P<secret>[A-Za-z0-9\-._~+/]{20,})"),
    ("url_credentials", r"://(?P<secret>[^/\s:@]+:[^/\s@]+)@"),
    ("key_assignment",
     r"(?i)(?:api[\s_-]?key|secret|password|passwd|pwd|auth[_-]?token|access[_-]?token)"
     r"\s*['\"]?\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9\-._~+/]{12,})['\"]?"),
    # "the api key is <value>" phrasing (natural-language disclosure).
    ("key_phrase",
     r"(?i)\bapi[\s_-]?key\b\s+(?:is\s+)?['\"]?(?P<secret>[A-Za-z0-9\-._~+/]{12,})['\"]?"),
]

_COMPILED = [(kind, re.compile(rx)) for kind, rx in SECRET_PATTERNS]

# $VAR / ${VAR} where VAR looks like it holds a secret.
SECRET_ENV_RE = re.compile(
    r"\$(?:{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))")
SECRET_NAME_RE = re.compile(
    r"(?i)(key|token|secret|password|passwd|credential|auth|private)")
B64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/]{48,}={0,2}")

REDACTED_FMT = "[REDACTED:{kind}]"


@dataclass
class SecretHit:
    kind: str
    value: str
    start: int
    end: int


def _spans_for(pattern: re.Pattern, kind: str, text: str) -> list[SecretHit]:
    hits = []
    for m in pattern.finditer(text):
        try:
            s, e = m.span("secret")
        except IndexError:
            s, e = m.span()
        if e > s:
            hits.append(SecretHit(kind, text[s:e], s, e))
    return hits


def find_secrets(text: str) -> list[SecretHit]:
    """Find secret-shaped spans in text, original coordinates."""
    if not text:
        return []
    hits: list[SecretHit] = []
    for kind, rx in _COMPILED:
        hits.extend(_spans_for(rx, kind, text))
    # Whitespace-collapsed view catches split tokens ("sk-\n ant-..."),
    # including JSON-escaped newlines ("sk-test-\\nFAKE") as seen in
    # serialized tool args.
    collapsed_chars: list[str] = []
    index_map: list[int] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in " \t\r\n":
            i += 1
            continue
        if ch == "\\" and i + 1 < n and text[i + 1] in "nrt":
            i += 2  # literal backslash-n/t/r escape: skip both chars
            continue
        collapsed_chars.append(ch)
        index_map.append(i)
        i += 1
    collapsed = "".join(collapsed_chars)
    if collapsed != text:
        for kind, rx in _COMPILED:
            for m in rx.finditer(collapsed):
                try:
                    s, e = m.span("secret")
                except IndexError:
                    s, e = m.span()
                if e > s:
                    os_, oe = index_map[s], index_map[e - 1] + 1
                    hits.append(SecretHit(kind, text[os_:oe], os_, oe))
    # Base64 blobs that decode to secrets.
    for m in B64_CANDIDATE_RE.finditer(text):
        blob = m.group()
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", "ignore")
        except Exception:
            continue
        if decoded and find_secrets(decoded):
            hits.append(SecretHit("base64_secret", blob, m.start(), m.end()))
    # Merge overlapping spans, keep the longest.
    hits.sort(key=lambda h: (h.start, -(h.end - h.start)))
    merged: list[SecretHit] = []
    for h in hits:
        if merged and h.start < merged[-1].end:
            if (h.end - h.start) > (merged[-1].end - merged[-1].start):
                merged[-1] = h
            continue
        merged.append(h)
    return merged


def find_secret_references(text: str) -> list[str]:
    """Env-var indirections that likely reference secrets ($FOO_KEY)."""
    refs = []
    for m in SECRET_ENV_RE.finditer(text or ""):
        name = m.group("braced") or m.group("plain")
        if SECRET_NAME_RE.search(name):
            refs.append(name)
    return refs


def redact(text: str) -> tuple[str, list[SecretHit]]:
    """Redact all secret-shaped spans. Returns (redacted, hits)."""
    hits = find_secrets(text)
    if not hits:
        return text, []
    out = text
    for h in sorted(hits, key=lambda x: x.start, reverse=True):
        out = out[:h.start] + REDACTED_FMT.format(kind=h.kind) + out[h.end:]
    return out, hits


def is_secret_bearing(text: str) -> bool:
    """True if text contains secrets OR references to secrets (env indirection)."""
    if not text:
        return False
    return bool(find_secrets(text)) or bool(find_secret_references(text))


def suspicious_token(text: str) -> bool:
    """High-entropy long token heuristic for secret-shaped payload blocking."""
    for tok in re.findall(r"[A-Za-z0-9\-_~+/=]{24,}", text or ""):
        if _entropy(tok) >= 4.0:
            return True
    return False


def _entropy(s: str) -> float:
    from collections import Counter
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# -- escape-encoded exfiltration -------------------------------------------
# Attackers hide secret-shaped payloads behind shell escapes (\ooo octal,
# \xhh hex, \uXXXX unicode) so naive scans miss them. Decoding before the
# secret scan closes that gap (EVL-176 class).

_ESCAPE_RUN_RE = re.compile(r"(?:\\[0-7]{3}|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){2,}")


def _decode_escape_run(run: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(run):
        if run.startswith("\\u", i) and i + 6 <= len(run):
            try:
                out.append(chr(int(run[i + 2:i + 6], 16)))
                i += 6
                continue
            except ValueError:
                pass
        if run.startswith("\\x", i) and i + 4 <= len(run):
            try:
                out.append(chr(int(run[i + 2:i + 4], 16)))
                i += 4
                continue
            except ValueError:
                pass
        m = re.match(r"\\([0-7]{3})", run[i:])
        if m:
            try:
                out.append(chr(int(m.group(1), 8)))
                i += 4
                continue
            except ValueError:
                pass
        out.append(run[i])
        i += 1
    return "".join(out)


def decode_escapes(text: str) -> str:
    """Decode runs of octal/hex/unicode escapes; passthrough otherwise."""
    if not text or "\\" not in text:
        return text
    return _ESCAPE_RUN_RE.sub(lambda m: _decode_escape_run(m.group(0)), text)


def find_encoded_secrets(text: str) -> list[SecretHit]:
    """Secrets visible only after escape-decoding. Coordinates are in the
    decoded space — use for blocking decisions, not for redaction spans."""
    if not text or "\\" not in text:
        return []
    decoded = decode_escapes(text)
    if decoded == text:
        return []
    return [SecretHit(f"encoded_{h.kind}", h.value, h.start, h.end)
            for h in find_secrets(decoded)]


def redact_encoded(text: str) -> str:
    """Redact escape-runs that decode to secret-bearing content, using the
    ORIGINAL coordinates so redaction spans stay valid."""

    def _repl(m: re.Match) -> str:
        run = m.group(0)
        if is_secret_bearing(_decode_escape_run(run)):
            return "[REDACTED:encoded_secret]"
        return run

    return _ESCAPE_RUN_RE.sub(_repl, text or "")
