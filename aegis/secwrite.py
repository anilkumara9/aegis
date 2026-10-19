"""Secure-by-construction: per-language vulnerability screening.

Screens source code the AGENT writes/edits (guard hook) and the user's own
code (`aegis review`) against per-language vulnerability patterns — SQL
injection, XSS/template injection, OS command injection, SSRF, insecure
deserialization, hardcoded secrets, path traversal, weak crypto.

Every pattern cites a KB technique id (same defensive-detection level as
MITRE ATT&CK / the existing AUDIT_PATTERNS in skills.py). Patterns are
compiled once at import; sources are screened line-by-line with a size
cap, so the guard hook stays fast.

Security: evidence snippets are secret-redacted at creation (never carry
raw secret material into guard verdicts, audit logs, or review output).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from .detect import secrets as sec
from .detect.engine import Finding

# (rule, language, regex, kb_id, severity, fix)
# Severity: "high" -> the guard BLOCKS the write; "medium" -> the guard
# escalates for human approval (warning + technique id). Fix strings are
# concrete safe patterns shown in `aegis review`.
SECWRITE_PATTERNS: list[tuple[str, str, str, str, str, str]] = [
    # -- Python -----------------------------------------------------------
    ("py_sqli_fstring", "python",
     r"f[\"'].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*\{\s*\w",
     "AEG-T139", "high",
     'Use parameterized queries: cursor.execute("SELECT ... WHERE id = %s", (user_id,)) — '
     "never interpolate values into SQL."),
    ("py_sqli_percent", "python",
     r"\b(execute|executemany)\b[^#\n]*[\w\"')]\s*%\s*(user|input|request|args?|params?|name|id|query|form|data)\w*",
     "AEG-T139", "high",
     'Use parameterized queries: cursor.execute("SELECT ... WHERE id = %s", (user_id,)) — '
     "never %-format values into SQL."),
    ("py_xss_template_string", "python",
     r"render_template_string\s*\(\s*(f[\"']|.*\.format\()",
     "AEG-T140", "high",
     "Use render_template() with context variables — Jinja auto-escapes by default. "
     "Never render_template_string() on user-influenced input."),
    ("py_cmd_fstring", "python",
     r"(os\.system|subprocess\.(run|call|Popen|check_output))\s*\(\s*f[\"'][^\"']*\{\s*\w",
     "AEG-T148", "high",
     "Pass argv as a list (subprocess.run([...], shell=False)) — never build shell "
     "command strings from variables."),
    ("py_shell_true", "python",
     r"(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True",
     "AEG-T148", "medium",
     "Drop shell=True and pass argv as a list; if a shell is truly required, "
     "quote every variable with shlex.quote()."),
    ("py_ssrf_unvalidated", "python",
     r"(requests\.(get|post|put|delete)|urllib\.request\.urlopen)\s*\(\s*(f[\"']|url|user|target|input|request\.|params)",
     "AEG-T141", "medium",
     "Validate the URL against an allowlist of schemes/hosts before fetching — "
     "never fetch a raw user-supplied URL."),
    ("py_pickle_loads", "python",
     r"pickle\.loads?\s*\(",
     "AEG-T142", "high",
     "Never unpickle untrusted data — pickle.loads() can execute arbitrary code. "
     "Use json or another schema-validated format."),
    ("py_yaml_unsafe_load", "python",
     r"yaml\.load\s*\(",
     "AEG-T142", "medium",
     "Use yaml.safe_load() instead of yaml.load()."),
    ("py_hardcoded_secret", "python",
     r"(?i)^\s*(api[_-]?key|secret|password|passwd|token|client[_-]?secret)\s*[:=]\s*[\"'][^\"']{8,}[\"']",
     "AEG-T031", "medium",
     "Load secrets from the environment (os.environ[...]) or a secret manager — "
     "never hardcode credentials in source."),
    ("py_path_traversal_join", "python",
     r"os\.path\.join\s*\([^)]*\b(user|request|input|argv|params|filename)\w*\b",
     "AEG-T147", "medium",
     "Canonicalize with os.path.realpath() and verify the result stays under the "
     "intended base directory before opening."),
    ("py_path_traversal_open", "python",
     r"\bopen\s*\(\s*f[\"'][^\"']*\{\s*\w",
     "AEG-T147", "medium",
     "Canonicalize the path with os.path.realpath() and confine it to the intended "
     "base directory — never open() a path built from raw input."),
    ("py_weak_crypto", "python",
     r"hashlib\.(md5|sha1)\s*\(",
     "AEG-T193", "medium",
     "Use hashlib.sha256() or stronger (bcrypt/argon2/scrypt for passwords) — "
     "MD5 and SHA-1 are broken."),
    # -- JavaScript / TypeScript -------------------------------------------
    ("js_sqli_template", "javascript",
     r"(query|execute)\s*\(\s*`[^`]*\$\{",
     "AEG-T139", "high",
     "Use parameterized queries ($1 / ? placeholders with a values array) — "
     "never interpolate into SQL template literals."),
    ("js_xss_sink", "javascript",
     r"(\.innerHTML\s*=|document\.write\s*\()",
     "AEG-T140", "medium",
     "Use textContent / createElement instead of innerHTML; escape untrusted "
     "data on output."),
    ("js_cmd_exec_template", "javascript",
     r"(child_process\.)?(exec|execSync|spawnSync)\s*\(\s*`[^`]*\$\{",
     "AEG-T148", "high",
     "Use spawn()/execFile() with an argv array — never build shell command "
     "strings from variables."),
    ("js_eval", "javascript",
     r"\beval\s*\(",
     "AEG-T148", "high",
     "Do not use eval() on dynamic input — it executes arbitrary code. "
     "Use JSON.parse() or a real parser."),
    ("js_new_function", "javascript",
     r"\bnew\s+Function\s*\(",
     "AEG-T148", "high",
     "new Function() compiles arbitrary code like eval() — refactor to a "
     "static function or a lookup table."),
    ("js_ssrf_unvalidated", "javascript",
     r"(fetch|axios\.(get|post|put|delete)|got\.(get|post))\s*\(\s*(url|user|target|input|req\.|params)",
     "AEG-T141", "medium",
     "Validate the URL against an allowlist of schemes/hosts before fetching — "
     "never fetch a raw user-supplied URL."),
    ("js_hardcoded_secret", "javascript",
     r"(?i)^\s*(const|let|var)\s+(api[_-]?key|secret|password|token|client[_-]?secret)\s*=\s*[\"'][^\"']{8,}[\"']",
     "AEG-T031", "medium",
     "Load secrets from process.env / a secret manager — never hardcode "
     "credentials in source."),
    ("js_path_traversal", "javascript",
     r"path\.join\s*\([^)]*\b(req\.|user|input|params|query)\w*\b",
     "AEG-T147", "medium",
     "Resolve with path.resolve() and verify the result stays under the intended "
     "base directory before reading."),
    ("js_weak_crypto", "javascript",
     r"createHash\s*\(\s*[\"'](md5|sha1)[\"']",
     "AEG-T193", "medium",
     "Use createHash('sha256') or stronger (bcrypt/scrypt/argon2 for passwords) — "
     "MD5 and SHA-1 are broken."),
    # -- Go ----------------------------------------------------------------
    ("go_sqli_sprintf", "go",
     r"\.(Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf",
     "AEG-T139", "high",
     "Use $1 / ? placeholders with args (db.Query(\"... WHERE id = $1\", id)) — "
     "never fmt.Sprintf values into SQL."),
    ("go_sqli_concat", "go",
     r"\.(Query|Exec|QueryRow)\s*\(\s*\"[^\"]*\"\s*\+",
     "AEG-T139", "high",
     "Use $1 / ? placeholders with args — never concatenate values into SQL."),
    ("go_xss_template_html", "go",
     r"template\.HTML\s*\(",
     "AEG-T140", "medium",
     "Avoid template.HTML on dynamic content — it disables escaping. "
     "Let html/template escape values by default."),
    ("go_cmd_shell", "go",
     r"exec\.Command\s*\(\s*\"(sh|bash|cmd)\"",
     "AEG-T148", "high",
     "Call the binary directly (exec.Command(\"tool\", args...)) — never route "
     "variables through sh -c."),
    ("go_cmd_sprintf", "go",
     r"exec\.Command\s*\([^)]*fmt\.Sprintf",
     "AEG-T148", "high",
     "Pass argv as separate arguments to exec.Command — never Sprintf a command "
     "string from variables."),
    ("go_ssrf_unvalidated", "go",
     r"http\.(Get|Post)\s*\(\s*(url|user|target|input|r\.|req\.)",
     "AEG-T141", "medium",
     "Parse and validate the URL (allowed schemes/hosts) before the request — "
     "never request a raw user-supplied URL."),
    ("go_gob_untrusted", "go",
     r"gob\.NewDecoder\s*\(",
     "AEG-T142", "medium",
     "Only gob-decode trusted streams; for untrusted input use a "
     "schema-validated format (JSON with strict decoding)."),
    ("go_hardcoded_secret", "go",
     r"(?i)^\s*(apiKey|api[_-]?key|secret|password|token)\s*(:=|=)\s*\"[^\"]{8,}\"",
     "AEG-T031", "medium",
     "Load secrets from os.Getenv() / a secret manager — never hardcode "
     "credentials in source."),
    ("go_path_traversal", "go",
     r"filepath\.Join\s*\([^)]*\b(r\.|req\.|user|input|param)\w*\b",
     "AEG-T147", "medium",
     "Clean with filepath.Clean() and verify the result stays under the intended "
     "base directory before opening."),
    ("go_weak_crypto", "go",
     r"\b(md5\.New|md5\.Sum|sha1\.New|sha1\.Sum)\s*\(",
     "AEG-T193", "medium",
     "Use crypto/sha256 or stronger (bcrypt via x/crypto for passwords) — "
     "MD5 and SHA-1 are broken."),
    # -- Rust ---------------------------------------------------------------
    ("rs_sqli_format", "rust",
     r"format!\s*\([^)]*\b(SELECT|INSERT|UPDATE|DELETE)\b",
     "AEG-T139", "high",
     "Use sqlx query!()/query() with .bind() parameters — never format! values "
     "into SQL."),
    ("rs_xss_format_html", "rust",
     r"format!\s*\(\s*\"<[^\"]*",
     "AEG-T140", "medium",
     "Do not build HTML with format!() on dynamic data — use a templating "
     "engine with escaping, or escape with an HTML-escaping helper."),
    ("rs_cmd_shell", "rust",
     r"Command::new\s*\(\s*\"(sh|bash|cmd)\"",
     "AEG-T148", "high",
     "Call the binary directly (Command::new(\"tool\").args([...])) — never route "
     "variables through sh -c."),
    ("rs_ssrf_unvalidated", "rust",
     r"reqwest::(get|post)\s*\(\s*(url|user|target|input)",
     "AEG-T141", "medium",
     "Parse with reqwest::Url and validate scheme/host against an allowlist "
     "before sending — never request a raw user-supplied URL."),
    ("rs_deser_bincode", "rust",
     r"bincode::(deserialize|options\([^)]*\)\.deserialize)\s*\(",
     "AEG-T142", "medium",
     "Only deserialize trusted bytes with bincode; for untrusted input prefer "
     "serde_json with deny_unknown_fields or another validated format."),
    ("rs_hardcoded_secret", "rust",
     r"(?i)^\s*let\s+(api[_-]?key|secret|password|token)\w*\s*(:\s*[\w<>\[\]]+\s*)?=\s*\"[^\"]{8,}\"",
     "AEG-T031", "medium",
     "Load secrets from std::env::var() / a secret manager — never hardcode "
     "credentials in source."),
    ("rs_path_traversal", "rust",
     r"(fs::read|fs::write|File::open|File::create)\s*\(\s*(user|input|path|param)",
     "AEG-T147", "medium",
     "Canonicalize with fs::canonicalize() and verify the result stays under the "
     "intended base directory before touching the filesystem."),
    ("rs_weak_crypto", "rust",
     r"\b(md5::compute|Sha1::|sha1::|Md5::)",
     "AEG-T193", "medium",
     "Use sha2::Sha256 or stronger (argon2/bcrypt for passwords) — MD5 and "
     "SHA-1 are broken."),
    # -- Java ---------------------------------------------------------------
    ("java_sqli_concat", "java",
     r"(executeQuery|executeUpdate|execute)\s*\(\s*\"[^\"]*\"\s*\+",
     "AEG-T139", "high",
     "Use PreparedStatement with ? placeholders and setString()/setInt() — "
     "never concatenate values into SQL."),
    ("java_xss_unescaped", "java",
     r"\.(write|print|println)\s*\([^)]*request\.getParameter",
     "AEG-T140", "high",
     "Escape untrusted data on output (e.g. OWASP Encoder / StringEscapeUtils.escapeHtml4) "
     "or render through a template engine with auto-escaping."),
    ("java_cmd_exec", "java",
     r"Runtime\.getRuntime\(\)\.exec\s*\(",
     "AEG-T148", "medium",
     "Use ProcessBuilder with an explicit argv list — never pass a single "
     "command string built from variables."),
    ("java_cmd_concat", "java",
     r"new\s+ProcessBuilder\s*\([^)]*\+",
     "AEG-T148", "high",
     "Pass argv as separate ProcessBuilder arguments — never concatenate "
     "variables into a command."),
    ("java_ssrf_unvalidated", "java",
     r"new\s+URL\s*\(\s*(url|user|target|input|request\.getParameter)",
     "AEG-T141", "medium",
     "Validate the URL (allowed schemes/hosts) before opening the connection — "
     "never open a raw user-supplied URL."),
    ("java_deser_objectinput", "java",
     r"new\s+ObjectInputStream\s*\(",
     "AEG-T142", "high",
     "Never deserialize untrusted data with Java native serialization "
     "(readObject can execute gadget chains). Use JSON/schema-validated formats; "
     "if unavoidable, use an ObjectInputFilter."),
    ("java_hardcoded_secret", "java",
     r"(?i)^\s*(String|final\s+String)\s+(api[_-]?key|secret|password|token|passwd)\s*=\s*\"[^\"]{8,}\"",
     "AEG-T031", "medium",
     "Load secrets from environment variables / a secret manager — never "
     "hardcode credentials in source."),
    ("java_path_traversal", "java",
     r"new\s+File\s*\([^)]*\b(user|input|getParameter|param)\w*\b",
     "AEG-T147", "medium",
     "Canonicalize with getCanonicalPath() and verify it starts with the intended "
     "base directory before opening."),
    ("java_weak_crypto", "java",
     r"getInstance\s*\(\s*\"(MD5|SHA-1|SHA1)\"",
     "AEG-T193", "medium",
     "Use SHA-256 or stronger (bcrypt/PBKDF2/Argon2 for passwords) — MD5 and "
     "SHA-1 are broken."),
    # -- C++ ----------------------------------------------------------------
    ("cpp_sqli_concat", "cpp",
     r"\.(exec|query)\s*\(\s*\"[^\"]*\"\s*\+",
     "AEG-T139", "high",
     "Use prepared statements with bound parameters — never concatenate values "
     "into SQL."),
    ("cpp_sqli_sprintf", "cpp",
     r"sprintf\s*\([^)]*\b(SELECT|INSERT|UPDATE|DELETE)\b",
     "AEG-T139", "high",
     "Use prepared statements with bound parameters — never sprintf values "
     "into SQL (and prefer snprintf to avoid buffer overflows)."),
    ("cpp_xss_stream", "cpp",
     r"(cout|response|html|out)\s*<<[^;]*\b(user|input|request|param)\w*\b",
     "AEG-T140", "medium",
     "HTML-escape untrusted data before streaming it into a response — never "
     "stream raw user input."),
    ("cpp_cmd_system", "cpp",
     r"\b(system|popen)\s*\(\s*(?!\")",
     "AEG-T148", "medium",
     "Prefer fork()+execve() with an explicit argv, or a process library — "
     "never pass variable data to system()/popen()."),
    ("cpp_ssrf_unvalidated", "cpp",
     r"CURLOPT_URL\s*,\s*(url|user|target|input)",
     "AEG-T141", "medium",
     "Validate the URL (allowed schemes/hosts) before setting CURLOPT_URL — "
     "never request a raw user-supplied URL."),
    ("cpp_deser_cast", "cpp",
     r"reinterpret_cast\s*<[^>]*>\s*\(\s*(buf|buffer|data|packet|recv)",
     "AEG-T142", "medium",
     "Bounds-check and validate untrusted bytes before casting — prefer "
     "length-checked parsing over reinterpret_cast on network data."),
    ("cpp_hardcoded_secret", "cpp",
     r"(?i)^\s*(std::string|string|const\s+char\s*\*)\s+(api[_-]?key|secret|password|token)\w*\s*=\s*\"[^\"]{8,}\"",
     "AEG-T031", "medium",
     "Load secrets from the environment / a secret manager — never hardcode "
     "credentials in source."),
    ("cpp_path_traversal", "cpp",
     r"\b(ifstream|ofstream)\s+\w+\s*\([^)]*\+|\bfopen\s*\([^)]*\+",
     "AEG-T147", "medium",
     "Canonicalize the path (std::filesystem::canonical / weakly_canonical) and "
     "verify it stays under the intended base directory before opening."),
    ("cpp_weak_crypto", "cpp",
     r"\b(MD5|SHA1)\s*\(",
     "AEG-T193", "medium",
     "Use SHA-256 or stronger (bcrypt/Argon2 for passwords) — MD5 and SHA-1 "
     "are broken."),
]

# Language detection from file extension.
_EXT_LANG = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".c++": "cpp",
    ".h": "cpp", ".hpp": "cpp", ".hh": "cpp",
}

# Per-write screening caps: keep the guard hook fast.
SECWRITE_MAX_BYTES = 512_000
SECWRITE_MAX_FINDINGS = 300

_COMPILED: list[tuple[str, str, re.Pattern, str, str, str]] = [
    (rule, lang, re.compile(rx, re.IGNORECASE), kb_id, sev, fix)
    for rule, lang, rx, kb_id, sev, fix in SECWRITE_PATTERNS
]


def detect_language(path: str) -> str | None:
    """Language key for a file path, or None when not a screened language."""
    return _EXT_LANG.get(Path(path).suffix.lower())


def languages() -> list[str]:
    return sorted({lang for _, lang, *_ in SECWRITE_PATTERNS})


def rules_for(language: str) -> list[str]:
    return [rule for rule, lang, *_ in SECWRITE_PATTERNS if lang == language]


@dataclass
class SecFinding:
    rule: str
    language: str
    line_no: int
    severity: str            # "high" | "medium"
    technique_id: str
    technique_name: str
    category: str
    evidence: str            # secret-redacted line excerpt
    fix: str

    def to_dict(self) -> dict:
        return {
            "rule": self.rule, "language": self.language,
            "line_no": self.line_no, "severity": self.severity,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name, "category": self.category,
            "evidence": self.evidence, "fix": self.fix,
        }


def _kb_name(kb, tech_id: str) -> tuple[str, str]:
    t = kb.by_id.get(tech_id) if kb is not None else None
    if t is None:
        return tech_id, ""
    return t.name, t.category


def screen_source(text: str, language: str, kb=None,
                  source: str = "<write>") -> list[SecFinding]:
    """Screen one source string against the language's patterns.

    Returns SecFindings (evidence secret-redacted). Fast path: compiled
    regexes, line-by-line, size cap.
    """
    if not isinstance(text, str) or not text:
        return []
    if len(text) > SECWRITE_MAX_BYTES:
        text = text[:SECWRITE_MAX_BYTES]
    findings: list[SecFinding] = []
    for rule, lang, rx, kb_id, sev, fix in _COMPILED:
        if lang != language:
            continue
        name, category = _kb_name(kb, kb_id)
        for i, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                evidence, _ = sec.redact(line.strip()[:160])
                findings.append(SecFinding(
                    rule=rule, language=language, line_no=i, severity=sev,
                    technique_id=kb_id, technique_name=name, category=category,
                    evidence=evidence, fix=fix))
                if len(findings) >= SECWRITE_MAX_FINDINGS:
                    return findings
    return findings


def screen_tool_call(tool: str, args: dict, kb=None) -> list[SecFinding]:
    """Screen the content an agent write/edit call is about to land.

    Returns [] for non-write tools, unknown languages, or empty content.
    """
    if not isinstance(args, dict):
        return []
    tool_l = (tool or "").lower()
    if tool_l == "write":
        content = args.get("content", "")
    elif tool_l == "edit":
        content = args.get("new_text", "")
    else:
        return []
    lang = detect_language(str(args.get("path", "")))
    if lang is None:
        return []
    return screen_source(content, lang, kb=kb,
                         source=f"{tool_l}:{args.get('path', '')}")


def to_engine_findings(sec_findings: list[SecFinding],
                       source: str = "") -> list[Finding]:
    """Convert SecFindings to guard-engine Findings for the guard path."""
    out: list[Finding] = []
    for f in sec_findings:
        loc = f"{source}:{f.line_no}" if source else f"line {f.line_no}"
        out.append(Finding(
            technique_id=f.technique_id, technique_name=f.technique_name,
            category=f.category, severity=f.severity,
            rule=f"secwrite_{f.rule}",
            evidence=f"secure-by-construction: [{f.rule}] {loc}: {f.evidence}",
            mitigation=f.fix))
    return out


# -- `aegis review` -----------------------------------------------------------
# Local-only: reuses the remote-refusal logic from skills.py.

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv",
              "dist", "build", ".aegis", "target"}
_MAX_FILE_BYTES = 200_000
_MAX_REVIEW_FINDINGS = 300


def _resolve_review_target(target: str) -> tuple[Path | None, str]:
    """Local file or directory only. Returns (path, error)."""
    from .skills import _looks_remote
    target = (target or "").strip()
    if not target:
        return None, "usage: aegis review <local-file-or-directory>"
    if _looks_remote(target):
        return None, ("refused: review only works on your OWN local code. "
                       "Give me a local file or directory path.")
    p = Path(target).expanduser()
    if not p.exists():
        return None, (f"refused: '{target}' does not exist. review works on "
                       "your own local code only — pass a file or directory "
                       "that exists on this machine.")
    return p, ""


def _review_file(fp: Path, rel: str, kb) -> list[SecFinding]:
    try:
        if fp.stat().st_size > _MAX_FILE_BYTES:
            return []
        text = fp.read_text(encoding="utf-8", errors="strict")
    except Exception:
        return []
    lang = detect_language(fp.name)
    if lang is None:
        return []
    findings = screen_source(text, lang, kb=kb, source=rel)
    for f in findings:
        f.evidence = f"{rel}:{f.line_no}: {f.evidence}"
    return findings


def review_report(path: str, kb=None) -> str:
    """Security code review of the user's OWN local code. Markdown report.

    Findings carry file:line, severity, technique id + name, the matched
    line (secret-redacted), and a concrete fix suggestion.
    """
    p, err = _resolve_review_target(path)
    if p is None:
        return err
    files: list[Path] = []
    if p.is_dir():
        for root, dirs, names in os.walk(p):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for n in names:
                fp = Path(root) / n
                if detect_language(fp.name):
                    files.append(fp)
    else:
        files = [p]
    findings: list[SecFinding] = []
    for fp in sorted(files):
        rel = str(fp.relative_to(p)) if p.is_dir() else fp.name
        findings.extend(_review_file(fp, rel, kb))
        if len(findings) >= _MAX_REVIEW_FINDINGS:
            break
    findings = findings[:_MAX_REVIEW_FINDINGS]
    lines = [f"# aegis review: {p}",
             f"Files scanned: {len(files)}. Findings: {len(findings)} "
             "(pattern-based triage, not a proof of exploitability).",
             ""]
    if not findings:
        lines.append("No matches for the built-in secure-coding patterns. "
                     "This is triage, not a clean bill of health.")
        return "\n".join(lines)
    order = {"high": 0, "medium": 1}
    for f in sorted(findings, key=lambda f: (order[f.severity], f.evidence)):
        lines.append(f"- [{f.severity.upper()}] {f.rule} "
                     f"{f.evidence}\n"
                     f"  Technique: {f.technique_id} {f.technique_name}\n"
                     f"  Fix: {f.fix}")
    lines += ["",
              "Fix in severity order, then re-run `aegis review`. The guard "
              "blocks high-severity patterns in the agent's own writes."]
    return "\n".join(lines)
