"""Polyglot toolchain detection and management (v0.7 Lane A).

Given a project directory, detect the languages in play from project
files (strong signal) and source extensions (fallback), know each
language's build/test/lint commands, check tool availability via
shutil.which, and run builds/tests locally. Pure functions, no network.

Defensive notes: commands run via subprocess with a timeout, in the
project directory only. Command output is redacted (secret patterns)
at capture time so build logs can never leak keys into reports, the
model's context, or the audit log.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .detect import secrets as sec

# Directories never walked for language/extension detection.
SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "dist",
    "build", "target", ".aegis", ".tox", ".mypy_cache", ".pytest_cache",
    ".gradle", "out", "bin", "obj", ".idea", ".vscode", "coverage",
    ".nyc_output", "vendor",
}

_MAX_WALK_FILES = 5000
_OUTPUT_TAIL_LINES = 40


@dataclass
class CommandAlt:
    """One way to run a step: binaries that must exist + argv."""
    needs: list[str]
    argv: list[str]


@dataclass
class LanguageSpec:
    project_files: list[str]          # strong signal: these files => language
    extensions: set[str]              # fallback signal: source extensions
    build: list[CommandAlt] = field(default_factory=list)
    test: list[CommandAlt] = field(default_factory=list)
    lint: list[CommandAlt] = field(default_factory=list)
    install_hints: dict[str, str] = field(default_factory=dict)


LANGUAGE_SPECS: dict[str, LanguageSpec] = {
    "python": LanguageSpec(
        project_files=["pyproject.toml", "setup.py", "setup.cfg",
                       "requirements.txt", "Pipfile", "poetry.lock",
                       "tox.ini"],
        extensions={".py"},
        build=[CommandAlt(["python3"],
                          ["python3", "-m", "compileall", "-q", "."])],
        test=[CommandAlt(["python3", "pytest"],
                         ["python3", "-m", "pytest", "-q"]),
              CommandAlt(["python3"],
                         ["python3", "-m", "unittest", "discover"])],
        lint=[CommandAlt(["ruff"], ["ruff", "check", "."]),
              CommandAlt(["flake8"], ["flake8", "."])],
        install_hints={
            "python3": "install Python 3.10+ (python.org, or apt install python3)",
            "pytest": "pip install pytest",
            "ruff": "pip install ruff",
            "flake8": "pip install flake8",
        },
    ),
    "node": LanguageSpec(
        project_files=["package.json", "package-lock.json", "yarn.lock",
                       "pnpm-lock.yaml"],
        extensions={".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
        build=[CommandAlt(["npm"],
                          ["npm", "run", "build", "--if-present"])],
        test=[CommandAlt(["npm"], ["npm", "test", "--", "--watchAll=false"])],
        lint=[CommandAlt(["npm"], ["npm", "run", "lint", "--if-present"]),
              CommandAlt(["npx"], ["npx", "eslint", "."])],
        install_hints={
            "node": "install Node.js LTS (nodejs.org)",
            "npm": "ships with Node.js (nodejs.org)",
            "npx": "ships with Node.js (nodejs.org)",
        },
    ),
    "rust": LanguageSpec(
        project_files=["Cargo.toml", "Cargo.lock"],
        extensions={".rs"},
        build=[CommandAlt(["cargo"], ["cargo", "build"])],
        test=[CommandAlt(["cargo"], ["cargo", "test"])],
        lint=[CommandAlt(["cargo"], ["cargo", "clippy", "--", "-D",
                                     "warnings"]),
              CommandAlt(["cargo"], ["cargo", "check"])],
        install_hints={"cargo": "install the Rust toolchain (rustup.rs)"},
    ),
    "go": LanguageSpec(
        project_files=["go.mod", "go.sum"],
        extensions={".go"},
        build=[CommandAlt(["go"], ["go", "build", "./..."])],
        test=[CommandAlt(["go"], ["go", "test", "./..."])],
        lint=[CommandAlt(["go"], ["go", "vet", "./..."])],
        install_hints={"go": "install Go (go.dev/dl)"},
    ),
    "java": LanguageSpec(
        project_files=["pom.xml", "build.gradle", "build.gradle.kts",
                       "settings.gradle"],
        extensions={".java", ".kt", ".kts"},
        build=[CommandAlt(["mvn"], ["mvn", "-q", "compile"]),
               CommandAlt(["gradle"], ["gradle", "-q", "assemble"])],
        test=[CommandAlt(["mvn"], ["mvn", "-q", "test"]),
              CommandAlt(["gradle"], ["gradle", "-q", "test"])],
        lint=[],
        install_hints={
            "mvn": "install Maven (maven.apache.org, or apt install maven)",
            "gradle": "install Gradle (gradle.org)",
        },
    ),
    "c++": LanguageSpec(
        project_files=["CMakeLists.txt", "Makefile", "makefile",
                       "meson.build"],
        extensions={".c", ".h", ".hpp", ".hh", ".cpp", ".cc", ".cxx"},
        build=[CommandAlt(["cmake", "make"],
                          ["cmake", "-S", ".", "-B", "build"]),
               CommandAlt(["make"], ["make"])],
        test=[CommandAlt(["ctest"], ["ctest", "--test-dir", "build"]),
              CommandAlt(["make"], ["make", "test"])],
        lint=[CommandAlt(["clang-tidy"], ["clang-tidy", "--version"])],
        install_hints={
            "cmake": "apt install cmake (cmake.org)",
            "make": "apt install build-essential",
            "ctest": "ships with CMake",
            "clang-tidy": "apt install clang-tidy",
        },
    ),
    "c#": LanguageSpec(
        project_files=[".sln", ".csproj"],
        extensions={".cs"},
        build=[CommandAlt(["dotnet"], ["dotnet", "build"])],
        test=[CommandAlt(["dotnet"], ["dotnet", "test"])],
        lint=[],
        install_hints={"dotnet": "install the .NET SDK (dotnet.microsoft.com)"},
    ),
}

# Suffix-style project files (".sln", ".csproj") match by suffix, not name.
_SUFFIX_PROJECT_FILES = {".sln", ".csproj"}


@dataclass
class LanguageHit:
    language: str
    via: list[str]            # project files / extensions that fired
    build_system: str | None  # e.g. "maven", "gradle", "cargo" ...
    strong: bool              # True = project-file signal, False = ext only


_BUILD_SYSTEM_FOR = {
    ("java", "pom.xml"): "maven",
    ("java", "build.gradle"): "gradle",
    ("java", "build.gradle.kts"): "gradle",
    ("java", "settings.gradle"): "gradle",
    ("python", "pyproject.toml"): "pyproject",
    ("python", "setup.py"): "setuptools",
    ("python", "poetry.lock"): "poetry",
    ("python", "Pipfile"): "pipenv",
    ("node", "package.json"): "npm",
    ("rust", "Cargo.toml"): "cargo",
    ("go", "go.mod"): "go modules",
    ("c++", "CMakeLists.txt"): "cmake",
    ("c++", "Makefile"): "make",
    ("c++", "makefile"): "make",
    ("c++", "meson.build"): "meson",
}


def available(binary: str) -> bool:
    """True when the binary is on PATH."""
    return shutil.which(binary) is not None


def _iter_project_files(root: Path):
    """Yield (relative name, language) for project files in root (top level)."""
    try:
        entries = list(root.iterdir())
    except OSError:
        return
    for lang, spec in LANGUAGE_SPECS.items():
        for pf in spec.project_files:
            if pf in _SUFFIX_PROJECT_FILES:
                matched = [e.name for e in entries
                           if e.is_file() and e.name.endswith(pf)]
            else:
                matched = [pf] if (root / pf).is_file() else []
            for m in matched:
                yield m, lang


def _extension_counts(root: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    n = 0
    for dirpath, dirnames, filenames in _walk(root):
        for fn in filenames:
            ext = Path(fn).suffix.lower()
            if ext:
                counts[ext] = counts.get(ext, 0) + 1
            n += 1
            if n >= _MAX_WALK_FILES:
                return counts
    return counts


def _walk(root: Path):
    import os
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        yield dirpath, dirnames, filenames


def detect_languages(project_dir: str | Path) -> list[LanguageHit]:
    """Detect languages: project files first (strong), extensions fallback."""
    root = Path(project_dir).expanduser().resolve()
    hits: dict[str, LanguageHit] = {}
    # Strong signal: project files in the top level.
    for name, lang in _iter_project_files(root):
        hit = hits.get(lang)
        build_sys = _BUILD_SYSTEM_FOR.get((lang, name))
        if hit is None:
            hits[lang] = LanguageHit(language=lang, via=[name],
                                     build_system=build_sys, strong=True)
        else:
            if name not in hit.via:
                hit.via.append(name)
            if build_sys and not hit.build_system:
                hit.build_system = build_sys
    # Fallback: source extensions anywhere in the tree.
    counts = _extension_counts(root)
    for lang, spec in LANGUAGE_SPECS.items():
        exts = sorted(e for e in spec.extensions if counts.get(e))
        if exts and lang not in hits:
            hits[lang] = LanguageHit(language=lang,
                                     via=[f"*{e} files" for e in exts],
                                     build_system=None, strong=False)
    strong = sorted([h for h in hits.values() if h.strong],
                    key=lambda h: h.language)
    weak = sorted([h for h in hits.values() if not h.strong],
                  key=lambda h: h.language)
    return strong + weak


def _select_alt(alts: list[CommandAlt]) -> CommandAlt | None:
    for alt in alts:
        if all(available(b) for b in alt.needs):
            return alt
    return None


def missing_tools(project_dir: str | Path) -> list[dict]:
    """Binaries the detected toolchains need but PATH lacks, with hints."""
    missing: list[dict] = []
    seen: set[str] = set()
    for hit in detect_languages(project_dir):
        spec = LANGUAGE_SPECS[hit.language]
        for kind in ("build", "test", "lint"):
            for alt in getattr(spec, kind):
                for b in alt.needs:
                    if b not in seen and not available(b):
                        seen.add(b)
                        missing.append({
                            "binary": b,
                            "needed_for": f"{hit.language} {kind}",
                            "hint": spec.install_hints.get(
                                b, f"install '{b}' and put it on PATH"),
                        })
    return missing


@dataclass
class StepResult:
    kind: str                      # "build" | "test" | "lint"
    argv: list[str]
    returncode: int
    output: str                    # redacted, tailed
    timed_out: bool = False
    skipped_missing: str = ""      # reason when the step could not run


@dataclass
class RunResult:
    language: str
    kind: str
    steps: list[StepResult]
    ok: bool
    summary: str


def _tail_redacted(text: str) -> str:
    redacted, _ = sec.redact(text or "")
    lines = redacted.splitlines()
    if len(lines) > _OUTPUT_TAIL_LINES:
        lines = [f"... ({len(lines) - _OUTPUT_TAIL_LINES} lines truncated) ..."] \
            + lines[-_OUTPUT_TAIL_LINES:]
    return "\n".join(lines)


def run_step(language: str, kind: str, root: Path,
             timeout: int = 180) -> StepResult:
    """Run one build/test/lint step for a language. Never raises."""
    spec = LANGUAGE_SPECS.get(language)
    if spec is None:
        return StepResult(kind, [], 2, "", skipped_missing=f"unknown language")
    alt = _select_alt(getattr(spec, kind))
    if alt is None:
        needs = sorted({b for a in getattr(spec, kind) for b in a.needs})
        return StepResult(kind, [], 2, "",
                          skipped_missing="missing tools: " + ", ".join(needs)
                          if needs else f"no {kind} command known")
    env = None
    if language == "python" and alt.argv[0] in ("python3", "python"):
        # Stale-bytecode race: an edit->test cycle that lands inside the
        # same mtime second as a previous run can make CPython trust a
        # stale __pycache__ entry (pyc invalidation is second-resolution).
        # __pycache__ is disposable, so clear it; and don't write new
        # bytecode for our own runs.
        _clear_pycache(root)
        import os as _os
        env = dict(_os.environ, PYTHONDONTWRITEBYTECODE="1")
    try:
        proc = subprocess.run(alt.argv, cwd=root, capture_output=True,
                              text=True, timeout=timeout, env=env)
        out = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
        return StepResult(kind, alt.argv, proc.returncode,
                          _tail_redacted(out))
    except FileNotFoundError:
        return StepResult(kind, alt.argv, 127, "",
                          skipped_missing=f"binary not found: {alt.argv[0]}")
    except subprocess.TimeoutExpired as e:
        partial = (e.stdout or "") if isinstance(e.stdout, str) else ""
        return StepResult(kind, alt.argv, 124, _tail_redacted(partial),
                          timed_out=True)


def _clear_pycache(root: Path) -> None:
    """Remove __pycache__ dirs under root (disposable bytecode cache).

    Called before Python build/test runs so an edit->test cycle can
    never execute stale bytecode (pyc invalidation is second-resolution;
    same-second edits would otherwise re-run the pre-edit code).
    """
    import os as _os
    import shutil as _shutil
    for dirpath, dirnames, _ in _os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS
                       or d == "__pycache__"]
        for d in [x for x in dirnames if x == "__pycache__"]:
            _shutil.rmtree(Path(dirpath) / d, ignore_errors=True)
            dirnames.remove(d)


_TEST_COUNT_RES = [
    # (regex, formatter) applied to combined output
    (re.compile(r"(\d+)\s+passed"), lambda m: f"{m.group(1)} passed"),
    (re.compile(r"Tests:\s+(\d+)\s+passed"), lambda m: f"{m.group(1)} passed"),
    (re.compile(r"test result:\s*ok\.\s*(\d+)\s+passed"),
     lambda m: f"{m.group(1)} passed"),
    (re.compile(r"OK\s*\((\d+)\s+tests?\)"), lambda m: f"{m.group(1)} passed"),
    (re.compile(r"Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+)"),
     lambda m: (f"{m.group(1)} run, {m.group(2)} failures, "
                f"{m.group(3)} errors")),
]


def _test_summary(language: str, step: StepResult) -> str:
    if step.skipped_missing:
        return f"skipped ({step.skipped_missing})"
    if step.timed_out:
        return f"TIMEOUT after command: {' '.join(step.argv)}"
    for rx, fmt in _TEST_COUNT_RES:
        m = rx.search(step.output)
        if m:
            tail = f" — {fmt(m)}" if step.returncode == 0 else \
                f" — {fmt(m)}, FAILING (exit {step.returncode})"
            return ("PASS" if step.returncode == 0 else "FAIL") + tail
    return ("PASS" if step.returncode == 0 else "FAIL") + \
        f" (exit {step.returncode})"


def run_build(project_dir: str | Path, timeout: int = 180) -> list[RunResult]:
    """Run each detected language's build. Returns one result per language."""
    root = Path(project_dir).expanduser().resolve()
    results = []
    for hit in detect_languages(project_dir):
        step = run_step(hit.language, "build", root, timeout)
        ok = step.returncode == 0 and not step.skipped_missing
        results.append(RunResult(hit.language, "build", [step], ok,
                                "BUILD OK" if ok else
                                f"BUILD FAILED ({step.skipped_missing or 'exit ' + str(step.returncode)})"))
    return results


def run_tests(project_dir: str | Path, timeout: int = 300) -> list[RunResult]:
    """Run each detected language's test suite. Returns one result per language."""
    root = Path(project_dir).expanduser().resolve()
    results = []
    for hit in detect_languages(project_dir):
        step = run_step(hit.language, "test", root, timeout)
        ok = step.returncode == 0 and not step.skipped_missing \
            and not step.timed_out
        results.append(RunResult(hit.language, "test", [step], ok,
                                f"TESTS {'GREEN' if ok else 'RED'}: "
                                f"{_test_summary(hit.language, step)}"))
    return results


def run_lint(project_dir: str | Path, timeout: int = 180) -> list[RunResult]:
    root = Path(project_dir).expanduser().resolve()
    results = []
    for hit in detect_languages(project_dir):
        step = run_step(hit.language, "lint", root, timeout)
        ok = step.returncode == 0 and not step.skipped_missing
        results.append(RunResult(hit.language, "lint", [step], ok,
                                "LINT CLEAN" if ok else
                                f"LINT ISSUES ({step.skipped_missing or 'exit ' + str(step.returncode)})"))
    return results


def toolchain_report(project_dir: str | Path) -> str:
    """Markdown report: detected languages, commands, availability, gaps."""
    root = Path(project_dir).expanduser().resolve()
    hits = detect_languages(project_dir)
    lines = [f"# Toolchain report: {root}", ""]
    if not hits:
        return "\n".join(lines + [
            "No known project files or source extensions found. "
            "Add a manifest (pyproject.toml, package.json, Cargo.toml, "
            "go.mod, pom.xml, …) or source files so the toolchain can be "
            "detected."])
    for hit in hits:
        spec = LANGUAGE_SPECS[hit.language]
        sig = "project files" if hit.strong else "file extensions (weak)"
        bs = f" — build system: {hit.build_system}" if hit.build_system else ""
        lines.append(f"## {hit.language}{bs}")
        lines.append(f"Detected via {sig}: {', '.join(hit.via)}")
        for kind in ("build", "test", "lint"):
            alt = _select_alt(getattr(spec, kind))
            if alt is None:
                needs = sorted({b for a in getattr(spec, kind)
                                for b in a.needs})
                lines.append(f"- {kind}: unavailable "
                             f"(needs: {', '.join(needs) or 'n/a'})")
            else:
                lines.append(f"- {kind}: `{' '.join(alt.argv)}` ✓")
        lines.append("")
    missing = missing_tools(project_dir)
    if missing:
        lines.append("## Missing tools")
        for m in missing:
            lines.append(f"- `{m['binary']}` (for {m['needed_for']}): "
                         f"{m['hint']}")
    else:
        lines.append("All toolchain binaries are on PATH. ✓")
    return "\n".join(lines)


def package_json_scripts(project_dir: str | Path) -> dict:
    """Read package.json scripts (used by repomap entry points)."""
    pj = Path(project_dir).expanduser().resolve() / "package.json"
    try:
        data = json.loads(pj.read_text(encoding="utf-8"))
    except Exception:
        return {}
    scripts = data.get("scripts")
    return scripts if isinstance(scripts, dict) else {}
