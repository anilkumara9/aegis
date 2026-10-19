"""Project intelligence: compact repo maps (v0.7 Lane A).

Produces a compact, agent-grounding summary of a project: languages with
file counts, entry points, build system, dependency files, test layout,
and config files. Skips VCS/build/dependency directories. Read-only.

The map is also the pre-index summary shown by /repomap and used to
decide what a deeper index (aegis.index) should cover.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from . import polyglot
from .polyglot import SKIP_DIRS

# extension -> display language (superset of polyglot's buildable set)
EXT_LANG = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin",
    ".kts": "kotlin", ".c": "c", ".h": "c/c++", ".hpp": "c++",
    ".hh": "c++", ".cpp": "c++", ".cc": "c++", ".cxx": "c++",
    ".cs": "c#", ".rb": "ruby", ".php": "php", ".swift": "swift",
    ".sh": "shell", ".bash": "shell", ".ps1": "powershell",
    ".sql": "sql", ".md": "markdown", ".rst": "docs",
    ".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".json": "json",
    ".xml": "xml", ".html": "html", ".css": "css", ".vue": "vue",
    ".dockerfile": "docker",
}

ENTRY_CANDIDATES = [
    "main.py", "app.py", "wsgi.py", "asgi.py", "manage.py",
    "index.js", "server.js", "app.js", "src/index.js", "src/main.js",
    "src/index.ts", "src/main.ts",
    "main.go", "cmd/main.go",
    "src/main.rs",
    "Main.java", "src/main/java",
    "main.c", "main.cpp",
    "Program.cs",
]

CONFIG_NAMES = {
    ".gitignore", ".dockerignore", "Dockerfile", "docker-compose.yml",
    "docker-compose.yaml", ".env.example",
    ".eslintrc.js", ".eslintrc.json", ".eslintrc.yml", "eslint.config.js",
    ".prettierrc", "pyproject.toml", "setup.cfg", "tox.ini",
    ".flake8", "ruff.toml", ".rubocop.yml", "tsconfig.json",
    "jest.config.js", "vitest.config.ts", "vite.config.ts",
    "webpack.config.js", ".github", "azure-pipelines.yml",
    "Makefile", "CMakeLists.txt", "go.mod", "Cargo.toml",
}

# Never list secret-bearing files as "config" content; names only, and
# .env itself is deliberately excluded.
_SECRET_NAME_RES = (".env",)


def _walk_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            yield Path(dirpath) / fn


def _rel(root: Path, p: Path) -> str:
    return str(p.relative_to(root))


def _package_entry_points(root: Path, found: list[str]) -> None:
    pj = root / "package.json"
    try:
        data = json.loads(pj.read_text(encoding="utf-8"))
    except Exception:
        return
    for key in ("main",):
        v = data.get(key)
        if isinstance(v, str) and (root / v).is_file():
            found.append(v)
    bin_ = data.get("bin")
    if isinstance(bin_, dict):
        for v in bin_.values():
            if isinstance(v, str) and (root / v).is_file():
                found.append(v)
    elif isinstance(bin_, str) and (root / bin_).is_file():
        found.append(bin_)


def _go_mains(root: Path, found: list[str], budget: int = 300) -> None:
    checked = 0
    for p in _walk_files(root):
        if p.suffix != ".go":
            continue
        checked += 1
        if checked > budget:
            break
        try:
            head = p.read_text(encoding="utf-8", errors="replace")[:2000]
        except OSError:
            continue
        if "package main" in head:
            found.append(_rel(root, p))


def repo_map(project_dir: str | Path) -> dict:
    """Build the repo map dict. Read-only; never raises on bad input."""
    root = Path(project_dir).expanduser().resolve()
    m: dict = {
        "root": str(root),
        "exists": root.is_dir(),
        "languages": [],
        "build_system": None,
        "detected": [],
        "entry_points": [],
        "dependency_files": [],
        "test_layout": {"dirs": [], "test_files": 0},
        "config_files": [],
        "total_files": 0,
    }
    if not root.is_dir():
        m["error"] = f"not a directory: {root}"
        return m

    lang_counts: dict[str, int] = {}
    test_files = 0
    test_dirs: set[str] = set()
    configs: set[str] = set()
    dep_files: set[str] = set()
    total = 0
    for p in _walk_files(root):
        total += 1
        rel = _rel(root, p)
        lang = EXT_LANG.get(p.suffix.lower())
        if p.name == "Dockerfile":
            lang = "docker"
        if lang:
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
        parts = rel.split(os.sep)
        if any(seg in ("test", "tests", "__tests__", "e2e")
               for seg in parts[:-1]) or "test" in p.stem.lower():
            test_files += 1
        for i, seg in enumerate(parts[:-1]):
            if seg in ("test", "tests", "__tests__", "e2e"):
                test_dirs.add(os.sep.join(parts[:i + 1]))
        if p.name in CONFIG_NAMES and not p.name.startswith(".env"):
            configs.add(rel)
        if p.name in ("requirements.txt", "Pipfile", "poetry.lock",
                      "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                      "Cargo.lock", "go.sum", "pom.xml"):
            dep_files.add(rel)
    m["total_files"] = total
    m["languages"] = [{"language": k, "files": v}
                      for k, v in sorted(lang_counts.items(),
                                         key=lambda kv: (-kv[1], kv[0]))]
    m["test_layout"] = {"dirs": sorted(test_dirs), "test_files": test_files}
    m["config_files"] = sorted(configs)
    m["dependency_files"] = sorted(dep_files)

    hits = polyglot.detect_languages(root)
    m["detected"] = [{"language": h.language, "via": h.via,
                      "build_system": h.build_system, "strong": h.strong}
                     for h in hits]
    m["build_system"] = hits[0].build_system if hits and hits[0].build_system \
        else (hits[0].language if hits else None)

    entry: list[str] = []
    for cand in ENTRY_CANDIDATES:
        if (root / cand).is_file():
            entry.append(cand)
    _package_entry_points(root, entry)
    _go_mains(root, entry)
    seen: set[str] = set()
    m["entry_points"] = [e for e in entry
                         if not (e in seen or seen.add(e))]
    return m


def render_repo_map(project_dir: str | Path) -> str:
    """Markdown rendering of repo_map()."""
    m = repo_map(project_dir)
    if m.get("error"):
        return f"# Repo map\n\nerror: {m['error']}"
    lines = [f"# Repo map: {m['root']}",
             f"{m['total_files']} files indexed (skipping VCS/build dirs).",
             ""]
    if m["languages"]:
        lines.append("## Languages")
        for l in m["languages"][:12]:
            lines.append(f"- {l['language']}: {l['files']} files")
        lines.append("")
    if m["build_system"]:
        lines.append(f"Build system: **{m['build_system']}**")
        det = "; ".join(
            f"{d['language']} ({', '.join(d['via'][:3])})"
            for d in m["detected"])
        lines.append(f"Detected toolchains: {det}")
        lines.append("")
    if m["entry_points"]:
        lines.append("## Entry points")
        lines.extend(f"- `{e}`" for e in m["entry_points"][:15])
        lines.append("")
    if m["dependency_files"]:
        lines.append("## Dependency manifests")
        lines.extend(f"- `{d}`" for d in m["dependency_files"])
        lines.append("")
    tl = m["test_layout"]
    lines.append("## Tests")
    lines.append(f"- {tl['test_files']} test files in "
                 f"{len(tl['dirs'])} test dirs: "
                 + (", ".join(f"`{d}`" for d in tl["dirs"][:8]) or "—"))
    lines.append("")
    if m["config_files"]:
        lines.append("## Config files")
        lines.extend(f"- `{c}`" for c in m["config_files"][:20])
        lines.append("")
    return "\n".join(lines)
