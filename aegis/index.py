"""Codebase indexing with incremental file-watching (v0.7 Lane A).

Index on startup: per-file records (path, language, size, mtime, hash,
exported symbols — functions/classes via AST or regex per language —
imports). A lightweight polling watcher (mtime+size) re-indexes ONLY
changed files. query_index() ranks relevant files by keyword + symbol
matching so the agent pulls relevant files per-request instead of
loading everything into context.

Secrets: records store metadata ONLY (paths, symbols, imports) — never
file content or snippets. A leaked index cache therefore cannot leak
secret values. See docs/INDEXING.md for the design tradeoffs.

Dependency-free by design: the watcher is mtime+size polling, no
watchdog. Rationale is documented in docs/INDEXING.md.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import config
from .polyglot import SKIP_DIRS

MAX_FILE_BYTES = 2_000_000       # files larger than this get metadata only
SYMBOL_FILE_BUDGET = 200_000     # symbol extraction skipped above this size


@dataclass
class FileRecord:
    path: str                    # repo-relative
    language: str
    size: int
    mtime: float
    sha256: str                  # of content ("" when skipped)
    functions: list[str] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    binary: bool = False


EXT_LANG = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin",
    ".c": "c", ".h": "c", ".hpp": "c++", ".hh": "c++", ".cpp": "c++",
    ".cc": "c++", ".cxx": "c++", ".cs": "c#", ".rb": "ruby",
    ".php": "php", ".swift": "swift", ".sh": "shell",
}


# -- symbol extraction ---------------------------------------------------

def _python_symbols(text: str) -> tuple[list[str], list[str], list[str]]:
    funcs, classes, imports = [], [], []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return funcs, classes, imports
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.append(node.name)
        elif isinstance(node, ast.ClassDef):
            classes.append(node.name)
        elif isinstance(node, ast.Import):
            imports.extend(a.asname or a.name.split(".")[0]
                           for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module.split(".")[0])
    return funcs, classes, imports


_JS_FUNC = re.compile(r"(?:function\s+([A-Za-z_$][\w$]*)\s*\(|"
                      r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
                      r"(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>)")
_JS_CLASS = re.compile(r"class\s+([A-Za-z_$][\w$]*)")
_JS_IMPORT = re.compile(r"import\s+(?:[^'\"]*?from\s+)?['\"]([^'\"]+)['\"]"
                        r"|require\(\s*['\"]([^'\"]+)['\"]\s*\)")


def _js_symbols(text: str) -> tuple[list[str], list[str], list[str]]:
    funcs = [m.group(1) or m.group(2) for m in _JS_FUNC.finditer(text)]
    classes = _JS_CLASS.findall(text)
    imports = [m.group(1) or m.group(2) for m in _JS_IMPORT.finditer(text)]
    return funcs, classes, imports


_GO_FUNC = re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(",
                      re.MULTILINE)
_GO_TYPE = re.compile(r"^type\s+([A-Za-z_]\w*)\s+(?:struct|interface)",
                      re.MULTILINE)
_GO_IMPORT = re.compile(r'^\s*(?:"([^"]+)"|`([^`]+)`)', re.MULTILINE)


def _go_symbols(text: str) -> tuple[list[str], list[str], list[str]]:
    in_import = False
    imports: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("import ("):
            in_import = True
            continue
        if in_import:
            if s == ")":
                in_import = False
            elif s.startswith('"'):
                imports.append(s.strip('"').split("/")[-1])
            continue
        if s.startswith("import ") and '"' in s:
            imports.append(s.split('"')[1].split("/")[-1])
    return ([m.group(1) for m in _GO_FUNC.finditer(text)],
            [m.group(1) for m in _GO_TYPE.finditer(text)], imports)


_RUST_FN = re.compile(r"(?:^|\n)\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+([a-z_]\w*)")
_RUST_TYPE = re.compile(r"(?:^|\n)\s*(?:pub(?:\([^)]*\))?\s+)?"
                        r"(?:struct|enum|trait)\s+([A-Za-z_]\w*)")
_RUST_USE = re.compile(r"(?:^|\n)\s*use\s+([^;]+);")


def _rust_symbols(text: str) -> tuple[list[str], list[str], list[str]]:
    imports = [u.strip().split("::")[0].strip()
               for u in _RUST_USE.findall(text)]
    return ([m.group(1) for m in _RUST_FN.finditer(text)],
            [m.group(1) for m in _RUST_TYPE.finditer(text)], imports)


_JAVA_CLASS = re.compile(r"\b(?:class|interface|enum|record)\s+([A-Za-z_]\w*)")
_JAVA_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)\s*;",
                          re.MULTILINE)


def _java_symbols(text: str) -> tuple[list[str], list[str], list[str]]:
    imports = [i.split(".")[-2] if len(i.split(".")) > 1 else i
               for i in _JAVA_IMPORT.findall(text)]
    return [], _JAVA_CLASS.findall(text), imports


_C_FUNC = re.compile(r"(?:^|\n)\s*(?:static\s+)?[\w:*<>]+\s+([a-zA-Z_]\w*)"
                     r"\s*\([^;{}]*\)\s*\{")
_C_CLASS = re.compile(r"\b(?:class|struct)\s+([A-Za-z_]\w*)")
_C_INCLUDE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', re.MULTILINE)


def _c_symbols(text: str) -> tuple[list[str], list[str], list[str]]:
    return ([m.group(1) for m in _C_FUNC.finditer(text)],
            _C_CLASS.findall(text),
            [m.group(1) for m in _C_INCLUDE.finditer(text)])


_EXTRACTORS = {
    "python": _python_symbols,
    "javascript": _js_symbols,
    "typescript": _js_symbols,
    "go": _go_symbols,
    "rust": _rust_symbols,
    "java": _java_symbols,
    "kotlin": _java_symbols,
    "c": _c_symbols,
    "c++": _c_symbols,
    "c#": _java_symbols,
}


def extract_symbols(language: str, text: str) -> tuple[list, list, list]:
    fn = _EXTRACTORS.get(language)
    if fn is None:
        return [], [], []
    try:
        return fn(text)
    except Exception:
        return [], [], []


def _hash_file(p: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def index_file(root: Path, rel: str) -> FileRecord | None:
    """Build the record for one repo-relative path. None if unreadable."""
    p = root / rel
    try:
        st = p.stat()
    except OSError:
        return None
    if not p.is_file():
        return None
    language = EXT_LANG.get(p.suffix.lower(), "other")
    rec = FileRecord(path=rel, language=language, size=st.st_size,
                     mtime=st.st_mtime, sha256="")
    if st.st_size > MAX_FILE_BYTES:
        return rec
    try:
        with open(p, "rb") as f:
            head = f.read(8192)
    except OSError:
        return None
    if b"\x00" in head:
        rec.binary = True
        rec.language = "binary"
        return rec
    rec.sha256 = _hash_file(p)
    if st.st_size <= SYMBOL_FILE_BUDGET:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return rec
        funcs, classes, imports = extract_symbols(language, text)
        rec.functions = sorted(set(funcs))[:200]
        rec.classes = sorted(set(classes))[:200]
        rec.imports = sorted(set(imports))[:200]
    return rec


# -- the index -------------------------------------------------------------

class CodeIndex:
    """Incremental per-repo code index."""

    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve()
        self.files: dict[str, FileRecord] = {}
        # last-seen (mtime, size) per path — the watcher's change signal.
        self._seen: dict[str, tuple[float, int]] = {}
        # count of stale records re-indexed by the most recent load()
        self._last_load_reindexed = 0

    # -- building ------------------------------------------------------
    def _walk_rels(self):
        rels = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                rels.append(str(Path(dirpath, fn).relative_to(self.root)))
        return sorted(rels)

    @classmethod
    def build(cls, root: str | Path) -> "CodeIndex":
        idx = cls(root)
        for rel in idx._walk_rels():
            rec = index_file(idx.root, rel)
            if rec is not None:
                idx.files[rel] = rec
                idx._seen[rel] = (rec.mtime, rec.size)
        return idx

    def update_path(self, rel: str) -> bool:
        """Re-index exactly one file. True when the record changed/was added."""
        rec = index_file(self.root, rel)
        old = self.files.get(rel)
        if rec is None:
            # deleted or unreadable: drop the record if we had one.
            if old is not None:
                del self.files[rel]
                self._seen.pop(rel, None)
                return True
            return False
        self.files[rel] = rec
        self._seen[rel] = (rec.mtime, rec.size)
        return old is None or asdict(old) != asdict(rec)

    def remove_path(self, rel: str) -> bool:
        if rel in self.files:
            del self.files[rel]
            self._seen.pop(rel, None)
            return True
        return False

    # -- incremental watch ----------------------------------------------
    def check(self) -> list[str]:
        """Poll for changes (mtime+size). Re-index ONLY changed files.

        Returns the sorted list of repo-relative paths that changed
        (added, modified, or deleted) since the last check/build.
        """
        current: dict[str, tuple[float, int]] = {}
        for rel in self._walk_rels():
            try:
                st = (self.root / rel).stat()
            except OSError:
                continue
            current[rel] = (st.st_mtime, st.st_size)
        changed: list[str] = []
        for rel, sig in current.items():
            if self._seen.get(rel) != sig:
                if self.update_path(rel):
                    changed.append(rel)
                else:
                    self._seen[rel] = sig
        for rel in [r for r in self._seen if r not in current]:
            if self.remove_path(rel):
                changed.append(rel)
        return sorted(changed)

    # -- retrieval -------------------------------------------------------
    def query(self, text: str, top_k: int = 8) -> list[tuple[float, str]]:
        """Rank files by keyword + symbol match. Returns (score, relpath)."""
        tokens = [t.lower() for t in re.findall(r"[A-Za-z_][\w]*", text)]
        if not tokens:
            return []
        scored: list[tuple[float, str]] = []
        for rel, rec in self.files.items():
            score = 0.0
            name = Path(rel).name.lower()
            dirparts = [d.lower() for d in Path(rel).parts[:-1]]
            syms = [s.lower() for s in rec.functions + rec.classes]
            imps = [i.lower() for i in rec.imports]
            for tok in tokens:
                if tok in syms:
                    score += 10
                elif any(tok in s for s in syms):
                    score += 5
                if tok in name:
                    score += 4
                elif tok in imps:
                    score += 3
                if any(tok in d for d in dirparts):
                    score += 1
            if score > 0:
                scored.append((score, rel))
        scored.sort(key=lambda s: (-s[0], s[1]))
        return scored[:top_k]

    def stats(self) -> dict:
        langs: dict[str, int] = {}
        syms = 0
        for rec in self.files.values():
            langs[rec.language] = langs.get(rec.language, 0) + 1
            syms += len(rec.functions) + len(rec.classes)
        return {"root": str(self.root), "files": len(self.files),
                "languages": langs, "symbols": syms}

    # -- persistence ------------------------------------------------------
    def _cache_path(self) -> Path:
        key = hashlib.sha1(str(self.root).encode()).hexdigest()[:16]
        d = config.state_dir() / "index"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{key}.json"

    def save(self) -> Path:
        """Persist the index under the state dir, keyed by repo path."""
        payload = {"root": str(self.root), "saved_at": time.time(),
                   "files": {rel: asdict(rec)
                             for rel, rec in self.files.items()},
                   "seen": {rel: list(sig)
                            for rel, sig in self._seen.items()}}
        p = self._cache_path()
        p.write_text(json.dumps(payload), encoding="utf-8")
        return p

    @classmethod
    def load(cls, root: str | Path) -> "CodeIndex | None":
        """Load a cached index, invalidating stale files by mtime+size.

        Returns None when no cache exists for this repo. Stale records
        (mtime or size changed since save) are re-indexed on load so the
        caller always gets a fresh index.
        """
        idx = cls(root)
        p = idx._cache_path()
        if not p.is_file():
            return None
        try:
            payload = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if payload.get("root") != str(idx.root):
            return None
        reindexed = 0
        for rel, rd in payload.get("files", {}).items():
            try:
                st = (idx.root / rel).stat()
            except OSError:
                continue  # deleted since save: drop
            saved_sig = tuple(payload.get("seen", {}).get(rel, ()))
            if len(saved_sig) == 2 and \
                    (st.st_mtime, st.st_size) == (saved_sig[0], saved_sig[1]):
                try:
                    rec = FileRecord(**rd)
                except TypeError:
                    continue
                idx.files[rel] = rec
                idx._seen[rel] = (st.st_mtime, st.st_size)
            else:
                rec = index_file(idx.root, rel)
                if rec is not None:
                    idx.files[rel] = rec
                    idx._seen[rel] = (rec.mtime, rec.size)
                    reindexed += 1
        # pick up files added since the save
        added = idx.check()
        idx._last_load_reindexed = reindexed + len(added)
        return idx


def query_index(root: str | Path, query: str,
                top_k: int = 8) -> list[tuple[float, str]]:
    """Retriever API: ranked relevant files for a query.

    Loads the persisted cache (fast path) or builds the index, then
    ranks by keyword + symbol match. Never loads file contents.
    """
    idx = CodeIndex.load(root)
    if idx is None:
        idx = CodeIndex.build(root)
        idx.save()
    else:
        idx.check()  # cheap incremental refresh on top of the cache
    return idx.query(query, top_k=top_k)


# -- polling watcher ---------------------------------------------------------

class IndexWatcher:
    """Lightweight polling watcher over a CodeIndex (dependency-free).

    poll() returns the changed paths since the last poll, re-indexing
    only those files. watch() loops poll() until stop_event is set,
    calling on_change(changed) for non-empty batches.
    """

    def __init__(self, index: CodeIndex, interval: float = 2.0):
        self.index = index
        self.interval = max(0.1, interval)
        self._stop = threading.Event()

    def poll(self) -> list[str]:
        return self.index.check()

    def stop(self) -> None:
        self._stop.set()

    def watch(self, on_change, stop_event: "threading.Event | None" = None
              ) -> None:
        stop = stop_event or self._stop
        while not stop.wait(self.interval):
            try:
                changed = self.poll()
            except Exception:
                continue
            if changed:
                try:
                    on_change(changed)
                except Exception:
                    continue
