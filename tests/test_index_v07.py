"""v0.7 Lane A: codebase index — build, incremental watch, retrieval,
cache persistence, and the secrets guarantee (metadata only, never
file contents)."""

import json
import time

from aegis.index import (CodeIndex, IndexWatcher, extract_symbols,
                         index_file, query_index)

FAKE_KEY = "sk-ant-fake0123456789abcdef"


def _repo(root):
    (root / "calc.py").write_text(
        "import os\n\n"
        "def add(a, b):\n    return a + b\n\n"
        "class Calculator:\n"
        "    def mul(self, a, b):\n        return a * b\n")
    (root / "main.js").write_text(
        "const util = require('./util');\n"
        "function greet(name) { return 'hi ' + name; }\n"
        "class Greeter {}\n"
        "module.exports = { greet };\n")
    (root / "secret_notes.py").write_text(
        "# TODO: rotate this key\n"
        f"API_KEY = '{FAKE_KEY}'\n")
    (root / "README.md").write_text("# hello\n")
    return root


def test_build_extracts_symbols(tmp_path):
    _repo(tmp_path)
    idx = CodeIndex.build(tmp_path)
    assert idx.stats()["files"] == 4
    rec = idx.files["calc.py"]
    assert rec.language == "python"
    assert "add" in rec.functions and "Calculator" in rec.classes
    assert "os" in rec.imports
    js = idx.files["main.js"]
    assert "greet" in js.functions and "Greeter" in js.classes


def test_extract_symbols_per_language():
    f, c, i = extract_symbols("go",
                              'package m\nimport "fmt"\nfunc Add(a int) int { return a }\ntype T struct{}\n')
    assert "Add" in f and "T" in c
    f, c, i = extract_symbols("rust", "use std::io;\nfn main() {}\nstruct S;\n")
    assert "main" in f and "S" in c and "std" in i
    assert extract_symbols("markdown", "# hi") == ([], [], [])


def test_index_skips_vcs_dirs(tmp_path):
    _repo(tmp_path)
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hidden.py").write_text("def nope(): pass\n")
    idx = CodeIndex.build(tmp_path)
    assert ".git/hidden.py" not in idx.files


def test_query_ranks_symbol_match_first(tmp_path):
    _repo(tmp_path)
    ranked = query_index(tmp_path, "Calculator", top_k=5)
    assert ranked and ranked[0][1] == "calc.py"
    ranked = query_index(tmp_path, "greet", top_k=5)
    assert ranked and ranked[0][1] == "main.js"


def test_watcher_reindexes_only_changed_file(tmp_path):
    _repo(tmp_path)
    idx = CodeIndex.build(tmp_path)
    before = {r: rec.sha256 for r, rec in idx.files.items()}
    # modify exactly one file (mtime granularity: force a newer mtime)
    p = tmp_path / "calc.py"
    p.write_text(p.read_text() + "\ndef sub(a, b):\n    return a - b\n")
    new_mtime = time.time() + 5
    import os
    os.utime(p, (new_mtime, new_mtime))
    changed = idx.check()
    assert changed == ["calc.py"], changed
    assert "sub" in idx.files["calc.py"].functions  # re-indexed
    assert idx.check() == []  # second poll: quiet


def test_watcher_sees_new_and_deleted(tmp_path):
    _repo(tmp_path)
    idx = CodeIndex.build(tmp_path)
    (tmp_path / "new.py").write_text("def fresh(): pass\n")
    (tmp_path / "README.md").unlink()
    changed = idx.check()
    assert "new.py" in changed and "README.md" in changed
    assert "new.py" in idx.files and "README.md" not in idx.files


def test_index_watcher_poll_loop(tmp_path):
    _repo(tmp_path)
    idx = CodeIndex.build(tmp_path)
    seen = []
    w = IndexWatcher(idx, interval=0.05)
    assert w.poll() == []
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    assert w.poll() == ["calc.py"]
    w.stop()
    assert seen == []


def test_cache_roundtrip_and_invalidation(tmp_path):
    _repo(tmp_path)
    idx = CodeIndex.build(tmp_path)
    cache = idx.save()
    assert cache.is_file()
    loaded = CodeIndex.load(tmp_path)
    assert loaded is not None
    assert set(loaded.files) == set(idx.files)
    # stale the cache: modify one file, reload -> re-indexed on load
    p = tmp_path / "main.js"
    p.write_text(p.read_text() + "\nfunction extra() {}\n")
    import os
    os.utime(p, (time.time() + 5, time.time() + 5))
    loaded2 = CodeIndex.load(tmp_path)
    assert "extra" in loaded2.files["main.js"].functions


def test_cache_miss_returns_none(tmp_path):
    assert CodeIndex.load(tmp_path / "does-not-exist-xyz") is None


def test_index_never_stores_file_contents(tmp_path):
    _repo(tmp_path)
    idx = CodeIndex.build(tmp_path)
    blob = json.dumps({r: rec.__dict__ for r, rec in idx.files.items()})
    assert FAKE_KEY not in blob
    cache = idx.save()
    assert FAKE_KEY not in cache.read_text(encoding="utf-8")


def test_query_index_uses_cache(tmp_path):
    _repo(tmp_path)
    first = query_index(tmp_path, "add")
    assert first and first[0][1] == "calc.py"
    # second call hits the persisted cache path (no rebuild needed)
    idx = CodeIndex.load(tmp_path)
    assert idx is not None and "calc.py" in idx.files
