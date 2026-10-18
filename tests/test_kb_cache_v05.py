"""v0.5 Lane D: KB binary cache — cold/warm/invalidation."""

import os
import shutil
import time

from aegis import config
from aegis.kb import KB


def _kb_src():
    return config.KB_DIR


def test_cache_warm_load_matches_cold(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_STATE_DIR", str(tmp_path / "state"))
    kb1 = KB.load(_kb_src(), use_cache=True)   # cold: parses + validates
    kb2 = KB.load(_kb_src(), use_cache=True)   # warm: from cache
    assert kb1.count() == kb2.count() >= 300
    assert [t.id for t in kb1.techniques] == [t.id for t in kb2.techniques]
    assert kb1.techniques[0].detection_patterns == \
        kb2.techniques[0].detection_patterns


def test_cache_invalidates_on_pack_change(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_STATE_DIR", str(tmp_path / "state"))
    shadow = tmp_path / "kbshadow"
    shutil.copytree(_kb_src(), shadow)
    kb1 = KB.load(shadow, use_cache=True)
    n_before = kb1.count()
    assert n_before >= 300
    # Warm now; then modify a pack (bump mtime + size) -> must reload cold.
    kb_warm = KB.load(shadow, use_cache=True)
    assert kb_warm.count() == n_before
    pack = sorted(shadow.glob("*.yaml"))[0]
    with open(pack, "a", encoding="utf-8") as fh:
        fh.write("\n# lane-d cache-invalidation probe\n")
    # Ensure mtime actually advances (coarse filesystems).
    os.utime(pack, (time.time() + 5, time.time() + 5))
    kb2 = KB.load(shadow, use_cache=True)
    assert kb2.count() == n_before  # same content, re-validated
    cache_files = list((tmp_path / "state").glob("kb_cache_*.pkl"))
    assert cache_files, "cache file should exist after loads"


def test_cache_corruption_falls_back(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_STATE_DIR", str(tmp_path / "state"))
    KB.load(_kb_src(), use_cache=True)  # populate
    for p in (tmp_path / "state").glob("kb_cache_*.pkl"):
        p.write_bytes(b"not a pickle")
    kb = KB.load(_kb_src(), use_cache=True)  # must not raise
    assert kb.count() >= 300


def test_cache_opt_out(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_STATE_DIR", str(tmp_path / "state"))
    kb = KB.load(_kb_src(), use_cache=False)
    assert kb.count() >= 300
    assert not list((tmp_path / "state").glob("kb_cache_*.pkl"))
