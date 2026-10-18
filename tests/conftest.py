"""pytest config: repo root on sys.path, shared fixtures."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Isolate user state during tests: never touch ~/.aegis.
os.environ.setdefault("AEGIS_STATE_DIR", str(ROOT / ".test-state"))

import pytest  # noqa: E402

from aegis.kb import KB  # noqa: E402


@pytest.fixture(scope="session")
def kb() -> KB:
    return KB.load()


@pytest.fixture()
def tmp_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path
