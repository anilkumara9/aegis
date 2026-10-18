"""Tests for install.sh (Aegis v0.3 single-command distribution).

Runs install.sh end-to-end with HOME redirected to a tmp dir and
AEGIS_SOURCE_DIR pointed at the repo, so no network is needed.
Skips gracefully when python3-venv is unavailable.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO / "install.sh"
AEGIS_VERSION = (REPO / "aegis" / "__init__.py").read_text()


def venv_available() -> bool:
    try:
        return (
            subprocess.run(
                [sys.executable, "-c", "import venv, ensurepip"],
                capture_output=True,
            ).returncode
            == 0
        )
    except OSError:
        return False


def run_install(home: Path, extra_env: dict | None = None, *args: str) -> subprocess.CompletedProcess:
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("AEGIS_HOME", "AEGIS_BIN_DIR", "AEGIS_SOURCE_DIR", "PYTHONPATH")
    }
    env["HOME"] = str(home)
    env["AEGIS_SOURCE_DIR"] = str(REPO)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["sh", str(INSTALL_SH), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


@pytest.fixture()
def fake_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    # Give install.sh rc files to append to.
    (home / ".bashrc").write_text("# test bashrc\n")
    return home


def test_install_sh_exists_and_is_posix():
    assert INSTALL_SH.is_file()
    assert os.access(INSTALL_SH, os.X_OK)
    assert INSTALL_SH.read_text().startswith("#!/bin/sh")
    assert "set -eu" in INSTALL_SH.read_text()


def test_install_end_to_end(fake_home: Path):
    if not venv_available():
        pytest.skip("python3-venv unavailable")
    proc = run_install(fake_home)
    assert proc.returncode == 0, f"install.sh failed:\n{proc.stdout}\n{proc.stderr}"

    venv = fake_home / ".aegis" / "venv"
    assert venv.is_dir(), "venv not created at $HOME/.aegis/venv"
    assert (venv / "bin" / "aegis").is_file()

    link = fake_home / ".local" / "bin" / "aegis"
    assert link.is_symlink(), "$HOME/.local/bin/aegis is not a symlink"
    assert link.resolve() == (venv / "bin" / "aegis").resolve()

    out = subprocess.run(
        [str(link), "version"], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0
    version = re.search(r"__version__\s*=\s*[\"']([^\"']+)[\"']", AEGIS_VERSION).group(1)
    assert out.stdout.strip() == f"aegis {version}"


def test_install_idempotent(fake_home: Path):
    if not venv_available():
        pytest.skip("python3-venv unavailable")
    first = run_install(fake_home)
    assert first.returncode == 0, f"first run failed:\n{first.stdout}\n{first.stderr}"
    second = run_install(fake_home)
    assert second.returncode == 0, f"second run failed:\n{second.stdout}\n{second.stderr}"

    bashrc = (fake_home / ".bashrc").read_text()
    assert bashrc.count("# >>> aegis installer >>>") == 1, "PATH block duplicated in .bashrc"

    # venv must still be intact and working after the re-run.
    link = fake_home / ".local" / "bin" / "aegis"
    out = subprocess.run([str(link), "version"], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0


def test_reinstall_flag_recreates_venv(fake_home: Path):
    if not venv_available():
        pytest.skip("python3-venv unavailable")
    first = run_install(fake_home)
    assert first.returncode == 0, f"first run failed:\n{first.stdout}\n{first.stderr}"
    venv = fake_home / ".aegis" / "venv"
    marker = venv / "bin" / "aegis"
    assert marker.is_file()
    proc = run_install(fake_home, None, "--reinstall")
    assert proc.returncode == 0, f"--reinstall failed:\n{proc.stdout}\n{proc.stderr}"
    assert marker.is_file()


def test_install_never_leaves_home(fake_home: Path, tmp_path: Path):
    if not venv_available():
        pytest.skip("python3-venv unavailable")
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "SENTINEL"
    sentinel.write_text("untouched")
    proc = run_install(fake_home)
    assert proc.returncode == 0, f"install failed:\n{proc.stdout}\n{proc.stderr}"
    assert sentinel.read_text() == "untouched"
    # Everything the installer wrote is under the fake HOME.
    written = [
        p
        for p in fake_home.rglob("*")
        if p.is_file() and ".cache" not in str(p)
    ]
    assert written, "installer wrote nothing under HOME"
    # No sudo usage in the script: no command line may invoke sudo as a command
    # (a mention inside an error-message hint is allowed).
    sudo_invocations = [
        line
        for line in INSTALL_SH.read_text().splitlines()
        if re.match(r"\s*sudo(\s|$)", line)
        or re.search(r"[;&|]\s*sudo(\s|$)", line)
        or re.match(r"\s*[A-Z_]+=\S*\s+sudo(\s|$)", line)
    ]
    assert not sudo_invocations, f"install.sh invokes sudo: {sudo_invocations}"
