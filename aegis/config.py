"""Runtime configuration: paths, environment, defaults."""

from __future__ import annotations

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
KB_DIR = PACKAGE_DIR / "kb"

# Per-user state lives here (sessions, audit logs). Never in the repo.
# Resolved lazily so tests can redirect via AEGIS_STATE_DIR.
def state_dir() -> Path:
    return Path(os.environ.get("AEGIS_STATE_DIR", str(Path.home() / ".aegis")))


def sessions_dir() -> Path:
    return state_dir() / "sessions"


def audit_dir() -> Path:
    return state_dir() / "audit"


# Backwards-compatible constants (default location at import time).
STATE_DIR = state_dir()
SESSIONS_DIR = sessions_dir()
AUDIT_DIR = audit_dir()

PROVIDER = os.environ.get("AEGIS_PROVIDER", "anthropic").lower()  # anthropic | openai | google | ollama | openrouter | mock
_MODEL_DEFAULTS = {
    "anthropic": "claude-sonnet-4-5-20250929",
    "openai": "gpt-4o",
    "google": "gemini-2.0-flash",
    # OpenRouter default is a FREE model (see OpenRouterProvider's free-only guard).
    "openrouter": "nvidia/nemotron-3-super-120b-a12b:free",
}
MODEL = os.environ.get("AEGIS_MODEL", _MODEL_DEFAULTS.get(PROVIDER, ""))
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "") or os.environ.get("GEMINI_API_KEY", "")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
# OpenRouter is free-models-only by default. Set AEGIS_ALLOW_PAID=1 to allow paid models.
OPENROUTER_ALLOW_PAID = os.environ.get("AEGIS_ALLOW_PAID", "") == "1"
OLLAMA_URL = os.environ.get("AEGIS_OLLAMA_URL", "http://localhost:11434")

# Tool sandbox: "docker" runs bash through a container when docker is present,
# "local" runs on the host (guard still enforced). Default: docker if available.
SANDBOX = os.environ.get("AEGIS_SANDBOX", "auto").lower()  # auto | docker | local
DOCKER_IMAGE = os.environ.get("AEGIS_DOCKER_IMAGE", "python:3.12-slim")
BASH_TIMEOUT = int(os.environ.get("AEGIS_BASH_TIMEOUT", "60"))

MAX_AGENT_ITERATIONS = int(os.environ.get("AEGIS_MAX_ITERATIONS", "25"))
WEBFETCH_TIMEOUT = int(os.environ.get("AEGIS_WEBFETCH_TIMEOUT", "20"))
WEBFETCH_MAX_BYTES = int(os.environ.get("AEGIS_WEBFETCH_MAX_BYTES", "200000"))


def ensure_state_dirs() -> None:
    sessions_dir().mkdir(parents=True, exist_ok=True)
    audit_dir().mkdir(parents=True, exist_ok=True)
