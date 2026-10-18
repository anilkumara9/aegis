"""Tool ABC, registry, and shared context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ToolContext:
    guard_session: Any      # aegis.guard.GuardSession
    kb: Any                 # aegis.kb.KB
    cwd: Path
    approval_callback: Any = None


class Tool(ABC):
    name: str = ""
    description: str = ""
    parameters: dict = {}

    @abstractmethod
    def run(self, args: dict, ctx: ToolContext) -> str:
        """Execute with already-guard-approved args. Return text result."""

    def spec(self) -> dict:
        return {"name": self.name, "description": self.description,
                "parameters": self.parameters}


def safe_path(cwd: Path, path: str) -> Path:
    """Resolve path inside cwd; raise on escape attempts."""
    p = (cwd / path).resolve()
    try:
        p.relative_to(cwd.resolve())
    except ValueError:
        raise PermissionError(f"path escapes working directory: {path}")
    return p
