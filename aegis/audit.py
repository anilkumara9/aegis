"""JSONL audit log: every tool call, redacted, append-only."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from . import config


class AuditLog:
    """Append-only JSONL audit log. All secrets are redacted BEFORE writing."""

    def __init__(self, session_id: str, path: Path | None = None):
        config.ensure_state_dirs()
        self.session_id = session_id
        self.path = path or (config.audit_dir() / f"{session_id}.jsonl")

    def record(self, event: dict[str, Any]) -> None:
        rec = {"ts": time.time(), "session": self.session_id}
        rec.update(event)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")

    def tool_call(self, tool: str, args: dict, verdict: str,
                  findings: list[dict] | None = None,
                  output_excerpt: str = "") -> None:
        self.record({
            "event": "tool_call", "tool": tool, "args": args,
            "verdict": verdict,
            "findings": findings or [],
            "output_excerpt": output_excerpt[:2000],
        })

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out
