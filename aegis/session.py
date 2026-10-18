"""Conversation session store: per-session message history + metadata.

Persisted as JSON under ``config.sessions_dir()/\"conversations\"`` (a
sub-directory, so conversation files never collide with the guard's own
``{session_id}.json`` state files). Sessions survive process restarts;
resuming restores history into the agent loop.

File layout per conversation ``<id>.json``::

    {"id": ..., "title": ..., "created": ..., "updated": ...,
     "messages": [{"role": ..., "content": ..., ...}, ...]}
"""

from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path

from . import config
from .detect import secrets as sec


def conversations_dir() -> Path:
    d = config.sessions_dir() / "conversations"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path(session_id: str) -> Path:
    return conversations_dir() / f"{session_id}.json"


def _collapse(text: str, limit: int = 60) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def new_session(session_id: str | None = None, title: str | None = None) -> dict:
    """Create a conversation session record and return its metadata dict."""
    sid = session_id or uuid.uuid4().hex[:12]
    now = time.time()
    rec = {"id": sid, "title": title or "untitled", "created": now,
           "updated": now, "messages": []}
    _write(rec)
    return rec


def load_session(session_id: str) -> dict | None:
    p = _path(session_id)
    if not p.exists():
        return None
    try:
        rec = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    return rec if isinstance(rec, dict) and rec.get("id") else None


def list_sessions() -> list[dict]:
    """All conversation sessions, newest (by updated) first."""
    out = []
    for p in conversations_dir().glob("*.json"):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(rec, dict) and rec.get("id"):
            out.append({
                "id": rec["id"],
                "title": rec.get("title") or "untitled",
                "created": rec.get("created", 0),
                "updated": rec.get("updated", 0),
                "messages": rec.get("messages", []),
            })
    out.sort(key=lambda r: (r["updated"], r["created"]), reverse=True)
    return out


def save_message(session_id: str, role: str, content: str,
                 extra: dict | None = None) -> dict:
    """Append one message to a session (creating it if needed).

    Returns the session record. The session title is derived from the
    first user message. Message content is secret-redacted before it is
    persisted — the store never holds raw secrets.
    """
    rec = load_session(session_id)
    if rec is None:
        rec = new_session(session_id)
    redacted, _ = sec.redact(str(content or ""))
    msg = {"role": role, "content": redacted}
    if extra:
        for k, v in extra.items():
            if k not in ("role", "content"):
                msg[k] = v
    rec.setdefault("messages", []).append(msg)
    if not rec.get("title") or rec["title"] == "untitled":
        if role == "user" and redacted.strip():
            rec["title"] = _collapse(redacted)
    rec["updated"] = time.time()
    _write(rec)
    return rec


def rename_session(session_id: str, title: str) -> bool:
    rec = load_session(session_id)
    if rec is None:
        return False
    title = title.strip()
    if not title:
        return False
    rec["title"] = _collapse(title, 80)
    rec["updated"] = time.time()
    _write(rec)
    return True


def delete_session(session_id: str) -> bool:
    p = _path(session_id)
    if not p.exists():
        return False
    p.unlink()
    return True


def resolve_session(spec: str, sessions: list[dict] | None = None) -> dict | None:
    """Resolve a ``/resume`` argument: a 1-based list number, a full id, or a
    unique id prefix."""
    spec = (spec or "").strip()
    if not spec:
        return None
    sessions = list_sessions() if sessions is None else sessions
    if spec.isdigit():
        i = int(spec) - 1
        return sessions[i] if 0 <= i < len(sessions) else None
    for s in sessions:
        if s["id"] == spec:
            return s
    prefixed = [s for s in sessions if s["id"].startswith(spec)]
    return prefixed[0] if len(prefixed) == 1 else None


def _write(rec: dict) -> None:
    _path(rec["id"]).write_text(json.dumps(rec), encoding="utf-8")
