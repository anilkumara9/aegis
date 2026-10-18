"""Read-only local system-inspection tools (defensive).

ps / netconns / hash / search are strictly read-only and local-only: they
inspect the machine the agent runs on and files inside the working directory.
Every call is guard-screened like any other tool. No network, no writes
(except hash baselines, which live in the agent's own state dir).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from . import Tool, ToolContext, safe_path
from .. import config

_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
    "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": "LISTEN", "0B": "CLOSING",
}


def _hex_addr_port(hexaddr: str) -> str:
    try:
        ip_hex, port_hex = hexaddr.split(":")
        port = int(port_hex, 16)
        # /proc/net/tcp stores IPv4 little-endian per 32-bit word.
        raw = bytes.fromhex(ip_hex)
        if len(raw) == 4:
            ip = ".".join(str(b) for b in raw[::-1])
        else:  # IPv6: 4 little-endian words
            words = [raw[i:i + 4][::-1] for i in range(0, 16, 4)]
            ip = ":".join(w.hex() for w in words)
        return f"{ip}:{port}"
    except Exception:
        return hexaddr


class PsTool(Tool):
    name = "ps"
    description = ("List local processes (read-only): pid, ppid, user, name, "
                   "command line. Local-only; no network.")
    parameters = {
        "type": "object",
        "properties": {
            "pattern": {"type": "string",
                        "description": "optional regex filter on name/cmdline"},
            "limit": {"type": "integer", "description": "max rows (default 100)"},
        },
    }

    def run(self, args: dict, ctx: ToolContext) -> str:
        filt = args.get("pattern") or ""
        limit = min(int(args.get("limit") or 100), 500)
        try:
            rx = re.compile(filt, re.IGNORECASE) if filt else None
        except re.error as e:
            return f"error: bad pattern: {e}"
        rows = []
        for entry in sorted(os.listdir("/proc")):
            if not entry.isdigit():
                continue
            try:
                pid = int(entry)
                name = Path(f"/proc/{pid}/comm").read_text().strip()
                cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(
                    b"\0", b" ").decode("utf-8", "replace").strip()[:200]
                ppid, uid = "?", "?"
                for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                    if line.startswith("PPid:"):
                        ppid = line.split()[1]
                    elif line.startswith("Uid:"):
                        uid = line.split()[1]
                row = f"{pid:>7} {ppid:>7} {uid:>6}  {name}  {cmd}"
                if rx and not rx.search(name + " " + cmd):
                    continue
                rows.append(row)
                if len(rows) >= limit:
                    break
            except Exception:
                continue  # process vanished or unreadable; skip
        header = f"{'PID':>7} {'PPID':>7} {'UID':>6}  NAME  COMMAND"
        return header + "\n" + "\n".join(rows) + f"\n({len(rows)} processes)"


class NetConnsTool(Tool):
    name = "netconns"
    description = ("List local TCP/UDP connections (read-only, from "
                   "/proc/net): local/remote address, state. Local-only.")
    parameters = {
        "type": "object",
        "properties": {
            "protocol": {"type": "string", "enum": ["tcp", "udp", "all"],
                         "description": "default all"},
            "limit": {"type": "integer", "description": "max rows (default 100)"},
        },
    }

    def _read_table(self, path: str) -> list[str]:
        rows = []
        try:
            lines = Path(path).read_text().splitlines()[1:]
        except Exception:
            return rows
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            rows.append(
                f"{_hex_addr_port(parts[1]):>22} -> "
                f"{_hex_addr_port(parts[2]):<22} "
                f"{_TCP_STATES.get(parts[3], parts[3])}")
        return rows

    def run(self, args: dict, ctx: ToolContext) -> str:
        proto = (args.get("protocol") or "all").lower()
        limit = min(int(args.get("limit") or 100), 500)
        rows = []
        if proto in ("tcp", "all"):
            rows += [f"tcp  {r}" for r in self._read_table("/proc/net/tcp")]
            rows += [f"tcp6 {r}" for r in self._read_table("/proc/net/tcp6")]
        if proto in ("udp", "all"):
            rows += [f"udp  {r}" for r in self._read_table("/proc/net/udp")]
            rows += [f"udp6 {r}" for r in self._read_table("/proc/net/udp6")]
        rows = rows[:limit]
        return "\n".join(rows) + f"\n({len(rows)} connections)"


class HashTool(Tool):
    name = "hash"
    description = ("SHA-256 file hashing and integrity checking inside the "
                   "working directory. 'hash' a file; 'baseline' stores "
                   "hashes; 'verify' reports changed/missing/new files.")
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string",
                     "description": "file or directory, relative to cwd"},
            "mode": {"type": "string", "enum": ["hash", "baseline", "verify"],
                     "description": "default hash"},
        },
    }

    def _baseline_path(self) -> Path:
        return config.state_dir() / "hash_baseline.json"

    def _iter_files(self, p: Path):
        if p.is_file():
            yield p
            return
        for sub in sorted(p.rglob("*")):
            if sub.is_file() and not sub.is_symlink():
                try:
                    if sub.stat().st_size <= 50_000_000:
                        yield sub
                except Exception:
                    continue

    @staticmethod
    def _sha256(p: Path) -> str:
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def run(self, args: dict, ctx: ToolContext) -> str:
        mode = (args.get("mode") or "hash").lower()
        try:
            root = safe_path(ctx.cwd, args.get("path") or ".")
        except PermissionError as e:
            return f"error: {e}"
        files = list(self._iter_files(root))
        if mode == "hash":
            lines = [f"{self._sha256(p)}  {p.relative_to(ctx.cwd.resolve())}"
                     for p in files[:200]]
            return "\n".join(lines) + f"\n({len(files)} file(s))"
        baseline_path = self._baseline_path()
        current = {}
        for p in files:
            try:
                current[str(p.relative_to(ctx.cwd.resolve()))] = self._sha256(p)
            except Exception:
                continue
        if mode == "baseline":
            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            baseline_path.write_text(json.dumps(
                {"cwd": str(ctx.cwd.resolve()), "hashes": current}, indent=1))
            return f"baseline stored: {len(current)} file(s)"
        # verify
        if not baseline_path.is_file():
            return "error: no baseline stored yet — run hash mode=baseline first"
        try:
            base = json.loads(baseline_path.read_text())
        except Exception as e:
            return f"error: cannot read baseline: {e}"
        if base.get("cwd") != str(ctx.cwd.resolve()):
            return ("error: baseline was taken for a different directory "
                    f"({base.get('cwd')})")
        old = base.get("hashes", {})
        changed = sorted(k for k in current if k in old and old[k] != current[k])
        missing = sorted(k for k in old if k not in current)
        new = sorted(k for k in current if k not in old)
        lines = ["# integrity verify"]
        lines += [f"CHANGED {c}" for c in changed]
        lines += [f"MISSING {m}" for m in missing]
        lines += [f"NEW     {n}" for n in new]
        lines.append(f"ok={len(current) - len(changed)} changed={len(changed)} "
                     f"missing={len(missing)} new={len(new)}")
        return "\n".join(lines)


class SearchTool(Tool):
    name = "search"
    description = ("Deep regex code search inside the working directory "
                   "(read-only): pattern over file contents, binary-safe, "
                   "size-capped.")
    parameters = {
        "type": "object",
        "properties": {
            "pattern": {"type": "string", "description": "regex to search for"},
            "glob": {"type": "string",
                     "description": "optional filename glob, e.g. *.py"},
            "limit": {"type": "integer",
                      "description": "max matches (default 50)"},
        },
    }

    def run(self, args: dict, ctx: ToolContext) -> str:
        pattern = args.get("pattern") or ""
        try:
            rx = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as e:
            return f"error: bad pattern: {e}"
        glob = args.get("glob") or "*"
        limit = min(int(args.get("limit") or 50), 500)
        cwd = ctx.cwd.resolve()
        hits: list[str] = []
        for p in sorted(cwd.rglob(glob)):
            if not p.is_file() or p.is_symlink():
                continue
            try:
                if p.stat().st_size > 2_000_000:
                    continue
                text = p.read_text(encoding="utf-8", errors="strict")
            except Exception:
                continue  # binary or unreadable; skip
            for i, line in enumerate(text.splitlines(), 1):
                m = rx.search(line)
                if m:
                    rel = p.relative_to(cwd)
                    hits.append(f"{rel}:{i}: {line.strip()[:220]}")
                    if len(hits) >= limit:
                        return "\n".join(hits) + f"\n(limit {limit} reached)"
        return "\n".join(hits) + f"\n({len(hits)} match(es))"
