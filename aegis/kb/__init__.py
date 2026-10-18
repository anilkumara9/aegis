"""Technique knowledge base: loading, strict validation, and query.

The KB is defensive knowledge at TTP/detection level (MITRE ATT&CK-style):
how attacks work, what they look like in telemetry, how to detect and stop
them. It never contains operational attack instructions or payloads.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .. import config

REQUIRED_FIELDS = (
    "id", "name", "category", "description", "how_it_works",
    "indicators", "detection", "severity", "mitigations", "references",
)
SEVERITIES = ("critical", "high", "medium", "low")
ID_RE = re.compile(r"^AEG-T\d{3}$")


class KBValidationError(Exception):
    """Raised when a KB pack fails strict schema validation."""


@dataclass
class Technique:
    id: str
    name: str
    category: str
    description: str
    how_it_works: str
    indicators: list[str]
    detection_rule: str
    detection_patterns: list[str]
    severity: str
    mitigations: list[str]
    references: list[str]
    variants: list[str] = field(default_factory=list)
    examples: list[dict] = field(default_factory=list)
    pack: str = ""

    def searchable_text(self) -> str:
        parts = [
            self.name, self.name, self.name,  # name weighted x3
            self.description,
            self.how_it_works,
            " ".join(self.variants),
            " ".join(self.indicators), " ".join(self.indicators),  # indicators x2
            " ".join(self.mitigations),
        ]
        return "\n".join(parts).lower()

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "category": self.category,
            "description": self.description, "how_it_works": self.how_it_works,
            "variants": self.variants, "indicators": self.indicators,
            "detection": {"rule": self.detection_rule, "patterns": self.detection_patterns},
            "severity": self.severity, "mitigations": self.mitigations,
            "examples": self.examples, "references": self.references, "pack": self.pack,
        }


def _validate_entry(pack_name: str, entry: dict, seen_ids: set[str]) -> Technique:
    loc = f"{pack_name}: entry {entry.get('id', '?')}"
    for f in REQUIRED_FIELDS:
        if f not in entry or entry[f] in (None, "", []):
            raise KBValidationError(f"{loc}: missing required field '{f}'")
    tid = entry["id"]
    if not ID_RE.match(tid):
        raise KBValidationError(f"{loc}: id '{tid}' must match AEG-TNNN")
    if tid in seen_ids:
        raise KBValidationError(f"{loc}: duplicate id '{tid}'")
    seen_ids.add(tid)
    if entry["category"] != pack_name:
        raise KBValidationError(
            f"{loc}: category '{entry['category']}' != pack '{pack_name}'")
    if entry["severity"] not in SEVERITIES:
        raise KBValidationError(f"{loc}: bad severity '{entry['severity']}'")
    det = entry["detection"]
    if not isinstance(det, dict) or "rule" not in det or "patterns" not in det:
        raise KBValidationError(f"{loc}: detection must have rule + patterns")
    for p in det["patterns"]:
        try:
            re.compile(p, re.IGNORECASE)
        except re.error as e:
            raise KBValidationError(f"{loc}: bad regex pattern {p!r}: {e}")
    for list_field in ("indicators", "mitigations", "references"):
        if not isinstance(entry[list_field], list) or len(entry[list_field]) < 2:
            raise KBValidationError(f"{loc}: '{list_field}' needs >= 2 items")
    if len(entry["description"].split()) < 15:
        raise KBValidationError(f"{loc}: description too thin (<15 words)")
    if len(entry["how_it_works"].split()) < 20:
        raise KBValidationError(f"{loc}: how_it_works too thin (<20 words)")
    return Technique(
        id=tid, name=str(entry["name"]), category=pack_name,
        description=str(entry["description"]), how_it_works=str(entry["how_it_works"]),
        indicators=[str(x) for x in entry["indicators"]],
        detection_rule=str(det["rule"]),
        detection_patterns=[str(x) for x in det["patterns"]],
        severity=entry["severity"],
        mitigations=[str(x) for x in entry["mitigations"]],
        references=[str(x) for x in entry["references"]],
        variants=[str(x) for x in entry.get("variants", [])],
        examples=list(entry.get("examples", [])),
        pack=pack_name,
    )


class KB:
    """Loaded, validated technique knowledge base."""

    def __init__(self, techniques: list[Technique]):
        self.techniques = techniques
        self.by_id = {t.id: t for t in techniques}
        self.by_category: dict[str, list[Technique]] = {}
        for t in techniques:
            self.by_category.setdefault(t.category, []).append(t)

    @classmethod
    def load(cls, kb_dir: Path | None = None) -> "KB":
        kb_dir = Path(kb_dir) if kb_dir else config.KB_DIR
        files = sorted(kb_dir.glob("*.yaml"))
        if not files:
            raise KBValidationError(f"no KB packs found in {kb_dir}")
        techniques: list[Technique] = []
        seen_ids: set[str] = set()
        for f in files:
            pack_name = f.stem
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8"))
            except yaml.YAMLError as e:
                raise KBValidationError(f"{f.name}: YAML parse error: {e}")
            if not isinstance(data, dict) or "techniques" not in data:
                raise KBValidationError(f"{f.name}: top level needs 'techniques'")
            entries = data["techniques"]
            if not isinstance(entries, list) or len(entries) < 10:
                raise KBValidationError(
                    f"{f.name}: pack needs >= 10 techniques, found "
                    f"{len(entries) if isinstance(entries, list) else 0}")
            for entry in entries:
                techniques.append(_validate_entry(pack_name, entry, seen_ids))
        techniques.sort(key=lambda t: t.id)
        return cls(techniques)

    # -- accessors ------------------------------------------------------
    def packs(self) -> list[str]:
        return sorted(self.by_category)

    def count(self) -> int:
        return len(self.techniques)

    def query(self, text: str, top_k: int = 5) -> list[Technique]:
        """Keyword relevance search over the KB. Deterministic, no deps."""
        tokens = [t for t in re.findall(r"[a-z0-9]{3,}", text.lower())
                  if t not in _STOPWORDS]
        if not tokens:
            return []
        scored = []
        for t in self.techniques:
            hay = t.searchable_text()
            score = sum(hay.count(tok) for tok in tokens)
            # phrase bonus
            if text.lower() in hay:
                score += 5
            if score:
                scored.append((score, t.id, t))
        scored.sort(key=lambda s: (-s[0], s[1]))
        return [t for _, _, t in scored[:top_k]]

    def coverage(self) -> dict[str, int]:
        return {p: len(v) for p, v in sorted(self.by_category.items())}

    # -- system prompt material ------------------------------------------
    def doctrine_section(self, max_chars: int | None = None) -> str:
        """hacker_mindset doctrine for the agent system prompt.

        max_chars=None (default) fits ALL doctrine — no truncation.
        Override per-call with an explicit arg, or at runtime with the
        AEGIS_DOCTRINE_CHARS env var, to control per-API-call cost.
        """
        if max_chars is None:
            env = os.environ.get("AEGIS_DOCTRINE_CHARS", "").strip()
            max_chars = int(env) if env else 0
        out = ["## Defender doctrine (think like an attacker, act like a defender)"]
        for t in self.by_category.get("hacker_mindset", []):
            chunk = f"### {t.id} {t.name}\n{t.description}\nKey: {t.how_it_works[:600]}"
            out.append(chunk)
        text = "\n\n".join(out)
        return text[:max_chars] if max_chars > 0 else text

    def technique_index(self, max_chars: int = 12000) -> str:
        """Condensed per-category technique index for the system prompt."""
        lines = ["## Known attack techniques (your defensive knowledge)"]
        for cat in self.packs():
            if cat == "hacker_mindset":
                continue
            lines.append(f"\n### {cat}")
            for t in self.by_category[cat]:
                lines.append(
                    f"- {t.id} [{t.severity}] {t.name}: "
                    f"{t.description[:140]}")
        text = "\n".join(lines)
        return text[:max_chars]


_STOPWORDS = frozenset(
    "the a an and or of to in for on with is are was were be been by as at "
    "from that this it its into over under their there here how what when "
    "which who whom whose than then also such can will would should could "
    .split()
)
