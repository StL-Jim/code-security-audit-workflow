"""Data models for the audit workflow: phases, partitions, findings."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class PhaseKind(Enum):
    DISCOVERY = "discovery"          # Phase 1
    PRIORITIZATION = "prioritization"  # Phase 2
    SECURITY = "security"            # Phase 3A (per partition)
    ARCHITECTURE = "architecture"    # Phase 4A (per partition)
    SHARED = "shared"                # Phase 3B/4B
    CONSOLIDATION = "consolidation"  # Phase 5
    COMPARISON = "comparison"        # Phase 5 comparison content (COORDINATED)


# Which phases route to the judgment provider (vs bulk).
JUDGMENT_PHASES = {
    PhaseKind.PRIORITIZATION,
    PhaseKind.CONSOLIDATION,
    PhaseKind.COMPARISON,
}


@dataclass
class Partition:
    id: str
    name: str
    type: str = "service"
    root: str = "."
    entrypoints: list[str] = field(default_factory=list)
    why: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Partition":
        return cls(
            id=str(d.get("id") or d.get("name") or "partition"),
            name=str(d.get("name") or d.get("id") or "partition"),
            type=str(d.get("type", "service")),
            root=str(d.get("root", ".")),
            entrypoints=list(d.get("entrypoints", []) or []),
            why=str(d.get("why", "")),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "type": self.type,
            "root": self.root, "entrypoints": self.entrypoints, "why": self.why,
        }


# Compact finding schema (see data/input prompt FINDING SCHEMA). Stored as YAML
# documents in findings_registry.md and per-worker findings.md.
FINDING_FIELDS = [
    "id", "pid", "src", "class", "sev", "conf", "score", "cat", "sub", "title",
    "scope", "deps", "exploit", "ev", "issue", "impact", "fix", "verify",
    "status", "rel", "sup", "threat_id", "threat_match",
]

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
