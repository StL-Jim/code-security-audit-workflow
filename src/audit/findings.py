"""
Finding parsing, deterministic risk scoring, and registry merge.

Workers emit findings as a sequence of YAML documents (--- separated). This
module parses them, computes the risk score in Python (the LLM supplies the
qualitative factors; the arithmetic is deterministic here), assigns stable IDs,
and merges into the global findings_registry.md.
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

from .models import FINDING_FIELDS, SEVERITIES

# --- Risk scoring scales (from the prompt's RISK SCORING section) -----------

SEVERITY_SCORE = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
CONFIDENCE_SCORE = {"high": 1.0, "medium": 0.7, "low": 0.4}
BLAST_SCORE = {
    "global": 10, "cross-service": 7, "service-wide": 5,
    "partition": 3, "module": 3, "local": 1,
}
EXPLOIT_BASE = {
    "trivial": 10, "easy": 7, "moderate": 4, "difficult": 2, "theoretical": 1,
}
EXPOSURE_MODIFIER = {
    "internet-facing": 1.0, "hybrid": 0.8, "internal": 0.6, "unknown": 1.0,
}


def compute_score(sev: str, conf: str, scope: str, exploit: str,
                  exposure: str) -> int:
    """risk_score = (severity x confidence x blast x exploitability) / 10, capped 0-100."""
    s = SEVERITY_SCORE.get((sev or "").strip().lower(), 4)
    c = CONFIDENCE_SCORE.get((conf or "").strip().lower(), 0.7)
    b = BLAST_SCORE.get((scope or "").strip().lower(), 3)
    e_base = EXPLOIT_BASE.get((exploit or "").strip().lower(), 4)
    mod = EXPOSURE_MODIFIER.get((exposure or "").strip().lower(), 1.0)
    raw = (s * c * b * (e_base * mod)) / 10.0
    return max(0, min(100, round(raw)))


def severity_rank(sev: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get((sev or "").strip().lower(), 5)


def _extract_yaml_docs(text: str) -> str:
    """Pull YAML out of a model response that may wrap it in ```yaml fences."""
    blocks = re.findall(r"```(?:ya?ml)?\s*\n(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if blocks:
        return "\n---\n".join(b.strip() for b in blocks)
    return text.strip()


# Inline scalar line: `key: value` at column 0, value on the same line and not a
# block-scalar opener (| or >). These are the lines that break YAML when the
# value starts with a reserved indicator (backtick, *, &, !, etc.) or contains
# ": ". Indented lines (block-scalar content) are never touched.
_INLINE_SCALAR = re.compile(r"^([A-Za-z_][\w]*):[ \t]+(?![|>])(\S.*)$")


def _repair_doc(chunk: str) -> str:
    """Quote inline scalar values so reserved characters don't break parsing."""
    out = []
    for line in chunk.splitlines():
        m = _INLINE_SCALAR.match(line)
        if m:
            key, val = m.group(1), m.group(2).rstrip()
            # leave already-quoted values alone
            if not (len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]):
                esc = val.replace("\\", "\\\\").replace('"', '\\"')
                line = f'{key}: "{esc}"'
        out.append(line)
    return "\n".join(out)


def _split_docs(payload: str) -> list[str]:
    """Split a multi-document YAML payload on lines that are exactly `---`."""
    chunks, current = [], []
    for line in payload.splitlines():
        if line.strip() == "---":
            if current:
                chunks.append("\n".join(current))
                current = []
            continue
        current.append(line)
    if current:
        chunks.append("\n".join(current))
    return [c for c in chunks if c.strip()]


def _load_one(chunk: str):
    """Load a single YAML document, repairing inline-scalar hazards on failure."""
    try:
        return yaml.safe_load(chunk)
    except yaml.YAMLError:
        pass
    try:
        return yaml.safe_load(_repair_doc(chunk))
    except yaml.YAMLError:
        return None


def parse_findings(text: str) -> list[dict]:
    """Parse worker output into finding dicts. Per-document and fault-tolerant:
    one malformed finding never discards the rest."""
    payload = _extract_yaml_docs(text)
    findings: list[dict] = []
    for chunk in _split_docs(payload):
        doc = _load_one(chunk)
        items = doc if isinstance(doc, list) else [doc]
        for item in items:
            if isinstance(item, dict) and (item.get("title") or item.get("issue")):
                findings.append({k: item.get(k) for k in FINDING_FIELDS})
    return findings


class FindingsRegistry:
    """Owns findings_registry.md: assigns IDs, scores, dedupes, persists."""

    def __init__(self, registry_path: Path, exposure: str):
        self.path = registry_path
        self.exposure = exposure
        self.findings: list[dict] = []
        self._seq = 0
        self._date = datetime.now().strftime("%Y%m%d")
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        try:
            docs = list(yaml.safe_load_all(self.path.read_text(encoding="utf-8")))
        except yaml.YAMLError:
            docs = []
        for doc in docs:
            if isinstance(doc, dict) and doc.get("id"):
                self.findings.append(doc)
                m = re.search(r"-(\d+)$", str(doc["id"]))
                if m:
                    self._seq = max(self._seq, int(m.group(1)))

    def _next_id(self) -> str:
        self._seq += 1
        return f"F-{self._date}-{self._seq:03d}"

    def add(self, raw: dict, pid: str) -> dict:
        f = {k: raw.get(k) for k in FINDING_FIELDS}
        if not f.get("id"):
            f["id"] = self._next_id()
        if not f.get("pid"):
            f["pid"] = pid
        f["score"] = compute_score(
            f.get("sev", ""), f.get("conf", ""), f.get("scope", ""),
            f.get("exploit", ""), self.exposure,
        )
        if not f.get("status"):
            f["status"] = "open"
        self.findings.append(f)
        return f

    def add_many(self, raws: list[dict], pid: str) -> list[dict]:
        return [self.add(r, pid) for r in raws]

    def sorted_findings(self) -> list[dict]:
        return sorted(
            self.findings,
            key=lambda f: (severity_rank(f.get("sev", "")), -int(f.get("score") or 0)),
        )

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        out = [
            "# Findings Registry\n",
            f"# Exposure: {self.exposure} | Findings: {len(self.findings)}\n",
            f"# Updated: {datetime.now().isoformat(timespec='seconds')}\n\n",
        ]
        for f in self.sorted_findings():
            clean = {k: v for k, v in f.items() if v is not None}
            out.append("---\n")
            out.append(yaml.safe_dump(clean, sort_keys=False, allow_unicode=False,
                                      default_flow_style=False, width=100))
            out.append("\n")
        self.path.write_text("".join(out), encoding="utf-8")

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            sev = (f.get("sev") or "").strip().capitalize()
            if sev in counts:
                counts[sev] += 1
        return counts

    def by_threat_match(self, value: str) -> list[dict]:
        return [f for f in self.findings if (f.get("threat_match") or "") == value]
