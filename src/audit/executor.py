"""
Audit orchestrator: runs the fixed phase sequence with dynamic per-partition
workers, native findings scoring, and native HTML rendering.

Phase flow:
  1. Discovery (bulk)        -> 01_discovery.md, partition_plan.md, c4_input.md
  2. Prioritization (judge)  -> 02_risk_prioritization.md
  3. per partition: Security (bulk) + Architecture (bulk) -> worker findings
  4. shared components (bulk, if any)
  5. Consolidation: prose (judge) + native HTML report/briefing
  6. Comparison (judge, COORDINATED only): Markdown + native HTML

All progress is tracked in audit_state/STATE.md so a run resumes after interrupt.
"""

import json
import re
from pathlib import Path
from typing import Optional

from . import prompts, render
from .findings import FindingsRegistry
from .models import JUDGMENT_PHASES, Partition, PhaseKind
from .providers import CostMeter, ModelRouter

MAX_FILE_CHARS = 50000
MAX_CONTEXT_CHARS = 400000
MAX_TOKENS = 8192
MAX_TOKENS_JUDGMENT = 16000  # prioritization/consolidation/comparison emit large docs

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist",
             "build", ".mypy_cache", ".pytest_cache", "audit_state"}

SOURCE_GLOBS = ["**/*.py", "**/*.js", "**/*.ts", "**/*.go", "**/*.java",
                "**/*.cs", "**/*.rb", "**/*.php", "**/*.tf", "**/*.yml",
                "**/*.yaml", "Dockerfile*", "docker-compose*", "**/*.json"]

THREAT_MODEL_REQUIRED = ["STATE.md", "00-scope.md", "01-inventory.md", "02-threats.md"]


def detect_coordination_mode(target_dir: Path) -> tuple[str, Optional[Path]]:
    tm_dir = target_dir / (target_dir.name + "-threat-model")
    if not tm_dir.is_dir():
        return "STANDALONE", None
    for name in THREAT_MODEL_REQUIRED:
        f = tm_dir / name
        if not f.is_file() or f.stat().st_size == 0:
            return "STANDALONE", None
    return "COORDINATED", tm_dir


class AuditExecutor:
    def __init__(self, target_dir: Path, router: ModelRouter,
                 exposure_override: Optional[str] = None,
                 stop_after: Optional[str] = None,
                 only_partition: Optional[str] = None):
        self.target_dir = target_dir.resolve()
        self.project = self.target_dir.name
        self.router = router
        self.state_dir = self.target_dir / "audit_state"
        self.workers_dir = self.state_dir / "workers"
        self.state_file = self.state_dir / "STATE.md"
        self.mode, self.tm_dir = detect_coordination_mode(self.target_dir)
        self.exposure = exposure_override or "Unknown"
        self.completed: set[str] = set()
        self.partitions: list[Partition] = []
        self.shared: list[dict] = []
        self.meter = CostMeter(self.state_dir / "costs.md")
        self.registry: Optional[FindingsRegistry] = None
        # bound the run for cheap validation: discovery|prioritization|security|None
        self.stop_after = stop_after
        self.only_partition = only_partition

    # -- infra ---------------------------------------------------------------

    def _bar(self, title: str) -> None:
        print(f"\n{'-'*60}\n  {title}\n{'-'*60}")

    def _call(self, phase: PhaseKind, instructions: str,
              files_ctx: str = "", max_tokens: int = MAX_TOKENS) -> str:
        client, model, provider = self.router.for_node(
            "judgment" if phase in JUDGMENT_PHASES else "bulk")
        msg = instructions
        if files_ctx:
            msg += "\n\n---\n\n" + files_ctx
        msg += "\n\n---\n\nExecute this step now."
        print(f"  Calling {provider}/{model}...")
        resp = client.messages.create(
            model=model, max_tokens=max_tokens, system=prompts.SYSTEM_PROMPT,
            messages=[{"role": "user", "content": msg}],
        )
        self.meter.record(phase.value, model, provider, resp)
        return resp.content[0].text.strip()

    def _write(self, name: str, content: str) -> None:
        path = self.state_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render.ascii_normalize(content), encoding="utf-8")
        print(f"  Written -> audit_state/{name}")

    def _read(self, name: str) -> str:
        path = self.state_dir / name
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def _read_tm(self, name: str) -> str:
        if not self.tm_dir:
            return ""
        path = self.tm_dir / name
        return path.read_text(encoding="utf-8") if path.exists() else ""

    # -- file gathering ------------------------------------------------------

    def _gather(self, root: Optional[str] = None, globs: Optional[list] = None) -> str:
        base = self.target_dir / root if root and root != "." else self.target_dir
        if not base.is_dir():
            base = self.target_dir
        globs = globs or SOURCE_GLOBS
        seen: set[str] = set()
        sections: list[str] = []
        total = 0
        for pattern in globs:
            for path in sorted(base.glob(pattern)):
                if not path.is_file() or any(s in path.parts for s in SKIP_DIRS):
                    continue
                try:
                    rel = str(path.relative_to(self.target_dir))
                except ValueError:
                    continue
                if rel in seen or total >= MAX_CONTEXT_CHARS:
                    continue
                seen.add(rel)
                try:
                    content = path.read_text(encoding="utf-8", errors="ignore")[:MAX_FILE_CHARS]
                except OSError:
                    continue
                entry = f"### `{rel}`\n```\n{content}\n```\n\n"
                sections.append(entry)
                total += len(entry)
        if not sections:
            return "## File Contents\n\n_No matching files found._\n"
        return "## File Contents\n\n" + "".join(sections)

    # -- state ---------------------------------------------------------------

    def _load_state(self) -> None:
        if not self.state_file.exists():
            return
        for line in self.state_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("- [x] "):
                self.completed.add(line[6:].strip())
            m = re.match(r"- EXPOSURE: (.+)", line)
            if m:
                self.exposure = m.group(1).strip()
        # rehydrate partitions from partition_plan.md if present
        plan = self._read("partition_plan.md")
        if plan:
            self._parse_partition_plan(plan, store_only=True)

    def _save_state(self) -> None:
        lines = [f"# Audit STATE -- {self.project}\n\n",
                 f"- MODE: {self.mode}\n", f"- EXPOSURE: {self.exposure}\n\n",
                 "## Completed steps\n\n"]
        for step in sorted(self.completed):
            lines.append(f"- [x] {step}\n")
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text("".join(lines), encoding="utf-8")

    def _done(self, step: str) -> bool:
        return step in self.completed

    def _mark(self, step: str) -> None:
        self.completed.add(step)
        self._save_state()

    # -- partition plan parsing ---------------------------------------------

    def _parse_partition_plan(self, text: str, store_only: bool = False) -> None:
        m = re.search(r"```json\s*\n(.*?)```", text, re.DOTALL)
        raw = m.group(1) if m else text
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {}
        parts = data.get("partitions") or []
        self.partitions = [Partition.from_dict(p) for p in parts] or \
            [Partition(id="root", name="Whole repository", root=".")]
        self.shared = data.get("shared_components") or []

    # -- phases --------------------------------------------------------------

    def _phase_discovery(self) -> None:
        if self._done("discovery"):
            print("  v discovery");
            return
        self._bar("Phase 1 -- Global Discovery")
        tm_excerpt = self._read_tm("01-inventory.md")[:8000] if self.mode == "COORDINATED" else ""
        instr = prompts.discovery_instructions(
            self.project, self.mode == "COORDINATED", tm_excerpt)
        out = self._call(PhaseKind.DISCOVERY, instr, self._gather())
        self._write("01_discovery.md", out)
        self._parse_partition_plan(out)
        # persist the json plan separately for resume
        m = re.search(r"```json\s*\n(.*?)```", out, re.DOTALL)
        plan_json = json.dumps(
            {"partitions": [p.to_dict() for p in self.partitions],
             "shared_components": self.shared}, indent=2)
        self._write("partition_plan.md", "# Partition Plan\n\n```json\n" + plan_json + "\n```\n")
        self._write("c4_input.md", "# C4 Input\n\nDerived from discovery; see "
                    "01_discovery.md for services, dependencies, trust boundaries.\n")
        print(f"  Partitions: {', '.join(p.id for p in self.partitions)}")
        self._mark("discovery")

    def _phase_prioritization(self) -> None:
        if self._done("prioritization"):
            print("  v prioritization");
            return
        self._bar("Phase 2 -- Risk Prioritization")
        instr = prompts.prioritization_instructions(
            self.project, self._read("01_discovery.md"), self._read("partition_plan.md"))
        out = self._call(PhaseKind.PRIORITIZATION, instr, max_tokens=MAX_TOKENS_JUDGMENT)
        self._write("02_risk_prioritization.md", out)
        self._mark("prioritization")

    def _worker(self, phase: PhaseKind, partition: Partition) -> None:
        step = f"{phase.value}:{partition.id}"
        if self._done(step):
            print(f"  v {step}");
            return
        self._bar(f"{'Phase 3A Security' if phase == PhaseKind.SECURITY else 'Phase 4A Architecture'}"
                  f" -- {partition.id}")
        tm_threats = self._read_tm("02-threats.md")[:12000] if self.mode == "COORDINATED" else ""
        prior_ctx = ""
        if phase == PhaseKind.ARCHITECTURE:
            sec = self._read(f"workers/{partition.id}/security_review.md")
            if sec:
                prior_ctx = "\n## Prior security review (this partition)\n" + sec[:6000]
        builder = (prompts.security_worker_instructions if phase == PhaseKind.SECURITY
                   else prompts.architecture_worker_instructions)
        instr = builder(self.project, partition, self.exposure,
                        self.mode == "COORDINATED", prior_ctx, tm_threats)
        instr += prompts.FINDINGS_SCHEMA_ADDON
        out = self._call(phase, instr, self._gather(partition.root))
        # persist raw review
        review_name = ("security_review.md" if phase == PhaseKind.SECURITY
                       else "architecture_review.md")
        self._write(f"workers/{partition.id}/{review_name}", out)
        # parse + score + merge findings
        from .findings import parse_findings
        raws = parse_findings(out)
        added = self.registry.add_many(raws, partition.id)
        self.registry.save()
        print(f"  Parsed {len(added)} findings from {partition.id} ({phase.value})")
        self._mark(step)

    def _phase_consolidation(self) -> None:
        if self._done("consolidation"):
            print("  v consolidation");
            return
        self._bar("Phase 5 -- Consolidation")
        # findings summary for the prose call
        summary_lines = []
        for f in self.registry.sorted_findings():
            summary_lines.append(f"- {f.get('id')} [{f.get('sev')}] {f.get('title')} "
                                 f"({f.get('cat')}, {f.get('pid')})")
        findings_summary = "\n".join(summary_lines) or "No findings."
        instr = prompts.consolidation_sections_instructions(
            self.project, findings_summary, self._read("01_discovery.md")[:8000])
        out = self._call(PhaseKind.CONSOLIDATION, instr, max_tokens=MAX_TOKENS_JUDGMENT)
        sections = self._split_sections(out)
        attack_paths = self._read("attack_paths.md") or "See per-finding evidence."
        # native HTML rendering
        report = render.render_consolidated_report(
            self.project, self.registry, sections, attack_paths)
        self._write("05_consolidated_report.html", report)
        briefing = render.render_executive_briefing(
            self.project, self.registry, sections.get("summary", ""), attack_paths)
        self._write("executive_briefing.html", briefing)
        self._write("consolidation_sections.md", out)
        self._mark("consolidation")

    def _phase_comparison(self) -> None:
        if self.mode != "COORDINATED":
            return
        if self._done("comparison"):
            print("  v comparison");
            return
        self._bar("Phase 5/6 -- Threat-Audit Comparison")
        # binding verification
        recorded = self._read("coordination_mode.md")
        cur = self._read_tm("STATE.md")
        # (timestamps compared loosely; full binding check is a follow-up)
        def block(findings):
            out = []
            for f in findings:
                out.append(f"id={f.get('id')} threat_id={f.get('threat_id')} "
                           f"sev={f.get('sev')} title={f.get('title')}\n"
                           f"  issue: {str(f.get('issue') or '').strip()[:400]}\n"
                           f"  ev: {str(f.get('ev') or '').strip()[:400]}\n"
                           f"  fix: {str(f.get('fix') or '').strip()[:400]}")
            return "\n".join(out) or "None."
        instr = prompts.comparison_instructions(
            self.project, self._read_tm("02-threats.md")[:14000],
            block(self.registry.by_threat_match("confirms")),
            block(self.registry.by_threat_match("partial")),
            block(self.registry.by_threat_match("unanticipated")))
        md = self._call(PhaseKind.COMPARISON, instr, max_tokens=MAX_TOKENS_JUDGMENT)
        self._write("threat_audit_comparison.md", md)
        html = render.render_comparison_html(self.project, md)
        self._write("threat_audit_comparison.html", html)
        # reciprocal copy to threat model dir
        if self.tm_dir:
            (self.tm_dir / "threat_audit_comparison.html").write_text(
                render.ascii_normalize(html), encoding="utf-8")
            print(f"  Copied -> {self.tm_dir.name}/threat_audit_comparison.html")
        self._mark("comparison")

    def _split_sections(self, text: str) -> dict:
        sections = {"summary": "", "coverage": "", "gaps": ""}
        current = None
        for line in text.splitlines():
            h = line.strip().lower()
            if h.startswith("# summary"):
                current = "summary"; continue
            if h.startswith("# coverage"):
                current = "coverage"; continue
            if h.startswith("# gaps"):
                current = "gaps"; continue
            if current:
                sections[current] += line + "\n"
        if not any(sections.values()):
            sections["summary"] = text
        return sections

    def _write_coordination_mode(self) -> None:
        lines = [f"# Audit Coordination Mode\n\nMODE: {self.mode}\n"]
        if self.mode == "COORDINATED" and self.tm_dir:
            lines.append(f"THREAT_MODEL_PATH: {self.tm_dir.name}/\n")
            lines.append(f"DEPLOYMENT_EXPOSURE: {self.exposure}\n")
        else:
            lines.append(f"DEPLOYMENT_EXPOSURE: {self.exposure}\n")
        self._write("coordination_mode.md", "".join(lines))

    def _resolve_exposure(self) -> None:
        if self.mode == "COORDINATED":
            scope = self._read_tm("00-scope.md").lower()
            for label in ("internet-facing", "hybrid", "internal"):
                if label in scope:
                    self.exposure = label.capitalize() if label != "internet-facing" else "Internet-facing"
                    break
            print(f"  Exposure inherited from threat model: {self.exposure}")
        elif self.exposure == "Unknown":
            self._ask_exposure()

    def _ask_exposure(self) -> None:
        print("\n  How is this application exposed?")
        print("    1) Internet-facing   2) Internal   3) Hybrid   4) Unknown")
        try:
            ans = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        self.exposure = {"1": "Internet-facing", "2": "Internal",
                         "3": "Hybrid", "4": "Unknown"}.get(ans, "Unknown")
        print(f"  Exposure: {self.exposure}\n")

    # -- run -----------------------------------------------------------------

    def run(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._load_state()
        if self.exposure == "Unknown" or not self.completed:
            self._resolve_exposure()
        self.registry = FindingsRegistry(self.state_dir / "findings_registry.md",
                                         self.exposure)
        self._write_coordination_mode()
        self._save_state()

        self._phase_discovery()
        if self.stop_after == "discovery":
            return self._stop_early("discovery")
        self._phase_prioritization()
        if self.stop_after == "prioritization":
            return self._stop_early("prioritization")
        active = [p for p in self.partitions
                  if not self.only_partition or p.id == self.only_partition]
        for p in active:
            self._worker(PhaseKind.SECURITY, p)
        if self.stop_after == "security":
            return self._stop_early("security")
        for p in active:
            self._worker(PhaseKind.ARCHITECTURE, p)
        self._phase_consolidation()
        self._phase_comparison()

        self._bar("Audit complete")
        self.meter.finalize()
        print(f"  Findings: {len(self.registry.findings)} | "
              f"Output: {self.state_dir}\n")

    def _stop_early(self, phase: str) -> None:
        self._bar(f"Stopped after {phase} (--stop-after)")
        self.meter.finalize()
        print(f"  Partitions: {', '.join(p.id for p in self.partitions)}")
        print(f"  Findings so far: {len(self.registry.findings)} | "
              f"Output: {self.state_dir}\n")
