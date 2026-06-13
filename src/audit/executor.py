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
                 only_partition: Optional[str] = None,
                 classification: str = "Internal Use Only"):
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
        # User-supplied classification marking for report headers/footers (the
        # agent-mode prompt forbids inventing org-specific markings).
        self.classification = classification or "Internal Use Only"

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

    def _tm_threat_sections(self, max_chars: int = 30000) -> str:
        """Extract the threat-bearing sections of 02-threats.md (main threat
        table, Inferred Threats, Excluded Threats Ledger) instead of naively
        slicing the file head. 02-threats.md = header + 02a context + 02b
        threats + 02c assumptions; a head slice can be consumed entirely by
        the 02a asset/flow tables and never reach a single threat, which would
        make every finding 'unanticipated'."""
        full = self._read_tm("02-threats.md")
        if not full:
            return ""
        keep = re.compile(r"threat table|threats|inferred|excluded threats ledger",
                          re.IGNORECASE)
        sections: list[str] = []
        current: list[str] = []
        keeping = False
        for line in full.splitlines():
            if line.startswith("#"):
                if keeping and current:
                    sections.append("\n".join(current))
                current = [line]
                keeping = bool(keep.search(line))
            elif keeping:
                current.append(line)
        if keeping and current:
            sections.append("\n".join(current))
        out = "\n\n".join(sections)
        if not out.strip():
            out = full  # fallback: no matching headings, send what we have
        return out[:max_chars]

    def _tm_state_timestamp(self) -> str:
        m = re.search(r"^LAST_UPDATED:\s*(.+)$", self._read_tm("STATE.md"),
                      re.MULTILINE)
        return m.group(1).strip() if m else ""

    # -- file gathering ------------------------------------------------------

    # Secret redaction before file content is sent to any LLM provider (the
    # default bulk provider is third-party). Mirrors the SECRETS REDACTION rule
    # in the agent-mode prompts: keep the first 4 chars, mask the rest.
    _SECRET_LINE = re.compile(
        r"(?i)^(\s*[\"']?[\w.\-]*(password|passwd|secret|token|api[_-]?key|apikey|"
        r"access[_-]?key|private[_-]?key|client[_-]?secret|connection[_-]?string)"
        r"[\w.\-]*[\"']?\s*[:=]\s*)(.+)$")
    _SECRET_VALUE = re.compile(
        r"(sk-[A-Za-z0-9_\-]{8,}|AKIA[0-9A-Z]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|"
        r"xox[baprs]-[A-Za-z0-9\-]{10,})")

    @staticmethod
    def _mask_secret(val: str) -> str:
        v = val.strip().strip("\"',;")
        return "****" if len(v) <= 8 else v[:4] + "****"

    def _redact_secrets(self, text: str) -> str:
        out: list[str] = []
        in_pem = False
        for line in text.splitlines():
            if "-----BEGIN" in line and "PRIVATE KEY" in line:
                in_pem = True
                out.append(line)
                continue
            if in_pem:
                if "-----END" in line:
                    in_pem = False
                    out.append(line)
                else:
                    out.append("    [REDACTED PRIVATE KEY MATERIAL]")
                continue
            m = self._SECRET_LINE.match(line)
            if m and m.group(3).strip() not in ("", "''", '""', "null", "None", "***"):
                line = m.group(1) + self._mask_secret(m.group(3))
            else:
                line = self._SECRET_VALUE.sub(
                    lambda mm: self._mask_secret(mm.group(0)), line)
            out.append(line)
        return "\n".join(out)

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
                    content = self._redact_secrets(
                        path.read_text(encoding="utf-8", errors="ignore")[:MAX_FILE_CHARS])
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

    def _git_exclude_state_dir(self) -> None:
        """Add audit_state/ to <target>/.git/info/exclude (repo-local,
        un-committed) so findings and secret locations can't be accidentally
        committed. Mirrors the threat modeling prompt's technique."""
        exclude = self.target_dir / ".git" / "info" / "exclude"
        if not exclude.parent.is_dir():
            return
        try:
            current = exclude.read_text(encoding="utf-8") if exclude.exists() else ""
            if "audit_state/" not in current:
                with open(exclude, "a", encoding="utf-8") as f:
                    f.write("\n# Added by code-security-audit-workflow\naudit_state/\n")
                print("  Added audit_state/ to .git/info/exclude")
        except OSError as err:
            print(f"  WARNING: could not update .git/info/exclude: {err}")

    def _worker(self, phase: PhaseKind, partition: Partition) -> None:
        step = f"{phase.value}:{partition.id}"
        if self._done(step):
            print(f"  v {step}");
            return
        self._bar(f"{'Phase 3A Security' if phase == PhaseKind.SECURITY else 'Phase 4A Architecture'}"
                  f" -- {partition.id}")
        tm_threats = self._tm_threat_sections(20000) if self.mode == "COORDINATED" else ""
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

    def _shared_worker(self, shared: dict) -> None:
        """Phase 3B/4B -- shared component review. Previously discovery parsed
        shared_components but nothing ever reviewed them; their findings also
        need the threat cross-reference in COORDINATED mode or the Phase 5
        comparison counts don't reconcile."""
        part = Partition.from_dict(shared)
        step = f"shared:{part.id}"
        if self._done(step):
            print(f"  v {step}")
            return
        self._bar(f"Phase 3B/4B Shared Component -- {part.id}")
        tm_threats = self._tm_threat_sections(20000) if self.mode == "COORDINATED" else ""
        prior_ctx = (
            "\nThis is a SHARED COMPONENT used by multiple services: weigh blast "
            "radius accordingly (deps: shared) and assess architecture concerns "
            "(coupling, failure modes) alongside security in the same pass.\n")
        instr = prompts.security_worker_instructions(
            self.project, part, self.exposure, self.mode == "COORDINATED",
            prior_ctx, tm_threats)
        instr += prompts.FINDINGS_SCHEMA_ADDON
        out = self._call(PhaseKind.SHARED, instr, self._gather(part.root))
        self._write(f"workers/shared-{part.id}/shared_review.md", out)
        from .findings import parse_findings
        raws = parse_findings(out)
        added = self.registry.add_many(raws, f"shared-{part.id}")
        self.registry.save()
        print(f"  Parsed {len(added)} findings from shared component {part.id}")
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
            self.project, self.registry, sections, attack_paths,
            classification=self.classification)
        self._write("05_consolidated_report.html", report)
        briefing = render.render_executive_briefing(
            self.project, self.registry, sections.get("summary", ""), attack_paths,
            classification=self.classification)
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
        # Binding verification (per the agent-mode prompt): if the threat model
        # was re-run mid-audit, findings reference threats that no longer exist
        # on disk -- refuse to produce the comparison.
        m = re.search(r"^THREAT_MODEL_LAST_UPDATED:\s*(.+)$",
                      self._read("coordination_mode.md"), re.MULTILINE)
        bound = m.group(1).strip() if m else ""
        current = self._tm_state_timestamp()
        if bound and current and bound != current:
            print("\n  === BINDING ERROR: THREAT MODEL CHANGED DURING AUDIT ===")
            print(f"  Bound at Phase 1: {bound}")
            print(f"  Current:          {current}")
            print("  Re-run the audit against the current threat model, or restore")
            print("  the original threat model state from git. Comparison NOT produced.")
            return

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
            self.project, self._tm_threat_sections(20000),
            block(self.registry.by_threat_match("confirms")),
            block(self.registry.by_threat_match("partial")),
            block(self.registry.by_threat_match("unanticipated")),
            promoted=block(self.registry.by_threat_match("promotes-inferred")),
            contradicts=block(self.registry.by_threat_match("contradicts-exclusion")),
            excluded_by_design=block(self.registry.by_threat_match("excluded-by-design")))
        md = self._call(PhaseKind.COMPARISON, instr, max_tokens=MAX_TOKENS_JUDGMENT)
        self._write("threat_audit_comparison.md", md)
        html = render.render_comparison_html(self.project, md,
                                             classification=self.classification)
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

    def _count_tm_threats(self) -> tuple[int, int, int]:
        """Count main-table threats, Inferred threats, and Excluded Threats
        Ledger rows in 02-threats.md (best effort, table-row heuristics)."""
        text = self._read_tm("02-threats.md")
        main = inferred = excluded = 0
        for line in text.splitlines():
            s = line.strip()
            if not s.startswith("|") or set(s.replace("|", "").replace("-", "")
                                            .replace(":", "").replace(" ", "")) == set():
                continue
            first = s.strip("|").split("|")[0].strip()
            up = first.upper()
            if up in ("THREATID", "EXCLUDEDID", "ID"):
                continue  # header row, not a data row
            if up.startswith("EX-"):
                excluded += 1
            elif up.startswith("INF"):
                inferred += 1
            elif up.startswith("THR") or re.fullmatch(r"\d{4}", first):
                main += 1
        return main, inferred, excluded

    def _write_coordination_mode(self) -> None:
        from datetime import datetime
        lines = [f"# Audit Coordination Mode\n\nMODE: {self.mode}\n",
                 f"DETECTED: {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}\n"]
        if self.mode == "COORDINATED" and self.tm_dir:
            main, inferred, excluded = self._count_tm_threats()
            # Preserve the timestamp recorded at the FIRST run of this audit:
            # it is the binding contract Phase 5 verifies. Re-recording the
            # current value on every resume would make verification vacuous.
            prev = re.search(r"^THREAT_MODEL_LAST_UPDATED:\s*(.+)$",
                             self._read("coordination_mode.md"), re.MULTILINE)
            bound = prev.group(1).strip() if prev else self._tm_state_timestamp()
            lines.append(f"THREAT_MODEL_PATH: {self.tm_dir.name}/\n")
            lines.append(f"THREAT_MODEL_LAST_UPDATED: {bound}\n")
            lines.append(f"DEPLOYMENT_EXPOSURE: {self.exposure}\n")
            lines.append(f"THREAT_COUNT_MAIN: {main}\n")
            lines.append(f"THREAT_COUNT_INFERRED: {inferred}\n")
            lines.append(f"EXCLUDED_LEDGER_COUNT: {excluded}\n")
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
        self._git_exclude_state_dir()
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
        if not self.only_partition:
            for s in self.shared:
                self._shared_worker(s)
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
