# Build Status -- Code Security Audit Workflow

Sibling of `threat-modeling-workflow`. Converts the CodeSecurityAudit prompt
(`data/input/code-security-audit-prompt.txt`) into a provider-flexible,
resumable workflow:

```
python scripts/run_audit.py --target <repo> --provider minimax --judgment-provider anthropic
```

## DONE -- build complete and validated (2026-06-11)

Architecture: explicit phase-based executor (NOT an LLM-decomposed DAG -- the
audit's phases are fixed, so a hand-authored plan is more deterministic) with
dynamic per-partition worker expansion at runtime.

Modules (`src/audit/`):
- [x] `models.py` -- PhaseKind, Partition, finding field list, JUDGMENT_PHASES
- [x] `providers.py` -- PROVIDER_CONFIGS, ModelRouter (bulk vs judgment routing),
      CostMeter (per-call usage -> console + costs.md), MODEL_PRICING
- [x] `findings.py` -- fault-tolerant per-document YAML parser (recovers from
      malformed findings instead of dropping the batch), deterministic risk
      scoring with exposure modifier, FindingsRegistry (ID assignment, resume,
      severity sort, threat-match filters)
- [x] `render.py` -- ascii_normalize, md_to_html, and NATIVE HTML renderers for
      all three deliverables. Replaces the prompt's Phase 5/6 scaffold-and-fill
      entirely: "every finding appears in the report" is true by construction.
- [x] `prompts.py` -- system prompt + per-phase instruction builders + findings
      schema addon (incl. YAML-safety guidance)
- [x] `executor.py` -- orchestrator: discovery -> prioritization -> per-partition
      security+architecture -> consolidation -> comparison (COORDINATED). STATE.md
      resume, native coordination-mode detection, interactive exposure question
      (STANDALONE), per-call cost metering.
- [x] `scripts/run_audit.py` -- CLI: --provider/--judgment-provider/--model/
      --judgment-model/--exposure/--stop-after/--only-partition
- [x] `tests/test_smoke.py` -- scoring, parsing, registry+resume, rendering,
      YAML-hazard regression, partition model. All pass.

Validation (live, against a real 13-partition repo, MiniMax M3):
- [x] Phase 1 discovery: parseable prose + 13-partition JSON plan. ~$0.04.
- [x] Phase 2 prioritization + Phase 3A security worker (config partition):
      model emitted 9 conformant findings with evidence, NIST mappings, and
      correct confirms/partial/unanticipated threat cross-reference. ~$0.05.
- [x] Findings parse + score + native HTML report/briefing rendered from the
      REAL worker output (zero extra API cost): all 9 findings in the report,
      briefing correctly filtered to High+.
- Full-run cost projection: ~$0.50-1.50 on MiniMax for the whole 13-partition
      audit.

Bug found and fixed during validation: MiniMax emitted a finding whose `title`
started with a backtick (illegal plain YAML), and the original all-or-nothing
parser discarded all 10 findings. Now parses per-document with a repair pass
that quotes inline scalars; regression test added.

Also raised judgment-phase max_tokens to 16000 (prioritization truncated at the
8192 default on a 13-partition repo).

## UPDATED 2026-06-12 -- synced to revised prompts

The agent-mode prompts (GenAIPrompts) were revised 2026-06-12; this workflow
was brought in line the same day:
- data/input prompt copy re-synced to the revised code-security-audit.md.
- threat_match enum extended: promotes-inferred (Inferred-table match),
  contradicts-exclusion / excluded-by-design (Excluded Threats Ledger match);
  worker + comparison instructions teach the full matching order.
- Comparison output now severity-floor stratified (Critical/High unanticipated
  reported separately from Medium/Low/Info expected non-matches).
- 02-threats.md is now section-extracted (threat tables + Inferred + ledger)
  instead of head-sliced -- the old [:12000] slice could be consumed entirely
  by 02a context and starve the cross-reference.
- coordination_mode.md enriched (THREAT_MODEL_LAST_UPDATED, THREAT_COUNT_MAIN/
  INFERRED, EXCLUDED_LEDGER_COUNT); binding verification implemented in
  _phase_comparison (refuses comparison if the threat model changed mid-audit).
- Phase 3B/4B shared-component review implemented (_shared_worker) with the
  threat cross-reference; previously shared components were parsed and ignored.
- Secrets redaction: rule added to SYSTEM_PROMPT and a masking pass in
  _gather() before content reaches any provider.
- audit_state/ auto-added to <target>/.git/info/exclude.
- cat: ARCH allowed for non-OWASP architecture findings.
- Classification marking is user-supplied via --classification (default
  "Internal Use Only"), no longer hard-coded.

## NOT YET DONE (next session, optional)

1. One full end-to-end run (all 13 partitions + shared components +
   consolidation + comparison) to produce the complete deliverable set and a
   real total in costs.md. ~$1 on MiniMax. Everything it exercises has been
   validated piecewise, but the 2026-06-12 changes are live-untested.
2. Live test of consolidation prose + COORDINATED comparison Markdown (the
   renderers they feed are proven; only the LLM prose calls are live-untested).
3. C4_architecture.md generation from c4_input.md (currently a stub file is
   written; the Mermaid generation step is not implemented).
4. security_architecture_audit.md idempotent cross-run log (not implemented).
   When built, follow the revised prompt: match cross-run findings by the
   stable content key (pid + src file + sub + normalized title), update in
   place, never key on the date-based finding id.
5. attack_paths.md is never produced (consolidation falls back to a
   placeholder). The revised prompt now defines an AP-NNN schema; implement
   generation against it.
6. Optional: copy `app.py` Streamlit refiner from the threat repo if a
   partition-plan review UI is wanted.
7. Verify MiniMax-M3 real pricing and update MODEL_PRICING in providers.py
   (currently MiniMax-M2 list price as placeholder).

## Design decisions (locked)

- Sibling repo, not a generalization of threat-modeling-workflow.
- Default bulk provider minimax; judgment phases optionally routed to anthropic.
- No aggregate security grades/scores; no remediation time estimates.
- ASCII-only generated output.
- Native Python rendering for all HTML (no agent budget discipline needed).
