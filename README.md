# Code Security Audit Workflow

Provider-flexible, resumable security and architecture audit workflow.
Sibling project of `threat-modeling-workflow`; runs the CodeSecurityAudit
prompt (`data/input/code-security-audit-prompt.txt`) as a phased workflow
against a target codebase, writing all state and deliverables to
`<target>/audit_state/`.

STATUS: scaffold -- provider routing, cost metering, and coordination-mode
detection work; the phase executor port is pending. See PLAN.md.

## Setup

```bash
pip install -r requirements.txt
copy .env.example .env     # then add your API keys
```

## Usage (planned)

```bash
# Everything on MiniMax (cheapest)
python scripts/run_audit.py --target C:\Users\stlji\gitlab\sophia --provider minimax

# Mixed routing: bulk scanning on MiniMax, judgment nodes on Sonnet
python scripts/run_audit.py --target C:\Users\stlji\gitlab\sophia --provider minimax --judgment-provider anthropic
```

Judgment nodes = risk prioritization, threat cross-reference, consolidation,
executive briefing. Everything else (discovery, per-partition scanning) is a
bulk node.

## Coordination with the threat model

If `<target>/<target-name>-threat-model/` exists and is complete (STATE.md,
00-scope.md, 01-inventory.md, 02-threats.md), the audit runs in COORDINATED
mode: findings are cross-referenced against threats and a threat-audit
comparison deliverable is produced. Otherwise STANDALONE mode, which asks the
deployment-exposure question interactively.

## Cost tracking

Every LLM call's token usage is recorded to `<target>/audit_state/costs.md`
with estimated USD cost per node and a session total. Pricing table lives in
`src/audit/providers.py` (MODEL_PRICING) -- update it when provider pricing
changes.
