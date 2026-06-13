"""
System prompt and per-phase instruction builders.

The instruction text is distilled from data/input/code-security-audit-prompt.txt.
Phases that the prompt described as agent-driven HTML generation (Phase 5/6) are
NOT here -- Python renders those deterministically in render.py. The LLM's job in
consolidation is to produce the prose sections and the comparison Markdown only.
"""

SYSTEM_PROMPT = """You are a production-grade Security and Architecture Audit
engine. You analyze a software codebase one phase at a time, using ONLY evidence
visible in the provided files. You never invent vulnerabilities, runtime
behavior, scan results, or CVEs. Missing evidence is never proof of safety.

Output rules (strictly enforced):
1. Start directly with the requested content. No "I'll analyze...", no preamble.
2. Never wrap output in <function_calls>, <invoke>, or any XML/tool tags.
3. Write in definitive, present-tense language. No hedging ("appears to",
   "might", "TBD") unless you are explicitly flagging genuine uncertainty.
4. ASCII only: use -- for em-dash, straight quotes, -> for arrows, >= and <=.
5. When you cannot verify something that should exist, write
   "UNCERTAIN: <reason>" rather than guessing.
6. CWE references are fine; cite a CVE id ONLY if it literally appears in the
   source files provided.
7. SECRETS REDACTION (mandatory): when you find a secret value (API key,
   password, token, connection string, private key), report the file path and
   line, the key/variable name, and a masked fragment only (first 4 chars +
   ****, e.g. AKIA****). NEVER reproduce the full secret value in any finding,
   evidence block, or report -- the finding is the LOCATION of the secret, not
   the secret itself.
"""

# Worker phases must emit findings in this exact YAML shape. Python computes the
# numeric score and assigns the id, so the model leaves score blank and supplies
# the qualitative exploit rating.
FINDINGS_SCHEMA_ADDON = """

## FINDINGS OUTPUT FORMAT (mandatory)

Emit each finding as a YAML document. Separate multiple findings with a line
containing only `---`. Emit ONLY the YAML documents, nothing else. Use this
schema exactly (omit a field only if truly not applicable):

---
pid: <partition id, provided below>
src: <file:line, e.g. src/auth/login.py:45-52>
class: Confirmed | Suspected | Not Assessable
sev: Critical | High | Medium | Low | Info
conf: High | Medium | Low
cat: <OWASP, e.g. A01:2021; use ARCH for architecture findings with no meaningful OWASP mapping>
sub: <subcategory, e.g. IDOR, SQL Injection; for ARCH e.g. Tight Coupling, Missing Bulkhead>
title: <<=80 chars>
scope: local | module | service-wide | cross-service | global
deps: local | shared | boundary-crossing
exploit: Trivial | Easy | Moderate | Difficult | Theoretical
ev: |
  <evidence: file:line, code snippets, grep output -- concrete anchors only>
issue: |
  <technical description of the defect>
impact: |
  <security/business impact>
fix: |
  <specific remediation steps>
verify: |
  <how to confirm the fix works>
status: open
threat_id: <COORDINATED only: matching threat id (0001-style, INF-/THR- prefixed, or EX-NNN for ledger matches), else omit>
threat_match: <COORDINATED only: confirms | partial | promotes-inferred | contradicts-exclusion | excluded-by-design | unanticipated, else omit>

YAML safety: if a single-line value (title, sub, src, etc.) starts with a
backtick, quote, asterisk, or contains a colon-space, wrap the whole value in
double quotes. Prefer block scalars (`|`) for ev/issue/impact/fix/verify so code
and punctuation are literal.

Do NOT compute the numeric risk score; leave it out. Do NOT assign the id.
If you find no issues in scope, output exactly: `# NO FINDINGS`
"""


def discovery_instructions(project: str, coordinated: bool, tm_excerpt: str) -> str:
    coord = ""
    if coordinated:
        coord = (
            "\nCOORDINATED MODE: a threat model exists. Treat its inventory as "
            "authoritative; confirm and extend rather than rebuild. Threat model "
            f"inventory excerpt:\n\n{tm_excerpt}\n"
        )
    return f"""PHASE 1 -- GLOBAL DISCOVERY for project `{project}`.

Scan the provided files and produce a discovery report in Markdown covering:
- repository type (monolith | monorepo | multi-service) and structure
- detected languages, runtimes, frameworks
- services / packages / modules and their entrypoints
- data stores, queues, external integrations
- auth/authz patterns, config and secret-loading patterns
- CI/CD, Docker, Kubernetes, Terraform, Helm if present
- trust boundaries and high-risk zones
- unknowns / gaps
{coord}
Then, at the very end, emit a fenced ```json block with the partition plan:

```json
{{"repo_type": "monolith|monorepo|multi-service",
  "partitions": [
    {{"id": "kebab-id", "name": "Human name", "type": "service|module|app",
      "root": "relative/path", "entrypoints": ["..."], "why": "why a partition"}}
  ],
  "shared_components": [
    {{"id": "kebab-id", "name": "Human name", "root": "relative/path",
      "why": "why security-critical"}}
  ]}}
```

Partition rules: create a partition per deployable service; for a small monolith
use a single partition with id "root" and root ".". Each partition should be
reviewable in ~5,000-10,000 tokens. Keep the JSON valid and ASCII-only."""


def prioritization_instructions(project: str, discovery_md: str,
                                partition_plan: str) -> str:
    return f"""PHASE 2 -- GLOBAL RISK PRIORITIZATION for `{project}`.

Using the discovery report and partition plan below, produce a Markdown report
that ranks partitions by exposure, blast radius, and likely defect density, and
within the top partitions names the exact files and interfaces that warrant the
deepest inspection. Be specific about file paths.

## Discovery
{discovery_md}

## Partition plan
{partition_plan}"""


def security_worker_instructions(project: str, partition, exposure: str,
                                 coordinated: bool, prior_ctx: str,
                                 tm_threats: str) -> str:
    coord = ""
    if coordinated:
        coord = (
            "\nCOORDINATED MODE: after forming each finding, cross-reference it "
            "against the threat model content below. It contains up to three "
            "matchable structures: the MAIN threat table (Confirmed/Likely), the "
            "INFERRED threats table (unverified, with a WhatWouldConfirm column), "
            "and the EXCLUDED THREATS LEDGER (EX-NNN rows of considered-but-"
            "excluded candidates; may be absent in older threat models). Scan in "
            "this order and stop at the first qualifying match:\n"
            "1. MAIN strong match (same component+OWASP, content aligns) -> "
            "threat_match: confirms\n"
            "2. MAIN partial match (same component, related concern) -> "
            "threat_match: partial\n"
            "3. INFERRED strong match where your finding answers the threat's "
            "WhatWouldConfirm question -> threat_match: promotes-inferred (high "
            "value: the audit completes verification the model could not)\n"
            "4. LEDGER match where the Exclusion Reason begins 'Fully mitigated' "
            "-> threat_match: contradicts-exclusion, threat_id: the EX-NNN id "
            "(highest value: the mitigation judgment was wrong). LEDGER match "
            "with any other exclusion reason -> threat_match: excluded-by-design\n"
            "5. No match anywhere -> threat_match: unanticipated\n"
            "Set threat_id to the matched id, or omit for unanticipated. Do NOT "
            "invent new threats.\n\n"
            f"## Threat model threats\n{tm_threats}\n"
        )
    return f"""PHASE 3A -- SECURITY REVIEW of partition `{partition.id}`
({partition.name}, root: {partition.root}) for project `{project}`.

Deployment exposure: {exposure}. Review ONLY this partition's code plus directly
relevant shared/trust-boundary files. Analyze against OWASP Top Ten 2021
(A01-A10) and map each finding to NIST 800-53r5 control families (AC, IA, SC,
SI, AU, CM, etc.) in the issue/fix text. Cover: broken access control / IDOR,
crypto failures and secrets, injection (SQL/NoSQL/OS/LDAP/XSS/template),
insecure design, misconfiguration, vulnerable components, auth/session failures,
integrity/deserialization, logging/monitoring gaps, SSRF. Also check input
validation, error handling, and race conditions.
{coord}{prior_ctx}"""


def architecture_worker_instructions(project: str, partition, exposure: str,
                                     coordinated: bool, prior_ctx: str,
                                     tm_threats: str) -> str:
    coord = ""
    if coordinated:
        coord = (
            "\nCOORDINATED MODE: cross-reference each architecture finding against "
            "the threat model content below using the same matching order as the "
            "security review: confirms / partial (main table), promotes-inferred "
            "(Inferred table), contradicts-exclusion / excluded-by-design "
            "(Excluded Threats Ledger), unanticipated (no match).\n\n"
            f"## Threat model threats\n{tm_threats}\n"
        )
    return f"""PHASE 4A -- ARCHITECTURE + FUNCTIONAL REVIEW of partition
`{partition.id}` ({partition.name}, root: {partition.root}) for `{project}`.

Deployment exposure: {exposure}. Review ONLY this partition plus directly
relevant shared/boundary files. Analyze: coupling/cohesion, dependency
direction, boundary violations, shared-state risks, error handling,
resilience/failure modes, race conditions, edge cases, operational fragility.
Record each issue as a finding using the schema. Use cat: ARCH for findings
with no meaningful OWASP mapping -- do not force-fit an OWASP category onto a
non-security architecture finding.
{coord}{prior_ctx}"""


def consolidation_sections_instructions(project: str, findings_summary: str,
                                        discovery_md: str) -> str:
    return f"""PHASE 5 -- CONSOLIDATION PROSE for `{project}`.

The findings registry is built and scored separately; you do NOT list findings
here. Produce three Markdown sections separated by these exact headers:

# SUMMARY
A 1-2 paragraph executive summary of the audit: what was reviewed, the overall
shape of the findings (by severity, drawn from the counts below), and the most
important themes. Do NOT assign an aggregate security grade or score. Do NOT
propose a remediation schedule or time estimates.

# COVERAGE
Partition coverage: which partitions were reviewed and any areas not deeply
examined.

# GAPS
Evidence gaps: what could not be determined from code alone and would need
runtime/config/environment access to assess.

## Findings summary (counts and titles)
{findings_summary}

## Discovery (for context)
{discovery_md}"""


def comparison_instructions(project: str, threats_md: str,
                            confirms, partials, unanticipated,
                            promoted="None.", contradicts="None.",
                            excluded_by_design="None.") -> str:
    return f"""PHASE 5 -- THREAT-AUDIT COMPARISON (Markdown) for `{project}`.

This is the headline deliverable. Produce comprehensive Markdown a reader can
use standalone -- reproduce actual content (threat descriptions, finding
evidence and fixes), not just IDs. Use these sections:

Section 1: Executive Summary -- one paragraph on how well the threat model
anticipated code reality, plus a counts table (total threats main/Inferred,
total findings, confirmed, partial, promoted-from-Inferred, exclusion
contradictions, unconfirmed, unanticipated, with percentages).
SEVERITY-FLOOR STRATIFICATION (mandatory): the threat model excludes Medium and
Low severity threats BY DESIGN, so every Medium/Low/Info audit finding is
structurally guaranteed not to match a threat. The counts table MUST report
"unanticipated (Critical/High)" -- the true threat-model misses -- separately
from "unanticipated (Medium/Low/Info)" -- expected non-matches given the
model's severity floor. Use the Critical/High number when characterizing how
much the threat model missed, with one sentence explaining why lower-severity
non-matches are expected.

Section 2: Threats Confirmed by Audit -- one detail block per confirmed threat:
threat-model context (severity, component, description, original mitigation),
each confirming finding (location, issue, evidence, fix), and a one-sentence
synthesis of how the evidence validates the threat. Include promoted Inferred
threats here, clearly labeled "PROMOTED FROM INFERRED", quoting the threat's
original WhatWouldConfirm question alongside the finding evidence that answers
it. Sort by severity.

Section 3: Threats Not Confirmed -- one block per threat with no confirming or
partial finding. Classify each as: well-mitigated in code | audit did not reach
this code | architectural threat not observable in code | unable to determine.
Give the reasoning. "Unable to determine" is an honest, acceptable answer.

Section 4: Audit Findings Not Anticipated -- entries for unanticipated and
contradicts-exclusion findings, with full content (severity, OWASP, location,
issue, evidence, impact, fix, verify) and a note on why the threat model missed
it. contradicts-exclusion entries come FIRST, labeled "CONTRADICTS THREAT MODEL
EXCLUSION", quoting the ledger row (EX-NNN, exclusion reason) the finding
disproves -- these are the most serious entries. Group remaining unanticipated
entries: Critical/High first (genuine misses), then Medium/Low/Info under a
subheading noting they are expected given the model's severity floor. Findings
with threat_match excluded-by-design get only a compact table at the end
(FindingID, severity, EX-NNN, exclusion reason) -- deliberate scoping
decisions, not misses; do not count them in unanticipated totals.

Section 5: Partial Matches -- one block per partially-matched threat: what the
finding addresses and what remains uncovered.

Section 6: Coverage Analysis -- confirmation rates (severity-weighted and not,
main table and Inferred reported separately), anticipated-vs-unanticipated
split computed twice (all findings, and Critical/High only -- the Critical/High
figure is the meaningful one; say explicitly that the all-findings figure is
depressed by the model's deliberate severity floor), severity correlation,
component blind spots.

Do NOT include a recommendations/roadmap/next-steps section.

## Threat model threats
{threats_md}

## Confirming findings
{confirms}

## Partial findings
{partials}

## Promoted-from-Inferred findings
{promoted}

## Exclusion-contradicting findings
{contradicts}

## Excluded-by-design findings
{excluded_by_design}

## Unanticipated findings
{unanticipated}"""
