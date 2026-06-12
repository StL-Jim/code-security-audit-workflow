"""Smoke tests for the non-LLM plumbing: parsing, scoring, rendering, state."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from audit import render
from audit.findings import FindingsRegistry, compute_score, parse_findings
from audit.models import Partition

WORKER_OUTPUT = """Some preamble the model shouldn't emit but we tolerate.

```yaml
pid: api
src: src/api/users.py:45-52
class: Confirmed
sev: High
conf: High
cat: A01:2021
sub: IDOR
title: User data exposed without authorization check
scope: service-wide
deps: local
exploit: Easy
ev: |
  src/api/users.py:45 get_user() has no ownership check
issue: |
  Any authenticated user can read any other user's record.
impact: |
  PII exposure for all users.
fix: |
  Add ownership check before returning the record.
verify: |
  Add test_cross_user_access asserting 403.
status: open
threat_id: "0007"
threat_match: confirms
```

```yaml
pid: api
src: src/api/search.py:12
class: Suspected
sev: Medium
conf: Medium
cat: A03:2021
sub: SQL Injection
title: Possible SQL injection in search filter
scope: module
deps: local
exploit: Moderate
ev: |
  String-formatted query at search.py:12
issue: |
  User input concatenated into SQL.
impact: |
  Data exfiltration.
fix: |
  Use parameterized queries.
verify: |
  sqlmap against the endpoint returns no injection.
threat_match: unanticipated
```
"""


def test_scoring():
    # Critical/High/Global/Trivial internet-facing -> 100
    assert compute_score("Critical", "High", "global", "Trivial", "Internet-facing") == 100
    # internal modifier 0.6 lowers it
    internal = compute_score("Critical", "High", "global", "Trivial", "Internal")
    assert internal == 60, internal
    # the example High finding
    s = compute_score("High", "High", "service-wide", "Easy", "Internet-facing")
    assert 0 < s <= 100
    print(f"scoring OK (internet=100, internal=60, example={s})")


def test_parse():
    findings = parse_findings(WORKER_OUTPUT)
    assert len(findings) == 2, len(findings)
    assert findings[0]["title"].startswith("User data exposed")
    assert findings[1]["threat_match"] == "unanticipated"
    print(f"parse OK ({len(findings)} findings)")


def test_registry_and_render():
    with tempfile.TemporaryDirectory() as d:
        reg = FindingsRegistry(Path(d) / "findings_registry.md", "Internet-facing")
        added = reg.add_many(parse_findings(WORKER_OUTPUT), "api")
        assert all(f["id"].startswith("F-") for f in added)
        assert all(isinstance(f["score"], int) for f in added)
        reg.save()
        # reload from disk -> ids preserved, seq continues
        reg2 = FindingsRegistry(Path(d) / "findings_registry.md", "Internet-facing")
        assert len(reg2.findings) == 2, len(reg2.findings)
        nxt = reg2._next_id()
        assert nxt.endswith("003"), nxt
        # severity sort: High before Medium
        ordered = reg2.sorted_findings()
        assert ordered[0]["sev"] == "High"
        print(f"registry OK (ids={[f['id'] for f in added]}, next={nxt})")

        # render all three deliverables
        report = render.render_consolidated_report(
            "demo", reg2, {"summary": "All clear-ish.", "coverage": "- api", "gaps": "none"},
            "1. attacker -> IDOR -> PII")
        assert "<!DOCTYPE html>" in report and "User data exposed" in report
        assert "Possible SQL injection" in report  # every finding present
        briefing = render.render_executive_briefing(
            "demo", reg2, "Summary text", "attack paths")
        assert "User data exposed" in briefing  # High shown
        assert "Possible SQL injection" not in briefing  # Medium excluded
        comp = render.render_comparison_html("demo", "# Section 1\nText\n\n## Threat 0007\nDetail")
        assert "<!DOCTYPE html>" in comp and "Threat 0007" in comp
        print("render OK (report has all findings, briefing filters to High+)")


def test_yaml_hazard_recovery():
    """Regression: a value starting with a backtick (illegal plain YAML) must not
    discard sibling findings. Observed live with MiniMax M3 on a real repo."""
    hazard = """pid: config
src: src/config.py:1-10
sev: High
title: `config = Config()` runs at import, leaking defaults
issue: |
  Module-level global with a backtick in the title.
threat_match: unanticipated
---
pid: config
src: src/config.py:20
sev: Medium
title: Second finding survives despite the first being malformed
issue: |
  Should still parse.
"""
    findings = parse_findings(hazard)
    assert len(findings) == 2, f"expected 2, got {len(findings)}"
    assert "Config()" in findings[0]["title"]
    print(f"yaml hazard recovery OK ({len(findings)} findings, backtick title preserved)")


def test_partition_model():
    p = Partition.from_dict({"id": "auth", "name": "Auth", "root": "src/auth"})
    assert p.id == "auth" and p.root == "src/auth"
    rt = Partition.from_dict(p.to_dict())
    assert rt.id == p.id
    print("partition model OK")


if __name__ == "__main__":
    test_scoring()
    test_parse()
    test_registry_and_render()
    test_yaml_hazard_recovery()
    test_partition_model()
    print("\nALL SMOKE TESTS PASSED")
