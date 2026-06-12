"""
Native (deterministic, no-LLM) rendering of audit deliverables.

Replaces the prompt's Phase 5/6 budget-driven scaffold-and-fill machinery:
because Python builds the HTML from the findings registry directly, "every
finding appears in the report" is true by construction, not by discipline.
"""

import html as html_module
import re
from pathlib import Path

from .findings import severity_rank
from .models import SEVERITIES

SEV_COLORS = {
    "Critical": "#b00020", "High": "#e65100",
    "Medium": "#f9a825", "Low": "#2e7d32", "Info": "#546e7a",
}

_ASCII_SUBS = [
    ("—", "--"), ("–", "-"), ("‘", "'"), ("’", "'"),
    ("“", '"'), ("”", '"'), ("…", "..."), (" ", " "),
    ("•", "-"), ("−", "-"), ("·", "."), ("→", "->"),
    ("≥", ">="), ("≤", "<="),
]


def ascii_normalize(text: str) -> str:
    for orig, repl in _ASCII_SUBS:
        text = text.replace(orig, repl)
    return text


def md_to_html(text: str) -> str:
    """Minimal but robust Markdown -> HTML for prose state files."""
    if not text or not text.strip():
        return "<p><em>No content.</em></p>"
    e = html_module.escape

    def inline(t: str) -> str:
        t = e(t)
        t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
        t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
        return t

    out: list[str] = []
    in_table = in_code = False
    rows: list[list[str]] = []

    def flush_table() -> None:
        if not rows:
            return
        buf = ["<div class='tbl-wrap'><table>"]
        for ri, trow in enumerate(rows):
            tag = "th" if ri == 0 else "td"
            buf.append("<tr>" + "".join(
                f"<{tag}>" + (inline(c) if tag == "td" else e(c)) + f"</{tag}>"
                for c in trow) + "</tr>")
        buf.append("</table></div>")
        out.append("\n".join(buf))
        rows.clear()

    for line in text.splitlines():
        s = line.strip()
        if s.startswith("```"):
            if in_table:
                flush_table(); in_table = False
            in_code = not in_code
            out.append("<pre>" if in_code else "</pre>")
            continue
        if in_code:
            out.append(e(line)); continue
        if s.startswith("|"):
            in_table = True
            inner = s.strip("|")
            if re.match(r"^[\s\-|:]+$", inner):
                continue
            rows.append([c.strip() for c in s.strip("|").split("|")])
            continue
        elif in_table:
            flush_table(); in_table = False
        m = re.match(r"^(#{1,4})\s+(.*)", s)
        if m:
            lvl = min(len(m.group(1)) + 1, 6)
            out.append(f"<h{lvl}>{inline(m.group(2))}</h{lvl}>"); continue
        m = re.match(r"^[-*]\s+(.*)", s) or re.match(r"^\d+\.\s+(.*)", s)
        if m:
            out.append(f"<li>{inline(m.group(1))}</li>"); continue
        out.append("" if not s else f"<p>{inline(s)}</p>")

    if in_table:
        flush_table()
    if in_code:
        out.append("</pre>")
    return "\n".join(out)


_BASE_CSS = """
:root{--font:system-ui,-apple-system,"Segoe UI",sans-serif;--bg:#f8f9fa;
--surface:#fff;--border:#dee2e6;--text:#212529;--muted:#6c757d;--sidebar-w:240px;}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;
line-height:1.55;display:flex;flex-direction:column;min-height:100vh;}
.site-header{background:#263238;color:#fff;padding:1.25rem 2rem;}
.site-header h1{font-size:1.5rem;font-weight:600;}
.site-header p{opacity:.7;font-size:.875rem;margin-top:.2rem;}
.classification{background:#b00020;color:#fff;text-align:center;font-size:.7rem;
letter-spacing:.15em;padding:.25rem;text-transform:uppercase;}
.layout{display:flex;flex:1;}
nav.toc{width:var(--sidebar-w);min-width:var(--sidebar-w);background:#37474f;
padding:1.5rem 0;position:sticky;top:0;height:100vh;overflow-y:auto;flex-shrink:0;}
nav.toc h3{color:#90a4ae;font-size:.7rem;letter-spacing:.1em;text-transform:uppercase;
padding:0 1rem .5rem;}
nav.toc ul{list-style:none;} nav.toc li a{display:block;color:#b0bec5;
text-decoration:none;padding:.4rem 1rem;font-size:.85rem;}
nav.toc li a:hover{background:rgba(255,255,255,.08);color:#fff;}
main{flex:1;padding:2rem;min-width:0;}
section{margin-bottom:3rem;}
h2{font-size:1.2rem;font-weight:600;border-bottom:2px solid var(--border);
padding-bottom:.35rem;margin-bottom:1rem;color:#263238;}
h3{font-size:1rem;font-weight:600;margin:1rem 0 .5rem;}
p{margin-bottom:.75rem;}
.tbl-wrap{overflow-x:auto;} table{width:100%;border-collapse:collapse;font-size:.82rem;}
th{background:#37474f;color:#fff;padding:.4rem .6rem;text-align:left;}
td{padding:.4rem .6rem;border-bottom:1px solid var(--border);vertical-align:top;}
.sev-cards{display:flex;gap:.75rem;flex-wrap:wrap;margin-bottom:1.5rem;}
.sev-card{border-radius:8px;padding:.75rem 1.25rem;min-width:100px;text-align:center;color:#fff;}
.scard-count{font-size:1.8rem;font-weight:700;}
.scard-label{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;opacity:.9;}
.sev-badge{display:inline-block;border-radius:3px;padding:.1rem .45rem;font-size:.75rem;
font-weight:600;color:#fff;}
.entry{background:var(--surface);border:1px solid var(--border);border-left:5px solid #999;
border-radius:6px;padding:1rem 1.25rem;margin-bottom:1.25rem;}
.entry h3{margin-top:0;} .entry .meta{font-size:.8rem;color:var(--muted);margin-bottom:.5rem;}
.entry .block{margin:.5rem 0;} .entry .block b{display:block;font-size:.78rem;
text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-bottom:.15rem;}
.entry pre,.entry code{background:#eceff1;border-radius:3px;font-size:.8em;
font-family:monospace;} .entry pre{padding:.5rem .75rem;overflow-x:auto;white-space:pre-wrap;}
.unanticipated{border-left-color:#6a1b9a;background:#faf5ff;}
.prose code{background:#eceff1;border-radius:3px;padding:.05rem .3rem;font-family:monospace;}
.prose pre{background:#eceff1;border-radius:4px;padding:.75rem 1rem;overflow-x:auto;
white-space:pre-wrap;} .prose li{margin-left:1.25rem;}
footer{background:#eceff1;color:var(--muted);text-align:center;font-size:.75rem;padding:1rem;}
@media print{nav.toc{display:none;} body{font-size:10pt;background:#fff;}
.sev-card,.sev-badge{-webkit-print-color-adjust:exact;print-color-adjust:exact;}}
"""


def _sev_badge(sev: str) -> str:
    e = html_module.escape
    color = SEV_COLORS.get((sev or "").capitalize(), "#555")
    return f'<span class="sev-badge" style="background:{color}">{e(sev or "?")}</span>'


def _sev_cards(counts: dict) -> str:
    cards = ""
    for sev in SEVERITIES:
        n = counts.get(sev, 0)
        if n:
            cards += (f'<div class="sev-card" style="background:{SEV_COLORS[sev]}">'
                      f'<div class="scard-count">{n}</div>'
                      f'<div class="scard-label">{sev}</div></div>')
    return f'<div class="sev-cards">{cards}</div>'


def _page(title: str, subtitle: str, toc: list, body: str, classification: str) -> str:
    e = html_module.escape
    toc_html = "".join(f'<li><a href="#{sid}">{e(lbl)}</a></li>' for sid, lbl in toc)
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n"
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        f"<title>{e(title)}</title>\n<style>{_BASE_CSS}</style>\n</head>\n<body>\n"
        f'<div class="classification">{e(classification)}</div>\n'
        f'<div class="site-header"><h1>{e(title)}</h1><p>{e(subtitle)}</p></div>\n'
        f'<div class="layout">\n<nav class="toc"><h3>Contents</h3><ul>{toc_html}</ul></nav>\n'
        f"<main>\n{body}\n</main>\n</div>\n"
        f'<div class="classification">{e(classification)}</div>\n'
        f"<footer>Generated by code-security-audit-workflow. "
        "Evidence-backed; no aggregate grade or remediation schedule by design.</footer>\n"
        "</body>\n</html>"
    )


def _finding_entry(f: dict, unanticipated: bool = False) -> str:
    e = html_module.escape
    sev = (f.get("sev") or "").capitalize()
    cls = "entry unanticipated" if unanticipated else "entry"
    color = SEV_COLORS.get(sev, "#999")
    blocks = ""
    for label, key in [("Location", "src"), ("Issue", "issue"), ("Evidence", "ev"),
                       ("Impact", "impact"), ("Fix", "fix"), ("Verify", "verify")]:
        val = f.get(key)
        if val:
            blocks += f'<div class="block"><b>{label}</b><pre>{e(str(val).strip())}</pre></div>'
    meta = (f'{_sev_badge(sev)} &nbsp; score {e(str(f.get("score","?")))} &nbsp; '
            f'{e(f.get("cat") or "")} &nbsp; partition: {e(f.get("pid") or "")}')
    tm = f.get("threat_match")
    if tm and tm != "null":
        meta += f' &nbsp; threat: {e(str(f.get("threat_id") or "-"))} ({e(tm)})'
    return (f'<article class="{cls}" style="border-left-color:{color}">'
            f'<h3>{e(f.get("id") or "")}: {e(f.get("title") or "")}</h3>'
            f'<div class="meta">{meta}</div>{blocks}</article>')


def render_consolidated_report(project: str, registry, sections_md: dict,
                               attack_paths_md: str) -> str:
    """Final report: every finding in the registry, full detail."""
    counts = registry.counts_by_severity()
    toc = [("summary", "Executive Summary"), ("coverage", "Partition Coverage"),
           ("findings", "Findings"), ("attack-paths", "Top Attack Paths"),
           ("gaps", "Evidence Gaps")]
    findings_html = "".join(_finding_entry(f) for f in registry.sorted_findings())
    if not findings_html:
        findings_html = "<p><em>No findings recorded.</em></p>"
    body = (
        f'<section id="summary"><h2>Executive Summary</h2>{_sev_cards(counts)}'
        f'<div class="prose">{md_to_html(sections_md.get("summary",""))}</div></section>'
        f'<section id="coverage"><h2>Partition Coverage</h2>'
        f'<div class="prose">{md_to_html(sections_md.get("coverage",""))}</div></section>'
        f'<section id="findings"><h2>Findings ({len(registry.findings)})</h2>{findings_html}</section>'
        f'<section id="attack-paths"><h2>Top Attack Paths</h2>'
        f'<div class="prose">{md_to_html(attack_paths_md)}</div></section>'
        f'<section id="gaps"><h2>Evidence Gaps</h2>'
        f'<div class="prose">{md_to_html(sections_md.get("gaps",""))}</div></section>'
    )
    n = len(registry.findings)
    return _page(f"Security & Architecture Audit -- {project}",
                 f"{n} findings | comprehensive report", toc, body,
                 "Confidential -- Internal Use Only")


def render_executive_briefing(project: str, registry, summary_md: str,
                              attack_paths_md: str) -> str:
    """Briefing: Critical/High findings only, plus top attack paths."""
    crit_high = [f for f in registry.sorted_findings()
                 if (f.get("sev") or "").lower() in ("critical", "high")]
    counts = {s: registry.counts_by_severity().get(s, 0) for s in ("Critical", "High")}
    toc = [("summary", "Summary"), ("key-findings", "Key Findings"),
           ("attack-paths", "Top Attack Paths")]
    findings_html = "".join(_finding_entry(f) for f in crit_high) or \
        "<p><em>No Critical or High findings.</em></p>"
    body = (
        f'<section id="summary"><h2>Summary</h2>{_sev_cards(counts)}'
        f'<div class="prose">{md_to_html(summary_md)}</div></section>'
        f'<section id="key-findings"><h2>Key Findings ({len(crit_high)})</h2>{findings_html}</section>'
        f'<section id="attack-paths"><h2>Top Attack Paths</h2>'
        f'<div class="prose">{md_to_html(attack_paths_md)}</div></section>'
    )
    return _page(f"Executive Briefing -- {project}",
                 f"{len(crit_high)} Critical/High findings", toc, body,
                 "Confidential -- Executive Briefing")


def render_comparison_html(project: str, comparison_md: str) -> str:
    """Render the COORDINATED-mode threat-audit comparison Markdown to HTML."""
    toc = [("comparison", "Threat-Audit Comparison")]
    body = (f'<section id="comparison"><h2>Threat-Audit Comparison</h2>'
            f'<div class="prose">{md_to_html(comparison_md)}</div></section>')
    return _page(f"Threat-Audit Comparison -- {project}",
                 "Headline deliverable: what the threat model anticipated vs. code reality",
                 toc, body, "Confidential -- Internal Use Only")
