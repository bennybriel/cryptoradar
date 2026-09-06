"""
report.py — Renders a scan result (single or multi-component) into a
self-contained HTML report: executive summary, per-component readiness
grades, a Mosca-inequality exposure panel, and the full CBOM finding list.
"""

from __future__ import annotations
import html
import json
from .risk import summarize, mosca_assessment, Z_ESTIMATE_LOW, Z_ESTIMATE_HIGH
from .detectors import Category

SEVERITY_LABEL = {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info"}
SEVERITY_COLOR = {5: "#b91c1c", 4: "#c2410c", 3: "#b45309", 2: "#0f766e", 1: "#475569"}
GRADE_COLOR = {"A": "#15803d", "B": "#65a30d", "C": "#ca8a04", "D": "#ea580c", "F": "#b91c1c"}

CSS = """
:root{--bg:#0b1220;--panel:#ffffff;--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--accent:#0e7490;}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f1f5f9;color:var(--ink);}
header.hero{background:linear-gradient(135deg,#0b1220,#0e3a53 60%,#0e7490);color:#fff;padding:40px 32px;}
header.hero h1{margin:0 0 6px;font-size:28px;letter-spacing:-0.02em;}
header.hero p{margin:0;color:#cbd5e1;max-width:760px;line-height:1.5;}
.wrap{max-width:1080px;margin:0 auto;padding:28px 24px 64px;}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px;margin:22px 0;}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px 20px;}
.card h3{margin:0 0 6px;font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);}
.card .big{font-size:30px;font-weight:700;}
.section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:22px 24px;margin:22px 0;}
.section h2{margin-top:0;font-size:19px;border-bottom:1px solid var(--line);padding-bottom:10px;}
table{width:100%;border-collapse:collapse;font-size:13.5px;}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top;}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em;}
tr:hover td{background:#f8fafc;}
code{background:#0f172a;color:#e2e8f0;padding:2px 6px;border-radius:5px;font-size:12px;}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;color:#fff;font-size:11.5px;font-weight:600;}
.grade-pill{display:inline-flex;align-items:center;justify-content:center;width:52px;height:52px;border-radius:50%;color:#fff;font-size:24px;font-weight:800;}
.muted{color:var(--muted);}
.component{margin-bottom:34px;}
.component h3{font-size:16px;margin-bottom:2px;}
.verdict{padding:14px 16px;border-radius:10px;border:1px solid var(--line);background:#f8fafc;font-size:13.5px;line-height:1.5;}
footer{text-align:center;color:var(--muted);font-size:12px;padding:24px;}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-top:10px;}
.legend span{display:flex;align-items:center;gap:5px;}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;}
"""


def _badge(sev: int) -> str:
    return f'<span class="badge" style="background:{SEVERITY_COLOR[sev]}">{SEVERITY_LABEL[sev]}</span>'


def _grade_pill(grade_str: str) -> str:
    letter = grade_str[0]
    color = GRADE_COLOR.get(letter, "#475569")
    return f'<span class="grade-pill" style="background:{color}">{letter}</span>'


def _findings_table(findings: list[dict]) -> str:
    findings_sorted = sorted(
        [f for f in findings if f["category"] != Category.PQC_PRESENT.value],
        key=lambda f: -f["severity"]
    )
    positive = [f for f in findings if f["category"] == Category.PQC_PRESENT.value]

    rows = []
    for f in findings_sorted:
        rows.append(f"""<tr>
            <td>{_badge(f['severity'])}</td>
            <td><strong>{html.escape(f['primitive'])}</strong><br><span class="muted">{html.escape(f['category'].replace('_',' '))}</span></td>
            <td><code>{html.escape(f['file'])}:{f['line']}</code><br><code style="opacity:.75">{html.escape(f['snippet'])}</code></td>
            <td>{html.escape(f['note'])}</td>
            <td>{html.escape(f['migration_hint'])}</td>
        </tr>""")

    table = f"""
    <table>
        <thead><tr><th>Severity</th><th>Primitive</th><th>Location</th><th>Why it matters</th><th>Migration hint</th></tr></thead>
        <tbody>{''.join(rows) if rows else '<tr><td colspan="5" class="muted">No findings.</td></tr>'}</tbody>
    </table>"""

    if positive:
        pos_rows = "".join(
            f"<tr><td>{html.escape(f['file'])}:{f['line']}</td><td><code>{html.escape(f['snippet'])}</code></td>"
            f"<td>{html.escape(f['migration_hint'])}</td></tr>" for f in positive
        )
        table += f"""
        <h3 style="margin-top:22px;font-size:14px;">Post-quantum primitives already detected ✓</h3>
        <table><thead><tr><th>Location</th><th>Match</th><th>Verification note</th></tr></thead>
        <tbody>{pos_rows}</tbody></table>"""
    return table


def _component_section(comp: dict) -> str:
    summary = summarize(comp["findings"])
    cat_counts = "".join(
        f"<span>{k.replace('_',' ')}: <strong>{v}</strong></span>"
        for k, v in sorted(summary.findings_by_category.items(), key=lambda kv: -kv[1])
    )
    return f"""
    <div class="component">
      <div style="display:flex;align-items:center;gap:16px;margin-bottom:10px;">
        {_grade_pill(summary.readiness_grade)}
        <div>
          <h3>{html.escape(comp['component'])}</h3>
          <span class="muted">{comp['files_scanned']} files scanned · {summary.total_findings} findings ·
          readiness {summary.readiness_percent}% · {summary.quantum_relevant_findings} quantum-relevant</span>
        </div>
      </div>
      <div class="legend">{cat_counts if cat_counts else '<span class="muted">No findings in this component.</span>'}</div>
      <div style="margin-top:14px;">{_findings_table(comp['findings'])}</div>
    </div>"""


def render_report(scan_result: dict, mosca_inputs: dict | None = None) -> str:
    """scan_result: output of scanner.scan_multi() (has 'components') or
    a single scanner.scan_repo() dict (wrapped automatically)."""
    if "components" in scan_result:
        components = scan_result["components"]
    else:
        components = [scan_result]

    all_findings = [f for c in components for f in c["findings"]]
    overall = summarize(all_findings)

    mosca_inputs = mosca_inputs or {"shelf_life_years": 10, "migration_years": 3}
    mosca = mosca_assessment(
        mosca_inputs.get("shelf_life_years", 10),
        mosca_inputs.get("migration_years", 3),
        mosca_inputs.get("z_low", Z_ESTIMATE_LOW),
        mosca_inputs.get("z_high", Z_ESTIMATE_HIGH),
    )
    mosca_risk_color = "#b91c1c" if mosca.at_risk_low else "#15803d"

    components_html = "".join(_component_section(c) for c in components)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Crypto Agility & Quantum-Readiness Report</title>
<style>{CSS}</style></head>
<body>
<header class="hero">
  <h1>Crypto Agility &amp; Quantum-Readiness Report</h1>
  <p>Generated by CryptoRadar — a crypto-inventory and migration-assessment
  toolkit for mixed legacy-core + modern-API fintech stacks. This report is a
  starting point for a migration roadmap, not a compliance certificate.</p>
</header>
<div class="wrap">
  <div class="grid">
    <div class="card"><h3>Components scanned</h3><div class="big">{len(components)}</div></div>
    <div class="card"><h3>Total findings</h3><div class="big">{overall.total_findings}</div></div>
    <div class="card"><h3>Quantum-relevant</h3><div class="big">{overall.quantum_relevant_findings}</div></div>
    <div class="card"><h3>Overall readiness</h3><div class="big" style="display:flex;align-items:center;gap:10px;">{_grade_pill(overall.readiness_grade)} {overall.readiness_percent}%</div></div>
  </div>

  <div class="section">
    <h2>Quantum exposure — Mosca inequality (X + Y &gt; Z)</h2>
    <p class="muted">X = data/system shelf-life required, Y = time needed to
    migrate once started, Z = years until a cryptographically relevant
    quantum computer exists (estimated as a range, not a fixed date).</p>
    <div class="grid" style="grid-template-columns:repeat(4,1fr);margin-top:4px;">
      <div class="card"><h3>Shelf-life (X)</h3><div class="big">{mosca.shelf_life_years}y</div></div>
      <div class="card"><h3>Migration time (Y)</h3><div class="big">{mosca.migration_years}y</div></div>
      <div class="card"><h3>X + Y</h3><div class="big">{mosca.shelf_life_years + mosca.migration_years}y</div></div>
      <div class="card"><h3>Z estimate range</h3><div class="big">{mosca.z_low}–{mosca.z_high}y</div></div>
    </div>
    <div class="verdict" style="margin-top:14px;border-left:4px solid {mosca_risk_color};">{html.escape(mosca.verdict)}</div>
  </div>

  <div class="section">
    <h2>Per-component findings</h2>
    {components_html}
  </div>

  <div class="section">
    <h2>How to read the readiness grade</h2>
    <p class="muted">The grade is a normalized average of severity-weighted
    findings per component — it rewards components with <em>few, well-understood</em>
    issues and penalizes those with many high-severity ones. It is a
    prioritization signal for where to start a migration program, not an
    absolute security score, and it does not replace a manual review of
    high-value flows (settlement, KYC data at rest, card/PAN handling).</p>
  </div>
</div>
<footer>CryptoRadar · Crypto Bill of Materials generated {html.escape(scan_result.get('generated_at',''))}</footer>
</body></html>"""


def render_cbom_json(scan_result: dict) -> str:
    """Machine-readable Crypto Bill of Materials for CI pipelines / SIEM ingestion."""
    return json.dumps(scan_result, indent=2, default=str)
