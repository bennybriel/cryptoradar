"""
roadmap.py — Builds the actual client deliverable: a Word document
containing only analyst-confirmed findings, organized into a phased
remediation roadmap, with an executive summary and a methodology section
that's honest about what the tool does and doesn't do.

This deliberately does NOT accept a raw CBOM. It takes a CBOM + a review
file, and calls review.merge_reviewed_findings(), which silently drops
anything without a review record. Unreviewed findings cannot reach a
client through this path.
"""

from __future__ import annotations
from datetime import datetime, date
from collections import defaultdict

from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn

from .review import merge_reviewed_findings, Status, Priority, PRIORITY_LABEL
from .risk import mosca_assessment, Z_ESTIMATE_LOW, Z_ESTIMATE_HIGH

NAVY = RGBColor(0x0B, 0x12, 0x20)
TEAL = RGBColor(0x0E, 0x74, 0x90)
MUTED = RGBColor(0x64, 0x74, 0x8B)
SEVERITY_LABEL = {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info"}


def _shade_cell(cell, hex_color: str):
    shd = cell._tc.get_or_add_tcPr().makeelement(qn("w:shd"), {
        qn("w:val"): "clear", qn("w:color"): "auto", qn("w:fill"): hex_color})
    cell._tc.get_or_add_tcPr().append(shd)


def _set_col_widths(table, widths_in):
    table.autofit = False
    for row in table.rows:
        for cell, w in zip(row.cells, widths_in):
            cell.width = Inches(w)


def _heading(doc, text, level=1):
    h = doc.add_heading(text, level=level)
    for run in h.runs:
        run.font.color.rgb = NAVY
    return h


def build_roadmap(cbom: dict, review: dict, meta: dict) -> Document:
    """meta keys: client, consultant, firm, engagement_date (optional),
    shelf_life_years, migration_years, z_low, z_high."""
    findings = merge_reviewed_findings(cbom, review)
    confirmed = [f for f in findings if f["review"]["status"] == Status.CONFIRMED.value]
    accepted_risk = [f for f in findings if f["review"]["status"] == Status.ACCEPTED_RISK.value]
    false_positives = [f for f in findings if f["review"]["status"] == Status.FALSE_POSITIVE.value]
    remediated = [f for f in findings if f["review"]["status"] == Status.REMEDIATED.value]

    doc = Document()
    doc.sections[0].left_margin = Inches(1)
    doc.sections[0].right_margin = Inches(1)

    # ---- Cover ----
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run("\n\n\n")
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run("Crypto Agility & Quantum-Readiness\nAssessment Roadmap")
    run.font.size = Pt(28)
    run.font.bold = True
    run.font.color.rgb = NAVY

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = sub.add_run(f"Prepared for {meta.get('client', 'Client')}")
    r.font.size = Pt(16)
    r.font.color.rgb = TEAL

    meta_p = doc.add_paragraph()
    meta_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    eng_date = meta.get("engagement_date") or date.today().isoformat()
    meta_line = (f"{meta.get('firm', '')} · {meta.get('consultant', '')}\n"
                 f"Engagement date: {eng_date}")
    r2 = meta_p.add_run(meta_line)
    r2.font.size = Pt(11)
    r2.font.color.rgb = MUTED
    doc.add_page_break()

    # ---- Executive summary ----
    _heading(doc, "Executive Summary", 1)
    doc.add_paragraph(
        f"This assessment scanned the components in scope and identified "
        f"{len(confirmed) + len(accepted_risk) + len(false_positives) + len(remediated)} "
        f"candidate findings via automated pattern analysis. Every finding in this "
        f"document has been individually reviewed by {meta.get('consultant', 'the consultant')} "
        f"and confirmed as a genuine issue before inclusion — automated tool output alone "
        f"is not treated as evidence of risk."
    )
    stats = doc.add_paragraph()
    stats.add_run(f"Confirmed findings requiring action: ").bold = True
    stats.add_run(f"{len(confirmed)}\n")
    stats.add_run(f"Accepted-risk items (reviewed, remediation deferred by client decision): ").bold = True
    stats.add_run(f"{len(accepted_risk)}\n")
    stats.add_run(f"False positives ruled out during review: ").bold = True
    stats.add_run(f"{len(false_positives)}\n")
    stats.add_run(f"Already remediated since scan: ").bold = True
    stats.add_run(f"{len(remediated)}")

    by_sev = defaultdict(int)
    for f in confirmed:
        by_sev[f["severity"]] += 1
    if confirmed:
        sev_p = doc.add_paragraph("Confirmed findings by severity: ")
        sev_p.add_run(", ".join(
            f"{SEVERITY_LABEL[s]}: {by_sev[s]}" for s in sorted(by_sev, reverse=True)
        )).italic = True

    # ---- Mosca exposure ----
    _heading(doc, "Quantum Exposure Assessment", 1)
    doc.add_paragraph(
        "Mosca's inequality frames when post-quantum migration becomes urgent: "
        "an organization is already exposed if the time data must remain "
        "confidential (X), plus the time needed to complete migration (Y), "
        "exceeds the time until a cryptographically relevant quantum computer "
        "exists (Z). Z is inherently uncertain and is treated here as a range, "
        "not a prediction."
    )
    m = mosca_assessment(
        meta.get("shelf_life_years", 10), meta.get("migration_years", 3),
        meta.get("z_low", Z_ESTIMATE_LOW), meta.get("z_high", Z_ESTIMATE_HIGH),
    )
    tbl = doc.add_table(rows=2, cols=4)
    tbl.style = "Light Grid Accent 1"
    hdr = tbl.rows[0].cells
    for i, label in enumerate(["Shelf-life (X)", "Migration time (Y)", "X + Y", "Z estimate range"]):
        hdr[i].text = label
    vals = tbl.rows[1].cells
    for i, v in enumerate([f"{m.shelf_life_years:.1f}y", f"{m.migration_years:.1f}y",
                            f"{m.shelf_life_years + m.migration_years:.1f}y",
                            f"{m.z_low}-{m.z_high}y"]):
        vals[i].text = v
    doc.add_paragraph()
    verdict_p = doc.add_paragraph()
    verdict_p.add_run("Verdict: ").bold = True
    verdict_p.add_run(m.verdict)

    # ---- Phased remediation roadmap ----
    _heading(doc, "Phased Remediation Roadmap", 1)
    doc.add_paragraph(
        "Confirmed findings are grouped below by the priority assigned during "
        "review, balancing severity against realistic sequencing — for "
        "example, hardcoded secrets are immediate regardless of migration "
        "complexity, while a full RSA-to-PQC signature migration is planned "
        "as a longer-term, coordinated effort."
    )
    by_priority = defaultdict(list)
    for f in confirmed:
        pr = f["review"].get("priority") or Priority.MONITOR.value
        by_priority[pr].append(f)

    for pr in [Priority.IMMEDIATE, Priority.SHORT_TERM, Priority.MEDIUM_TERM,
               Priority.LONG_TERM, Priority.MONITOR]:
        items = by_priority.get(pr.value, [])
        if not items:
            continue
        _heading(doc, PRIORITY_LABEL[pr], 2)
        table = doc.add_table(rows=1, cols=4)
        table.style = "Light List Accent 1"
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        hdr = table.rows[0].cells
        for i, label in enumerate(["Severity", "Finding", "Location", "Recommended action"]):
            hdr[i].text = label
        _set_col_widths(table, [0.8, 1.7, 1.9, 2.1])
        for f in sorted(items, key=lambda x: -x["severity"]):
            row = table.add_row().cells
            row[0].text = SEVERITY_LABEL[f["severity"]]
            row[1].text = f["primitive"]
            row[2].text = f"{f['file']}:{f['line']}"
            row[3].text = f["migration_hint"]
        doc.add_paragraph()

    # ---- Accepted-risk register ----
    if accepted_risk:
        _heading(doc, "Accepted-Risk Register", 1)
        doc.add_paragraph(
            "The following confirmed findings were reviewed and, by client "
            "decision, are not scheduled for immediate remediation. They "
            "should be revisited at the next assessment cycle."
        )
        table = doc.add_table(rows=1, cols=3)
        table.style = "Light List Accent 1"
        hdr = table.rows[0].cells
        for i, label in enumerate(["Finding", "Location", "Reviewer note"]):
            hdr[i].text = label
        for f in accepted_risk:
            row = table.add_row().cells
            row[0].text = f["primitive"]
            row[1].text = f"{f['file']}:{f['line']}"
            row[2].text = f["review"].get("note") or "—"

    # ---- Detailed appendix ----
    doc.add_page_break()
    _heading(doc, "Appendix A: Detailed Confirmed Findings", 1)
    for f in sorted(confirmed, key=lambda x: -x["severity"]):
        p = doc.add_paragraph()
        p.add_run(f"{f['primitive']} — {SEVERITY_LABEL[f['severity']]}").bold = True
        doc.add_paragraph(f"Location: {f['file']}:{f['line']}  ·  Component: {f.get('_component','')}")
        code_p = doc.add_paragraph()
        code_run = code_p.add_run(f["snippet"])
        code_run.font.name = "Consolas"
        code_run.font.size = Pt(9)
        doc.add_paragraph(f["note"])
        rec_p = doc.add_paragraph()
        rec_p.add_run("Recommendation: ").italic = True
        rec_p.add_run(f["migration_hint"])
        if f["review"].get("note"):
            note_p = doc.add_paragraph()
            note_p.add_run("Reviewer note: ").italic = True
            note_p.add_run(f["review"]["note"])
        doc.add_paragraph("")  # spacer

    # ---- Methodology & limitations ----
    doc.add_page_break()
    _heading(doc, "Methodology & Limitations", 1)
    doc.add_paragraph(
        "Findings originated from CryptoRadar, an automated pattern-based "
        "scanner, and were subsequently reviewed and confirmed individually "
        "by the named consultant before inclusion in this document."
    )
    for line in [
        "This is a source-code and configuration-level assessment. It does not "
        "constitute a penetration test, a formal security audit, or a "
        "compliance certification (e.g. PCI-DSS, ISO 27001, CBN guidelines).",
        "Automated scanning uses pattern matching and may not detect every "
        "instance of a weak cryptographic primitive, particularly where "
        "usage is dynamically constructed, obfuscated, or in a language/"
        "format outside the scanner's current signature set.",
        "The quantum-exposure timeline (Z) is an industry-range estimate, "
        "not a prediction; it should be revisited periodically as public "
        "estimates and the organization's own data-retention requirements evolve.",
        "This document should be handled as a confidential, sensitive "
        "artifact — it references the organization's real security posture.",
    ]:
        doc.add_paragraph(line, style="List Bullet")

    return doc
