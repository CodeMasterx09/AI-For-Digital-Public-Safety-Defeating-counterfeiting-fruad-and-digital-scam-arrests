"""
Case File Export — turns a graph_intel.py intel package + its audit trail
into an actual downloadable document, not a JSON blob.

Uses reportlab (the standard library's pdf skill recommends it) when
available for a properly formatted multi-section PDF with real tables.
Falls back to a plain-text case file if reportlab isn't installed, so the
endpoint still returns something useful with zero required installs --
same graceful-degradation pattern as counterfeit_currency.py.
"""
import io
from datetime import datetime, timezone

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                     TableStyle, HRFlowable)
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def generate_case_file(intel_package: dict, audit_entries: list, case_ref: str):
    """Returns (bytes, content_type, filename, format)."""
    if REPORTLAB_AVAILABLE:
        pdf_bytes = _build_pdf(intel_package, audit_entries, case_ref)
        return pdf_bytes, "application/pdf", f"{case_ref}.pdf", "pdf"
    text = _build_text(intel_package, audit_entries, case_ref)
    return text.encode("utf-8"), "text/plain", f"{case_ref}.txt", "txt"


# ---------------- reportlab path -------------------------------------------

def _build_pdf(intel, audit_entries, case_ref):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        topMargin=22 * mm, bottomMargin=18 * mm, leftMargin=18 * mm, rightMargin=18 * mm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("CaseTitle", parent=styles["Title"], fontSize=18, spaceAfter=2)
    meta_style = ParagraphStyle("Meta", parent=styles["Normal"], fontSize=9, textColor=colors.grey)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=12.5, spaceBefore=14, spaceAfter=6)
    body = styles["Normal"]
    mono = ParagraphStyle("Mono", parent=styles["Normal"], fontName="Courier", fontSize=8, leading=11)

    story = []
    story.append(Paragraph("PRAHARI AI — Fraud Network Intelligence Package", title_style))
    story.append(Paragraph(f"Case reference: {case_ref} &nbsp;&nbsp;|&nbsp;&nbsp; Generated: {_now()}", meta_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=colors.HexColor("#888888"), spaceBefore=8, spaceAfter=12))

    story.append(Paragraph("1. Case Summary", h2))
    risk_color = {"HIGH": colors.HexColor("#B3261E"), "MEDIUM": colors.HexColor("#B45F06"),
                  "LOW": colors.HexColor("#0B6E4F")}.get(intel.get("risk_level"), colors.black)
    summary_rows = [
        ["Cluster ID", str(intel.get("cluster_id"))],
        ["Risk level", intel.get("risk_level")],
        ["Risk score", f"{intel.get('risk_score')}/100"],
        ["Linked entities", str(intel.get("entity_count"))],
        ["Linkages found", str(len(intel.get("linkages", [])))],
    ]
    t = Table(summary_rows, colWidths=[120, 350])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("TEXTCOLOR", (1, 1), (1, 1), risk_color),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#DDDDDD")),
    ]))
    story.append(t)
    story.append(Spacer(1, 6))
    story.append(Paragraph(intel.get("summary", ""), body))

    story.append(Paragraph("2. Linked Entities", h2))
    entity_rows = [["Entity ID", "Type"]] + [[e.get("id", ""), e.get("type", "") or "—"] for e in intel.get("entities", [])]
    et = Table(entity_rows, colWidths=[300, 170], repeatRows=1)
    et.setStyle(_table_style())
    story.append(et)

    story.append(Paragraph("3. Linkages (Evidence of Coordination)", h2))
    link_rows = [["From", "To", "Relation", "Confidence"]]
    for l in intel.get("linkages", []):
        link_rows.append([l.get("from", ""), l.get("to", ""), l.get("relation", "") or "—",
                           f"{l.get('weight', '')}"])
    lt = Table(link_rows, colWidths=[140, 140, 110, 80], repeatRows=1)
    lt.setStyle(_table_style())
    story.append(lt)

    story.append(Paragraph("4. Chain of Custody — Audit Trail", h2))
    if audit_entries:
        story.append(Paragraph(
            "Each row below is one tamper-evident log entry: its hash is computed over its own "
            "content plus the previous entry's hash, so altering any past entry invalidates every "
            "hash after it. Verify at any time via the /audit/verify endpoint.", body))
        story.append(Spacer(1, 4))
        audit_rows = [["Seq", "Timestamp (UTC)", "Event", "Hash (sha256, truncated)"]]
        for e in audit_entries:
            audit_rows.append([str(e["seq"]), e["timestamp"][:19], e["event_type"], e["hash"][:16] + "…"])
        at = Table(audit_rows, colWidths=[35, 140, 150, 145], repeatRows=1)
        at.setStyle(_table_style(font="Courier", size=7.5))
        story.append(at)
    else:
        story.append(Paragraph("No audit events recorded for this case yet.", body))

    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CCCCCC")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<i>This package is AI-assisted investigative intelligence generated by PRAHARI AI for "
        "lead generation and resource prioritization. It is not, by itself, a substitute for "
        "forensic verification or a court-certified evidentiary chain — it is designed to "
        "accelerate and support a human investigator's process, with the audit trail above "
        "providing tamper-evidence for whatever was actually logged.</i>", meta_style))

    doc.build(story)
    return buf.getvalue()


def _table_style(font="Helvetica", size=8.5):
    return TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), font),
        ("FONTSIZE", (0, 0), (-1, -1), size),
        ("FONTNAME", (0, 0), (-1, 0), font + "-Bold" if font == "Helvetica" else font),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1530")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DDDDDD")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F7FA")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ])


# ---------------- plain-text fallback (no reportlab installed) ------------

def _build_text(intel, audit_entries, case_ref):
    lines = []
    lines.append("PRAHARI AI -- FRAUD NETWORK INTELLIGENCE PACKAGE")
    lines.append(f"Case reference: {case_ref}    Generated: {_now()}")
    lines.append("=" * 70)
    lines.append("\n1. CASE SUMMARY")
    lines.append(f"   Cluster ID:       {intel.get('cluster_id')}")
    lines.append(f"   Risk level:       {intel.get('risk_level')}")
    lines.append(f"   Risk score:       {intel.get('risk_score')}/100")
    lines.append(f"   Linked entities:  {intel.get('entity_count')}")
    lines.append(f"   Linkages found:   {len(intel.get('linkages', []))}")
    lines.append(f"\n   {intel.get('summary', '')}")

    lines.append("\n2. LINKED ENTITIES")
    for e in intel.get("entities", []):
        lines.append(f"   - {e.get('id','')} ({e.get('type','') or 'unknown'})")

    lines.append("\n3. LINKAGES (EVIDENCE OF COORDINATION)")
    for l in intel.get("linkages", []):
        lines.append(f"   - {l.get('from','')} <-> {l.get('to','')}  relation={l.get('relation','')}  confidence={l.get('weight','')}")

    lines.append("\n4. CHAIN OF CUSTODY -- AUDIT TRAIL")
    if audit_entries:
        lines.append("   Each entry's hash covers its content + the previous entry's hash.")
        lines.append("   Altering any past entry invalidates every hash after it.")
        for e in audit_entries:
            lines.append(f"   [{e['seq']:>3}] {e['timestamp'][:19]}  {e['event_type']:<24} hash={e['hash'][:16]}...")
    else:
        lines.append("   No audit events recorded for this case yet.")

    lines.append("\n" + "-" * 70)
    lines.append(
        "NOTE (reportlab not installed -- this is a plain-text fallback):\n"
        "This package is AI-assisted investigative intelligence for lead generation and\n"
        "resource prioritization, not by itself a substitute for forensic verification or\n"
        "a court-certified evidentiary chain. Run `pip install reportlab` for a formatted PDF."
    )
    return "\n".join(lines)


def generate_citizen_report(session: dict, case_ref: str):
    """
    Generates a citizen-facing PDF (or plain-text fallback) summarising
    a single classify session — safe to hand directly to the victim.

    Returns (bytes, content_type, filename, format).
    """
    if REPORTLAB_AVAILABLE:
        pdf_bytes = _build_citizen_pdf(session, case_ref)
        return pdf_bytes, "application/pdf", f"{case_ref}.pdf", "pdf"
    text = _build_citizen_text(session, case_ref)
    return text.encode("utf-8"), "text/plain", f"{case_ref}.txt", "txt"


def _build_citizen_pdf(session: dict, case_ref: str):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        topMargin=22 * 72 / 25.4, bottomMargin=18 * 72 / 25.4,
        leftMargin=18 * 72 / 25.4, rightMargin=18 * 72 / 25.4,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("CitTitle", parent=styles["Title"], fontSize=18, spaceAfter=2)
    meta_style  = ParagraphStyle("CitMeta",  parent=styles["Normal"], fontSize=9,  textColor=colors.grey)
    h2          = ParagraphStyle("CitH2",    parent=styles["Heading2"], fontSize=12, spaceBefore=14, spaceAfter=6)
    body        = styles["Normal"]
    warn_style  = ParagraphStyle("CitWarn",  parent=styles["Normal"], fontSize=9,
                                  textColor=colors.HexColor("#B3261E"), leading=14)

    verdict      = session.get("verdict", "UNKNOWN")
    risk_score   = session.get("risk_score", 0)
    scam_type    = session.get("scam_type") or session.get("type") or "—"
    channel      = session.get("channel", "—")
    district     = session.get("district") or "—"
    timestamp    = session.get("timestamp", _now())
    explanation  = session.get("explanation") or session.get("reason") or "No additional details available."
    advice       = session.get("advice") or _default_advice(verdict)

    verdict_color = {
        "SCAM_LIKELY": colors.HexColor("#B3261E"),
        "SUSPICIOUS":  colors.HexColor("#B45F06"),
        "SAFE":        colors.HexColor("#0B6E4F"),
    }.get(verdict, colors.black)

    story = []
    story.append(Paragraph("PRAHARI AI — Citizen Fraud Report", title_style))
    story.append(Paragraph(
        f"Reference: {case_ref} &nbsp;&nbsp;|&nbsp;&nbsp; Generated: {_now()}", meta_style))
    story.append(HRFlowable(width="100%", thickness=0.8,
                             color=colors.HexColor("#888888"), spaceBefore=8, spaceAfter=12))

    # ── Section 1: Result summary ──────────────────────────────────────────────
    story.append(Paragraph("1. Analysis Result", h2))
    summary_rows = [
        ["Reference",   case_ref],
        ["Verdict",     verdict],
        ["Risk Score",  f"{risk_score}/100"],
        ["Scam Type",   scam_type],
        ["Channel",     channel],
        ["District",    district],
        ["Reported At", str(timestamp)[:19]],
    ]
    t = Table(summary_rows, colWidths=[120, 350])
    t.setStyle(TableStyle([
        ("FONTSIZE",     (0, 0), (-1, -1), 9.5),
        ("FONTNAME",     (0, 0), (0, -1),  "Helvetica-Bold"),
        ("TEXTCOLOR",    (1, 1), (1, 1),   verdict_color),
        ("FONTNAME",     (1, 1), (1, 1),   "Helvetica-Bold"),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("LINEBELOW",    (0, 0), (-1, -1), 0.4, colors.HexColor("#DDDDDD")),
    ]))
    story.append(t)

    # ── Section 2: What was detected ──────────────────────────────────────────
    story.append(Paragraph("2. What Was Detected", h2))
    story.append(Paragraph(explanation, body))

    # ── Section 3: Advice ─────────────────────────────────────────────────────
    story.append(Paragraph("3. What You Should Do", h2))
    if isinstance(advice, list):
        for item in advice:
            story.append(Paragraph(f"• {item}", body))
    else:
        story.append(Paragraph(str(advice), body))

    # ── Section 4: Emergency contacts ─────────────────────────────────────────
    story.append(Paragraph("4. Emergency Contacts", h2))
    contacts = [
        ["National Cyber Crime Helpline", "1930"],
        ["Cyber Crime Portal",            "cybercrime.gov.in"],
        ["PRAHARI AI Helpline",           "support@prahari.ai (simulated)"],
    ]
    ct = Table(contacts, colWidths=[300, 170])
    ct.setStyle(_table_style())
    story.append(ct)

    # ── Footer disclaimer ──────────────────────────────────────────────────────
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CCCCCC")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<i>This report is AI-assisted analysis generated by PRAHARI AI for citizen awareness. "
        "It is not a legal document or a substitute for filing a formal complaint. "
        "Please report fraud at cybercrime.gov.in or call 1930 immediately.</i>", meta_style))

    doc.build(story)
    return buf.getvalue()


def _default_advice(verdict: str) -> list:
    if verdict == "SCAM_LIKELY":
        return [
            "Do NOT share OTPs, Aadhaar, PAN, or bank details with anyone.",
            "Hang up immediately if you are on a call with the suspected scammer.",
            "File a complaint at cybercrime.gov.in or call 1930 right away.",
            "Inform your bank if you have already shared any financial details.",
            "Screenshot and preserve any messages or call records as evidence.",
        ]
    if verdict == "SUSPICIOUS":
        return [
            "Be cautious — do not share personal or financial information yet.",
            "Verify the caller/sender through official channels before responding.",
            "If in doubt, report to 1930 or cybercrime.gov.in.",
        ]
    return [
        "This interaction appears safe, but always stay vigilant.",
        "Never share OTPs or passwords with anyone, even if they claim to be from a bank.",
    ]


def _build_citizen_text(session: dict, case_ref: str) -> str:
    verdict     = session.get("verdict", "UNKNOWN")
    risk_score  = session.get("risk_score", 0)
    scam_type   = session.get("scam_type") or session.get("type") or "—"
    channel     = session.get("channel", "—")
    district    = session.get("district") or "—"
    timestamp   = session.get("timestamp", _now())
    explanation = session.get("explanation") or session.get("reason") or "No additional details."
    advice      = session.get("advice") or _default_advice(verdict)

    lines = [
        "PRAHARI AI -- CITIZEN FRAUD REPORT",
        f"Reference: {case_ref}    Generated: {_now()}",
        "=" * 70,
        "\n1. ANALYSIS RESULT",
        f"   Verdict:     {verdict}",
        f"   Risk Score:  {risk_score}/100",
        f"   Scam Type:   {scam_type}",
        f"   Channel:     {channel}",
        f"   District:    {district}",
        f"   Reported At: {str(timestamp)[:19]}",
        "\n2. WHAT WAS DETECTED",
        f"   {explanation}",
        "\n3. WHAT YOU SHOULD DO",
    ]
    if isinstance(advice, list):
        for item in advice:
            lines.append(f"   • {item}")
    else:
        lines.append(f"   {advice}")

    lines += [
        "\n4. EMERGENCY CONTACTS",
        "   National Cyber Crime Helpline : 1930",
        "   Cyber Crime Portal            : cybercrime.gov.in",
        "   PRAHARI AI Helpline           : support@prahari.ai (simulated)",
        "\n" + "-" * 70,
        "NOTE: This is AI-assisted analysis for citizen awareness only.",
        "It is not a legal document. File a formal complaint at cybercrime.gov.in or call 1930.",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    demo_intel = {
        "cluster_id": 1, "risk_level": "HIGH", "risk_score": 78.4, "entity_count": 6,
        "entities": [{"id": "PHONE_12345678", "type": "PHONE"}, {"id": "UPI_ID_87654321", "type": "UPI_ID"}],
        "linkages": [{"from": "PHONE_12345678", "to": "UPI_ID_87654321", "relation": "shared_device", "weight": 0.91}],
        "summary": "Cluster 1 contains 6 linked entities with HIGH coordinated-fraud risk.",
    }
    import audit_log
    audit_log.append_event("ALERT_GENERATED", {"session_id": "abc123"})
    audit_log.append_event("INTEL_PACKAGE_ACCESSED", {"cluster_id": 1})
    data, ctype, fname, fmt = generate_case_file(demo_intel, audit_log.get_log(), "PRAHARI-CASE-0001")
    print(f"format={fmt} content_type={ctype} filename={fname} bytes={len(data)}")
    with open(f"/tmp/{fname}", "wb") as f:
        f.write(data)
    print(f"wrote /tmp/{fname}")
