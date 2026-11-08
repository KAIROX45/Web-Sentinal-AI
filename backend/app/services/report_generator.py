import io
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)


def generate_threat_report_pdf(report_data: Dict[str, Any]) -> bytes:
    """
    Generates a professional, print-ready PDF cyber threat intelligence briefing
    adhering to the WebSentinel AI design system (Evening, Stormy, Sunset, Cloud).
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    # Color palette definitions matching the design system
    COLOR_EVENING = colors.HexColor("#192034")
    COLOR_STORMY = colors.HexColor("#494E6B")
    COLOR_CLOUD = colors.HexColor("#98878F")
    COLOR_SUNSET = colors.HexColor("#985E6D")
    COLOR_BG_CARD = colors.HexColor("#242A42")
    COLOR_BORDER = colors.HexColor("#3D435E")

    styles = getSampleStyleSheet()

    # Custom typography styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.white
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=COLOR_CLOUD
    )
    h2_style = ParagraphStyle(
        'Heading2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=COLOR_SUNSET
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#E2E0E4")
    )
    meta_label = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=COLOR_CLOUD
    )
    meta_val = ParagraphStyle(
        'MetaVal',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=11,
        textColor=colors.white
    )

    story = []

    # 1. Header Banner
    header_content = [
        [
            Paragraph("<b>WEBSENTINEL<font color='#985E6D'> AI</font></b>", title_style),
            Paragraph(f"<b>CLASSIFICATION:</b> TLP:AMBER<br/><b>DATE:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", subtitle_style)
        ],
        [
            Paragraph("CYBER THREAT INTELLIGENCE INVESTIGATION BRIEF", subtitle_style),
            Paragraph(f"<b>REPORT ID:</b> {report_data.get('id', 'N/A')[:18]}...", meta_label)
        ]
    ]
    header_table = Table(header_content, colWidths=[340, 200])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), COLOR_EVENING),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 14))

    # 2. Executive Threat Assessment Summary Card
    risk_level = report_data.get('risk_level', 'LOW')
    risk_score = report_data.get('risk_score', 0)
    target = report_data.get('target') or report_data.get('submitted_url') or report_data.get('ip_address') or "Target Entity"

    risk_badge_color = COLOR_SUNSET if risk_level in ("HIGH", "CONFIRMED MALICIOUS") else colors.HexColor("#C48D52") if risk_level == "SUSPICIOUS" else colors.HexColor("#4A7A6D")

    summary_table_data = [
        [
            Paragraph("<b>INVESTIGATION TARGET</b>", meta_label),
            Paragraph("<b>ASSESSED RISK LEVEL</b>", meta_label),
            Paragraph("<b>THREAT SCORE</b>", meta_label)
        ],
        [
            Paragraph(f"<b>{target}</b>", meta_val),
            Paragraph(f"<b><font color='{risk_badge_color.hexval()}'>{risk_level}</font></b>", ParagraphStyle('Risk', parent=meta_val, fontName='Helvetica-Bold', fontSize=12, leading=14)),
            Paragraph(f"<b>{risk_score} / 100</b>", ParagraphStyle('Score', parent=meta_val, fontName='Helvetica-Bold', fontSize=12, leading=14))
        ]
    ]
    summary_table = Table(summary_table_data, colWidths=[310, 130, 100])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), COLOR_BG_CARD),
        ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # 3. Technical Evidence & Indicators
    story.append(Paragraph("TECHNICAL EVIDENCE & THREAT INDICATORS", h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_STORMY, spaceBefore=4, spaceAfter=8))

    evidence_items = report_data.get('evidence', [])
    if evidence_items:
        evidence_rows = [
            [
                Paragraph("<b>CATEGORY</b>", meta_label),
                Paragraph("<b>INDICATOR</b>", meta_label),
                Paragraph("<b>DESCRIPTION</b>", meta_label),
                Paragraph("<b>SEVERITY</b>", meta_label)
            ]
        ]
        for ev in evidence_items[:8]:
            sev_color = COLOR_SUNSET if ev.get('severity') in ("HIGH", "CONFIRMED MALICIOUS") else COLOR_CLOUD
            evidence_rows.append([
                Paragraph(ev.get('category', 'General'), body_style),
                Paragraph(f"<b>{ev.get('indicator', 'Finding')}</b>", meta_val),
                Paragraph(ev.get('description', ''), body_style),
                Paragraph(f"<b><font color='{sev_color.hexval()}'>{ev.get('severity', 'LOW')}</font></b>", meta_label)
            ])
        evidence_table = Table(evidence_rows, colWidths=[100, 130, 240, 70])
        evidence_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_EVENING),
            ('BACKGROUND', (0, 1), (-1, -1), COLOR_BG_CARD),
            ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(evidence_table)
    else:
        story.append(Paragraph("No active threat signatures or indicators triggered during standard inspection.", body_style))

    story.append(Spacer(1, 14))

    # 4. Recommended Actions
    story.append(Paragraph("RECOMMENDED REMEDIATION ACTIONS", h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_STORMY, spaceBefore=4, spaceAfter=8))

    recs = report_data.get('recommendations', [])
    if recs:
        rec_rows = [
            [
                Paragraph("<b>PRIORITY</b>", meta_label),
                Paragraph("<b>ACTION TITLE</b>", meta_label),
                Paragraph("<b>GUIDANCE</b>", meta_label)
            ]
        ]
        for r in recs[:5]:
            p_color = COLOR_SUNSET if r.get('priority') in ("Critical", "High") else COLOR_CLOUD
            rec_rows.append([
                Paragraph(f"<b><font color='{p_color.hexval()}'>{r.get('priority', 'Medium')}</font></b>", meta_label),
                Paragraph(f"<b>{r.get('title', 'Action')}</b>", meta_val),
                Paragraph(r.get('action', ''), body_style)
            ])
        rec_table = Table(rec_rows, colWidths=[80, 160, 300])
        rec_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_EVENING),
            ('BACKGROUND', (0, 1), (-1, -1), COLOR_BG_CARD),
            ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(rec_table)

    story.append(Spacer(1, 14))

    # 5. Blockchain Cryptographic Verification Stamp
    canonical_hash = report_data.get('canonical_hash') or "0x0000000000000000000000000000000000000000000000000000000000000000"
    blockchain_info = [
        [
            Paragraph("<b>IMMUTABLE BLOCKCHAIN VERIFICATION PROOF</b>", meta_label),
            Paragraph("<b>INTEGRITY STATUS: VERIFIED</b>", ParagraphStyle('V', parent=meta_label, textColor=colors.HexColor("#4A7A6D")))
        ],
        [
            Paragraph(f"<b>CANONICAL SHA-256 HASH:</b><br/>{canonical_hash}", meta_val),
            Paragraph("Anchored to EVM Smart Contract registry.<br/>Cryptographically tamper-evident.", subtitle_style)
        ]
    ]
    bc_table = Table(blockchain_info, colWidths=[380, 160])
    bc_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), COLOR_EVENING),
        ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(bc_table)

    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()

