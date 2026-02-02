import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak


def generate_pdf(scan, vulnerabilities):
    file_path = f"reports/scan_report_{scan.id}.pdf"
    
    # Ensure reports directory exists
    os.makedirs("reports", exist_ok=True)

    doc = SimpleDocTemplate(
        file_path,
        pagesize=A4,
        rightMargin=50,
        leftMargin=50,
        topMargin=50,
        bottomMargin=50,
        author=f"XScan Security ({scan.user.username})",
        title=f"Security Report - {scan.target_url}"
    )

    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle(
        'MainTitle',
        parent=styles['Heading1'],
        fontSize=24,
        fontName='Helvetica-Bold',
        spaceAfter=20,
        textColor=colors.HexColor("#2C3E50")
    )
    
    section_title_style = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading2'],
        fontSize=16,
        fontName='Helvetica-Bold',
        spaceAfter=12,
        spaceBefore=20,
        textColor=colors.HexColor("#34495E")
    )

    severity_styles = {
        "Critical": colors.HexColor("#D32F2F"),
        "High": colors.HexColor("#F57C00"),
        "Medium": colors.HexColor("#FBC02D"),
        "Low": colors.HexColor("#388E3C")
    }

    elements = []

    # --- Header Branding ---
    elements.append(Paragraph("XSCAN Security Report", title_style))
    elements.append(Paragraph(f"Official Security Assessment for {scan.target_url}", styles['Normal']))
    elements.append(Spacer(1, 0.2 * inch))
    
    # Add a colored line
    line_data = [[""]]
    line_table = Table(line_data, colWidths=[doc.width])
    line_table.setStyle(TableStyle([
        ('LINEBELOW', (0,0), (-1,-1), 2, colors.HexColor("#F1C40F")),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    elements.append(line_table)
    elements.append(Spacer(1, 0.3 * inch))

    # --- Executive Summary ---
    elements.append(Paragraph("Executive Summary", section_title_style))
    
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for v in vulnerabilities:
        counts[v.severity] = counts.get(v.severity, 0) + 1

    summary_data = [
        ["Severity", "Findings Count"],
        ["Critical", counts["Critical"]],
        ["High", counts["High"]],
        ["Medium", counts["Medium"]],
        ["Low", counts["Low"]],
    ]
    
    summary_table = Table(summary_data, colWidths=[1.5*inch, 1*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2C3E50")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('GRID', (0,0), (-1,-1), 1, colors.grey),
        ('BACKGROUND', (0,1), (0,1), severity_styles["Critical"]),
        ('BACKGROUND', (0,2), (0,2), severity_styles["High"]),
        ('BACKGROUND', (0,3), (0,3), severity_styles["Medium"]),
        ('BACKGROUND', (0,4), (0,4), severity_styles["Low"]),
        ('TEXTCOLOR', (0,1), (0,4), colors.whitesmoke),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.4 * inch))

    # --- Scan Details ---
    elements.append(Paragraph("Scan Metadata", section_title_style))
    meta_data = [
        ["Item", "Detail"],
        ["Scan ID", f"XSC-{scan.id}"],
        ["Target URL", scan.target_url],
        ["Lead Researcher", scan.user.username.capitalize()],
        ["Generated On", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Scan Protocol", scan.scan_type.upper()],
    ]
    meta_table = Table(meta_data, colWidths=[1.5*inch, 3.5*inch])
    meta_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('BACKGROUND', (0,0), (1,0), colors.HexColor("#ECF0F1")),
    ]))
    elements.append(meta_table)
    
    # --- Detailed Findings ---
    elements.append(PageBreak())
    elements.append(Paragraph("Detailed Findings", section_title_style))

    if not vulnerabilities:
        elements.append(Paragraph("No security vulnerabilities were identified during this assessment.", styles['Italic']))
    else:
        for i, v in enumerate(vulnerabilities):
            v_title = Paragraph(f"{i+1}. {v.title}", styles['Heading3'])
            elements.append(v_title)
            
            # Severity Badge
            sev_color = severity_styles.get(v.severity, colors.grey)
            sev_data = [[v.severity.upper()]]
            sev_table = Table(sev_data, colWidths=[1*inch])
            sev_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), sev_color),
                ('TEXTCOLOR', (0,0), (-1,-1), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
            ]))
            elements.append(sev_table)
            elements.append(Spacer(1, 0.1 * inch))
            
            # Description & Mitigation
            detail_data = [
                ["Description", Paragraph(v.description, styles['Normal'])],
                ["Mitigation", Paragraph(v.mitigation, styles['Normal'])],
            ]
            detail_table = Table(detail_data, colWidths=[1.2*inch, 4*inch])
            detail_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            ]))
            elements.append(detail_table)
            elements.append(Spacer(1, 0.2 * inch))

    # --- Footer ---
    def add_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 9)
        footer_text = f"XSCAN Professional Report - Page {doc.page}"
        canvas.drawCentredString(A4[0]/2, 30, footer_text)
        canvas.restoreState()

    doc.build(elements, onFirstPage=add_footer, onLaterPages=add_footer)
    return file_path
