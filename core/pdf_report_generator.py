import os
from datetime import datetime
from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORTS_DIR = _PROJECT_ROOT / "output" / "reports"

class PdfReportGenerator:
    """
    Generates formal structurally complete PDF reports for PQC Scans.
    Uses reportlab to dynamically scale text and table visuals mapping
    the 1-10 priority matrices.
    """

    def __init__(self, output_dir: str | Path | None = None):
        self.output_dir = Path(output_dir) if output_dir else DEFAULT_REPORTS_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, assessment_data: dict, domain_name: str = "PQC") -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{domain_name}_Migration_Report_{timestamp}.pdf"
        filepath = self.output_dir / filename

        doc = SimpleDocTemplate(str(filepath), pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = styles['Title']
        heading_style = styles['Heading2']
        normal_style = styles['BodyText']
        bullet_style = ParagraphStyle(
            name='Bullet',
            parent=styles['Normal'],
            leftIndent=20,
            bulletIndent=10
        )

        elements = []

        # 1. Title Page & Executive Summary
        elements.append(Paragraph(f"Post-Quantum Cryptography Assessment", title_style))
        elements.append(Paragraph(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("Executive Summary", heading_style))
        summary_text = (
            f"This formal report outlines the Post-Quantum Cryptographic (PQC) readiness of the requested infrastructure '{domain_name}'. "
            "It maps discovered endpoints and capabilities against upcoming quantum computing risks (Shor's Algorithm) based on the latest NIST transitions (FIPS 203, 204, 205)."
        )
        elements.append(Paragraph(summary_text, normal_style))
        elements.append(Spacer(1, 20))

        # 2. Priority Ranking Matrix
        elements.append(Paragraph("Infrastructure Priority Matrix (1-10)", heading_style))
        
        table_data = [["Rank", "Asset", "Score", "Verdict"]]
        rated_assets = assessment_data.get("rated_assets", [])
        
        for item in rated_assets:
            table_data.append([
                str(item.get("priority_rank", "-")),
                item.get("asset", "Unknown"),
                f"{item.get('score_100', '?')}/100",
                item.get("verdict", "Unknown")
            ])
            
        t = Table(table_data, colWidths=[40, 200, 60, 200])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.beige),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 30))

        # 3. Detailed Breakdown
        elements.append(Paragraph("Detailed Asset Breakdown & Migration Roadmaps", heading_style))
        
        for idx, item in enumerate(rated_assets, 1):
            asset_name = item.get("asset", "Unknown")
            score_100 = item.get("score_100", "?")
            action = item.get("action", "Unknown")
            priority = item.get("priority_level", "?")

            elements.append(Paragraph(f"Asset #{idx}: {asset_name}", styles['Heading3']))
            elements.append(Paragraph(f"Risk Score: {score_100}/100 — Priority: {priority} — {action}", normal_style))
            elements.append(Spacer(1, 10))

            # 10-Parameter Scores Table
            param_scores = item.get("parameter_scores", {})
            if param_scores:
                elements.append(Paragraph("Parameter Analysis (10 Dimensions):", normal_style))
                param_table_data = [["Parameter", "Score", "Weight", "Details"]]
                for param_name, param_data in param_scores.items():
                    score_val = param_data.get("score")
                    score_str = f"{score_val:.2f}" if score_val is not None else "N/A"
                    weight_str = f"{param_data.get('effective_weight', 0):.2f}"
                    details = param_data.get("details", "")[:60]
                    param_table_data.append([param_name.replace("_", " ").title(), score_str, weight_str, details])

                pt = Table(param_table_data, colWidths=[140, 45, 45, 270])
                pt.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('ALIGN', (1,0), (2,-1), 'CENTER'),
                    ('BACKGROUND', (0,1), (-1,-1), colors.lightblue),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.whitesmoke, colors.lightblue]),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ]))
                elements.append(pt)
                elements.append(Spacer(1, 10))

            # Recommendations
            recs = item.get("migration_recommendations", [])
            elements.append(Paragraph("Required Migration Steps:", normal_style))
            if recs:
                for rec in recs:
                    elements.append(Paragraph(f"• {rec}", bullet_style))
            else:
                elements.append(Paragraph("• No immediate cryptographic migrations mapped currently.", bullet_style))

            elements.append(Spacer(1, 20))

        # Build Document
        doc.build(elements)
        return str(filepath)
