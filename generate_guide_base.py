"""
AgentBreak V2 - Complete Project Explanation & Defense Guide PDF Generator
Compiles the comprehensive, professional 14-chapter technical manual for hackathon review.
"""

import os
import sys
from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    KeepTogether, PageBreak, Image, HRFlowable
)
from reportlab.pdfgen import canvas

# Page dimensions for A4: 595.27 x 841.89 points
# Margins: Left=45, Right=45, Top=54, Bottom=54
# Usable printable width = 595.27 - 90 = 505.27 points
USABLE_WIDTH = 505.0

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that accumulates total page count and renders
    professional running headers and footers on every page except cover.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            if self._pageNumber > 1:
                self.saveState()
                self.setFont('Helvetica-Bold', 7.5)
                self.setFillColor(HexColor('#1e40af'))
                self.drawString(45, 841.89 - 36, "AGENTBREAK V2")
                self.setFont('Helvetica', 7.5)
                self.setFillColor(HexColor('#64748b'))
                self.drawString(120, 841.89 - 36, "— Autonomous AI-Agent Security Testing & Defense Guide")
                
                # Header divider line
                self.setStrokeColor(HexColor('#cbd5e1'))
                self.setLineWidth(0.5)
                self.line(45, 841.89 - 42, 595.27 - 45, 841.89 - 42)
                
                # Footer divider line
                self.line(45, 42, 595.27 - 45, 42)
                self.drawString(45, 30, "ByteForge College Round | Confidential Presentation & Architecture Guide")
                page_str = f"Page {self._pageNumber} of {num_pages}"
                self.drawRightString(595.27 - 45, 30, page_str)
                self.restoreState()
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

def setup_styles():
    """Initializes and returns custom typographic styles."""
    styles = getSampleStyleSheet()
    
    # Document Level
    styles.add(ParagraphStyle(
        'CoverSuper',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=HexColor('#2563eb'),
        spaceAfter=10,
        alignment=0
    ))
    styles.add(ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=26,
        leading=32,
        textColor=HexColor('#0f172a'),
        spaceAfter=12,
        alignment=0
    ))
    styles.add(ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=13,
        leading=18,
        textColor=HexColor('#334155'),
        spaceAfter=20,
        alignment=0
    ))
    styles.add(ParagraphStyle(
        'ChapterHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=HexColor('#0f172a'),
        spaceBefore=16,
        spaceAfter=8,
        keepWithNext=True
    ))
    styles.add(ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11.5,
        leading=15,
        textColor=HexColor('#1e40af'),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    ))
    styles.add(ParagraphStyle(
        'SubSectionHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=13,
        textColor=HexColor('#0f172a'),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    ))
    styles.add(ParagraphStyle(
        'BodyCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=HexColor('#1e293b'),
        spaceAfter=5
    ))
    styles.add(ParagraphStyle(
        'BodyCustomBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=12,
        textColor=HexColor('#0f172a'),
        spaceAfter=5
    ))
    styles.add(ParagraphStyle(
        'BulletCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=HexColor('#1e293b'),
        leftIndent=12,
        firstLineIndent=-8,
        spaceAfter=3
    ))
    styles.add(ParagraphStyle(
        'CodeText',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.2,
        leading=9.5,
        textColor=HexColor('#0f172a')
    ))
    styles.add(ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=HexColor('#ffffff'),
        alignment=0
    ))
    styles.add(ParagraphStyle(
        'TableBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.2,
        leading=9.5,
        textColor=HexColor('#1e293b'),
        alignment=0
    ))
    styles.add(ParagraphStyle(
        'TableBodyBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.2,
        leading=9.5,
        textColor=HexColor('#0f172a'),
        alignment=0
    ))
    return styles

def make_callout(text, title=None, alert_type="note", styles=None):
    """Generates a clean GitHub-style callout box."""
    configs = {
        "note": ("#eff6ff", "#3b82f6", "#1d4ed8", "NOTE"),
        "tip": ("#f0fdf4", "#10b981", "#047857", "TIP"),
        "warning": ("#fffbeb", "#f59e0b", "#b45309", "WARNING"),
        "danger": ("#fef2f2", "#ef4444", "#b91c1c", "CRITICAL WARNING"),
        "security": ("#faf5ff", "#8b5cf6", "#6d28d9", "SECURITY NOTICE"),
    }
    bg_hex, border_hex, text_hex, default_title = configs.get(alert_type, configs["note"])
    box_title = title if title else default_title

    content = [
        Paragraph(f"<b>{box_title}:</b>", ParagraphStyle('CT', fontName='Helvetica-Bold', fontSize=8, leading=10, textColor=HexColor(text_hex), spaceAfter=2)),
        Paragraph(text, ParagraphStyle('CB', fontName='Helvetica', fontSize=7.8, leading=10.5, textColor=HexColor('#1e293b')))
    ]
    t = Table([[content]], colWidths=[USABLE_WIDTH])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), HexColor(bg_hex)),
        ('BOX', (0,0), (-1,-1), 0.5, HexColor(border_hex)),
        ('LINELEFT', (0,0), (-1,-1), 3.0, HexColor(border_hex)),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    return t

def make_code_box(code_text, styles):
    """Renders formatted code blocks with syntax background."""
    escaped = (code_text.strip()
               .replace('&', '&amp;')
               .replace('<', '&lt;')
               .replace('>', '&gt;')
               .replace('\n', '<br/>')
               .replace(' ', '&nbsp;'))
    p = Paragraph(escaped, styles['CodeText'])
    t = Table([[p]], colWidths=[USABLE_WIDTH])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 0.5, HexColor('#cbd5e1')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    return t

def make_table(headers, rows, col_widths, styles, header_bg='#1e3a8a'):
    """Generates standard styled tables with automatic text wrapping."""
    table_data = []
    # Header row
    header_row = [Paragraph(f"<b>{h}</b>", styles['TableHeader']) for h in headers]
    table_data.append(header_row)
    
    # Body rows
    for r in rows:
        row_cells = []
        for c in r:
            if isinstance(c, str):
                row_cells.append(Paragraph(c, styles['TableBody']))
            elif isinstance(c, (list, tuple)):
                row_cells.append([Paragraph(item, styles['TableBody']) for item in c])
            else:
                row_cells.append(c)
        table_data.append(row_cells)

    t = Table(table_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), HexColor(header_bg)),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 3.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3.5),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [HexColor('#ffffff'), HexColor('#f8fafc')]),
        ('GRID', (0,0), (-1,-1), 0.5, HexColor('#e2e8f0')),
    ]))
    return t

print("Helper definitions successfully configured.")
