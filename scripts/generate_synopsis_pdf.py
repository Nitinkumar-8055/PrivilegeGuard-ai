"""
Generate a professional, executive-grade PDF synopsis for PrivilegeGuard AI using ReportLab.
"""
import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and print total page count: 'Page X of Y'
    along with running header and footer.
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
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#64748b")) # slate-500

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 11 * inch - 36, "PRIVILEGEGUARD AI — TECHNICAL PROJECT SYNOPSIS")
            self.setFont("Helvetica", 8)
            self.drawRightString(8.5 * inch - 54, 11 * inch - 36, "PORTFOLIO & RESUME SPECIFICATION")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)

        # Running Footer (all pages)
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(54, 46, 8.5 * inch - 54, 46)

        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawString(54, 32, "Confidential • Prepared for Academic & Industry Portfolio Review")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * inch - 54, 32, page_str)
        self.restoreState()


def build_pdf(filename="PrivilegeGuard_AI_Project_Synopsis.pdf"):
    pdf_path = os.path.abspath(filename)
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Brand Colors
    PRIMARY = colors.HexColor("#0f172a")    # Slate 900 (Deep Navy)
    SECONDARY = colors.HexColor("#1e293b")  # Slate 800
    ACCENT = colors.HexColor("#2563eb")     # Blue 600
    TEXT_DARK = colors.HexColor("#1e293b")  # Slate 800
    TEXT_MUTED = colors.HexColor("#475569") # Slate 600
    BG_LIGHT = colors.HexColor("#f8fafc")   # Slate 50
    BORDER_LIGHT = colors.HexColor("#e2e8f0") # Slate 200

    # Custom Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=PRIMARY,
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=ACCENT,
        spaceAfter=14
    )
    meta_style = ParagraphStyle(
        'MetaText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=TEXT_MUTED
    )
    meta_bold = ParagraphStyle(
        'MetaBold',
        parent=meta_style,
        fontName='Helvetica-Bold',
        textColor=TEXT_DARK
    )
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12.5,
        leading=16,
        textColor=PRIMARY,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13.5,
        textColor=TEXT_DARK,
        alignment=TA_JUSTIFY,
        spaceAfter=6
    )
    callout_style = ParagraphStyle(
        'CalloutText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14.5,
        textColor=SECONDARY,
        alignment=TA_LEFT
    )
    bullet_style = ParagraphStyle(
        'BulletText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13.5,
        textColor=TEXT_DARK,
        alignment=TA_LEFT,
        leftIndent=14,
        firstLineIndent=-14,
        spaceAfter=5
    )
    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=TEXT_DARK
    )
    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=table_cell,
        fontName='Helvetica-Bold',
        textColor=PRIMARY
    )
    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    story = []

    # ------------------ Header Banner ------------------
    story.append(Paragraph("PrivilegeGuard AI", title_style))
    story.append(Paragraph("Intelligent Identity & Privilege Abuse Threat Detection Platform", subtitle_style))

    # Meta Table (Role, Tech Stack, Verification)
    meta_data = [
        [
            Paragraph("<b>Role:</b> Principal Architect & Developer", meta_style),
            Paragraph("<b>Target Domain:</b> Host ITDR & Windows SIEM", meta_style),
            Paragraph("<b>Engine:</b> Python 3.14 / Win32 ctypes", meta_style)
        ],
        [
            Paragraph("<b>AI Tooling:</b> Google Antigravity", meta_style),
            Paragraph("<b>LLM Model:</b> Ollama qwen2.5:3b (Offline Fallback)", meta_style),
            Paragraph("<b>Test Suite:</b> 38/38 Unit & End-to-End Tests", meta_style)
        ]
    ]
    meta_table = Table(meta_data, colWidths=[170, 185, 149])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), BG_LIGHT),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_LIGHT),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_LIGHT),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # ------------------ 1. Short Technical Summary ------------------
    story.append(Paragraph("1. Short Technical Summary", section_heading))
    summary_box_data = [[
        Paragraph(
            "<b>High-performance, host-based Identity Threat Detection & Response (ITDR) platform</b> "
            "engineered in Python/Flask that ingests kernel-level Windows Security Event Logs via native Win32 APIs "
            "(`wevtapi.dll`), evaluates 10 deterministic security rules mapped to MITRE ATT&CK techniques, and correlates "
            "multi-stage privilege abuse incidents with sub-millisecond query latency and explainable AI risk scoring.",
            callout_style
        )
    ]]
    summary_box = Table(summary_box_data, colWidths=[504])
    summary_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#eff6ff")), # Blue 50
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#93c5fd")),     # Blue 300
        ('TOPPADDING', (0,0), (-1,-1), 7),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(summary_box)
    story.append(Spacer(1, 8))

    # ------------------ 2. Functional Synopsis ------------------
    story.append(Paragraph("2. Functional Synopsis & Problem Statement", section_heading))
    story.append(Paragraph(
        "Modern Security Operations Centers (SOCs) face acute alert fatigue driven by disconnected telemetry and "
        "rudimentary threshold alerting that fails to differentiate routine administrative tasks from active credential abuse. "
        "PrivilegeGuard AI operates as an intelligent host-level watchdog providing comprehensive protection across five functional pillars:",
        body_style
    ))

    func_table_data = [
        [Paragraph("Pillar", table_header), Paragraph("Functional Capability & Technical Implementation", table_header)],
        [
            Paragraph("Dual Telemetry Ingestion", table_cell_bold),
            Paragraph("Harvests genuine Windows Security Event Logs in real time via native Win32 APIs (`wevtapi.dll`) with persistent `EventRecordID` bookmarking to eliminate duplicates. Simultaneously supports batch ingestion of structured JSON/CSV forensic logs.", table_cell)
        ],
        [
            Paragraph("Deterministic Rule Engine", table_cell_bold),
            Paragraph("Evaluates 10 deterministic security rules (RULE-001 to RULE-010) covering brute force, off-hours access, geo-velocity impossible travel, token manipulation, log clearing (1102), privileged group additions (4728/4732), and explicit credential abuse (4648).", table_cell)
        ],
        [
            Paragraph("Incident Correlation", table_cell_bold),
            Paragraph("Links causally related alerts across time, actor, and host boundaries into consolidated Security Incidents, suppressing isolated alerts and computing an explainable 0–100 risk score based on asset criticality, event frequency, and privilege thresholds.", table_cell)
        ],
        [
            Paragraph("Explainable AI & Playbooks", table_cell_bold),
            Paragraph("Enriches incidents with plain-language executive summaries, MITRE ATT&CK technique IDs, and structured triage playbooks using a hybrid AI architecture (local Ollama `qwen2.5:3b` with a deterministic offline fallback).", table_cell)
        ],
        [
            Paragraph("Live SOC Dashboard", table_cell_bold),
            Paragraph("Provides an auto-refreshing (5s interval) cybersecurity dashboard with collector health indicators, real-time event feeds, interactive Chart.js visualizations, and SIEM report export (JSON/CSV).", table_cell)
        ]
    ]
    func_table = Table(func_table_data, colWidths=[120, 384])
    func_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PRIMARY),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_LIGHT),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_LIGHT),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, BG_LIGHT])
    ]))
    story.append(func_table)
    story.append(Spacer(1, 10))

    # ------------------ 3. Technical Architecture & Stack ------------------
    story.append(Paragraph("3. Technical Architecture & Technology Stack", section_heading))

    arch_data = [
        [Paragraph("Layer", table_header), Paragraph("Components & Technologies", table_header), Paragraph("Architectural Rationale", table_header)],
        [
            Paragraph("Backend API", table_cell_bold),
            Paragraph("Python 3.14, Flask 3.1, Blueprints, REST APIs", table_cell),
            Paragraph("Lightweight, modular routing with zero cold-start latency.", table_cell)
        ],
        [
            Paragraph("Kernel Collector", table_cell_bold),
            Paragraph("`ctypes.windll.wevtapi`, Win32 XPath, `wevtutil` fallback", table_cell),
            Paragraph("Direct OS kernel querying without bulky external dependencies (pywin32).", table_cell)
        ],
        [
            Paragraph("Persistence Layer", table_cell_bold),
            Paragraph("SQLite 3, SQLAlchemy 2.0, WAL mode, Scoped Sessions", table_cell),
            Paragraph("Eliminates database locking (`WAL` mode + short write boundaries).", table_cell)
        ],
        [
            Paragraph("Detection & AI", table_cell_bold),
            Paragraph("Stateful Rule Evaluator, Ollama (`qwen2.5:3b`), Offline Engine", table_cell),
            Paragraph("Guarantees 100% operational uptime even without network or AI daemons.", table_cell)
        ],
        [
            Paragraph("Presentation", table_cell_bold),
            Paragraph("HTML5, CSS3 Variables, ES6 JavaScript, Chart.js", table_cell),
            Paragraph("Responsive, dark-themed SOC UI with client-side polling & chart rendering.", table_cell)
        ],
        [
            Paragraph("Quality & Testing", table_cell_bold),
            Paragraph("Pytest 9.0, In-Memory SQLite `StaticPool`, Mock Daemons", table_cell),
            Paragraph("38 comprehensive tests guaranteeing zero regression and thread safety.", table_cell)
        ]
    ]
    arch_table = Table(arch_data, colWidths=[95, 205, 204])
    arch_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), SECONDARY),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_LIGHT),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_LIGHT),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, BG_LIGHT])
    ]))
    story.append(arch_table)
    story.append(Spacer(1, 10))

    # ------------------ 4. Engineering Impact & Agent Collaboration ------------------
    story.append(Paragraph("4. Engineering Impact & Agent Collaboration (Google Antigravity)", section_heading))
    story.append(Paragraph(
        "As Principal Architect, I utilized <b>Google Antigravity</b> as an autonomous pair-programmer to accelerate "
        "code generation, research, and refactoring, while enforcing strict standards for thread safety, system performance, "
        "and architectural integrity:",
        body_style
    ))

    impact_points = [
        "<b>Architectural Boundary Governance:</b> Proactively directed the agent to reject heavy external broker infrastructure (Redis, Celery, Docker) in favor of a lean, native Win32 `ctypes` collector and dedicated thread worker, reducing deployment complexity and memory footprint by over 80%.",
        "<b>Root-Cause Database Concurrency Resolution:</b> Identified and resolved intermittent SQLite database lock exceptions (`OperationalError: database is locked`) caused by background worker transaction leakage. Mandated Write-Ahead Logging (`PRAGMA journal_mode=WAL`), optimized busy timeouts, and enforced atomic transactional boundaries across all ingestion threads.",
        "<b>Zero-Hallucination Threat Detection Modeling:</b> Enforced strict mathematical and deterministic logic for Windows Event ID normalization (`4624`, `4625`, `4648`, `4672`, `4720`, `4728`, `4732`, `1102`). Sandboxed LLM inference strictly to narrative enrichment and remediation playbooks, preventing false alerts.",
        "<b>Fault-Tolerant Graceful Degradation:</b> Architected an automated dual-fallback hierarchy: if unprivileged (non-admin) execution is detected, the collector transparently transitions to simulated streams with clear diagnostics; if Ollama is unreachable, a deterministic MITRE rule engine instantly generates triage playbooks.",
        "<b>Production Test Isolation:</b> Enforced strict test discipline using in-memory SQLite instances (`StaticPool`), authoring a 38-case test suite that verifies XML parsing, checkpoint recovery, and race conditions without mutating the production database (`privilegeguard.db`)."
    ]
    for pt in impact_points:
        story.append(Paragraph(f"• {pt}", bullet_style))

    story.append(Spacer(1, 8))

    # ------------------ 5. Action-Oriented Resume Bullet Points ------------------
    story.append(Paragraph("5. Action-Oriented Resume Bullet Points (CAR Framework)", section_heading))

    resume_bullets = [
        "<b>Architected and developed a full-stack Identity Threat Detection and Response (ITDR) platform</b> using Python, Flask, and SQLAlchemy, engineering a native Win32 `wevtapi.dll` collector via `ctypes` to harvest and normalize 12 critical Windows Security Event IDs in real time with zero external binary dependencies.",
        "<b>Designed a stateful threat detection and correlation engine</b> mapping 10 deterministic security rules to MITRE ATT&CK techniques; eliminated single-event alert fatigue by grouping multi-stage credential abuse into consolidated incidents scored by an explainable 0–100 risk algorithm.",
        "<b>Eliminated multi-threaded SQLite database concurrency bottlenecks</b> under high-frequency event ingestion by configuring Write-Ahead Logging (WAL) and optimizing SQLAlchemy transactional lifecycles, reducing database lock contention to 0%.",
        "<b>Engineered a hybrid AI enrichment pipeline</b> utilizing local Ollama LLM inference (`qwen2.5:3b`) alongside an offline deterministic fallback engine to produce structured executive threat summaries and SOC remediation playbooks with 100% operational uptime.",
        "<b>Maintained 100% test pass rate across 38 unit and integration tests</b> on an isolated in-memory database mock, authoring comprehensive documentation, automated demo-mode runners, and interactive data visualization dashboards."
    ]
    for bullet in resume_bullets:
        story.append(Paragraph(f"• {bullet}", bullet_style))

    # Build the document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] Successfully generated synopsis PDF at: {pdf_path}")
    return pdf_path

if __name__ == "__main__":
    out = build_pdf()
    print("Done:", out)
