import re
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def build_pdf_report(
    suspicious_df,
    summary_text: str,
    top_finding: str,
    threat_score: int,
    threat_level: str,
    generated_report: str,
    audience: str,
    report_style: str,
    include_mitre: bool,
    analyst_status: str = "Investigating",
    analyst_notes: str = "",
) -> bytes:
    """
    Build a professional PDF investigation report
    and return it as bytes.
    """

    # Clean small formatting artifacts from generated content.
    summary_text = summary_text.replace("ATT&CK;", "ATT&CK")
    top_finding = top_finding.replace("ATT&CK;", "ATT&CK")

    if generated_report:
        generated_report = generated_report.replace(
            "ATT&CK;",
            "ATT&CK",
        )

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title="SignalScope AI Investigation Report",
        author="SignalScope AI",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "SignalScopeTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        alignment=TA_LEFT,
        spaceAfter=6,
    )

    subtitle_style = ParagraphStyle(
        "SignalScopeSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#555555"),
        spaceAfter=18,
    )

    section_style = ParagraphStyle(
        "SignalScopeSection",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        spaceBefore=10,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "SignalScopeBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=14,
        spaceAfter=7,
    )

    small_style = ParagraphStyle(
        "SignalScopeSmall",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#555555"),
    )

    story = []

    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "SIGNALSCOPE AI",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "Security Investigation Report",
            subtitle_style,
        )
    )

    metadata = [
        ["Audience", audience],
        ["Report Style", report_style],
        ["Findings", str(len(suspicious_df))],
    ]

    metadata_table = Table(
        metadata,
        colWidths=[
            1.25 * inch,
            5.75 * inch,
        ],
    )

    metadata_table.setStyle(
        TableStyle(
            [
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#F1F5F9"),
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#CBD5E1"),
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.25,
                    colors.HexColor("#E2E8F0"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
            ]
        )
    )

    story.append(
        metadata_table
    )

    story.append(
        Spacer(1, 0.18 * inch)
    )

    # --------------------------------------------------------
    # Threat overview
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "INVESTIGATION OVERVIEW",
            section_style,
        )
    )

    overview_data = [
        [
            Paragraph(
                "<b>Threat Score</b>",
                body_style,
            ),
            Paragraph(
                f"<b>{threat_score}/100</b>",
                body_style,
            ),
        ],
        [
            Paragraph(
                "<b>Threat Level</b>",
                body_style,
            ),
            Paragraph(
                threat_level,
                body_style,
            ),
        ],
    ]

    overview_table = Table(
        overview_data,
        colWidths=[
            1.6 * inch,
            5.4 * inch,
        ],
    )

    overview_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#F8FAFC"),
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#CBD5E1"),
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.25,
                    colors.HexColor("#E2E8F0"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(
        overview_table
    )

    # --------------------------------------------------------
    # Incident summary
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "INCIDENT SUMMARY",
            section_style,
        )
    )

    story.append(
        Paragraph(
            summary_text,
            body_style,
        )
    )

    # --------------------------------------------------------
    # Top finding
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "TOP FINDING",
            section_style,
        )
    )

    top_finding_table = Table(
        [
            [
                Paragraph(
                    top_finding,
                    body_style,
                )
            ]
        ],
        colWidths=[7.0 * inch],
    )

    top_finding_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor("#F8FAFC"),
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.75,
                    colors.HexColor("#CBD5E1"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
            ]
        )
    )

    story.append(
        top_finding_table
    )

    # --------------------------------------------------------
    # Suspicious events
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "SUSPICIOUS EVENTS",
            section_style,
        )
    )

    event_columns = [
        "timestamp",
        "username",
        "source_ip",
        "severity",
        "suspicion_reason",
    ]

    available_columns = [
        column
        for column in event_columns
        if column in suspicious_df.columns
    ]

    table_data = [
        [
            Paragraph(
                column.replace(
                    "_",
                    " ",
                ).title(),
                small_style,
            )
            for column in available_columns
        ]
    ]

    for _, row in suspicious_df.iterrows():

        table_row = []

        for column in available_columns:

            value = str(
                row.get(
                    column,
                    "",
                )
            )

            table_row.append(
                Paragraph(
                    value,
                    small_style,
                )
            )

        table_data.append(
            table_row
        )

    if len(table_data) > 1:

        column_widths = [
            1.0 * inch,
            0.7 * inch,
            1.0 * inch,
            0.65 * inch,
            3.65 * inch,
        ]

        column_widths = (
            column_widths[
                : len(available_columns)
            ]
        )

        events_table = Table(
            table_data,
            colWidths=column_widths,
            repeatRows=1,
        )

        events_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#E2E8F0"),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#0F172A"),
                    ),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.HexColor("#CBD5E1"),
                    ),
                    (
                        "INNERGRID",
                        (0, 0),
                        (-1, -1),
                        0.25,
                        colors.HexColor("#E2E8F0"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                ]
            )
        )

        story.append(
            events_table
        )

    else:

        story.append(
            Paragraph(
                "No suspicious events were detected.",
                body_style,
            )
        )

    # --------------------------------------------------------
    # MITRE ATT&CK
    # --------------------------------------------------------

    if include_mitre:

        story.append(
            Paragraph(
                "MITRE ATT&amp;CK",
                section_style,
            )
        )

        if (
            not suspicious_df.empty
            and "mitre_technique"
            in suspicious_df.columns
        ):

            techniques = (
                suspicious_df[
                    "mitre_technique"
                ]
                .dropna()
                .astype(str)
                .drop_duplicates()
                .tolist()
            )

            if techniques:

                for technique in techniques:

                    story.append(
                        Paragraph(
                            f"- {technique}",
                            body_style,
                        )
                    )

            else:

                story.append(
                    Paragraph(
                        "No MITRE ATT&CK mappings available.",
                        body_style,
                    )
                )

        else:

            story.append(
                Paragraph(
                    "No MITRE ATT&CK mappings available.",
                    body_style,
                )
            )

    # --------------------------------------------------------
    # AI investigation
    # --------------------------------------------------------

    if generated_report:

        story.append(
            Paragraph(
                "AI INVESTIGATION",
                section_style,
            )
        )

        # ReportLab Paragraph expects HTML-like markup,
        # so convert the basic Markdown produced by the AI
        # into simple HTML-like formatting.
        report_parts = (
            generated_report
            .replace(
                "\r\n",
                "\n",
            )
            .split("\n")
        )

        for part in report_parts:

            cleaned = part.strip()

            if not cleaned:
                story.append(
                    Spacer(
                        1,
                        0.06 * inch,
                    )
                )
                continue

            # ------------------------------------------------
            # Markdown headings
            # ------------------------------------------------

            if cleaned.startswith("### "):

                story.append(
                    Paragraph(
                        cleaned[4:],
                        section_style,
                    )
                )

                continue

            if cleaned.startswith("## "):

                story.append(
                    Paragraph(
                        cleaned[3:],
                        section_style,
                    )
                )

                continue

            # ------------------------------------------------
            # Numbered list items
            # ------------------------------------------------

            if re.match(
                r"^\d+\.\s+",
                cleaned,
            ):

                list_number = re.match(
                    r"^(\d+)\.\s+",
                    cleaned,
                ).group(1)

                list_text = re.sub(
                    r"^\d+\.\s+",
                    "",
                    cleaned,
                )

                list_text = re.sub(
                    r"\*\*(.*?)\*\*",
                    r"<b>\1</b>",
                    list_text,
                )

                story.append(
                    Paragraph(
                        f"{list_number}. {list_text}",
                        body_style,
                    )
                )

                continue

            # ------------------------------------------------
            # Bullet list items
            # ------------------------------------------------

            if cleaned.startswith("- "):

                bullet_text = cleaned[2:]

                bullet_text = re.sub(
                    r"\*\*(.*?)\*\*",
                    r"<b>\1</b>",
                    bullet_text,
                )

                story.append(
                    Paragraph(
                        f"- {bullet_text}",
                        body_style,
                    )
                )

                continue

            # ------------------------------------------------
            # Bold Markdown
            # ------------------------------------------------
            
            cleaned = cleaned.replace(
                "&",
                "&amp;",
            )

            cleaned = re.sub(
                r"\*\*(.*?)\*\*",
                r"<b>\1</b>",
                cleaned,
            )

            # ------------------------------------------------
            # Inline code
            # ------------------------------------------------

            cleaned = re.sub(
                r"`([^`]+)`",
                r"<font name='Courier'>\1</font>",
                cleaned,
            )

            story.append(
                Paragraph(
                    cleaned,
                    body_style,
                )
            ) 

    # --------------------------------------------------------
    # Analyst assessment
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "ANALYST ASSESSMENT",
            section_style,
        )
    )

    assessment_data = [
        [
            Paragraph(
                "<b>Investigation Status</b>",
                body_style,
            ),
            Paragraph(
                str(analyst_status),
                body_style,
            ),
        ],
    ]

    assessment_table = Table(
        assessment_data,
        colWidths=[
            1.6 * inch,
            5.4 * inch,
        ],
    )

    assessment_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#F8FAFC"),
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#CBD5E1"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(
        assessment_table
    )

    story.append(
        Spacer(
            1,
            0.08 * inch,
        )
    )

    story.append(
        Paragraph(
            "<b>Analyst Notes</b>",
            body_style,
        )
    )

    if analyst_notes.strip():

        safe_notes = (
            analyst_notes
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

        story.append(
            Paragraph(
                safe_notes,
                body_style,
            )
        )

    else:

        story.append(
            Paragraph(
                "No analyst notes were recorded.",
                small_style,
            )
        )

    story.append(
        Spacer(
            1,
            0.08 * inch,
        )
    )

    story.append(
        Paragraph(
            "This assessment reflects analyst judgment after "
            "reviewing the available SignalScope evidence and "
            "AI-assisted analysis.",
            small_style,
        )
    )
    
    # --------------------------------------------------------
    # Footer
    # --------------------------------------------------------

    story.append(
        Spacer(
            1,
            0.2 * inch,
        )
    )

    story.append(
        Paragraph(
            "Generated by SignalScope AI. "
            "Threat scoring is determined by the "
            "SignalScope deterministic detection engine.",
            small_style,
        )
    )

    document.build(story)

    return buffer.getvalue()