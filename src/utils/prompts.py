def build_ai_prompt(
    summary_text: str,
    suspicious_events_text: str,
    audience: str,
    report_style: str,
    include_mitre: bool,
    include_recommendations: bool,
    include_confidence: bool,
    threat_score: int,
    threat_level: str,
) -> str:

    sections = [
        "- Incident Summary",
        "- Threat Level",
    ]

    if include_mitre:
        sections.append(
            "- MITRE ATT&CK Techniques"
        )

    sections.append(
        "- Why This Matters"
    )

    if include_recommendations:
        sections.append(
            "- Recommended Actions"
        )

    if include_confidence:
        sections.append(
            "- Confidence Score"
        )

    sections_text = "\n".join(
        sections
    )

    return f"""
You are a cybersecurity analyst assisting with a security investigation.

Analyze ONLY the evidence provided below.

Do not invent facts that are not supported by the evidence.

The deterministic SignalScope AI detection engine has already calculated:

Threat Score: {threat_score}/100
Threat Level: {threat_level}

Do NOT recalculate or override the threat score or threat level.

Your job is to explain the findings and provide useful investigative context.

Write a {report_style.lower()} incident report for a {audience.lower()}.

Return the report with these sections:

{sections_text}

Use a professional, concise tone.

Distinguish confirmed evidence from possible interpretations.

If the evidence is insufficient to determine something, say so.

Investigation Summary:
{summary_text}

Suspicious Events:
{suspicious_events_text}
""".strip()