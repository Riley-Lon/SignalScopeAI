import pandas as pd


def build_download_report(
    df: pd.DataFrame,
    suspicious_df: pd.DataFrame,
    summary_text: str,
    top_finding: str,
    threat_score: int,
    threat_level: str,
    generated_report: str,
    audience: str,
    report_style: str,
    include_mitre: bool,
) -> str:

    timestamp = pd.Timestamp.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    lines = [
        "SIGNALSCOPE AI INVESTIGATION REPORT",
        "=" * 50,
        "",
        f"Generated: {timestamp}",
        f"Report Audience: {audience}",
        f"Report Style: {report_style}",
        "",
        "INVESTIGATION OVERVIEW",
        "-" * 30,
        f"Threat Score: {threat_score}/100",
        f"Threat Level: {threat_level}",
        f"Suspicious Events: {len(suspicious_df)}",
        "",
        "INCIDENT SUMMARY",
        "-" * 30,
        summary_text,
        "",
        "TOP FINDING",
        "-" * 30,
        top_finding,
        "",
        "SUSPICIOUS EVENTS",
        "-" * 30,
        suspicious_df.to_string(index=False),
        "",
    ]

    if include_mitre:

        lines.extend(
            [
                "MITRE ATT&CK",
                "-" * 30,
            ]
        )

        if (
            not suspicious_df.empty
            and "mitre_technique"
            in suspicious_df.columns
        ):

            mitre_values = (
                suspicious_df["mitre_technique"]
                .dropna()
                .astype(str)
                .drop_duplicates()
            )

            if len(mitre_values) > 0:

                for technique in mitre_values:
                    lines.append(
                        f"- {technique}"
                    )

            else:

                lines.append(
                    "No MITRE ATT&CK mappings available."
                )

        else:

            lines.append(
                "No MITRE ATT&CK mappings available."
            )

        lines.append("")

    if generated_report:

        lines.extend(
            [
                "AI INVESTIGATION REPORT",
                "-" * 30,
                generated_report,
                "",
            ]
        )

    return "\n".join(lines)