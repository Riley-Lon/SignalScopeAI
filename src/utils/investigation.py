import pandas as pd


def build_summary(suspicious_df: pd.DataFrame) -> str:
    if suspicious_df.empty:
        return (
            "No suspicious activity was found "
            "based on the current rules."
        )

    high_count = (
        suspicious_df["severity"] == "High"
    ).sum()

    medium_count = (
        suspicious_df["severity"] == "Medium"
    ).sum()

    low_count = (
        suspicious_df["severity"] == "Low"
    ).sum()

    return (
        f"SignalScope AI found {len(suspicious_df)} "
        f"suspicious events. There are "
        f"{high_count} high-severity, "
        f"{medium_count} medium-severity, "
        f"and {low_count} low-severity findings."
    )


def severity_breakdown(
    suspicious_df: pd.DataFrame,
) -> pd.DataFrame:

    if suspicious_df.empty:
        return pd.DataFrame(
            {
                "Severity": [],
                "Count": [],
            }
        )

    counts = suspicious_df[
        "severity"
    ].value_counts().reindex(
        [
            "High",
            "Medium",
            "Low",
        ],
        fill_value=0,
    )

    return pd.DataFrame(
        {
            "Severity": counts.index,
            "Count": counts.values,
        }
    )


def get_top_finding(
    suspicious_df: pd.DataFrame,
) -> str:

    if suspicious_df.empty:
        return "No suspicious activity was detected."

    high_df = suspicious_df[
        suspicious_df["severity"] == "High"
    ]

    if not high_df.empty:
        top_row = high_df.iloc[0]
    else:
        top_row = suspicious_df.iloc[0]

    reason = str(
        top_row.get(
            "suspicion_reason",
            "Suspicious activity detected",
        )
    )

    username = str(
        top_row.get(
            "username",
            "unknown user",
        )
    )

    source_ip = str(
        top_row.get(
            "source_ip",
            "unknown source IP",
        )
    )

    return (
        f"{reason} for "
        f"{username} from "
        f"{source_ip}."
    )


def build_timeline(
    suspicious_df: pd.DataFrame,
) -> pd.DataFrame:

    if suspicious_df.empty:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "username",
                "action",
                "severity",
                "suspicion_reason",
            ]
        )

    timeline_df = suspicious_df.copy()

    if "timestamp" in timeline_df.columns:
        timeline_df["timestamp"] = pd.to_datetime(
            timeline_df["timestamp"],
            errors="coerce",
        )

        timeline_df = timeline_df.sort_values(
            "timestamp"
        )

    display_cols = [
        col
        for col in [
            "timestamp",
            "username",
            "action",
            "severity",
            "suspicion_reason",
        ]
        if col in timeline_df.columns
    ]

    return timeline_df[display_cols]


def build_detection_breakdown(
    suspicious_df: pd.DataFrame,
) -> pd.DataFrame:

    if (
        suspicious_df.empty
        or "suspicion_reason"
        not in suspicious_df.columns
    ):
        return pd.DataFrame(
            {
                "Detection Type": [],
                "Count": [],
            }
        )

    counter = {
        "Failed login attempt": 0,
        "Successful login after prior failures": 0,
        "PowerShell execution detected": 0,
        "Possible encoded command": 0,
        "Outbound network connection": 0,
    }

    for reason_text in suspicious_df[
        "suspicion_reason"
    ].astype(str):

        for key in counter:
            if key.lower() in reason_text.lower():
                counter[key] += 1

    breakdown = pd.DataFrame(
        {
            "Detection Type": list(
                counter.keys()
            ),
            "Count": list(
                counter.values()
            ),
        }
    )

    return breakdown[
        breakdown["Count"] > 0
    ]


def build_highlights(
    df: pd.DataFrame,
    suspicious_df: pd.DataFrame,
) -> pd.DataFrame:

    if df.empty:
        return pd.DataFrame(
            {
                "Metric": [],
                "Value": [],
            }
        )

    unique_users = (
        df["username"].nunique()
        if "username" in df.columns
        else 0
    )

    unique_sources = (
        df["source_ip"].nunique()
        if "source_ip" in df.columns
        else 0
    )

    if (
        "action" in df.columns
        and not df["action"].mode().empty
    ):
        most_common_action = (
            df["action"].mode().iloc[0]
        )
    else:
        most_common_action = "Unknown"

    if (
        not suspicious_df.empty
        and "severity" in suspicious_df.columns
    ):
        high_count = int(
            (
                suspicious_df["severity"]
                == "High"
            ).sum()
        )
    else:
        high_count = 0

    return pd.DataFrame(
        {
            "Metric": [
                "Unique Users",
                "Unique Source IPs",
                "Most Common Action",
                "High-Severity Findings",
            ],
            "Value": [
                unique_users,
                unique_sources,
                most_common_action,
                high_count,
            ],
        }
    )


def build_investigation_context(
    suspicious_df: pd.DataFrame,
    summary_text: str,
    threat_score: int,
    threat_level: str,
) -> str:

    return f"""
SignalScope AI Investigation Context

Threat Score: {threat_score}/100
Threat Level: {threat_level}

Investigation Summary:
{summary_text}

Suspicious Events:
{suspicious_df.to_string(index=False)}
""".strip()