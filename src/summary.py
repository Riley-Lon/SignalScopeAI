import pandas as pd


def build_summary(suspicious_df: pd.DataFrame) -> str:
    if suspicious_df.empty:
        return "No suspicious activity was found based on the current rules."

    high_count = (suspicious_df["severity"] == "High").sum()
    medium_count = (suspicious_df["severity"] == "Medium").sum()
    low_count = (suspicious_df["severity"] == "Low").sum()

    return (
        f"SignalScope AI found {len(suspicious_df)} suspicious events. "
        f"There are {high_count} high-severity, {medium_count} medium-severity, "
        f"and {low_count} low-severity findings."
    )


def severity_breakdown(suspicious_df: pd.DataFrame) -> pd.DataFrame:
    if suspicious_df.empty:
        return pd.DataFrame({"Severity": [], "Count": []})

    counts = suspicious_df["severity"].value_counts().reindex(
        ["High", "Medium", "Low"], fill_value=0
    )
    return pd.DataFrame({"Severity": counts.index, "Count": counts.values})


def calculate_threat_score(suspicious_df: pd.DataFrame) -> int:
    if suspicious_df.empty:
        return 0

    score = 0

    for severity in suspicious_df["severity"]:
        if severity == "High":
            score += 15
        elif severity == "Medium":
            score += 8
        elif severity == "Low":
            score += 3

    return min(score, 100)