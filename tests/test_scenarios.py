from src.parser import load_csv
from src.detector import find_suspicious_events
from src.utils.scoring import (
    calculate_threat_score,
    get_threat_level,
)


def analyze_scenario(file_path: str):
    """Load a CSV and return its findings, score, and level."""

    df = load_csv(file_path)
    findings = find_suspicious_events(df)
    score = calculate_threat_score(findings)
    level = get_threat_level(score)

    return findings, score, level


def test_normal_activity():
    findings, score, level = analyze_scenario(
        "data/normal_activity.csv"
    )

    assert len(findings) == 0
    assert score == 0
    assert level == "Low"


def test_normal_powershell_activity():
    findings, score, level = analyze_scenario(
        "data/powershell_activity.csv"
    )

    assert len(findings) == 0
    assert score == 0
    assert level == "Low"


def test_powershell_attack():
    findings, score, level = analyze_scenario(
        "data/powershell_attack.csv"
    )

    assert len(findings) == 5
    assert score == 44
    assert level == "Medium"


def test_sample_logs():
    findings, score, level = analyze_scenario(
        "data/sample_logs.csv"
    )

    assert len(findings) == 6
    assert score == 52
    assert level == "Medium"


def test_multi_stage_attack():
    findings, score, level = analyze_scenario(
        "data/multi_stage_attack.csv"
    )

    assert len(findings) == 8
    assert score == 73
    assert level == "High"

    reasons = (
        findings["suspicion_reason"]
        .astype(str)
        .str.lower()
        .tolist()
    )

    assert any(
        "credential attack" in reason
        for reason in reasons
    )

    assert any(
        "powershell network activity" in reason
        for reason in reasons
    )


def test_normal_admin_activity():
    findings, score, level = analyze_scenario(
        "data/normal_admin_activity.csv"
    )

    assert len(findings) == 0
    assert score == 0
    assert level == "Low"


def test_privilege_escalation():
    findings, score, level = analyze_scenario(
        "data/privilege_escalation.csv"
    )

    assert len(findings) == 2
    assert score == 22
    assert level == "Low"

    reasons = (
        findings["suspicion_reason"]
        .astype(str)
        .str.lower()
        .tolist()
    )

    privilege_findings = [
        reason
        for reason in reasons
        if "privilege escalation" in reason
    ]

    assert len(privilege_findings) == 2

    privilege_rows = findings[
        findings["suspicion_reason"]
        .astype(str)
        .str.lower()
        .str.contains(
            "privilege escalation",
            na=False,
        )
    ]

    assert all(
        severity == "High"
        for severity in privilege_rows["severity"]
    )


def test_normal_scheduled_task():
    findings, score, level = analyze_scenario(
        "data/normal_scheduled_task.csv"
    )

    assert len(findings) == 0
    assert score == 0
    assert level == "Low"


def test_scheduled_task_persistence():
    findings, score, level = analyze_scenario(
        "data/scheduled_task_persistence.csv"
    )

    assert len(findings) == 2
    assert score == 31
    assert level == "Medium"

    reasons = (
        findings["suspicion_reason"]
        .astype(str)
        .str.lower()
        .tolist()
    )

    persistence_findings = [
        reason
        for reason in reasons
        if "scheduled task persistence" in reason
    ]

    assert len(persistence_findings) == 1

    persistence_rows = findings[
        findings["suspicion_reason"]
        .astype(str)
        .str.lower()
        .str.contains(
            "scheduled task persistence",
            na=False,
        )
    ]

    assert all(
        severity == "High"
        for severity in persistence_rows["severity"]
    )