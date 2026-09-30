def calculate_threat_score(suspicious_df) -> int:
    """
    Calculate an overall investigation-risk score from 0-100.

    The score is divided into three components:
    1. Base evidence
    2. Behavioral correlations
    3. Investigation breadth

    The goal is to reflect the combination of evidence
    rather than simply counting findings.
    """

    if suspicious_df.empty:
        return 0

    reasons = (
        suspicious_df["suspicion_reason"]
        .astype(str)
        .str.lower()
        .tolist()
    )

    reasons_text = " ".join(reasons)

    # ========================================================
    # 1. BASE EVIDENCE: 0-30
    # ========================================================

    base_score = 0

    failed_login_count = sum(
        "failed login attempt" in reason
        for reason in reasons
    )

    # Repeated failed logins add modest risk.
    base_score += min(
        failed_login_count * 2,
        6,
    )

    encoded_command_count = sum(
        "encoded command" in reason
        for reason in reasons
    )

    if encoded_command_count > 0:
        base_score += 8

    if encoded_command_count >= 2:
        base_score += 3

    if encoded_command_count >= 3:
        base_score += 2

    standalone_outbound_count = sum(
        (
            "outbound network connection" in reason
            and "powershell network activity" not in reason
        )
        for reason in reasons
    )

    if standalone_outbound_count > 0:
        base_score += 5

    # Cap the base evidence contribution.
    base_score = min(
        base_score,
        30,
    )

    # ========================================================
    # 2. BEHAVIORAL CORRELATIONS: 0-45
    # ========================================================

    correlation_score = 0

    if "credential attack" in reasons_text:
        correlation_score += 18

    powershell_network_count = sum(
        "powershell network activity" in reason
        for reason in reasons
    )

    if powershell_network_count > 0:
        correlation_score += 18

    if powershell_network_count >= 2:
        correlation_score += 5

    privilege_escalation_count = sum(
        "privilege escalation" in reason
        for reason in reasons
    )

    if privilege_escalation_count > 0:
        correlation_score += 18

    if privilege_escalation_count >= 2:
        correlation_score += 4

    scheduled_task_persistence_count = sum(
        "scheduled task persistence" in reason
        for reason in reasons
    )

    if scheduled_task_persistence_count > 0:
        correlation_score += 18

    if scheduled_task_persistence_count >= 2:
        correlation_score += 4

    # Cap all behavioral correlations at 45.
    correlation_score = min(
        correlation_score,
        45,
    )

    # ========================================================
    # 3. INVESTIGATION BREADTH: 0-25
    # ========================================================

    breadth_score = 0

    behavior_categories = []

    if "credential attack" in reasons_text:
        behavior_categories.append(
            "authentication"
        )

    if "encoded command" in reasons_text:
        behavior_categories.append(
            "execution"
        )

    if (
        "outbound network connection"
        in reasons_text
        or "powershell network activity"
        in reasons_text
    ):
        behavior_categories.append(
            "network"
        )

    if "privilege escalation" in reasons_text:
        behavior_categories.append(
            "privilege"
        )

    if (
        "scheduled task persistence"
        in reasons_text
    ):
        behavior_categories.append(
            "persistence"
        )

    distinct_categories = len(
        set(behavior_categories)
    )

    if distinct_categories >= 2:
        breadth_score += 8

    if distinct_categories >= 3:
        breadth_score += 7

    if distinct_categories >= 4:
        breadth_score += 5

    if distinct_categories >= 5:
        breadth_score += 5

    breadth_score = min(
        breadth_score,
        25,
    )

    # ========================================================
    # FINAL SCORE
    # ========================================================

    total_score = (
        base_score
        + correlation_score
        + breadth_score
    )

    return min(
        total_score,
        100,
    )


def get_threat_level(threat_score: int) -> str:
    """
    Convert the overall investigation score into
    a threat level.
    """

    if threat_score >= 70:
        return "High"

    if threat_score >= 30:
        return "Medium"

    return "Low"


def get_score_breakdown(suspicious_df) -> list:
    """
    Return an explainable breakdown of the score.

    Each returned item contains:
    (description, points)
    """

    if suspicious_df.empty:
        return []

    reasons = (
        suspicious_df["suspicion_reason"]
        .astype(str)
        .str.lower()
        .tolist()
    )

    reasons_text = " ".join(reasons)

    breakdown = []

    # ========================================================
    # BASE EVIDENCE
    # ========================================================

    failed_login_count = sum(
        "failed login attempt" in reason
        for reason in reasons
    )

    failed_login_points = min(
        failed_login_count * 2,
        6,
    )

    if failed_login_points > 0:
        breakdown.append(
            (
                "Failed login activity",
                failed_login_points,
            )
        )

    encoded_command_count = sum(
        "encoded command" in reason
        for reason in reasons
    )

    if encoded_command_count > 0:
        breakdown.append(
            (
                "Encoded command detected",
                8,
            )
        )

    if encoded_command_count >= 2:
        breakdown.append(
            (
                "Repeated encoded activity",
                3,
            )
        )

    if encoded_command_count >= 3:
        breakdown.append(
            (
                "Additional repeated encoded activity",
                2,
            )
        )

    standalone_outbound_count = sum(
        (
            "outbound network connection" in reason
            and "powershell network activity" not in reason
        )
        for reason in reasons
    )

    if standalone_outbound_count > 0:
        breakdown.append(
            (
                "Outbound network activity",
                5,
            )
        )

    # ========================================================
    # BEHAVIORAL CORRELATIONS
    # ========================================================

    if "credential attack" in reasons_text:
        breakdown.append(
            (
                "Credential attack correlation",
                18,
            )
        )

    powershell_network_count = sum(
        "powershell network activity" in reason
        for reason in reasons
    )

    if powershell_network_count > 0:
        breakdown.append(
            (
                "PowerShell/network correlation",
                18,
            )
        )

    if powershell_network_count >= 2:
        breakdown.append(
            (
                "Repeated PowerShell/network correlation",
                5,
            )
        )

    privilege_escalation_count = sum(
        "privilege escalation" in reason
        for reason in reasons
    )

    if privilege_escalation_count > 0:
        breakdown.append(
            (
                "Privilege escalation",
                18,
            )
        )

    if privilege_escalation_count >= 2:
        breakdown.append(
            (
                "Repeated privilege escalation activity",
                4,
            )
        )

    scheduled_task_persistence_count = sum(
        "scheduled task persistence" in reason
        for reason in reasons
    )

    if scheduled_task_persistence_count > 0:
        breakdown.append(
            (
                "Scheduled task persistence",
                18,
            )
        )

    if scheduled_task_persistence_count >= 2:
        breakdown.append(
            (
                "Repeated scheduled task persistence",
                4,
            )
        )

    # ========================================================
    # INVESTIGATION BREADTH
    # ========================================================

    behavior_categories = []

    if "credential attack" in reasons_text:
        behavior_categories.append(
            "authentication"
        )

    if "encoded command" in reasons_text:
        behavior_categories.append(
            "execution"
        )

    if (
        "outbound network connection"
        in reasons_text
        or "powershell network activity"
        in reasons_text
    ):
        behavior_categories.append(
            "network"
        )

    if "privilege escalation" in reasons_text:
        behavior_categories.append(
            "privilege"
        )

    if (
        "scheduled task persistence"
        in reasons_text
    ):
        behavior_categories.append(
            "persistence"
        )

    distinct_categories = len(
        set(behavior_categories)
    )

    if distinct_categories >= 2:
        breakdown.append(
            (
                "Multiple suspicious behavior categories",
                8,
            )
        )

    if distinct_categories >= 3:
        breakdown.append(
            (
                "Additional behavior category",
                7,
            )
        )

    if distinct_categories >= 4:
        breakdown.append(
            (
                "Broad multi-stage behavior",
                5,
            )
        )

    if distinct_categories >= 5:
        breakdown.append(
            (
                "Full-spectrum behavior coverage",
                5,
            )
        )

    return breakdown