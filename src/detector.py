import pandas as pd

from src.mitre_map import map_mitre


def classify_severity(reason_text: str) -> str:
    reason_text = reason_text.lower()

    if (
        "encoded command" in reason_text
        or "credential attack" in reason_text
        or "powershell network activity" in reason_text
        or "privilege escalation" in reason_text
        or "scheduled task persistence" in reason_text
    ):
        return "High"

    if "outbound network connection" in reason_text:
        return "Medium"

    if "failed login" in reason_text:
        return "Low"

    return "Low"


def detect_login_attack_sequences(
    df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Detect 3 or more failed logins followed by a
    successful login for the same user and source IP
    within five minutes.
    """

    if df.empty:
        return pd.DataFrame()

    required_columns = [
        "timestamp",
        "username",
        "source_ip",
        "action",
    ]

    for column in required_columns:
        if column not in df.columns:
            return pd.DataFrame()

    working_df = df.copy()

    working_df["timestamp"] = pd.to_datetime(
        working_df["timestamp"],
        errors="coerce",
    )

    working_df = working_df.sort_values(
        "timestamp"
    )

    suspicious_rows = []

    for _, group in working_df.groupby(
        ["username", "source_ip"]
    ):

        group = group.sort_values(
            "timestamp"
        )

        for _, row in group.iterrows():

            action = str(
                row.get(
                    "action",
                    "",
                )
            ).lower()

            message = str(
                row.get(
                    "message",
                    "",
                )
            ).lower()

            is_success = (
                "successful_login" in action
                or "login successful" in message
            )

            if not is_success:
                continue

            success_time = row["timestamp"]

            if pd.isna(success_time):
                continue

            window_start = (
                success_time
                - pd.Timedelta(minutes=5)
            )

            previous_rows = group[
                (
                    group["timestamp"]
                    >= window_start
                )
                & (
                    group["timestamp"]
                    < success_time
                )
            ]

            failed_mask = (
                previous_rows["action"]
                .astype(str)
                .str.lower()
                .str.contains(
                    "failed_login",
                    na=False,
                )
            )

            failed_rows = previous_rows[
                failed_mask
            ]

            if len(failed_rows) < 3:
                continue

            correlated_row = row.copy()

            correlated_row[
                "suspicion_reason"
            ] = (
                "Possible credential attack: "
                f"{len(failed_rows)} failed login attempts "
                "followed by a successful login "
                "within 5 minutes"
            )

            correlated_row[
                "severity"
            ] = "High"

            correlated_row[
                "mitre_technique"
            ] = map_mitre(
                correlated_row[
                    "suspicion_reason"
                ]
            )

            suspicious_rows.append(
                correlated_row
            )

    if suspicious_rows:
        return pd.DataFrame(
            suspicious_rows
        )

    return pd.DataFrame()


def detect_powershell_network_sequences(
    df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Detect an outbound network event occurring within
    five minutes after encoded PowerShell activity
    from the same source IP.
    """

    if df.empty:
        return pd.DataFrame()

    required_columns = [
        "timestamp",
        "source_ip",
        "action",
        "message",
    ]

    for column in required_columns:
        if column not in df.columns:
            return pd.DataFrame()

    working_df = df.copy()

    working_df["timestamp"] = pd.to_datetime(
        working_df["timestamp"],
        errors="coerce",
    )

    working_df = working_df.sort_values(
        "timestamp"
    )

    suspicious_rows = []

    for _, network_row in working_df.iterrows():

        network_action = str(
            network_row.get(
                "action",
                "",
            )
        ).lower()

        network_message = str(
            network_row.get(
                "message",
                "",
            )
        ).lower()

        is_outbound = (
            "network_connection"
            in network_action
            or "outbound"
            in network_message
        )

        if not is_outbound:
            continue

        network_time = network_row[
            "timestamp"
        ]

        source_ip = str(
            network_row.get(
                "source_ip",
                "",
            )
        )

        if pd.isna(network_time):
            continue

        window_start = (
            network_time
            - pd.Timedelta(minutes=5)
        )

        previous_rows = working_df[
            (
                working_df["timestamp"]
                >= window_start
            )
            & (
                working_df["timestamp"]
                < network_time
            )
            & (
                working_df["source_ip"]
                .astype(str)
                == source_ip
            )
        ]

        encoded_powershell_found = False

        for _, previous_row in previous_rows.iterrows():

            previous_action = str(
                previous_row.get(
                    "action",
                    "",
                )
            ).lower()

            previous_message = str(
                previous_row.get(
                    "message",
                    "",
                )
            ).lower()

            has_powershell = (
                "powershell"
                in previous_action
                or "powershell"
                in previous_message
            )

            has_encoded = (
                "encoded"
                in previous_action
                or "encoded"
                in previous_message
            )

            if (
                has_powershell
                and has_encoded
            ):
                encoded_powershell_found = True
                break

        if not encoded_powershell_found:
            continue

        correlated_row = (
            network_row.copy()
        )

        correlated_row[
            "suspicion_reason"
        ] = (
            "Possible PowerShell network activity: "
            "encoded PowerShell execution followed "
            "by an outbound network connection "
            "within 5 minutes"
        )

        correlated_row[
            "severity"
        ] = "High"

        correlated_row[
            "mitre_technique"
        ] = map_mitre(
            correlated_row[
                "suspicion_reason"
            ]
        )

        suspicious_rows.append(
            correlated_row
        )

    if suspicious_rows:
        return pd.DataFrame(
            suspicious_rows
        )

    return pd.DataFrame()


def detect_privilege_escalation_sequences(
    df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Detect a privilege change followed by an
    administrative or restricted action by the
    same user within five minutes.
    """

    if df.empty:
        return pd.DataFrame()

    required_columns = [
        "timestamp",
        "username",
        "action",
        "message",
    ]

    for column in required_columns:
        if column not in df.columns:
            return pd.DataFrame()

    working_df = df.copy()

    working_df["timestamp"] = pd.to_datetime(
        working_df["timestamp"],
        errors="coerce",
    )

    working_df = working_df.sort_values(
        "timestamp"
    )

    suspicious_rows = []

    for _, privilege_row in working_df.iterrows():

        privilege_action = str(
            privilege_row.get(
                "action",
                "",
            )
        ).lower()

        privilege_message = str(
            privilege_row.get(
                "message",
                "",
            )
        ).lower()

        is_privilege_change = (
            "privilege_change"
            in privilege_action
            or "administrator group"
            in privilege_message
            or "elevated privileges"
            in privilege_message
            or "elevated"
            in privilege_message
        )

        if not is_privilege_change:
            continue

        privilege_time = privilege_row[
            "timestamp"
        ]

        username = str(
            privilege_row.get(
                "username",
                "",
            )
        )

        if pd.isna(privilege_time):
            continue

        later_rows = working_df[
            (
                working_df["timestamp"]
                > privilege_time
            )
            & (
                working_df["timestamp"]
                <= (
                    privilege_time
                    + pd.Timedelta(minutes=5)
                )
            )
            & (
                working_df["username"]
                .astype(str)
                == username
            )
        ]

        for _, later_row in later_rows.iterrows():

            later_action = str(
                later_row.get(
                    "action",
                    "",
                )
            ).lower()

            later_message = str(
                later_row.get(
                    "message",
                    "",
                )
            ).lower()

            is_admin_action = (
                "admin_action"
                in later_action
                or "administrative"
                in later_message
                or "restricted"
                in later_message
            )

            if not is_admin_action:
                continue

            correlated_row = (
                later_row.copy()
            )

            correlated_row[
                "suspicion_reason"
            ] = (
                "Possible privilege escalation: "
                "elevated privileges were followed by "
                "an administrative or restricted action "
                "within 5 minutes"
            )

            correlated_row[
                "severity"
            ] = "High"

            correlated_row[
                "mitre_technique"
            ] = map_mitre(
                correlated_row[
                    "suspicion_reason"
                ]
            )

            suspicious_rows.append(
                correlated_row
            )

    if suspicious_rows:
        return pd.DataFrame(
            suspicious_rows
        )

    return pd.DataFrame()


def detect_scheduled_task_persistence(
    df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Detect a scheduled task that is created,
    configured for automatic/logon/startup execution,
    and then executed within five minutes.
    """

    if df.empty:
        return pd.DataFrame()

    required_columns = [
        "timestamp",
        "username",
        "action",
        "message",
    ]

    for column in required_columns:
        if column not in df.columns:
            return pd.DataFrame()

    working_df = df.copy()

    working_df["timestamp"] = pd.to_datetime(
        working_df["timestamp"],
        errors="coerce",
    )

    working_df = working_df.sort_values(
        "timestamp"
    )

    suspicious_rows = []

    for _, create_row in working_df.iterrows():

        create_action = str(
            create_row.get(
                "action",
                "",
            )
        ).lower()

        create_message = str(
            create_row.get(
                "message",
                "",
            )
        ).lower()

        if (
            "scheduled_task_create"
            not in create_action
        ):
            continue

        create_time = create_row[
            "timestamp"
        ]

        username = str(
            create_row.get(
                "username",
                "",
            )
        )

        if pd.isna(create_time):
            continue

        later_rows = working_df[
            (
                working_df["timestamp"]
                > create_time
            )
            & (
                working_df["timestamp"]
                <= (
                    create_time
                    + pd.Timedelta(minutes=5)
                )
            )
            & (
                working_df["username"]
                .astype(str)
                == username
            )
        ]

        configuration_row = None

        for _, later_row in later_rows.iterrows():

            later_action = str(
                later_row.get(
                    "action",
                    "",
                )
            ).lower()

            later_message = str(
                later_row.get(
                    "message",
                    "",
                )
            ).lower()

            is_task_update = (
                "scheduled_task_update"
                in later_action
            )

            has_persistence_language = (
                "logon" in later_message
                or "startup" in later_message
                or "automatically" in later_message
                or "automatic" in later_message
            )

            if (
                is_task_update
                and has_persistence_language
            ):
                configuration_row = later_row
                break

        if configuration_row is None:
            continue

        configuration_time = (
            configuration_row["timestamp"]
        )

        execution_rows = working_df[
            (
                working_df["timestamp"]
                > configuration_time
            )
            & (
                working_df["timestamp"]
                <= (
                    configuration_time
                    + pd.Timedelta(minutes=5)
                )
            )
            & (
                working_df["username"]
                .astype(str)
                == username
            )
        ]

        for _, execution_row in execution_rows.iterrows():

            execution_action = str(
                execution_row.get(
                    "action",
                    "",
                )
            ).lower()

            execution_message = str(
                execution_row.get(
                    "message",
                    "",
                )
            ).lower()

            is_task_execution = (
                "scheduled_task_run"
                in execution_action
                or "task executed"
                in execution_message
            )

            if not is_task_execution:
                continue

            task_name = None

            if "named " in create_message:

                task_name = (
                    create_message
                    .split(
                        "named ",
                        1,
                    )[1]
                    .split(
                        " ",
                        1,
                    )[0]
                )

            correlated_row = (
                execution_row.copy()
            )

            if task_name:

                correlated_row[
                    "suspicion_reason"
                ] = (
                    "Possible scheduled task persistence: "
                    f"task '{task_name}' was configured "
                    "for automatic execution and then ran "
                    "within 5 minutes"
                )

            else:

                correlated_row[
                    "suspicion_reason"
                ] = (
                    "Possible scheduled task persistence: "
                    "a newly created task was configured "
                    "for automatic execution and then ran "
                    "within 5 minutes"
                )

            correlated_row[
                "severity"
            ] = "High"

            correlated_row[
                "mitre_technique"
            ] = map_mitre(
                correlated_row[
                    "suspicion_reason"
                ]
            )

            suspicious_rows.append(
                correlated_row
            )

            break

    if suspicious_rows:
        return pd.DataFrame(
            suspicious_rows
        )

    return pd.DataFrame()


def find_suspicious_events(
    df: pd.DataFrame,
) -> pd.DataFrame:

    if df.empty:
        return pd.DataFrame()

    suspicious_rows = []

    # --------------------------------------------------------
    # Behavioral detections
    # --------------------------------------------------------

    login_sequences = (
        detect_login_attack_sequences(
            df
        )
    )

    powershell_sequences = (
        detect_powershell_network_sequences(
            df
        )
    )

    privilege_sequences = (
        detect_privilege_escalation_sequences(
            df
        )
    )

    scheduled_task_sequences = (
        detect_scheduled_task_persistence(
            df
        )
    )

    # --------------------------------------------------------
    # Events represented by stronger correlations
    # --------------------------------------------------------

    correlated_network_events = set()

    if not powershell_sequences.empty:

        for _, row in powershell_sequences.iterrows():

            correlated_network_events.add(
                (
                    str(
                        pd.to_datetime(
                            row.get(
                                "timestamp",
                                "",
                            ),
                            errors="coerce",
                        )
                    ),
                    str(
                        row.get(
                            "source_ip",
                            "",
                        )
                    ),
                )
            )

    # --------------------------------------------------------
    # Event-level detections
    # --------------------------------------------------------

    for _, row in df.iterrows():

        reasons = []

        action = str(
            row.get(
                "action",
                "",
            )
        ).lower()

        message = str(
            row.get(
                "message",
                "",
            )
        ).lower()

        # ----------------------------------------------------
        # Failed login
        # ----------------------------------------------------

        if (
            "failed_login" in action
            or "login failed" in message
        ):

            reasons.append(
                "Failed login attempt"
            )

        # ----------------------------------------------------
        # Encoded PowerShell
        # ----------------------------------------------------

        has_powershell = (
            "powershell" in action
            or "powershell" in message
        )

        has_encoded = (
            "encoded" in action
            or "encoded" in message
        )

        if (
            has_powershell
            and has_encoded
        ):

            reasons.append(
                "PowerShell execution detected"
            )

            reasons.append(
                "Possible encoded command"
            )

        elif has_encoded:

            reasons.append(
                "Possible encoded command"
            )

        # ----------------------------------------------------
        # Network activity
        # ----------------------------------------------------

        is_outbound = (
            "network_connection" in action
            or "outbound" in message
        )

        if is_outbound:

            row_timestamp = pd.to_datetime(
                row.get(
                    "timestamp",
                    "",
                ),
                errors="coerce",
            )

            network_key = (
                str(row_timestamp),
                str(
                    row.get(
                        "source_ip",
                        "",
                    )
                ),
            )

            if (
                network_key
                not in correlated_network_events
            ):

                reasons.append(
                    "Outbound network connection"
                )

        # Normal PowerShell and scheduled-task
        # operations are not automatically suspicious.

        if reasons:

            suspicious_row = row.copy()

            suspicious_row[
                "suspicion_reason"
            ] = "; ".join(
                reasons
            )

            suspicious_row[
                "severity"
            ] = classify_severity(
                suspicious_row[
                    "suspicion_reason"
                ]
            )

            suspicious_row[
                "mitre_technique"
            ] = map_mitre(
                suspicious_row[
                    "suspicion_reason"
                ]
            )

            suspicious_rows.append(
                suspicious_row
            )

    event_results = pd.DataFrame(
        suspicious_rows
    )

    # --------------------------------------------------------
    # Add behavioral findings
    # --------------------------------------------------------

    result_frames = []

    if not event_results.empty:
        result_frames.append(
            event_results
        )

    if not login_sequences.empty:
        result_frames.append(
            login_sequences
        )

    if not powershell_sequences.empty:
        result_frames.append(
            powershell_sequences
        )

    if not privilege_sequences.empty:
        result_frames.append(
            privilege_sequences
        )

    if not scheduled_task_sequences.empty:
        result_frames.append(
            scheduled_task_sequences
        )

    if not result_frames:
        return pd.DataFrame()

    results = pd.concat(
        result_frames,
        ignore_index=True,
    )

    # --------------------------------------------------------
    # Remove duplicate findings
    # --------------------------------------------------------

    dedupe_columns = [
        column
        for column in [
            "timestamp",
            "username",
            "source_ip",
            "suspicion_reason",
        ]
        if column in results.columns
    ]

    if dedupe_columns:

        results = (
            results.drop_duplicates(
                subset=dedupe_columns
            )
        )

    # --------------------------------------------------------
    # Sort chronologically
    # --------------------------------------------------------

    if "timestamp" in results.columns:

        results["timestamp"] = (
            pd.to_datetime(
                results["timestamp"],
                errors="coerce",
            )
        )

        results = results.sort_values(
            "timestamp"
        )

    return results.reset_index(
        drop=True
    )