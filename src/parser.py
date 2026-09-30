import pandas as pd


REQUIRED_COLUMNS = {
    "timestamp",
    "username",
    "source_ip",
    "action",
    "message",
}


def load_csv(uploaded_file) -> pd.DataFrame:
    """
    Load a CSV security log and validate that it
    contains usable data and the fields required
    by SignalScope's detection engine.
    """

    try:
        df = pd.read_csv(uploaded_file)

    except pd.errors.EmptyDataError:
        raise ValueError(
            "The uploaded CSV is empty. "
            "Please upload a CSV containing security log data."
        )

    except pd.errors.ParserError:
        raise ValueError(
            "The uploaded CSV could not be parsed. "
            "Please check that the file is a valid CSV."
        )

    except Exception as e:
        raise ValueError(
            f"Could not read CSV: {e}"
        )

    if df.empty:
        raise ValueError(
            "The uploaded CSV contains no data rows. "
            "Please upload a CSV containing security log data."
        )

    if len(df.columns) == 0:
        raise ValueError(
            "The uploaded CSV does not contain any columns."
        )

    missing_columns = (
        REQUIRED_COLUMNS
        - set(df.columns)
    )

    if missing_columns:
        missing_text = ", ".join(
            sorted(missing_columns)
        )

        raise ValueError(
            "The uploaded CSV is missing required "
            f"security log columns: {missing_text}. "
            "Required columns are: "
            "timestamp, username, source_ip, "
            "action, and message."
        )

    # --------------------------------------------------------
    # Validate timestamps
    # --------------------------------------------------------

    parsed_timestamps = pd.to_datetime(
    df["timestamp"],
    format="%Y-%m-%d %H:%M:%S",
    errors="coerce",
)

    invalid_timestamp_mask = (
        parsed_timestamps.isna()
    )

    if invalid_timestamp_mask.any():

        invalid_rows = (
            invalid_timestamp_mask
            .to_numpy()
            .nonzero()[0]
        )

        first_invalid_row = (
            int(invalid_rows[0]) + 2
        )

        raise ValueError(
            "The uploaded CSV contains invalid "
            f"timestamps. The first invalid value "
            f"appears near CSV row {first_invalid_row}. "
            "Please ensure all values in the "
            "timestamp column are valid date/time values."
        )

    df["timestamp"] = parsed_timestamps

    return df