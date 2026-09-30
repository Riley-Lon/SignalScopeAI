import pytest
from src.parser import load_csv


def test_empty_csv():
    with pytest.raises(
        ValueError,
        match="uploaded CSV is empty",
    ):
        load_csv("data/empty_log.csv")


def test_missing_required_columns():
    with pytest.raises(
        ValueError,
        match="missing required security log columns",
    ):
        load_csv("data/malformed_log.csv")


def test_invalid_timestamps():
    with pytest.raises(
        ValueError,
        match="contains invalid timestamps",
    ):
        load_csv("data/malformed_timestamps.csv")