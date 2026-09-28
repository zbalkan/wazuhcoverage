import duckdb
import pytest

from wazuhcoverage.preprocessing import install_preprocessor


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-09-26T10:58:42Z",
        "2026-09-26T10:58:42.123456Z",
        "2026-09-26T13:58:42+03:00",
        "2026-09-26T13:58:42.123+03:00",
        "Sep 26 13:58:42",
        "Sep  6 13:58:42",
        "2026-09-26T13:58:42",
        "2026-09-26 13:58:42.123",
        "2026-09-26 13:58:42+03:00",
        "2026-09-26 13:58:42Z",
        "2026-09-26 13:58:42.123-05:00",
        "Sep 26  13:58:42",
        "Sep\t6 13:58:42",
        "Sep   6\t13:58:42",
        "26/Sep/2026:13:58:42 +0300",
        "2026-09-26T10:58:42.1234567Z",
        "Sat Sep 26 13:58:42 2026",
        "26/09/2026 13:58:42",
        "09/26/2026 13:58:42",
        "20260926T105842Z",
    ],
)
def test_timestamp_prefixes_are_replaced_before_mining(timestamp: str) -> None:
    connection = duckdb.connect()
    try:
        install_preprocessor(connection)
        row = connection.execute(
            "SELECT preprocess_log(?)",
            [f"{timestamp} daemon: action"],
        ).fetchone()
        assert row is not None
        value = row[0]
    finally:
        connection.close()

    assert value == "<TIMESTAMP> daemon: action"


@pytest.mark.parametrize(
    ("log", "expected_tokens"),
    [
        # A timezone remnant would add a token and shift every later position.
        ("2026-09-26 13:58:42+03:00 sshd: accepted", ["<TIMESTAMP>", "sshd:", "accepted"]),
        # A surviving month name would become a Drain prefix-tree routing key.
        ("Sep 26  13:58:42 sshd: accepted", ["<TIMESTAMP>", "sshd:", "accepted"]),
    ],
)
def test_timestamp_prefix_collapses_to_a_single_drain_token(log: str, expected_tokens: list[str]) -> None:
    connection = duckdb.connect()
    try:
        install_preprocessor(connection)
        row = connection.execute("SELECT preprocess_log(?)", [log]).fetchone()
        assert row is not None
        value = row[0]
    finally:
        connection.close()

    # drain3 tokenizes on whitespace after stripping.
    assert value.split() == expected_tokens


def test_embedded_timestamp_is_not_replaced() -> None:
    connection = duckdb.connect()
    try:
        install_preprocessor(connection)
        row = connection.execute(
            "SELECT preprocess_log(?)",
            ["certificate expires 2027-01-01 00:00:00"],
        ).fetchone()
        assert row is not None
        value = row[0]
    finally:
        connection.close()

    assert value == "certificate expires 2027-01-01 00:00:00"


def test_existing_conservative_value_masks_are_preserved() -> None:
    connection = duckdb.connect()
    try:
        install_preprocessor(connection)
        row = connection.execute(
            "SELECT preprocess_log(?)",
            ["id=12345 uuid=123e4567-e89b-12d3-a456-426614174000 hash=0123456789abcdef"],
        ).fetchone()
        assert row is not None
        value = row[0]
    finally:
        connection.close()

    assert value == "id=<NUM> uuid=<UUID> hash=<HEX>"
