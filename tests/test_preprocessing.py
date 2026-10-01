from typing import Optional

import duckdb
import pytest

from wazuhcoverage.preprocessing import install_preprocessor


def _preprocess(log: Optional[str], header_time: Optional[str] = None, header_host: Optional[str] = None) -> str:
    connection = duckdb.connect()
    try:
        install_preprocessor(connection)
        row = connection.execute("SELECT preprocess_log(?, ?, ?)", [log, header_time, header_host]).fetchone()
        assert row is not None
        return row[0]
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("log", "header_time", "header_host"),
    [
        # As Wazuh 4.14.8 archived them: predecoder.timestamp, predecoder.hostname.
        ("Sep 29 10:00:00 web-01 sshd[123]: Failed password", "Sep 29 10:00:00", "web-01"),
        ("Sep  3 10:00:01 db-02 sshd[999]: Failed password", "Sep  3 10:00:01", "db-02"),
        # Wazuh's own misparse of a header without a hostname, kept consistent.
        ("Sep 29 10:00:03 kernel: sshd[1]: Failed password", "Sep 29 10:00:03", "kernel:"),
    ],
)
def test_the_predecoded_header_is_removed_by_value(log: str, header_time: str, header_host: str) -> None:
    assert _preprocess(log, header_time, header_host).startswith("sshd[")


def test_only_the_recorded_timestamp_is_removed_when_no_hostname_was_recorded() -> None:
    # Wazuh records no hostname for this ISO-prefixed line, so the host token stays.
    log = "2026-09-29T10:00:02.123456+03:00 app-03 myapp[42]: order declined"

    assert _preprocess(log, "2026-09-29T10:00:02.123456+03:00") == "app-03 myapp[42]: order declined"


def test_a_log_without_a_predecoded_header_is_mined_as_it_is() -> None:
    log = "Sep 26 13:58:42 host daemon: action"

    assert _preprocess(log) == log
    assert _preprocess(log, "", "") == log


def test_a_header_field_is_removed_only_as_a_whole_leading_token() -> None:
    # The recorded value must start the log and end at whitespace.
    assert _preprocess("x Sep 26 13:58:42 host daemon", "Sep 26 13:58:42", "host") == "x Sep 26 13:58:42 host daemon"
    assert _preprocess("Sep 26 13:58:42 hostname daemon", "Sep 26 13:58:42", "host") == "hostname daemon"
    assert _preprocess("Sep 26 13:58:42", "Sep 26 13:58:42") == ""


def test_identifier_masks_still_apply() -> None:
    log = "id=12345 uuid=123e4567-e89b-12d3-a456-426614174000 hash=0123456789abcdef"

    assert _preprocess(log) == "id=<NUM> uuid=<UUID> hash=<HEX>"
    assert _preprocess(None) == ""
