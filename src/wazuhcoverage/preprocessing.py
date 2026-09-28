"""Deterministic preprocessing applied before Drain template mining."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection


# These expressions deliberately stay inside the regex subset shared by
# DuckDB/RE2 and Wazuh PCRE2. They recognize syntax, not calendar validity.
#
# Order matters where one syntax is a prefix of another. Timezone-bearing ISO
# forms must be tried before the otherwise identical no-timezone form. The
# space-separated form keeps its timezone optional instead: the greedy group
# consumes it, so no "+03:00" or "Z" remnant is left behind as its own token.
# RFC3164 separators accept runs of spaces or tabs, as syslog senders pad the
# day inconsistently; a raw month left behind would become a Drain routing key.
TIMESTAMP_PATTERNS = (
    (
        "iso8601_tz",
        (
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"([.,][0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})"
        ),
    ),
    (
        "iso8601_no_tz",
        (
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"([.,][0-9]+)?"
        ),
    ),
    (
        "ymd_space",
        (
            r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"([.,][0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})?"
        ),
    ),
    (
        "rfc3164",
        (
            r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
            r"[ \t]+[0-9]{1,2}[ \t]+[0-9]{2}:[0-9]{2}:[0-9]{2}"
        ),
    ),
    (
        "clf",
        (
            r"[0-9]{2}/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
            r"/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4}"
        ),
    ),
    (
        "ctime",
        (
            r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
            r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
            r" {1,2}[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}"
        ),
    ),
    (
        "locale_slash",
        (
            r"[0-9]{2}/[0-9]{2}/[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"([.][0-9]+)?"
        ),
    ),
    (
        "compact_iso8601",
        r"[0-9]{8}T[0-9]{6}([.][0-9]+)?Z",
    ),
)

_TIMESTAMP_ALTERNATION = "|".join(pattern for _, pattern in TIMESTAMP_PATTERNS)
TIMESTAMP_PREFIX_RE2 = f"^({_TIMESTAMP_ALTERNATION})"
WAZUH_TIMESTAMP_PCRE2 = f"(?:{_TIMESTAMP_ALTERNATION})"

_UUID_RE2 = r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
_HEX_RE2 = r"\b(0x)?[0-9A-Fa-f]{16,}\b"
_NUM_RE2 = r"\b[0-9]{5,}\b"
# Every UUID, HEX or NUM match contains one of these runs: a UUID opens with
# eight hexadecimal characters, a HEX token has at least sixteen and a NUM
# token at least five digits. A log without either run cannot change in those
# three passes, so the guard skips them without altering any output. It pays
# for itself on logs that carry no such values; on logs that do, it costs one
# extra scan up to the first qualifying run.
_VALUE_MASK_GUARD_RE2 = r"[0-9]{5}|[0-9A-Fa-f]{8}"


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def install_preprocessor(connection: DuckDBPyConnection) -> None:
    """Install the vectorized preprocessing macro used immediately before Drain.

    Only timestamp prefixes are replaced. Embedded timestamps are left alone
    because they may be semantically meaningful fields in the log message.
    UUID, long hexadecimal tokens and long decimal IDs retain the conservative
    masking behavior that existed before this stage became explicit.
    """

    timestamp = _sql_literal(TIMESTAMP_PREFIX_RE2)
    uuid = _sql_literal(_UUID_RE2)
    hexadecimal = _sql_literal(_HEX_RE2)
    number = _sql_literal(_NUM_RE2)
    guard = _sql_literal(_VALUE_MASK_GUARD_RE2)

    # The timestamp step cannot create a guard run, since "<TIMESTAMP>" holds
    # no eight consecutive hexadecimal characters, so the guard reads the raw
    # log and the timestamp step is written once per branch.
    stamped = f"regexp_replace(coalesce(log, ''), {timestamp}, '<TIMESTAMP>', 'c')"
    connection.execute(
        f"""
        CREATE TEMP MACRO preprocess_log(log) AS
        trim(
            CASE
                WHEN regexp_matches(coalesce(log, ''), {guard}) THEN
                    regexp_replace(
                        regexp_replace(
                            regexp_replace({stamped}, {uuid}, '<UUID>', 'g'),
                            {hexadecimal},
                            '<HEX>',
                            'g'
                        ),
                        {number},
                        '<NUM>',
                        'g'
                    )
                ELSE {stamped}
            END
        )
        """
    )
