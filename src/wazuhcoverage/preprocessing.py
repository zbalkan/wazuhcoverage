"""Deterministic preprocessing applied before Drain template mining."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection


# These expressions deliberately stay inside the regex subset shared by
# DuckDB/RE2 and Wazuh PCRE2. They recognize syntax, not calendar validity.
#
# Order matters where one syntax is a prefix of another. Timezone-bearing ISO
# forms must be tried before the otherwise identical no-timezone form.
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
            r"([.,][0-9]+)?"
        ),
    ),
    (
        "rfc3164",
        (
            r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
            r" {1,2}[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}"
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

    connection.execute(
        f"""
        CREATE TEMP MACRO preprocess_log(log) AS
        trim(
            regexp_replace(
                regexp_replace(
                    regexp_replace(
                        regexp_replace(
                            coalesce(log, ''),
                            {timestamp},
                            '<TIMESTAMP>',
                            'c'
                        ),
                        {uuid},
                        '<UUID>',
                        'g'
                    ),
                    {hexadecimal},
                    '<HEX>',
                    'g'
                ),
                {number},
                '<NUM>',
                'g'
            )
        )
        """
    )
