"""Deterministic preprocessing applied before Drain template mining."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection


# Values that vary per event inside otherwise identical messages. Short numbers,
# IPs, ports, usernames, paths, event IDs and status codes are kept on purpose:
# they can change detection semantics, and Drain parametrizes them where they
# vary anyway.
_UUID_RE2 = r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
_HEX_RE2 = r"\b(0x)?[0-9A-Fa-f]{16,}\b"
_NUM_RE2 = r"\b[0-9]{5,}\b"


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def install_preprocessor(connection: DuckDBPyConnection) -> None:
    """Install the macro that turns an archived log into the text Drain mines.

    ``preprocess_log(log, timestamp, hostname)`` first removes the syslog header
    Wazuh's pre-decoder already parsed, by value: the archive records it as
    ``predecoder.timestamp`` and, when one was found, ``predecoder.hostname``.
    The header is the one part of a syslog line that differs on nearly every
    event, and left in place it splits every message family by month and by
    host -- on a labelled corpus with realistic headers, a family fragmented
    into one template per host at any threshold that kept families apart.
    Removing exactly what Wazuh recorded needs no timestamp patterns and makes
    no guess about the layout; a record without a pre-decoded header is mined
    as it is.

    The UUID, long hexadecimal and long decimal masks then remove the
    identifiers that still vary within a family.
    """

    uuid = _sql_literal(_UUID_RE2)
    hexadecimal = _sql_literal(_HEX_RE2)
    number = _sql_literal(_NUM_RE2)

    # A prefix is removed only when it is followed by whitespace or the end of
    # the log, so a hostname that merely starts the next token is left alone.
    connection.execute(
        """
        CREATE TEMP MACRO drop_header_field(text, field) AS
        CASE
            WHEN nullif(field, '') IS NOT NULL
                AND starts_with(text, field)
                AND (length(text) = length(field) OR substr(text, length(field) + 1, 1) IN (' ', '\t'))
                THEN ltrim(substr(text, length(field) + 1), ' \t')
            ELSE text
        END
        """
    )
    connection.execute(
        f"""
        CREATE TEMP MACRO preprocess_log(log, header_time, header_host) AS
        trim(
            regexp_replace(
                regexp_replace(
                    regexp_replace(
                        drop_header_field(drop_header_field(coalesce(log, ''), header_time), header_host),
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
