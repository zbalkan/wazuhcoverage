"""DuckDB-backed analysis of one Wazuh archive."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from wazuhcoverage.models import ArchiveAnalysis, Finding, LogTypeCount, STATUSES, StatusCount

DEFAULT_ALERT_THRESHOLD = 3


def _sql_literal(value: str) -> str:
    """Quote a string as a DuckDB SQL literal."""

    return "'" + value.replace("'", "''") + "'"


def _load_duckdb() -> Any:
    try:
        import duckdb
    except ImportError as exc:  # pragma: no cover - installation error path
        raise RuntimeError("DuckDB is required. Install wazuhcoverage with its dependencies.") from exc
    return duckdb


def analyze_archive(path: str | Path, *, alert_threshold: int = DEFAULT_ALERT_THRESHOLD) -> ArchiveAnalysis:
    """Analyze one Wazuh NDJSON archive.

    The compressed/uncompressed source is scanned once into a temporary table.
    All subsequent classification, grouping and sampling runs against that table.
    """

    archive = Path(path).expanduser().resolve()
    if not archive.is_file():
        raise FileNotFoundError(archive)

    if alert_threshold < 0:
        raise ValueError("alert_threshold must be non-negative")

    if archive.stat().st_size == 0:
        return _empty_analysis(archive)

    duckdb = _load_duckdb()
    connection = duckdb.connect(":memory:")
    try:
        _create_events(connection, archive)
        _create_views(connection, alert_threshold)

        total_events = int(connection.execute("SELECT count(*) FROM classified_events").fetchone()[0])

        raw_statuses = dict(
            connection.execute(
                "SELECT observed_status, count(*) FROM classified_events GROUP BY observed_status"
            ).fetchall()
        )
        status_counts = tuple(StatusCount(status, int(raw_statuses.get(status, 0))) for status in STATUSES)

        log_type_counts = tuple(
            LogTypeCount(str(status), str(log_type), int(count))
            for status, log_type, count in connection.execute(
                """
                SELECT observed_status, log_type, count(*) AS event_count
                FROM classified_events
                GROUP BY observed_status, log_type
                ORDER BY observed_status, event_count DESC, log_type
                """
            ).fetchall()
        )

        findings = tuple(
            Finding(
                finding_key=str(row[0]),
                observed_status=str(row[1]),
                log_type=_string_or_none(row[2]),
                message_pattern=str(row[3]),
                event_count=int(row[4]),
                affected_agents=int(row[5]),
                first_seen=_string_or_none(row[6]),
                last_seen=_string_or_none(row[7]),
                observed_decoder=_string_or_none(row[8]),
                observed_rule_id=_string_or_none(row[9]),
                observed_rule_level=int(row[10]) if row[10] is not None else None,
                sample_log=str(row[11]),
            )
            for row in connection.execute(
                """
                SELECT
                    finding_key,
                    observed_status,
                    log_type,
                    message_pattern,
                    event_count,
                    affected_agents,
                    first_seen,
                    last_seen,
                    observed_decoder,
                    observed_rule_id,
                    observed_rule_level,
                    sample_log
                FROM findings
                ORDER BY event_count DESC, observed_status, coalesce(log_type, ''), finding_key
                """
            ).fetchall()
        )

        return ArchiveAnalysis(
            path=archive,
            total_events=total_events,
            status_counts=status_counts,
            log_type_counts=log_type_counts,
            findings=findings,
        )
    finally:
        connection.close()


def _string_or_none(value: Any) -> str | None:
    return None if value is None else str(value)


def _empty_analysis(archive: Path) -> ArchiveAnalysis:
    return ArchiveAnalysis(
        path=archive,
        total_events=0,
        status_counts=tuple(StatusCount(status, 0) for status in STATUSES),
        log_type_counts=(),
        findings=(),
    )


def _create_events(connection: Any, archive: Path) -> None:
    archive_sql = _sql_literal(str(archive))

    # Reading the objects as JSON rather than relying on automatic structural
    # inference makes the envelope stable when an archive happens to contain no
    # rule objects or contains empty decoder objects ("decoder": {}).
    connection.execute(
        f"""
        CREATE TEMP TABLE events AS
        WITH extracted AS (
            SELECT json_extract_string(
                json,
                [
                    '$.timestamp',
                    '$.agent.id',
                    '$.agent.name',
                    '$.location',
                    '$.full_log',
                    '$.predecoder.program_name',
                    '$.decoder.name',
                    '$.decoder.parent',
                    '$.rule.id',
                    '$.rule.level',
                    '$.rule.description'
                ]
            ) AS fields
            FROM read_ndjson_objects({archive_sql}, ignore_errors = false)
        )
        SELECT
            try_cast(fields[1] AS TIMESTAMP) AS event_timestamp,
            fields[2] AS agent_id,
            fields[3] AS agent_name,
            fields[4] AS location,
            fields[5] AS full_log,
            fields[6] AS program_name,
            fields[7] AS decoder_name,
            fields[8] AS decoder_parent,
            fields[9] AS rule_id,
            try_cast(fields[10] AS INTEGER) AS rule_level,
            fields[11] AS rule_description
        FROM extracted
        """
    )


def _create_views(connection: Any, alert_threshold: int) -> None:
    connection.execute(
        f"""
        CREATE TEMP VIEW classified_events AS
        SELECT
            *,
            CASE
                WHEN nullif(decoder_name, '') IS NULL THEN 'no_decoder'
                WHEN nullif(rule_id, '') IS NULL THEN 'no_rule'
                WHEN rule_level IS NULL OR rule_level < {int(alert_threshold)} THEN 'below_threshold'
                ELSE 'at_or_above_threshold'
            END AS observed_status,
            CASE
                WHEN nullif(decoder_name, '') IS NOT NULL THEN decoder_name
                WHEN nullif(program_name, '') IS NOT NULL THEN program_name
                WHEN nullif(location, '') IS NOT NULL THEN location
                ELSE 'unknown'
            END AS log_type
        FROM events
        """
    )

    # Conservative normalization: common timestamp prefixes, UUIDs, long hex
    # tokens and long decimal IDs. Short numbers, IPs, ports, usernames, paths,
    # event IDs and status codes are intentionally retained because they can
    # materially change detection semantics.
    connection.execute(
        r"""
        CREATE TEMP VIEW normalized_events AS
        SELECT
            *,
            trim(
                regexp_replace(
                    regexp_replace(
                        regexp_replace(
                            regexp_replace(
                                regexp_replace(
                                    coalesce(full_log, ''),
                                    '^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[[:space:]]+[0-9]{1,2}[[:space:]]+[0-9]{2}:[0-9]{2}:[0-9]{2}',
                                    '<TIMESTAMP>',
                                    'c'
                                ),
                                '^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}([.,][0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})?',
                                '<TIMESTAMP>',
                                'c'
                            ),
                            '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}',
                            '<UUID>',
                            'g'
                        ),
                        '\b(0x)?[0-9A-Fa-f]{16,}\b',
                        '<HEX>',
                        'g'
                    ),
                    '\b[0-9]{5,}\b',
                    '<NUM>',
                    'g'
                )
            ) AS normalized_log
        FROM classified_events
        """
    )

    connection.execute(
        """
        CREATE TEMP VIEW finding_events AS
        SELECT
            *,
            CASE
                WHEN observed_status = 'below_threshold' THEN concat('rule:', coalesce(rule_id, 'unknown'))
                ELSE normalized_log
            END AS message_pattern,
            CASE
                WHEN observed_status = 'below_threshold' THEN NULL
                ELSE log_type
            END AS finding_log_type,
            md5(
                CASE
                    WHEN observed_status = 'below_threshold'
                        THEN concat(observed_status, '|', coalesce(rule_id, 'unknown'))
                    ELSE concat(observed_status, '|', log_type, '|', normalized_log)
                END
            ) AS finding_key
        FROM normalized_events
        WHERE observed_status <> 'at_or_above_threshold'
          AND full_log IS NOT NULL
          AND full_log <> ''
        """
    )

    connection.execute(
        """
        CREATE TEMP VIEW findings AS
        SELECT
            finding_key,
            any_value(observed_status) AS observed_status,
            any_value(finding_log_type) AS log_type,
            any_value(message_pattern) AS message_pattern,
            count(*) AS event_count,
            count(DISTINCT agent_id) FILTER (WHERE agent_id IS NOT NULL) AS affected_agents,
            min(event_timestamp) AS first_seen,
            max(event_timestamp) AS last_seen,
            any_value(decoder_name) AS observed_decoder,
            any_value(rule_id) AS observed_rule_id,
            any_value(rule_level) AS observed_rule_level,
            min(full_log) AS sample_log
        FROM finding_events
        GROUP BY finding_key
        """
    )
