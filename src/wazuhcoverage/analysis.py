"""DuckDB-backed analysis of one Wazuh archive."""

from __future__ import annotations

import csv
import os
import tempfile
from pathlib import Path
from typing import Any, Optional, Union

from wazuhcoverage.models import STATUSES, ArchiveAnalysis, Finding, LogTypeCount, StatusCount

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


def _load_template_miner() -> Any:
    """Build a drain3 template miner.

    drain3 is an optional extra rather than a runtime dependency, so the import
    error is translated into an actionable message instead of a traceback.
    """

    try:
        from drain3 import TemplateMiner
        from drain3.template_miner_config import TemplateMinerConfig
    except ImportError as exc:
        raise RuntimeError(
            "Template mining requires drain3. Install it with: pip install 'wazuhcoverage[drain3]'"
        ) from exc

    # The config is constructed explicitly because drain3 otherwise loads a
    # drain3.ini from the current working directory, which would make an
    # archive's findings depend on where the command happened to run.
    config = TemplateMinerConfig()
    config.profiling_enabled = False
    # No masking instructions are registered: the SQL normalizer already applies
    # the conservative masks this project documents, and a second masking pass
    # would silently widen them beyond what the README promises.
    config.masking_instructions = []
    # No persistence handler: state is per-archive, keeping the CLI's single
    # piece of persistent state (history.db) as the only thing on disk.
    return TemplateMiner(config=config)


def analyze_archive(
    path: Union[str, Path],
    *,
    alert_threshold: int = DEFAULT_ALERT_THRESHOLD,
    skip_malformed: bool = True,
    template_mining: bool = False,
) -> ArchiveAnalysis:
    """Analyze one Wazuh NDJSON archive.

    The compressed/uncompressed source is scanned once into a temporary table.
    All subsequent classification, grouping and sampling runs against that table.

    A line DuckDB cannot parse as a JSON object is skipped rather than failing
    the whole archive, and the number of such lines is reported as
    ``ArchiveAnalysis.malformed_lines``. Skipped lines are excluded from
    ``total_events``, so the coverage denominator stays exact and auditable.
    Pass ``skip_malformed=False`` to reject the archive on the first bad line.

    ``template_mining=True`` replaces the regex-normalized message with a Drain
    template mined from the archive, which collapses variants the regex masks
    cannot reach -- usernames, hostnames, paths and other categorical tokens.
    It requires the ``drain3`` extra and changes ``Finding.finding_key``, so
    findings produced with and without it are not comparable.
    """

    archive = Path(path).expanduser().resolve()
    if not archive.is_file():
        raise FileNotFoundError(archive)

    if alert_threshold < 0:
        raise ValueError("alert_threshold must be non-negative")

    # Built before any work so a missing extra fails immediately rather than
    # after a full archive scan.
    miner = _load_template_miner() if template_mining else None

    if archive.stat().st_size == 0:
        return _empty_analysis(archive, template_mining=template_mining)

    duckdb = _load_duckdb()
    connection = duckdb.connect(":memory:")
    try:
        connection.execute("SET TimeZone = 'UTC'")
        _create_events(connection, archive, skip_malformed=skip_malformed)
        _create_views(connection, alert_threshold)
        use_templates = _create_template_map(connection, miner)
        _create_finding_views(connection, use_templates=use_templates)

        malformed_lines = int(connection.execute("SELECT count(*) FROM events WHERE is_malformed").fetchone()[0])
        total_events = int(connection.execute("SELECT count(*) FROM classified_events").fetchone()[0])

        raw_statuses = {
            str(status): int(count)
            for status, count in connection.execute(
                "SELECT observed_status, count(*) FROM classified_events GROUP BY observed_status"
            ).fetchall()
        }

        # Every status is reported even when it holds no event: a zero bucket is
        # a coverage statement, not missing data. Ties keep the STATUSES order so
        # two runs over the same archive render identically.
        status_counts = tuple(
            sorted(
                (
                    StatusCount(
                        status=status,
                        event_count=raw_statuses.get(status, 0),
                        percentage=_percentage(raw_statuses.get(status, 0), total_events),
                    )
                    for status in STATUSES
                ),
                key=lambda item: (-item.event_count, STATUSES.index(item.status)),
            )
        )

        log_type_counts = tuple(
            LogTypeCount(
                status=str(status),
                log_type=_string_or_none(log_type),
                event_count=int(count),
                percentage=_percentage(int(count), total_events),
                status_percentage=_percentage(int(count), raw_statuses.get(str(status), 0)),
            )
            for status, log_type, count in connection.execute(
                """
                SELECT observed_status, log_type, count(*) AS event_count
                FROM classified_events
                GROUP BY observed_status, log_type
                ORDER BY event_count DESC, observed_status, log_type
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
            malformed_lines=malformed_lines,
            status_counts=status_counts,
            log_type_counts=log_type_counts,
            findings=findings,
            template_mining=template_mining,
        )
    finally:
        connection.close()


def _string_or_none(value: Any) -> Optional[str]:
    return None if value is None else str(value)


def _percentage(part: int, whole: int) -> float:
    """Return ``part`` as a percentage of ``whole``, or 0.0 when ``whole`` is 0.

    An empty denominator is a real case here -- an empty archive, or a status
    bucket no event fell into -- and 0.0 is the only honest answer for it.
    """

    return 0.0 if whole == 0 else 100.0 * part / whole


def _empty_analysis(archive: Path, *, template_mining: bool = False) -> ArchiveAnalysis:
    return ArchiveAnalysis(
        path=archive,
        total_events=0,
        malformed_lines=0,
        status_counts=tuple(StatusCount(status=status, event_count=0, percentage=0.0) for status in STATUSES),
        log_type_counts=(),
        findings=(),
        template_mining=template_mining,
    )


def _create_events(connection: Any, archive: Path, *, skip_malformed: bool) -> None:
    archive_sql = _sql_literal(str(archive))
    ignore_errors = "true" if skip_malformed else "false"

    # Reading the objects as JSON rather than relying on automatic structural
    # inference makes the envelope stable when an archive happens to contain no
    # rule objects or contains empty decoder objects ("decoder": {}).
    #
    # ignore_errors = true does not drop an unparseable line: DuckDB yields a
    # NULL document in its place. Such a row would otherwise extract as all-NULL
    # fields and be classified as no_decoder, inflating both the event total and
    # that bucket. It is therefore tagged here and excluded from classification,
    # which keeps the coverage denominator exact while still counting the loss.
    # A line that parses but is not an object -- a bare scalar, array or null --
    # is rejected by strict mode too, so it is tagged the same way.
    connection.execute(
        f"""
        CREATE TEMP TABLE events AS
        WITH extracted AS (
            SELECT
                (json IS NULL OR json_type(json) <> 'OBJECT') AS is_malformed,
                json_extract_string(
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
            FROM read_ndjson_objects({archive_sql}, ignore_errors = {ignore_errors})
        )
        SELECT
            is_malformed,
            try_cast(fields[1] AS TIMESTAMPTZ) AS event_timestamp,
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
            * EXCLUDE (is_malformed),
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
        WHERE NOT is_malformed
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


def _create_template_map(connection: Any, miner: Optional[Any]) -> bool:
    """Mine one Drain template per distinct normalized message.

    Only the statuses that group by message text are mined. ``below_threshold``
    is excluded because it groups by rule ID, where the rule is already the
    semantic grouping and a mined template would add nothing.

    The scan, the deduplication, the join and the counting all stay in DuckDB;
    Drain only ever sees the distinct normalized strings, which keeps the cost
    proportional to the archive's vocabulary rather than to its event count.

    Drain is order dependent, so distinct messages are fed in sorted order.
    drain3's ``cluster_id`` is deliberately not used as a key: it is assigned in
    arrival order. Template IDs are derived from the sorted template text
    instead, so the same archive always produces the same grouping.

    Returns ``False`` when mining was not requested or found nothing to group.
    """

    if miner is None:
        return False

    connection.execute(
        """
        CREATE TEMP TABLE distinct_logs AS
        SELECT
            normalized_log,
            row_number() OVER (ORDER BY normalized_log) AS log_id
        FROM (
            SELECT DISTINCT normalized_log
            FROM normalized_events
            WHERE observed_status IN ('no_decoder', 'no_rule')
              AND full_log IS NOT NULL
              AND full_log <> ''
        )
        """
    )

    rows = connection.execute("SELECT log_id, normalized_log FROM distinct_logs ORDER BY log_id").fetchall()
    if not rows:
        return False

    # The template a message receives when it is inserted can still widen as
    # later messages join the same cluster, so the cluster is recorded during
    # the pass and the final template is read back only once every message has
    # been seen. Mapping on the insertion-time template would split a cluster.
    assignments = []
    for row in rows:
        assignments.append((int(row[0]), miner.add_log_message(str(row[1]))["cluster_id"]))

    mined = {cluster.cluster_id: cluster.get_template() for cluster in miner.drain.clusters}
    template_ids = {
        template: index for index, template in enumerate(sorted({mined[cluster] for _, cluster in assignments}))
    }

    _load_log_templates(connection, [(log_id, template_ids[mined[cluster]]) for log_id, cluster in assignments])

    connection.execute("CREATE TEMP TABLE templates (template_id INTEGER, log_template VARCHAR)")
    connection.executemany(
        "INSERT INTO templates VALUES (?, ?)",
        [(template_id, template) for template, template_id in template_ids.items()],
    )
    return True


def _load_log_templates(connection: Any, assignments: list[tuple[int, int]]) -> None:
    """Load the log-ID to template-ID mapping through a temporary CSV file.

    DuckDB's Python parameter binding costs roughly 140 microseconds per row for
    bulk data -- about 25 seconds for one high-entropy archive -- while its CSV
    reader loads the same rows in 0.2 seconds. Chunking the binding does not
    help, so the mapping is handed over as a file instead.

    Only integers are written. No log text passes through CSV quoting, so an
    embedded delimiter, quote or newline in a message cannot corrupt the join
    key. The file is removed before this function returns.
    """

    handle, path = tempfile.mkstemp(prefix="wazuhcoverage-templates-", suffix=".csv")
    os.close(handle)
    try:
        with open(path, "w", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerows(assignments)
        connection.execute(
            "CREATE TEMP TABLE log_templates AS SELECT * FROM "
            "read_csv(?, header = false, columns = {'log_id': 'BIGINT', 'template_id': 'INTEGER'})",
            [path],
        )
    finally:
        os.unlink(path)


def _create_finding_views(connection: Any, *, use_templates: bool) -> None:
    # coalesce() keeps the regex-normalized message as the fallback so a row
    # that somehow missed the join still groups rather than collapsing to NULL.
    pattern = "coalesce(t.log_template, n.normalized_log)" if use_templates else "n.normalized_log"
    source = (
        """normalized_events n
        LEFT JOIN distinct_logs d ON d.normalized_log = n.normalized_log
        LEFT JOIN log_templates lt ON lt.log_id = d.log_id
        LEFT JOIN templates t ON t.template_id = lt.template_id"""
        if use_templates
        else "normalized_events n"
    )

    connection.execute(
        f"""
        CREATE TEMP VIEW finding_events AS
        SELECT
            n.*,
            CASE
                WHEN n.observed_status = 'below_threshold' THEN concat('rule:', coalesce(n.rule_id, 'unknown'))
                ELSE {pattern}
            END AS message_pattern,
            CASE
                WHEN n.observed_status = 'below_threshold' THEN NULL
                ELSE n.log_type
            END AS finding_log_type,
            CASE
                WHEN n.observed_status = 'below_threshold' THEN NULL
                ELSE n.decoder_name
            END AS finding_decoder,
            md5(
                CASE
                    WHEN n.observed_status = 'below_threshold'
                        THEN concat(n.observed_status, '|', coalesce(n.rule_id, 'unknown'))
                    ELSE concat(n.observed_status, '|', n.log_type, '|', {pattern})
                END
            ) AS finding_key
        FROM {source}
        WHERE n.observed_status <> 'at_or_above_threshold'
          AND n.full_log IS NOT NULL
          AND n.full_log <> ''
        """
    )

    # Raw string: the sample normalization below passes regex escapes to
    # DuckDB, they are not Python escapes.
    connection.execute(
        r"""
        CREATE TEMP VIEW findings AS
        SELECT
            finding_key,
            any_value(observed_status) AS observed_status,
            any_value(finding_log_type) AS log_type,
            any_value(message_pattern) AS message_pattern,
            count(*) AS event_count,
            count(DISTINCT agent_id) FILTER (WHERE agent_id IS NOT NULL) AS affected_agents,
            strftime(min(event_timestamp), '%Y-%m-%d %H:%M:%S%z') AS first_seen,
            strftime(max(event_timestamp), '%Y-%m-%d %H:%M:%S%z') AS last_seen,
            any_value(finding_decoder) AS observed_decoder,
            any_value(rule_id) AS observed_rule_id,
            any_value(rule_level) AS observed_rule_level,
            -- The representative is still the deterministic min() of the raw
            -- logs; only its line breaks are collapsed. A sample exists to be
            -- replayed through wazuh-logtest, which reads one log per line, so
            -- a multi-line log emitted verbatim would be replayed as several
            -- unrelated logs -- the first tested against the wrong decoder and
            -- the rest as fragments no rule was ever written for.
            trim(regexp_replace(min(full_log), '[\r\n]+', ' ', 'g')) AS sample_log
        FROM finding_events
        GROUP BY finding_key
        """
    )
