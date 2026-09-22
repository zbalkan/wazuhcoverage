"""DuckDB-backed analysis of one Wazuh archive."""

from __future__ import annotations

import csv
import json
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


# Drain tuning. The library defaults (sim_th = 0.4, depth = 4) merge log
# families a coverage report must keep apart: on a labelled corpus of sixteen
# families they placed Windows 4624 and 4625 -- a successful and a failed logon
# -- in one template, and did the same for firewall ACCEPT and DROP. Raising
# the similarity threshold removes those merges, and raising it too far shatters
# families whose variable tokens are paths or hostnames. Measured across three
# corpus seeds, thresholds up to 0.53 always produced cross-family merges and
# 0.58 exploded the template count from 25 to 93; 0.56 and 0.57 were the only
# values with neither defect on every seed, so the midpoint of that plateau is
# taken with margin on both sides. Re-run tools/tune_drain.py after changing
# the normalizer, the corpus or the drain3 version.
_DRAIN_SIM_TH = 0.56
# Depth of the prefix tree, in tokens plus two sentinel levels. Left at the
# library default: at the chosen threshold a depth of 3 produced identical
# results with one fewer discriminating token, and 5 only fragmented further.
_DRAIN_DEPTH = 4
# Bound on the number of live clusters, evicted least-recently-used. It bounds
# both memory and time on input that defeats grouping, and time is the reason
# it exists. Measured on messages that share no structure at all, where every
# message becomes its own cluster: 60,000 of them took 103 seconds, 120,000
# took 1,373 seconds and peaked at 127 MB, so the cost grows far faster than
# the input. Capping the live clusters bounds it -- the same 120,000 messages
# took 449 seconds and 25 MB under a 20,000 cluster cap. A cluster costs about
# 1.1 KB, so this bound holds the miner near 22 MB and avoids permitting the
# roughly 2.5-times-longer scan implied by the former 50,000-cluster cap.
#
# Eviction is a safety valve rather than part of normal grouping. Templates are
# keyed by text, so a cluster recreated after an eviction still lands in its
# original finding.
_DRAIN_MAX_CLUSTERS = 20_000


def _build_template_miner() -> Any:
    """Build the Drain template miner used to group unresolved events."""

    try:
        from drain3 import TemplateMiner
        from drain3.template_miner_config import TemplateMinerConfig
        from wazuhcoverage._drain import IndexedDrain
    except ImportError as exc:  # pragma: no cover - installation error path
        raise RuntimeError("drain3 is required. Install wazuhcoverage with its dependencies.") from exc

    # The config is constructed explicitly because drain3 otherwise loads a
    # drain3.ini from the current working directory, which would make an
    # archive's findings depend on where the command happened to run.
    config = TemplateMinerConfig()
    config.profiling_enabled = False
    config.drain_sim_th = _DRAIN_SIM_TH
    config.drain_depth = _DRAIN_DEPTH
    config.drain_max_clusters = _DRAIN_MAX_CLUSTERS
    # Numeric tokens stay parametrized, as drain3 ships them. Turning this off
    # to protect event IDs and ports was measured and rejected: it multiplied
    # the template count roughly tenfold without removing a single cross-family
    # merge, because the tokens that distinguish those families carry digits
    # inside a larger token and are wildcarded either way.
    config.parametrize_numeric_tokens = True
    # No masking instructions are registered: the SQL normalizer already applies
    # the conservative masks this project documents, and a second masking pass
    # would silently widen them beyond what the README promises.
    config.masking_instructions = []
    # No persistence handler: mined state is per-archive and stays in memory,
    # which is what lets a run leave nothing on disk behind it.
    miner = TemplateMiner(config=config)
    miner.drain = IndexedDrain(
        sim_th=config.drain_sim_th,
        depth=config.drain_depth,
        max_children=config.drain_max_children,
        max_clusters=config.drain_max_clusters,
        extra_delimiters=config.drain_extra_delimiters,
        profiler=miner.profiler,
        param_str=config.mask_prefix + "*" + config.mask_suffix,
        parametrize_numeric_tokens=config.parametrize_numeric_tokens,
    )
    return miner


def analyze_archive(
    path: Union[str, Path],
    *,
    alert_threshold: int = DEFAULT_ALERT_THRESHOLD,
    skip_malformed: bool = True,
) -> ArchiveAnalysis:
    """Analyze one Wazuh NDJSON archive.

    The compressed/uncompressed source is scanned once into a temporary table.
    All subsequent classification, grouping and sampling runs against that table.

    Unresolved events are grouped by a Drain template mined from the archive,
    which collapses the variants regex masks cannot reach -- usernames,
    hostnames, paths and other categorical tokens. Mining is the only grouping
    engine; the regex normalizer runs ahead of it as a masking pass.

    A line DuckDB cannot parse as a JSON object is skipped rather than failing
    the whole archive, and the number of such lines is reported as
    ``ArchiveAnalysis.malformed_lines``. Skipped lines are excluded from
    ``total_events``, so the coverage denominator stays exact and auditable.
    Pass ``skip_malformed=False`` to reject the archive on the first bad line.
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
        connection.execute("SET TimeZone = 'UTC'")
        _create_events(connection, archive, skip_malformed=skip_malformed)
        _create_views(connection, alert_threshold)
        _create_template_map(connection, _build_template_miner())
        _create_finding_views(connection)

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
                observed_location=_string_or_none(row[9]),
                observed_rule_id=_string_or_none(row[10]),
                observed_rule_level=int(row[11]) if row[11] is not None else None,
                sample_log=str(row[12]),
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
                    observed_location,
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


def _empty_analysis(archive: Path) -> ArchiveAnalysis:
    return ArchiveAnalysis(
        path=archive,
        total_events=0,
        malformed_lines=0,
        status_counts=tuple(StatusCount(status=status, event_count=0, percentage=0.0) for status in STATUSES),
        log_type_counts=(),
        findings=(),
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
    # The classification reads the archive record and nothing else. The rule
    # branch is the one that cannot be tightened: analysisd abandons a level-0
    # match before it assigns lf->generated_rule, and sets that pointer back to
    # NULL when a rule's ignore window suppresses the event, yet queues the
    # archive record in every case; the JSON formatter writes a "rule" object
    # only when the pointer survived. A missing rule therefore covers "nothing
    # matched", "a level-0 rule matched" and "a match was suppressed" alike,
    # and no field in the record separates them. The bucket is named for what
    # can be proven -- no alerting rule was attached -- rather than for the
    # stronger claim that no rule was evaluated.
    connection.execute(
        f"""
        CREATE TEMP VIEW classified_events AS
        SELECT
            * EXCLUDE (is_malformed),
            CASE
                WHEN nullif(decoder_name, '') IS NULL THEN 'no_decoder'
                WHEN nullif(rule_id, '') IS NULL THEN 'no_alerting_rule'
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


def _create_template_map(connection: Any, miner: Any) -> None:
    """Mine one Drain template per distinct normalized message.

    Only the statuses that group by message text are mined. ``below_threshold``
    is excluded because it groups by rule ID, where the rule is already the
    semantic grouping and a mined template would add nothing. ``no_decoder``
    and ``no_alerting_rule`` have no rule ID to group by -- the latter by
    definition, since the absence of a rule is what puts an event there -- so
    the message is the only grouping key available to them.

    The scan, the deduplication, the join and the counting all stay in DuckDB;
    Drain only ever sees the distinct normalized strings, which keeps the cost
    proportional to the archive's vocabulary rather than to its event count.

    Drain is order dependent, so distinct messages are fed in sorted order.
    drain3's ``cluster_id`` is deliberately not used as a key: it is assigned in
    arrival order. Template IDs are derived from the sorted template text
    instead, so the same archive always produces the same grouping.

    The mapping tables are always created, empty included, so the finding views
    join against a fixed shape whatever the archive contains.
    """

    connection.execute(
        """
        CREATE TEMP TABLE distinct_logs AS
        SELECT
            normalized_log,
            row_number() OVER (ORDER BY normalized_log) AS log_id
        FROM (
            SELECT DISTINCT normalized_log
            FROM normalized_events
            WHERE observed_status IN ('no_decoder', 'no_alerting_rule')
              AND full_log IS NOT NULL
              AND full_log <> ''
        )
        """
    )

    rows = connection.execute("SELECT log_id, normalized_log FROM distinct_logs ORDER BY log_id").fetchall()

    # The template a message receives when it is inserted can still widen as
    # later messages join the same cluster. Keep the most recently returned
    # template for every cluster so all of its assignments use the final value.
    # This also preserves the last template of an LRU-evicted cluster: reading
    # only miner.drain.clusters after the pass would lose it and make the safety
    # cap turn into a KeyError as soon as the first eviction occurred.
    assignments = []
    mined: dict[int, str] = {}
    for log_id, normalized_log in rows:
        result = miner.add_log_message(str(normalized_log))
        cluster_id = int(result["cluster_id"])
        assignments.append((int(log_id), cluster_id))
        mined[cluster_id] = str(result["template_mined"])

    # Two clusters can carry the same template text once eviction recreates one,
    # so text is the key and such clusters land in a single finding.
    template_ids = {
        template: index for index, template in enumerate(sorted({mined[cluster] for _, cluster in assignments}))
    }

    connection.execute("CREATE TEMP TABLE log_templates (log_id BIGINT, template_id INTEGER)")
    connection.execute("CREATE TEMP TABLE templates (template_id INTEGER, log_template VARCHAR)")
    if not assignments:
        return

    _load_log_templates(connection, [(log_id, template_ids[mined[cluster]]) for log_id, cluster in assignments])
    _load_templates(connection, [(template_id, template) for template, template_id in template_ids.items()])


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
            "INSERT INTO log_templates SELECT * FROM "
            "read_csv(?, header = false, columns = {'log_id': 'BIGINT', 'template_id': 'INTEGER'})",
            [path],
        )
    finally:
        os.unlink(path)


def _load_templates(connection: Any, templates: list[tuple[int, str]]) -> None:
    """Bulk-load template text through NDJSON instead of per-row bindings."""

    handle, path = tempfile.mkstemp(prefix="wazuhcoverage-template-text-", suffix=".json")
    os.close(handle)
    try:
        with open(path, "w", encoding="utf-8") as stream:
            for template_id, template in templates:
                json.dump({"template_id": template_id, "log_template": template}, stream, ensure_ascii=False)
                stream.write("\n")
        connection.execute(
            """
            INSERT INTO templates
            SELECT
                cast(json_extract(json, '$.template_id') AS INTEGER),
                json_extract_string(json, '$.log_template')
            FROM read_ndjson_objects(?)
            """,
            [path],
        )
    finally:
        os.unlink(path)


def _create_finding_views(connection: Any) -> None:
    # coalesce() keeps the regex-normalized message as the fallback so a row
    # that somehow missed the join still groups rather than collapsing to NULL.
    # below_threshold rows always take that path: they are not mined, because a
    # rule ID is already their grouping.
    pattern = "coalesce(t.log_template, n.normalized_log)"
    source = """normalized_events n
        LEFT JOIN distinct_logs d ON d.normalized_log = n.normalized_log
        LEFT JOIN log_templates lt ON lt.log_id = d.log_id
        LEFT JOIN templates t ON t.template_id = lt.template_id"""

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
            -- Reported for the same reason the decoder is: a below_threshold
            -- finding spans whatever sources its rule fired on, so claiming
            -- one of their locations would be arbitrary.
            CASE
                WHEN n.observed_status = 'below_threshold' THEN NULL
                ELSE n.location
            END AS finding_location,
            md5(to_json(
                CASE
                    WHEN n.observed_status = 'below_threshold'
                        THEN [n.observed_status, coalesce(n.rule_id, 'unknown')]
                    ELSE [n.observed_status, n.log_type, {pattern}]
                END
            )) AS finding_key
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
            arg_min(struct_pack(decoder := finding_decoder, location := finding_location,
                rule := rule_id, level := rule_level),
                struct_pack(log := full_log, location := coalesce(finding_location, ''),
                decoder := coalesce(finding_decoder, ''), rule := coalesce(rule_id, ''),
                level := coalesce(rule_level, -1))).decoder AS observed_decoder,
            arg_min(struct_pack(decoder := finding_decoder, location := finding_location,
                rule := rule_id, level := rule_level),
                struct_pack(log := full_log, location := coalesce(finding_location, ''),
                decoder := coalesce(finding_decoder, ''), rule := coalesce(rule_id, ''),
                level := coalesce(rule_level, -1))).location AS observed_location,
            arg_min(struct_pack(decoder := finding_decoder, location := finding_location,
                rule := rule_id, level := rule_level),
                struct_pack(log := full_log, location := coalesce(finding_location, ''),
                decoder := coalesce(finding_decoder, ''), rule := coalesce(rule_id, ''),
                level := coalesce(rule_level, -1))).rule AS observed_rule_id,
            arg_min(struct_pack(decoder := finding_decoder, location := finding_location,
                rule := rule_id, level := rule_level),
                struct_pack(log := full_log, location := coalesce(finding_location, ''),
                decoder := coalesce(finding_decoder, ''), rule := coalesce(rule_id, ''),
                level := coalesce(rule_level, -1))).level AS observed_rule_level,
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
