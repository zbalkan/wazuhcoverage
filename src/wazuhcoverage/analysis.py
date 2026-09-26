"""DuckDB-backed analysis of one Wazuh archive."""

from __future__ import annotations

import csv
import heapq
import json
import os
import struct
import tempfile
from collections.abc import Generator, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, Optional, Union

from wazuhcoverage.models import STATUSES, ArchiveAnalysis, Finding, LogTypeCount, StatusCount
from wazuhcoverage.preprocessing import install_preprocessor

try:
    from drain3 import TemplateMiner
    from drain3.template_miner_config import TemplateMinerConfig

    from wazuhcoverage._drain import IndexedDrain
except ImportError as exc:  # pragma: no cover - installation error path
    raise RuntimeError("drain3 is required. Install wazuhcoverage with its dependencies.") from exc

try:
    import duckdb
    if TYPE_CHECKING:
        from duckdb import DuckDBPyConnection

except ImportError as exc:  # pragma: no cover - installation error path
    raise RuntimeError(
        "DuckDB is required. Install wazuhcoverage with its dependencies.") from exc

DEFAULT_ALERT_THRESHOLD = 3


def _sql_literal(value: str) -> str:
    """Quote a string as a DuckDB SQL literal."""

    return "'" + value.replace("'", "''") + "'"


@contextmanager
def _connect() -> Generator[DuckDBPyConnection, None, None]:
    """Open an in-memory DuckDB connection that spills to a private directory.

    Memory and threads are DuckDB's own defaults. The archive is held in
    memory while it fits and moves to disk when it does not: once DuckDB
    reaches its memory limit, 80% of physical memory by default, it evicts
    blocks of the event table and of large sorts, joins and aggregations to its
    temp directory instead of failing.

    DuckDB's own default spill location is ``.tmp`` under the current working
    directory, which would make where a run writes depend on where it was
    launched and fail outright in a read-only directory. The spill directory is
    therefore created under the system temporary directory, private to this
    connection, and removed with everything in it once the connection closes.
    """

    with tempfile.TemporaryDirectory(prefix="wazuhcoverage-duckdb-") as spill_directory:
        connection: DuckDBPyConnection = duckdb.connect(":memory:", config={"temp_directory": spill_directory})
        try:
            # Every join here is written with its small side on the right, and
            # that side has to stay the build side: the events feeding them
            # carry logs of up to 64 KiB, and DuckDB estimates how many survive
            # the finding filter at a few percent of the true count. With the
            # reordering on, it turned the template join around and built its
            # hash table from the events, which then needs memory in proportion
            # to the archive's text rather than to its number of templates.
            connection.execute("SET disabled_optimizers = 'join_order,build_side_probe_side'")
            yield connection
        finally:
            # Closed before the directory is removed: DuckDB releases its spill
            # files on close, and Windows refuses to delete a file still open.
            connection.close()


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
# the preprocessor, the corpus or the drain3 version.
_DRAIN_SIM_TH = 0.56
# Depth of the prefix tree, in tokens plus two sentinel levels. Left at the
# library default: at the chosen threshold a depth of 3 produced identical
# results with one fewer discriminating token, and 5 only fragmented further.
_DRAIN_DEPTH = 4
# Bound on the number of live clusters, evicted least-recently-used. It limits
# memory and the candidate-heavy cases that defeat both the prefix tree and the
# positional index. A cluster costs about 1.1 KB, so this holds cluster storage
# near 22 MB. The indexed unique-heavy benchmark processed one million distinct
# messages in 48.5 seconds while keeping both live clusters and index entries at
# this limit.
#
# Eviction is a safety valve rather than part of normal grouping. Templates are
# keyed by text, so a cluster recreated after an eviction still lands in its
# original finding.
_DRAIN_MAX_CLUSTERS = 20_000
# Raw log text read from DuckDB and sorted in Python at a time, before it is
# written to disk as one run of the merge that feeds Drain in order. Python
# holds one run while writing it, and one line per run while merging. It only
# trades round trips for memory; it has no effect on the result.
_SORT_RUN_CHARACTERS = 64 * 1024 * 1024
_ASSIGNMENTS_FILE = "assignments.csv"
_TEMPLATES_FILE = "templates.ndjson"


def _build_template_miner() -> TemplateMiner:
    """Build the Drain template miner used to group unresolved events."""

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
    # No masking instructions are registered: the preprocessor already applies
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
    engine; the preprocessor runs ahead of it as a masking pass.

    A line DuckDB cannot parse as a JSON object is skipped rather than failing
    the whole archive, and the number of such lines is reported as
    ``ArchiveAnalysis.malformed_lines``. Skipped lines are excluded from
    ``total_events``, so the coverage denominator stays exact and auditable.
    Pass ``skip_malformed=False`` to reject the archive on the first bad line.

    The analysis runs in memory and spills to a private temporary directory
    when it outgrows DuckDB's default memory limit, 80% of physical memory.
    """

    archive = Path(path).expanduser().resolve()
    if not archive.is_file():
        raise FileNotFoundError(archive)

    if alert_threshold < 0:
        raise ValueError("alert_threshold must be non-negative")

    if archive.stat().st_size == 0:
        return _empty_analysis(archive)

    return _analyze(archive, alert_threshold, skip_malformed)


def _analyze(archive: Path, alert_threshold: int, skip_malformed: bool) -> ArchiveAnalysis:
    with _connect() as connection:
        connection.execute("SET TimeZone = 'UTC'")
        _create_events(connection, archive, skip_malformed=skip_malformed)
        _create_views(connection, alert_threshold)
        install_preprocessor(connection)
        _create_template_map(connection, _build_template_miner())
        _create_finding_views(connection)

        malformed_lines = _count_rows(connection, "SELECT count(*) FROM events WHERE is_malformed")
        total_events = _count_rows(connection, "SELECT count(*) FROM classified_events")

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


def _count_rows(connection: DuckDBPyConnection, query: str) -> int:
    """Run a scalar count query and return its non-null value."""

    row = connection.execute(query).fetchone()
    if row is None or len(row) != 1 or row[0] is None:
        raise RuntimeError("count query returned no scalar value")
    return int(row[0])


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


def _create_events(connection: DuckDBPyConnection, archive: Path, *, skip_malformed: bool) -> None:
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


def _create_views(connection: DuckDBPyConnection, alert_threshold: int) -> None:
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
            rowid AS event_id,
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


def _create_template_map(connection: DuckDBPyConnection, miner: TemplateMiner) -> None:
    """Mine one Drain template per distinct normalized message.

    Only the statuses that group by message text are mined. ``below_threshold``
    is excluded because it groups by rule ID, where the rule is already the
    semantic grouping and a mined template would add nothing. ``no_decoder``
    and ``no_alerting_rule`` have no rule ID to group by -- the latter by
    definition, since the absence of a rule is what puts an event there -- so
    the message is the only grouping key available to them.

    Messages are identified by the 128-bit MD5 of their normalized text, and
    the text itself never enters a hash table or a sort inside DuckDB. A
    Windows event's message runs to 32,766 characters and its full_log to 64
    KiB, and DuckDB cannot spill a DISTINCT, an ORDER BY or a hash join whose
    rows carry text that long: each needed memory in proportion to the
    archive's distinct text, so no memory limit held. Hashing, grouping and
    joining on the digest keeps those steps at a few bytes per message, and
    the text reaches Python by a streaming scan. Two different messages sharing
    a digest would merge their findings, which at 2^-128 per pair is not a
    practical risk.

    Drain is order dependent, so distinct messages are fed in sorted order.
    The sort runs in Python over sorted runs spilled to disk and merged, which
    bounds its memory; Python orders strings by code point, which is the order
    DuckDB's binary collation gives UTF-8, so the feed is the one an ORDER BY
    would produce. drain3's ``cluster_id`` is deliberately not used as a key:
    it is assigned in arrival order. Template IDs are derived from the
    template text instead, so the same archive always produces the same
    grouping.

    The mapping tables are always created, empty included, so the finding views
    join against a fixed shape whatever the archive contains.
    """

    connection.execute(
        """
        CREATE TEMP TABLE event_logs AS
        SELECT
            event_id,
            md5_number_upper(preprocess_log(full_log)) AS log_hi,
            md5_number_lower(preprocess_log(full_log)) AS log_lo,
            strlen(full_log) AS log_length
        FROM classified_events
        WHERE observed_status IN ('no_decoder', 'no_alerting_rule')
          AND full_log IS NOT NULL
          AND full_log <> ''
        """
    )
    # One event per distinct message: the first, by position in the archive.
    # Which one does not matter, since they all normalize to the same text.
    # Stored in event order with each raw log's length, which is what lets the
    # text be read back in bounded chunks by event range; normalization never
    # lengthens a log, so the raw length is an upper bound on what a chunk holds.
    connection.execute(
        """
        CREATE TEMP TABLE first_logs AS
        SELECT min(event_id) AS event_id, arg_min(log_length, event_id) AS log_length
        FROM event_logs
        GROUP BY log_hi, log_lo
        ORDER BY event_id
        """
    )
    connection.execute("CREATE TEMP TABLE log_templates (log_hi UBIGINT, log_lo UBIGINT, template_id BIGINT)")
    connection.execute("CREATE TEMP TABLE templates (template_id BIGINT, log_template VARCHAR)")

    with tempfile.TemporaryDirectory(prefix="wazuhcoverage-mining-") as work:
        if not _mine(connection, miner, work):
            return
        _load_template_map(connection, work)


def _mine(connection: DuckDBPyConnection, miner: TemplateMiner, work: str) -> int:
    """Feed the distinct messages to Drain in sorted order and spool its decisions.

    Two files come out of the pass. The assignments file holds one
    ``(log_hi, log_lo, cluster_id)`` row per message. The templates file holds
    one row each time a cluster is created or its template changes, numbered
    in the order they happened.

    The template a message receives when it is inserted can still widen as
    later messages join the same cluster, so it is not final until the pass
    ends. Recording every change and keeping the last one per cluster gives
    every assignment the final value without holding the assignments in
    memory. It also preserves the last template of an LRU-evicted cluster:
    reading only ``miner.drain.clusters`` after the pass would lose it and make
    the safety cap turn into a missing template as soon as the first eviction
    occurred.

    Returns the number of messages mined.
    """

    mined = 0
    change = 0
    with ExitStack() as stack:
        assignments_stream = stack.enter_context(
            open(os.path.join(work, _ASSIGNMENTS_FILE), "w", newline="", encoding="utf-8")
        )
        templates_stream = stack.enter_context(
            open(os.path.join(work, _TEMPLATES_FILE), "w", newline="\n", encoding="utf-8")
        )
        assignments = csv.writer(assignments_stream)
        for normalized_log, log_hi, log_lo in _sorted_messages(connection, work, stack):
            result = miner.add_log_message(normalized_log)
            cluster_id = int(result["cluster_id"])
            assignments.writerow((log_hi, log_lo, cluster_id))
            if result["change_type"] != "none":
                change += 1
                record = {"change": change, "cluster_id": cluster_id, "log_template": str(result["template_mined"])}
                templates_stream.write(json.dumps(record, ensure_ascii=False) + "\n")
            mined += 1
    return mined


def _sorted_messages(connection: DuckDBPyConnection, work: str, stack: ExitStack) -> Iterator[tuple[str, int, int]]:
    """Yield every distinct message once, as ``(text, hi, lo)``, in sorted order.

    The messages are read in chunks of consecutive events holding at most
    ``_SORT_RUN_CHARACTERS`` of raw log between them. An archive whose distinct
    text fits one chunk is sorted in memory and yielded directly. Otherwise
    each chunk is sorted and written to disk as a run, and ``heapq.merge``
    reads the runs back as one sorted sequence while holding a record per run.

    Each chunk is its own query over an event-ID range, which DuckDB answers
    from the row groups that range covers. One query streaming every distinct
    message was not an option: DuckDB either materializes such a result in
    full -- all of the archive's distinct text -- or, streaming it, spent a
    tenth of a second on every batch it handed over.
    """

    chunks = connection.execute(
        f"""
        SELECT min(event_id), max(event_id)
        FROM (
            SELECT
                event_id,
                (sum(log_length) OVER (ORDER BY event_id ROWS UNBOUNDED PRECEDING) - log_length)
                    // {_SORT_RUN_CHARACTERS} AS chunk
            FROM first_logs
        )
        GROUP BY chunk
        ORDER BY chunk
        """
    ).fetchall()

    if len(chunks) == 1:
        run = _read_chunk(connection, *chunks[0])
        run.sort()
        return iter(run)

    runs = []
    for index, (first_event, last_event) in enumerate(chunks):
        run = _read_chunk(connection, first_event, last_event)
        run.sort()
        path = os.path.join(work, f"run-{index:06d}.bin")
        with open(path, "wb") as stream:
            _write_run(stream, run)
        del run
        runs.append(_read_run(stack.enter_context(open(path, "rb"))))  # noqa: SIM115 - the ExitStack closes it
    return heapq.merge(*runs)


def _read_chunk(connection: DuckDBPyConnection, first_event: int, last_event: int) -> list[tuple[str, int, int]]:
    # A semi-join, with the digest recomputed from the text it selects, so no
    # join has to carry the log text. The digest travels as its two 64-bit
    # halves: handing DuckDB's 128-bit integer to Python, or casting it to
    # text, cost about 100 microseconds a row -- half a minute for 320,000
    # messages -- where the halves cost about one.
    return connection.execute(
        """
        SELECT normalized_log, md5_number_upper(normalized_log), md5_number_lower(normalized_log)
        FROM (
            SELECT preprocess_log(full_log) AS normalized_log
            FROM classified_events
            WHERE event_id BETWEEN $first AND $last
              AND event_id IN (SELECT event_id FROM first_logs WHERE event_id BETWEEN $first AND $last)
        )
        """,
        {"first": first_event, "last": last_event},
    ).fetchall()


# A run record: the UTF-8 length of the text, the two digest halves, then the
# text. Plain struct packing rather than JSON, which cost several microseconds a
# record each way, or pickle, which would execute whatever a tampered run file
# told it to.
_RUN_RECORD = struct.Struct("<IQQ")


def _write_run(stream: BinaryIO, run: list[tuple[str, int, int]]) -> None:
    pack = _RUN_RECORD.pack
    for normalized_log, log_hi, log_lo in run:
        text = normalized_log.encode("utf-8")
        stream.write(pack(len(text), log_hi, log_lo))
        stream.write(text)


def _read_run(stream: BinaryIO) -> Iterator[tuple[str, int, int]]:
    unpack = _RUN_RECORD.unpack
    size = _RUN_RECORD.size
    while True:
        header = stream.read(size)
        if not header:
            return
        length, log_hi, log_lo = unpack(header)
        yield stream.read(length).decode("utf-8"), log_hi, log_lo


def _load_template_map(connection: DuckDBPyConnection, work: str) -> None:
    """Load the spooled mining results into ``templates`` and ``log_templates``.

    DuckDB's Python parameter binding costs roughly 140 microseconds per row for
    bulk data -- 27 seconds for 50,000 templates -- while its file readers load
    the same rows in a fraction of a second, so the results are handed over as
    files rather than bound as parameters.

    The assignments file is CSV and carries only integers, so no log text passes
    through CSV quoting. The template text goes through JSON instead, whose
    escaping round-trips every delimiter, quote, newline and control character
    a log can contain. As with messages, templates are matched by digest and
    their text is read by streaming scans only.

    Two clusters can carry the same template text once eviction recreates one,
    so text is the key and such clusters land in a single finding: the
    template ID is the smallest cluster ID carrying that text.
    """

    changes = (
        "read_json(?, format = 'newline_delimited', "
        "columns = {'change': 'BIGINT', 'cluster_id': 'BIGINT', 'log_template': 'VARCHAR'})"
    )
    templates_path = os.path.join(work, _TEMPLATES_FILE)
    connection.execute(
        f"""
        CREATE TEMP TABLE cluster_last AS
        SELECT cluster_id, max(change) AS change
        FROM {changes}
        GROUP BY cluster_id
        """,
        [templates_path],
    )
    connection.execute(
        f"""
        CREATE TEMP TABLE cluster_templates AS
        SELECT r.cluster_id, md5_number(r.log_template) AS template_hash
        FROM {changes} r
        JOIN cluster_last l ON l.cluster_id = r.cluster_id AND l.change = r.change
        """,
        [templates_path],
    )
    connection.execute(
        """
        CREATE TEMP TABLE template_ids AS
        SELECT template_hash, min(cluster_id) AS template_id
        FROM cluster_templates
        GROUP BY template_hash
        """
    )
    connection.execute(
        f"""
        INSERT INTO templates
        SELECT r.cluster_id, r.log_template
        FROM {changes} r
        JOIN cluster_last l ON l.cluster_id = r.cluster_id AND l.change = r.change
        JOIN template_ids t ON t.template_id = r.cluster_id
        """,
        [templates_path],
    )
    connection.execute(
        """
        INSERT INTO log_templates
        SELECT a.log_hi, a.log_lo, t.template_id
        FROM read_csv(
            ?,
            header = false,
            columns = {'log_hi': 'UBIGINT', 'log_lo': 'UBIGINT', 'cluster_id': 'BIGINT'}
        ) a
        JOIN cluster_templates c ON c.cluster_id = a.cluster_id
        JOIN template_ids t ON t.template_hash = c.template_hash
        """,
        [os.path.join(work, _ASSIGNMENTS_FILE)],
    )


def _create_finding_views(connection: DuckDBPyConnection) -> None:
    # Events reach their template through their message digest, and findings
    # group on the template ID; the template text is attached only once per
    # finding, at the end. Keyed on text, the join and the grouping would each
    # hold every distinct message, which is what no memory limit could bound.
    connection.execute(
        """
        CREATE TEMP VIEW finding_events AS
        SELECT
            c.*,
            lt.template_id,
            -- A mined event always has a template. Should one ever miss it, the
            -- event still groups with the others of its exact message rather
            -- than collapsing into one finding with every other orphan.
            CASE WHEN c.observed_status <> 'below_threshold' AND lt.template_id IS NULL THEN el.log_hi END
                AS orphan_hi,
            CASE WHEN c.observed_status <> 'below_threshold' AND lt.template_id IS NULL THEN el.log_lo END
                AS orphan_lo,
            CASE
                WHEN c.observed_status = 'below_threshold' THEN coalesce(c.rule_id, 'unknown')
            END AS rule_key,
            CASE
                WHEN c.observed_status = 'below_threshold' THEN NULL
                ELSE c.log_type
            END AS finding_log_type,
            CASE
                WHEN c.observed_status = 'below_threshold' THEN NULL
                ELSE c.decoder_name
            END AS finding_decoder,
            -- Reported for the same reason the decoder is: a below_threshold
            -- finding spans whatever sources its rule fired on, so claiming
            -- one of their locations would be arbitrary.
            CASE
                WHEN c.observed_status = 'below_threshold' THEN NULL
                ELSE c.location
            END AS finding_location
        FROM classified_events c
        LEFT JOIN event_logs el ON el.event_id = c.event_id
        LEFT JOIN log_templates lt ON lt.log_hi = el.log_hi AND lt.log_lo = el.log_lo
        WHERE c.observed_status <> 'at_or_above_threshold'
          AND c.full_log IS NOT NULL
          AND c.full_log <> ''
        """
    )

    connection.execute(
        """
        CREATE TEMP VIEW finding_groups AS
        SELECT
            observed_status,
            finding_log_type,
            template_id,
            orphan_hi,
            orphan_lo,
            rule_key,
            count(*) AS event_count,
            count(DISTINCT agent_id) FILTER (WHERE agent_id IS NOT NULL) AS affected_agents,
            min(event_timestamp) AS first_timestamp,
            max(event_timestamp) AS last_timestamp,
            -- The fields a replay depends on come from the sample's own
            -- event. Aggregating them separately would pick each from
            -- whichever row a parallel scan reached first, so the location
            -- could change between runs and pair the sample with another
            -- event's source -- and the decoder chain consults the location,
            -- so that replay could resolve differently from the event that was
            -- archived. min() over the struct takes the row with the smallest
            -- raw log and breaks ties on the remaining fields, so the choice is
            -- total and deterministic.
            min(
                {
                    'full_log': full_log,
                    'location': finding_location,
                    'decoder': finding_decoder,
                    'rule_id': rule_id,
                    'rule_level': rule_level
                }
            ) AS sample
        FROM finding_events
        GROUP BY observed_status, finding_log_type, template_id, orphan_hi, orphan_lo, rule_key
        """
    )

    # Raw string: the sample normalization below passes regex escapes to
    # DuckDB, they are not Python escapes.
    connection.execute(
        r"""
        CREATE TEMP VIEW findings AS
        SELECT
            -- The key parts are encoded as a JSON array rather than joined with
            -- a delimiter. A log type and a message can both contain any
            -- delimiter, so joining them is not injective: location "a|b" with
            -- message "c" and location "a" with message "b|c" would share one
            -- key and merge two findings into one.
            md5(
                to_json(
                    CASE
                        WHEN observed_status = 'below_threshold' THEN [observed_status, rule_key]
                        ELSE [observed_status, finding_log_type, message_pattern]
                    END
                )
            ) AS finding_key,
            observed_status,
            finding_log_type AS log_type,
            message_pattern,
            event_count,
            affected_agents,
            strftime(first_timestamp, '%Y-%m-%d %H:%M:%S%z') AS first_seen,
            strftime(last_timestamp, '%Y-%m-%d %H:%M:%S%z') AS last_seen,
            sample.decoder AS observed_decoder,
            sample.location AS observed_location,
            sample.rule_id AS observed_rule_id,
            sample.rule_level AS observed_rule_level,
            -- The representative is still the deterministic min() of the raw
            -- logs; only its line breaks are collapsed. A sample exists to be
            -- replayed through wazuh-logtest, which reads one log per line, so
            -- a multi-line log emitted verbatim would be replayed as several
            -- unrelated logs -- the first tested against the wrong decoder and
            -- the rest as fragments no rule was ever written for.
            trim(regexp_replace(sample.full_log, '[\r\n]+', ' ', 'g')) AS sample_log
        FROM (
            SELECT
                g.*,
                CASE
                    WHEN g.observed_status = 'below_threshold' THEN concat('rule:', g.rule_key)
                    ELSE coalesce(t.log_template, preprocess_log(g.sample.full_log))
                END AS message_pattern
            FROM finding_groups g
            LEFT JOIN templates t ON t.template_id = g.template_id
        )
        """
    )
