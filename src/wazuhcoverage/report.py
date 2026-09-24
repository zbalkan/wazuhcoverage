"""Text rendering for CLI output."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Optional

from wazuhcoverage.models import DROPPED_STATUSES, EFFECTIVE_STATES, PROCESSED_STATUS, ArchiveAnalysis, Verification

_PROCESSED_LABEL = "Processed"
_DROPPED_LABEL = "Dropped"
# The processed row names its bucket inline. The dropped rows name theirs by
# being the bucket, so this is the only row that would otherwise leave a reader
# unable to map the report back to the observed_status values the API returns.
_PROCESSED_OUTCOME = f"{_PROCESSED_LABEL} ({PROCESSED_STATUS})"
_OUTCOME_WIDTH = max(24, len(_PROCESSED_OUTCOME) + 2)
_LOG_TYPE_WIDTH = 32
_COUNT_WIDTH = 14
_PERCENT_WIDTH = 10
_DROPPED_PERCENT_WIDTH = 12
# One column per outcome, then the breakdown of the dropped one. The two
# aggregates come first so a row can be read for coverage alone; the three
# that follow say why the dropped share was dropped and sum back to it.
_LOG_TYPE_COLUMNS = (_PROCESSED_LABEL, _DROPPED_LABEL) + DROPPED_STATUSES
_LOG_TYPE_COLUMN_WIDTHS = {column: max(12, len(column) + 2) for column in _LOG_TYPE_COLUMNS}
# The one bucket whose meaning the archive underdetermines; see
# wazuhcoverage.models.STATUSES for why.
_AMBIGUOUS_STATUS = "no_alerting_rule"
_EFFECTIVE_WIDTH = max(24, max(len(state) for state in EFFECTIVE_STATES) + 2)


def render_report(
    analysis: ArchiveAnalysis,
    verifications: Sequence[Verification] = (),
    *,
    alert_threshold: Optional[int] = None,
    threshold_source: Optional[str] = None,
) -> str:
    """Render a compact human-readable report for one archive.

    The first table splits the archive into the two outcomes that matter --
    processed and dropped -- and breaks the dropped share into the three
    buckets that explain it, ranked by event count. The second pivots the
    status/log-type cells into one row per log type and ranks those rows by
    aggregate event count.

    ``verifications`` are optional wazuh-logtest replays. When present they add
    an effective-coverage table and an ``Effective`` line to each finding they
    cover, and they suppress the note about what an absent rule cannot prove,
    because a replay has since answered that question.
    """

    lines: list[str] = [f"Archive: {analysis.path}"]
    if alert_threshold is not None:
        source = f" ({threshold_source})" if threshold_source else ""
        lines.append(f"Alert threshold: {alert_threshold}{source}")

    lines.extend(
        [
            f"Total events: {analysis.total_events:,}",
            f"Malformed lines skipped: {analysis.malformed_lines:,}",
            "",
            "Outcome",
            "-------",
            _outcome_row("Outcome", "Events", "% total", "% dropped"),
        ]
    )

    lines.extend(_outcome_table(analysis))

    lines.extend(
        [
            "",
            "Log types",
            "---------",
            _log_type_row(
                "Log type",
                "Events",
                "% total",
                {column: column for column in _LOG_TYPE_COLUMNS},
            ),
        ]
    )

    for log_type, event_count, status_counts in _summarize_log_types(analysis):
        lines.append(
            _log_type_row(
                log_type or "-",
                f"{event_count:,}",
                _percent(_percentage(event_count, analysis.total_events)),
                _log_type_cells(status_counts),
            )
        )

    by_key = {item.finding_key: item for item in verifications}
    lines.extend(_effective_table(analysis, by_key))

    lines.extend(["", f"Findings: {len(analysis.findings):,}", ""])
    if not by_key:
        lines.extend(_no_alerting_rule_note(analysis))

    for index, finding in enumerate(analysis.findings, start=1):
        verification = by_key.get(finding.finding_key)
        lines.extend(
            [
                f"[{index}] {finding.observed_status} | {finding.log_type or '-'}",
                f"    Events: {finding.event_count:,}",
                f"    Affected agents: {finding.affected_agents:,}",
                f"    First seen: {finding.first_seen or '-'}",
                f"    Last seen: {finding.last_seen or '-'}",
                f"    Decoder: {finding.observed_decoder or '-'}",
                f"    Rule: {finding.observed_rule_id or '-'}",
                f"    Level: {finding.observed_rule_level if finding.observed_rule_level is not None else '-'}",
                f"    Pattern: {_single_row(finding.message_pattern)}",
                f"    Sample: {finding.sample_log}",
            ]
        )
        lines.extend(_finding_verdict(verification))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _outcome_table(analysis: ArchiveAnalysis) -> list[str]:
    """Render the archive as two outcomes, with the dropped one broken out.

    Only ``at_or_above_threshold`` reaches an alert, so it is the whole of the
    processed outcome; everything else was dropped somewhere earlier in the
    pipeline. The three dropped buckets are the diagnosis and stay visible
    beneath their total, in the order the analysis ranked them, which is by
    event count with ties keeping the declared bucket order. Every bucket is
    listed even at zero, because an empty bucket is a coverage statement.

    ``% dropped`` sizes a bucket against the dropped events rather than the
    archive. A bucket holding four per cent of an archive that is ninety-five
    per cent covered is most of the remaining problem, and the ``% total``
    column alone hides that.
    """

    by_status = {item.status: item for item in analysis.status_counts}
    processed = by_status[PROCESSED_STATUS].event_count if PROCESSED_STATUS in by_status else 0
    dropped = sum(by_status[status].event_count for status in DROPPED_STATUSES if status in by_status)

    def share(count: int) -> str:
        # An archive that dropped nothing has no shares to report, and a column
        # of 0.00% would read as a measurement rather than an empty set.
        return _percent(_percentage(count, dropped)) if dropped else "-"

    rows = [
        _outcome_row(
            _PROCESSED_OUTCOME,
            f"{processed:,}",
            _percent(_percentage(processed, analysis.total_events)),
            "-",
        ),
        _outcome_row(
            _DROPPED_LABEL,
            f"{dropped:,}",
            _percent(_percentage(dropped, analysis.total_events)),
            share(dropped),
        ),
    ]
    rows.extend(
        _outcome_row(
            f"  {item.status}",
            f"{item.event_count:,}",
            _percent(item.percentage),
            share(item.event_count),
        )
        for item in analysis.status_counts
        if item.status in DROPPED_STATUSES
    )
    return rows


def _log_type_cells(status_counts: dict[str, int]) -> dict[str, str]:
    """Lay one log type's buckets out as the outcome columns of its row."""

    dropped = sum(status_counts.get(status, 0) for status in DROPPED_STATUSES)
    cells = {
        _PROCESSED_LABEL: f"{status_counts.get(PROCESSED_STATUS, 0):,}",
        _DROPPED_LABEL: f"{dropped:,}",
    }
    cells.update({status: f"{status_counts.get(status, 0):,}" for status in DROPPED_STATUSES})
    return cells


def _effective_table(analysis: ArchiveAnalysis, by_key: dict[str, Verification]) -> list[str]:
    """Rank the replayed verdicts by how many events each one accounts for.

    Findings are weighted by ``event_count`` rather than counted, because one
    finding standing for 40,000 events and one standing for three are not the
    same coverage statement. Only replayed findings appear, so the total is the
    events those findings cover and not the archive's.
    """

    if not by_key:
        return []

    events: dict[str, int] = {}
    findings: dict[str, int] = {}
    for finding in analysis.findings:
        verification = by_key.get(finding.finding_key)
        if verification is None:
            continue
        events[verification.effective_state] = events.get(verification.effective_state, 0) + finding.event_count
        findings[verification.effective_state] = findings.get(verification.effective_state, 0) + 1

    covered = sum(events.values())
    rows = [
        "",
        "Effective coverage (wazuh-logtest)",
        "----------------------------------",
        _effective_row("State", "Findings", "Events", "% replayed"),
    ]
    rows.extend(
        _effective_row(
            state,
            f"{findings.get(state, 0):,}",
            f"{events.get(state, 0):,}",
            _percent(_percentage(events.get(state, 0), covered)),
        )
        for state in EFFECTIVE_STATES
        if findings.get(state, 0)
    )
    return rows


def _finding_verdict(verification: Optional[Verification]) -> list[str]:
    """Render one finding's replay result, or nothing when it was not replayed."""

    if verification is None:
        return []

    rule = verification.rule_id or "-"
    level = verification.rule_level if verification.rule_level is not None else "-"
    rows = [f"    Effective: {verification.effective_state} (rule {rule}, level {level})"]

    if verification.rule_description:
        rows.append(f"    Matched: {_single_row(verification.rule_description)}")
    if verification.error:
        rows.append(f"    Replay: {_single_row(verification.error)}")
    return rows


def _effective_row(state: str, findings: str, events: str, percentage: str) -> str:
    cells = [
        f"{state:<{_EFFECTIVE_WIDTH}}",
        f"{findings:>12}",
        f"{events:>{_COUNT_WIDTH}}",
        f"{percentage:>12}",
    ]
    return "".join(cells).rstrip()


def _no_alerting_rule_note(analysis: ArchiveAnalysis) -> list[str]:
    """Return the caveat rows for the ``no_alerting_rule`` bucket, if it is used.

    The bucket name is honest but incomplete on its own: the report shows an
    empty Rule and Level for every one of these findings, which reads as "the
    decoder chain dead-ended" when it can equally mean that a level-0 rule
    matched and Wazuh chose not to alert. That difference decides whether a
    finding is a detection gap or a deliberate suppression, and the archive cannot
    settle it, so the report says so where the findings are read rather than
    leaving it to the documentation.

    The rows are emitted only when the bucket holds events, so an archive that
    never hits the ambiguity is not asked to carry a note about it.
    """

    if not any(item.status == _AMBIGUOUS_STATUS and item.event_count for item in analysis.status_counts):
        return []

    return [
        f"Note: a {_AMBIGUOUS_STATUS} event carries no rule in the archive. Wazuh writes that",
        "      same record whether no rule matched, the matching rule was level 0, or a",
        "      rule's ignore window suppressed the match. Replay the sample through",
        "      wazuh-logtest to tell those apart.",
        "",
    ]


def _summarize_log_types(
    analysis: ArchiveAnalysis,
) -> list[tuple[Optional[str], int, dict[str, int]]]:
    """Pivot detailed status/log-type counts into one row per log type."""

    by_log_type: dict[Optional[str], dict[str, int]] = {}
    for item in analysis.log_type_counts:
        status_counts = by_log_type.setdefault(item.log_type, {})
        status_counts[item.status] = status_counts.get(item.status, 0) + item.event_count

    rows = [(log_type, sum(status_counts.values()), status_counts) for log_type, status_counts in by_log_type.items()]
    rows.sort(key=lambda item: (-item[1], item[0] or ""))
    return rows


def _outcome_row(outcome: str, count: str, percentage: str, dropped_share: str) -> str:
    cells = [
        f"{outcome:<{_OUTCOME_WIDTH}}",
        f"{count:>{_COUNT_WIDTH}}",
        f"{percentage:>{_PERCENT_WIDTH}}",
        f"{dropped_share:>{_DROPPED_PERCENT_WIDTH}}",
    ]
    return "".join(cells).rstrip()


def _log_type_row(
    log_type: str,
    count: str,
    percentage: str,
    column_values: dict[str, str],
) -> str:
    """Lay out one log-type summary row without truncating its identifier."""

    cells = [
        f"{log_type:<{_LOG_TYPE_WIDTH}}",
        f"{count:>{_COUNT_WIDTH}}",
        f"{percentage:>{_PERCENT_WIDTH}}",
    ]
    for column in _LOG_TYPE_COLUMNS:
        cells.append(f"{column_values.get(column, ''):>{_LOG_TYPE_COLUMN_WIDTHS[column]}}")
    return "".join(cells).rstrip()


def _percentage(part: int, whole: int) -> float:
    return 0.0 if whole == 0 else 100.0 * part / whole


def _single_row(value: str) -> str:
    """Keep one report field on one line.

    sample_log is already collapsed by the analysis layer because it is
    replayed into logtest. message_pattern is not: it is a grouping key and
    is reported verbatim, so a multi-line log would break the finding block
    across rows here. Collapsing is a rendering concern only and never changes
    the value a consumer reads from the model.
    """

    return " ".join(value.split("\n")).replace("\r", " ").strip()


def _percent(value: float) -> str:
    return f"{value:.2f}%"
