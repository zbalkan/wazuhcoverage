"""Text rendering for CLI output."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, Optional

from wazuhcoverage.metrics import MetricSnapshot, MetricValue, calculate_metrics, resolve_effective_counts
from wazuhcoverage.models import (
    DROPPED_STATUSES,
    EFFECTIVE_STATES,
    PROCESSED_STATUS,
    ArchiveAnalysis,
    Finding,
    Verification,
)
from wazuhcoverage.presentation import (
    FINDING_GROUPS,
    RESOLVED_OUTCOMES,
    finding_group,
    outcome_counts,
    present_finding,
)
from wazuhcoverage.wazuh_regex import suggest_wazuh_regex

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
_LOG_TYPE_COLUMNS: tuple[Literal['Processed'], Literal['Dropped'], str, ...] = (_PROCESSED_LABEL, _DROPPED_LABEL) + DROPPED_STATUSES # type: ignore
_LOG_TYPE_COLUMN_WIDTHS = {column: max(12, len(column) + 2) for column in _LOG_TYPE_COLUMNS}
# The one bucket whose meaning the archive underdetermines; see
# wazuhcoverage.models.STATUSES for why.
_AMBIGUOUS_STATUS = "no_alerting_rule"
_EFFECTIVE_WIDTH = max(24, max(len(state) for state in EFFECTIVE_STATES) + 2)
_RESOLVED_LOG_WIDTHS: dict[str, int] = {column: max(12, len(column) + 2) for column in RESOLVED_OUTCOMES}


def render_report(
    analysis: ArchiveAnalysis,
    verifications: Sequence[Verification] = (),
    *,
    alert_threshold: Optional[int] = None,
    threshold_source: Optional[str] = None,
) -> str:
    """Render a compact human-readable report for one archive.

    Without replays, the outcome and log-type tables show archive observations.
    With replays, the full-archive tables use replay verdicts for the findings
    they cover and archive observations for the remainder. A matched rule below
    the alert threshold is Suppressed, while a confirmed unmatched or undecoded
    event is Dropped. Ambiguous or failed replays remain Unresolved.
    """

    lines: list[str] = [f"Archive: {analysis.path}"]
    by_key = {item.finding_key: item for item in verifications}
    if alert_threshold is not None:
        source = f" ({threshold_source})" if threshold_source else ""
        lines.append(f"Alert threshold: {alert_threshold}{source}")

    lines.extend(
        [
            f"Total events: {analysis.total_events:,}",
            f"Malformed lines skipped: {analysis.malformed_lines:,}",
        ]
    )
    if by_key:
        status_counts, log_type_counts = resolve_effective_counts(analysis, verifications)
        lines.extend(_resolved_outcome_table(status_counts, analysis.total_events))
        lines.extend(_resolved_log_type_table(log_type_counts, analysis.total_events))
    else:
        lines.extend(["", "Outcome", "-------", _outcome_row("Outcome", "Events", "% total", "% dropped")])
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

    metrics = calculate_metrics(analysis, verifications)
    lines.extend(_metrics_table(metrics))
    lines.extend(_metric_contributors(metrics))
    lines.extend(_effective_table(analysis, by_key))

    lines.extend(["", f"Findings: {len(analysis.findings):,}", ""])
    if not by_key:
        lines.extend(_no_alerting_rule_note(analysis))

    grouped: dict[str, list[tuple[Finding, Optional[Verification]]]] = {
        group: [] for group in FINDING_GROUPS
    }
    for finding in analysis.findings:
        verification = by_key.get(finding.finding_key)
        status = verification.effective_state if verification is not None else finding.observed_status
        grouped[finding_group(status)].append((finding, verification))

    for group in FINDING_GROUPS:
        entries = grouped[group]
        if not entries:
            continue
        entries.sort(key=lambda item: (-item[0].event_count, item[0].finding_key))
        lines.extend([group, "-" * len(group)])
        for index, (finding, verification) in enumerate(entries, start=1):
            lines.extend(_finding_rows(index, finding, verification))
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _finding_rows(index: int, finding: Finding, verification: Optional[Verification]) -> list[str]:
    """Render a finding within its effective outcome group."""

    presented = present_finding(finding, verification)
    rows = [
        f"[{index}] {presented.status} | {presented.log_type or '-'}",
        f"    Events: {finding.event_count:,}",
        f"    Affected agents: {finding.affected_agents:,}",
        f"    First seen: {finding.first_seen or '-'}",
        f"    Last seen: {finding.last_seen or '-'}",
        f"    Decoder: {presented.decoder or '-'}",
    ]
    if presented.rule_id is not None:
        rows.append(f"    Rule: {presented.rule_id}")
    if presented.rule_level is not None:
        rows.append(f"    Level: {presented.rule_level}")
    pattern = _single_row(finding.message_pattern)
    rows.append(f"    Pattern: {pattern}")
    if finding.observed_status in ("no_decoder", "no_alerting_rule"):
        regex_type, regex = suggest_wazuh_regex(pattern)
        rows.append(f"    Suggested Wazuh regex ({regex_type}): {regex}")
    rows.append(f"    Sample: {finding.sample_log}")
    if presented.rule_description:
        rows.append(f"    Matched: {_single_row(presented.rule_description)}")
    if presented.replay_error:
        rows.append(f"    Replay: {_single_row(presented.replay_error)}")
    return rows


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


def _resolved_outcome_table(statuses: dict[str, int], total: int) -> list[str]:
    """Keep whole-archive totals while separating matched suppression from loss."""

    outcomes = outcome_counts(statuses, resolved=True)
    rows = [
        "",
        "Outcome (with replay)",
        "---------------------",
        _outcome_row("Outcome", "Events", "% total", "% dropped"),
    ]
    for outcome, count in outcomes.items():
        rows.append(
            _outcome_row(
                outcome, f"{count:,}", _percent(_percentage(count, total)),
                _percent(100.0) if outcome == "Dropped" and count else "-",
            )
        )
        if outcome in ("Suppressed", "Dropped"):
            states = ("suppressed", "below_threshold") if outcome == "Suppressed" else ("no_decoder", "uncovered")
            rows.extend(
                _outcome_row(
                    f"  {state}",
                    f"{statuses.get(state, 0):,}",
                    _percent(_percentage(statuses.get(state, 0), total)),
                    _percent(_percentage(statuses.get(state, 0), count)) if outcome == "Dropped" and count else "-",
                )
                for state in states
            )
    return rows


def _resolved_log_type_table(log_types: dict[Optional[str], dict[str, int]], total: int) -> list[str]:
    """Include every log type, including those without replayed findings."""

    rows = [
        "",
        "Log types (with replay)",
        "-----------------------",
        _resolved_log_type_row("Log type", "Events", "% total", {name: name for name in RESOLVED_OUTCOMES}),
    ]
    for log_type, statuses in sorted(log_types.items(), key=lambda item: (-sum(item[1].values()), item[0] or "")):
        counts = outcome_counts(statuses, resolved=True)
        event_count = sum(counts.values())
        if not event_count:
            continue
        rows.append(
            _resolved_log_type_row(
                log_type or "-",
                f"{event_count:,}",
                _percent(_percentage(event_count, total)),
                {name: f"{counts[name]:,}" for name in RESOLVED_OUTCOMES},
            )
        )
    return rows


def _resolved_log_type_row(log_type: str, count: str, percentage: str, counts: dict[str, str]) -> str:
    cells = [
        f"{log_type:<{_LOG_TYPE_WIDTH}}",
        f"{count:>{_COUNT_WIDTH}}",
        f"{percentage:>{_PERCENT_WIDTH}}",
    ]
    cells.extend(f"{counts[name]:>{_RESOLVED_LOG_WIDTHS[name]}}" for name in RESOLVED_OUTCOMES)
    return "".join(cells).rstrip()


def _log_type_cells(status_counts: dict[str, int]) -> dict[str, str]:
    """Lay one log type's buckets out as the outcome columns of its row."""

    dropped = sum(status_counts.get(status, 0) for status in DROPPED_STATUSES)
    cells = {
        _PROCESSED_LABEL: f"{status_counts.get(PROCESSED_STATUS, 0):,}",
        _DROPPED_LABEL: f"{dropped:,}",
    }
    cells.update({status: f"{status_counts.get(status, 0):,}" for status in DROPPED_STATUSES})
    return cells


def _metrics_table(snapshot: MetricSnapshot) -> list[str]:
    """Render the five primary metrics with their numerator and denominator."""

    rows = [
        "",
        "Metrics",
        "-------",
        _metric_row("Metric", "Count / denominator", "Rate"),
        _metric_value_row("Malformed input", snapshot.malformed_rate),
        _metric_value_row("Decoder failure", snapshot.decoder_failure_rate),
        _metric_value_row("Uncovered", snapshot.uncovered_rate),
        _metric_value_row("Below threshold", snapshot.below_threshold_rate),
        _metric_value_row("Unresolved", snapshot.uncertainty_rate),
    ]
    return rows


def _metric_contributors(snapshot: MetricSnapshot) -> list[str]:
    """Show the largest log-type contributors while preserving local severity."""

    groups = (
        ("Decoder failure", "decoder_failure_rate", "decoder_failure_contribution"),
        ("Uncovered", "uncovered_rate", "uncovered_contribution"),
        ("Below threshold", "below_threshold_rate", "below_threshold_contribution"),
    )
    rows: list[str] = []

    for label, local_name, contribution_name in groups:
        candidates = []
        for item in snapshot.log_types:
            local = getattr(item, local_name)
            contribution = getattr(item, contribution_name)
            if (
                not local.available
                or local.count is None
                or local.count == 0
                or not contribution.available
                or contribution.ratio is None
            ):
                continue
            candidates.append((item, local, contribution))

        candidates.sort(
            key=lambda entry: (
                -(entry[2].ratio or 0.0),
                -(entry[1].count or 0),
                entry[0].log_type or "",
            )
        )
        if not candidates:
            continue

        if not rows:
            rows.extend(["", "Largest metric contributors", "---------------------------"])
        rows.append(label)
        for item, local, contribution in candidates[:3]:
            local_rate = "n/a" if local.ratio is None else _ratio_percent(local.ratio)
            contribution_rate = _ratio_percent(contribution.ratio)
            rows.append(
                f"  {item.log_type or '-'}: {local.count:,} events | "
                f"local {local_rate} | contribution {contribution_rate}"
            )

    return rows


def _metric_value_row(label: str, metric: MetricValue) -> str:
    if not metric.available:
        return f"{label:<24}unavailable without complete replay"
    if metric.count is None or metric.denominator is None:
        return f"{label:<24}unavailable"

    count = f"{metric.count:,} / {metric.denominator:,}"
    rate = "n/a" if metric.ratio is None else _ratio_percent(metric.ratio)
    return _metric_row(label, count, rate)


def _metric_row(label: str, count: str, rate: str) -> str:
    return f"{label:<24}{count:>24}{rate:>12}".rstrip()


def _ratio_percent(value: float) -> str:
    return _percent(value * 100.0)


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
