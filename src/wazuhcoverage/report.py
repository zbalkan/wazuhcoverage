"""Text rendering for CLI output."""

from __future__ import annotations

from typing import Optional

from wazuhcoverage.models import STATUSES, ArchiveAnalysis

_STATUS_WIDTH = 24
_LOG_TYPE_WIDTH = 32
_COUNT_WIDTH = 14
_PERCENT_WIDTH = 10
_STATUS_COUNT_WIDTHS = {status: max(12, len(status) + 2) for status in STATUSES}


def render_report(analysis: ArchiveAnalysis) -> str:
    """Render a compact human-readable report for one archive.

    The first table ranks status buckets by event count. The second pivots the
    status/log-type cells into one row per log type and ranks those rows by
    aggregate event count.
    """

    lines: list[str] = [
        f"Archive: {analysis.path}",
        f"Total events: {analysis.total_events:,}",
        f"Malformed lines skipped: {analysis.malformed_lines:,}",
        "",
        "Status",
        "------",
        _status_row("Status", "Events", "% total"),
    ]

    for status in analysis.status_counts:
        lines.append(
            _status_row(
                status.status,
                f"{status.event_count:,}",
                _percent(status.percentage),
            )
        )

    lines.extend(
        [
            "",
            "Log types",
            "---------",
            _log_type_row(
                "Log type",
                "Events",
                "% total",
                {status: status for status in STATUSES},
            ),
        ]
    )

    for log_type, event_count, status_counts in _summarize_log_types(analysis):
        lines.append(
            _log_type_row(
                log_type or "-",
                f"{event_count:,}",
                _percent(_percentage(event_count, analysis.total_events)),
                {status: f"{status_counts.get(status, 0):,}" for status in STATUSES},
            )
        )

    lines.extend(["", f"Findings: {len(analysis.findings):,}", ""])

    for index, finding in enumerate(analysis.findings, start=1):
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
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


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


def _status_row(status: str, count: str, percentage: str) -> str:
    cells = [
        f"{status:<{_STATUS_WIDTH}}",
        f"{count:>{_COUNT_WIDTH}}",
        f"{percentage:>{_PERCENT_WIDTH}}",
    ]
    return "".join(cells).rstrip()


def _log_type_row(
    log_type: str,
    count: str,
    percentage: str,
    status_values: dict[str, str],
) -> str:
    """Lay out one log-type summary row without truncating its identifier."""

    cells = [
        f"{log_type:<{_LOG_TYPE_WIDTH}}",
        f"{count:>{_COUNT_WIDTH}}",
        f"{percentage:>{_PERCENT_WIDTH}}",
    ]
    for status in STATUSES:
        cells.append(f"{status_values.get(status, ''):>{_STATUS_COUNT_WIDTHS[status]}}")
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
