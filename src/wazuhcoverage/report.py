"""Text rendering for CLI output."""

from __future__ import annotations

from typing import Optional

from wazuhcoverage.models import ArchiveAnalysis

_STATUS_WIDTH = 24
_LOG_TYPE_WIDTH = 32
_COUNT_WIDTH = 14
_PERCENT_WIDTH = 10


def render_report(analysis: ArchiveAnalysis) -> str:
    """Render a compact human-readable report for one archive.

    Both tables are ordered by event count, descending. Percentages are shares
    of ``total_events``, which excludes malformed lines; ``% status`` is instead
    the share of the row's own status bucket.
    """

    lines: list[str] = [
        f"Archive: {analysis.path}",
        f"Total events: {analysis.total_events:,}",
        f"Malformed lines skipped: {analysis.malformed_lines:,}",
        f"Pattern source: {'drain3 template mining' if analysis.template_mining else 'regex normalization'}",
        "",
        "Status",
        "------",
        _row("Status", None, "Events", "% total", None),
    ]

    for status in analysis.status_counts:
        lines.append(
            _row(
                status.status,
                None,
                f"{status.event_count:,}",
                _percent(status.percentage),
                None,
            )
        )

    lines.extend(
        [
            "",
            "Log types",
            "---------",
            _row("Status", "Log type", "Events", "% total", "% status"),
        ]
    )

    for log_type in analysis.log_type_counts:
        lines.append(
            _row(
                log_type.status,
                log_type.log_type or "-",
                f"{log_type.event_count:,}",
                _percent(log_type.percentage),
                _percent(log_type.status_percentage),
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


def _row(
    status: str,
    log_type: Optional[str],
    count: str,
    percentage: str,
    status_percentage: Optional[str],
) -> str:
    """Lay out one table row. Over-long labels push the columns rather than
    being truncated: a decoder or location name is identifying information, and
    silently cutting it would make two different sources read as one."""

    cells = [f"{status:<{_STATUS_WIDTH}}"]
    if log_type is not None:
        cells.append(f"{log_type:<{_LOG_TYPE_WIDTH}}")
    cells.append(f"{count:>{_COUNT_WIDTH}}")
    cells.append(f"{percentage:>{_PERCENT_WIDTH}}")
    if status_percentage is not None:
        cells.append(f"{status_percentage:>{_PERCENT_WIDTH}}")
    return "".join(cells).rstrip()


def _single_row(value: str) -> str:
    """Keep one report field on one line.

    ``sample_log`` is already collapsed by the analysis layer because it is
    replayed into logtest. ``message_pattern`` is not: it is a grouping key and
    is reported verbatim, so a multi-line log would break the finding block
    across rows here. Collapsing is a rendering concern only and never changes
    the value a consumer reads from the model.
    """

    return " ".join(value.split("\n")).replace("\r", " ").strip()


def _percent(value: float) -> str:
    return f"{value:.2f}%"
