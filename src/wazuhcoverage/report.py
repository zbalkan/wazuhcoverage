"""Text rendering for CLI output."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Dict, List, Tuple  # noqa: UP035

from wazuhcoverage.metrics import MetricSnapshot, MetricValue, calculate_metrics, resolve_effective_counts
from wazuhcoverage.models import (
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
from wazuhcoverage.wazuh_regex import suggest_for_finding

_PROCESSED_LABEL = "Processed"
# The processed row names its bucket inline. The dropped rows name theirs by
# being the bucket, so this is the only row that would otherwise leave a reader
# unable to map the report back to the observed_status values the API returns.
_PROCESSED_OUTCOME = f"{_PROCESSED_LABEL} ({PROCESSED_STATUS})"
_OUTCOME_WIDTH = max(24, len(_PROCESSED_OUTCOME) + 2)
_LOG_TYPE_WIDTH = 32
_COUNT_WIDTH = 14
_PERCENT_WIDTH = 10
_DROPPED_PERCENT_WIDTH = 12
_EFFECTIVE_WIDTH = max(24, max(len(state) for state in EFFECTIVE_STATES) + 2)
_RESOLVED_LOG_WIDTHS: Dict[str, int] = {column: max(12, len(column) + 2) for column in RESOLVED_OUTCOMES}  # noqa: UP006


def render_report(
    analysis: ArchiveAnalysis,
    verifications: Sequence[Verification] = (),
    *,
    alert_threshold: int | None = None,
    threshold_source: str | None = None,
) -> str:
    """Render a compact human-readable report for one archive.

    The full-archive tables use replay verdicts for the findings they cover and
    archive observations for the remainder. A matched rule below
    the alert threshold is Suppressed, while a confirmed unmatched or undecoded
    event is Dropped. Ambiguous or failed replays remain Unresolved.
    """

    lines: List[str] = [f"Archive: {analysis.path}"]  # noqa: UP006
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
    status_counts, log_type_counts = resolve_effective_counts(analysis, verifications)
    lines.extend(_resolved_outcome_table(status_counts, analysis.total_events))
    lines.extend(_resolved_log_type_table(log_type_counts, analysis.total_events))

    metrics = calculate_metrics(analysis, verifications)
    lines.extend(_metrics_table(metrics))
    lines.extend(_metric_contributors(metrics))
    lines.extend(_effective_table(analysis, by_key))

    lines.extend(["", f"Findings: {len(analysis.findings):,}", ""])

    grouped: Dict[str, List[Tuple[Finding, Verification | None]]] = {group: [] for group in FINDING_GROUPS}  # noqa: UP006
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


def _finding_rows(index: int, finding: Finding, verification: Verification | None) -> List[str]:  # noqa: UP006
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
    suggestion = suggest_for_finding(finding, verification)
    if suggestion is not None:
        heading, text = suggestion
        rows.append(f"    {heading}: {_single_row(text)}")
    rows.append(f"    Sample: {finding.sample_log}")
    if presented.rule_description:
        rows.append(f"    Matched: {_single_row(presented.rule_description)}")
    if presented.replay_error:
        rows.append(f"    Replay: {_single_row(presented.replay_error)}")
    return rows


def _resolved_outcome_table(statuses: Dict[str, int], total: int) -> List[str]:  # noqa: UP006
    """Keep whole-archive totals while separating matched suppression from loss."""

    outcomes = outcome_counts(statuses)
    rows = [
        "",
        "Outcome",
        "-------",
        _outcome_row("Outcome", "Events", "% total", "% dropped"),
    ]
    for outcome, count in outcomes.items():
        rows.append(
            _outcome_row(
                outcome,
                f"{count:,}",
                _percent(_percentage(count, total)),
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


def _resolved_log_type_table(log_types: Dict[str | None, Dict[str, int]], total: int) -> List[str]:  # noqa: UP006
    """Include every log type, including those without replayed findings."""

    rows = [
        "",
        "Log types",
        "---------",
        _resolved_log_type_row("Log type", "Events", "% total", {name: name for name in RESOLVED_OUTCOMES}),
    ]
    for log_type, statuses in sorted(log_types.items(), key=lambda item: (-sum(item[1].values()), item[0] or "")):
        counts = outcome_counts(statuses)
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


def _resolved_log_type_row(log_type: str, count: str, percentage: str, counts: Dict[str, str]) -> str:  # noqa: UP006
    cells = [
        f"{log_type:<{_LOG_TYPE_WIDTH}}",
        f"{count:>{_COUNT_WIDTH}}",
        f"{percentage:>{_PERCENT_WIDTH}}",
    ]
    cells.extend(f"{counts[name]:>{_RESOLVED_LOG_WIDTHS[name]}}" for name in RESOLVED_OUTCOMES)
    return "".join(cells).rstrip()


def _metrics_table(snapshot: MetricSnapshot) -> List[str]:  # noqa: UP006
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


def _metric_contributors(snapshot: MetricSnapshot) -> List[str]:  # noqa: UP006
    """Show the largest log-type contributors while preserving local severity."""

    groups = (
        ("Decoder failure", "decoder_failure_rate", "decoder_failure_contribution"),
        ("Uncovered", "uncovered_rate", "uncovered_contribution"),
        ("Below threshold", "below_threshold_rate", "below_threshold_contribution"),
    )
    rows: List[str] = []  # noqa: UP006

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


def _effective_table(analysis: ArchiveAnalysis, by_key: Dict[str, Verification]) -> List[str]:  # noqa: UP006
    """Rank the replayed verdicts by how many events each one accounts for.

    Findings are weighted by ``event_count`` rather than counted, because one
    finding standing for 40,000 events and one standing for three are not the
    same coverage statement. Only replayed findings appear, so the total is the
    events those findings cover and not the archive's.
    """

    if not by_key:
        return []

    events: Dict[str, int] = {}  # noqa: UP006
    findings: Dict[str, int] = {}  # noqa: UP006
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


def _outcome_row(outcome: str, count: str, percentage: str, dropped_share: str) -> str:
    cells = [
        f"{outcome:<{_OUTCOME_WIDTH}}",
        f"{count:>{_COUNT_WIDTH}}",
        f"{percentage:>{_PERCENT_WIDTH}}",
        f"{dropped_share:>{_DROPPED_PERCENT_WIDTH}}",
    ]
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
