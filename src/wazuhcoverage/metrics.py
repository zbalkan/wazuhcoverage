"""Derived reliability and efficiency metrics."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Optional

from wazuhcoverage.models import ArchiveAnalysis, Verification

_REPLAYABLE_STATUSES = ("no_decoder", "no_alerting_rule")
_BELOW_THRESHOLD_STATES = ("suppressed", "below_threshold")


@dataclass(frozen=True)
class MetricValue:
    """One measured ratio with its auditable numerator and denominator."""

    count: Optional[int]
    denominator: Optional[int]
    ratio: Optional[float]
    available: bool = True


@dataclass(frozen=True)
class LogTypeMetrics:
    """Reliability and efficiency measurements for one effective log type."""

    log_type: Optional[str]
    event_count: int
    decoder_failure_rate: MetricValue
    decoder_failure_contribution: MetricValue
    uncovered_rate: MetricValue
    uncovered_contribution: MetricValue
    below_threshold_rate: MetricValue
    below_threshold_contribution: MetricValue


@dataclass(frozen=True)
class MetricSnapshot:
    """Derived metrics for one archive analysis and optional replay result."""

    total_events: int
    malformed_lines: int
    malformed_rate: MetricValue
    decoder_failure_rate: MetricValue
    uncovered_rate: MetricValue
    below_threshold_rate: MetricValue
    uncertainty_rate: MetricValue
    log_types: tuple[LogTypeMetrics, ...]


def calculate_metrics(
    analysis: ArchiveAnalysis,
    verifications: Sequence[Verification] = (),
) -> MetricSnapshot:
    """Calculate metrics without rereading the archive or inferring analyst intent.

    Replay verdicts replace the observed status of the finding they represent,
    using the same whole-archive adjustment as the human-readable report.
    Uncovered coverage is unavailable until every ambiguous replay target is
    resolved, unless the archive contains no rule-less decoded events at all.
    """

    statuses, log_types = resolve_effective_counts(analysis, verifications)
    replay_complete = _replay_complete(analysis, verifications)

    malformed = _metric(
        analysis.malformed_lines,
        analysis.total_events + analysis.malformed_lines,
    )
    decoder_failures = statuses.get("no_decoder", 0)
    decoder_failure = _metric(decoder_failures, analysis.total_events)

    below_threshold_count = sum(statuses.get(state, 0) for state in _BELOW_THRESHOLD_STATES)
    below_threshold = _metric(below_threshold_count, analysis.total_events)

    uncertainty_count = statuses.get("no_alerting_rule", 0) + statuses.get("unverified", 0)
    uncertainty = _metric(uncertainty_count, analysis.total_events)

    if replay_complete:
        uncovered_count = statuses.get("uncovered", 0)
        uncovered = _metric(uncovered_count, analysis.total_events - decoder_failures)
    else:
        uncovered = _unavailable_metric()

    per_log_type = tuple(
        _log_type_metrics(
            log_type,
            counts,
            decoder_failures=decoder_failures,
            uncovered_total=statuses.get("uncovered", 0),
            below_threshold_total=below_threshold_count,
            uncovered_available=uncovered.available,
        )
        for log_type, counts in sorted(
            log_types.items(),
            key=lambda item: (-sum(item[1].values()), item[0] or ""),
        )
        if sum(counts.values())
    )

    return MetricSnapshot(
        total_events=analysis.total_events,
        malformed_lines=analysis.malformed_lines,
        malformed_rate=malformed,
        decoder_failure_rate=decoder_failure,
        uncovered_rate=uncovered,
        below_threshold_rate=below_threshold,
        uncertainty_rate=uncertainty,
        log_types=per_log_type,
    )


def resolve_effective_counts(
    analysis: ArchiveAnalysis,
    verifications: Sequence[Verification] = (),
) -> tuple[dict[str, int], dict[Optional[str], dict[str, int]]]:
    """Return whole-archive status and log-type counts after replay replacements."""

    statuses = {item.status: item.event_count for item in analysis.status_counts}
    log_types: dict[Optional[str], dict[str, int]] = {}
    for item in analysis.log_type_counts:
        counts = log_types.setdefault(item.log_type, {})
        counts[item.status] = counts.get(item.status, 0) + item.event_count

    by_key = {item.finding_key: item for item in verifications}
    if not by_key:
        return statuses, log_types

    for finding in analysis.findings:
        verification = by_key.get(finding.finding_key)
        if verification is None:
            continue

        old = finding.observed_status
        new = verification.effective_state
        count = finding.event_count

        statuses[old] = statuses.get(old, 0) - count
        statuses[new] = statuses.get(new, 0) + count

        old_counts = log_types.setdefault(finding.log_type, {})
        old_counts[old] = old_counts.get(old, 0) - count

        effective_log_type = (
            (verification.decoder or finding.log_type)
            if new != "unverified"
            else finding.log_type
        )
        new_counts = log_types.setdefault(effective_log_type, {})
        new_counts[new] = new_counts.get(new, 0) + count

    return statuses, log_types


def metrics_to_dict(snapshot: MetricSnapshot) -> dict[str, Any]:
    """Return a JSON-serializable representation with ratios kept as fractions."""

    return {
        "total_events": snapshot.total_events,
        "malformed_lines": snapshot.malformed_lines,
        "malformed": _metric_dict(snapshot.malformed_rate),
        "decoder_failure": _metric_dict(snapshot.decoder_failure_rate),
        "uncovered": _metric_dict(snapshot.uncovered_rate),
        "below_threshold": _metric_dict(snapshot.below_threshold_rate),
        "uncertainty": _metric_dict(snapshot.uncertainty_rate),
        "log_types": [
            {
                "log_type": item.log_type,
                "event_count": item.event_count,
                "decoder_failure": _metric_dict(item.decoder_failure_rate),
                "decoder_failure_contribution": _metric_dict(item.decoder_failure_contribution),
                "uncovered": _metric_dict(item.uncovered_rate),
                "uncovered_contribution": _metric_dict(item.uncovered_contribution),
                "below_threshold": _metric_dict(item.below_threshold_rate),
                "below_threshold_contribution": _metric_dict(item.below_threshold_contribution),
            }
            for item in snapshot.log_types
        ],
    }


def _replay_complete(
    analysis: ArchiveAnalysis,
    verifications: Sequence[Verification],
) -> bool:
    """Say whether replay-dependent uncovered counts are complete enough to expose."""

    observed = {item.status: item.event_count for item in analysis.status_counts}
    no_alerting_rule = observed.get("no_alerting_rule", 0)

    # With no replay, zero rule-less decoded events is already a complete
    # statement: every decoded event has an observed rule outcome.
    if not verifications:
        has_ruleless_finding = any(
            finding.observed_status == "no_alerting_rule" for finding in analysis.findings
        )
        return no_alerting_rule == 0 and not has_ruleless_finding

    required_events = sum(observed.get(status, 0) for status in _REPLAYABLE_STATUSES)
    targets = [
        finding
        for finding in analysis.findings
        if finding.observed_status in _REPLAYABLE_STATUSES
    ]
    if sum(finding.event_count for finding in targets) != required_events:
        return False

    verified = {item.finding_key for item in verifications}
    return all(finding.finding_key in verified for finding in targets)


def _log_type_metrics(
    log_type: Optional[str],
    counts: dict[str, int],
    *,
    decoder_failures: int,
    uncovered_total: int,
    below_threshold_total: int,
    uncovered_available: bool,
) -> LogTypeMetrics:
    event_count = sum(counts.values())
    decoder_failure_count = counts.get("no_decoder", 0)
    below_threshold_count = sum(counts.get(state, 0) for state in _BELOW_THRESHOLD_STATES)

    if uncovered_available:
        uncovered_count = counts.get("uncovered", 0)
        uncovered_rate = _metric(uncovered_count, event_count - decoder_failure_count)
        uncovered_contribution = _metric(uncovered_count, uncovered_total)
    else:
        uncovered_rate = _unavailable_metric()
        uncovered_contribution = _unavailable_metric()

    return LogTypeMetrics(
        log_type=log_type,
        event_count=event_count,
        decoder_failure_rate=_metric(decoder_failure_count, event_count),
        decoder_failure_contribution=_metric(decoder_failure_count, decoder_failures),
        uncovered_rate=uncovered_rate,
        uncovered_contribution=uncovered_contribution,
        below_threshold_rate=_metric(below_threshold_count, event_count),
        below_threshold_contribution=_metric(below_threshold_count, below_threshold_total),
    )


def _metric(count: int, denominator: int) -> MetricValue:
    if denominator < 0:
        raise ValueError("metric denominator cannot be negative")
    return MetricValue(
        count=count,
        denominator=denominator,
        ratio=None if denominator == 0 else count / denominator,
        available=True,
    )


def _unavailable_metric() -> MetricValue:
    return MetricValue(count=None, denominator=None, ratio=None, available=False)


def _metric_dict(metric: MetricValue) -> dict[str, Any]:
    return {
        "count": metric.count,
        "denominator": metric.denominator,
        "rate": metric.ratio,
        "available": metric.available,
    }
