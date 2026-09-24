from __future__ import annotations

from pathlib import Path
from typing import Optional

import pytest

from wazuhcoverage.metrics import calculate_metrics, metrics_to_dict
from wazuhcoverage.models import (
    ArchiveAnalysis,
    Finding,
    LogTypeCount,
    StatusCount,
    Verification,
)


def _finding(key: str, status: str, log_type: str, count: int) -> Finding:
    return Finding(
        finding_key=key,
        observed_status=status,
        log_type=log_type,
        message_pattern=key,
        event_count=count,
        affected_agents=1,
        first_seen=None,
        last_seen=None,
        observed_decoder=log_type if status != "no_decoder" else None,
        observed_location="syslog",
        observed_rule_id=None,
        observed_rule_level=None,
        sample_log=key,
    )


def _verification(
    key: str,
    state: str,
    *,
    decoder: Optional[str] = None,
    level: Optional[int] = None,
) -> Verification:
    return Verification(
        finding_key=key,
        effective_state=state,
        logtest_status="RuleMatch" if level is not None else "NoRule",
        decoder=decoder,
        rule_id="1" if level is not None else None,
        rule_level=level,
        rule_description=None,
        rule_groups=(),
        error="replay failed" if state == "unverified" else None,
    )


def _analysis() -> ArchiveAnalysis:
    return ArchiveAnalysis(
        path=Path("/archives/a.json"),
        total_events=1000,
        malformed_lines=100,
        status_counts=(
            StatusCount("at_or_above_threshold", 430, 43.0),
            StatusCount("below_threshold", 300, 30.0),
            StatusCount("no_alerting_rule", 170, 17.0),
            StatusCount("no_decoder", 100, 10.0),
        ),
        log_type_counts=(
            LogTypeCount("no_decoder", "app", 100, 10.0, 100.0),
            LogTypeCount("no_alerting_rule", "firewall", 90, 9.0, 90 / 170 * 100),
            LogTypeCount("no_alerting_rule", "auditd", 50, 5.0, 50 / 170 * 100),
            LogTypeCount("below_threshold", "auditd", 300, 30.0, 100.0),
            LogTypeCount("no_alerting_rule", "sshd", 30, 3.0, 30 / 170 * 100),
            LogTypeCount("at_or_above_threshold", "sshd", 430, 43.0, 100.0),
        ),
        findings=(
            _finding("nd", "no_decoder", "app", 100),
            _finding("u", "no_alerting_rule", "firewall", 90),
            _finding("s", "no_alerting_rule", "auditd", 50),
            _finding("v", "no_alerting_rule", "sshd", 30),
        ),
    )


def _verifications() -> tuple[Verification, ...]:
    return (
        _verification("nd", "no_decoder", decoder=None),
        _verification("u", "uncovered", decoder="firewall"),
        _verification("s", "suppressed", decoder="auditd", level=0),
        _verification("v", "unverified", decoder=None),
    )


def test_archive_only_metrics_keep_ambiguous_events_uncertain() -> None:
    snapshot = calculate_metrics(_analysis())

    assert snapshot.malformed_rate.count == 100
    assert snapshot.malformed_rate.denominator == 1100
    assert snapshot.malformed_rate.ratio == pytest.approx(100 / 1100)

    assert snapshot.decoder_failure_rate.count == 100
    assert snapshot.decoder_failure_rate.denominator == 1000
    assert snapshot.decoder_failure_rate.ratio == pytest.approx(0.10)

    assert snapshot.below_threshold_rate.count == 300
    assert snapshot.below_threshold_rate.ratio == pytest.approx(0.30)

    assert snapshot.uncertainty_rate.count == 170
    assert snapshot.uncertainty_rate.ratio == pytest.approx(0.17)

    assert snapshot.uncovered_rate.available is False
    assert snapshot.uncovered_rate.count is None
    assert snapshot.uncovered_rate.denominator is None
    assert snapshot.uncovered_rate.ratio is None


def test_replay_refines_metrics_without_changing_the_total_population() -> None:
    snapshot = calculate_metrics(_analysis(), _verifications())

    assert snapshot.total_events == 1000
    assert snapshot.decoder_failure_rate.count == 100
    assert snapshot.decoder_failure_rate.ratio == pytest.approx(0.10)

    assert snapshot.uncovered_rate.available is True
    assert snapshot.uncovered_rate.count == 90
    assert snapshot.uncovered_rate.denominator == 900
    assert snapshot.uncovered_rate.ratio == pytest.approx(0.10)

    # A level-0 match satisfies rule matched AND level < log_alert_level, so it
    # joins the directly observed below-threshold population after replay.
    assert snapshot.below_threshold_rate.count == 350
    assert snapshot.below_threshold_rate.ratio == pytest.approx(0.35)

    assert snapshot.uncertainty_rate.count == 30
    assert snapshot.uncertainty_rate.ratio == pytest.approx(0.03)


def test_partial_replay_does_not_turn_an_incomplete_uncovered_count_into_zero() -> None:
    snapshot = calculate_metrics(_analysis(), (_verifications()[1],))

    assert snapshot.uncovered_rate.available is False
    assert snapshot.uncovered_rate.ratio is None


def test_uncovered_is_measurable_without_replay_when_no_ruleless_decoded_events_exist() -> None:
    analysis = ArchiveAnalysis(
        path=Path("/archives/clean.json"),
        total_events=10,
        malformed_lines=0,
        status_counts=(
            StatusCount("at_or_above_threshold", 8, 80.0),
            StatusCount("below_threshold", 1, 10.0),
            StatusCount("no_alerting_rule", 0, 0.0),
            StatusCount("no_decoder", 1, 10.0),
        ),
        log_type_counts=(),
        findings=(),
    )

    snapshot = calculate_metrics(analysis)

    assert snapshot.uncovered_rate.available is True
    assert snapshot.uncovered_rate.count == 0
    assert snapshot.uncovered_rate.denominator == 9
    assert snapshot.uncovered_rate.ratio == 0.0


def test_per_log_type_metrics_expose_local_rate_and_global_contribution() -> None:
    snapshot = calculate_metrics(_analysis(), _verifications())
    rows = {item.log_type: item for item in snapshot.log_types}

    assert rows["app"].decoder_failure_rate.ratio == pytest.approx(1.0)
    assert rows["app"].decoder_failure_contribution.ratio == pytest.approx(1.0)

    assert rows["firewall"].uncovered_rate.ratio == pytest.approx(1.0)
    assert rows["firewall"].uncovered_contribution.ratio == pytest.approx(1.0)

    assert rows["auditd"].below_threshold_rate.count == 350
    assert rows["auditd"].below_threshold_rate.ratio == pytest.approx(1.0)
    assert rows["auditd"].below_threshold_contribution.ratio == pytest.approx(1.0)


def test_populated_contributions_sum_to_one() -> None:
    snapshot = calculate_metrics(_analysis(), _verifications())

    decoder = [
        item.decoder_failure_contribution.ratio
        for item in snapshot.log_types
        if item.decoder_failure_contribution.ratio is not None
    ]
    uncovered = [
        item.uncovered_contribution.ratio
        for item in snapshot.log_types
        if item.uncovered_contribution.ratio is not None
    ]
    below = [
        item.below_threshold_contribution.ratio
        for item in snapshot.log_types
        if item.below_threshold_contribution.ratio is not None
    ]

    assert sum(decoder) == pytest.approx(1.0)
    assert sum(uncovered) == pytest.approx(1.0)
    assert sum(below) == pytest.approx(1.0)


def test_replay_decoder_moves_the_effective_log_type() -> None:
    verifications = list(_verifications())
    verifications[1] = _verification("u", "uncovered", decoder="normalized-firewall")

    snapshot = calculate_metrics(_analysis(), tuple(verifications))
    rows = {item.log_type: item for item in snapshot.log_types}

    assert rows["normalized-firewall"].uncovered_rate.count == 90
    assert "firewall" not in rows


def test_empty_population_is_distinct_from_an_unavailable_metric() -> None:
    analysis = ArchiveAnalysis(
        path=Path("/archives/empty.json"),
        total_events=0,
        malformed_lines=0,
        status_counts=(),
        log_type_counts=(),
        findings=(),
    )

    snapshot = calculate_metrics(analysis)

    assert snapshot.malformed_rate.available is True
    assert snapshot.malformed_rate.count == 0
    assert snapshot.malformed_rate.denominator == 0
    assert snapshot.malformed_rate.ratio is None
    assert snapshot.uncovered_rate.available is True
    assert snapshot.uncovered_rate.denominator == 0
    assert snapshot.uncovered_rate.ratio is None


def test_machine_readable_metrics_keep_fractional_rates_and_availability() -> None:
    payload = metrics_to_dict(calculate_metrics(_analysis()))

    assert payload["malformed"]["count"] == 100
    assert payload["malformed"]["denominator"] == 1100
    assert payload["malformed"]["rate"] == pytest.approx(100 / 1100)
    assert payload["uncovered"] == {
        "count": None,
        "denominator": None,
        "rate": None,
        "available": False,
    }
