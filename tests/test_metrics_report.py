from pathlib import Path

from wazuhcoverage import ArchiveAnalysis, Finding, LogTypeCount, StatusCount, Verification
from wazuhcoverage.report import render_report


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
        observed_decoder=None if status == "no_decoder" else log_type,
        observed_location="syslog",
        observed_rule_id=None,
        observed_rule_level=None,
        sample_log=key,
    )


def _analysis() -> ArchiveAnalysis:
    return ArchiveAnalysis(
        path=Path("/archives/a.json"),
        total_events=10,
        malformed_lines=2,
        status_counts=(
            StatusCount("no_decoder", 3, 30.0),
            StatusCount("no_alerting_rule", 3, 30.0),
            StatusCount("at_or_above_threshold", 3, 30.0),
            StatusCount("below_threshold", 1, 10.0),
        ),
        log_type_counts=(
            LogTypeCount("no_decoder", "app", 3, 30.0, 100.0),
            LogTypeCount("no_alerting_rule", "firewall", 2, 20.0, 200 / 3),
            LogTypeCount("no_alerting_rule", "auditd", 1, 10.0, 100 / 3),
            LogTypeCount("below_threshold", "auditd", 1, 10.0, 100.0),
            LogTypeCount("at_or_above_threshold", "sshd", 3, 30.0, 100.0),
        ),
        findings=(
            _finding("nd", "no_decoder", "app", 3),
            _finding("u", "no_alerting_rule", "firewall", 2),
            _finding("s", "no_alerting_rule", "auditd", 1),
        ),
    )


def _verifications() -> tuple[Verification, ...]:
    return (
        Verification("nd", "no_decoder", "NoDecoder", None, None, None, None, (), None),
        Verification("u", "uncovered", "NoRule", "firewall", None, None, None, (), None),
        Verification("s", "suppressed", "RuleMatch", "auditd", "1", 0, None, (), None),
    )


def test_report_shows_primary_metrics_and_unavailable_uncovered_state() -> None:
    text = render_report(_analysis())

    assert "\nMetrics\n-------\n" in text
    assert "Malformed input" in text and "2 / 12" in text and "16.67%" in text
    assert "Decoder failure" in text and "3 / 10" in text and "30.00%" in text
    assert "Below threshold" in text and "1 / 10" in text and "10.00%" in text
    assert "Unresolved" in text and "3 / 10" in text and "30.00%" in text
    assert "Uncovered" in text and "unavailable without complete replay" in text


def test_replayed_report_shows_rates_and_largest_contributors() -> None:
    text = render_report(_analysis(), _verifications())

    metrics = text.split("\nMetrics\n-------\n", 1)[1].split("\nLargest metric contributors\n", 1)[0]
    assert "Uncovered" in metrics and "2 / 7" in metrics and "28.57%" in metrics
    assert "Below threshold" in metrics and "2 / 10" in metrics and "20.00%" in metrics
    assert "Unresolved" in metrics and "0 / 10" in metrics and "0.00%" in metrics

    contributors = text.split("\nLargest metric contributors\n", 1)[1]
    assert "app: 3 events | local 100.00% | contribution 100.00%" in contributors
    assert "firewall: 2 events | local 100.00% | contribution 100.00%" in contributors
    assert "auditd: 2 events | local 100.00% | contribution 100.00%" in contributors


def test_metrics_report_remains_plain_ascii() -> None:
    assert render_report(_analysis(), _verifications()).isascii()
