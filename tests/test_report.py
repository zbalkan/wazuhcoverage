from dataclasses import replace
from pathlib import Path

from wazuhcoverage import ArchiveAnalysis, Finding, LogTypeCount, StatusCount, Verification
from wazuhcoverage.report import render_report


def _analysis() -> ArchiveAnalysis:
    return ArchiveAnalysis(
        path=Path("/archives/archive.json.gz"),
        total_events=10,
        malformed_lines=2,
        status_counts=(
            StatusCount(status="no_decoder", event_count=3, percentage=30.0),
            StatusCount(status="no_alerting_rule", event_count=3, percentage=30.0),
            StatusCount(status="at_or_above_threshold", event_count=3, percentage=30.0),
            StatusCount(status="below_threshold", event_count=1, percentage=10.0),
        ),
        log_type_counts=(
            LogTypeCount(
                status="no_alerting_rule",
                log_type="sshd",
                event_count=2,
                percentage=20.0,
                status_percentage=66.6666666667,
            ),
            LogTypeCount(
                status="no_decoder",
                log_type="/var/log/app.log",
                event_count=3,
                percentage=30.0,
                status_percentage=100.0,
            ),
            LogTypeCount(
                status="below_threshold",
                log_type="sshd",
                event_count=1,
                percentage=10.0,
                status_percentage=100.0,
            ),
            LogTypeCount(
                status="no_alerting_rule",
                log_type=None,
                event_count=1,
                percentage=10.0,
                status_percentage=33.3333333333,
            ),
            LogTypeCount(
                status="at_or_above_threshold",
                log_type="sshd",
                event_count=3,
                percentage=30.0,
                status_percentage=100.0,
            ),
        ),
        findings=(),
    )


def _rendered_log_type_rows(analysis: ArchiveAnalysis) -> list[str]:
    lines = render_report(analysis).splitlines()
    header = next(index for index, line in enumerate(lines) if line.startswith("Log type") and "Processed" in line)
    end = lines.index("", header + 1)
    return lines[header + 1: end]


def _rendered_outcome_rows(analysis: ArchiveAnalysis) -> list[str]:
    lines = render_report(analysis).splitlines()
    header = next(index for index, line in enumerate(lines) if line.startswith("Outcome") and "% dropped" in line)
    end = lines.index("", header + 1)
    return lines[header + 1: end]


def test_report_renders_outcome_and_log_type_tables() -> None:
    lines = render_report(_analysis()).splitlines()

    header = next(line for line in lines if line.startswith("Outcome") and "% dropped" in line)
    assert header.split() == ["Outcome", "Events", "%", "total", "%", "dropped"]

    log_types = next(line for line in lines if line.startswith("Log type") and "Processed" in line)
    assert log_types.split() == [
        "Log",
        "type",
        "Events",
        "%",
        "total",
        "Processed",
        "Dropped",
        "no_decoder",
        "no_alerting_rule",
        "below_threshold",
    ]


def test_the_outcome_table_splits_the_archive_into_processed_and_dropped() -> None:
    # at_or_above_threshold is the only bucket that reached an alert, so it is
    # the whole of Processed and the other three are the whole of Dropped.
    rows = [row.split() for row in _rendered_outcome_rows(_analysis())]

    assert rows[0] == ["Processed", "(at_or_above_threshold)", "3", "30.00%", "-"]
    assert rows[1] == ["Dropped", "7", "70.00%", "100.00%"]
    assert [row[0] for row in rows[2:]] == ["no_decoder", "no_alerting_rule", "below_threshold"]


def test_the_dropped_buckets_sum_back_to_the_dropped_total() -> None:
    rows = [row.split() for row in _rendered_outcome_rows(_analysis())]

    assert sum(int(row[1]) for row in rows[2:]) == int(rows[1][1])
    assert int(rows[0][2]) + int(rows[1][1]) == 10


def test_a_dropped_bucket_is_sized_against_the_dropped_events() -> None:
    # 3 of 7 dropped events, not 3 of 10 archived ones: a bucket holding a few
    # per cent of a well-covered archive can still be most of what is left.
    rows = [row.split() for row in _rendered_outcome_rows(_analysis())]

    assert rows[2] == ["no_decoder", "3", "30.00%", "42.86%"]
    assert rows[4] == ["below_threshold", "1", "10.00%", "14.29%"]


def test_the_dropped_share_is_blank_when_nothing_was_dropped() -> None:
    # A column of 0.00% would read as a measurement rather than an empty set.
    analysis = replace(
        _analysis(),
        total_events=3,
        status_counts=(
            StatusCount(status="at_or_above_threshold", event_count=3, percentage=100.0),
            StatusCount(status="no_decoder", event_count=0, percentage=0.0),
            StatusCount(status="no_alerting_rule", event_count=0, percentage=0.0),
            StatusCount(status="below_threshold", event_count=0, percentage=0.0),
        ),
    )

    rows = [row.split() for row in _rendered_outcome_rows(analysis)]

    assert rows[1] == ["Dropped", "0", "0.00%", "-"]
    assert [row[-1] for row in rows[2:]] == ["-", "-", "-"]


def test_every_bucket_is_listed_even_at_zero() -> None:
    analysis = replace(
        _analysis(),
        status_counts=tuple(
            replace(item, event_count=0, percentage=0.0) if item.status == "below_threshold" else item
            for item in _analysis().status_counts
        ),
    )

    rows = [row.split() for row in _rendered_outcome_rows(analysis)]

    assert rows[-1][:2] == ["below_threshold", "0"]


def test_log_type_table_groups_statuses_into_one_row_per_type() -> None:
    rows = _rendered_log_type_rows(_analysis())

    sshd = next(row for row in rows if row.startswith("sshd"))
    assert sshd.split() == ["sshd", "6", "60.00%", "3", "3", "0", "2", "1"]


def test_log_type_table_is_sorted_by_aggregate_event_count() -> None:
    rows = _rendered_log_type_rows(_analysis())

    assert [row.split()[0] for row in rows] == ["sshd", "/var/log/app.log", "-"]


def test_report_renders_a_missing_log_type_as_a_dash() -> None:
    rows = _rendered_log_type_rows(_analysis())

    missing = next(row for row in rows if row.lstrip().startswith("-"))
    assert missing.split() == ["-", "1", "10.00%", "0", "1", "0", "1", "0"]
    assert not any("None" in row for row in rows)


def test_report_still_reports_totals_and_malformed_lines() -> None:
    text = render_report(_analysis())

    assert "Total events: 10" in text
    assert "Malformed lines skipped: 2" in text
    assert "Findings: 0" in text


def test_finding_fields_stay_on_one_row_each() -> None:
    analysis = replace(
        _analysis(),
        findings=(
            Finding(
                finding_key="key",
                observed_status="no_decoder",
                log_type="/var/log/app.log",
                message_pattern="Exception in thread main\nat com.acme.Foo.bar",
                event_count=1,
                affected_agents=1,
                first_seen=None,
                last_seen=None,
                observed_decoder=None,
                observed_location="syslog",
                observed_rule_id=None,
                observed_rule_level=None,
                sample_log="Exception in thread main at com.acme.Foo.bar",
            ),
        ),
    )

    lines = render_report(analysis).splitlines()
    pattern_rows = [line for line in lines if line.strip().startswith("Pattern:")]
    sample_rows = [line for line in lines if line.strip().startswith("Sample:")]

    # A multi-line pattern must not break the finding block across rows.
    assert len(pattern_rows) == 1
    assert pattern_rows[0].strip() == "Pattern: Exception in thread main at com.acme.Foo.bar"
    assert len(sample_rows) == 1


def test_report_never_truncates_a_long_log_type() -> None:
    # The column widths are minimums, not limits. A long decoder or location
    # name widens its row rather than being cut: a truncated name cannot be
    # pasted into a query, and two distinct sources can collapse into one row.
    long_type = "/var/ossec/logs/archives/" + "x" * 400
    analysis = _analysis()
    analysis = replace(
        analysis,
        log_type_counts=(replace(analysis.log_type_counts[0], log_type=long_type),),
    )

    text = render_report(analysis)

    assert long_type in text
    assert "…" not in text
    assert "..." not in text


def test_a_long_sample_is_never_wrapped_or_padded() -> None:
    # A finding's sample is a raw log destined for logtest. It must reach the
    # pipe on one row, with nothing added to either end.
    sample = "sshd: " + "y" * 500
    analysis = replace(
        _analysis(),
        findings=(
            Finding(
                finding_key="key",
                observed_status="no_alerting_rule",
                log_type="sshd",
                message_pattern="pattern",
                event_count=1,
                affected_agents=1,
                first_seen=None,
                last_seen=None,
                observed_decoder="sshd",
                observed_location="syslog",
                observed_rule_id=None,
                observed_rule_level=None,
                sample_log=sample,
            ),
        ),
    )

    rows = [line for line in render_report(analysis).splitlines() if line.strip().startswith("Sample:")]

    assert rows == [f"    Sample: {sample}"]


def test_report_output_is_plain_ascii_text() -> None:
    # The report goes to whatever stdout the caller supplies. Colour codes would
    # corrupt a redirected report, and non-ASCII box drawing raises
    # UnicodeEncodeError on a Windows stdout using the locale code page.
    text = render_report(_analysis())

    assert "\x1b" not in text
    assert text.isascii()


def test_report_flags_what_an_absent_rule_does_not_prove() -> None:
    # An empty Rule and Level reads as "nothing matched", but Wazuh writes the
    # same archive record for a level-0 match and for a suppressed one. The
    # report carries that caveat where the findings are read.
    text = render_report(_analysis())

    assert "no_alerting_rule event carries no rule in the archive" in text
    assert "the matching rule was level 0" in text
    assert "wazuh-logtest" in text


def test_the_caveat_is_omitted_when_the_bucket_is_empty() -> None:
    analysis = _analysis()
    analysis = replace(
        analysis,
        status_counts=tuple(
            replace(item, event_count=0, percentage=0.0) if item.status == "no_alerting_rule" else item
            for item in analysis.status_counts
        ),
    )

    assert "Note:" not in render_report(analysis)


def _verified_analysis() -> ArchiveAnalysis:
    return replace(
        _analysis(),
        total_events=53,
        status_counts=(
            StatusCount(status="at_or_above_threshold", event_count=3, percentage=300 / 53),
            StatusCount(status="no_alerting_rule", event_count=50, percentage=5000 / 53),
        ),
        log_type_counts=(
            LogTypeCount(
                status="at_or_above_threshold", log_type="sshd",
                event_count=3, percentage=300 / 53, status_percentage=100.0,
            ),
            LogTypeCount(
                status="no_alerting_rule", log_type="sshd",
                event_count=10, percentage=1000 / 53, status_percentage=20.0,
            ),
            LogTypeCount(
                status="no_alerting_rule", log_type="windows_eventchannel",
                event_count=40, percentage=4000 / 53, status_percentage=80.0,
            ),
        ),
        findings=(
            Finding(
                finding_key="suppressed",
                observed_status="no_alerting_rule",
                log_type="windows_eventchannel",
                message_pattern="pattern",
                event_count=40,
                affected_agents=1,
                first_seen=None,
                last_seen=None,
                observed_decoder="windows_eventchannel",
                observed_location="EventChannel",
                observed_rule_id=None,
                observed_rule_level=None,
                sample_log="a windows record",
            ),
            Finding(
                finding_key="gap",
                observed_status="no_alerting_rule",
                log_type="sshd",
                message_pattern="pattern",
                event_count=10,
                affected_agents=1,
                first_seen=None,
                last_seen=None,
                observed_decoder="sshd",
                observed_location="syslog",
                observed_rule_id=None,
                observed_rule_level=None,
                sample_log="an sshd record",
            ),
        ),
    )


def _verifications() -> tuple[Verification, ...]:
    return (
        Verification(
            finding_key="suppressed",
            effective_state="suppressed",
            logtest_status="RuleMatch",
            decoder="windows_eventchannel",
            rule_id="61100",
            rule_level=0,
            rule_description="Windows System informational event",
            rule_groups=("windows", "windows_system"),
            error=None,
        ),
        Verification(
            finding_key="gap",
            effective_state="uncovered",
            logtest_status="NoRule",
            decoder="sshd",
            rule_id=None,
            rule_level=None,
            rule_description=None,
            rule_groups=(),
            error=None,
        ),
    )


def test_a_verified_report_names_the_rule_the_archive_omitted() -> None:
    text = render_report(_verified_analysis(), _verifications())

    assert text.index("Dropped\n-------") < text.index("Processed\n---------")
    assert "[1] uncovered | sshd" in text
    uncovered = text.split("[1] uncovered | sshd", 1)[1].split("Processed\n---------", 1)[0]
    suppressed = text.split("[1] suppressed | windows_eventchannel", 1)[1]
    assert "    Rule: 61100\n    Level: 0\n" in suppressed
    assert "no_alerting_rule" not in suppressed
    assert "    Rule: -\n" not in suppressed
    assert "    Level: -\n" not in suppressed
    assert "Matched: Windows System informational event" in text
    assert "    Rule:" not in uncovered
    assert "    Level:" not in uncovered
    assert "    Effective:" not in text
    assert "  no_alerting_rule" not in text
    assert "\nOutcome\n" not in text
    assert "\nLog types\n" not in text


def test_the_effective_table_weights_states_by_events() -> None:
    # One finding standing for 40 events and one standing for 10 are not the
    # same coverage statement, so the table counts events as well as findings.
    lines = render_report(_verified_analysis(), _verifications()).splitlines()
    header = lines.index("Effective coverage (wazuh-logtest)")
    rows = [line.split() for line in lines[header + 3: header + 5]]

    assert rows[0] == ["uncovered", "1", "10", "20.00%"]
    assert rows[1] == ["suppressed", "1", "40", "80.00%"]


def test_replayed_summary_separates_suppressed_from_dropped() -> None:
    text = render_report(_verified_analysis(), _verifications())
    lines = text.splitlines()
    start = lines.index("Outcome (with replay)")
    rows = [line.split() for line in lines[start + 3:start + 11]]

    assert rows == [
        ["Processed", "3", "5.66%", "-"],
        ["Suppressed", "40", "75.47%", "-"],
        ["suppressed", "40", "75.47%", "-"],
        ["below_threshold", "0", "0.00%", "-"],
        ["Dropped", "10", "18.87%", "100.00%"],
        ["no_decoder", "0", "0.00%", "0.00%"],
        ["uncovered", "10", "18.87%", "100.00%"],
        ["Unresolved", "0", "0.00%", "-"],
    ]
    assert sum(int(rows[index][1]) for index in (0, 1, 4, 7)) == 53
    start = lines.index("Log types (with replay)")
    log_types = [line.split() for line in lines[start + 3:start + 5]]
    assert log_types == [
        ["windows_eventchannel", "40", "75.47%", "0", "40", "0", "0"],
        ["sshd", "13", "24.53%", "3", "0", "10", "0"],
    ]


def test_replay_decoder_replaces_archive_decoder_and_log_type() -> None:
    verification = replace(_verifications()[0], decoder="auditd")
    text = render_report(_verified_analysis(), (verification, _verifications()[1]))

    suppressed = text.split("[1] suppressed | auditd", 1)[1]
    assert "    Decoder: auditd\n" in suppressed
    assert "    Decoder: windows_eventchannel\n" not in suppressed
    lines = text.splitlines()
    start = lines.index("Log types (with replay)")
    log_types = [line.split() for line in lines[start + 3:start + 5]]
    assert log_types == [
        ["auditd", "40", "75.47%", "0", "40", "0", "0"],
        ["sshd", "13", "24.53%", "3", "0", "10", "0"],
    ]


def test_findings_sort_by_event_count_within_each_outcome() -> None:
    base = _verified_analysis()
    smaller_processed = replace(
        base.findings[1], finding_key="processed-small",
        observed_status="at_or_above_threshold", event_count=3,
        observed_rule_id="321", observed_rule_level=5,
    )
    text = render_report(replace(base, findings=base.findings + (smaller_processed,)), _verifications())
    processed = text.split("\nProcessed\n---------\n", 1)[1]

    assert processed.index("[1] suppressed | windows_eventchannel") < processed.index(
        "[2] at_or_above_threshold | sshd"
    )
    assert text.index("\nDropped\n-------\n") < text.index("\nProcessed\n---------\n")


def test_below_threshold_replay_is_suppressed_not_dropped() -> None:
    verification = replace(
        _verifications()[0],
        effective_state="below_threshold",
        rule_id="100210",
        rule_level=2,
    )
    text = render_report(_verified_analysis(), (verification,))

    assert "[1] below_threshold | windows_eventchannel" in text
    assert "    Rule: 100210\n    Level: 2\n" in text
    rows = text.splitlines()
    start = rows.index("Outcome (with replay)")
    assert rows[start + 4].split() == ["Suppressed", "40", "75.47%", "-"]
    assert rows[start + 6].split() == ["below_threshold", "40", "75.47%", "-"]
    assert rows[start + 7].split() == ["Dropped", "0", "0.00%", "-"]
    assert rows[start + 10].split() == ["Unresolved", "10", "18.87%", "-"]


def test_a_verified_report_drops_the_note_it_has_answered() -> None:
    # The note exists because the archive cannot separate suppressed from
    # uncovered. Once a replay has, repeating it would be noise.
    assert "Note:" not in render_report(_verified_analysis(), _verifications())
    assert "Note:" in render_report(_verified_analysis())


def test_an_unverified_finding_says_why() -> None:
    verifications = (
        Verification(
            finding_key="gap",
            effective_state="unverified",
            logtest_status="Error",
            decoder=None,
            rule_id=None,
            rule_level=None,
            rule_description=None,
            rule_groups=(),
            error="the logtest daemon reported an error for this sample",
        ),
    )

    text = render_report(_verified_analysis(), verifications)

    assert "[2] unverified | sshd" in text
    assert "Replay: the logtest daemon reported an error for this sample" in text
    assert "[1] no_alerting_rule | windows_eventchannel" in text
    lines = text.splitlines()
    start = lines.index("Outcome (with replay)")
    assert lines[start + 10].split() == ["Unresolved", "50", "94.34%", "-"]


def test_an_unverified_report_is_unchanged() -> None:
    assert render_report(_verified_analysis()) == render_report(_verified_analysis(), ())
    assert "Effective coverage" not in render_report(_verified_analysis())


def test_a_verified_report_is_still_plain_ascii() -> None:
    text = render_report(_verified_analysis(), _verifications())

    assert "\x1b" not in text
    assert text.isascii()
