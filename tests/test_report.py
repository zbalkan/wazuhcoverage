from dataclasses import replace
from pathlib import Path

from wazuhcoverage import ArchiveAnalysis, Finding, LogTypeCount, StatusCount
from wazuhcoverage.report import render_report


def _analysis() -> ArchiveAnalysis:
    return ArchiveAnalysis(
        path=Path("/archives/archive.json.gz"),
        total_events=10,
        malformed_lines=2,
        status_counts=(
            StatusCount(status="no_decoder", event_count=3, percentage=30.0),
            StatusCount(status="no_rule", event_count=3, percentage=30.0),
            StatusCount(status="at_or_above_threshold", event_count=3, percentage=30.0),
            StatusCount(status="below_threshold", event_count=1, percentage=10.0),
        ),
        log_type_counts=(
            LogTypeCount(
                status="no_rule",
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
                status="no_rule",
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
    header = next(
        index for index, line in enumerate(lines) if line.startswith("Log type") and "at_or_above_threshold" in line
    )
    end = lines.index("", header + 1)
    return lines[header + 1 : end]


def test_report_renders_status_and_log_type_tables() -> None:
    lines = render_report(_analysis()).splitlines()

    assert "Status                          Events   % total" in lines
    assert lines[lines.index("Status") + 3].split() == ["no_decoder", "3", "30.00%"]

    header = next(line for line in lines if line.startswith("Log type") and "at_or_above_threshold" in line)
    assert header.split() == [
        "Log",
        "type",
        "Events",
        "%",
        "total",
        "no_decoder",
        "no_rule",
        "below_threshold",
        "at_or_above_threshold",
    ]


def test_log_type_table_groups_statuses_into_one_row_per_type() -> None:
    rows = _rendered_log_type_rows(_analysis())

    sshd = next(row for row in rows if row.startswith("sshd"))
    assert sshd.split() == ["sshd", "6", "60.00%", "0", "2", "1", "3"]


def test_log_type_table_is_sorted_by_aggregate_event_count() -> None:
    rows = _rendered_log_type_rows(_analysis())

    assert [row.split()[0] for row in rows] == ["sshd", "/var/log/app.log", "-"]


def test_report_renders_a_missing_log_type_as_a_dash() -> None:
    rows = _rendered_log_type_rows(_analysis())

    missing = next(row for row in rows if row.lstrip().startswith("-"))
    assert missing.split() == ["-", "1", "10.00%", "0", "1", "0", "0"]
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
                observed_status="no_rule",
                log_type="sshd",
                message_pattern="pattern",
                event_count=1,
                affected_agents=1,
                first_seen=None,
                last_seen=None,
                observed_decoder="sshd",
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
