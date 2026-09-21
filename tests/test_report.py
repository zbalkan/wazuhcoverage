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
            StatusCount(status="no_decoder", event_count=6, percentage=60.0),
            StatusCount(status="no_rule", event_count=4, percentage=40.0),
            StatusCount(status="below_threshold", event_count=0, percentage=0.0),
            StatusCount(status="at_or_above_threshold", event_count=0, percentage=0.0),
        ),
        log_type_counts=(
            LogTypeCount(
                status="no_decoder",
                log_type="/var/log/app.log",
                event_count=6,
                percentage=60.0,
                status_percentage=100.0,
            ),
            LogTypeCount(
                status="no_rule",
                log_type=None,
                event_count=4,
                percentage=40.0,
                status_percentage=100.0,
            ),
        ),
        findings=(),
    )


def test_report_renders_both_percentage_columns() -> None:
    lines = render_report(_analysis()).splitlines()

    assert "Status                          Events   % total" in lines
    assert lines[lines.index("Status") + 3].split() == ["no_decoder", "6", "60.00%"]

    header = lines.index("Status                  Log type                                Events   % total  % status")
    assert lines[header + 1].split() == ["no_decoder", "/var/log/app.log", "6", "60.00%", "100.00%"]


def test_report_renders_a_missing_log_type_as_a_dash() -> None:
    # log_type is Optional in the model; rendering it must not raise or print
    # the string "None" into a table an operator reads as data.
    rows = [line.split() for line in render_report(_analysis()).splitlines()]

    assert ["no_rule", "-", "4", "40.00%", "100.00%"] in rows
    assert not any("None" in line for line in rows)


def test_report_preserves_the_order_the_analysis_produced() -> None:
    # Ordering is decided in the analysis layer, by count descending. The
    # renderer must not re-sort or regroup, or the two views would disagree.
    text = render_report(_analysis())

    assert text.index("no_decoder") < text.index("no_rule")
    assert text.index("below_threshold") < text.index("at_or_above_threshold")


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
