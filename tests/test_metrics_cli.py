import json
import os
from pathlib import Path

import pytest

from wazuhcoverage import ArchiveAnalysis, Finding, LogTypeCount, StatusCount, Verification, cli


def _analysis(path: Path) -> ArchiveAnalysis:
    return ArchiveAnalysis(
        path=path,
        total_events=10,
        malformed_lines=2,
        status_counts=(
            StatusCount("at_or_above_threshold", 6, 60.0),
            StatusCount("below_threshold", 2, 20.0),
            StatusCount("no_alerting_rule", 2, 20.0),
            StatusCount("no_decoder", 0, 0.0),
        ),
        log_type_counts=(
            LogTypeCount("at_or_above_threshold", "sshd", 6, 60.0, 100.0),
            LogTypeCount("below_threshold", "sshd", 2, 20.0, 100.0),
            LogTypeCount("no_alerting_rule", "sshd", 2, 20.0, 100.0),
        ),
        findings=(
            Finding(
                finding_key="gap",
                observed_status="no_alerting_rule",
                log_type="sshd",
                message_pattern="gap",
                event_count=2,
                affected_agents=1,
                first_seen=None,
                last_seen=None,
                observed_decoder="sshd",
                observed_location="syslog",
                observed_rule_id=None,
                observed_rule_level=None,
                sample_log="gap",
            ),
        ),
    )


def test_json_flag_is_machine_output_and_excludes_no_stats() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(["--json", "a.json"])
    assert args.json is True
    assert args.no_stats is False

    with pytest.raises(SystemExit):
        parser.parse_args(["--json", "--no-stats", "a.json"])


def test_json_output_contains_metric_counts_denominators_and_fractional_rates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    archive = tmp_path / "archive.json"
    archive.touch()

    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "unavailable_reason", lambda: "no manager")
    monkeypatch.setattr(cli, "read_alert_threshold", lambda: 3)
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(Path(path)))

    assert cli.main(["--json", str(archive)]) == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["archive"] == str(archive)
    assert payload["alert_threshold"] == 3
    assert payload["malformed"] == {
        "available": True,
        "count": 2,
        "denominator": 12,
        "rate": pytest.approx(2 / 12),
    }
    assert payload["below_threshold"]["count"] == 2
    assert payload["below_threshold"]["rate"] == pytest.approx(0.2)
    assert payload["uncovered"] == {
        "available": False,
        "count": None,
        "denominator": None,
        "rate": None,
    }
    assert "Processing" in captured.err


def test_multiple_archives_use_one_json_object_per_line(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    archives = [tmp_path / "a.json", tmp_path / "b.json"]
    for archive in archives:
        archive.touch()

    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: archives)
    monkeypatch.setattr(cli, "unavailable_reason", lambda: "no manager")
    monkeypatch.setattr(cli, "read_alert_threshold", lambda: 3)
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(Path(path)))

    assert cli.main(["-j", *(str(path) for path in archives)]) == 0

    payloads = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [item["archive"] for item in payloads] == [str(path) for path in archives]


def test_json_output_uses_replay_adjusted_metrics(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    archive = tmp_path / "archive.json"
    archive.touch()

    verification = Verification(
        finding_key="gap",
        effective_state="uncovered",
        logtest_status="NoRule",
        decoder="sshd",
        rule_id=None,
        rule_level=None,
        rule_description=None,
        rule_groups=(),
        error=None,
    )

    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "unavailable_reason", lambda: None)
    monkeypatch.setattr(cli, "read_alert_threshold", lambda: 3)
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(Path(path)))
    monkeypatch.setattr(cli, "verify_findings", lambda *_args, **_kwargs: (verification,))

    assert cli.main(["--json", str(archive)]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["uncovered"]["available"] is True
    assert payload["uncovered"]["count"] == 2
    assert payload["uncovered"]["denominator"] == 10
    assert payload["uncovered"]["rate"] == pytest.approx(0.2)



def test_html_flag_is_an_output_mode_and_excludes_json_and_no_stats() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(["--html", "report.html", "a.json"])
    assert args.html == Path("report.html")
    assert args.json is False
    assert args.no_stats is False

    with pytest.raises(SystemExit):
        parser.parse_args(["--html", "report.html", "--json", "a.json"])

    with pytest.raises(SystemExit):
        parser.parse_args(["--html", "report.html", "--no-stats", "a.json"])


def test_html_output_writes_report_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    archive = tmp_path / "archive.json"
    output = tmp_path / "report.html"
    archive.touch()

    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "unavailable_reason", lambda: "no manager")
    monkeypatch.setattr(cli, "read_alert_threshold", lambda: 3)
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(Path(path)))

    assert cli.main(["--html", str(output), str(archive)]) == 0

    captured = capsys.readouterr()
    assert captured.out == ""
    assert output.exists()
    rendered = output.read_text(encoding="utf-8")
    assert "<title>Wazuh Coverage Report - archive.json</title>" in rendered
    assert 'data-tab="dashboard"' in rendered
    assert 'data-tab="findings"' in rendered
    assert f"HTML report: {output}" in captured.err


def test_html_output_requires_exactly_one_archive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    archives = [tmp_path / "a.json", tmp_path / "b.json"]
    for archive in archives:
        archive.touch()

    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: archives)

    assert cli.main(["--html", str(tmp_path / "report.html"), *(str(path) for path in archives)]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "--html requires exactly one archive" in captured.err


def test_html_output_refuses_to_overwrite_input_archive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    archive = tmp_path / "archive.json"
    archive.touch()

    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])

    assert cli.main(["--html", str(archive), str(archive)]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "must not overwrite the input archive" in captured.err



def test_html_output_refuses_hard_link_to_input_archive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    archive = tmp_path / "archive.json"
    output = tmp_path / "report.html"
    archive.write_text("archive", encoding="utf-8")
    try:
        os.link(archive, output)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")

    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])

    assert cli.main(["--html", str(output), str(archive)]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "must not overwrite the input archive" in captured.err
    assert archive.read_text(encoding="utf-8") == "archive"
