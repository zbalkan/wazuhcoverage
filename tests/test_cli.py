import io
from dataclasses import replace
from pathlib import Path

import pytest

from wazuhcoverage import ArchiveAnalysis, Finding, cli


def test_cli_flags_and_targets() -> None:
    args = cli.build_parser().parse_args(
        ["--ignore-history", "--no-stats", "/archives/**/*.json.gz", "/other/a.json.gz"]
    )

    assert args.ignore_history is True
    assert args.no_stats is True
    assert args.strict is False
    assert args.targets == ["/archives/**/*.json.gz", "/other/a.json.gz"]


def test_short_flags_mirror_the_long_ones() -> None:
    parser = cli.build_parser()

    short = parser.parse_args(["-i", "-n", "-s", "a.json"])
    long = parser.parse_args(["--ignore-history", "--no-stats", "--strict", "a.json"])

    assert (short.ignore_history, short.no_stats, short.strict) == (True, True, True)
    assert vars(short) == vars(long)


def test_short_flags_combine_in_any_order() -> None:
    # Single-character store_true flags are what makes a cluster possible, so
    # this pins the property rather than the three spellings below: a flag that
    # grew a value or a second character would silently break "-ins" in a cron
    # entry that already uses it.
    parser = cli.build_parser()
    expected = vars(parser.parse_args(["-i", "-n", "-s", "a.json"]))

    for cluster in ("-ins", "-sin", "-nsi"):
        assert vars(parser.parse_args([cluster, "a.json"])) == expected

    # A cluster still has to be wholly valid.
    with pytest.raises(SystemExit):
        parser.parse_args(["-inx", "a.json"])


def test_flags_are_accepted_before_or_after_the_targets() -> None:
    parser = cli.build_parser()

    leading = parser.parse_args(["-ns", "/archives/a.json", "/archives/b.json"])
    trailing = parser.parse_args(["/archives/a.json", "/archives/b.json", "-ns"])

    assert vars(leading) == vars(trailing)
    assert leading.targets == ["/archives/a.json", "/archives/b.json"]


def test_cli_exposes_no_engine_switch() -> None:
    # Template mining is the grouping engine, not a mode, so there is nothing
    # to select. A stale --template-mining in a cron entry must fail loudly
    # rather than be accepted as a no-op.
    parser = cli.build_parser()
    assert not hasattr(parser.parse_args(["a.json"]), "template_mining")
    with pytest.raises(SystemExit):
        parser.parse_args(["--template-mining", "a.json"])


def test_cli_forwards_parsing_mode_to_the_analysis(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    archive = tmp_path / "archive.json.gz"
    archive.touch()
    received: list[dict] = []

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(
        cli,
        "analyze_archive",
        lambda path, **kwargs: received.append(kwargs) or _analysis(path),
    )
    monkeypatch.setattr(cli, "render_report", lambda _analysis: "report\n")

    assert cli.main(["--strict", str(archive)]) == 0
    assert received == [{"alert_threshold": 3, "skip_malformed": False}]
    capsys.readouterr()


def _analysis(path: Path) -> ArchiveAnalysis:
    return ArchiveAnalysis(
        path=path,
        total_events=1,
        malformed_lines=0,
        status_counts=(),
        log_type_counts=(),
        findings=(
            Finding(
                finding_key="key",
                observed_status="no_alerting_rule",
                log_type="sshd",
                message_pattern="sample",
                event_count=1,
                affected_agents=1,
                first_seen=None,
                last_seen=None,
                observed_decoder="sshd",
                observed_rule_id=None,
                observed_rule_level=None,
                sample_log="raw sample",
            ),
        ),
    )


def test_no_stats_keeps_stdout_machine_clean(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    archive = tmp_path / "archive.json.gz"
    archive.touch()
    added: list[Path] = []

    class FakeHistory:
        def __init__(self, _path: Path) -> None:
            pass

        def contains(self, _path: Path) -> bool:
            return False

        def add(self, path: Path) -> None:
            added.append(path)

    monkeypatch.setattr(cli, "History", FakeHistory)
    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(path))

    assert cli.main(["--no-stats", str(archive)]) == 0
    captured = capsys.readouterr()
    assert captured.out == "raw sample\n"
    assert "Processing" in captured.err
    assert "Processed: 1" in captured.err
    assert added == [archive]


def test_ignore_history_processes_hit_and_retains_history(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    archive = tmp_path / "archive.json.gz"
    archive.touch()
    added: list[Path] = []
    analyzed: list[Path] = []

    class FakeHistory:
        def __init__(self, _path: Path) -> None:
            pass

        def contains(self, _path: Path) -> bool:
            return True

        def add(self, path: Path) -> None:
            added.append(path)

    monkeypatch.setattr(cli, "History", FakeHistory)
    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(
        cli,
        "analyze_archive",
        lambda path, **_kwargs: analyzed.append(path) or _analysis(path),
    )
    monkeypatch.setattr(cli, "render_report", lambda _analysis: "report\n")

    assert cli.main(["--ignore-history", str(archive)]) == 0
    assert analyzed == [archive]
    assert added == [archive]


def test_history_hit_is_skipped(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    archive = tmp_path / "archive.json.gz"
    archive.touch()

    class FakeHistory:
        def __init__(self, _path: Path) -> None:
            pass

        def contains(self, _path: Path) -> bool:
            return True

        def add(self, _path: Path) -> None:
            raise AssertionError("skipped archive must not be added")

    monkeypatch.setattr(cli, "History", FakeHistory)
    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "analyze_archive", lambda *_args, **_kwargs: pytest.fail("archive should be skipped"))

    assert cli.main([str(archive)]) == 0


def test_broken_pipe_does_not_update_history(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    archive = tmp_path / "archive.json.gz"
    archive.touch()
    added: list[Path] = []

    class FakeHistory:
        def __init__(self, _path: Path) -> None:
            pass

        def contains(self, _path: Path) -> bool:
            return False

        def add(self, path: Path) -> None:
            added.append(path)

    class BrokenPipeStdout:
        def write(self, _text: str) -> int:
            return len(_text)

        def flush(self) -> None:
            raise BrokenPipeError

    monkeypatch.setattr(cli, "History", FakeHistory)
    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(path))
    monkeypatch.setattr(cli.sys, "stdout", BrokenPipeStdout())

    assert cli.main(["--no-stats", str(archive)]) == 1
    assert added == []
    assert isinstance(cli.sys.stdout, io.StringIO)


def test_no_stats_emits_exactly_one_row_per_finding(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    archive = tmp_path / "archive.json.gz"
    archive.touch()

    class FakeHistory:
        def __init__(self, _path: Path) -> None:
            pass

        def contains(self, _path: Path) -> bool:
            return False

        def add(self, path: Path) -> None:
            pass

    analysis = _analysis(archive)
    findings = analysis.findings + (
        Finding(
            finding_key="second",
            observed_status="no_decoder",
            log_type="/var/log/app.log",
            message_pattern="pattern",
            event_count=1,
            affected_agents=1,
            first_seen=None,
            last_seen=None,
            observed_decoder=None,
            observed_rule_id=None,
            observed_rule_level=None,
            sample_log="another raw sample",
        ),
    )
    analysis = replace(analysis, findings=findings)

    monkeypatch.setattr(cli, "History", FakeHistory)
    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: analysis)

    assert cli.main(["--no-stats", str(archive)]) == 0
    captured = capsys.readouterr()

    # The stdout contract for the logtest pipe: one log per line, so the row
    # count and the finding count must agree exactly.
    assert captured.out.splitlines() == ["raw sample", "another raw sample"]
    assert len(captured.out.splitlines()) == len(analysis.findings)
