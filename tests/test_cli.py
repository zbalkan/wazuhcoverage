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
    assert args.template_mining is False
    assert args.targets == ["/archives/**/*.json.gz", "/other/a.json.gz"]


def test_template_mining_flag_defaults_off_and_parses() -> None:
    assert cli.build_parser().parse_args(["a.json"]).template_mining is False
    assert cli.build_parser().parse_args(["--template-mining", "a.json"]).template_mining is True


def test_cli_forwards_template_mining_to_the_analysis(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
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

    assert cli.main(["--template-mining", str(archive)]) == 0
    assert received == [{"alert_threshold": 3, "skip_malformed": True, "template_mining": True}]
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
                observed_status="no_rule",
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


def test_no_stats_emits_exactly_one_row_per_finding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
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
