from pathlib import Path
import pytest

from wazuhcoverage import ArchiveAnalysis, Finding, cli


def test_cli_flags_and_targets() -> None:
    args = cli.build_parser().parse_args(
        ["--ignore-history", "--no-stats", "/archives/**/*.json.gz", "/other/a.json.gz"]
    )

    assert args.ignore_history is True
    assert args.no_stats is True
    assert args.targets == ["/archives/**/*.json.gz", "/other/a.json.gz"]


def _analysis(path: Path) -> ArchiveAnalysis:
    return ArchiveAnalysis(
        path=path,
        total_events=1,
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
    monkeypatch.setattr(cli, "analyze_archive", lambda path, alert_threshold: _analysis(path))

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
        lambda path, alert_threshold: analyzed.append(path) or _analysis(path),
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
    monkeypatch.setattr(cli, "analyze_archive", lambda path, alert_threshold: _analysis(path))
    monkeypatch.setattr(cli.sys, "stdout", BrokenPipeStdout())

    assert cli.main(["--no-stats", str(archive)]) == 1
    assert added == []
