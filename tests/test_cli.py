import gzip
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


def test_version_flag_prints_the_package_version(capsys) -> None:
    import wazuhcoverage

    for flag in ("-V", "--version"):
        with pytest.raises(SystemExit) as exit_info:
            cli.build_parser().parse_args([flag])

        assert exit_info.value.code == 0
        assert capsys.readouterr().out.strip() == f"wazuhcoverage {wazuhcoverage.__version__}"


def test_version_needs_no_target() -> None:
    # TARGET is nargs="+", so anything that reads as a normal flag would make
    # "wazuhcoverage --version" fail on a missing argument. The version action
    # prints and exits before that check, which is the point of using it.
    with pytest.raises(SystemExit) as exit_info:
        cli.build_parser().parse_args(["--version"])

    assert exit_info.value.code == 0


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


class _PipedStdin:
    """A stdin that is a pipe carrying ``data``."""

    def __init__(self, data: bytes) -> None:
        self.buffer = io.BytesIO(data)

    def isatty(self) -> bool:
        return False


class _TerminalStdin:
    def __init__(self) -> None:
        self.buffer = io.BytesIO(b"")

    def isatty(self) -> bool:
        return True


def test_targets_are_optional_so_a_pipe_can_supply_one() -> None:
    assert cli.build_parser().parse_args(["-sin"]).targets == []


def test_a_piped_archive_is_analyzed_without_a_target(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    rows = b'{"full_log": "piped", "decoder": {"name": "sshd"}}\n'
    scanned: list[Path] = []

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli.sys, "stdin", _PipedStdin(rows))
    monkeypatch.setattr(
        cli,
        "analyze_archive",
        lambda path, **_kwargs: scanned.append(Path(path)) or _analysis(Path(path)),
    )

    assert cli.main(["-n"]) == 0

    captured = capsys.readouterr()
    assert captured.out == "raw sample\n"
    assert "Processing standard input" in captured.err
    assert "Matched: 1 | Processed: 1" in captured.err

    # The stream was spooled to a real file that DuckDB could have scanned,
    # and that file does not outlive the run.
    assert len(scanned) == 1
    assert not scanned[0].exists()


def test_a_dash_target_reads_the_pipe_explicitly(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli.sys, "stdin", _PipedStdin(b'{"full_log": "piped"}\n'))
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(Path(path)))

    assert cli.main(["-n", "-"]) == 0
    assert capsys.readouterr().out == "raw sample\n"


def test_a_piped_report_is_labelled_stdin_not_a_temporary_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    # The spooled path is a per-run temporary name. Printing it would make two
    # runs over the same stream produce different reports and would name a file
    # the reader cannot open.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli.sys, "stdin", _PipedStdin(b'{"full_log": "piped"}\n'))
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(Path(path)))

    assert cli.main([]) == 0

    out = capsys.readouterr().out
    assert "Archive: <stdin>" in out
    assert "wazuhcoverage-stdin-" not in out


def test_a_gzipped_pipe_is_spooled_under_a_gz_name(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    # DuckDB chooses its decompressor from the extension, so the sniffed magic
    # number has to reach the spooled file's name or a compressed pipe is read
    # as binary garbage.
    payload = gzip.compress(b'{"full_log": "piped"}\n')
    suffixes: list[str] = []

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli.sys, "stdin", _PipedStdin(payload))
    monkeypatch.setattr(
        cli,
        "analyze_archive",
        lambda path, **_kwargs: suffixes.append("".join(Path(path).suffixes)) or _analysis(Path(path)),
    )

    assert cli.main(["-n"]) == 0
    assert suffixes == [".json.gz"]
    capsys.readouterr()


def test_a_plain_pipe_is_spooled_byte_for_byte(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    # The first bytes are consumed to sniff for gzip and must be written back,
    # or every uncompressed archive loses its first two characters.
    rows = b'{"full_log": "first"}\n{"full_log": "second"}\n'
    spooled: list[bytes] = []

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli.sys, "stdin", _PipedStdin(rows))
    monkeypatch.setattr(
        cli,
        "analyze_archive",
        lambda path, **_kwargs: spooled.append(Path(path).read_bytes()) or _analysis(Path(path)),
    )

    assert cli.main(["-n"]) == 0
    assert spooled == [rows]
    capsys.readouterr()


def test_a_terminal_without_a_target_asks_for_one(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli.sys, "stdin", _TerminalStdin())
    monkeypatch.setattr(cli, "analyze_archive", lambda *_args, **_kwargs: pytest.fail("nothing to analyze"))

    assert cli.main([]) == 2
    assert "no target given" in capsys.readouterr().err


def test_a_piped_archive_is_never_recorded_in_history(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    # A stream has no stable path, so it can be neither looked up nor stored.
    # Recording the spooled temporary name would grow history.db without ever
    # skipping anything.
    class FakeHistory:
        def __init__(self, _path: Path) -> None:
            pass

        def contains(self, _path: Path) -> bool:
            raise AssertionError("a stream must not be looked up in history")

        def add(self, _path: Path) -> None:
            raise AssertionError("a stream must not be recorded in history")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "History", FakeHistory)
    monkeypatch.setattr(cli.sys, "stdin", _PipedStdin(b'{"full_log": "piped"}\n'))
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(Path(path)))

    assert cli.main(["-n"]) == 0
    capsys.readouterr()


def test_a_failing_stream_still_leaves_no_temporary_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    seen: list[Path] = []

    def explode(path, **_kwargs):
        seen.append(Path(path))
        raise RuntimeError("boom")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli.sys, "stdin", _PipedStdin(b"not json\n"))
    monkeypatch.setattr(cli, "analyze_archive", explode)

    assert cli.main(["-n"]) == 1
    assert seen and not seen[0].exists()
    assert "failed <stdin>" in capsys.readouterr().err


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
    monkeypatch.setattr(cli, "render_report", lambda _analysis, _verifications=(): "report\n")

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
                observed_location="syslog",
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
    monkeypatch.setattr(cli, "render_report", lambda _analysis, _verifications=(): "report\n")

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
            observed_location="syslog",
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


def test_logtest_joins_the_short_flag_cluster() -> None:
    parser = cli.build_parser()

    expected = vars(parser.parse_args(["-i", "-n", "-s", "-l", "a.json"]))
    for cluster in ("-insl", "-lsni", "-sil", "-nl"):
        merged = vars(parser.parse_args([cluster, "a.json"]))
        assert all(merged[flag] for flag in _flags_in(cluster))

    assert vars(parser.parse_args(["-insl", "a.json"])) == expected
    assert parser.parse_args(["a.json"]).logtest is False


def _flags_in(cluster: str) -> list[str]:
    names = {"i": "ignore_history", "n": "no_stats", "s": "strict", "l": "logtest"}
    return [names[letter] for letter in cluster.lstrip("-")]


def test_logtest_options_have_documented_defaults() -> None:
    args = cli.build_parser().parse_args(["a.json"])

    assert args.log_format == "syslog"
    assert args.logtest_socket is None


def test_an_unreachable_daemon_stops_before_any_archive_is_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    # Scanning thirty archives and only then failing on a socket that was
    # never going to answer is the expensive way to learn about a typo.
    archive = tmp_path / "archive.json.gz"
    archive.touch()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "analyze_archive", lambda *_args, **_kwargs: pytest.fail("must not scan"))
    monkeypatch.setattr(cli, "_check_logtest", _refuse_logtest)

    assert cli.main(["--logtest", str(archive)]) == 2
    assert "not accepting connections" in capsys.readouterr().err


def _refuse_logtest(_socket_path) -> None:
    raise RuntimeError("the wazuh-logtest socket at /var/ossec/queue/sockets/logtest is not accepting connections.")


def test_logtest_options_reach_the_verifier(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    archive = tmp_path / "archive.json.gz"
    archive.touch()
    received: list[dict] = []

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(Path(path)))
    monkeypatch.setattr(cli, "_check_logtest", lambda _socket_path: None)
    monkeypatch.setattr(cli, "verify_findings", lambda analysis, **kwargs: received.append(kwargs) or ())
    monkeypatch.setattr(cli, "render_report", lambda _analysis, _verifications=(): "report\n")

    assert cli.main(["--logtest", "--log-format", "json", "--logtest-socket", "/tmp/s", str(archive)]) == 0
    assert received == [{"alert_threshold": 3, "log_format": "json", "socket_path": "/tmp/s"}]
    capsys.readouterr()


def test_without_logtest_nothing_is_replayed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    archive = tmp_path / "archive.json.gz"
    archive.touch()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(Path(path)))
    monkeypatch.setattr(cli, "_check_logtest", lambda _socket_path: pytest.fail("must not probe the daemon"))
    monkeypatch.setattr(cli, "verify_findings", lambda *_args, **_kwargs: pytest.fail("must not replay"))

    assert cli.main(["--no-stats", str(archive)]) == 0
    capsys.readouterr()
