import gzip
import io
from dataclasses import replace
from pathlib import Path

import pytest

from wazuhcoverage import ArchiveAnalysis, Finding, cli


def test_cli_flags_and_targets() -> None:
    args = cli.build_parser().parse_args(["--no-stats", "/archives/**/*.json.gz", "/other/a.json.gz"])

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


@pytest.mark.parametrize("version_flag", ["-V", "--version"])
@pytest.mark.parametrize("other_flag", ["-n", "--strict", "-f"])
def test_version_warns_when_combined_with_another_flag(
    version_flag: str, other_flag: str, capsys
) -> None:
    arguments = [version_flag, other_flag]
    if other_flag == "-f":
        arguments.append("json")

    with pytest.raises(SystemExit) as exit_info:
        cli.build_parser().parse_args(arguments)

    captured = capsys.readouterr()
    assert exit_info.value.code == 0
    assert captured.out.strip().startswith("wazuhcoverage ")
    assert "warning: -V/--version cannot be combined with other flags" in captured.err


def test_version_does_not_warn_for_a_target(capsys) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.build_parser().parse_args(["archive.json", "--version"])

    assert exit_info.value.code == 0
    assert capsys.readouterr().err == ""


def test_short_flags_mirror_the_long_ones() -> None:
    parser = cli.build_parser()

    short = parser.parse_args(["-n", "-s", "a.json"])
    long = parser.parse_args(["--no-stats", "--strict", "a.json"])

    assert (short.no_stats, short.strict) == (True, True)
    assert vars(short) == vars(long)


def test_short_flags_combine_in_any_order() -> None:
    # Single-character store_true flags are what makes a cluster possible, so
    # this pins the property rather than the three spellings below: a flag that
    # grew a value or a second character would silently break "-ins" in a cron
    # entry that already uses it.
    parser = cli.build_parser()
    expected = vars(parser.parse_args(["-n", "-s", "a.json"]))

    for cluster in ("-ns", "-sn"):
        assert vars(parser.parse_args([cluster, "a.json"])) == expected

    # A cluster still has to be wholly valid.
    with pytest.raises(SystemExit):
        parser.parse_args(["-nsx", "a.json"])


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
    assert cli.build_parser().parse_args(["-sn"]).targets == []


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


def test_no_run_writes_persistent_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    # A run must leave the working directory exactly as it found it: no
    # cache, no lock file, no stray temporary.
    archive = tmp_path / "archive.json.gz"
    archive.touch()
    before = set(tmp_path.iterdir())

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(path))
    monkeypatch.setattr(cli, "render_report", lambda _analysis, _verifications=(), **_kwargs: "report\n")

    assert cli.main([str(archive)]) == 0
    assert set(tmp_path.iterdir()) == before
    capsys.readouterr()


def test_the_same_archive_is_processed_every_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    archive = tmp_path / "archive.json.gz"
    archive.touch()
    analyzed: list[Path] = []

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: analyzed.append(path) or _analysis(path))
    monkeypatch.setattr(cli, "render_report", lambda _analysis, _verifications=(), **_kwargs: "report\n")

    assert cli.main([str(archive)]) == 0
    assert cli.main([str(archive)]) == 0
    assert analyzed == [archive, archive]
    capsys.readouterr()


def test_repeated_targets_are_still_read_once(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    # Dedup within a run never depended on the cache: resolving targets
    # collapses overlapping globs to a set of absolute paths.
    archive = tmp_path / "archive.json.gz"
    archive.write_text("{}\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(Path(path)))
    monkeypatch.setattr(cli, "render_report", lambda _analysis, _verifications=(), **_kwargs: "report\n")

    assert cli.main([str(archive), str(archive), "*.json.gz"]) == 0
    assert "Matched: 1 | Processed: 1 | Failed: 0" in capsys.readouterr().err


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
    monkeypatch.setattr(cli, "render_report", lambda _analysis, _verifications=(), **_kwargs: "report\n")

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

    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(path))

    assert cli.main(["--no-stats", str(archive)]) == 0
    captured = capsys.readouterr()
    assert captured.out == "raw sample\n"
    assert "Processing" in captured.err
    assert "Processed: 1" in captured.err


def test_a_broken_pipe_stops_the_run_and_silences_stdout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # A downstream consumer that exits early must not leave the interpreter
    # flushing into a dead pipe at shutdown, which would turn the exit status
    # into 120 regardless of what happened here.
    archive = tmp_path / "archive.json.gz"
    archive.touch()

    class BrokenPipeStdout:
        def write(self, _text: str) -> int:
            return len(_text)

        def flush(self) -> None:
            raise BrokenPipeError

    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(path))
    monkeypatch.setattr(cli.sys, "stdout", BrokenPipeStdout())

    assert cli.main(["--no-stats", str(archive)]) == 1
    assert isinstance(cli.sys.stdout, io.StringIO)


def test_no_stats_emits_exactly_one_row_per_finding(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    archive = tmp_path / "archive.json.gz"
    archive.touch()

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

    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: analysis)

    assert cli.main(["--no-stats", str(archive)]) == 0
    captured = capsys.readouterr()

    # The stdout contract for the logtest pipe: one log per line, so the row
    # count and the finding count must agree exactly.
    assert captured.out.splitlines() == ["raw sample", "another raw sample"]
    assert len(captured.out.splitlines()) == len(analysis.findings)


def test_there_is_no_flag_to_select_replay() -> None:
    # Replay is decided by what the machine can reach, not by an argument, so
    # a script carrying -l or --logtest must stop rather than run with a flag
    # that means nothing.
    parser = cli.build_parser()
    assert not hasattr(parser.parse_args(["a.json"]), "logtest")
    for argument in ("--logtest", "-l", "--logtest-socket=/tmp/s"):
        with pytest.raises(SystemExit):
            parser.parse_args([argument, "a.json"])


def test_there_is_no_flag_to_ignore_history() -> None:
    # -i/--ignore-history went with the processed-path cache. A run keeps no
    # state, so there is nothing left to ignore, and a script or a README
    # example still carrying the flag must stop rather than appear to work.
    parser = cli.build_parser()
    assert not hasattr(parser.parse_args(["a.json"]), "ignore_history")
    for argument in ("--ignore-history", "-i", "-sin"):
        with pytest.raises(SystemExit):
            parser.parse_args([argument, "a.json"])


def test_the_documented_short_flags_still_cluster() -> None:
    # The README pipes an archive in as `wazuhcoverage -sn`, which only works
    # while both flags stay single-character store_true options.
    arguments = cli.build_parser().parse_args(["-sn"])

    assert (arguments.strict, arguments.no_stats) == (True, True)
    assert arguments.targets == []


def test_log_format_keeps_its_documented_default() -> None:
    assert cli.build_parser().parse_args(["a.json"]).log_format == "syslog"


def test_log_format_has_a_short_form() -> None:
    parser = cli.build_parser()

    assert parser.parse_args(["-f", "json", "a.json"]).log_format == "json"
    assert parser.parse_args(["--log-format", "json", "a.json"]).log_format == "json"


def test_the_short_log_format_closes_a_cluster() -> None:
    # -f takes a value, so argparse reads the rest of the cluster as that
    # value. Closing a cluster is the only position where it means what the
    # README says it means, in either the separated or the attached spelling.
    parser = cli.build_parser()

    for argv in (["-snf", "json", "a.json"], ["-snfjson", "a.json"]):
        arguments = parser.parse_args(argv)
        assert (arguments.strict, arguments.no_stats, arguments.log_format) == (True, True, "json")
        assert arguments.targets == ["a.json"]


def test_a_mid_cluster_log_format_swallows_the_rest_of_the_cluster() -> None:
    # Documented rather than defended against: this is how getopt has always
    # treated an option with an argument. The test exists so the README's
    # warning cannot drift away from what the parser actually does.
    arguments = cli.build_parser().parse_args(["-fsn", "json", "a.json"])

    assert arguments.log_format == "sn"
    assert (arguments.strict, arguments.no_stats) == (False, False)
    assert arguments.targets == ["json", "a.json"]


def test_a_reachable_daemon_is_used_without_being_asked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    archive = tmp_path / "archive.json.gz"
    archive.touch()
    received: list[dict] = []

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(Path(path)))
    monkeypatch.setattr(cli, "unavailable_reason", lambda: None)
    monkeypatch.setattr(cli, "read_alert_threshold", lambda: 7)
    monkeypatch.setattr(cli, "verify_findings", lambda analysis, **kwargs: received.append(kwargs) or ())
    monkeypatch.setattr(cli, "render_report", lambda _analysis, _verifications=(), **_kwargs: "report\n")

    assert cli.main(["--log-format", "json", str(archive)]) == 0
    assert received == [{"alert_threshold": 7, "log_format": "json"}]
    assert "reporting from the archive alone" not in capsys.readouterr().err


def test_an_unusable_daemon_warns_once_and_keeps_going(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    # The whole point of best effort: a laptop with no Wazuh on it still gets
    # its coverage report, and is told what the report cannot answer.
    first = tmp_path / "a.json.gz"
    second = tmp_path / "b.json.gz"
    first.touch()
    second.touch()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [first, second])
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(Path(path)))
    monkeypatch.setattr(cli, "unavailable_reason", lambda: "wazuhtester is not installed")
    monkeypatch.setattr(cli, "verify_findings", lambda *_args, **_kwargs: pytest.fail("must not replay"))
    monkeypatch.setattr(cli, "render_report", lambda _analysis, _verifications=(), **_kwargs: "report\n")

    assert cli.main([str(first), str(second)]) == 0

    captured = capsys.readouterr()
    assert captured.out == "report\nreport\n"
    assert captured.err.count("reporting from the archive alone") == 1
    assert "wazuhtester is not installed" in captured.err
    assert "docs/CAVEATS.md" in captured.err
    assert "Processed: 2 | Failed: 0" in captured.err


def test_the_daemon_is_probed_once_not_per_archive(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    archives = [tmp_path / f"{name}.json.gz" for name in ("a", "b", "c")]
    for archive in archives:
        archive.touch()
    probes: list[int] = []

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: archives)
    monkeypatch.setattr(cli, "analyze_archive", lambda path, **_kwargs: _analysis(Path(path)))
    monkeypatch.setattr(cli, "unavailable_reason", lambda: probes.append(1) and None)
    monkeypatch.setattr(cli, "verify_findings", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(cli, "render_report", lambda _analysis, _verifications=(), **_kwargs: "report\n")

    assert cli.main([str(a) for a in archives]) == 0
    assert len(probes) == 1
    capsys.readouterr()


def test_the_probe_happens_before_the_first_archive_is_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    # A warning printed halfway down a report is a warning nobody reads.
    archive = tmp_path / "archive.json.gz"
    archive.touch()
    order: list[str] = []

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(
        cli,
        "analyze_archive",
        lambda path, **_kwargs: order.append("analyze") or _analysis(Path(path)),
    )
    monkeypatch.setattr(cli, "unavailable_reason", lambda: order.append("probe") or "no socket")
    monkeypatch.setattr(cli, "render_report", lambda _analysis, _verifications=(), **_kwargs: "report\n")

    assert cli.main([str(archive)]) == 0
    assert order == ["probe", "analyze"]
    capsys.readouterr()


def test_offline_run_assumes_wazuh_default_threshold(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    archive = tmp_path / "archive.json.gz"
    archive.touch()
    analyzed: list[dict] = []

    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: [archive])
    monkeypatch.setattr(cli, "unavailable_reason", lambda: "no manager")
    monkeypatch.setattr(
        cli,
        "read_alert_threshold",
        lambda: (_ for _ in ()).throw(FileNotFoundError("offline")),
    )
    monkeypatch.setattr(
        cli,
        "analyze_archive",
        lambda path, **kwargs: analyzed.append(kwargs) or _analysis(Path(path)),
    )

    assert cli.main([str(archive)]) == 0
    captured = capsys.readouterr()

    assert analyzed == [{"alert_threshold": 3, "skip_malformed": True}]
    assert "Alert threshold: 3 (Wazuh default assumed; could not read /var/ossec/etc/ossec.conf)" in captured.out


def test_online_run_reads_threshold_once_and_reports_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    archives = [tmp_path / "a.json.gz", tmp_path / "b.json.gz"]
    for archive in archives:
        archive.touch()

    reads: list[int] = []
    analyzed: list[dict] = []

    monkeypatch.setattr(cli, "resolve_targets", lambda _targets: archives)
    monkeypatch.setattr(cli, "unavailable_reason", lambda: None)
    monkeypatch.setattr(cli, "read_alert_threshold", lambda: reads.append(1) and 6)
    monkeypatch.setattr(
        cli,
        "analyze_archive",
        lambda path, **kwargs: analyzed.append(kwargs) or _analysis(Path(path)),
    )
    monkeypatch.setattr(cli, "verify_findings", lambda *_args, **_kwargs: ())

    assert cli.main([str(path) for path in archives]) == 0
    captured = capsys.readouterr()

    assert len(reads) == 1
    assert analyzed == [
        {"alert_threshold": 6, "skip_malformed": True},
        {"alert_threshold": 6, "skip_malformed": True},
    ]
    assert captured.out.count(
        "Alert threshold: 6 (from /var/ossec/etc/ossec.conf)"
    ) == 2


def test_online_run_assumes_default_when_threshold_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(cli, "read_alert_threshold", lambda: (_ for _ in ()).throw(PermissionError("denied")))

    threshold, source = cli._resolve_alert_threshold()
    captured = capsys.readouterr()

    assert threshold == 3
    assert "default assumed" in source
    assert "assuming Wazuh default alert threshold 3" in captured.err
