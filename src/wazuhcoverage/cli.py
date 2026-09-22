"""Command-line interface for wazuhcoverage."""

from __future__ import annotations

import argparse
import io
import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, Optional

from wazuhcoverage import __version__
from wazuhcoverage.analysis import DEFAULT_ALERT_THRESHOLD, analyze_archive
from wazuhcoverage.history import History
from wazuhcoverage.report import render_report
from wazuhcoverage.targets import resolve_targets
from wazuhcoverage.verification import DEFAULT_LOG_FORMAT, verify_findings

HISTORY_FILE = Path("history.db")

# The conventional spelling for "read the archive from standard input". It is
# also implied when no target is given and stdin is not a terminal, which is
# what makes `cat archive.json | wazuhcoverage -sin` work.
STDIN_TARGET = "-"

# What the report calls a piped archive. A spooled stream has a temporary path
# that means nothing to the reader and differs on every run, so the label is
# substituted at render time; the analysis itself still carries the real path
# it scanned.
STDIN_LABEL = Path("<stdin>")

# gzip's magic number. DuckDB picks its decompressor from the file extension,
# so a spooled stream has to be named for what it actually contains.
_GZIP_MAGIC = b"\x1f\x8b"


def build_parser() -> argparse.ArgumentParser:
    # The short behaviour flags are single-character store_true options, so
    # argparse accepts them merged into one cluster (-ins, -sin, -insl) as well
    # as separately. Keeping them single-character is what preserves that, and
    # the long forms stay the documented spelling for anything written into a
    # cron entry or a script. --log-format and --logtest-socket take values, so
    # they have no short form and cannot join a cluster.
    parser = argparse.ArgumentParser(
        prog="wazuhcoverage",
        description="Analyze Wazuh JSON archives and emit coverage statistics or representative samples.",
    )
    # --version is an argparse action rather than a flag on the namespace: it
    # prints and exits, so it never reaches main() and never has to be excluded
    # from the "targets are required" rule the way a store_true would.
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Print the installed version and exit.",
    )
    parser.add_argument(
        "-i",
        "--ignore-history",
        action="store_true",
        help="Process matching archives even when they are already present in history.db.",
    )
    parser.add_argument(
        "-n",
        "--no-stats",
        action="store_true",
        help="Write only one representative sample per finding to stdout; suitable for piping to logtest.",
    )
    parser.add_argument(
        "-s",
        "--strict",
        action="store_true",
        help="Fail an archive on the first unparseable line instead of skipping and counting it.",
    )
    parser.add_argument(
        "-l",
        "--logtest",
        action="store_true",
        help=(
            "Replay one sample per finding through wazuh-logtest and report its effective state. "
            "Needs the wazuhcoverage[logtest] extra and a reachable Wazuh manager."
        ),
    )
    parser.add_argument(
        "--log-format",
        default=DEFAULT_LOG_FORMAT,
        metavar="FORMAT",
        help=(
            "Log format reported to wazuh-logtest when replaying, e.g. syslog or json. "
            f"Default: {DEFAULT_LOG_FORMAT}. Only meaningful with --logtest."
        ),
    )
    parser.add_argument(
        "--logtest-socket",
        default=None,
        metavar="PATH",
        help="wazuh-logtest socket to replay against. Defaults to the Wazuh install location.",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        metavar="TARGET",
        help=(
            "Archive file path or glob pattern. Recursive ** patterns are supported. "
            "Use - to read one archive from standard input, which is also assumed when "
            "no target is given and stdin is a pipe."
        ),
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    paths = [target for target in args.targets if target != STDIN_TARGET]
    read_stdin = STDIN_TARGET in args.targets or (not args.targets and not _stdin_is_a_terminal())

    if not args.targets and not read_stdin:
        print(
            "wazuhcoverage: no target given; pass an archive path, or pipe an archive on stdin",
            file=sys.stderr,
        )
        return 2

    targets = resolve_targets(paths)

    if not targets and not read_stdin:
        print("wazuhcoverage: no files matched the supplied targets", file=sys.stderr)
        return 2

    try:
        history = History(HISTORY_FILE)
    except (OSError, ValueError) as exc:
        print(f"wazuhcoverage: cannot read {HISTORY_FILE}: {exc}", file=sys.stderr)
        return 2

    # A missing library or an unreachable daemon is a configuration fault, and
    # it is the same fault for every archive. Finding it after scanning thirty
    # of them, or worse, printing reports whose effective column is silently
    # absent, would be the expensive way to learn it.
    if args.logtest:
        try:
            _check_logtest(args.logtest_socket)
        except RuntimeError as exc:
            print(f"wazuhcoverage: {exc}", file=sys.stderr)
            return 2

    processed = 0
    skipped = 0
    failed = 0

    # Standard input runs first, and always runs: a stream has no stable path,
    # so it can neither be looked up in history nor recorded there. Piping the
    # same archive twice analyzes it twice, which is the only honest answer
    # when there is nothing to compare against.
    if read_stdin:
        print("Processing standard input", file=sys.stderr)
        try:
            with _spooled_stdin() as spooled:
                if spooled.stat().st_size == 0:
                    print("wazuhcoverage: read 0 bytes from stdin", file=sys.stderr)
                _report_one(spooled, STDIN_LABEL, args)
        except BrokenPipeError:
            _silence_broken_stdout()
            return 1
        except Exception as exc:  # noqa: BLE001 - a bad stream must not hide the file targets
            failed += 1
            print(f"wazuhcoverage: failed {STDIN_LABEL}: {exc}", file=sys.stderr)
        else:
            processed += 1

    for archive in targets:
        if not args.ignore_history and history.contains(archive):
            skipped += 1
            continue

        print(f"Processing {archive}", file=sys.stderr)

        try:
            _report_one(archive, archive, args)

            # History is updated only after analysis and output completed.
            history.add(archive)
            processed += 1

        except BrokenPipeError:
            # A closed downstream pipe means output did not complete, so do not
            # mark the current archive as processed. Redirect the underlying
            # descriptor before interpreter shutdown to avoid a second flush
            # changing the process exit status to 120.
            _silence_broken_stdout()
            return 1
        except Exception as exc:  # noqa: BLE001 - one bad archive should not block the rest
            failed += 1
            print(f"wazuhcoverage: failed {archive}: {exc}", file=sys.stderr)

    matched = len(targets) + (1 if read_stdin else 0)
    print(
        f"Matched: {matched} | Processed: {processed} | Skipped: {skipped} | Failed: {failed}",
        file=sys.stderr,
    )
    return 1 if failed else 0


def _report_one(archive: Path, label: Path, args: argparse.Namespace) -> None:
    """Analyze one archive and write its output, raising on failure.

    ``label`` is what the reader should see. It differs from ``archive`` only
    for a piped stream, whose spooled temporary path is meaningless in a report.
    """

    analysis = analyze_archive(
        archive,
        alert_threshold=DEFAULT_ALERT_THRESHOLD,
        skip_malformed=not args.strict,
    )

    verifications = ()
    if args.logtest:
        verifications = verify_findings(
            analysis,
            alert_threshold=DEFAULT_ALERT_THRESHOLD,
            log_format=args.log_format,
            socket_path=args.logtest_socket,
        )

    # Surface the loss on stderr too: with --no-stats the report that carries
    # this count is never rendered, and a silently shrunken denominator is
    # exactly what makes coverage numbers untrustworthy.
    if analysis.malformed_lines:
        print(
            f"wazuhcoverage: skipped {analysis.malformed_lines} unparseable line(s) in {label}",
            file=sys.stderr,
        )

    if args.no_stats:
        for finding in analysis.findings:
            sys.stdout.write(f"{finding.sample_log}\n")
    else:
        rendered = analysis if label == analysis.path else replace(analysis, path=label)
        sys.stdout.write(render_report(rendered, verifications))

    # A successful flush is part of successful processing. This matters when
    # stdout is a pipe and the downstream consumer exits early.
    sys.stdout.flush()


def _check_logtest(socket_path: Optional[str]) -> None:
    """Fail unless wazuh-logtest can actually be reached.

    verify_findings performs the same check per archive. Doing it once up
    front turns a per-archive failure into a refusal to start, which is what
    a configuration fault deserves.
    """

    from wazuhcoverage.verification import _load_wazuhtester

    wazuhtester = _load_wazuhtester()
    if not wazuhtester.is_logtest_available(socket_path):
        where = socket_path or wazuhtester.get_socket_path()
        raise RuntimeError(
            f"the wazuh-logtest socket at {where} is not accepting connections. "
            "Check that the Wazuh manager is running and that this user may read the socket, "
            "or set WAZUH_LOGTEST_SOCKET."
        )


def _stdin_is_a_terminal() -> bool:
    """Report whether stdin is an interactive terminal.

    A stdin that cannot answer is treated as a terminal, so an environment
    without one (a GUI launcher, a closed descriptor) asks for a target rather
    than silently analyzing an empty stream.
    """

    stream = sys.stdin
    if stream is None:
        return True
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError, ValueError):
        return True


@contextmanager
def _spooled_stdin() -> Iterator[Path]:
    """Copy stdin to a temporary file and yield its path.

    DuckDB scans a path and needs to seek within it, and a pipe offers neither,
    so a piped archive is spooled to disk first. The file is removed before
    this context manager returns, whatever the analysis did.

    The stream is sniffed for gzip's magic number and the temporary file is
    named ``.json.gz`` or ``.json`` to match, because DuckDB selects its
    decompressor from the extension. Spooling means a piped archive needs
    temporary space of its own size; pass the path directly to avoid that.
    """

    stream = _stdin_bytes()
    head = stream.read(len(_GZIP_MAGIC))
    suffix = ".json.gz" if head == _GZIP_MAGIC else ".json"

    handle, name = tempfile.mkstemp(prefix="wazuhcoverage-stdin-", suffix=suffix)
    path = Path(name)
    try:
        with os.fdopen(handle, "wb") as sink:
            if head:
                sink.write(head)
            shutil.copyfileobj(stream, sink)
        yield path
    finally:
        try:
            path.unlink()
        except OSError:  # pragma: no cover - the file is ours and was just written
            pass


def _stdin_bytes() -> Any:
    """Return the binary stdin stream.

    An archive is bytes: gzip detection has to see the magic number, and a
    decoding layer would corrupt a compressed stream outright.
    """

    stream = sys.stdin
    if stream is None:
        raise RuntimeError("standard input is not available")
    return getattr(stream, "buffer", stream)


def _silence_broken_stdout() -> None:
    """Redirect stdout to the null device after a downstream pipe closes."""

    try:
        stdout_fd = sys.stdout.fileno()
    except (AttributeError, OSError, ValueError):
        sys.stdout = io.StringIO()
        return

    null_fd = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(null_fd, stdout_fd)
    finally:
        os.close(null_fd)


if __name__ == "__main__":
    raise SystemExit(main())
