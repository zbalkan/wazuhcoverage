"""Command-line interface for wazuhcoverage."""

from __future__ import annotations

import argparse
import io
import os
import sys
from pathlib import Path
from typing import Optional

from wazuhcoverage.analysis import DEFAULT_ALERT_THRESHOLD, analyze_archive
from wazuhcoverage.history import History
from wazuhcoverage.report import render_report
from wazuhcoverage.targets import resolve_targets

HISTORY_FILE = Path("history.db")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wazuhcoverage",
        description="Analyze Wazuh JSON archives and emit coverage statistics or representative samples.",
    )
    parser.add_argument(
        "--ignore-history",
        action="store_true",
        help="Process matching archives even when they are already present in history.db.",
    )
    parser.add_argument(
        "--no-stats",
        action="store_true",
        help="Write only one representative sample per finding to stdout; suitable for piping to logtest.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail an archive on the first unparseable line instead of skipping and counting it.",
    )
    parser.add_argument(
        "targets",
        nargs="+",
        metavar="TARGET",
        help="Archive file path or glob pattern. Recursive ** patterns are supported.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    targets = resolve_targets(args.targets)

    if not targets:
        print("wazuhcoverage: no files matched the supplied targets", file=sys.stderr)
        return 2

    try:
        history = History(HISTORY_FILE)
    except (OSError, ValueError) as exc:
        print(f"wazuhcoverage: cannot read {HISTORY_FILE}: {exc}", file=sys.stderr)
        return 2

    processed = 0
    skipped = 0
    failed = 0

    for archive in targets:
        if not args.ignore_history and history.contains(archive):
            skipped += 1
            continue

        print(f"Processing {archive}", file=sys.stderr)

        try:
            analysis = analyze_archive(
                archive,
                alert_threshold=DEFAULT_ALERT_THRESHOLD,
                skip_malformed=not args.strict,
            )

            # Surface the loss on stderr too: with --no-stats the report that
            # carries this count is never rendered, and a silently shrunken
            # denominator is exactly what makes coverage numbers untrustworthy.
            if analysis.malformed_lines:
                print(
                    f"wazuhcoverage: skipped {analysis.malformed_lines} unparseable line(s) in {archive}",
                    file=sys.stderr,
                )

            if args.no_stats:
                for finding in analysis.findings:
                    sys.stdout.write(f"{finding.sample_log}\n")
            else:
                sys.stdout.write(render_report(analysis))

            # A successful flush is part of successful processing. This matters
            # when stdout is a pipe and the downstream consumer exits early.
            sys.stdout.flush()

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

    print(
        f"Matched: {len(targets)} | Processed: {processed} | Skipped: {skipped} | Failed: {failed}",
        file=sys.stderr,
    )
    return 1 if failed else 0


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
