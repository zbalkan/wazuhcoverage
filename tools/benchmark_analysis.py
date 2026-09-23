"""Benchmark complete archive analysis on repeatable synthetic workloads.

Two cases isolate the behavior discussed in ``docs/design-notes.md``:

``realistic``
    Syslog-shaped authentication messages whose retained users, addresses,
    ports and PIDs produce a normalized vocabulary close to 80% of the event
    count, while their common shape still allows Drain to group them.

``unique``
    Same-length messages with no shared tokens after the timestamp. Every
    message creates a cluster and exercises the positional index, eviction,
    bulk loading, SQL grouping and report-model construction together.

Examples::

    PYTHONPATH=src python tools/benchmark_analysis.py --events 100000
    PYTHONPATH=src python tools/benchmark_analysis.py --events 1000000 --case unique
"""

from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path
from typing import Callable, Iterator

from wazuhcoverage import analyze_archive


def _realistic_rows(event_count: int) -> Iterator[dict]:
    vocabulary = max(1, (event_count * 4) // 5)
    for index in range(event_count):
        variant = index % vocabulary
        yield {
            "timestamp": f"2026-09-23T12:{index % 60:02d}:{index // 60 % 60:02d}+00:00",
            "agent": {"id": f"{index % 250:03d}", "name": f"host-{index % 250:03d}"},
            "location": "/var/log/secure",
            "full_log": (
                f"Sep 23 12:00:00 host-{variant % 997:03d} sshd[{10000 + variant}]: "
                f"Failed password for user-{variant % 4093} from "
                f"10.{variant // 65536 % 256}.{variant // 256 % 256}.{variant % 256} "
                f"port {1024 + variant % 64000} ssh2"
            ),
            "decoder": {},
        }


def _unique_rows(event_count: int) -> Iterator[dict]:
    for index in range(event_count):
        # Alphabetic IDs survive the production normalizer; decimal IDs of five
        # or more digits would intentionally collapse to ``<NUM>``.
        value = index
        label = ""
        while True:
            label = chr(ord("a") + value % 26) + label
            value = value // 26 - 1
            if value < 0:
                break
        unique_tokens = " ".join(f"token{position}-{label}" for position in range(10))
        yield {
            "location": "syslog",
            "full_log": f"Sep 23 12:00:00 {unique_tokens}",
            "decoder": {},
        }


CASES: dict[str, Callable[[int], Iterator[dict]]] = {
    "realistic": _realistic_rows,
    "unique": _unique_rows,
}


def _run(case: str, event_count: int, directory: Path) -> dict:
    archive = directory / f"{case}.json"
    with archive.open("w", encoding="utf-8") as stream:
        for row in CASES[case](event_count):
            stream.write(json.dumps(row, separators=(",", ":")) + "\n")

    started = time.perf_counter()
    result = analyze_archive(archive)
    elapsed = time.perf_counter() - started
    finding_events = sum(finding.event_count for finding in result.findings)
    if result.total_events != event_count or finding_events != event_count:
        raise RuntimeError(
            f"benchmark lost events: expected={event_count}, total={result.total_events}, findings={finding_events}"
        )
    expected_findings = event_count if case == "unique" else 1
    if len(result.findings) != expected_findings:
        raise RuntimeError(
            f"benchmark shape drifted: case={case}, expected_findings={expected_findings}, "
            f"actual_findings={len(result.findings)}"
        )
    return {
        "case": case,
        "events": event_count,
        "findings": len(result.findings),
        "seconds": round(elapsed, 3),
        "events_per_second": round(event_count / elapsed),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=100_000, help="events generated per case (default: 100000)")
    parser.add_argument("--case", choices=["both", *CASES], default="both", help="workload to run (default: both)")
    args = parser.parse_args()
    if args.events < 1:
        parser.error("--events must be positive")

    selected = list(CASES) if args.case == "both" else [args.case]
    with tempfile.TemporaryDirectory(prefix="wazuhcoverage-benchmark-") as temporary_directory:
        directory = Path(temporary_directory)
        for case in selected:
            print(json.dumps(_run(case, args.events, directory), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
