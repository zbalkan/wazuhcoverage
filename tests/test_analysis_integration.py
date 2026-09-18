import importlib.util
import json
from pathlib import Path

import pytest

from wazuhcoverage.analysis import analyze_archive

pytestmark = pytest.mark.skipif(importlib.util.find_spec("duckdb") is None, reason="duckdb is not installed")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")


def test_analysis_classifies_and_groups_findings(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {
                "timestamp": "2026-09-18T10:00:00+00:00",
                "agent": {"id": "001", "name": "a"},
                "location": "/var/log/app.log",
                "full_log": "app transaction 12345 failed",
                "decoder": {},
            },
            {
                "timestamp": "2026-09-18T10:00:01+00:00",
                "agent": {"id": "002", "name": "b"},
                "location": "/var/log/app.log",
                "full_log": "app transaction 67890 failed",
                "decoder": {},
            },
            {
                "timestamp": "2026-09-18T10:00:02+00:00",
                "agent": {"id": "001", "name": "a"},
                "location": "syslog",
                "full_log": "sshd unknown message",
                "decoder": {"name": "sshd"},
            },
            {
                "timestamp": "2026-09-18T10:00:03+00:00",
                "agent": {"id": "001", "name": "a"},
                "location": "syslog",
                "full_log": "sshd low level",
                "decoder": {"name": "sshd"},
                "rule": {"id": "100", "level": 2, "description": "low"},
            },
            {
                "timestamp": "2026-09-18T10:00:04+00:00",
                "agent": {"id": "001", "name": "a"},
                "location": "syslog",
                "full_log": "sshd alert",
                "decoder": {"name": "sshd"},
                "rule": {"id": "101", "level": 5, "description": "alert"},
            },
        ],
    )

    result = analyze_archive(archive)
    counts = {item.status: item.event_count for item in result.status_counts}

    assert result.total_events == 5
    assert counts == {
        "no_decoder": 2,
        "no_rule": 1,
        "below_threshold": 1,
        "at_or_above_threshold": 1,
    }

    no_decoder = [finding for finding in result.findings if finding.observed_status == "no_decoder"]
    assert len(no_decoder) == 1
    assert no_decoder[0].event_count == 2
    assert no_decoder[0].affected_agents == 2
