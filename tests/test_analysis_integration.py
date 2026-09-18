import gzip
import json
from pathlib import Path

import pytest

from wazuhcoverage import analyze_archive


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")


def _write_jsonl_gz(path: Path, rows: list[dict]) -> None:
    with gzip.open(path, "wt", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")


def _fixture_rows() -> list[dict]:
    return [
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
    ]


def test_analysis_classifies_and_groups_findings(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(archive, _fixture_rows())

    result = analyze_archive(archive)
    counts = {item.status: item.event_count for item in result.status_counts}

    assert result.total_events == 5
    assert counts == {
        "no_decoder": 2,
        "no_rule": 1,
        "below_threshold": 1,
        "at_or_above_threshold": 1,
    }
    assert sum(counts.values()) == result.total_events

    no_decoder = [finding for finding in result.findings if finding.observed_status == "no_decoder"]
    assert len(no_decoder) == 1
    assert no_decoder[0].event_count == 2
    assert no_decoder[0].affected_agents == 2


def test_rule_without_usable_level_is_below_threshold(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {
                "full_log": "missing level",
                "decoder": {"name": "json"},
                "rule": {"id": "100"},
            },
            {
                "full_log": "invalid level",
                "decoder": {"name": "json"},
                "rule": {"id": "101", "level": "not-a-number"},
            },
        ],
    )

    result = analyze_archive(str(archive))
    counts = {item.status: item.event_count for item in result.status_counts}
    assert counts["below_threshold"] == 2
    assert counts["at_or_above_threshold"] == 0


def test_below_threshold_rule_does_not_claim_one_log_type(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {
                "full_log": "first",
                "decoder": {"name": "decoder-a"},
                "rule": {"id": "200", "level": 1},
            },
            {
                "full_log": "second",
                "decoder": {"name": "decoder-b"},
                "rule": {"id": "200", "level": 1},
            },
        ],
    )

    result = analyze_archive(archive)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.observed_status == "below_threshold"
    assert finding.observed_rule_id == "200"
    assert finding.log_type is None
    assert finding.event_count == 2


def test_compressed_and_uncompressed_archives_match(tmp_path: Path) -> None:
    rows = _fixture_rows()
    plain = tmp_path / "archives.json"
    compressed = tmp_path / "archives.json.gz"
    _write_jsonl(plain, rows)
    _write_jsonl_gz(compressed, rows)

    plain_result = analyze_archive(plain)
    compressed_result = analyze_archive(compressed)

    assert plain_result.total_events == compressed_result.total_events
    assert plain_result.status_counts == compressed_result.status_counts
    assert plain_result.log_type_counts == compressed_result.log_type_counts
    assert [f.finding_key for f in plain_result.findings] == [f.finding_key for f in compressed_result.findings]


def test_empty_archive_returns_zero_counts(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    archive.touch()

    result = analyze_archive(archive)
    assert result.total_events == 0
    assert all(item.event_count == 0 for item in result.status_counts)
    assert result.log_type_counts == ()
    assert result.findings == ()


def test_malformed_json_is_not_silently_ignored(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    archive.write_text('{"full_log": "valid"}\n{not-json}\n', encoding="utf-8")

    with pytest.raises(Exception):
        analyze_archive(archive)


def test_representative_sample_is_deterministic(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {"full_log": "event 67890", "decoder": {}},
            {"full_log": "event 12345", "decoder": {}},
        ],
    )

    first = analyze_archive(archive)
    second = analyze_archive(archive)
    assert first.findings[0].sample_log == second.findings[0].sample_log == "event 12345"


def test_normalization_retains_security_semantic_values(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {"full_log": "source=10.0.0.1 port=22 event=4625 id=12345", "decoder": {}},
            {"full_log": "source=10.0.0.2 port=22 event=4625 id=67890", "decoder": {}},
        ],
    )

    result = analyze_archive(archive)
    assert len(result.findings) == 2
    patterns = {finding.message_pattern for finding in result.findings}
    assert any("10.0.0.1" in pattern and "port=22" in pattern and "event=4625" in pattern for pattern in patterns)
    assert any("10.0.0.2" in pattern and "port=22" in pattern and "event=4625" in pattern for pattern in patterns)
    assert all("id=<NUM>" in pattern for pattern in patterns)
