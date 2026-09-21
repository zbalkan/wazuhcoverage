import json
import sys
from pathlib import Path

import pytest

from wazuhcoverage import analyze_archive


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")


def _undecoded(full_log: str, agent_id: str = "001") -> dict:
    return {
        "timestamp": "2026-09-18T10:00:00+00:00",
        "agent": {"id": agent_id, "name": "host"},
        "location": "/var/log/secure",
        "full_log": full_log,
        "decoder": {},
    }


def _ssh_failures() -> list[dict]:
    # The normalizer deliberately retains short numbers, IPs and usernames, so
    # these five lines are five distinct patterns under regex normalization.
    return [
        _undecoded("Failed password for root from 10.0.0.1 port 2201 ssh2", "001"),
        _undecoded("Failed password for admin from 10.0.0.2 port 2202 ssh2", "002"),
        _undecoded("Failed password for jdoe from 10.0.0.3 port 2203 ssh2", "003"),
        _undecoded("Failed password for postgres from 10.0.0.4 port 2204 ssh2", "004"),
        _undecoded("Failed password for guest from 10.0.0.5 port 2205 ssh2", "005"),
    ]


def test_template_mining_collapses_variants_that_regex_normalization_keeps_apart(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(archive, _ssh_failures())

    regex_mode = analyze_archive(archive)
    template_mode = analyze_archive(archive, template_mining=True)

    # This is the whole point of the extra: categorical tokens (usernames, IPs,
    # short ports) cannot be masked by regex without enumerating them.
    assert len(regex_mode.findings) == 5
    assert len(template_mode.findings) == 1

    finding = template_mode.findings[0]
    assert finding.event_count == 5
    assert finding.affected_agents == 5
    assert "<*>" in finding.message_pattern
    # The representative sample stays a real raw line, not a synthesized one.
    assert finding.sample_log in {row["full_log"] for row in _ssh_failures()}


def test_template_mining_preserves_the_event_total(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(archive, _ssh_failures())

    regex_mode = analyze_archive(archive)
    template_mode = analyze_archive(archive, template_mining=True)

    # Merging findings must never lose rows: the join that attaches templates is
    # a LEFT JOIN precisely so an unmatched message still groups.
    assert template_mode.total_events == regex_mode.total_events
    assert sum(f.event_count for f in template_mode.findings) == sum(f.event_count for f in regex_mode.findings)
    assert template_mode.status_counts == regex_mode.status_counts


def test_template_mining_is_deterministic_across_runs(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(archive, _ssh_failures() + [_undecoded("session opened for user root by (uid=0)")])

    first = analyze_archive(archive, template_mining=True)
    second = analyze_archive(archive, template_mining=True)

    # Drain is order dependent, so distinct messages are fed sorted and the key
    # hashes the template string rather than drain3's arrival-ordered cluster_id.
    assert [f.finding_key for f in first.findings] == [f.finding_key for f in second.findings]
    assert [f.message_pattern for f in first.findings] == [f.message_pattern for f in second.findings]


def test_below_threshold_grouping_is_unaffected_by_template_mining(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {"full_log": "first message", "decoder": {"name": "a"}, "rule": {"id": "200", "level": 1}},
            {"full_log": "second message", "decoder": {"name": "b"}, "rule": {"id": "200", "level": 1}},
        ],
    )

    regex_mode = analyze_archive(archive)
    template_mode = analyze_archive(archive, template_mining=True)

    # below_threshold groups by rule ID, where the rule is already the semantic
    # grouping, so mining must not touch it.
    assert len(template_mode.findings) == 1
    assert template_mode.findings[0].finding_key == regex_mode.findings[0].finding_key
    assert template_mode.findings[0].message_pattern == "rule:200"


def test_analysis_records_which_pattern_source_was_used(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(archive, _ssh_failures())

    assert analyze_archive(archive).template_mining is False
    assert analyze_archive(archive, template_mining=True).template_mining is True


def test_empty_archive_still_reports_the_mode(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    archive.touch()

    result = analyze_archive(archive, template_mining=True)
    assert result.total_events == 0
    assert result.findings == ()
    assert result.template_mining is True


def test_archive_without_minable_events_falls_back_cleanly(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    # Only at_or_above_threshold events, so there is nothing to mine at all.
    _write_jsonl(
        archive,
        [{"full_log": "alert", "decoder": {"name": "sshd"}, "rule": {"id": "101", "level": 9}}],
    )

    result = analyze_archive(archive, template_mining=True)
    assert result.total_events == 1
    assert result.findings == ()


def test_missing_drain3_raises_an_actionable_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(archive, _ssh_failures())

    # A None entry in sys.modules makes the import fail the way a missing
    # installation would.
    monkeypatch.setitem(sys.modules, "drain3", None)

    with pytest.raises(RuntimeError, match=r"wazuhcoverage\[drain3\]"):
        analyze_archive(archive, template_mining=True)


def test_missing_drain3_fails_before_the_archive_is_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "archives.json"
    archive.write_text("{not-json}\n", encoding="utf-8")
    monkeypatch.setitem(sys.modules, "drain3", None)

    # Fails on the missing extra rather than on the unparseable line, which
    # proves the check runs before any scanning work.
    with pytest.raises(RuntimeError, match=r"wazuhcoverage\[drain3\]"):
        analyze_archive(archive, template_mining=True, skip_malformed=False)


def test_messages_containing_csv_metacharacters_still_group_correctly(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    # The mapping is handed to DuckDB through a CSV file. Only integers are
    # written precisely so that a comma, quote, newline or carriage return in a
    # message can never corrupt the join key.
    nasty = [
        'app said "hello, world" to alice\nsecond line',
        'app said "hello, world" to bob\nsecond line',
        'app said "hello, world" to carol\r\nsecond line',
    ]
    _write_jsonl(archive, [_undecoded(text, f"00{i}") for i, text in enumerate(nasty, start=1)])

    result = analyze_archive(archive, template_mining=True)

    assert result.total_events == 3
    assert sum(f.event_count for f in result.findings) == 3
    # Whatever Drain decides to merge, no event may be lost. Samples remain
    # source-derived, with only CR/LF runs collapsed for the one-row logtest
    # contract.
    expected_samples = {text.replace("\r\n", " ").replace("\n", " ") for text in nasty}
    assert all(f.sample_log in expected_samples for f in result.findings)


def test_distinct_families_are_not_merged(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    rows = _ssh_failures() + [
        _undecoded("kernel: usb 1-1: new high-speed USB device number 4 using ehci-pci", "010"),
        _undecoded("kernel: usb 1-2: new high-speed USB device number 5 using ehci-pci", "011"),
    ]
    _write_jsonl(archive, rows)

    result = analyze_archive(archive, template_mining=True)

    assert len(result.findings) == 2
    assert sorted(f.event_count for f in result.findings) == [2, 5]
    assert sum(f.event_count for f in result.findings) == len(rows)
