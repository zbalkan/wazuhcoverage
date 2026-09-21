import json
from pathlib import Path

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
    # The normalizer masks syntactic variance only, so these five lines are five
    # distinct strings when they reach the miner: usernames, addresses and short
    # ports cannot be masked by regex without enumerating them.
    return [
        _undecoded("Failed password for root from 10.0.0.1 port 2201 ssh2", "001"),
        _undecoded("Failed password for admin from 10.0.0.2 port 2202 ssh2", "002"),
        _undecoded("Failed password for jdoe from 10.0.0.3 port 2203 ssh2", "003"),
        _undecoded("Failed password for postgres from 10.0.0.4 port 2204 ssh2", "004"),
        _undecoded("Failed password for guest from 10.0.0.5 port 2205 ssh2", "005"),
    ]


def test_grouping_collapses_categorical_variants(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(archive, _ssh_failures())

    result = analyze_archive(archive)

    # This is the whole point of mining: categorical tokens that no regex can
    # mask without enumerating them still collapse into one finding.
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.event_count == 5
    assert finding.affected_agents == 5
    assert "<*>" in finding.message_pattern
    # The representative sample stays a real raw line, not a synthesized one.
    assert finding.sample_log in {row["full_log"] for row in _ssh_failures()}


def test_grouping_preserves_the_event_total(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    rows = _ssh_failures() + [
        _undecoded("kernel: usb 1-1: new high-speed USB device number 4 using ehci-pci", "010"),
        {"full_log": "alert", "decoder": {"name": "sshd"}, "rule": {"id": "101", "level": 9}},
    ]
    _write_jsonl(archive, rows)

    result = analyze_archive(archive)

    # Merging findings must never lose rows: the join that attaches templates is
    # a LEFT JOIN precisely so an unmatched message still groups.
    assert result.total_events == len(rows)
    assert sum(f.event_count for f in result.findings) == len(rows) - 1
    assert sum(s.event_count for s in result.status_counts) == len(rows)


def test_grouping_is_deterministic_across_runs(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(archive, _ssh_failures() + [_undecoded("session opened for user root by (uid=0)")])

    first = analyze_archive(archive)
    second = analyze_archive(archive)

    # Drain is order dependent, so distinct messages are fed sorted and the key
    # hashes the template string rather than drain3's arrival-ordered cluster_id.
    assert [f.finding_key for f in first.findings] == [f.finding_key for f in second.findings]
    assert [f.message_pattern for f in first.findings] == [f.message_pattern for f in second.findings]


def test_below_threshold_grouping_is_not_mined(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {"full_log": "first message", "decoder": {"name": "a"}, "rule": {"id": "200", "level": 1}},
            {"full_log": "second message", "decoder": {"name": "b"}, "rule": {"id": "200", "level": 1}},
        ],
    )

    result = analyze_archive(archive)

    # below_threshold groups by rule ID, where the rule is already the semantic
    # grouping, so mining must not touch it.
    assert len(result.findings) == 1
    assert result.findings[0].message_pattern == "rule:200"


def test_empty_archive_produces_no_findings(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    archive.touch()

    result = analyze_archive(archive)
    assert result.total_events == 0
    assert result.findings == ()


def test_archive_without_minable_events_still_analyzes(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    # Only at_or_above_threshold events, so there is nothing to mine at all.
    _write_jsonl(
        archive,
        [{"full_log": "alert", "decoder": {"name": "sshd"}, "rule": {"id": "101", "level": 9}}],
    )

    result = analyze_archive(archive)
    assert result.total_events == 1
    assert result.findings == ()


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

    result = analyze_archive(archive)

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

    result = analyze_archive(archive)

    assert len(result.findings) == 2
    assert sorted(f.event_count for f in result.findings) == [2, 5]
    assert sum(f.event_count for f in result.findings) == len(rows)


def test_opposite_outcomes_of_one_log_family_stay_apart(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    # These pairs are why the similarity threshold is tuned above the drain3
    # default of 0.4: at that default both pairs merge into a single finding,
    # which would report a failed logon and a successful one, or a dropped
    # packet and an accepted one, as one missing decoder.
    pairs = [
        (
            (
                "WinEvtLog: Security: AUDIT_SUCCESS(4624): Microsoft-Windows-Security-Auditing: "
                "alice: CORP: srv-001: An account was successfully logged on"
            ),
            (
                "WinEvtLog: Security: AUDIT_FAILURE(4625): Microsoft-Windows-Security-Auditing: "
                "bob: CORP: srv-002: An account failed to log on"
            ),
        ),
        (
            "iptables: IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.9 PROTO=TCP SPT=4001 DPT=443 ACTION=ACCEPT",
            "iptables: IN=eth0 OUT= SRC=10.0.0.2 DST=10.0.0.8 PROTO=TCP SPT=4002 DPT=23 ACTION=DROP",
        ),
    ]
    rows = [_undecoded(text, f"0{index:02d}") for index, text in enumerate(sum(pairs, ()), start=1)]
    _write_jsonl(archive, rows)

    result = analyze_archive(archive)

    assert len(result.findings) == len(rows)
    assert sum(f.event_count for f in result.findings) == len(rows)


def test_a_high_cardinality_family_collapses_to_one_finding(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    # The complementary risk to the test above: a threshold tuned too high
    # shatters one family into a finding per variable token. Paths and hostnames
    # are the tokens that fragment first.
    rows = [
        _undecoded(f"backup: copied /srv/app/{index}/data-{index}.bin to srv-{index:03d} in {index}s", f"{index:03d}")
        for index in range(40)
    ]
    _write_jsonl(archive, rows)

    result = analyze_archive(archive)

    assert len(result.findings) == 1
    assert result.findings[0].event_count == len(rows)
