import gzip
import json
from pathlib import Path

import duckdb
import pytest

from wazuhcoverage import analyze_archive
from wazuhcoverage import analysis as analysis_module


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
        "no_alerting_rule": 1,
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
    assert finding.observed_decoder is None
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


def test_duckdb_spill_directory_is_removed_after_success_and_failure(tmp_path: Path, monkeypatch) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(archive, [{"full_log": "event", "decoder": {}}])
    real_temporary_directory = analysis_module.tempfile.TemporaryDirectory
    created: list[Path] = []

    def tracked_temporary_directory(*args, **kwargs):  # type: ignore[no-untyped-def]
        directory = real_temporary_directory(*args, **kwargs)
        if kwargs.get("prefix") == "wazuhcoverage-duckdb-":
            created.append(Path(directory.name))
        return directory

    monkeypatch.setattr(analysis_module.tempfile, "TemporaryDirectory", tracked_temporary_directory)

    analyze_archive(archive)
    archive.write_text("{not-json}\n", encoding="utf-8")
    with pytest.raises(duckdb.Error):
        analyze_archive(archive, skip_malformed=False)

    assert len(created) == 2
    assert all(not path.exists() for path in created)


def test_malformed_line_is_skipped_and_counted_not_silently_dropped(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    archive.write_text('{"full_log": "valid"}\n{not-json}\n', encoding="utf-8")

    result = analyze_archive(archive)

    # The bad line must not survive as an all-NULL event: that would land in
    # no_decoder and quietly inflate the denominator it is meant to exclude.
    assert result.malformed_lines == 1
    assert result.total_events == 1
    counts = {item.status: item.event_count for item in result.status_counts}
    assert sum(counts.values()) == result.total_events
    assert counts["no_decoder"] == 1


def test_archive_with_only_malformed_lines_has_zero_classified_totals(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    archive.write_text("{not-json}\nnull\n", encoding="utf-8")

    result = analyze_archive(archive)

    assert result.malformed_lines == 2
    assert result.total_events == 0
    assert all(item.event_count == 0 for item in result.status_counts)
    assert result.log_type_counts == ()
    assert result.findings == ()


def test_strict_mode_still_rejects_a_malformed_archive(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    archive.write_text('{"full_log": "valid"}\n{not-json}\n', encoding="utf-8")

    with pytest.raises(duckdb.Error):
        analyze_archive(archive, skip_malformed=False)


def test_non_object_lines_count_as_malformed_and_blank_lines_do_not(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    # Bare scalars, arrays and null parse as JSON but are not events; strict
    # mode rejects them, so they are accounted for the same way. Blank and
    # whitespace-only lines are not data loss and must not be counted.
    archive.write_text(
        '{"full_log": "valid", "decoder": {}}\n\n   \nnull\n[1, 2]\n"scalar"\n42\n',
        encoding="utf-8",
    )

    result = analyze_archive(archive)

    assert result.total_events == 1
    assert result.malformed_lines == 4


def test_clean_archive_reports_no_malformed_lines(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(archive, _fixture_rows())

    assert analyze_archive(archive).malformed_lines == 0


def test_malformed_lines_are_counted_identically_when_compressed(tmp_path: Path) -> None:
    rows = _fixture_rows()
    plain = tmp_path / "archives.json"
    compressed = tmp_path / "archives.json.gz"
    _write_jsonl(plain, rows)
    _write_jsonl_gz(compressed, rows)
    with plain.open("a", encoding="utf-8") as stream:
        stream.write("{not-json}\n")
    import gzip as _gzip

    with _gzip.open(compressed, "at", encoding="utf-8") as stream:
        stream.write("{not-json}\n")

    plain_result = analyze_archive(plain)
    compressed_result = analyze_archive(compressed)

    assert plain_result.malformed_lines == compressed_result.malformed_lines == 1
    assert plain_result.total_events == compressed_result.total_events == len(rows)


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


def test_replay_metadata_comes_from_the_representative_sample(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {
                "location": "sample-location",
                "full_log": "application event alpha",
                "decoder": {"name": "application"},
            },
            {
                "location": "other-location",
                "full_log": "application event beta",
                "decoder": {"name": "application"},
            },
        ],
    )

    finding = analyze_archive(archive).findings[0]

    assert finding.sample_log == "application event alpha"
    assert finding.observed_location == "sample-location"


def test_null_replay_metadata_is_not_replaced_from_another_event(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {"full_log": "application event alpha", "decoder": {"name": "application"}},
            {
                "location": "other-location",
                "full_log": "application event beta",
                "decoder": {"name": "application"},
            },
        ],
    )

    finding = analyze_archive(archive).findings[0]

    assert finding.sample_log == "application event alpha"
    assert finding.observed_location is None


def test_finding_key_serializes_components_without_delimiter_collisions(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {"location": "a|b", "full_log": "c", "decoder": {}},
            {"location": "a", "full_log": "b|c", "decoder": {}},
        ],
    )

    findings = analyze_archive(archive).findings

    assert len(findings) == 2
    assert len({finding.finding_key for finding in findings}) == 2


def test_masking_runs_before_mining_and_constant_values_survive_both(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {"full_log": "source=10.0.0.1 port=22 event=4625 id=12345", "decoder": {}},
            {"full_log": "source=10.0.0.2 port=22 event=4625 id=67890", "decoder": {}},
        ],
    )

    result = analyze_archive(archive)

    # The regex normalizer is the masking pass in front of the miner: the long
    # identifier is masked before Drain ever sees it, which is why the two lines
    # differ in one token and merge. Tokens that are constant across the family
    # survive both stages, so a port and an event ID stay readable in the
    # pattern and only the varying token becomes a wildcard.
    assert len(result.findings) == 1
    pattern = result.findings[0].message_pattern
    assert "id=<NUM>" in pattern
    assert "port=22" in pattern and "event=4625" in pattern
    assert "10.0.0.1" not in pattern and "10.0.0.2" not in pattern
    assert "<*>" in pattern


def test_event_time_ordering_respects_timezone_offsets(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {
                "timestamp": "2026-09-18T12:00:00+0300",
                "full_log": "same event 12345",
                "decoder": {},
            },
            {
                "timestamp": "2026-09-18T10:30:00+0000",
                "full_log": "same event 67890",
                "decoder": {},
            },
        ],
    )

    result = analyze_archive(archive)
    finding = result.findings[0]

    assert finding.first_seen is not None
    assert finding.last_seen is not None
    assert finding.first_seen.startswith("2026-09-18 09:00:00")
    assert finding.last_seen.startswith("2026-09-18 10:30:00")


def test_status_counts_carry_total_percentage_and_are_ordered_descending(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(archive, _fixture_rows())

    result = analyze_archive(archive)
    counts = [item.event_count for item in result.status_counts]
    percentages = {item.status: item.percentage for item in result.status_counts}

    assert counts == sorted(counts, reverse=True)
    assert result.status_counts[0].status == "no_decoder"
    assert percentages["no_decoder"] == pytest.approx(40.0)
    assert percentages["no_alerting_rule"] == pytest.approx(20.0)
    # Malformed lines are outside the denominator, so the buckets account for
    # the whole archive and nothing else.
    assert sum(percentages.values()) == pytest.approx(100.0)


def test_status_count_ties_keep_a_stable_declared_order(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {"full_log": "a", "decoder": {}},
            {"full_log": "b", "decoder": {"name": "sshd"}},
        ],
    )

    result = analyze_archive(archive)

    assert [item.status for item in result.status_counts] == [
        "no_decoder",
        "no_alerting_rule",
        "below_threshold",
        "at_or_above_threshold",
    ]
    assert [item.event_count for item in result.status_counts] == [1, 1, 0, 0]


def test_log_type_counts_are_ordered_by_count_across_statuses(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {"full_log": "one", "decoder": {"name": "sshd"}},
            {"full_log": "two", "decoder": {"name": "sshd"}},
            {"full_log": "three", "decoder": {"name": "sshd"}},
            {"full_log": "four", "decoder": {"name": "windows"}},
            {"location": "/var/log/app.log", "full_log": "five", "decoder": {}},
        ],
    )

    result = analyze_archive(archive)
    counts = [item.event_count for item in result.log_type_counts]

    # A global count ordering, not one grouped by status first: the largest
    # populations must surface regardless of which bucket they fell into.
    assert counts == sorted(counts, reverse=True)
    assert (result.log_type_counts[0].status, result.log_type_counts[0].log_type) == ("no_alerting_rule", "sshd")


def test_log_type_percentages_measure_archive_and_status_shares(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {"full_log": "one", "decoder": {"name": "sshd"}},
            {"full_log": "two", "decoder": {"name": "sshd"}},
            {"full_log": "three", "decoder": {"name": "sshd"}},
            {"full_log": "four", "decoder": {"name": "windows"}},
            {"location": "/var/log/app.log", "full_log": "five", "decoder": {}},
        ],
    )

    result = analyze_archive(archive)
    rows = {(item.status, item.log_type): item for item in result.log_type_counts}

    sshd = rows[("no_alerting_rule", "sshd")]
    assert sshd.percentage == pytest.approx(60.0)
    assert sshd.status_percentage == pytest.approx(75.0)

    app = rows[("no_decoder", "/var/log/app.log")]
    assert app.percentage == pytest.approx(20.0)
    # The only source in a small bucket still owns all of it. That contrast is
    # the reason both percentages are reported rather than one.
    assert app.status_percentage == pytest.approx(100.0)

    assert sum(item.percentage for item in result.log_type_counts) == pytest.approx(100.0)
    for status in ("no_decoder", "no_alerting_rule"):
        shares = [item.status_percentage for item in result.log_type_counts if item.status == status]
        assert sum(shares) == pytest.approx(100.0)


def test_empty_archive_reports_zero_percentages(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    archive.touch()

    result = analyze_archive(archive)

    assert all(item.percentage == 0.0 for item in result.status_counts)


def _multiline_rows() -> list[dict]:
    return [
        {
            "location": "/var/log/app.log",
            "decoder": {},
            "full_log": "Exception in thread main\n\tat com.acme.Foo.bar(Foo.java:42)\r\n\tat com.acme.Baz.run(Baz.java:7)",
        },
        {
            "location": "/var/log/app.log",
            "decoder": {},
            "full_log": "Exception in thread main\n\tat com.acme.Foo.bar(Foo.java:99)\r\n\tat com.acme.Baz.run(Baz.java:7)",
        },
    ]


def test_sample_log_is_always_one_row(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(archive, _multiline_rows())

    result = analyze_archive(archive)

    # logtest reads one log per line. A multi-line sample emitted verbatim
    # would be replayed as several unrelated logs, so the first line would be
    # tested against the wrong decoder and the rest as fragments no rule was
    # ever written for.
    assert result.findings
    for finding in result.findings:
        assert "\n" not in finding.sample_log
        assert "\r" not in finding.sample_log


def test_collapsing_a_sample_preserves_its_content(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(archive, _multiline_rows()[:1])

    sample = analyze_archive(archive).findings[0].sample_log

    # Each run of line breaks becomes one separator; nothing else about the log
    # is rewritten, because logtest must see what the decoder would see. The
    # tabs are part of the log and are preserved.
    assert sample == ("Exception in thread main \tat com.acme.Foo.bar(Foo.java:42) \tat com.acme.Baz.run(Baz.java:7)")


def test_single_line_samples_are_untouched(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    _write_jsonl(archive, _fixture_rows())

    for finding in analyze_archive(archive).findings:
        assert finding.sample_log == finding.sample_log.strip()
        assert "\n" not in finding.sample_log


def test_a_level_zero_match_is_archived_as_no_alerting_rule(tmp_path: Path) -> None:
    # Regression guard for the bucket's meaning, not for a code path. Wazuh's
    # analysisd abandons a level-0 match before it assigns lf->generated_rule
    # and clears that pointer when a rule's ignore window suppresses the event,
    # while the archive record is written either way; the JSON formatter emits
    # a "rule" object only when the pointer survived. This record is a real
    # archived EventChannel event that wazuh-logtest resolves to rule 61100 at
    # level 0, so a decoded event with no rule must land in no_alerting_rule
    # and must not be reported as though no rule had been evaluated.
    archive = tmp_path / "archives.json"
    _write_jsonl(
        archive,
        [
            {
                "timestamp": "2026-09-20T21:00:05+00:00",
                "agent": {"id": "003", "name": "jumphost1"},
                "location": "EventChannel",
                "decoder": {"name": "windows_eventchannel"},
                "full_log": (
                    '{"win":{"system":{"providerName":"Service Control Manager",'
                    '"eventID":"7036","channel":"System",'
                    '"computer":"jumphost1.zaferbalkan.com",'
                    '"message":"The Client License Service (ClipSVC) service '
                    'entered the stopped state."}}}'
                ),
            }
        ],
    )

    result = analyze_archive(archive)
    counts = {item.status: item.event_count for item in result.status_counts}

    assert counts["no_alerting_rule"] == 1
    assert counts["no_decoder"] == 0

    finding = result.findings[0]
    assert finding.observed_status == "no_alerting_rule"
    assert finding.observed_decoder == "windows_eventchannel"
    # The archive has no rule to report, and the model says so with None rather
    # than inventing one. Separating a level-0 match from an unmatched event
    # requires replaying the sample, which is why the sample is carried.
    assert finding.observed_rule_id is None
    assert finding.observed_rule_level is None
    assert finding.sample_log.startswith('{"win":')


def test_no_alerting_rule_is_the_declared_bucket_name() -> None:
    # The name is load-bearing. "no_rule" would assert that no rule was
    # evaluated, which an archive record cannot show, and a reader who acts on
    # that name writes a rule for an event a level-0 rule already recognises.
    # Pin the identifier so the weaker, provable claim survives a refactor.
    from wazuhcoverage.models import STATUSES

    assert STATUSES == (
        "no_decoder",
        "no_alerting_rule",
        "below_threshold",
        "at_or_above_threshold",
    )
