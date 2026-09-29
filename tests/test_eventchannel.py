import json
from dataclasses import replace
from pathlib import Path
from typing import Dict, List, Optional  # noqa: UP035

from wazuhcoverage import analyze_archive  # type: ignore
from wazuhcoverage.eventchannel import NO_PAYLOAD_PATTERN, suggest_rule
from wazuhcoverage.html_report import _render_finding
from wazuhcoverage.models import Finding, Verification
from wazuhcoverage.report import _finding_rows


def _win_log(
    event_id: Optional[str],
    record_id: int,
    *,
    channel: str = "Security",
    provider: str = "Microsoft-Windows-Security-Auditing",
) -> str:
    # The shape DecodeWinevt stores: compact JSON, per-event fields first.
    system: Dict[str, str] = {  # noqa: UP006
        "providerName": provider,
        "systemTime": f"2026-09-28T10:00:{record_id % 60:02d}.123456Z",
        "eventRecordID": str(1000 + record_id),
        "channel": channel,
        "severityValue": "AUDIT_SUCCESS",
        "message": '"An account was successfully logged on."',
    }
    if event_id is not None:
        system["eventID"] = event_id
    return json.dumps({"win": {"system": system, "eventdata": {"logonType": "3"}}}, separators=(",", ":"))


def _row(full_log: str, *, decoder: str = "windows_eventchannel") -> Dict:  # noqa: UP006
    return {
        "timestamp": "2026-09-28T10:00:00+00:00",
        "agent": {"id": "001", "name": "win"},
        "location": "EventChannel",
        "decoder": {"name": decoder},
        "full_log": full_log,
    }


def _analyze(tmp_path: Path, rows: List[Dict]):  # noqa: UP006
    archive = tmp_path / "archives.json"
    with archive.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")
    return analyze_archive(archive)


def test_eventchannel_records_group_by_channel_provider_and_event_id(tmp_path: Path) -> None:
    rows = [_row(_win_log("4624", n)) for n in range(5)]
    rows += [_row(_win_log("4625", n)) for n in range(5, 8)]
    rows += [_row(_win_log("7036", 9, channel="System", provider="Service Control Manager"))]

    result = _analyze(tmp_path, rows)
    patterns = {finding.message_pattern: finding.event_count for finding in result.findings}

    # Every record differs in systemTime and eventRecordID, which Drain would
    # split into one finding each.
    assert patterns == {
        "channel=Security provider=Microsoft-Windows-Security-Auditing eventID=4624": 5,
        "channel=Security provider=Microsoft-Windows-Security-Auditing eventID=4625": 3,
        "channel=System provider=Service Control Manager eventID=7036": 1,
    }


def test_eventchannel_record_without_xml_payload_has_its_own_finding(tmp_path: Path) -> None:
    # What DecodeWinevt emits when the manager cannot parse the event XML.
    collapsed = json.dumps({"win": {"system": {"message": '"text"'}}}, separators=(",", ":"))
    rows = [_row(collapsed), _row(json.dumps({"win": {"system": {}}})), _row(_win_log("4624", 1))]

    patterns = {f.message_pattern: f.event_count for f in _analyze(tmp_path, rows).findings}

    assert patterns[NO_PAYLOAD_PATTERN] == 2
    assert patterns["channel=Security provider=Microsoft-Windows-Security-Auditing eventID=4624"] == 1


def test_non_json_eventchannel_log_and_other_decoders_are_still_mined(tmp_path: Path) -> None:
    rows = [
        _row("not json at all", decoder="windows_eventchannel"),
        _row('{"win":{"system":{"eventID":"4624"}}}', decoder="json"),
    ]

    patterns = {f.message_pattern for f in _analyze(tmp_path, rows).findings}

    assert "not json at all" in patterns
    assert not any(pattern.startswith("channel=") for pattern in patterns)


def test_rule_skeleton_keys_on_event_id_and_provider_under_the_given_parent() -> None:
    rule = suggest_rule(_win_log("4624", 1), parent="60106")

    assert rule is not None
    assert "<if_sid>60106</if_sid>" in rule
    assert '<field name="win.system.eventID" type="pcre2">^4624$</field>' in rule
    assert '<field name="win.system.providerName" type="pcre2">^Microsoft-Windows-Security-Auditing$</field>' in rule


def test_rule_skeleton_escapes_regex_and_xml() -> None:
    rule = suggest_rule(_win_log("1", 1, channel="Custom/Operational", provider="A&B (x)"), parent="60000")

    assert rule is not None
    assert "^A&amp;B \\(x\\)$" in rule


def test_no_rule_skeleton_without_a_provider() -> None:
    # Rule 60000 requires win.system.providerName, so nothing below it can match.
    record = json.dumps({"win": {"system": {"channel": "Security", "eventID": "0"}}})

    assert suggest_rule(record, parent="60000") is None


def test_no_rule_skeleton_without_an_event_id() -> None:
    assert suggest_rule(_win_log(None, 1), parent="60000") is None
    assert suggest_rule("not json", parent="60000") is None
    assert suggest_rule('{"win":{"system":{"eventID":4624}}}', parent="60000") is None


def _eventchannel_finding(sample: str) -> Finding:
    return Finding(
        finding_key="key",
        observed_status="no_alerting_rule",
        log_type="windows_eventchannel",
        message_pattern="channel=Security provider=Microsoft-Windows-Security-Auditing eventID=4624",
        event_count=5,
        affected_agents=1,
        first_seen=None,
        last_seen=None,
        observed_decoder="windows_eventchannel",
        observed_location="EventChannel",
        observed_rule_id=None,
        observed_rule_level=None,
        sample_log=sample,
    )


def _verification(state: str, rule_id: Optional[str]) -> Verification:
    return Verification(
        finding_key="key",
        effective_state=state,
        logtest_status="RuleMatch" if rule_id else "NoRule",
        decoder="json",
        rule_id=rule_id,
        rule_level=0 if rule_id else None,
        rule_description=None,
        rule_groups=("windows",),
        error=None,
    )


def test_a_replayed_match_becomes_the_parent_of_the_suggested_rule() -> None:
    # Verified on Wazuh 4.14.8: a rule under 60002 for System 7036 never fires,
    # because the stock level-0 sibling 61100 matches first.
    finding = _eventchannel_finding(_win_log("7036", 1, channel="System", provider="Service Control Manager"))

    rows = _finding_rows(1, finding, _verification("suppressed", "61100"))

    suggestion = next(row for row in rows if "Suggested Wazuh rule" in row)
    assert "<if_sid>61100</if_sid>" in suggestion


def test_reports_suggest_a_rule_not_a_regex_for_eventchannel_findings() -> None:
    finding = _eventchannel_finding(_win_log("4624", 1))
    matched = _verification("suppressed", "60106")

    rows = _finding_rows(1, finding, matched)
    rendered = _render_finding(finding, matched)

    assert any(row.startswith("    Suggested Wazuh rule (eventchannel): <rule ") for row in rows)
    assert not any("Suggested Wazuh regex" in row for row in rows)
    assert "<h4>Suggested Wazuh rule (eventchannel)</h4>" in rendered
    assert "&lt;if_sid&gt;60106&lt;/if_sid&gt;" in rendered


def test_no_suggestion_without_a_replayed_match() -> None:
    # Unverified leaves the parent unknown; uncovered means rule 60000 itself did
    # not match, so no child of it could.
    finding = _eventchannel_finding(_win_log("4624", 1))

    for verification in (None, _verification("unverified", None), _verification("uncovered", None)):
        assert not any("Suggested" in row for row in _finding_rows(1, finding, verification))
        assert "Suggested" not in _render_finding(finding, verification)


def test_no_suggestion_for_an_eventchannel_record_without_a_key() -> None:
    finding = _eventchannel_finding('{"win":{"system":{"message":"\\"text\\""}}}')
    matched = _verification("suppressed", "60000")

    assert not any("Suggested" in row for row in _finding_rows(1, finding, matched))
    assert "Suggested" not in _render_finding(finding, matched)


def test_no_suggestion_when_replay_shows_the_finding_already_alerts() -> None:
    finding = _eventchannel_finding(_win_log("4104", 1, channel="Microsoft-Windows-PowerShell/Operational"))
    alerting = replace(_verification("at_or_above_threshold", "91815"), rule_level=4)

    assert not any("Suggested" in row for row in _finding_rows(1, finding, alerting))
    assert "Suggested" not in _render_finding(finding, alerting)
