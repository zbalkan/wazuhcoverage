"""Verification maps logtest replies onto effective states.

The tests stub wazuhtester rather than importing it: the library needs Linux,
Python 3.10 or newer and a running Wazuh manager, none of which this suite may
assume, and all the logic under test is the mapping on this side of the call.
"""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from wazuhcoverage import ArchiveAnalysis, Finding, verify_findings
from wazuhcoverage import verification as verification_module


def _finding(key: str, status: str = "no_alerting_rule", **overrides) -> Finding:
    base = Finding(
        finding_key=key,
        observed_status=status,
        log_type="sshd",
        message_pattern="pattern",
        event_count=1,
        affected_agents=1,
        first_seen=None,
        last_seen=None,
        observed_decoder="sshd",
        observed_location="syslog",
        observed_rule_id=None,
        observed_rule_level=None,
        sample_log=f"sample for {key}",
    )
    return replace(base, **overrides)


def _analysis(*findings: Finding) -> ArchiveAnalysis:
    return ArchiveAnalysis(
        path=Path("/archives/a.json"),
        total_events=sum(finding.event_count for finding in findings),
        malformed_lines=0,
        status_counts=(),
        log_type_counts=(),
        findings=findings,
    )


def _response(status: str, **fields) -> SimpleNamespace:
    return SimpleNamespace(
        status=SimpleNamespace(name=status),
        decoder=fields.get("decoder"),
        rule_id=fields.get("rule_id"),
        rule_level=fields.get("rule_level"),
        rule_description=fields.get("rule_description"),
        rule_groups=fields.get("rule_groups", set()),
    )


class _FakeTester:
    """A stand-in for the wazuhtester module."""

    def __init__(self, replies, available: bool = True) -> None:
        self._replies = replies
        self._available = available
        self.calls: list[dict] = []

    def is_logtest_available(self, socket_path=None) -> bool:
        return self._available

    def get_socket_path(self) -> str:
        return "/var/ossec/queue/sockets/logtest"

    def send_log(self, log, location="stdin", log_format="syslog", socket_path=None):
        self.calls.append({"log": log, "location": location, "log_format": log_format, "socket": socket_path})
        reply = self._replies[len(self.calls) - 1] if isinstance(self._replies, list) else self._replies
        if isinstance(reply, Exception):
            raise reply
        return reply


def _install(monkeypatch: pytest.MonkeyPatch, tester: _FakeTester) -> _FakeTester:
    monkeypatch.setattr(verification_module, "_load_wazuhtester", lambda: tester)
    return tester


def test_a_level_zero_match_is_suppressiond_not_uncovered(monkeypatch: pytest.MonkeyPatch) -> None:
    # The whole point of replaying. The archive recorded no rule for this
    # event; logtest reports the rule that matched and its level, so the two
    # outcomes the archive stores identically come apart here.
    _install(
        monkeypatch,
        _FakeTester(
            _response(
                "RuleMatch",
                decoder="windows_eventchannel",
                rule_id="61100",
                rule_level=0,
                rule_description="Windows System informational event",
                rule_groups={"windows", "windows_system"},
            )
        ),
    )

    (result,) = verify_findings(_analysis(_finding("k")))

    assert result.effective_state == "suppressed"
    assert (result.rule_id, result.rule_level) == ("61100", 0)
    assert result.rule_groups == ("windows", "windows_system")
    assert result.error is None


@pytest.mark.parametrize(
    ("status", "level", "expected"),
    [
        ("NoRule", None, "uncovered"),
        ("NoDecoder", None, "no_decoder"),
        ("RuleMatch", 0, "suppressed"),
        ("RuleMatch", 2, "below_threshold"),
        ("RuleMatch", 3, "at_or_above_threshold"),
        ("RuleMatch", 12, "at_or_above_threshold"),
    ],
)
def test_every_reply_maps_to_one_effective_state(
    monkeypatch: pytest.MonkeyPatch, status: str, level, expected: str
) -> None:
    _install(monkeypatch, _FakeTester(_response(status, rule_id="1", rule_level=level)))

    (result,) = verify_findings(_analysis(_finding("k")), alert_threshold=3)

    assert result.effective_state == expected


def test_the_threshold_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeTester(_response("RuleMatch", rule_id="1", rule_level=5)))

    (result,) = verify_findings(_analysis(_finding("k")), alert_threshold=7)

    assert result.effective_state == "below_threshold"


def test_a_daemon_error_is_unverified_never_uncovered(monkeypatch: pytest.MonkeyPatch) -> None:
    # Reporting a failed replay as "uncovered" would invent a coverage gap out
    # of a broken socket, which is the one mistake this feature must not make.
    _install(monkeypatch, _FakeTester(_response("Error")))

    (result,) = verify_findings(_analysis(_finding("k")))

    assert result.effective_state == "unverified"
    assert result.error


def test_a_raised_exception_leaves_the_other_samples_running(monkeypatch: pytest.MonkeyPatch) -> None:
    tester = _install(
        monkeypatch,
        _FakeTester(
            [
                RuntimeError("socket went away"),
                _response("RuleMatch", rule_id="5715", rule_level=3),
            ]
        ),
    )

    first, second = verify_findings(_analysis(_finding("a"), _finding("b")))

    assert first.effective_state == "unverified"
    assert "socket went away" in first.error
    assert second.effective_state == "at_or_above_threshold"
    assert len(tester.calls) == 2


def test_a_matched_rule_without_a_usable_level_is_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    # Placing it on either side of the threshold would be the same guess the
    # archive makes, which is what this feature exists to stop doing.
    _install(monkeypatch, _FakeTester(_response("RuleMatch", rule_id="1", rule_level="not-a-number")))

    (result,) = verify_findings(_analysis(_finding("k")))

    assert result.effective_state == "unverified"
    assert result.rule_id == "1"


def test_the_findings_location_is_replayed_not_a_default(monkeypatch: pytest.MonkeyPatch) -> None:
    # The decoder chain consults location. Replaying an EventChannel record as
    # "stdin" resolves it to the JSON decoder instead of windows_eventchannel,
    # which is a different answer to the question being asked.
    tester = _install(monkeypatch, _FakeTester(_response("NoRule")))
    finding = _finding("k", observed_location="EventChannel")

    verify_findings(_analysis(finding), log_format="json", socket_path="/tmp/sock")

    assert tester.calls == [
        {"log": "sample for k", "location": "EventChannel", "log_format": "json", "socket": "/tmp/sock"}
    ]


def test_a_finding_without_a_location_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    tester = _install(monkeypatch, _FakeTester(_response("NoRule")))

    verify_findings(_analysis(_finding("k", observed_location=None)))

    assert tester.calls[0]["location"] == "stdin"


def test_only_the_ambiguous_buckets_are_replayed(monkeypatch: pytest.MonkeyPatch) -> None:
    # A below_threshold finding already names the rule that fired, so a replay
    # would spend a round trip confirming the record.
    tester = _install(monkeypatch, _FakeTester(_response("NoRule")))
    analysis = _analysis(
        _finding("a", status="no_alerting_rule"),
        _finding("b", status="no_decoder"),
        _finding("c", status="below_threshold"),
    )

    results = verify_findings(analysis)

    assert len(results) == 2
    assert {result.finding_key for result in results} == {"a", "b"}
    assert len(tester.calls) == 2


def test_one_round_trip_per_finding_not_per_event(monkeypatch: pytest.MonkeyPatch) -> None:
    # Grouping is what makes this affordable: a finding standing for 40,000
    # events costs exactly one replay.
    tester = _install(monkeypatch, _FakeTester(_response("NoRule")))

    verify_findings(_analysis(_finding("k", event_count=40_000)))

    assert len(tester.calls) == 1


def test_an_unreachable_daemon_is_refused_not_reported_as_a_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeTester(_response("NoRule"), available=False))

    with pytest.raises(RuntimeError, match="not answering"):
        verify_findings(_analysis(_finding("k")))


def test_nothing_to_replay_needs_no_daemon(monkeypatch: pytest.MonkeyPatch) -> None:
    # The availability check comes after the target selection, so an archive
    # with full coverage does not fail on a machine with no manager.
    def explode() -> None:
        raise AssertionError("wazuhtester must not be loaded when there is nothing to replay")

    monkeypatch.setattr(verification_module, "_load_wazuhtester", explode)

    assert verify_findings(_analysis(_finding("c", status="below_threshold"))) == ()


def test_a_negative_threshold_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        verify_findings(_analysis(_finding("k")), alert_threshold=-1)


def test_a_missing_library_names_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def refuse(name, *args, **kwargs):
        if name == "wazuhtester":
            raise ImportError("No module named 'wazuhtester'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse)

    with pytest.raises(RuntimeError, match=r"wazuhcoverage\[logtest\]"):
        verify_findings(_analysis(_finding("k")))


def test_the_probe_is_silent_when_a_replay_is_possible(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeTester(_response("NoRule")))

    assert verification_module.unavailable_reason() is None


def test_the_probe_names_an_unanswering_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeTester(_response("NoRule"), available=False))

    reason = verification_module.unavailable_reason("/tmp/nope.sock")

    assert reason is not None
    assert "/tmp/nope.sock" in reason


def test_the_probe_reports_a_missing_library_instead_of_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    # A best-effort caller needs a sentence to print, not an exception to
    # catch: not having Wazuh on the machine is not an error in the archive.
    def refuse() -> None:
        raise RuntimeError("wazuhtester is not installed, so findings cannot be replayed.")

    monkeypatch.setattr(verification_module, "_load_wazuhtester", refuse)

    assert verification_module.unavailable_reason() == "wazuhtester is not installed, so findings cannot be replayed."


def test_a_half_removed_install_is_a_reason_not_a_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    # pip uninstall can leave an empty wazuhtester directory behind, and Python
    # imports that as a namespace package with no attributes at all. So does
    # any stray directory of that name on the path. Importing is not the same
    # as the library being there, and a best-effort caller must not die on it.
    import sys
    from types import ModuleType

    monkeypatch.setitem(sys.modules, "wazuhtester", ModuleType("wazuhtester"))

    reason = verification_module.unavailable_reason()

    assert reason is not None
    assert "is_logtest_available" in reason
    assert "not a usable install" in reason


def test_a_probe_that_raises_still_returns_a_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    class Exploding(_FakeTester):
        def is_logtest_available(self, socket_path=None) -> bool:
            raise PermissionError("cannot read the socket")

    _install(monkeypatch, Exploding(_response("NoRule")))

    reason = verification_module.unavailable_reason()

    assert reason is not None
    assert "cannot read the socket" in reason
