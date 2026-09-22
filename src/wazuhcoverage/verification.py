"""Replay finding samples through wazuh-logtest to get their effective state.

An archive records what analysisd committed to, not what it decided. A rule
that matched at level 0 leaves no rule in the record, so ``no_alerting_rule``
covers both "nothing matched" and "something matched and was silenced". Nothing
in the archive separates them.

wazuh-logtest does. It reports the rule it matched whatever that rule's level
is, because it is a testing interface rather than the alert pipeline. Replaying
one representative sample per finding therefore turns the archive's ambiguous
bucket into an answer, at the cost of needing a reachable Wazuh manager.

This module is the only part of wazuhcoverage that talks to anything outside
the archive file. ``analyze_archive`` stays offline and unchanged; verification
is a separate call, and ``wazuhtester`` is an optional dependency so the
package still installs where no manager exists.

Two callers with different needs are served deliberately differently.
``verify_findings`` is explicit: asked to replay, it raises rather than quietly
returning less than it promised. ``unavailable_reason`` answers the question a
best-effort caller has instead -- can this machine replay at all -- so the CLI
can say why it cannot and carry on reading the archive.
"""

from __future__ import annotations

from typing import Any, Optional, Union

from wazuhcoverage.models import ArchiveAnalysis, Finding, Verification

# The archive statuses worth replaying. below_threshold and
# at_or_above_threshold already name the rule that fired, so a replay would
# only confirm what the record states; the two buckets that name no rule are
# the ones a replay can actually resolve.
DEFAULT_VERIFIED_STATUSES = ("no_decoder", "no_alerting_rule")

# wazuh-logtest's own default. The archive does not record the log format, so
# it cannot be derived -- a JSON or EventChannel source needs the right value
# passed in or its sample replays against the wrong decoder chain.
DEFAULT_LOG_FORMAT = "syslog"

# What logtest is told when a finding carries no location, which happens for a
# below_threshold finding and for an archive whose events had none.
DEFAULT_LOCATION = "stdin"


# What this package calls on wazuhtester. Checked after import because the name
# importing is not the same as the library being there: a half-removed install
# leaves an empty directory that Python happily imports as a namespace package,
# and so does any directory called wazuhtester that happens to be on the path.
_REQUIRED_ATTRIBUTES = ("is_logtest_available", "get_socket_path", "send_log")


def _load_wazuhtester() -> Any:
    try:
        import wazuhtester
    except ImportError as exc:
        raise RuntimeError(
            "wazuhtester is not installed, so findings cannot be replayed. "
            "Install it with: pip install 'wazuhcoverage[logtest]' "
            "(Linux, Python 3.10 or newer, with a running Wazuh manager)"
        ) from exc
    except RuntimeError as exc:
        # wazuhtester refuses to import off Linux, where the logtest socket
        # cannot exist. That is a fact about the machine, not a fault.
        raise RuntimeError(f"wazuhtester cannot run on this platform: {exc}") from exc

    missing = [name for name in _REQUIRED_ATTRIBUTES if not hasattr(wazuhtester, name)]
    if missing:
        where = getattr(wazuhtester, "__file__", None) or "a namespace package with no module file"
        raise RuntimeError(
            f"the wazuhtester importable from {where} is missing {', '.join(missing)}, "
            "so it is not a usable install. Reinstall it with: "
            "pip install --force-reinstall 'wazuhcoverage[logtest]'"
        )

    return wazuhtester


def unavailable_reason(socket_path: Optional[str] = None) -> Optional[str]:
    """Return None when replay is possible here, or a short reason why not.

    Three things can stop a replay, and a caller that means to continue without
    one needs to tell a user which: the library is not installed, the platform
    cannot run it, or the daemon is not answering. None of them is an error in
    the archive, so none of them raises.
    """

    try:
        wazuhtester = _load_wazuhtester()
        if not wazuhtester.is_logtest_available(socket_path):
            where = socket_path or wazuhtester.get_socket_path()
            return f"the wazuh-logtest socket at {where} is not answering"
    except Exception as exc:  # noqa: BLE001 - a probe that raises defeats its own purpose
        # Anything at all: a broken install, a permission error reaching the
        # socket, a wazuhtester whose interface has moved. The caller wants a
        # sentence to print and a report to carry on writing.
        return f"{type(exc).__name__}: {exc}" if not isinstance(exc, RuntimeError) else str(exc)

    return None


def verify_findings(
    analysis: ArchiveAnalysis,
    *,
    alert_threshold: int = 3,
    statuses: tuple[str, ...] = DEFAULT_VERIFIED_STATUSES,
    log_format: str = DEFAULT_LOG_FORMAT,
    socket_path: Optional[str] = None,
) -> tuple[Verification, ...]:
    """Replay each selected finding's sample and report its effective state.

    One sample is replayed per finding, which is what grouping is for: an
    archive with a million uncovered events still costs one round trip per
    distinct message shape.

    Each sample is replayed in a session of its own. Sharing one session would
    let a frequency or composite rule fire on a later sample because earlier,
    unrelated samples happened to prime it, which would report coverage that
    does not exist. The cost of that isolation is the opposite blind spot,
    stated in the README: a rule that only fires on the Nth event cannot be
    reproduced from one event, so a finding covered solely by such a rule
    replays as ``uncovered``.

    Raises ``RuntimeError`` when wazuhtester is missing or the logtest socket
    is not answering, because a caller that asked for a replay is owed the
    reason rather than a silently emptier answer; ``unavailable_reason`` is
    there for callers that would rather continue without one. A failure on a
    single sample is a result, not a fault: that finding comes back
    ``unverified`` with the error text, and the remaining samples still run.
    """

    if alert_threshold < 0:
        raise ValueError("alert_threshold must be non-negative")

    targets = tuple(
        finding for finding in analysis.findings if finding.observed_status in statuses and finding.sample_log
    )
    if not targets:
        return ()

    reason = unavailable_reason(socket_path)
    if reason is not None:
        raise RuntimeError(reason)

    wazuhtester = _load_wazuhtester()

    return tuple(
        _verify_one(
            wazuhtester,
            finding,
            alert_threshold=alert_threshold,
            log_format=log_format,
            socket_path=socket_path,
        )
        for finding in targets
    )


def _verify_one(
    wazuhtester: Any,
    finding: Finding,
    *,
    alert_threshold: int,
    log_format: str,
    socket_path: Optional[str],
) -> Verification:
    try:
        response = wazuhtester.send_log(
            finding.sample_log,
            location=finding.observed_location or DEFAULT_LOCATION,
            log_format=log_format,
            socket_path=socket_path,
        )
    except Exception as exc:  # noqa: BLE001 - one bad sample must not end the pass
        return _unverified(finding, f"{type(exc).__name__}: {exc}")

    status = getattr(response.status, "name", str(response.status))

    if status == "Error":
        return _unverified(finding, "the logtest daemon reported an error for this sample", status=status)
    if status == "NoDecoder":
        return _verification(finding, "no_decoder", response, status)
    if status == "NoRule":
        return _verification(finding, "uncovered", response, status)
    if status != "RuleMatch":  # pragma: no cover - a status this version does not know
        return _unverified(finding, f"unrecognized logtest status {status!r}", status=status)

    level = _level(response.rule_level)
    if level is None:
        # A matched rule with no readable level cannot be placed against the
        # threshold, and guessing a side would be the same mistake the archive
        # makes.
        return _unverified(finding, "the matched rule reported no usable level", status=status, response=response)

    if level == 0:
        state = "silenced"
    elif level < alert_threshold:
        state = "below_threshold"
    else:
        state = "at_or_above_threshold"

    return _verification(finding, state, response, status)


def _verification(finding: Finding, state: str, response: Any, status: str) -> Verification:
    return Verification(
        finding_key=finding.finding_key,
        effective_state=state,
        logtest_status=status,
        decoder=response.decoder,
        rule_id=_string_or_none(response.rule_id),
        rule_level=_level(response.rule_level),
        rule_description=_string_or_none(response.rule_description),
        rule_groups=tuple(sorted(response.rule_groups or ())),
        error=None,
    )


def _unverified(
    finding: Finding,
    error: str,
    *,
    status: Optional[str] = None,
    response: Any = None,
) -> Verification:
    return Verification(
        finding_key=finding.finding_key,
        effective_state="unverified",
        logtest_status=status,
        decoder=None if response is None else response.decoder,
        rule_id=None if response is None else _string_or_none(response.rule_id),
        rule_level=None if response is None else _level(response.rule_level),
        rule_description=None if response is None else _string_or_none(response.rule_description),
        rule_groups=() if response is None else tuple(sorted(response.rule_groups or ())),
        error=error,
    )


def _level(value: Union[int, str, None]) -> Optional[int]:
    """Coerce a rule level to an int, or None when it is not one.

    The daemon sends a number, but the field is read straight out of a JSON
    envelope this package does not control, so a string is accepted rather
    than raising in the middle of a pass.
    """

    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _string_or_none(value: Any) -> Optional[str]:
    return None if value is None else str(value)
