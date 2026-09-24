"""Shared presentation semantics for text and HTML reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from wazuhcoverage.models import PROCESSED_STATUS, Finding, Verification

RESOLVED_OUTCOMES = ("Processed", "Suppressed", "Dropped", "Unresolved")
FINDING_GROUPS = ("Dropped", "Processed", "Unresolved")

_EFFECTIVE_OUTCOME = {
    "at_or_above_threshold": "Processed",
    "suppressed": "Suppressed",
    "below_threshold": "Suppressed",
    "no_decoder": "Dropped",
    "uncovered": "Dropped",
    "no_alerting_rule": "Unresolved",
    "unverified": "Unresolved",
}
_FINDING_GROUP = {
    "no_decoder": "Dropped",
    "uncovered": "Dropped",
    "at_or_above_threshold": "Processed",
    "suppressed": "Processed",
    "below_threshold": "Processed",
    "no_alerting_rule": "Unresolved",
    "unverified": "Unresolved",
}


@dataclass(frozen=True)
class FindingPresentation:
    """Replay-aware fields shared by report renderers."""

    status: str
    log_type: Optional[str]
    decoder: Optional[str]
    rule_id: Optional[str]
    rule_level: Optional[int]
    rule_description: Optional[str]
    replay_error: Optional[str]


def effective_outcome(status: str) -> str:
    """Map an effective status to the report's resolved outcome."""

    return _EFFECTIVE_OUTCOME[status]


def finding_group(status: str) -> str:
    """Return the Findings section for an observed or effective status."""

    return _FINDING_GROUP[status]


def outcome_counts(statuses: dict[str, int], *, resolved: bool) -> dict[str, int]:
    """Aggregate statuses using archive-only or replay-resolved semantics."""

    if not resolved:
        processed = statuses.get(PROCESSED_STATUS, 0)
        return {
            "Processed": processed,
            "Dropped": sum(statuses.values()) - processed,
        }

    counts = dict.fromkeys(RESOLVED_OUTCOMES, 0)
    for status, count in statuses.items():
        counts[effective_outcome(status)] += count
    return counts


def present_finding(
    finding: Finding,
    verification: Optional[Verification],
) -> FindingPresentation:
    """Resolve display fields without mixing stale archive values into replay."""

    if verification is None:
        return FindingPresentation(
            status=finding.observed_status,
            log_type=finding.log_type,
            decoder=finding.observed_decoder,
            rule_id=finding.observed_rule_id,
            rule_level=finding.observed_rule_level,
            rule_description=None,
            replay_error=None,
        )

    status = verification.effective_state
    if status == "unverified":
        decoder = finding.observed_decoder
        log_type = finding.log_type
    else:
        decoder = verification.decoder
        log_type = verification.decoder or finding.log_type

    return FindingPresentation(
        status=status,
        log_type=log_type,
        decoder=decoder,
        rule_id=verification.rule_id,
        rule_level=verification.rule_level,
        rule_description=verification.rule_description,
        replay_error=verification.error,
    )
