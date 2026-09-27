"""Shared presentation semantics for text and HTML reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Literal, Tuple  # noqa: UP035

from wazuhcoverage.models import PROCESSED_STATUS, Finding, Verification

ResolvedOutcome = Literal[
    "Processed",
    "Suppressed",
    "Dropped",
    "Unresolved",
]

FindingGroup = Literal[
    "Dropped",
    "Processed",
    "Unresolved",
]


RESOLVED_OUTCOMES: Tuple[ResolvedOutcome, ...] = (  # noqa: UP006
    "Processed",
    "Suppressed",
    "Dropped",
    "Unresolved",
)

FINDING_GROUPS: Tuple[FindingGroup, ...] = (  # noqa: UP006
    "Dropped",
    "Processed",
    "Unresolved",
)

_EFFECTIVE_OUTCOME: Dict[str, ResolvedOutcome] = {  # noqa: UP006
    "at_or_above_threshold": "Processed",
    "suppressed": "Suppressed",
    "below_threshold": "Suppressed",
    "no_decoder": "Dropped",
    "uncovered": "Dropped",
    "no_alerting_rule": "Unresolved",
    "unverified": "Unresolved",
}

_FINDING_GROUP: Dict[str, FindingGroup] = {  # noqa: UP006
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
    log_type: str | None
    decoder: str | None
    rule_id: str | None
    rule_level: int | None
    rule_description: str | None
    replay_error: str | None


def effective_outcome(status: str) -> ResolvedOutcome:
    """Map an effective status to the report's resolved outcome."""

    return _EFFECTIVE_OUTCOME[status]


def finding_group(status: str) -> FindingGroup:
    """Return the Findings section for an observed or effective status."""

    return _FINDING_GROUP[status]


def outcome_counts(statuses: Dict[str, int], *, resolved: bool) -> Dict[str, int]:  # noqa: UP006
    """Aggregate statuses using archive-only or replay-resolved semantics."""

    if not resolved:
        processed = statuses.get(PROCESSED_STATUS, 0)
        return {
            "Processed": processed,
            "Dropped": sum(statuses.values()) - processed,
        }

    counts: Dict[str, int] = dict.fromkeys(RESOLVED_OUTCOMES, 0)  # noqa: UP006
    for status, count in statuses.items():
        counts[effective_outcome(status)] += count

    return counts


def present_finding(
    finding: Finding,
    verification: Verification | None,
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
