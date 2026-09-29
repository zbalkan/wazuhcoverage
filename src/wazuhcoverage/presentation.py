"""Shared presentation semantics for text and HTML reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Literal, Tuple  # noqa: UP035

from wazuhcoverage.models import Finding, Verification

ResolvedOutcome = Literal[
    "Rule matched, alerted",
    "Rule matched, no alert",
    "No rule",
    "No decoder",
    "Not verified",
]

ALERTED: ResolvedOutcome = "Rule matched, alerted"
NO_ALERT: ResolvedOutcome = "Rule matched, no alert"
NO_RULE: ResolvedOutcome = "No rule"
NO_DECODER: ResolvedOutcome = "No decoder"
NOT_VERIFIED: ResolvedOutcome = "Not verified"

# Table and chart order: what happened to the events, from an alert down to
# no verdict at all.
RESOLVED_OUTCOMES: Tuple[ResolvedOutcome, ...] = (ALERTED, NO_ALERT, NO_RULE, NO_DECODER, NOT_VERIFIED)  # noqa: UP006

# Finding order: the gaps someone can act on first.
FINDING_GROUPS: Tuple[ResolvedOutcome, ...] = (NO_RULE, NO_DECODER, NO_ALERT, ALERTED, NOT_VERIFIED)  # noqa: UP006

# The statuses each outcome is made of, in the order their breakdown rows are
# shown. A replay-resolved status and the archive status it stands in for map
# to the same outcome; a rule-less record without a verdict is not verified.
OUTCOME_STATUSES: Dict[ResolvedOutcome, Tuple[str, ...]] = {  # noqa: UP006
    ALERTED: ("at_or_above_threshold",),
    NO_ALERT: ("suppressed", "below_threshold"),
    NO_RULE: ("uncovered",),
    NO_DECODER: ("no_decoder",),
    NOT_VERIFIED: ("no_alerting_rule", "unverified"),
}

# Column headings where the full labels would not fit, such as one column per
# outcome in the log-type table. They keep the full labels' order and wording.
SHORT_LABELS: Dict[ResolvedOutcome, str] = {  # noqa: UP006
    ALERTED: "Alerted",
    NO_ALERT: "No alert",
    NO_RULE: "No rule",
    NO_DECODER: "No decoder",
    NOT_VERIFIED: "Not verified",
}

# How a status reads in an outcome's breakdown rows.
STATUS_LABELS: Dict[str, str] = {  # noqa: UP006
    "suppressed": "level 0",
    "below_threshold": "below threshold",
}

_EFFECTIVE_OUTCOME: Dict[str, ResolvedOutcome] = {  # noqa: UP006
    status: outcome for outcome, statuses in OUTCOME_STATUSES.items() for status in statuses
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


def finding_group(status: str) -> ResolvedOutcome:
    """Return the Findings section for an observed or effective status."""

    return _EFFECTIVE_OUTCOME[status]


def outcome_counts(statuses: Dict[str, int]) -> Dict[str, int]:  # noqa: UP006
    """Aggregate observed and effective statuses into the report's outcomes."""

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
