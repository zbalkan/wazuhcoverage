"""Analysis result models."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# These dataclasses are part of the public, py.typed API, so their annotations
# must stay resolvable at runtime on every supported interpreter. Optional[...]
# is used instead of PEP 604 "X | None" because Python 3.9 cannot evaluate the
# union operator when a consumer calls typing.get_type_hints(). PEP 585 builtin
# generics such as tuple[...] are subscriptable on 3.9 and are kept as-is.
# Bucket identifiers, in declared order. They name what the archive record
# proves, not what analysisd did internally, because an archive event carries
# no trace of the rule evaluation that produced it.
#
# "no_alerting_rule" is deliberately not called "no_rule". Wazuh's analysisd
# only attaches a rule to an archived event once it has committed to alerting
# on it: the matching loop abandons a level-0 match before the rule pointer is
# assigned, and clears that pointer again when a rule's ignore window swallows
# the event, while the archive record is queued either way. The JSON formatter
# then emits a "rule" object only when that pointer survived. A record with no
# rule therefore means no alerting rule was attached -- three different upstream
# outcomes that the archive stores identically. See docs/DESIGN.md for
# the upstream source references.
STATUSES = (
    "no_decoder",
    "no_alerting_rule",
    "below_threshold",
    "at_or_above_threshold",
)

# The two outcomes the report groups those buckets into. An event either
# reached an alerting rule at or above the threshold, which is the only
# outcome the alert pipeline acts on, or it did not. The three ways it can
# fail to are what a coverage gap is diagnosed from, so the grouping is a
# presentation layer over STATUSES and never replaces it: observed_status
# keeps naming the exact bucket on every model, and the counts are unchanged.
PROCESSED_STATUS = "at_or_above_threshold"
DROPPED_STATUSES = tuple(status for status in STATUSES if status != PROCESSED_STATUS)


@dataclass(frozen=True)
class StatusCount:
    status: str
    event_count: int
    # Share of ArchiveAnalysis.total_events, in percent. Malformed lines are
    # excluded from that denominator, so these percentages sum to 100.0 (up to
    # float representation) across all statuses of a non-empty archive.
    percentage: float


@dataclass(frozen=True)
class LogTypeCount:
    status: str
    log_type: Optional[str]
    event_count: int
    # Share of ArchiveAnalysis.total_events, in percent.
    percentage: float
    # Share of the events in this row's status bucket, in percent. The two
    # answer different questions: percentage sizes a log type against the whole
    # archive, status_percentage ranks it inside its own bucket, where a small
    # bucket can still be dominated by one source.
    status_percentage: float


# What a replay through wazuh-logtest found, in declared order. These are not
# the archive's buckets: logtest reports the rule it matched whatever that
# rule's level is, so the two outcomes an archive cannot separate --
# "no rule matched" and "a level-0 rule matched" -- arrive here as distinct
# answers. "unverified" is the honest bucket for a replay that did not produce
# one, and it is never inferred from the archive.
EFFECTIVE_STATES = (
    "no_decoder",
    "uncovered",
    "suppressed",
    "below_threshold",
    "at_or_above_threshold",
    "unverified",
)


@dataclass(frozen=True)
class Finding:
    finding_key: str
    observed_status: str
    log_type: Optional[str]
    message_pattern: str
    event_count: int
    affected_agents: int
    first_seen: Optional[str]
    last_seen: Optional[str]
    observed_decoder: Optional[str]
    # The archive's location field for this group, which is what a faithful
    # replay has to report to Wazuh: the decoder chain consults it, so a
    # sample replayed under the wrong location can resolve to a different
    # decoder than the one that actually ran.
    observed_location: Optional[str]
    observed_rule_id: Optional[str]
    observed_rule_level: Optional[int]
    sample_log: str


@dataclass(frozen=True)
class Verification:
    """What wazuh-logtest made of one finding's representative sample.

    ``effective_state`` is the answer the archive could not give. The rule
    fields describe the rule logtest matched, which may be a level-0 rule the
    archive recorded as no rule at all.
    """

    finding_key: str
    effective_state: str
    # The raw LogtestStatus name (RuleMatch, NoRule, NoDecoder, Error), kept so
    # a caller can tell a daemon error apart from a clean "nothing matched".
    logtest_status: Optional[str]
    decoder: Optional[str]
    rule_id: Optional[str]
    rule_level: Optional[int]
    rule_description: Optional[str]
    rule_groups: tuple[str, ...]
    # Why the state is "unverified"; None whenever it is not.
    error: Optional[str]


@dataclass(frozen=True)
class ArchiveAnalysis:
    path: Path
    total_events: int
    # Lines DuckDB could not parse as a JSON object. They are excluded from
    # total_events and from every bucket, so coverage percentages stay exact;
    # this field is what makes the loss visible rather than silent.
    malformed_lines: int
    status_counts: tuple[StatusCount, ...]
    log_type_counts: tuple[LogTypeCount, ...]
    findings: tuple[Finding, ...]
