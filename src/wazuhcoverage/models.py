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
STATUSES = (
    "no_decoder",
    "no_rule",
    "below_threshold",
    "at_or_above_threshold",
)


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
    observed_rule_id: Optional[str]
    observed_rule_level: Optional[int]
    sample_log: str


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
    # How Finding.message_pattern and Finding.finding_key were derived. Regex
    # normalization and Drain template mining produce different keys for the
    # same events, so findings from the two modes must not be compared or
    # diffed; recording the mode is what makes that mistake detectable.
    template_mining: bool = False
