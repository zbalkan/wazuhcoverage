"""Analysis result models."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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


@dataclass(frozen=True)
class LogTypeCount:
    status: str
    log_type: str
    event_count: int


@dataclass(frozen=True)
class Finding:
    finding_key: str
    observed_status: str
    log_type: str
    message_pattern: str
    event_count: int
    affected_agents: int
    first_seen: str | None
    last_seen: str | None
    observed_decoder: str | None
    observed_rule_id: str | None
    observed_rule_level: int | None
    sample_log: str


@dataclass(frozen=True)
class ArchiveAnalysis:
    path: Path
    total_events: int
    status_counts: tuple[StatusCount, ...]
    log_type_counts: tuple[LogTypeCount, ...]
    findings: tuple[Finding, ...]
