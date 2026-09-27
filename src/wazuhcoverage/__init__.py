"""Public API for Wazuh archive coverage analysis."""

import sys

if sys.platform != "linux":
    raise RuntimeError(
        "wazuhcoverage supports Linux only because it replays findings "
        "through the local Wazuh wazuh-logtest Unix socket."
    )

from .analysis import DEFAULT_ALERT_THRESHOLD, analyze_archive
from .metrics import LogTypeMetrics, MetricSnapshot, MetricValue, calculate_metrics, metrics_to_dict
from .models import (
    DROPPED_STATUSES,
    EFFECTIVE_STATES,
    PROCESSED_STATUS,
    STATUSES,
    ArchiveAnalysis,
    Finding,
    LogTypeCount,
    StatusCount,
    Verification,
)
from .verification import verify_findings

__all__ = [
    "DEFAULT_ALERT_THRESHOLD",
    "DROPPED_STATUSES",
    "EFFECTIVE_STATES",
    "PROCESSED_STATUS",
    "STATUSES",
    "ArchiveAnalysis",
    "Finding",
    "LogTypeCount",
    "LogTypeMetrics",
    "MetricSnapshot",
    "MetricValue",
    "StatusCount",
    "Verification",
    "analyze_archive",
    "calculate_metrics",
    "metrics_to_dict",
    "verify_findings",
]

__version__ = "0.9.0"
