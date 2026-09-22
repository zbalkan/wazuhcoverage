"""Public API for Wazuh archive coverage analysis."""

from .analysis import DEFAULT_ALERT_THRESHOLD, analyze_archive
from .models import EFFECTIVE_STATES, STATUSES, ArchiveAnalysis, Finding, LogTypeCount, StatusCount, Verification
from .verification import verify_findings

__all__ = [
    "DEFAULT_ALERT_THRESHOLD",
    "EFFECTIVE_STATES",
    "STATUSES",
    "ArchiveAnalysis",
    "Finding",
    "LogTypeCount",
    "StatusCount",
    "Verification",
    "analyze_archive",
    "verify_findings",
]

__version__ = "0.5.0"
