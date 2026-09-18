"""Public API for Wazuh archive coverage analysis."""

from .analysis import DEFAULT_ALERT_THRESHOLD, analyze_archive
from .models import ArchiveAnalysis, Finding, LogTypeCount, StatusCount

__all__ = [
    "analyze_archive",
    "DEFAULT_ALERT_THRESHOLD",
    "ArchiveAnalysis",
    "Finding",
    "LogTypeCount",
    "StatusCount",
]

__version__ = "0.2.0"
