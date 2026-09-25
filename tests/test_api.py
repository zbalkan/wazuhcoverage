from pathlib import Path

import wazuhcoverage
from wazuhcoverage import (
    ArchiveAnalysis,
    Finding,
    LogTypeCount,
    LogTypeMetrics,
    MetricSnapshot,
    MetricValue,
    StatusCount,
    analyze_archive,
    calculate_metrics,
    metrics_to_dict,
)


def test_public_api_is_available_from_package() -> None:
    assert callable(analyze_archive)
    assert callable(calculate_metrics)
    assert callable(metrics_to_dict)
    assert wazuhcoverage.DEFAULT_ALERT_THRESHOLD == 3
    assert wazuhcoverage.__version__ == "0.8.2"
    assert ArchiveAnalysis.__module__ == "wazuhcoverage.models"
    assert Finding.__module__ == "wazuhcoverage.models"
    assert LogTypeCount.__module__ == "wazuhcoverage.models"
    assert StatusCount.__module__ == "wazuhcoverage.models"
    assert MetricValue.__module__ == "wazuhcoverage.metrics"
    assert LogTypeMetrics.__module__ == "wazuhcoverage.metrics"
    assert MetricSnapshot.__module__ == "wazuhcoverage.metrics"


def test_analysis_annotation_accepts_string_or_path() -> None:
    annotations = analyze_archive.__annotations__
    assert "str" in str(annotations["path"])
    assert "Path" in str(annotations["path"])
    assert Path is not None
