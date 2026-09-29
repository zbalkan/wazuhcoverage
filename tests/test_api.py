from pathlib import Path

import pytest

import wazuhcoverage
from wazuhcoverage import (
    ArchiveAnalysis,  # type: ignore
    Finding,  # type: ignore
    LogTypeCount,  # type: ignore
    LogTypeMetrics,  # type: ignore
    MetricSnapshot,  # type: ignore
    MetricValue,  # type: ignore
    StatusCount,  # type: ignore
    analyze_archive,  # type: ignore
    calculate_metrics,  # type: ignore
    metrics_to_dict,  # type: ignore
)


def test_public_api_is_available_from_package() -> None:
    assert callable(analyze_archive)
    assert callable(calculate_metrics)
    assert callable(metrics_to_dict)
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
