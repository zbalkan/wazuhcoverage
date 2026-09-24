from pathlib import Path

import wazuhcoverage
from wazuhcoverage import ArchiveAnalysis, Finding, LogTypeCount, StatusCount, analyze_archive


def test_public_api_is_available_from_package() -> None:
    assert callable(analyze_archive)
    assert wazuhcoverage.DEFAULT_ALERT_THRESHOLD == 3
    assert wazuhcoverage.__version__ == "0.6.1"
    assert ArchiveAnalysis.__module__ == "wazuhcoverage.models"
    assert Finding.__module__ == "wazuhcoverage.models"
    assert LogTypeCount.__module__ == "wazuhcoverage.models"
    assert StatusCount.__module__ == "wazuhcoverage.models"


def test_analysis_annotation_accepts_string_or_path() -> None:
    annotations = analyze_archive.__annotations__
    assert "str" in str(annotations["path"])
    assert "Path" in str(annotations["path"])
    assert Path is not None
