import json
import subprocess
import sys
from pathlib import Path


def test_benchmark_cases_exercise_expected_end_to_end_shapes() -> None:
    repository = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [sys.executable, str(repository / "tools" /
                             "benchmark_analysis.py"), "--events", "100"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    results = {result["case"]: result for result in map(
        json.loads, completed.stdout.splitlines())}

    assert set(results) == {"realistic", "unique"}
    assert results["realistic"]["events"] == 100
    assert results["realistic"]["findings"] == 1
    assert results["realistic"]["events_per_second"] > 0
    assert results["unique"]["events"] == 100
    assert results["unique"]["findings"] == 100
    assert results["unique"]["events_per_second"] > 0
