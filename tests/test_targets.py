from pathlib import Path

from wazuhcoverage.targets import resolve_targets


def test_resolve_targets_supports_literal_glob_recursive_and_dedup(tmp_path: Path) -> None:
    one = tmp_path / "a.json.gz"
    nested = tmp_path / "2026" / "09" / "b.json.gz"
    nested.parent.mkdir(parents=True)
    one.touch()
    nested.touch()

    targets = resolve_targets(
        [
            str(one),
            str(tmp_path / "*.json.gz"),
            str(tmp_path / "**" / "*.json.gz"),
        ]
    )

    assert targets == sorted({one.resolve(), nested.resolve()}, key=str)
