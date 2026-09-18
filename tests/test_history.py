from pathlib import Path

from wazuhcoverage.history import History


def test_history_persists_absolute_path(tmp_path: Path) -> None:
    cache = tmp_path / "history.db"
    archive = tmp_path / "archive.json.gz"
    archive.touch()

    history = History(cache)
    assert not history.contains(archive)

    history.add(archive)
    assert history.contains(archive)

    reloaded = History(cache)
    assert reloaded.contains(archive)
