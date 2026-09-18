import json
from pathlib import Path

from wazuhcoverage.history import History


def test_history_persists_absolute_path_as_json(tmp_path: Path) -> None:
    cache = tmp_path / "history.db"
    archive = tmp_path / "archive.json.gz"
    archive.touch()

    history = History(cache)
    assert not history.contains(archive)

    history.add(archive)
    assert history.contains(archive)
    assert json.loads(cache.read_text(encoding="utf-8")) == [str(archive.resolve())]

    reloaded = History(cache)
    assert reloaded.contains(archive)


def test_history_overwrites_non_json_content_without_deserializing_it(tmp_path: Path) -> None:
    cache = tmp_path / "history.db"
    cache.write_bytes(b"\x80\x04malicious-looking-pickle")

    history = History(cache)

    assert json.loads(cache.read_text(encoding="utf-8")) == []
    assert history._items == set()


def test_history_overwrites_invalid_json_structure(tmp_path: Path) -> None:
    cache = tmp_path / "history.db"
    cache.write_text('{"unexpected": "object"}\n', encoding="utf-8")

    history = History(cache)

    assert json.loads(cache.read_text(encoding="utf-8")) == []
    assert history._items == set()


def test_history_merges_updates_from_multiple_instances(tmp_path: Path) -> None:
    cache = tmp_path / "history.db"
    first_archive = tmp_path / "first.json.gz"
    second_archive = tmp_path / "second.json.gz"
    first_archive.touch()
    second_archive.touch()

    first = History(cache)
    second = History(cache)

    first.add(first_archive)
    second.add(second_archive)

    reloaded = History(cache)
    assert reloaded.contains(first_archive)
    assert reloaded.contains(second_archive)
