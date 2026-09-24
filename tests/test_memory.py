import json
import os
import tempfile
from pathlib import Path

import duckdb
import pytest

from wazuhcoverage import analysis, analyze_archive


def _write_archive(path: Path) -> Path:
    rows = [
        {
            "agent": {"id": f"{index % 5:03d}"},
            "location": "/var/log/secure",
            "full_log": f"Failed password for user{index % 7} from 10.0.0.{index % 9} port 22{index % 10} ssh2",
            "decoder": {},
        }
        for index in range(200)
    ]
    with path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")
    return path


def test_spill_directory_is_private_and_removed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # DuckDB's default spill location is .tmp under the working directory. The
    # connection must use a directory of its own under the system temporary
    # directory instead, and leave nothing behind once it closes.
    system_tmp = tmp_path / "system-tmp"
    system_tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(system_tmp))

    with analysis._connect() as connection:
        row = connection.execute("SELECT current_setting('temp_directory')").fetchone()
        assert row is not None, "Query returned no rows"
        spill = Path(row[0])
        assert spill.parent == system_tmp
        assert spill.name.startswith("wazuhcoverage-duckdb-")
        assert spill.is_dir()

    assert not spill.exists()
    assert list(system_tmp.iterdir()) == []


def test_memory_and_threads_are_duckdb_defaults() -> None:
    reference = duckdb.connect(":memory:")
    try:
        expected = reference.execute("SELECT current_setting('memory_limit'), current_setting('threads')").fetchone()
    finally:
        reference.close()

    with analysis._connect() as connection:
        actual = connection.execute("SELECT current_setting('memory_limit'), current_setting('threads')").fetchone()

    assert actual == expected


def test_a_run_leaves_the_working_directory_untouched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = _write_archive(tmp_path / "archives.json")
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    system_tmp = tmp_path / "system-tmp"
    system_tmp.mkdir()
    monkeypatch.chdir(workdir)
    monkeypatch.setattr(tempfile, "tempdir", str(system_tmp))

    result = analyze_archive(archive)

    assert result.total_events == 200
    assert list(workdir.iterdir()) == []
    assert list(system_tmp.iterdir()) == []


def test_temporary_files_do_not_outlive_a_failed_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = _write_archive(tmp_path / "archives.json")
    system_tmp = tmp_path / "system-tmp"
    system_tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(system_tmp))

    def broken(*_args, **_kwargs):
        raise RuntimeError("mining failed")

    monkeypatch.setattr(analysis, "_create_finding_views", broken)

    with pytest.raises(RuntimeError, match="mining failed"):
        analyze_archive(archive)

    assert os.listdir(system_tmp) == []
