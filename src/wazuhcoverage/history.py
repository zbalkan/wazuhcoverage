"""Persistent history for successfully processed archive paths."""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator


class History:
    """A JSON-encoded set of path strings stored in history.db.

    The file is an internal cache, not a general-purpose database. Paths are
    normalized to absolute paths before membership checks or insertion. A small
    sidecar lock serializes read-modify-write operations between processes.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock_path = path.with_name(f".{path.name}.lock")
        with self._locked():
            self._items = self._load_unlocked()

    def _load_unlocked(self) -> set[str]:
        if not self.path.exists():
            return set()

        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid history file: {self.path}") from exc

        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"Invalid history file: {self.path}")
        return set(value)

    @staticmethod
    def key(path: Path) -> str:
        return str(path.expanduser().resolve())

    def contains(self, path: Path) -> bool:
        with self._locked():
            self._items = self._load_unlocked()
            return self.key(path) in self._items

    def add(self, path: Path) -> None:
        key = self.key(path)
        with self._locked():
            current = self._load_unlocked()
            if key in current:
                self._items = current
                return
            current.add(key)
            self._save_unlocked(current)
            self._items = current

    def _save_unlocked(self, items: set[str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")

        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as stream:
                json.dump(sorted(items), stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock_path.open("a+b") as stream:
            _lock_file(stream)
            try:
                yield
            finally:
                _unlock_file(stream)


def _lock_file(stream: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
        return

    import fcntl

    fcntl.flock(stream.fileno(), fcntl.LOCK_EX)


def _unlock_file(stream: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        stream.seek(0)
        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
