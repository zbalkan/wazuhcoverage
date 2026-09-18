"""Minimal persistent history for successfully processed archive paths."""

from __future__ import annotations

import os
import pickle
from pathlib import Path


class History:
    """A pickled ``set[str]`` stored in ``history.db``.

    The file is an internal cache, not a general-purpose database. Paths are
    normalized to absolute paths before membership checks or insertion.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._items = self._load()

    def _load(self) -> set[str]:
        if not self.path.exists():
            return set()

        with self.path.open("rb") as stream:
            value = pickle.load(stream)

        if not isinstance(value, set) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"Invalid history file: {self.path}")
        return value

    @staticmethod
    def key(path: Path) -> str:
        return str(path.expanduser().resolve())

    def contains(self, path: Path) -> bool:
        return self.key(path) in self._items

    def add(self, path: Path) -> None:
        key = self.key(path)
        if key in self._items:
            return
        self._items.add(key)
        self._save()

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.tmp")

        try:
            with temporary.open("wb") as stream:
                pickle.dump(self._items, stream, protocol=pickle.HIGHEST_PROTOCOL)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)
