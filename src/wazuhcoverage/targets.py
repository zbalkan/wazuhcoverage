"""Target expansion for literal archive paths and glob patterns."""

from __future__ import annotations

from glob import glob
from pathlib import Path


def resolve_targets(targets: list[str]) -> list[Path]:
    """Resolve literal paths and glob patterns to unique absolute files.

    ``**`` is supported. Results are sorted to make repeated runs deterministic.
    """

    files: set[Path] = set()

    for target in targets:
        expanded = str(Path(target).expanduser())
        matches = glob(expanded, recursive=True)

        if not matches:
            candidate = Path(expanded)
            if candidate.is_file():
                matches = [str(candidate)]

        for match in matches:
            path = Path(match)
            if path.is_file():
                files.add(path.resolve())

    return sorted(files, key=str)
