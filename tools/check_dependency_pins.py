"""Fail when the dependency tree acquires an exact pin nobody reviewed.

An exact pin (``==``) inside a dependency is the failure mode this project has
to watch. drain3 is a runtime dependency and pins two libraries to a single
version each, so any environment that also wants a different jsonpickle or
cachetools cannot install wazuhcoverage at all. ``pip check`` does not see
this: it reports on what is installed, not on how narrow the constraints are,
and a resolver that already gave up never gets that far.

This script walks the installed dependency graph from wazuhcoverage, collects
every exact pin it finds, and compares the result with the set recorded below.
It fails when a pin appears that is not recorded, which is the moment to decide
whether the new constraint is acceptable, and when a recorded pin disappears,
which means the note is stale and should be deleted.

Run it against an environment where the package is installed:

    python -m pip install -e ".[dev]"
    python tools/check_dependency_pins.py
"""

from __future__ import annotations

import re
import sys
from importlib import metadata
from typing import Optional

ROOT = "wazuhcoverage"

# Exact pins known to exist, each with the reason it is tolerated. Everything
# here is a constraint imposed on anyone who installs this package.
KNOWN_PINS = {
    ("drain3", "jsonpickle"): "drain3 0.9.11 pins its state-serialization library; unused by wazuhcoverage",
    ("drain3", "cachetools"): "drain3 0.9.11 pins its LRU cache library; conflicts with cachetools>=5 consumers",
}

_NAME = re.compile(r"^\s*([A-Za-z0-9._-]+)")
_EXACT = re.compile(r"[=]{2,3}\s*[A-Za-z0-9][^,;\s]*")


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirement_name(requirement: str) -> Optional[str]:
    match = _NAME.match(requirement)
    return _canonical(match.group(1)) if match else None


def _requirements(distribution: str) -> list[str]:
    try:
        requires = metadata.distribution(distribution).requires or []
    except metadata.PackageNotFoundError:
        print(f"error: {distribution} is not installed; install the package before running this check", file=sys.stderr)
        raise SystemExit(2) from None

    # Requirements guarded by an extra are not part of a default install, so an
    # exact pin behind one constrains nobody who simply installs the package.
    return [requirement for requirement in requires if "extra ==" not in requirement]


def collect_pins() -> dict[tuple[str, str], str]:
    """Return {(requiring distribution, required distribution): requirement}."""

    pins: dict[tuple[str, str], str] = {}
    seen = {_canonical(ROOT)}
    queue = [_canonical(ROOT)]

    while queue:
        current = queue.pop()
        for requirement in _requirements(current):
            name = _requirement_name(requirement)
            if name is None:
                continue
            if _EXACT.search(requirement):
                pins[(current, name)] = requirement.strip()
            if name not in seen:
                seen.add(name)
                try:
                    metadata.distribution(name)
                except metadata.PackageNotFoundError:
                    # Not installed on this interpreter, usually an unmet
                    # environment marker. Nothing to walk into.
                    continue
                queue.append(name)
    return pins


def main() -> int:
    pins = collect_pins()
    found = set(pins)
    known = set(KNOWN_PINS)

    print(f"exact pins reachable from {ROOT}: {len(found)}")
    for key in sorted(found):
        note = KNOWN_PINS.get(key, "NOT RECORDED")
        print(f"  {key[0]} -> {pins[key]:<24} {note}")

    unexpected = sorted(found - known)
    resolved = sorted(known - found)

    for key in unexpected:
        print(
            f"error: {key[0]} pins {key[1]} exactly ({pins[key]}), which is not recorded in KNOWN_PINS", file=sys.stderr
        )
    for key in resolved:
        print(
            f"error: {key[0]} no longer pins {key[1]}; drop the entry from KNOWN_PINS and the README",
            file=sys.stderr,
        )

    return 1 if unexpected or resolved else 0


if __name__ == "__main__":
    raise SystemExit(main())
