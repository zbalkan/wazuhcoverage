# wazuhcoverage

`wazuhcoverage` is a Python library and small batch CLI for measuring coverage in Wazuh JSON archives. It reads each archive once with DuckDB, classifies every event, groups unresolved or low-level events into findings, and selects one deterministic representative `full_log` sample per finding.

The CLI keeps only one piece of persistent state: `history.db`, an internal pickled `set[str]` of successfully processed absolute archive paths. The library API has no dependency on that history mechanism.

## Installation

### Command-line use

For command-line use, install with [pipx](https://pipx.pypa.io/). It keeps the application and its dependencies in an isolated environment while exposing the `wazuhcoverage` command on your `PATH`:

```bash
pipx install wazuhcoverage
```

Upgrade or remove it with:

```bash
pipx upgrade wazuhcoverage
pipx uninstall wazuhcoverage
```

From a local checkout:

```bash
pipx install --editable .
```

### Python library

To use `wazuhcoverage` from another Python project, install it into that project's environment with pip:

```bash
python -m pip install wazuhcoverage
```

Then import the public package API:

```python
from wazuhcoverage import ArchiveAnalysis, Finding, analyze_archive

analysis = analyze_archive("/archives/2026/09/archive.json.gz")
print(analysis.total_events)

for finding in analysis.findings:
    print(finding.observed_status, finding.event_count, finding.sample_log)
```

The same PyPI distribution provides both the library and the console entry point. `pipx` is the recommended installation method for CLI-only use; `pip` is the recommended method when another Python project imports the library.

### Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

## CLI usage

Literal files and glob patterns are accepted as positional arguments:

```bash
wazuhcoverage /archives/2026/09/archive.json.gz
wazuhcoverage "/archives/2026/09/*.json.gz"
wazuhcoverage "/archives/**/*.json.gz"
```

Multiple targets may be supplied. Overlapping patterns are deduplicated and processed in deterministic path order.

The CLI intentionally has no subcommands:

```text
wazuhcoverage [--ignore-history] [--no-stats] TARGET [TARGET...]
```

### Ignore history

```bash
wazuhcoverage --ignore-history "/archives/**/*.json.gz"
```

The archive is processed even if its absolute path is already present in `history.db`. A successful run still records or retains the path in history.

### Samples only

```bash
wazuhcoverage --no-stats "/archives/**/*.json.gz"
```

`stdout` contains only one representative raw `full_log` per finding. Progress, errors, and the run summary go to `stderr`, so output remains safe to pipe into another program:

```bash
wazuhcoverage --no-stats "/archives/**/*.json.gz" | wazuh-logtest
```

History is updated only after analysis completes and stdout flushes successfully. A broken downstream pipe therefore does not mark the current archive as processed.

## Python API

The supported package-level API is:

```python
from wazuhcoverage import (
    DEFAULT_ALERT_THRESHOLD,
    ArchiveAnalysis,
    Finding,
    LogTypeCount,
    StatusCount,
    analyze_archive,
)
```

`analyze_archive()` accepts either `str` or `pathlib.Path` and returns an `ArchiveAnalysis`. CLI concerns such as glob expansion, `history.db`, report rendering, stdout/stderr, and exit codes are intentionally outside the analysis API.

## Classification

Every archive event is placed in exactly one bucket:

- `no_decoder`: no named Wazuh decoder is represented in the archive event.
- `no_rule`: a decoder is present but no final rule is represented.
- `below_threshold`: a rule is represented but its level is below the alert threshold, or its level is missing/unparseable and therefore cannot be proven to meet the threshold.
- `at_or_above_threshold`: a rule is represented with a usable level at or above the threshold.

These buckets are mutually exclusive and their event counts sum to `total_events`.

The CLI currently uses an alert threshold of 3. The library accepts an alternate `alert_threshold` value so configuration discovery can be added later without changing the analysis model.

`no_rule` means no final rule is represented in the archive; it does not prove that no rule predicate was evaluated internally by Wazuh.

## Finding grouping

`below_threshold` events are grouped by rule ID because the rule is already the semantic grouping. Such findings deliberately do not claim one arbitrary log type even when that rule appears across several decoders or sources; log-type population statistics remain available separately in `ArchiveAnalysis.log_type_counts`.

`no_decoder` and `no_rule` events are grouped by log type and a conservative normalized message pattern. The normalizer currently replaces common timestamp prefixes, UUIDs, long hexadecimal values, and decimal numbers with five or more digits. Short numbers, IP addresses, ports, usernames, paths, event IDs, and HTTP status codes are deliberately retained.

Malformed NDJSON is not silently ignored because doing so would corrupt the coverage denominator. Compressed `.json.gz` and uncompressed NDJSON archives are both supported directly by DuckDB.

## Scope

`wazuhcoverage` owns archive coverage analysis. It does not depend on `wazuhtester` and does not run Wazuh logtest internally. A higher-level toolkit can compose the libraries directly, for example by analyzing an archive with `wazuhcoverage` and replaying selected samples with `wazuhtester`.

`history.db` remains only a processed-path cache. It is not intended to become an analytics database.

## License

GNU General Public License version 2 only. See [LICENSE](LICENSE).
