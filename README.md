# wazuhcoverage

`wazuhcoverage` is a small batch CLI for measuring coverage in Wazuh JSON archives. It reads each archive once with DuckDB, classifies every event, groups unresolved or low-level events into findings, and selects one representative `full_log` sample per finding.

The CLI keeps only one piece of persistent state: `history.db`, an internal pickled `set[str]` of successfully processed absolute archive paths.

## Installation

```bash
python -m pip install .
```

## Usage

Literal files and glob patterns are accepted as positional arguments:

```bash
wazuhcoverage /archives/2026/09/archive.json.gz
wazuhcoverage "/archives/2026/09/*.json.gz"
wazuhcoverage "/archives/**/*.json.gz"
```

Multiple targets may be supplied. Overlapping patterns are deduplicated.

### Ignore history

```bash
wazuhcoverage --ignore-history "/archives/**/*.json.gz"
```

The archive is processed even if its absolute path is already present in `history.db`. A successful run still records/retains the path in history.

### Samples only

```bash
wazuhcoverage --no-stats "/archives/**/*.json.gz"
```

`stdout` contains only one representative raw `full_log` per finding. Progress and errors go to `stderr`, so the output can be piped directly into another program:

```bash
wazuhcoverage --no-stats "/archives/**/*.json.gz" | wazuh-logtest
```

## Current classification

Every archive event is placed in exactly one bucket:

- `no_decoder`: no named Wazuh decoder is represented in the archive event.
- `no_rule`: a decoder is present but no final rule is represented.
- `below_threshold`: a rule is present with a level below 3.
- `at_or_above_threshold`: all remaining rule-bearing events.

The threshold is intentionally fixed at 3 in the initial CLI design. The library code accepts an alternate threshold so configuration discovery can be added later without changing the analysis model.

`no_rule` means no final rule is represented in the archive; it does not prove that no rule predicate was evaluated internally by Wazuh.

## Finding grouping

`below_threshold` events are grouped by rule ID. `no_decoder` and `no_rule` events are grouped by log type and a conservative normalized message pattern. The normalizer currently replaces common timestamp prefixes, UUIDs, long hexadecimal values, and decimal numbers with five or more digits. Short numbers, IP addresses, ports, usernames, paths, event IDs, and HTTP status codes are deliberately retained.

The normalization logic is intentionally conservative and should be validated against real heterogeneous archives before being broadened.

## License

GNU General Public License version 2 only. See [LICENSE](LICENSE).
