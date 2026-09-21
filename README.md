# wazuhcoverage

`wazuhcoverage` is a Python library and small batch CLI for measuring coverage in Wazuh JSON archives. It reads each archive once with DuckDB, classifies every event, groups unresolved or low-level events into findings, and selects one deterministic representative `full_log` sample per finding, emitted as a single row.

The CLI keeps only one piece of persistent state: `history.db`, an internal JSON array representing the set of successfully processed absolute archive paths. Updates are serialized with a small sidecar lock and written atomically. The library API has no dependency on that history mechanism.

## Requirements

Python 3.9 or newer on Linux, macOS, or Windows. Two runtime dependencies are installed automatically: DuckDB, which does the scanning and aggregation, and [drain3](https://github.com/IBM/Drain3), which mines the templates that group unresolved events. Both are mandatory; there is no build of this tool that groups without mining.

drain3 is pure Python and imposes no interpreter floor, but version 0.9.11 ships as a source distribution only and pins `jsonpickle==1.5.1` and `cachetools==4.2.1` exactly. A `pipx` install is unaffected, because it gets an environment of its own and nothing else resolves against those pins. The constraint applies only when the library is installed into a shared environment, and only when that environment's own constraints exclude the pinned versions: a project requiring `cachetools>=5` cannot install wazuhcoverage at all, while one depending on `google-auth`, whose range is `cachetools>=2,<7`, resolves normally and simply lands on 4.2.1.

Adding a dependency is therefore the thing to be careful about, and the checks exist to enforce that rather than to describe today's tree. `tools/check_dependency_pins.py` walks the installed graph and fails when an exact pin appears or disappears; CI runs it on every supported interpreter alongside `pip check` and a from-scratch resolution, so a new dependency that narrows what this package can coexist with fails review instead of a user's install.

Python 3.9 is supported as a compatibility floor for hosts that still ship it, and it constrains the DuckDB version. DuckDB dropped 3.9 in 1.5.0, so the dependency is capped at `duckdb<1.5` on 3.9 via an explicit environment marker; such installs stay on the 1.4.x line, which no longer receives upstream fixes. Python 3.10 or newer is recommended wherever the host allows it.

Because 3.9 cannot evaluate PEP 604 `X | None` annotations at runtime, the public models are annotated with `typing.Optional` and `typing.Union`. This keeps `typing.get_type_hints()` working on every supported interpreter, so consumers that introspect annotations at runtime behave identically across the range.

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

The Drain parameters are chosen by measurement, not by feel. `tools/tune_drain.py` rebuilds the labelled corpus they were selected against and prints the grid; re-run it after changing the normalizer, the corpus, or the drain3 version.

```bash
python tools/tune_drain.py
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
wazuhcoverage [--ignore-history] [--no-stats] [--strict] TARGET [TARGET...]
```

### Ignore history

```bash
wazuhcoverage --ignore-history "/archives/**/*.json.gz"
```

The archive is processed even if its absolute path is already present in `history.db`. A successful run still records or retains the path in history.

### Strict parsing

```bash
wazuhcoverage --strict "/archives/**/*.json.gz"
```

By default a line that DuckDB cannot parse as a JSON object is skipped, counted, and reported; the archive still produces a result. `--strict` restores fail-fast behaviour, rejecting the whole archive on the first such line.

Skipping is the default because a single truncated line — the usual result of a rotated or partially written archive — would otherwise discard an entire day of coverage data. The count is never hidden: it appears as `Malformed lines skipped` in the report, as a `wazuhcoverage: skipped N unparseable line(s)` warning on stderr, and as `ArchiveAnalysis.malformed_lines` in the API.

### Samples only

```bash
wazuhcoverage --no-stats "/archives/**/*.json.gz"
```

`stdout` contains exactly one row per finding, each row a representative `full_log`. Progress, errors, and the run summary go to `stderr`, so output remains safe to pipe into another program:

```bash
wazuhcoverage --no-stats "/archives/**/*.json.gz" | wazuh-logtest
```

One log per row is a contract, not a formatting preference. `wazuh-logtest` reads one log per line, so a multi-line sample — a stack trace, a wrapped EventChannel record, anything collected with `multi-line` or `multi-line-regex` — would be replayed as several unrelated logs: the first tested against the wrong decoder and the remainder as fragments no rule was ever written for. Runs of `CR`/`LF` inside the selected sample are therefore collapsed to a single space, and leading and trailing whitespace is trimmed. Nothing else is rewritten; tabs, spacing, and every other character reach logtest as the decoder would see them. `Finding.sample_log` carries the same single-row value, so an API consumer that replays samples gets the identical guarantee.

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

`analyze_archive()` accepts either `str` or `pathlib.Path` and returns an `ArchiveAnalysis`. Pass `skip_malformed=False` for the fail-fast behaviour that `--strict` selects. Grouping is not parameterized: every call mines templates, so two analyses of the same archive are always comparable. CLI concerns such as glob expansion, `history.db`, report rendering, stdout/stderr, and exit codes are intentionally outside the analysis API.

## Statistics

A report opens with a header that records the archive path, the event total, and how many malformed lines were skipped. Two complementary tables follow. The first is status-based and ranks status buckets by event count. The second is log-type-based: it pivots the detailed `(status, log type)` cells into one row per log type, ranks log types by aggregate event count, and shows the four status counts side by side.

```text
Archive: /archives/2026/09/archive.json.gz
Total events: 8
Malformed lines skipped: 0

Status
------
Status                          Events   % total
no_decoder                           3    37.50%
no_rule                              2    25.00%
at_or_above_threshold                2    25.00%
below_threshold                      1    12.50%

Log types
---------
Log type                                Events   % total  no_decoder     no_rule  below_threshold  at_or_above_threshold
sshd                                         4    50.00%           0           1                1                      2
/var/log/app.log                             3    37.50%           3           0                0                      0
windows                                      1    12.50%           0           1                0                      0
```

`% total` is the share of `total_events`, which excludes malformed lines. The four status columns in the log-type table are event counts, and together they equal `Events` for that row. This lets the report answer both which log types dominate the archive and how each log type is classified without repeating a status-first breakdown.

`ArchiveAnalysis.log_type_counts` remains the detailed API representation with one record per `(status, log type)` pair. `LogTypeCount.percentage` is the pair's share of the whole archive and `LogTypeCount.status_percentage` is its share of that status bucket. The CLI pivots those records only while rendering, so the analysis model and public API do not change.

Every status is listed even when its count is zero, because an empty bucket is a coverage statement rather than missing data. Equal status counts keep the declared bucket order (`no_decoder`, `no_rule`, `below_threshold`, `at_or_above_threshold`). Log types are ordered by aggregate event count descending, with the log-type label breaking ties deterministically.

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

`no_decoder` and `no_rule` events are grouped by log type and a mined message template. Grouping runs in two stages. A regex normalizer masks syntactic variance first: common timestamp prefixes, UUIDs, long hexadecimal values, and decimal numbers with five or more digits. Drain then mines a template from the masked messages, which collapses the categorical variance no regex can reach without enumerating it — usernames, hostnames, file paths, commands, URL routes. Tokens that stay constant across a family survive both stages, so a port, an event ID, or an HTTP status code that never varies remains readable in the pattern; only positions that actually vary become `<*>`.

Mining is the only grouping engine. There is no flag to disable it, because masking alone leaves a high-entropy archive with nearly as many findings as it has events: on the labelled corpus in `tools/tune_drain.py`, 6,400 events across sixteen log families reduce to 5,352 distinct masked messages, and mining turns those into 25 templates.

DuckDB performs the scan, the deduplication, the join and the counting; Drain only sees the distinct masked strings, so the added cost scales with an archive's vocabulary rather than with its event count. Distinct messages are fed in sorted order and findings are keyed on the template text rather than on drain3's arrival-ordered `cluster_id`, so a given archive always yields the same findings. `below_threshold` grouping is untouched, because a rule ID is already the semantic grouping.

### Drain configuration

The Drain parameters are set in `wazuhcoverage.analysis` and differ from the drain3 defaults, which are not safe for this use.

| Parameter | Value | drain3 default | Reason |
| --- | --- | --- | --- |
| `sim_th` | 0.56 | 0.4 | The default merges log families a coverage report must separate. |
| `depth` | 4 | 4 | Unchanged; 3 measured identically and 5 only fragmented further. |
| `max_clusters` | 50,000 | unbounded | Caps miner memory near 55 MB on input that defeats grouping. |
| `parametrize_numeric_tokens` | `true` | `true` | Unchanged; disabling it multiplied templates without preventing a merge. |

The similarity threshold is the consequential one, and both directions fail loudly. At the drain3 default of 0.4, the corpus merges Windows `4624` with `4625` — a successful logon reported together with a failed one — and firewall `ACCEPT` with `DROP`. Above 0.57 the count jumps from 25 templates to 93 as families whose variable tokens are paths or hostnames shatter into one finding per value. Across three corpus seeds, 0.56 and 0.57 were the only values with neither defect, so 0.56 is taken with margin on both sides. Two tests in `tests/test_template_mining.py` guard that band: one fails if opposite outcomes of a family merge, the other if a high-cardinality family fragments.

The trade-off that remains is real. Drain merges by positional shape, so messages that share a shape but differ in meaning can still land in one finding, and `message_pattern` reports `<*>` where a username or path was. The tuning reduces that risk on the families measured; it does not eliminate it for shapes the corpus does not cover. `sample_log` is unaffected and stays source-derived, so every finding still carries a real line to replay. Mined state is per archive and never written to disk, so `history.db` remains the only persistent state, and templates are re-derived per archive rather than accumulated across them.

Malformed NDJSON is skipped rather than ignored. The distinction matters because ignoring it would corrupt the coverage denominator: DuckDB does not drop an unparseable line when errors are tolerated, it yields a NULL document, which would extract as an event with no decoder and inflate both `total_events` and the `no_decoder` bucket. Such lines are therefore excluded from every bucket and reported separately as `malformed_lines`, so the buckets still sum exactly to `total_events`. Lines that parse but are not objects — a bare scalar, array, or `null` — are rejected by strict mode too and are accounted for the same way; blank and whitespace-only lines are not data loss and are not counted.

Compressed `.json.gz` and uncompressed NDJSON archives are both supported directly by DuckDB.

## Scope

`wazuhcoverage` owns archive coverage analysis. It does not depend on `wazuhtester` and does not run Wazuh logtest internally. A higher-level toolkit can compose the libraries directly, for example by analyzing an archive with `wazuhcoverage` and replaying selected samples with `wazuhtester`.

`history.db` remains only a processed-path cache. It is not intended to become an analytics database. Malformed, legacy-pickle, or structurally invalid history files are never deserialized. Because history is only a disposable processed-path cache, the tool replaces such files atomically with an empty JSON history and continues.

## License

GNU General Public License version 2 only. See [LICENSE](LICENSE).
