# wazuhcoverage

`wazuhcoverage` answers one question about a Wazuh deployment: of everything the agents actually sent, how much did the ruleset do anything with? It reads a JSON archive, sorts every event into one of four coverage buckets, groups the uncovered ones into a short list of findings, and hands you one real log line per finding that you can replay through `wazuh-logtest`.

It works on `archives.json` and `archives.json.gz` produced by `<logall_json>yes</logall_json>`, offline and read-only. It never contacts a manager, an API, or an indexer, so it is safe to run against a copy of an archive on a laptop.

It ships as a library and a CLI in the same distribution. The CLI is a batch runner for a directory full of daily archives; the library is what you call when you want the numbers in your own program.

## Requirements

Python 3.9 or newer on Linux, macOS, or Windows. Two runtime dependencies install automatically: [DuckDB](https://duckdb.org/), which scans and aggregates, and [drain3](https://github.com/IBM/Drain3), which mines the templates that group findings.

Python 3.10 or newer is recommended. On 3.9 the DuckDB dependency is capped at `duckdb<1.5`, which no longer receives upstream fixes; 3.9 is kept only as a floor for hosts that still ship it.

One caveat applies to shared environments rather than to `pipx`: drain3 0.9.11 pins `jsonpickle` and `cachetools` to exact versions, so a project that itself requires `cachetools>=5` cannot install this package alongside it. See [design notes](https://github.com/zbalkan/wazuhcoverage/blob/master/docs/design-notes.md#dependency-constraints) if you hit that.

## Installation

For command-line use, [pipx](https://pipx.pypa.io/) keeps the tool and its dependencies isolated while putting `wazuhcoverage` on your `PATH`:

```bash
pipx install wazuhcoverage
pipx upgrade wazuhcoverage
pipx uninstall wazuhcoverage
```

To use the library from another project, install it into that project's environment:

```bash
python -m pip install wazuhcoverage
```

From a local checkout, `pipx install --editable .` for the CLI or `python -m pip install -e .` for the library.

## Quick start

Point it at one archive and read the report:

```bash
wazuhcoverage /var/ossec/logs/archives/2026/Sep/ossec-archive-18.json.gz
```

Sweep a month, then replay everything that is not covered through logtest:

```bash
wazuhcoverage --no-stats "/var/ossec/logs/archives/2026/**/*.json.gz" | wazuh-logtest
```

Re-read archives you have already processed:

```bash
wazuhcoverage -i "/var/ossec/logs/archives/2026/**/*.json.gz"
```

## Command line

```text
wazuhcoverage [-i|--ignore-history] [-n|--no-stats] [-s|--strict] TARGET [TARGET...]
```

There are no subcommands. Each `TARGET` is a literal path or a glob; `**` recurses. Quote globs so the shell does not expand them first. Multiple targets are allowed, overlapping matches are deduplicated, and archives are processed in sorted path order. Flags may appear before or after the targets.

| Short | Long | Effect |
| --- | --- | --- |
| `-i` | `--ignore-history` | Process an archive even if `history.db` already lists it. A successful run still records the path. |
| `-n` | `--no-stats` | Write only one representative log line per finding to stdout, one per row. Everything else goes to stderr. |
| `-s` | `--strict` | Reject the whole archive on the first unparseable line instead of skipping and counting it. |

All three short flags take no value, so they can be merged into one cluster in any order. These are equivalent:

```bash
wazuhcoverage -ins "/archives/**/*.json.gz"
wazuhcoverage -sin "/archives/**/*.json.gz"
wazuhcoverage -i -n -s "/archives/**/*.json.gz"
wazuhcoverage --ignore-history --no-stats --strict "/archives/**/*.json.gz"
```

| Exit code | Meaning |
| --- | --- |
| `0` | Every matched archive was processed. |
| `1` | At least one archive failed, or the downstream pipe closed early. |
| `2` | No target matched, or `history.db` could not be read. |

Progress lines, warnings, and the closing `Matched / Processed / Skipped / Failed` summary always go to stderr. Only the report or the samples go to stdout, so redirecting stdout gives you a clean file either way. One failing archive does not stop the run; the others still process and the failure is named on stderr.

### Processing history

The CLI remembers which archives it has already handled in `history.db`, a JSON file written in the current working directory. An archive listed there is skipped on the next run, which is what makes a nightly cron entry over a growing archive directory cheap.

A path is recorded only after analysis finished **and** stdout flushed, so a run that dies partway through, or whose downstream pipe closed, does not mark the archive as done. Delete the file to start over, or pass `--ignore-history` for one run. The library API does not use it.

### Replaying samples through logtest

`--no-stats` exists for exactly one pipeline:

```bash
wazuhcoverage --no-stats "/archives/**/*.json.gz" | wazuh-logtest
```

Each row is a real `full_log` taken from the archive, not a reconstruction. One log per row is a contract: `wazuh-logtest` reads one log per line, so a multi-line sample — a stack trace, a wrapped EventChannel record, anything collected with `multi-line` — would be replayed as several unrelated logs. Runs of `CR`/`LF` inside a sample are collapsed to a single space and the ends are trimmed. Nothing else is rewritten, so tabs and spacing reach logtest exactly as a decoder would see them. `Finding.sample_log` carries the same value for API callers.

### Malformed lines

A rotated or partially written archive usually ends in one truncated line. By default such a line is skipped and counted rather than failing the archive, because failing it would discard a whole day of coverage data.

The count is never hidden. It appears as `Malformed lines skipped` in the report, as a `wazuhcoverage: skipped N unparseable line(s)` warning on stderr, and as `ArchiveAnalysis.malformed_lines` in the API. Skipped lines are excluded from the event total, so the percentages stay exact. Blank lines are not data loss and are not counted. Use `--strict` when you would rather know immediately that an archive is damaged.

## Reading the report

```text
Archive: /archives/2026/09/archive.json.gz
Total events: 8
Malformed lines skipped: 0

Status
------
Status                          Events   % total
no_decoder                           3    37.50%
no_alerting_rule                     2    25.00%
at_or_above_threshold                2    25.00%
below_threshold                      1    12.50%

Log types
---------
Log type                                Events   % total  no_decoder  no_alerting_rule  below_threshold  at_or_above_threshold
sshd                                         4    50.00%           0                 1                1                      2
/var/log/app.log                             3    37.50%           3                 0                0                      0
windows                                      1    12.50%           0                 1                0                      0

Findings: 2

Note: a no_alerting_rule event carries no rule in the archive. Wazuh writes that
      same record whether no rule matched, the matching rule was level 0, or a
      rule's ignore window suppressed the match. Replay the sample through
      wazuh-logtest to tell those apart.

[1] no_decoder | /var/log/app.log
    Events: 3
    Affected agents: 2
    First seen: 2026-09-18 10:00:00+00
    Last seen: 2026-09-18 10:04:12+00
    Decoder: -
    Rule: -
    Level: -
    Pattern: app transaction <*> failed
    Sample: app transaction 12345 failed

[2] below_threshold | -
    Events: 1
    Affected agents: 1
    First seen: 2026-09-18 10:02:30+00
    Last seen: 2026-09-18 10:02:30+00
    Decoder: -
    Rule: 5715
    Level: 2
    Pattern: rule:5715
    Sample: Sep 18 10:02:30 host sshd[2201]: Accepted publickey for ops from 10.0.0.9 port 51022 ssh2
```

The **Status** table tells you how much of the archive the ruleset acted on. The **Log types** table tells you where the gaps live: it ranks each decoder or source by volume and breaks it down across the same four buckets, so a row's four counts add up to its `Events`. Every bucket is listed even at zero, because an empty bucket is a coverage statement rather than missing data.

`% total` is the share of `Total events`, which excludes malformed lines. Log types are ranked by volume, ties broken by name, and equal status counts keep the declared bucket order, so two runs over the same archive render identically.

Each **finding** is one group of uncovered events with a representative line. `Pattern` is the shape the group was mined down to, with `<*>` where values varied; `Sample` is a real line from the archive, ready to replay. `Affected agents` is how many distinct agents contributed, which separates a single noisy host from a fleet-wide gap. Nothing is ever truncated or wrapped — a long log type or sample widens its row instead — and the output is plain ASCII with no colour codes, so it survives redirection and a Windows code page.

## Classification

Every event lands in exactly one bucket, and the counts add up to the event total.

| Bucket | Meaning | Typical action |
| --- | --- | --- |
| `no_decoder` | Nothing decoded the event. | Write or fix a decoder; check the log format reaching the agent. |
| `no_alerting_rule` | It decoded, but the archive records no rule. | Replay the sample; see below. |
| `below_threshold` | A rule fired below the alert threshold. | Decide whether that rule should be raised, or accept it as tuned. |
| `at_or_above_threshold` | A rule fired at or above the threshold. | Covered. |

The CLI uses an alert threshold of 3. The library takes an `alert_threshold` argument if your `<log_alert_level>` differs. A rule with a missing or unparseable level counts as `below_threshold`, because it cannot be shown to meet the threshold.

### Reading a `no_alerting_rule` finding

This is the bucket that needs care, and the report says so next to the findings. Wazuh writes the same rule-less archive record in three different situations: no rule matched at all, a rule matched but sits at level 0, or a rule matched and its `ignore` window suppressed the event. The archive keeps no field that separates them, so this tool cannot either.

That matters because the three mean different things. A level-0 base rule such as `61100`, catching Windows System events no child rule claimed, is a real coverage gap. A local level-0 rule written to silence a known-noisy source is a decision someone already made deliberately. Both appear here with an empty `Rule` and `Level`.

Replaying the sample settles it:

```console
$ wazuh-logtest
...
**Phase 3: Completed filtering (rules).
        id: '61100'
        level: '0'
        description: 'Windows System informational event'
```

A replay that resolves to a level-0 rule means silenced, not undetected. A replay that reaches no rule means genuinely uncovered. If a level-0 rule dominates one of your log types and you control its child chain, `<rule id="61100" level="1" overwrite="yes">` restores rule information to the archive and collapses those events into a single `below_threshold` finding — at the cost of making the event an alert internally, which changes fired counters and what correlation rules keyed on that rule see. The mechanism behind all of this is in the [design notes](https://github.com/zbalkan/wazuhcoverage/blob/master/docs/design-notes.md#why-a-level-0-match-looks-like-no-rule).

## How findings are grouped

Findings exist so that ten thousand uncovered events become a list you can work through, not a list you scroll past.

`below_threshold` events group by rule ID, because the rule is already the semantic grouping. Such a finding deliberately claims no single log type, since one rule can fire across several decoders; use the Log types table for that breakdown.

`no_decoder` and `no_alerting_rule` events have no rule to group by, so they group by log type and by a mined message template. A regex pass first masks timestamps, UUIDs, long hexadecimal values, and long numbers; drain3 then mines a template that also collapses the categorical variation no regex can reach — usernames, hostnames, paths, commands, URL routes. Tokens that stay constant across a family survive both passes, so a port, an event ID, or an HTTP status code that never varies stays readable in the pattern, and only positions that actually vary become `<*>`.

Grouping is not configurable and the result is deterministic: the same archive always produces the same findings in the same order. Mined state lives in memory for the duration of one archive and is never written to disk. The tuning behind the miner, and the trade-off it accepts, are in the [design notes](https://github.com/zbalkan/wazuhcoverage/blob/master/docs/design-notes.md#template-mining).

## Python API

```python
from wazuhcoverage import (
    DEFAULT_ALERT_THRESHOLD,
    ArchiveAnalysis,
    Finding,
    LogTypeCount,
    StatusCount,
    analyze_archive,
)

analysis = analyze_archive("/archives/2026/09/archive.json.gz", alert_threshold=3)

print(analysis.total_events, analysis.malformed_lines)

for status in analysis.status_counts:
    print(f"{status.status:<24} {status.event_count:>8} {status.percentage:6.2f}%")

for finding in analysis.findings:
    if finding.observed_status == "no_alerting_rule":
        print(finding.log_type, finding.event_count, finding.sample_log)
```

`analyze_archive(path, *, alert_threshold=3, skip_malformed=True)` takes a `str` or `pathlib.Path`, expands `~`, and returns an `ArchiveAnalysis`. It raises `FileNotFoundError` for a missing path and `ValueError` for a negative threshold. Pass `skip_malformed=False` for the fail-fast behaviour `--strict` selects. Grouping is not parameterized, so two analyses of the same archive are always comparable.

| Model | Fields |
| --- | --- |
| `ArchiveAnalysis` | `path`, `total_events`, `malformed_lines`, `status_counts`, `log_type_counts`, `findings` |
| `StatusCount` | `status`, `event_count`, `percentage` |
| `LogTypeCount` | `status`, `log_type`, `event_count`, `percentage`, `status_percentage` |
| `Finding` | `finding_key`, `observed_status`, `log_type`, `message_pattern`, `event_count`, `affected_agents`, `first_seen`, `last_seen`, `observed_decoder`, `observed_rule_id`, `observed_rule_level`, `sample_log` |

All models are frozen dataclasses and every collection is a tuple, so a result can be cached or shared without defensive copying. `LogTypeCount.percentage` is the pair's share of the whole archive; `status_percentage` is its share of that one bucket, which ranks a log type inside a small bucket that a whole-archive percentage would flatten to nothing. The package is `py.typed`, and annotations resolve under `typing.get_type_hints()` on every supported interpreter.

Glob expansion, `history.db`, report rendering, stdout and stderr, and exit codes are CLI concerns and are deliberately outside the analysis API.

### Compatibility

The status strings carried by `StatusCount.status`, `LogTypeCount.status`, and `Finding.observed_status` are part of the API surface. Version 0.4.0 renamed `no_rule` to `no_alerting_rule`; a consumer matching on the old string must be updated. No alias is provided, because the old name asserted something an archive cannot show.

## Limitations

The tool reads archives and nothing else, which is what makes it safe to run offline, and also what bounds it. It cannot distinguish an unmatched event from a level-0 or suppressed one, as described above. It reports what Wazuh recorded, so an archive written by a manager whose ruleset has since changed describes that older ruleset.

Grouping merges by positional shape, so messages that share a shape but differ in meaning can land in one finding, and a pattern shows `<*>` where a username or path was. The tuning reduces that on the log families it was measured against; it does not eliminate it for shapes that corpus does not cover. Samples are unaffected, so every finding still carries a real line to check.

`wazuhcoverage` does not run logtest for you and does not depend on `wazuhtester`. Composing the two — analyze here, replay there — is a caller's job, and keeping that boundary is why this package stays installable anywhere a Python interpreter runs.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m ruff format --check .
```

`tools/tune_drain.py` rebuilds the labelled corpus the miner's parameters were selected against and prints the grid. Re-run it after changing the normalizer, the corpus, or the drain3 version:

```bash
python tools/tune_drain.py
```

`tools/check_dependency_pins.py` walks the installed dependency graph and fails when an exact version pin appears or disappears. CI runs it on every supported interpreter alongside `pip check`, so a new dependency that narrows what this package can coexist with fails review rather than a user's install.

Design rationale, measurements, and the upstream Wazuh behaviour this tool has to work around live in [docs/design-notes.md](https://github.com/zbalkan/wazuhcoverage/blob/master/docs/design-notes.md).

## License

GNU General Public License version 2 only. See [LICENSE](LICENSE).
