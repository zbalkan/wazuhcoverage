# wazuhcoverage

`wazuhcoverage` answers one question about a Wazuh deployment: of everything the agents actually sent, how much did the ruleset do anything with? It reads a JSON archive, sorts every event into one of four coverage buckets, groups the uncovered ones into a short list of findings, and hands you one real log line per finding that you can replay through `wazuh-logtest`.

It works on `archives.json` and `archives.json.gz` produced by `<logall_json>yes</logall_json>`, read-only.

Where it can, it also asks the manager. An archive cannot tell you whether an event nothing alerted on was unmatched or deliberately silenced — Wazuh writes the same record either way — but `wazuh-logtest` can. When its socket is reachable, one representative sample per finding is replayed and the report gains an effective state per finding. When it is not, the run says so on stderr and reports from the archive alone. There is no flag for either; the tool uses what is there.

Read [docs/CAVEATS.md](https://github.com/zbalkan/wazuhcoverage/blob/master/docs/CAVEATS.md) before trusting the numbers. It documents the Wazuh behaviours that make a coverage report harder to read than it looks.

It ships as a library and a CLI in the same distribution. The CLI is a batch runner for a directory full of daily archives; the library is what you call when you want the numbers in your own program. Neither keeps state: a run reads the archives you name, writes its output, and leaves nothing behind.

## Requirements

Python 3.9 or newer on Linux, macOS, or Windows. Two runtime dependencies install automatically: [DuckDB](https://duckdb.org/), which scans and aggregates, and [drain3](https://github.com/IBM/Drain3), which mines the templates that group findings.

Python 3.10 or newer is recommended. On 3.9 the DuckDB dependency is capped at `duckdb<1.5`, which no longer receives upstream fixes; 3.9 is kept only as a floor for hosts that still ship it.

Replaying findings through `wazuh-logtest` is an optional extra with stricter requirements of its own: Linux, Python 3.10 or newer, and a reachable manager. It is used automatically when all three hold, and skipped with a warning when any does not.

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

To let it replay findings through `wazuh-logtest`, install the `logtest` extra on the Wazuh manager itself, or on a host that can reach its socket:

```bash
pipx install "wazuhcoverage[logtest]"
python -m pip install "wazuhcoverage[logtest]"
```

The extra pulls in [wazuhtester](https://github.com/zbalkan/wazuhtester), which needs Linux, Python 3.10 or newer, and a running manager. Without it, or away from a manager, the tool warns once and reports from the archive alone.

From a local checkout, `pipx install --editable .` for the CLI or `python -m pip install -e .` for the library.

## Quick start

Point it at one archive and read the report. Run it on the manager and it also replays what it finds:

```bash
wazuhcoverage /var/ossec/logs/archives/2026/Sep/ossec-archive-18.json.gz
```

Sweep a month, then replay everything that is not covered through logtest:

```bash
wazuhcoverage --no-stats "/var/ossec/logs/archives/2026/**/*.json.gz" | wazuh-logtest
```

Feed it an archive on standard input, from a file, a decompressor, or a remote host:

```bash
cat logs.json | wazuhcoverage -sin
ssh manager "cat /var/ossec/logs/archives/2026/Sep/ossec-archive-18.json.gz" | wazuhcoverage
```

## Command line

```text
wazuhcoverage [-n|--no-stats] [-s|--strict] [--log-format FORMAT] [TARGET...]
wazuhcoverage (-V|--version)
wazuhcoverage (-h|--help)
```

There are no subcommands. Each `TARGET` is a literal path, a glob, or `-` for standard input; `**` recurses. Quote globs so the shell does not expand them first. Multiple targets are allowed, overlapping matches are deduplicated, and archives are processed in sorted path order. Flags may appear before or after the targets.

| Short | Long | Effect |
| --- | --- | --- |
| `-n` | `--no-stats` | Write only one representative log line per finding to stdout, one per row. Everything else goes to stderr. |
| `-s` | `--strict` | Reject the whole archive on the first unparseable line instead of skipping and counting it. |
|  | `--log-format` | Log format reported to `wazuh-logtest` when replaying. Default `syslog`. Ignored when no manager is reachable. |
| `-V` | `--version` | Print the installed version and exit. Needs no target. |
| `-h` | `--help` | Print usage and exit. |

The two short behaviour flags take no value, so they can be merged in either order. `--log-format` takes a value and cannot join a cluster. These are equivalent:

```bash
wazuhcoverage -ns "/archives/**/*.json.gz"
wazuhcoverage -sn "/archives/**/*.json.gz"
wazuhcoverage -n -s "/archives/**/*.json.gz"
wazuhcoverage --no-stats --strict "/archives/**/*.json.gz"
```

| Exit code | Meaning |
| --- | --- |
| `0` | Every matched archive was processed. |
| `1` | At least one archive failed, or the downstream pipe closed early. |
| `2` | No target was given or matched. |

`--version` prints `wazuhcoverage <version>` to stdout and exits `0` without needing a target, so it is safe to call from a health check or a deployment script. The number it prints is the same one the installed distribution carries; `pyproject.toml` reads it from `wazuhcoverage.__version__`, so the two cannot disagree.

Progress lines, warnings, and the closing `Matched / Processed / Failed` summary always go to stderr. Only the report or the samples go to stdout, so redirecting stdout gives you a clean file either way. One failing archive does not stop the run; the others still process and the failure is named on stderr.

### Repeated runs

A run holds no state. Every archive a target resolves to is read every time, and nothing is written outside stdout and stderr.

Within one run, overlapping targets are still collapsed: `resolve_targets` reduces literal paths and globs to a set of absolute paths, so naming the same archive twice, or matching it with two patterns, reads it once.

Across runs, narrow the targets rather than asking the tool to remember. A dated glob costs nothing and is auditable:

```bash
wazuhcoverage "/var/ossec/logs/archives/2026/Sep/ossec-archive-$(date +%d).json.gz"
```

There is deliberately no processed-path cache. One would make a run's behaviour depend on the directory it was launched from and on a file nobody inspects, and it would buy only what a narrower glob already gives.

### Reading from standard input

An archive can arrive on a pipe instead of as a path. Either spell it as the target `-`, or leave the targets out entirely and let the tool notice that stdin is not a terminal:

```bash
cat logs.json | wazuhcoverage -sin
gunzip -c archive.json.gz | wazuhcoverage -
ssh manager "cat /var/ossec/logs/archives/2026/Sep/ossec-archive-18.json.gz" | wazuhcoverage -n | wazuh-logtest
```

Plain and gzipped streams both work; the stream is sniffed for gzip's magic number, so nothing needs to be declared. A piped archive may be mixed with path targets, and is always processed first.

Two things differ from analyzing a path, both consequences of a stream having no name:

The report calls it `<stdin>` rather than naming the temporary file it was spooled to, so two runs over the same stream produce the same report. And it costs temporary disk space of its own size, because DuckDB scans and seeks within a file and a pipe offers neither. For a multi-gigabyte archive that is already on disk, pass the path.

If stdin is a terminal and no target is given, the tool asks for one and exits `2` rather than waiting for input that is not coming. If it is a pipe that turns out to be empty, you get an empty report and a `read 0 bytes from stdin` warning on stderr.

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

Outcome
-------
Outcome                                    Events   % total   % dropped
Processed (at_or_above_threshold)               2    25.00%           -
Dropped                                         6    75.00%     100.00%
  no_decoder                                    3    37.50%      50.00%
  no_alerting_rule                              2    25.00%      33.33%
  below_threshold                               1    12.50%      16.67%

Log types
---------
Log type                                Events   % total   Processed     Dropped  no_decoder  no_alerting_rule  below_threshold
sshd                                         4    50.00%           2           2           0                 1                1
/var/log/app.log                             3    37.50%           0           3           3                 0                0
windows                                      1    12.50%           0           1           0                 1                0

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

The **Outcome** table answers the coverage question in two rows before it explains anything. An event was either processed — a rule fired on it at or above the alert threshold, which is the one outcome that reaches an alert — or it was dropped, and the three indented rows say why. They are the same buckets the API reports as `observed_status`, so `Processed` is exactly `at_or_above_threshold` and the indented three are exactly the rest; the report names the bucket next to `Processed` rather than leaving that mapping to this page. The three sum back to `Dropped`, and `Processed` plus `Dropped` is `Total events`.

`% total` is the share of `Total events`, which excludes malformed lines, while `% dropped` is the share of the dropped events alone. The second column is what ranks the work: a bucket holding four per cent of an archive that is ninety-five per cent covered is most of what remains, and `% total` alone makes it look negligible. It reads `-` on the `Processed` row, which is not part of that denominator, and on every row of an archive that dropped nothing, where a column of `0.00%` would read as a measurement rather than an empty set.

The **Log types** table tells you where the gaps live: it ranks each decoder or source by volume, splits it across the same two outcomes, and then breaks the dropped column into its three buckets. A row's `Processed` and `Dropped` add up to its `Events`, and its last three columns add up to its `Dropped`. Every bucket is listed even at zero, because an empty bucket is a coverage statement rather than missing data.

Log types are ranked by volume, ties broken by name, and equal status counts keep the declared bucket order, so two runs over the same archive render identically.

Each **finding** is one group of uncovered events with a representative line. `Pattern` is the shape the group was mined down to, with `<*>` where values varied; `Sample` is a real line from the archive, ready to replay. `Affected agents` is how many distinct agents contributed, which separates a single noisy host from a fleet-wide gap. Nothing is ever truncated or wrapped — a long log type or sample widens its row instead — and the output is plain ASCII with no colour codes, so it survives redirection and a Windows code page.

## Classification

Every event lands in exactly one bucket, and the counts add up to the event total. The report groups those four buckets into two outcomes; the bucket names are what the API returns and what the tables below use.

| Outcome | Bucket | Meaning | Typical action |
| --- | --- | --- | --- |
| Processed | `at_or_above_threshold` | A rule fired at or above the threshold. | Covered. |
| Dropped | `no_decoder` | Nothing decoded the event. | Write or fix a decoder; check the log format reaching the agent. |
| Dropped | `no_alerting_rule` | It decoded, but the archive records no rule. | Replay the sample; see below. |
| Dropped | `below_threshold` | A rule fired below the alert threshold. | Decide whether that rule should be raised, or accept it as tuned. |

`Dropped` names what the alert pipeline did with the event, not what the archive did: all four buckets are archived records, and a dropped event is one that produced no alert. `below_threshold` is dropped in that sense while having been decoded and matched, which is why the breakdown matters more than the total — one of those three rows is a tuning decision someone already made, and the other two are usually gaps.

The CLI uses an alert threshold of 3. The library takes an `alert_threshold` argument if your `<log_alert_level>` differs. A rule with a missing or unparseable level counts as `below_threshold`, because it cannot be shown to meet the threshold.

### Resolving a `no_alerting_rule` finding

This is the bucket that needs care. Wazuh writes the same rule-less archive record in three different situations: no rule matched at all, a rule matched but sits at level 0, or a rule matched and its `ignore` window suppressed the event. The archive keeps no field that separates them, and [docs/CAVEATS.md](https://github.com/zbalkan/wazuhcoverage/blob/master/docs/CAVEATS.md#an-archived-event-that-matched-a-level-0-rule-carries-no-rule) shows the analysisd code that makes it so.

The three mean different things. A level-0 base rule such as `61100`, catching Windows System events no child rule claimed, is a real coverage gap. A local level-0 rule written to silence a known-noisy source is a decision someone already made. Both otherwise appear with an empty `Rule` and `Level`.

A replay settles it, because `wazuh-logtest` reports the rule it matched whatever that rule's level is. Run the tool where the socket is reachable and the report gains an effective state without being asked:

```text
Effective coverage (wazuh-logtest)
----------------------------------
State                       Findings        Events  % replayed
silenced                          14        38,204      92.19%
uncovered                          6         3,120       7.53%
no_decoder                         1           118       0.28%

[2] no_alerting_rule | windows_eventchannel
    ...
    Rule: -
    Level: -
    Effective: silenced (rule 61100, level 0)
    Matched: Windows System informational event
```

`Rule` and `Level` stay empty, because that is what the archive holds. `Effective` is what actually happens today, and the note about what an absent rule cannot prove disappears, because a replay has answered it.

| Effective state | Meaning |
| --- | --- |
| `no_decoder` | Still nothing decodes it. |
| `uncovered` | It decodes and no rule matches. A real gap. |
| `silenced` | A rule matched at level 0. Recognised and deliberately quiet. |
| `below_threshold` | A rule matched under the alert threshold. |
| `at_or_above_threshold` | A rule matched at or above it. |
| `unverified` | The replay produced no usable answer. Never inferred from the archive. |

Where no socket is reachable, the run warns once on stderr and the report carries its note instead:

```text
wazuhcoverage: the wazuh-logtest socket at /var/ossec/queue/sockets/logtest is not answering
wazuhcoverage: reporting from the archive alone, which cannot tell an unmatched event from a silenced one; see docs/CAVEATS.md
```

Three things are worth knowing before you trust a replayed run, and all three are expanded in [docs/CAVEATS.md](https://github.com/zbalkan/wazuhcoverage/blob/master/docs/CAVEATS.md):

It answers for the manager you replay against, not the one that wrote the archive. It cannot reproduce a rule that only fires on the Nth event, so a finding covered solely by such a rule reports `uncovered`. And `--log-format` matters: the archive does not record the format, the default is `syslog`, and a JSON or EventChannel source replayed as `syslog` resolves against the wrong decoder chain. The location *is* taken from the archive, so that part is faithful.

A failed replay is `unverified`, never `uncovered`. Inventing a coverage gap out of a broken socket is the one mistake this must not make.

`wazuhcoverage --no-stats ... | wazuh-logtest` still does the same thing by hand, which is useful when the archive and the manager are on different machines.

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
| `Finding` | `finding_key`, `observed_status`, `log_type`, `message_pattern`, `event_count`, `affected_agents`, `first_seen`, `last_seen`, `observed_decoder`, `observed_location`, `observed_rule_id`, `observed_rule_level`, `sample_log` |
| `Verification` | `finding_key`, `effective_state`, `logtest_status`, `decoder`, `rule_id`, `rule_level`, `rule_description`, `rule_groups`, `error` |

`STATUSES` names the archive's buckets and `EFFECTIVE_STATES` names the replay verdicts. They are separate because they answer different questions: one reports what the record holds, the other what the manager does. `PROCESSED_STATUS` and `DROPPED_STATUSES` are the report's two-outcome grouping over `STATUSES`, exported so a caller can reproduce the split without hardcoding the bucket name; no model field changes with it, and `observed_status` keeps naming the exact bucket.

All models are frozen dataclasses and every collection is a tuple, so a result can be cached or shared without defensive copying. `LogTypeCount.percentage` is the pair's share of the whole archive; `status_percentage` is its share of that one bucket, which ranks a log type inside a small bucket that a whole-archive percentage would flatten to nothing. The package is `py.typed`, and annotations resolve under `typing.get_type_hints()` on every supported interpreter.

Glob expansion, report rendering, stdout and stderr, and exit codes are CLI concerns and are deliberately outside the analysis API.

### Verifying findings

`verify_findings()` is the library side of what the CLI does automatically. It is a separate call rather than an argument to `analyze_archive()`, so analysis stays offline and pure: nothing in `analyze_archive()` opens a socket, and a caller that never imports this function never needs the optional dependency.

```python
from wazuhcoverage import analyze_archive, verify_findings

analysis = analyze_archive("/archives/2026/09/archive.json.gz")
verdicts = {v.finding_key: v for v in verify_findings(analysis, log_format="json")}

for finding in analysis.findings:
    verdict = verdicts.get(finding.finding_key)
    if verdict and verdict.effective_state == "uncovered":
        print(finding.event_count, finding.sample_log)
```

`verify_findings(analysis, *, alert_threshold=3, statuses=("no_decoder", "no_alerting_rule"), log_format="syslog", socket_path=None)` replays one sample per selected finding and returns a `Verification` for each, in findings order. It raises `RuntimeError` when `wazuhtester` is missing or the socket refuses connections, and `ValueError` for a negative threshold. A failure on one sample is a result, not an exception: that finding comes back `unverified` with the error text and the rest still run.

Widen `statuses` to replay buckets the archive already resolved — useful for auditing whether the manager still behaves as the archive says, at the cost of a round trip per finding.

The library does not decide policy. `verify_findings()` raises when no manager is reachable, because a caller that asked for a replay is owed the reason; `unavailable_reason(socket_path=None)` returns that reason as a string, or `None` when a replay is possible, which is how the CLI chooses to carry on without one.

## Limitations

Left to itself the tool reads archives and nothing else, which is what makes it safe to run offline and also what bounds it. From the archive alone it cannot distinguish an unmatched event from a level-0 or suppressed one, and it reports what Wazuh recorded, so an archive written by a manager whose ruleset has since changed describes that older ruleset.

Grouping merges by positional shape, so messages that share a shape but differ in meaning can land in one finding, and a pattern shows `<*>` where a username or path was. The tuning reduces that on the log families it was measured against; it does not eliminate it for shapes that corpus does not cover. Samples are unaffected, so every finding still carries a real line to check.

Replaying through `wazuh-logtest` removes the level-0 ambiguity and brings limits of its own: it answers for the manager you replay against rather than the one that wrote the archive, it cannot reproduce a rule that needs several events, and it depends on `--log-format` being right for the source. Where no manager is reachable nothing opens a socket, and the tool stays installable anywhere a Python interpreter runs.

[docs/CAVEATS.md](https://github.com/zbalkan/wazuhcoverage/blob/master/docs/CAVEATS.md) collects the Wazuh behaviours behind all of this and is worth reading once before acting on a report.

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

Design rationale and measurements live in [docs/design-notes.md](https://github.com/zbalkan/wazuhcoverage/blob/master/docs/design-notes.md). The upstream Wazuh behaviour this tool works around is in [docs/CAVEATS.md](https://github.com/zbalkan/wazuhcoverage/blob/master/docs/CAVEATS.md).

## License

GNU General Public License version 2 only. See [LICENSE](LICENSE).
