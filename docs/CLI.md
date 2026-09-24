# Command-line reference

The README covers the normal workflow. This page documents the exact CLI contract: target resolution, streams, output, exit status, replay behaviour, and report interpretation.

## Usage

```text
wazuhcoverage [-n|--no-stats] [-s|--strict] [-f|--log-format FORMAT] [TARGET...]
wazuhcoverage (-V|--version)
wazuhcoverage (-h|--help)
```

There are no subcommands. Each `TARGET` is a literal path, a glob, or `-` for standard input. `**` recurses. Quote globs so the shell does not expand them first. Multiple targets are allowed, overlapping matches are deduplicated, and archives are processed in sorted path order.

| Short | Long | Effect |
| --- | --- | --- |
| `-n` | `--no-stats` | Write one representative log line per finding to stdout. Progress and warnings remain on stderr. |
| `-s` | `--strict` | Reject an archive on its first unparseable line instead of skipping and counting malformed lines. |
| `-f` | `--log-format FORMAT` | Log format supplied when findings are replayed through `wazuh-logtest`. Default: `syslog`. |
| `-V` | `--version` | Print the installed version and exit. |
| `-h` | `--help` | Print usage and exit. |

The boolean short options may be clustered:

```bash
wazuhcoverage -sn "/archives/**/*.json.gz"
wazuhcoverage -n -s "/archives/**/*.json.gz"
```

`-f` takes an argument and therefore must end a short-option cluster:

```bash
wazuhcoverage -snf json "/archives/**/*.json.gz"
wazuhcoverage -snfjson "/archives/**/*.json.gz"
wazuhcoverage --strict --no-stats --log-format json "/archives/**/*.json.gz"
```

Prefer the long form in scripts where ambiguity would be expensive. In ordinary getopt-style parsing, `-fsn json` means that `sn` is the value of `-f`, not two more flags.

## Inputs

A target can be a plain `archives.json` file, a gzipped `archives.json.gz` file, or a glob matching either. The files are read-only.

```bash
wazuhcoverage /var/ossec/logs/archives/2026/Sep/ossec-archive-18.json.gz
wazuhcoverage "/var/ossec/logs/archives/2026/**/*.json.gz"
```

Within one run, literal paths and glob matches are reduced to a set of absolute paths, so the same archive is processed once even when several targets match it. Across runs there is deliberately no processed-path cache: every matched archive is read again. Use a dated or otherwise narrow glob when scheduling incremental runs.

### Standard input

Use `-` for standard input, or omit targets when stdin is already a pipe:

```bash
cat logs.json | wazuhcoverage -sn
gunzip -c archive.json.gz | wazuhcoverage -
ssh manager "cat /var/ossec/logs/archives/2026/Sep/ossec-archive-18.json.gz" | wazuhcoverage
```

Plain and gzipped streams are detected automatically. A stream can be combined with path targets and is processed first.

DuckDB needs seekable input, so stdin is spooled to a temporary file. Reports identify it as `<stdin>`, not by the temporary filename. For a large archive that already exists on disk, pass its path instead of piping it.

If stdin is a terminal and no target is supplied, the command exits with status `2` rather than waiting indefinitely. An empty pipe produces an empty report and a warning.

## Output and exit status

Reports and sample rows go to stdout. Progress, warnings, and the final `Matched / Processed / Failed` summary go to stderr, so stdout can be redirected or piped without mixing in diagnostics.

One archive failing does not stop the remaining targets.

| Exit code | Meaning |
| --- | --- |
| `0` | Every matched archive was processed. |
| `1` | At least one archive failed, or a downstream pipe closed early. |
| `2` | No target was supplied or matched. |
| `143` | The run received SIGTERM. It stops at once and removes its temporary files first. |

`--version` prints `wazuhcoverage <version>` to stdout and exits `0` without requiring a target. The version comes from the installed distribution. Combining `--version` with other flags prints a warning because those flags are not used.

## Memory and temporary disk

An archive is analysed in memory while it fits and on disk when it does not. DuckDB runs with its own defaults: a memory limit of 80% of physical memory and one thread per core. Once it reaches that limit it moves the event table and large sorts, joins and aggregations to a spill directory instead of failing, so disk is used only when the archive would otherwise not fit.

Those defaults are sized for a machine the analysis has to itself. On a host shared with a Wazuh manager, run the analysis where it cannot compete with the manager for memory, or copy the archive elsewhere first.

The spill directory is created under the system temporary directory, private to each archive, and removed when that archive is done. Set `TMPDIR` to choose where it goes. If the temporary directory is a `tmpfs`, as on some Linux distributions, spilling lands in memory after all; point `TMPDIR` at a disk-backed path instead.

## Malformed archive lines

A partially written or rotated archive can end in a truncated JSON line. By default, `wazuhcoverage` skips unparseable lines, counts them, and excludes them from the event denominator. Blank lines are not counted as malformed.

The skipped count appears in the report and a warning is written to stderr. Use `--strict` when any malformed line should reject the archive.

## Coverage report

Every parsed event is assigned to exactly one observed bucket:

| Outcome | Bucket | Meaning |
| --- | --- | --- |
| Processed | `at_or_above_threshold` | A rule fired at or above the configured alert threshold. |
| Dropped | `no_decoder` | No decoder was recorded for the event. |
| Dropped | `no_alerting_rule` | The event decoded, but the archive records no alerting rule. |
| Dropped | `below_threshold` | A rule fired below the alert threshold. |

The CLI reads `<alerts><log_alert_level>` from `/var/ossec/etc/ossec.conf` when that local configuration is readable. If it is absent or cannot be read, the CLI assumes Wazuh's documented default of `3`. The resolved value and its provenance are printed near the top of every statistics report, for example `Alert threshold: 6 (from /var/ossec/etc/ossec.conf)` or `Alert threshold: 3 (Wazuh default assumed; could not read /var/ossec/etc/ossec.conf)`. The same resolved value is used for both archive classification and manager replay. Library callers choose the threshold explicitly; see [API.md](API.md).

Without replay results, the report starts with an archive outcome table, then breaks those observed outcomes down by log type, followed by grouped findings. `% total` uses all parsed events as its denominator. `% dropped` uses only dropped events.

A finding represents a group of similar uncovered events. It includes event count, affected agents, time range, observed decoder/rule information, a mined message pattern, and one real sample from the archive. The sample is suitable for replay: embedded CR/LF runs are collapsed to one space so one source event remains one input line.

`below_threshold` findings group by rule ID. `no_decoder` and `no_alerting_rule` findings group by log type and a message template mined with drain3. The implementation, determinism rules, and tuning rationale are in [DESIGN.md](DESIGN.md#template-mining).

## Manager replay

An archive alone cannot always distinguish an event that was genuinely unmatched from one that was deliberately quiet. When the optional `logtest` extra is installed and a usable Wazuh manager socket is available, the CLI automatically replays one representative sample per relevant finding through `wazuh-logtest`.

The replay provides an effective state for the representative sample:

| Effective state | Meaning |
| --- | --- |
| `no_decoder` | The replay still does not decode. |
| `uncovered` | It decodes and no rule matches. |
| `suppressed` | A level-0 rule matches. |
| `below_threshold` | A rule matches below the alert threshold. |
| `at_or_above_threshold` | A rule matches at or above the threshold. |
| `unverified` | Replay did not produce a usable answer. |

A replay failure is `unverified`, never `uncovered`.

For a replayed finding, the CLI displays this effective state as its status and uses the replayed decoder, rule ID, and level. It does not repeat the archive's `no_alerting_rule` status or blank rule fields beside a confirmed match. With replay results present, the outcome and log-type tables still cover the whole archive: they replace each replayed finding's observed status with the sample's effective verdict and use its replay decoder as the log type when available. The other events retain their archive observations. Processed means an alerting rule met the threshold; Suppressed means a rule matched at level 0 or below the threshold; Dropped means no decoder or matching rule; Unresolved covers unreplayed rule-less events and replay failures. The separate effective-coverage table reports the replayed findings alone. Counts attributed to replay verdicts are the sizes of their represented findings; only one sample from each finding was replayed.

Findings appear under Dropped, Processed, and, when needed, Unresolved headings. A suppressed or below-threshold finding belongs to Processed because a rule matched, even though it did not produce an alert. Each heading sorts findings by event count, largest first, and numbers them within that heading. The outcome table keeps Suppressed separate so its count is visible.

Replay describes the manager used for the replay, which may not have the same ruleset as the manager that originally wrote the archive. A single-sample replay also cannot reproduce rules that require event history, and the archive does not preserve the original `log_format`. These limitations are explained in [CAVEATS.md](CAVEATS.md).

For JSON or EventChannel-style input, set the format explicitly when needed:

```bash
wazuhcoverage --log-format json /path/to/archive.json.gz
```

The `--no-stats` mode can also feed representative samples to a separate `wazuh-logtest` process, which is useful when analysis and replay happen on different hosts:

```bash
wazuhcoverage --no-stats "/archives/**/*.json.gz" | wazuh-logtest
```

## Wazuh background

For Wazuh behaviour itself, use the upstream documentation rather than this project:

- [Archiving event logs](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html#archiving-event-logs)
- [Alert threshold](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html#alert-threshold)
- [Rules classification](https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html)
- [wazuh-logtest tool reference](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
- [wazuh-logtest development reference](https://documentation.wazuh.com/current/development/wazuh-logtest.html)
- [rule_test configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/rule-test.html#reference-ossec-rule-test)
- [wazuh-analysisd](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html#wazuh-analysisd)
- [How Wazuh log data collection works](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html)
