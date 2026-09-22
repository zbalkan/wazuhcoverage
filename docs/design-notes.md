# Design notes

Rationale behind decisions that the [README](../README.md) states as behaviour. Nothing here is needed to use the tool; it exists so that a change to any of it is made deliberately, with the measurement or the upstream constraint in view.

## Why the ambiguous bucket is named as it is

Wazuh's analysisd drops the matched rule from an archived event when that rule sits at level 0, and again when a rule's `ignore` window suppresses the event. The mechanism, with source references, is in [docs/CAVEATS.md](https://github.com/zbalkan/wazuhcoverage/blob/master/docs/CAVEATS.md); what follows is what this project does about it.

The bucket is named for what the record proves — no alerting rule was attached — rather than for the stronger claim that no rule was evaluated. `no_rule`, the obvious name, is the one it must not have: a reader acts on that name, and acting on it means writing a rule for an event a level-0 rule already recognises.

When no replay is possible the report prints a note beside the findings, because an empty `Rule` and `Level` otherwise imply the stronger claim on their own. When a replay is possible the note is dropped, since the `Effective` line has answered the question the note exists to raise.

`tests/test_analysis_integration.py` pins both the bucket name and the classification of a real archived EventChannel event that logtest resolves to rule `61100` at level 0.

## Verification through logtest

Verification lives in `wazuhcoverage.verification` and nowhere else. `analyze_archive()` opens no socket and gains no parameter for one, so the analysis path stays offline, deterministic, and installable on a laptop; `verify_findings()` is a separate call whose optional dependency a caller that never invokes it never needs.

### One replay per finding

The unit of replay is the finding, not the event. That is what grouping bought: an archive with forty thousand uncovered EventChannel records that mine to fourteen templates costs fourteen round trips, not forty thousand. Findings already carry a deterministic representative sample chosen for exactly this purpose.

### A session per sample

`wazuhtester` offers `send_multiple_logs()`, which shares one daemon session so that frequency and composite rules can fire. That is the wrong primitive here: the samples in a coverage report are unrelated messages from different log families, and a shared session would let them prime each other. Each sample therefore goes through `send_log()` without a token, which creates and removes a session of its own. The blind spot that buys, and why that trade was taken, is in [docs/CAVEATS.md](https://github.com/zbalkan/wazuhcoverage/blob/master/docs/CAVEATS.md#logtest-sees-one-event-so-frequency-rules-never-fire).

### Location, and what could not be derived

`Finding` carries `observed_location`, taken from the archive with `any_value()` over the group, because the decoder chain consults it. `log_format` could not be handled the same way, since the archive does not record it; it is a parameter with wazuh-logtest's own `syslog` default. Both are covered in [docs/CAVEATS.md](https://github.com/zbalkan/wazuhcoverage/blob/master/docs/CAVEATS.md#location-decides-the-decoder-and-a-pasted-log-has-none).

### Failure is never a gap

A replay that does not produce a usable answer is `unverified`, and `unverified` is never inferred from the archive. A daemon error, a raised exception, an unrecognized status, and a matched rule whose level cannot be read all land there with the reason attached. Turning a broken socket into a coverage gap would send someone to write a rule for an event that is already handled, which is the specific failure this whole feature exists to prevent.

Configuration faults are separated from results. A missing `wazuhtester` or a socket that refuses connections is the same fault for every archive, so the CLI probes once before scanning anything and exits `2`. Discovering it after thirty archives, or printing reports whose effective column is silently absent, would be the expensive way to learn about a typo.

### Best effort, decided once

The CLI probes for a usable daemon once, before the first archive is read, and reports from the archive alone when there is none. Deciding per archive would be the same answer computed repeatedly; deciding lazily, at the first finding, would bury the warning in the middle of a report whose effective column had silently gone missing.

`verify_findings()` does not adopt that policy. A caller that asked for a replay is owed the reason it could not happen, so the library raises and `unavailable_reason()` exists for callers that would rather carry on. Policy lives in the CLI; the library states facts.

The archive's own `Rule` and `Level` stay in the report beside the `Effective` line rather than being overwritten by it, because a replay answers for the manager running now rather than the one that wrote the archive.

## Template mining

Findings for `no_decoder` and `no_alerting_rule` group by a template mined with [drain3](https://github.com/IBM/Drain3). Masking alone is not enough: on the labelled corpus in `tools/tune_drain.py`, 6,400 events across sixteen log families reduce to 5,352 distinct masked messages, and mining turns those into 25 templates. A report with one finding per event is not a report.

Mining is the only grouping engine and there is no flag to disable it, so two analyses of the same archive are always comparable.

### Parameters

The parameters are set in `wazuhcoverage.analysis` and differ from the drain3 defaults, which are not safe for this use.

| Parameter | Value | drain3 default | Reason |
| --- | --- | --- | --- |
| `sim_th` | 0.56 | 0.4 | The default merges log families a coverage report must separate. |
| `depth` | 4 | 4 | Unchanged; 3 measured identically and 5 only fragmented further. |
| `max_clusters` | 50,000 | unbounded | Bounds mining time and memory on input that defeats grouping. |
| `parametrize_numeric_tokens` | `true` | `true` | Unchanged; disabling it multiplied templates without preventing a merge. |

The similarity threshold is the consequential one, and both directions fail loudly. At the drain3 default of 0.4 the corpus merges Windows `4624` with `4625` — a successful logon reported together with a failed one — and firewall `ACCEPT` with `DROP`. Above 0.57 the count jumps from 25 templates to 93 as families whose variable tokens are paths or hostnames shatter into one finding per value. Across three corpus seeds, 0.56 and 0.57 were the only values with neither defect, so 0.56 is taken with margin on both sides. Two tests in `tests/test_template_mining.py` guard that band: one fails if opposite outcomes of a family merge, the other if a high-cardinality family fragments.

drain3 is configured explicitly rather than from a `drain3.ini`, because the library otherwise loads one from the current working directory, which would make an archive's findings depend on where the command happened to run. No masking instructions are registered with drain3 either; the SQL normalizer already applies the masks the README documents, and a second masking pass would silently widen them.

### Cost and the cluster cap

Mining cost tracks an archive's vocabulary, not its event count, because DuckDB deduplicates first and drain3 only ever sees the distinct masked strings. It degrades sharply only when messages share no structure at all, since every message then becomes its own cluster. Measured on such input, 60,000 distinct shapes took 103 seconds, and 120,000 took 1,373 seconds while peaking at 127 MB — the cost grows far faster than the input.

Capping the live clusters bounds it: the same 120,000 shapes took 449 seconds and 25 MB under a 20,000 cluster cap. A cluster costs about 1.1 KB, so the 50,000 cap holds the miner near 55 MB. That sits far above the vocabulary of a real archive, where messages group and mining stays under two seconds, so eviction is a safety valve rather than part of normal operation. An archive that reaches the cap carries more distinct shapes than a coverage report could be read from.

### Determinism

drain3 is order dependent and assigns `cluster_id` in arrival order, so neither could be used as a finding key. Distinct messages are fed to the miner in sorted order, and template IDs are derived from the sorted template text instead.

The template a message receives when it is inserted can still widen as later messages join the same cluster, so the most recently returned template is kept for every cluster and all of its assignments use that final value. This also preserves the last template of a cluster the LRU cap evicted; reading only `miner.drain.clusters` after the pass would lose it and turn the safety cap into a `KeyError` on the first eviction. Two clusters can carry the same template text once eviction recreates one, so templates are keyed by text and such clusters land in a single finding.

### The trade-off

Drain merges by positional shape, so messages that share a shape but differ in meaning can still land in one finding, and `message_pattern` reports `<*>` where a username or path was. The tuning reduces that risk on the families measured; it does not eliminate it for shapes the corpus does not cover. `sample_log` is unaffected and stays source-derived, so every finding still carries a real line to replay.

## Archive reading

The archive is scanned once into a temporary DuckDB table, and all subsequent classification, grouping, and sampling runs against that table. Fields are read with `read_ndjson_objects` and explicit JSON path extraction rather than automatic structural inference, which keeps the envelope stable when an archive happens to contain no rule objects or contains empty decoder objects such as `"decoder": {}`.

### Malformed lines

`ignore_errors = true` does not drop an unparseable line in DuckDB: it yields a NULL document in its place. Such a row would otherwise extract as all-NULL fields and be classified as `no_decoder`, inflating both the event total and that bucket. Malformed rows are therefore tagged during the scan and excluded from classification, which keeps the coverage denominator exact while still counting the loss. A line that parses but is not an object — a bare scalar, array, or `null` — is rejected by strict mode too, so it is tagged the same way.

The distinction between skipping and ignoring is the whole point: ignoring would corrupt the denominator silently, which is exactly what makes coverage numbers untrustworthy.

### Normalization

The regex pass ahead of mining is deliberately conservative: common timestamp prefixes, UUIDs, hexadecimal tokens of sixteen characters or more, and decimal numbers of five digits or more. Short numbers, IP addresses, ports, usernames, paths, event IDs, and status codes are retained, because masking them can materially change detection semantics and a pattern that hides an event ID is not worth reading.

### Bulk loading the template map

DuckDB's Python parameter binding costs roughly 140 microseconds per row for bulk data — about 25 seconds for one high-entropy archive — while its CSV reader loads the same rows in 0.2 seconds. Chunking the binding does not help, so the log-ID to template-ID mapping is handed over through a temporary CSV file that is removed before the load returns.

Only integers are written to that file. No log text passes through CSV quoting, so an embedded delimiter, quote, or newline in a message cannot corrupt the join key.

## Samples

A finding's representative is the deterministic `min()` of its raw logs, with only its line breaks collapsed. The sample exists to be replayed through `wazuh-logtest`, which reads one log per line, so a multi-line log emitted verbatim would be replayed as several unrelated logs — the first tested against the wrong decoder and the rest as fragments no rule was ever written for.

`Finding.sample_log` carries the collapsed value, so an API consumer that replays samples gets the same guarantee the CLI does. `message_pattern` is not collapsed, because it is a grouping key and is reported verbatim; the report collapses it only while rendering.

## No persistent state

A run writes nothing but stdout and stderr. There is no processed-path cache, no lock file, and no flag to bypass one.

The obvious design is a JSON list of processed absolute paths in the working directory, skipped on the next run. It answers a question a narrower glob already answers, and it charges for the answer three times over. A run's behaviour comes to depend on the directory it was launched from, so the same command means different things from a shell and from cron. The file is state nobody inspects, whose staleness is invisible until a re-analysis silently does nothing. And skipping keys on the path rather than the content, so an archive rotated under a name already recorded is never re-read — a correctness hole, not merely wasted work.

Deduplication within one run needs none of it: `resolve_targets` collapses literal paths and globs into a set of absolute paths, so overlapping targets are read once whatever the user types.

The cost is real and belongs in the open: a nightly sweep over a growing archive directory re-reads what it read yesterday unless its glob is dated. A dated glob is one shell expansion, and it puts the decision in the command where it can be read.

## Dependency constraints

drain3 is pure Python and imposes no interpreter floor, but version 0.9.11 ships as a source distribution only and pins `jsonpickle==1.5.1` and `cachetools==4.2.1` exactly. A `pipx` install is unaffected, because it gets an environment of its own and nothing else resolves against those pins.

The constraint applies only in a shared environment, and only when that environment's own constraints exclude the pinned versions. A project requiring `cachetools>=5` cannot install wazuhcoverage at all; one depending on `google-auth`, whose range is `cachetools>=2,<7`, resolves normally and simply lands on 4.2.1.

Adding a dependency is therefore the thing to be careful about, and `tools/check_dependency_pins.py` exists to enforce that rather than to describe today's tree. It walks the installed graph and fails when an exact pin appears or disappears; CI runs it on every supported interpreter alongside `pip check` and a from-scratch resolution.

`wazuhtester` is an optional extra rather than a dependency, because it requires strictly more than this package does: Linux, Python 3.10 or newer, and a reachable Wazuh manager. Declaring it as a dependency would drop the 3.9 floor, the Windows and macOS support, and the ability to analyze an archive on a laptop, all to serve one flag. The test suite stubs it for the same reason, so CI exercises the mapping logic on every supported interpreter without installing a package half of them cannot have.

DuckDB dropped Python 3.9 in 1.5.0, so the dependency is capped at `duckdb<1.5` on 3.9 through an explicit environment marker. The cap is stated in `pyproject.toml` even though resolvers already honour `Requires-Python`, so a 3.9 install can never silently acquire a DuckDB the package has not been tested against.

Because 3.9 cannot evaluate PEP 604 `X | None` annotations at runtime, the public models are annotated with `typing.Optional` and `typing.Union`. This keeps `typing.get_type_hints()` working on every supported interpreter, so consumers that introspect annotations at runtime behave identically across the range. The `UP007` and `UP045` ruff rules are disabled for that reason and should be re-enabled when the floor moves to 3.10.
