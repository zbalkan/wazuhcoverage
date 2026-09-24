# Design notes

Rationale behind implementation decisions described at a higher level in the [README](../README.md), [CLI reference](CLI.md), and [API reference](API.md). This page exists so changes to those decisions are made with their measurements and upstream constraints in view.

## Why the ambiguous bucket is named as it is

Wazuh's analysisd drops the matched rule from an archived event when that rule sits at level 0, and again when a rule's `ignore` window suppresses the event. The mechanism, with source references, is in [CAVEATS.md](CAVEATS.md); what follows is what this project does about it.

The bucket is named for what the record proves — no alerting rule was attached — rather than for the stronger claim that no rule was evaluated. `no_rule`, the obvious name, is the one it must not have: a reader acts on that name, and acting on it means writing a rule for an event a level-0 rule already recognises.

When no replay is possible the report prints a note beside the findings, because an empty `Rule` and `Level` otherwise imply the stronger claim on their own. When a replay is possible the note is dropped, since the `Effective` line has answered the question the note exists to raise.

`tests/test_analysis_integration.py` pins both the bucket name and the classification of a real archived EventChannel event that logtest resolves to rule `61100` at level 0.

## Alert threshold resolution

The analysis API accepts an explicit threshold and remains independent of manager configuration. The CLI adds local policy on top: it reads `/var/ossec/etc/ossec.conf` once per run and uses `<alerts><log_alert_level>` when present. If the file is absent, unreadable, malformed, or has no configured value, the CLI falls back to Wazuh's default threshold of `3` and makes that assumption visible in the report.

Threshold discovery is independent of replay availability. A manager can have a readable configuration even when the optional `wazuhtester` integration is not installed, and classification should still use the correct local threshold. The same resolved value is passed to both `analyze_archive()` and `verify_findings()` so the observed and effective states cannot disagree merely because they used different thresholds.

## Verification through logtest

Verification lives in `wazuhcoverage.verification` and nowhere else. `analyze_archive()` opens no socket and gains no parameter for one, so the analysis path stays offline, deterministic, and installable on a laptop; `verify_findings()` is a separate call whose optional dependency a caller that never invokes it never needs.

### One replay per finding

The unit of replay is the finding, not the event. That is what grouping bought: an archive with forty thousand uncovered EventChannel records that mine to fourteen templates costs fourteen round trips, not forty thousand. Findings already carry a deterministic representative sample chosen for exactly this purpose.

### A session per sample

`wazuhtester` offers `send_multiple_logs()`, which shares one daemon session so that frequency and composite rules can fire. That is the wrong primitive here: the samples in a coverage report are unrelated messages from different log families, and a shared session would let them prime each other. Each sample therefore goes through `send_log()` without a token, which creates and removes a session of its own. The blind spot that buys, and why that trade was taken, is in [CAVEATS.md](CAVEATS.md#one-sample-cannot-reproduce-stateful-rules).

### Location, and what could not be derived

`Finding` carries `observed_location` because the decoder chain consults it. The location and other replay metadata are selected from the same deterministically chosen event as the representative sample, rather than independently from the group. `log_format` cannot be handled the same way, since the archive does not record it; it is a parameter with wazuh-logtest's own `syslog` default. Both are covered in [CAVEATS.md](CAVEATS.md#location-is-preserved-log-format-is-not).

### Failure is never a gap

A replay that does not produce a usable answer is `unverified`, and `unverified` is never inferred from the archive. A daemon error, a raised exception, an unrecognized status, and a matched rule whose level cannot be read all land there with the reason attached. Turning a broken socket into a coverage gap would send someone to write a rule for an event that is already handled, which is the specific failure this whole feature exists to prevent.

Replay availability is separated from archive processing. A missing `wazuhtester` or an unusable socket has the same answer for every archive, so the CLI probes once before scanning anything. If replay is unavailable, it warns once and continues with archive-only results rather than failing otherwise valid analysis.

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
| `max_clusters` | 20,000 | unbounded | Bounds mining time and memory on input that defeats grouping. |
| `parametrize_numeric_tokens` | `true` | `true` | Unchanged; disabling it multiplied templates without preventing a merge. |

The similarity threshold is the consequential one, and both directions fail loudly. At the drain3 default of 0.4 the corpus merges Windows `4624` with `4625` — a successful logon reported together with a failed one — and firewall `ACCEPT` with `DROP`. Above 0.57 the count jumps from 25 templates to 93 as families whose variable tokens are paths or hostnames shatter into one finding per value. Across three corpus seeds, 0.56 and 0.57 were the only values with neither defect, so 0.56 is taken with margin on both sides. Two tests in `tests/test_template_mining.py` guard that band: one fails if opposite outcomes of a family merge, the other if a high-cardinality family fragments.

drain3 is configured explicitly rather than from a `drain3.ini`, because the library otherwise loads one from the current working directory, which would make an archive's findings depend on where the command happened to run. No masking instructions are registered with drain3 either; the analysis normalizer already applies the masks described in this section, and a second masking pass would silently widen them.

### Cost and the cluster cap

DuckDB deduplicates messages before mining, so repeated events are cheap, but stock Drain's cost depends on both the archive's vocabulary and the number of candidate clusters in a prefix-tree leaf. With the current syslog normalization and tree depth, the leading `<TIMESTAMP>` token provides no useful routing; unique-heavy input therefore made stock Drain approach a pairwise scan. It took 103 seconds for 60,000 structure-free messages and 1,373 seconds for 120,000 while peaking at 127 MB.

The analyzer adds a positional inverted index over each cluster's non-wildcard template tokens. A length-*n* template needs at least *k* = `ceil(sim_th × n)` exact positional matches, so every valid candidate must occur in the posting list of at least one of any *n − k + 1* message positions. Probing the rarest of those positions discards unrelated clusters before the exact Drain distance calculation. Monotonically increasing cluster IDs preserve the original leaf order without scanning the leaf to filter the candidate set, retaining Drain's match and tie semantics. Template widening and LRU eviction update the index, and differential tests compare every assignment with stock Drain.

The index makes the measured unique-heavy case close to linear rather than pairwise: 100,000 distinct messages took 5.5 seconds and one million took 48.5 seconds, with both live clusters and indexed templates remaining at 20,000 after the cap. The cap remains a safety bound for candidate-heavy shapes that defeat the index as well as the prefix tree. Eviction can change grouping after the cap is reached; templates remain keyed by text so a recreated cluster still rejoins its original finding.

`tools/benchmark_analysis.py` makes these checks repeatable through the public `analyze_archive()` path. Its `realistic` workload keeps the normalized vocabulary near 80% of the event count using syslog fields the conservative normalizer deliberately retains; its `unique` workload forces one cluster per message. The tool verifies both the archive total and the sum of finding counts before reporting JSON timings, and writes its generated archives only inside a temporary directory. A small subprocess smoke test runs both cases in the normal test suite so generator, CLI, and output-contract drift is caught without turning CI into a performance test.

### Determinism

drain3 is order dependent and assigns `cluster_id` in arrival order, so neither could be used as a finding key. Distinct messages are fed to the miner in sorted order, and template IDs are derived from the sorted template text instead.

The template a message receives when it is inserted can still widen as later messages join the same cluster, so every template change is recorded in order and each cluster keeps the last one; all of its assignments use that final value. This also preserves the last template of a cluster the LRU cap evicted; reading only `miner.drain.clusters` after the pass would lose it and turn the safety cap into a missing template on the first eviction. Two clusters can carry the same template text once eviction recreates one, so templates are keyed by text and such clusters land in a single finding.

### The trade-off

Drain merges by positional shape, so messages that share a shape but differ in meaning can still land in one finding, and `message_pattern` reports `<*>` where a username or path was. The tuning reduces that risk on the families measured; it does not eliminate it for shapes the corpus does not cover. `sample_log` is unaffected and stays source-derived, so every finding still carries a real line to replay.

## Archive reading

The archive is scanned once into a temporary DuckDB table, and all subsequent classification, grouping, and sampling runs against that table. Status totals are derived from the same grouped result as log-type totals instead of rescanning the classified events. Fields are read with `read_ndjson_objects` and explicit JSON path extraction rather than automatic structural inference, which keeps the envelope stable when an archive happens to contain no rule objects or contains empty decoder objects such as `"decoder": {}`.

### Malformed lines

`ignore_errors = true` does not drop an unparseable line in DuckDB: it yields a NULL document in its place. Such a row would otherwise extract as all-NULL fields and be classified as `no_decoder`, inflating both the event total and that bucket. Malformed rows are therefore tagged during the scan and excluded from classification, which keeps the coverage denominator exact while still counting the loss. A line that parses but is not an object — a bare scalar, array, or `null` — is rejected by strict mode too, so it is tagged the same way.

The distinction between skipping and ignoring is the whole point: ignoring would corrupt the denominator silently, which is exactly what makes coverage numbers untrustworthy.

### Normalization

The regex pass ahead of mining is deliberately conservative: common timestamp prefixes, UUIDs, hexadecimal tokens of sixteen characters or more, and decimal numbers of five digits or more. Short numbers, IP addresses, ports, usernames, paths, event IDs, and status codes are retained, because masking them can materially change detection semantics and a pattern that hides an event ID is not worth reading.

### Keeping message text out of memory

A Windows event's message runs to 32,766 characters, and Wazuh caps a log at `OS_MAXSTR`, 64 KiB, so an archive of Windows events carries `full_log` values up to 64 KiB, each repeated in decoded fields. DuckDB can spill a table of such text, but not a `DISTINCT`, an `ORDER BY` or a hash join whose rows carry it. Each of those needed memory in proportion to the archive's distinct text, whatever the memory limit: 389 MB of distinct messages failed under a 512 MiB limit and 779 MB under 768 MiB, so an archive's distinct text, not the limit, decided whether a run fit.

Messages are therefore identified by the MD5 of their normalized text, held as two 64-bit halves, and the text never enters a hash table or a sort inside DuckDB. Each mined event is hashed once; the first event of each digest is found by grouping on the digest; findings group on template IDs, and the template and sample text is attached once per finding at the end. Two different messages sharing a digest would merge their findings, which at 2^-128 per pair is not a practical risk. The digest travels as two halves because handing DuckDB's 128-bit integer to Python, or casting it to text, cost about 100 microseconds a row.

Drain must still see the distinct messages in sorted order. They are read out of DuckDB in chunks of consecutive events holding at most 64 MiB of raw log, each chunk its own query over an event range, which DuckDB answers from the row groups that range covers. An archive whose distinct text fits one chunk is sorted in memory and mined directly. Otherwise each chunk is sorted in Python and written to disk as a run of length-prefixed records, and `heapq.merge` reads the runs back as one sorted sequence, holding a record per run. The records are packed with `struct` rather than JSON, which cost several microseconds a record each way, or pickle, which would execute whatever a tampered run file told it to. Python orders strings by code point, which is the order DuckDB's binary collation gives UTF-8, so the feed is exactly the one an `ORDER BY` produced and the findings are unchanged. A single query streaming every distinct message was not an option: DuckDB either materialized the whole result, which is the archive's distinct text again, or spent a tenth of a second on each batch it handed over.

Drain's decisions are written to disk as they are made: one `(log_hi, log_lo, cluster_id)` row per message, and one row per template change. DuckDB keeps the last template of each cluster, by digest again, and joins the assignments to it. Python holds one run and the miner's own state, never the whole vocabulary.

This bounds memory, not time, and it costs some. On an archive of 1.6 million distinct syslog lines, with mining stubbed out, reading, sorting and merging the messages took about 17 seconds where one sorted query had taken 8. Mining those lines for real takes more than twenty-five minutes, so the difference is under one per cent of a real run, and on an archive whose messages repeat the new path is faster. Mining cost is set by how many clusters each message is compared with, and that is unchanged.

### Bulk loading the template map

DuckDB's Python parameter binding costs roughly 140 microseconds per row for bulk data — 27 seconds for 50,000 templates — while its file readers load the same rows in a fraction of a second. Chunking the binding does not help, so both mining outputs are handed over as temporary files that are removed before the load returns.

The assignments file is CSV and carries only integers, so no log text passes through CSV quoting and an embedded delimiter, quote, or newline cannot corrupt the join key. Template text goes through newline-delimited JSON instead, whose escaping round-trips every delimiter, quote, newline, and control character a log can contain.

The template-text table likewise avoids per-row parameter binding, but uses a temporary NDJSON file because it must preserve arbitrary log text. JSON escaping makes quotes, pipes, line breaks and Unicode unambiguous. The file is removed before the load returns.

## Samples

A finding's representative is the deterministic `min()` of its raw logs, with only its line breaks collapsed. Its location, decoder and rule metadata all come from that same source event; ties between identical raw logs are resolved by those metadata fields. The sample exists to be replayed through `wazuh-logtest`, which reads one log per line, so a multi-line log emitted verbatim would be replayed as several unrelated logs — the first tested against the wrong decoder and the rest as fragments no rule was ever written for.

The fields a replay depends on — `observed_location`, `observed_decoder`, `observed_rule_id`, and `observed_rule_level` — are taken from the sample's own event. Aggregating each one separately would pick it from whichever row a parallel scan reached first, so the location could change between runs and pair the sample with another event's source; the decoder chain consults the location, so such a replay could resolve differently from the event that was archived. The sample is the minimum of a struct whose first field is the raw log and whose remaining fields break ties, so the choice is total and deterministic.

`Finding.sample_log` carries the collapsed value, so an API consumer that replays samples gets the same guarantee the CLI does. `message_pattern` is not collapsed, because it is a grouping key and is reported verbatim; the report collapses it only while rendering.

## Finding keys

`finding_key` is the MD5 of the key parts encoded as a JSON array: the status and rule ID for `below_threshold`, and the status, log type, and message pattern otherwise. The parts are not joined with a delimiter because a log type and a message can both contain any delimiter, so a join is not injective. A command-output location such as `a|b` with the message `c`, and a location `a` with the message `b|c`, would share one key and be reported as a single finding. Keys are stable across runs of the same version, not across versions.

## Memory and spilling

The archive is analysed in an in-memory DuckDB database that spills to disk, with DuckDB's own memory limit and thread count: 80% of physical memory and one thread per core. Once it reaches the limit it evicts blocks of the event table and of large sorts, joins and aggregations to a temp directory instead of failing. There is no option to change either. A memory-limit option was tried and dropped: making a low limit hold took capping threads by measured per-thread allowances, and those allowances depended on the DuckDB version and the length of the logs.

DuckDB's default spill location is `.tmp` under the current working directory. That would make where a run writes depend on where it was launched, fail outright in a read-only directory, and leave a stray directory in whatever folder cron started in. Each connection therefore gets a private directory under the system temporary directory, removed with its contents once the connection closes.

Spilling covers tables, sorts, joins and aggregations, not everything. Two kinds of working memory sit outside it, and both scale with the thread count rather than with the archive. Reading the archive holds a JSON read buffer per thread: on archives of Windows events, DuckDB 1.5 needed 382 MiB for one thread and 844 MiB for four, whatever the line length. After the scan, each thread evaluates the normalization over vectors of 2,048 logs and keeps a copy at each stage of it: about 378 MB for one thread over logs of 49 KiB, negligible for syslog lines. On a machine with many cores and an archive of long Windows events, that working memory comes on top of the limit.

Every join is written with its small side on the right, and DuckDB's join reordering is disabled so that side stays the build side. It estimated the events surviving the finding filter at a few percent of the true count and turned the template join around, building its hash table from events that carry the 64 KiB logs.

## No persistent state

A run writes nothing but stdout and stderr, apart from temporary files it removes before it finishes: a spooled stdin, the mining handover files, and the spill directory. The CLI turns SIGTERM into an ordinary exit so those are removed even when a run is stopped by a timeout or a service manager; only SIGKILL or a crash can leave them behind. There is no processed-path cache, no lock file, and no flag to bypass one.

DuckDB is in-memory, but it can spill intermediate data under memory pressure. Its spill directory is set explicitly to an owned system-temporary directory rather than the default relative `.tmp`; the connection is closed before that directory is removed, including on analysis errors. The CSV and NDJSON bulk-load files use the system temporary directory and are likewise removed in `finally` blocks.

The obvious design is a JSON list of processed absolute paths in the working directory, skipped on the next run. It answers a question a narrower glob already answers, and it charges for the answer three times over. A run's behaviour comes to depend on the directory it was launched from, so the same command means different things from a shell and from cron. The file is state nobody inspects, whose staleness is invisible until a re-analysis silently does nothing. And skipping keys on the path rather than the content, so an archive rotated under a name already recorded is never re-read — a correctness hole, not merely wasted work.

Deduplication within one run needs none of it: `resolve_targets` collapses literal paths and globs into a set of absolute paths, so overlapping targets are read once whatever the user types.

The cost is real and belongs in the open: a nightly sweep over a growing archive directory re-reads what it read yesterday unless its glob is dated. A dated glob is one shell expansion, and it puts the decision in the command where it can be read.

## Dependency constraints

drain3 is pure Python and imposes no interpreter floor, but version 0.9.11 ships as a source distribution only and pins `jsonpickle==1.5.1` and `cachetools==4.2.1` exactly. A `pipx` install is unaffected, because it gets an environment of its own and nothing else resolves against those pins.

The constraint applies only in a shared environment, and only when that environment's own constraints exclude the pinned versions. A project requiring `cachetools>=5` cannot install wazuhcoverage at all; one depending on `google-auth`, whose range is `cachetools>=2,<7`, resolves normally and simply lands on 4.2.1.

Adding a dependency is therefore the thing to be careful about, and `tools/check_dependency_pins.py` exists to enforce that rather than to describe today's tree. It walks the installed graph and fails when an exact pin appears or disappears; CI runs it on every supported interpreter alongside `pip check` and a from-scratch resolution.

`wazuhtester` is an optional extra rather than a dependency, because it requires strictly more than this package does: Linux, Python 3.10 or newer, and a reachable Wazuh manager. Declaring it as a dependency would drop the 3.9 floor, the Windows and macOS support, and the ability to analyze an archive on a laptop, all to serve optional manager replay. The test suite stubs it for the same reason, so CI exercises the mapping logic on every supported interpreter without installing a package half of them cannot have.

DuckDB dropped Python 3.9 in 1.5.0, so the dependency is capped at `duckdb<1.5` on 3.9 through an explicit environment marker. The cap is stated in `pyproject.toml` even though resolvers already honour `Requires-Python`, so a 3.9 install can never silently acquire a DuckDB the package has not been tested against.

Because 3.9 cannot evaluate PEP 604 `X | None` annotations at runtime, the public models are annotated with `typing.Optional` and `typing.Union`. This keeps `typing.get_type_hints()` working on every supported interpreter, so consumers that introspect annotations at runtime behave identically across the range. The `UP007` and `UP045` ruff rules are disabled for that reason and should be re-enabled when the floor moves to 3.10.
