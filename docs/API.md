# Python API

This page documents the library interface. Command-line behaviour is documented separately in [CLI.md](CLI.md).

```python
from wazuhcoverage import (
    DEFAULT_ALERT_THRESHOLD,
    ArchiveAnalysis,
    Finding,
    LogTypeCount,
    LogTypeMetrics,
    MetricSnapshot,
    MetricValue,
    StatusCount,
    analyze_archive,
    calculate_metrics,
    metrics_to_dict,
)

analysis = analyze_archive("/archives/2026/09/archive.json.gz", alert_threshold=3)

print(analysis.total_events, analysis.malformed_lines)

for status in analysis.status_counts:
    print(f"{status.status:<24} {status.event_count:>8} {status.percentage:6.2f}%")

for finding in analysis.findings:
    if finding.observed_status == "no_alerting_rule":
        print(finding.log_type, finding.event_count, finding.sample_log)
```

`analyze_archive(path, *, alert_threshold=3, skip_malformed=True)` takes a `str` or `pathlib.Path`, expands `~`, and returns an `ArchiveAnalysis`. The default `3` matches Wazuh's default `log_alert_level`; the library does not read `ossec.conf`, so callers analysing archives from a manager with a different threshold should pass it explicitly. It raises `FileNotFoundError` for a missing path and `ValueError` for a negative threshold. Pass `skip_malformed=False` for the fail-fast behaviour `--strict` selects. The analysis runs with DuckDB's default memory limit and thread count, and spills to a private temporary directory beyond that limit. Grouping is not parameterized, so two analyses of the same archive are always comparable.

| Model | Fields |
| --- | --- |
| `ArchiveAnalysis` | `path`, `total_events`, `malformed_lines`, `status_counts`, `log_type_counts`, `findings` |
| `StatusCount` | `status`, `event_count`, `percentage` |
| `LogTypeCount` | `status`, `log_type`, `event_count`, `percentage`, `status_percentage` |
| `MetricValue` | `count`, `denominator`, `ratio`, `available` |
| `LogTypeMetrics` | `log_type`, `event_count`, local rates and global contributions for decoder failure, uncovered, and below-threshold populations |
| `MetricSnapshot` | `total_events`, `malformed_lines`, five primary metrics, `log_types` |
| `Finding` | `finding_key`, `observed_status`, `log_type`, `message_pattern`, `event_count`, `affected_agents`, `first_seen`, `last_seen`, `observed_decoder`, `observed_location`, `observed_rule_id`, `observed_rule_level`, `sample_log` |
| `Verification` | `finding_key`, `effective_state`, `logtest_status`, `decoder`, `rule_id`, `rule_level`, `rule_description`, `rule_groups`, `error` |

`STATUSES` names the archive's buckets and `EFFECTIVE_STATES` names the replay verdicts. They are separate because they answer different questions: one reports what the record holds, the other what the manager does. `PROCESSED_STATUS` and `DROPPED_STATUSES` are the report's two-outcome grouping over `STATUSES`, exported so a caller can reproduce the split without hardcoding the bucket name; no model field changes with it, and `observed_status` keeps naming the exact bucket.

All models are frozen dataclasses and every collection is a tuple, so a result can be cached or shared without defensive copying. `LogTypeCount.percentage` is the pair's share of the whole archive; `status_percentage` is its share of that one bucket, which ranks a log type inside a small bucket that a whole-archive percentage would flatten to nothing. The package is `py.typed`, and annotations resolve under `typing.get_type_hints()` on every supported interpreter.

Glob expansion, report rendering, stdout and stderr, and exit codes are CLI concerns and are deliberately outside the analysis API; see [CLI.md](CLI.md).

## Deriving metrics

`calculate_metrics(analysis, verifications=())` derives metrics from an existing `ArchiveAnalysis` and optional `Verification` sequence. It does not reopen the archive or access Wazuh.

```python
from wazuhcoverage import analyze_archive, calculate_metrics, metrics_to_dict

analysis = analyze_archive("/archives/2026/09/archive.json.gz")
snapshot = calculate_metrics(analysis)

print(snapshot.decoder_failure_rate.count)
print(snapshot.decoder_failure_rate.denominator)
print(snapshot.decoder_failure_rate.ratio)

payload = metrics_to_dict(snapshot)
```

A `MetricValue` always makes availability explicit. Measured metrics carry `count` and `denominator`; `ratio` is a fraction between `0` and `1`. An empty denominator has `ratio=None`. A replay-dependent metric that cannot yet be established has `available=False` and null count, denominator, and ratio.

The primary metrics are malformed rate, decoder failure rate, uncovered rate, below-threshold rate, and uncertainty rate. `MetricSnapshot.log_types` carries the full per-log-type local rates and contributions. See [METRICS.md](METRICS.md) for formulas, replay behavior, and interpretation limits.

`metrics_to_dict()` returns a JSON-serializable dictionary. It preserves ratios as fractions; percentage formatting is a presentation concern.

## Verifying findings

`verify_findings()` is the library side of what the CLI does automatically. It is a separate call rather than an argument to `analyze_archive()`, so analysis stays offline and pure: nothing in `analyze_archive()` opens a socket, and a caller that never imports this function never needs the optional dependency. Replay interpretation limits are documented in [CAVEATS.md](CAVEATS.md).

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
