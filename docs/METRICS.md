# Metrics

`wazuhcoverage` derives reliability and efficiency measurements from the same archive analysis and optional replay results used by the report. Metrics do not rescan the archive and do not change event classification.

The measurement boundary starts at the Wazuh JSON archive. These metrics cannot measure telemetry that was never generated, collected, transported, or written to the archive.

## Primary metrics

Let:

- `N` be valid archived events;
- `M` be malformed archive lines;
- `ND` be effective `no_decoder` events;
- `BT` be events with an effective matched rule below `log_alert_level`;
- `U` be replay-confirmed `uncovered` events;
- `R` be unresolved events.

| Metric | Formula | Interpretation |
| --- | --- | --- |
| Malformed rate | `M / (N + M)` | Archive input that could not participate in analysis. |
| Decoder failure rate | `ND / N` | Archived events for which no decoder is established. |
| Uncovered rate | `U / (N - ND)` | Decoded events confirmed by replay to match no rule. |
| Below-threshold rate | `BT / N` | Events with a matched rule below the alert threshold. |
| Uncertainty rate | `R / N` | Events whose effective outcome remains unresolved. |

Every metric carries its count, denominator, and fractional ratio. A ratio is `null` when its denominator is empty. A replay-dependent metric is marked unavailable rather than reported as zero when the required evidence is incomplete.

A level-0 replay match has effective state `suppressed` in the report. It also contributes to the below-threshold metric because it satisfies `rule matched AND level < log_alert_level`. This is a quantitative statement, not an inference about why the rule is level 0.

## Replay semantics

Without replay, `no_alerting_rule` remains unresolved. It is never reinterpreted as `uncovered`.

With replay, the representative finding count is moved from its observed archive state to the replayed effective state. The same adjusted counts are used by both report tables and metrics.

A failed replay contributes to uncertainty. It never contributes to uncovered coverage.

Replay describes the manager queried now. It does not prove that the historical manager which wrote the archive behaved identically. The existing replay caveats in [CAVEATS.md](CAVEATS.md) still apply.

## Log-type metrics

For each log type, `wazuhcoverage` exposes both local severity and contribution to the global condition.

For example:

```text
decoder failure rate for log type l
    ND_l / N_l

decoder failure contribution for log type l
    ND_l / ND
```

The same pair is available for uncovered and below-threshold populations.

These two dimensions answer different questions. A low-volume source can have a high local failure rate while contributing little to the total condition. A high-volume source can have a modest local rate while producing most affected events.

The human-readable report shows only the largest contributors and includes both their local rate and contribution. The Python API and JSON output retain the complete per-log-type set.

## Python API

```python
from wazuhcoverage import analyze_archive, calculate_metrics, verify_findings

analysis = analyze_archive("archive.json.gz")
verifications = verify_findings(analysis)
snapshot = calculate_metrics(analysis, verifications)

print(snapshot.decoder_failure_rate.count)
print(snapshot.decoder_failure_rate.denominator)
print(snapshot.decoder_failure_rate.ratio)
```

`MetricValue.ratio` is a fraction between `0` and `1`, not a formatted percentage.

## JSON output

Use `--json` or `-j` for machine-readable metrics:

```bash
wazuhcoverage --json archive.json.gz
```

One archive produces one JSON object. Multiple archives produce one object per line, making stdout JSON Lines.

Each metric contains:

```json
{
  "count": 14822,
  "denominator": 8441920,
  "rate": 0.001756,
  "available": true
}
```

The object also includes complete per-log-type rates and contributions, the archive label, and the alert-threshold value and source.

## Interpretation limits

These metrics are intentionally separate. `wazuhcoverage` does not combine them into a coverage, reliability, efficiency, or SIEM-health score.

Below-threshold processing does not prove waste, bad configuration, or intentional suppression. Uncovered events do not prove useless telemetry. The tool measures and ranks observable populations; the analyst determines their operational meaning.

The tool remains a batch analyzer. It does not add a scheduler, metrics database, monitoring daemon, dashboard, or long-term state store.
