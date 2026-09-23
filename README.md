# wazuhcoverage

[![CI](https://github.com/zbalkan/wazuhcoverage/actions/workflows/ci.yml/badge.svg)](https://github.com/zbalkan/wazuhcoverage/actions/workflows/ci.yml)
[![Dependency Graph](https://github.com/zbalkan/wazuhcoverage/actions/workflows/dependabot/update-graph/badge.svg)](https://github.com/zbalkan/wazuhcoverage/actions/workflows/dependabot/update-graph)

`wazuhcoverage` measures what happens to events captured in Wazuh JSON archives. It classifies each event by decoder/rule outcome, groups uncovered events into actionable findings, and keeps one real sample per finding for replay through `wazuh-logtest`.

It reads `archives.json` and `archives.json.gz` produced when Wazuh JSON archiving is enabled and never modifies them. See the Wazuh documentation for [archiving event logs](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html#archiving-event-logs).

When a usable Wazuh manager is available, `wazuhcoverage` can replay representative findings through `wazuh-logtest` and report what the current ruleset does with them. Without a manager it remains an offline archive analyzer.

## Installation

Python 3.9 or newer is supported; Python 3.10 or newer is recommended.

For command-line use:

```bash
pipx install wazuhcoverage
```

For use as a Python library:

```bash
python -m pip install wazuhcoverage
```

Manager replay is an optional extra. It requires Linux, Python 3.10 or newer, and access to a running Wazuh manager:

```bash
pipx install "wazuhcoverage[logtest]"
```

The base package installs DuckDB for archive analysis and drain3 for finding grouping. Dependency constraints and their rationale are documented in [design notes](docs/DESIGN.md#dependency-constraints).

## Quick start

Analyze one archive:

```bash
wazuhcoverage /var/ossec/logs/archives/2026/Sep/ossec-archive-18.json.gz
```

Analyze a set of archives:

```bash
wazuhcoverage "/var/ossec/logs/archives/2026/**/*.json.gz"
```

Read from standard input:

```bash
cat logs.json | wazuhcoverage
ssh manager "cat /var/ossec/logs/archives/2026/Sep/ossec-archive-18.json.gz" | wazuhcoverage
```

Run `wazuhcoverage --help` for the short CLI summary. Target resolution, stdin behaviour, strict parsing, exit codes, output streams, and replay options are documented in [docs/CLI.md](docs/CLI.md).

## Coverage model

Every parsed event lands in exactly one observed bucket:

| Outcome | Bucket | Meaning | Typical action |
| --- | --- | --- | --- |
| Processed | `at_or_above_threshold` | A rule fired at or above the alert threshold. | Covered. |
| Dropped | `no_decoder` | No decoder was recorded for the event. | Check collection format or decoder coverage. |
| Dropped | `no_alerting_rule` | The event decoded, but the archive records no alerting rule. | Replay the sample before treating it as a gap. |
| Dropped | `below_threshold` | A rule fired below the alert threshold. | Review whether the level is intentional. |

The CLI reads `<alerts><log_alert_level>` from `/var/ossec/etc/ossec.conf` when the local manager configuration is available. Otherwise it assumes Wazuh's default threshold of `3`. The report shows both the threshold and its source before the statistics. The Python API keeps the threshold explicit for callers analysing archives elsewhere.

`no_alerting_rule` needs care. A rule-less archive record does not, by itself, prove that no rule was evaluated. Wazuh can produce the same observable archive state for events that require different interpretations. When replay is available, `wazuhcoverage` uses `wazuh-logtest` to refine the result. See [CAVEATS.md](docs/CAVEATS.md) before treating coverage numbers as ground truth.

## Findings

Raw event counts are usually too noisy to act on directly. `wazuhcoverage` therefore groups dropped events into findings.

`below_threshold` events group by rule ID. `no_decoder` and `no_alerting_rule` events group by log type and a mined message template. Each finding contains its event count, affected agents, observed time range, decoder/rule information where available, a message pattern, and one real source log.

The sample is retained for validation and replay rather than reconstructed from parsed fields. Grouping is deterministic for the same archive. The mining strategy, measurements, and trade-offs are documented in [DESIGN.md](docs/DESIGN.md#template-mining).

## Manager replay

If the `logtest` extra is installed and the manager socket is usable, the CLI automatically replays representative findings. This can distinguish several states that the archive alone cannot safely separate, including genuinely uncovered events and events matched by a level-0 rule.

Replay answers for the manager being queried now, not necessarily the manager configuration that originally wrote the archive. It also cannot reproduce every stateful rule from one representative event. See [CAVEATS.md](docs/CAVEATS.md) for the interpretation limits and the Wazuh references behind them.

For Wazuh itself, refer to the upstream [alert-threshold documentation](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html#alert-threshold), [rules classification](https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html), [wazuh-logtest reference](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html), [wazuh-analysisd reference](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html#wazuh-analysisd), and [log collection documentation](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html).

## Documentation

- [Command-line reference](docs/CLI.md) — targets, streams, report semantics, exit codes, and replay behaviour.
- [Python API](docs/API.md) — analysis models and verification API.
- [Caveats](docs/CAVEATS.md) — Wazuh behaviours that affect interpretation.
- [Design notes](docs/DESIGN.md) — implementation rationale, template-mining measurements, and dependency constraints.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m ruff format --check .
```

## License

GNU General Public License version 2 only. See [LICENSE](LICENSE).
