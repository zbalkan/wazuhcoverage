# wazuhcoverage

[![CI](https://github.com/zbalkan/wazuhcoverage/actions/workflows/ci.yml/badge.svg)](https://github.com/zbalkan/wazuhcoverage/actions/workflows/ci.yml)
[![Dependency Graph](https://github.com/zbalkan/wazuhcoverage/actions/workflows/dependabot/update-graph/badge.svg)](https://github.com/zbalkan/wazuhcoverage/actions/workflows/dependabot/update-graph)

`wazuhcoverage` measures what happens to events captured in Wazuh JSON archives. It classifies each event by decoder/rule outcome, groups unresolved events into actionable findings, derives auditable reliability and efficiency metrics, and keeps one real sample per finding for replay through `wazuh-logtest`.

It reads `archives.json` and `archives.json.gz` produced when Wazuh JSON archiving is enabled and never modifies them. See the Wazuh documentation for [archiving event logs](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html#archiving-event-logs).

`wazuhcoverage` supports Linux only and requires Python 3.9 or newer. Findings are replayed through the local `wazuh-logtest` socket, so it needs a running Wazuh manager that the invoking user can reach. If the socket is absent, unresponsive, or not permitted, the CLI states why and exits with status `3` without reading any archive: an archive alone cannot tell an unmatched event from a suppressed one.

## Installation

For command-line use:

```bash
pipx install wazuhcoverage
```

For use as a Python library:

```bash
python -m pip install wazuhcoverage
```

`wazuhtester` is a runtime dependency because every run replays its findings through the manager.

The package installs DuckDB for archive analysis and drain3 for finding grouping. Dependency constraints and their rationale are documented in [design notes](docs/DESIGN.md#dependency-constraints).

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

For machine-readable metrics, use `wazuhcoverage --json archive.json.gz`. Multiple archives are emitted as JSON Lines. For an interactive two-tab report, use `wazuhcoverage --html report.html archive.json.gz`. The generated file contains the report HTML, CSS and application JavaScript; pinned Pico CSS and ECharts resources are loaded from jsDelivr. Run `wazuhcoverage --help` for the short CLI summary. Target resolution, stdin behaviour, strict parsing, exit codes, output streams, and replay options are documented in [docs/CLI.md](docs/CLI.md).

## Coverage model

Every parsed event lands in exactly one outcome. The archive records one of four statuses; replaying a rule-less event through the manager resolves it into one of the others:

| Outcome | Status | Meaning | Typical action |
| --- | --- | --- | --- |
| Rule matched, alerted | `at_or_above_threshold` | A rule fired at or above the alert threshold. | Covered. |
| Rule matched, no alert | `suppressed`, `below_threshold` | A rule matched at level 0, or below the alert threshold. | Review whether the level is intentional. |
| No rule | `uncovered` | The event decoded, and the replay matched no rule. | Write a rule. |
| No decoder | `no_decoder` | No decoder parsed the event. | Check collection format or decoder coverage. |
| Not verified | `no_alerting_rule`, `unverified` | The archive records no rule and the replay gave no usable verdict. | Read the replay error. |

The CLI reads `<alerts><log_alert_level>` from `/var/ossec/etc/ossec.conf` when the local manager configuration is available. Otherwise it assumes Wazuh's default threshold of `3`. The report shows both the threshold and its source before the statistics. The Python API keeps the threshold explicit for callers analysing archives elsewhere.

`no_alerting_rule` needs care. A rule-less archive record does not, by itself, prove that no rule was evaluated. Wazuh can produce the same observable archive state for events that require different interpretations. `wazuhcoverage` replays each such finding through `wazuh-logtest` to resolve it. See [CAVEATS.md](docs/CAVEATS.md) before treating coverage numbers as ground truth.

## Metrics

The statistics report derives five independent measurements: malformed input, decoder failure, replay-confirmed uncovered coverage, below-threshold processing, and unresolved outcomes. Every metric retains its numerator and denominator; replay-dependent measurements are reported as unavailable when the evidence is incomplete rather than silently becoming zero.

The same measurements are available by log type with both the local rate and the log type's contribution to the estate-wide condition. The human report shows the largest contributors, while the Python API and `--json` output retain the complete per-log-type set.

Metrics begin at the archive boundary. They do not measure events that should have been generated but never reached the archive, and they are not combined into a composite health or coverage score. See [METRICS.md](docs/METRICS.md) for formulas and interpretation limits.

## Findings

Raw event counts are usually too noisy to act on directly. `wazuhcoverage` therefore groups dropped events into findings.

`below_threshold` events group by rule ID. `no_decoder` and `no_alerting_rule` events group by log type and a mined message template, except Windows EventChannel records, which group by channel, provider and event ID. Each finding contains its event count, affected agents, observed time range, decoder/rule information where available, a message pattern, and one real source log.

The sample is retained for validation and replay rather than reconstructed from parsed fields. Grouping is deterministic for the same archive. The mining strategy, measurements, and trade-offs are documented in [DESIGN.md](docs/DESIGN.md#template-mining).

## Manager replay

The CLI replays representative findings through the local manager's `wazuh-logtest` socket. This distinguishes states that the archive alone cannot safely separate, including genuinely uncovered events and events matched by a level-0 rule, so replay is required: if the socket cannot be used, the CLI reports the reason and exits with status `3`.

Replay answers for the manager being queried now, not necessarily the manager configuration that originally wrote the archive. It also cannot reproduce every stateful rule from one representative event, and Windows EventChannel findings replay only on a manager whose rule 60000 uses `<decoded_as>json</decoded_as>`, because `wazuh-logtest` cannot run the EventChannel decoder; otherwise they are reported as unverified. See [CAVEATS.md](docs/CAVEATS.md) for the interpretation limits and the Wazuh references behind them.

For Wazuh itself, refer to the upstream [alert-threshold documentation](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html#alert-threshold), [rules classification](https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html), [wazuh-logtest reference](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html), [wazuh-analysisd reference](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html#wazuh-analysisd), and [log collection documentation](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html).

## Documentation

- [Command-line reference](docs/CLI.md) — targets, streams, report semantics, exit codes, and replay behaviour.
- [Python API](docs/API.md) — analysis, verification, and metric APIs.
- [Metrics](docs/METRICS.md) — formulas, replay semantics, log-type dimensions, and interpretation limits.
- [Caveats](docs/CAVEATS.md) — Wazuh behaviours that affect interpretation.
- [Design notes](docs/DESIGN.md) — implementation rationale, template-mining measurements, and dependency constraints.
- [Third-party software](docs/THIRD_PARTY.md) — direct dependency license references.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m ruff format --check .
```

## License

GNU General Public License version 2 only. See [LICENSE](LICENSE). Direct
dependencies retain their respective licenses; see the
[third-party software notice](docs/THIRD_PARTY.md) for license references.
