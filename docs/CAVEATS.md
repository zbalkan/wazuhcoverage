# Caveats

This page documents the limits that matter when interpreting a `wazuhcoverage` result. It does not repeat Wazuh's general architecture or tool documentation; those references are collected at the end.

The most important distinction is between **what the archive proves** and **what a replay against a manager shows now**.

## A rule-less archive record is ambiguous

A decoded event with no rule object in `archives.json` does not prove that no rule was evaluated. In the Wazuh analysis path, the same observable archive state can result from different outcomes, including:

| Analysis outcome | Archive observation |
| --- | --- |
| No rule matched | no `rule` object |
| A level-0 rule matched | no `rule` object |
| A matching rule was suppressed by its `ignore` window | no `rule` object |

That is why the observed bucket is named `no_alerting_rule`, not `no_rule`. The archive proves that no alerting rule was attached to the archived record; it does not prove why.

This behaviour was verified against Wazuh 4.12 analysisd. The relevant implementation points are the [rule-processing path](https://github.com/wazuh/wazuh/blob/v4.12.0/src/analysisd/analysisd.c#L2083-L2116) and [JSON serialization](https://github.com/wazuh/wazuh/blob/v4.12.0/src/analysisd/format/to_json.c#L48-L86). Re-check the behaviour when adopting a later major Wazuh version.

A missing or unusable rule level is therefore not treated as proof of a level-0 match. `wazuhcoverage` classifies what the archive demonstrates and leaves stronger conclusions to replay.

## Alert threshold is configuration-dependent

Coverage classification depends on the manager's `<alerts><log_alert_level>`, not on a universal level of `3`. Wazuh uses `3` as the default, but deployments can configure another value from `1` to `16`.

The CLI reads `/var/ossec/etc/ossec.conf` when it is locally available and reports the resolved threshold before the statistics. When that configuration cannot be read, the CLI explicitly marks `3` as an assumed Wazuh default. An archive does not contain the manager's `log_alert_level`, so offline analysis cannot recover the historical threshold from the archive itself. On a live manager, the value read from `ossec.conf` is the current threshold and may differ from the threshold that was active when an older archive was written.

Library callers analysing data away from the manager should pass the appropriate `alert_threshold` explicitly.

## Replay can refine the result

`wazuh-logtest` reports the rule selected during testing, including level-0 rules. When the optional replay integration is available, `wazuhcoverage` sends one representative sample per relevant finding and records an effective state beside the archive observation.

The archive fields are not overwritten. They describe what the stored record contains; the effective state describes what the replaying manager does with the sample now.

A replay that fails or returns no usable answer is `unverified`, never `uncovered`. Infrastructure failure must not be converted into a coverage gap.

## Replay answers for the manager used now

The ruleset used for replay may differ from the ruleset that originally wrote the archive. Replaying old data therefore answers "what would this manager do with this sample now?", not necessarily "what did the original manager do then?".

That difference is often useful, but it must remain explicit when rules have been added, removed, re-levelled, or otherwise changed.

## One sample cannot reproduce stateful rules

Verification is intentionally performed with an isolated replay per finding. This prevents unrelated findings from priming one another inside a shared logtest session.

The trade-off is that rules requiring history, such as frequency-based logic that fires only after several matching events, cannot be reproduced from one representative sample. A finding covered only by such logic can therefore replay as `uncovered`.

The tool prefers this false-negative direction over a shared session that could create a false impression of coverage by allowing unrelated samples to influence each other.

## Location is preserved; log format is not

Wazuh decoder selection can depend on event location. `wazuhcoverage` retains the observed location from the archive and supplies it during replay.

The original `log_format` is not present in the archive, so it cannot be recovered reliably. Replay defaults to `syslog`; use `--log-format` when the source requires another format. A wrong format can send the sample through the wrong decoder chain and make the replay result misleading.

See [CLI.md](CLI.md#manager-replay) for the command-line behaviour.

## Archives must exist before they can be analysed

`wazuhcoverage` works from Wazuh JSON archives, not from `alerts.json`. Wazuh does not archive all events unless event archiving is enabled.

Configuration and storage details belong to the upstream [Archiving event logs](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html#archiving-event-logs) documentation.

## Raising a level-0 rule changes more than the archive

Overriding a level-0 rule to a positive level can make rule information visible in the archive and may simplify coverage analysis, but it also changes Wazuh rule-processing behaviour.

In particular, it can affect fired counters and correlation paths that depend on prior rule matches. Treat such an override as a ruleset change, not as a reporting-only adjustment, and validate it with `wazuh-logtest`.

## Template grouping is lossy by design

For `no_decoder` and `no_alerting_rule`, findings are grouped by log type and message shape. Messages that share a positional shape but differ semantically can still be merged.

The representative sample remains a real source log, so grouping never removes the ability to inspect or replay an example. The miner's tuning, determinism rules, and measured trade-offs are documented in [DESIGN.md](DESIGN.md#template-mining).

## Wazuh references

Use the upstream documentation for Wazuh behaviour and configuration:

- [Archiving event logs](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html#archiving-event-logs)
- [Alert threshold](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html#alert-threshold)
- [Rules classification](https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html)
- [wazuh-logtest tool reference](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
- [wazuh-logtest development reference](https://documentation.wazuh.com/current/development/wazuh-logtest.html)
- [rule_test configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/rule-test.html#reference-ossec-rule-test)
- [wazuh-analysisd](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html#wazuh-analysisd)
- [How Wazuh log data collection works](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html)
