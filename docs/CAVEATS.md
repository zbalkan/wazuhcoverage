# Caveats

Wazuh behaves, in a few places, in ways that surprise anyone reading its output at face value. None of these are bugs this project can fix, and all of them change how a coverage report should be read. Line references are to [wazuh/wazuh v4.12.0](https://github.com/wazuh/wazuh/tree/v4.12.0) and have been stable across the 4.x line; re-check them against a later major version before relying on the wording.

## An archived event that matched a level-0 rule carries no rule

This is the one that matters most, because it makes a silenced event and an uncovered event indistinguishable in `archives.json`.

In `src/analysisd/analysisd.c`, the rule-matching loop abandons a level-0 match well before it records which rule matched:

```c
/* Ignore level 0 */
if (t_currently_rule->level == 0) {
    break;                                  /* line 2083 */
}
...
/* Pointer to the rule that generated it */
lf->generated_rule = t_currently_rule;      /* line 2111 */
```

A few lines further down the same pointer is cleared again when a rule's `ignore` window swallows a repeated event:

```c
if (t_currently_rule->ckignore && IGnore(lf, t_id)) {
    lf->generated_rule = NULL;              /* line 2116 */
    break;
}
```

The archive record is queued to the writer thread in every one of those cases (line 2199), but `Eventinfo_to_jsonstr` in `src/analysisd/format/to_json.c` builds the `rule` object only when the pointer survived:

```c
if(lf->generated_rule){
    cJSON_AddItemToObject(root, "rule", rule = cJSON_CreateObject());   /* line 48 */
}
```

So three different outcomes reach `archives.json` as the same rule-less record:

| What analysisd did | What the archive shows |
| --- | --- |
| No rule matched at all | no `rule` object |
| A rule matched at level 0 | no `rule` object |
| A rule matched and its `ignore` window suppressed the event | no `rule` object |

Nothing else in the record separates them, which is why this tool's bucket is called `no_alerting_rule` rather than `no_rule`: the archive proves that no alerting rule was attached, and nothing more. Acting on the stronger reading means writing a rule for an event that a level-0 rule already recognises.

The three matter differently. A level-0 base rule such as `61100`, catching Windows System events no child rule claimed, is a genuine coverage gap. A local level-0 rule written to silence a known-noisy source is a decision somebody already made. An `ignore` suppression is neither — the rule works and fired recently.

## `rule.level` is omitted when the level is zero

Also in `to_json.c`, the level is written only when it is truthy:

```c
if(lf->generated_rule->level) {
    cJSON_AddNumberToObject(rule, "level", lf->generated_rule->level);   /* line 86 */
}
```

Taken alone this says a rule with no `level` field is a level-0 rule. It is not safe to read it that way. The level-0 `break` above means a record carrying a rule at all has already passed a non-zero level check, so the combination should not occur; a record that has both is evidence that something else produced it, not evidence of a silenced event. `wazuhcoverage` therefore treats a rule with an unusable level as `below_threshold` — it cannot be shown to meet the threshold — rather than inferring zero.

## logtest reports the rule whatever its level

The asymmetry that makes verification possible: `wazuh-logtest` is a testing interface, not the alert pipeline, and it reports the matched rule regardless of level. Replaying the exact record from the first section gives what the archive refused to:

```text
**Phase 3: Completed filtering (rules).
        id: '61100'
        level: '0'
        description: 'Windows System informational event'
```

`wazuhcoverage` replays one representative sample per finding for this reason. The verdict appears as the `Effective` line and the effective-coverage table; the archive's own empty `Rule` and `Level` stay beside it, because they are still what the record holds.

## A replay answers for today's manager

The ruleset on the manager being replayed against is not necessarily the ruleset that wrote the archive. Replaying last year's archive answers "would we catch this now", which is usually the more useful question and is not the same question. Rules added, removed, or re-levelled since the archive was written all move the answer.

## logtest sees one event, so frequency rules never fire

A rule that only fires on the Nth matching event within a window cannot be reproduced from a single replayed sample, so a finding covered solely by such a rule is reported as `uncovered`.

`wazuhcoverage` replays each sample in a session of its own, which is what forces this. The alternative — one shared session, as `send_multiple_logs` provides — would let four superficially similar samples prime a frequency rule so the fifth reports a match production would never produce. Between under-reporting and over-reporting coverage, under-reporting sends somebody to look at a rule and over-reporting closes a real gap, so the isolation is deliberate.

## Location decides the decoder, and a pasted log has none

Wazuh's decoder chain consults the event's `location`. Pasting a raw EventChannel record into `wazuh-logtest` by hand resolves it to the `json` decoder rather than `windows_eventchannel`, because the interactive tool has no location to offer — which is why a hand replay can disagree with the archive about which decoder ran.

`wazuhcoverage` avoids that by carrying `Finding.observed_location` from the archive and reporting it on replay. A finding spanning several locations reports one of them, the same compromise already made for the decoder.

## Log format cannot be recovered from the archive

`archives.json` does not record the `log_format` that analysisd was given, so a replay cannot derive it. The default is `syslog`, matching `wazuh-logtest`'s own, and an EventChannel or JSON source replayed as `syslog` resolves against the wrong decoder chain and gives a wrong answer. Pass `--log-format json` for a JSON source.

Deriving the value from the decoder name was considered and rejected: the mapping belongs to Wazuh rather than to this package, and a wrong guess would be indistinguishable from a real result.

## archives.json only exists if you asked for it

Coverage analysis needs the archive, and Wazuh does not write one by default. `<logall_json>yes</logall_json>` in the manager's `ossec.conf` turns it on. Without it there is only `alerts.json`, which by construction contains nothing that failed to alert — that is, none of what a coverage report is about.

## Raising a level-0 rule has side effects

Where a level-0 rule dominates a log type and you control its child chain, `<rule id="61100" level="1" overwrite="yes">` restores rule information to the archive and collapses those events into a single `below_threshold` finding rather than one finding per message shape.

It is not free. The override makes the event an alert internally, so it increments the rule's fired counters, and it changes what correlation rules keyed on that rule see through `if_matched_sid` and the last-events list. Apply it to rules whose child chain you own, and check the result with `wazuh-logtest` rather than assuming.
