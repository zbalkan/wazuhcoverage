"""Structured grouping for Windows EventChannel records.

Wazuh does not store an EventChannel event as text. analysisd's DecodeWinevt
rebuilds the agent's XML as compact JSON, ``{"win":{"system":{...},...}}``, and
overwrites ``full_log`` with it (wazuh 4.14 src/analysisd/decoders/
winevtchannel.c:725-729). Whitespace tokenization therefore sees one token for
almost the whole system block, and that token carries the per-event
``systemTime`` and ``eventRecordID``, so Drain assigns nearly every record its own
cluster. The records already carry the key Wazuh's own Windows rules are written
against -- channel, provider and event ID -- so they are grouped by it instead.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Optional, Tuple  # noqa: UP035

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

    from wazuhcoverage.models import Finding, Verification


# analysisd's internal decoder name for these records (src/analysisd/rules.h:432).
DECODER_NAME = "windows_eventchannel"

# The pattern of a record whose XML the manager could not parse. DecodeWinevt
# then emits only the rendered message, or nothing, under win.system (for
# example when one value reaches os_xml's 20,480-byte limit), so no key exists.
NO_PAYLOAD_PATTERN = "EventChannel event without an XML payload"


_PCRE2_SPECIALS = frozenset(r"\.^$|?*+()[]{}")

# Replay verdicts that name the rule a sample reaches today. A new rule placed
# anywhere else can be shadowed by that rule: Wazuh descends into the first
# matching child, so a level-0 sibling such as 61100 wins over a new rule that
# hangs off the same channel group rule.
_MATCHED_STATES = frozenset({"suppressed", "below_threshold"})


def install_eventchannel_macros(connection: DuckDBPyConnection) -> None:
    """Install the macros that recognize EventChannel records and name their group.

    ``eventchannel_fields`` returns ``[channel, providerName, eventID]`` for a
    record decoded by DecodeWinevt and NULL for any other record. The JSON check
    comes first because DuckDB's extraction raises on malformed input, and a
    CASE evaluates its branch only for the rows that reach it.
    """

    connection.execute(
        f"""
        CREATE TEMP MACRO eventchannel_fields(decoder, log) AS
        CASE
            WHEN decoder = '{DECODER_NAME}' AND json_valid(log) THEN
                json_extract_string(
                    log,
                    ['$.win.system.channel', '$.win.system.providerName', '$.win.system.eventID']
                )
        END
        """
    )
    connection.execute(
        f"""
        CREATE TEMP MACRO eventchannel_pattern(fields) AS
        CASE
            WHEN fields IS NULL THEN NULL
            WHEN fields[1] IS NULL AND fields[2] IS NULL AND fields[3] IS NULL THEN '{NO_PAYLOAD_PATTERN}'
            ELSE concat(
                'channel=', coalesce(fields[1], '-'),
                ' provider=', coalesce(fields[2], '-'),
                ' eventID=', coalesce(fields[3], '-')
            )
        END
        """
    )


def suggest_for_finding(
    finding: Finding,
    verification: Verification | None = None,
) -> Optional[Tuple[str, str]]:  # noqa: UP006, UP045
    """Return a heading and a rule skeleton for an unresolved EventChannel finding.

    Wazuh's Windows rules match decoded fields rather than the JSON text, so the
    skeleton is keyed on those fields. It descends from the rule a replay
    matched, since a sibling of it would never be evaluated, and is offered only
    when there is one. Any other finding gets None: a finding from any other
    decoder, a resolved finding, one a replay showed already alerts, and one
    with no key to offer (for example a record whose XML the manager could not
    parse).
    """

    if finding.observed_decoder != DECODER_NAME:
        return None
    # A finding with this decoder was decoded, so no_decoder cannot occur here.
    if finding.observed_status != "no_alerting_rule":
        return None
    # Only a replayed match names a parent that cannot shadow the new rule.
    # Without one the finding is unverified, or no Windows rule matched at
    # all, which rules out every child of rule 60000 too.
    if verification is None or verification.effective_state not in _MATCHED_STATES or not verification.rule_id:
        return None
    rule = suggest_rule(finding.sample_log, parent=verification.rule_id)
    return None if rule is None else ("Suggested Wazuh rule (eventchannel)", rule)


def suggest_rule(sample_log: str, *, parent: str) -> Optional[str]:  # noqa: UP045
    """Return a rule skeleton for an EventChannel sample, or None without a key.

    The skeleton keys on the event ID, as the stock Windows rules do, and pins
    the provider because event IDs repeat across providers within a channel.
    ``parent`` is the rule a replay matched: Wazuh descends into the first
    matching child, so a rule placed anywhere else can be shadowed by it (on
    4.14.8 a rule for System 7036 under the channel rule 60002 never fired,
    because the level-0 sibling 61100 matched first). A record without a
    provider gets none: the base rule 60000 requires win.system.providerName,
    so no rule below it could ever match such a record.
    """

    fields = _key_fields(sample_log)
    if fields is None:
        return None
    channel, provider, event_id = fields
    if event_id is None or not provider:
        return None

    lines = [
        '<rule id="100000" level="3">',
        f"  <if_sid>{parent}</if_sid>",
        f'  <field name="win.system.eventID" type="pcre2">^{_escape_xml(_escape_pcre2(event_id))}$</field>',
        f'  <field name="win.system.providerName" type="pcre2">^{_escape_xml(_escape_pcre2(provider))}$</field>',
    ]
    description = f"{channel or 'EventChannel'}: {provider} event {event_id}"
    lines.append(f"  <description>{_escape_xml(description)}</description>")
    lines.append("</rule>")
    return "\n".join(lines)


def _key_fields(sample_log: str) -> Optional[Tuple[Optional[str], Optional[str], Optional[str]]]:  # noqa: UP006, UP045
    try:
        system = json.loads(sample_log)["win"]["system"]
    except (ValueError, KeyError, TypeError):
        return None
    if not isinstance(system, dict):
        return None
    values = tuple(system.get(name) for name in ("channel", "providerName", "eventID"))
    if not all(value is None or isinstance(value, str) for value in values):
        return None
    return values  # type: ignore[return-value]


def _escape_pcre2(text: str) -> str:
    return "".join(f"\\{char}" if char in _PCRE2_SPECIALS else char for char in text)


def _escape_xml(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
