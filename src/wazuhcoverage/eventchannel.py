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
from typing import TYPE_CHECKING, Dict, Optional, Tuple  # noqa: UP035

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection


# analysisd's internal decoder name for these records (src/analysisd/rules.h:432).
DECODER_NAME = "windows_eventchannel"

# The pattern of a record whose XML the manager could not parse. DecodeWinevt
# then emits only the rendered message, or nothing, under win.system (for
# example when one value reaches os_xml's 20,480-byte limit), so no key exists.
NO_PAYLOAD_PATTERN = "EventChannel event without an XML payload"

# Channel group rules in the stock 4.14 ruleset: the rules whose only field test
# is win.system.channel (0575-win-base_rules.xml, 0620-win-generic_rules.xml,
# 0915-win-powershell_rules.xml). A rule for any other channel hangs off the base
# Windows rule.
_BASE_RULE = "60000"
_CHANNEL_RULES: Dict[str, str] = {  # noqa: UP006
    "Security": "60001",
    "System": "60002",
    "Application": "60003",
    "Microsoft-Windows-Sysmon/Operational": "60004",
    "Microsoft-Windows-Windows Defender/Operational": "60005",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall": "60016",
    "File Replication Service": "64100",
    "Microsoft-Windows-TerminalServices-Gateway/Operational": "64104",
    "Microsoft-Windows-PowerShell/Operational": "91801",
}

_PCRE2_SPECIALS = frozenset(r"\.^$|?*+()[]{}")


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


def suggest_rule(sample_log: str, *, parent: Optional[str] = None) -> Optional[str]:
    """Return a rule skeleton for an EventChannel sample, or None without a key.

    The skeleton keys on the event ID under the channel's group rule, as the
    stock Windows rules do, and pins the provider because event IDs repeat
    across providers within a channel. A record without a provider gets none:
    the base rule 60000 requires win.system.providerName, so no rule below it
    could ever match such a record.

    ``parent`` overrides the channel's group rule. Callers pass the rule a
    replay matched, because Wazuh descends into the first matching child and a
    new sibling of that rule would be shadowed by it.
    """

    fields = _key_fields(sample_log)
    if fields is None:
        return None
    channel, provider, event_id = fields
    if event_id is None or not provider:
        return None

    if parent is None:
        parent = _CHANNEL_RULES.get(channel or "", _BASE_RULE)
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


def _key_fields(sample_log: str) -> Optional[Tuple[Optional[str], Optional[str], Optional[str]]]:  # noqa: UP006
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
