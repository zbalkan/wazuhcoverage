"""Best-effort Wazuh regex suggestions from mined message patterns."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional, Tuple  # noqa: UP035

from wazuhcoverage import eventchannel
from wazuhcoverage.preprocessing import WAZUH_TIMESTAMP_PCRE2

if TYPE_CHECKING:
    from wazuhcoverage.models import Finding, Verification

# Replay verdicts that name the rule a sample reaches today. A new rule placed
# anywhere else can be shadowed by that rule: Wazuh descends into the first
# matching child, so a level-0 sibling such as 61100 wins over a new rule that
# hangs off the same channel group rule.
_MATCHED_STATES = frozenset({"suppressed", "below_threshold"})

_PLACEHOLDER_RE = re.compile(r"(<\*>|<TIMESTAMP>|<UUID>|<HEX>|<NUM>)")
_OSREGEX_UNREPRESENTABLE = frozenset("^*+")
_OSREGEX_ESCAPES = frozenset("$()\\|<")
_PCRE2_ONLY_PLACEHOLDERS = frozenset({"<TIMESTAMP>", "<UUID>", "<HEX>", "<NUM>"})

_OSREGEX_PLACEHOLDERS = {
    "<*>": r"\S+",
}

_PCRE2_PLACEHOLDERS = {
    "<*>": r"\S+",
    "<NUM>": r"[0-9]{5,}",
    "<UUID>": (
        r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
        r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
    ),
    "<HEX>": r"(?:0x)?[0-9A-Fa-f]{16,}",
    "<TIMESTAMP>": WAZUH_TIMESTAMP_PCRE2,
}
_PCRE2_SPECIALS = frozenset(r"\.^$|?*+()[]{}")


def suggest_for_finding(
    finding: Finding,
    verification: Verification | None = None,
) -> Optional[Tuple[str, str]]:  # noqa: UP006
    """Return a heading and a best-effort suggestion for an unresolved finding.

    EventChannel findings get a rule skeleton keyed on their fields, because
    Wazuh's Windows rules match decoded fields rather than the JSON text. The
    skeleton descends from the rule a replay matched, since a sibling of it
    would never be evaluated, and is offered only when there is one. A finding
    with no key to offer (for
    example an EventChannel record whose XML the manager could not parse) gets
    None, as does any resolved finding, including one a replay showed already
    alerts.
    """

    if finding.observed_status not in ("no_decoder", "no_alerting_rule"):
        return None
    if verification is not None and verification.effective_state == "at_or_above_threshold":
        return None
    if finding.observed_decoder == eventchannel.DECODER_NAME:
        # Only a replayed match names a parent that cannot shadow the new rule.
        # Without one the finding is unverified, or no Windows rule matched at
        # all, which rules out every child of rule 60000 too.
        if verification is None or verification.effective_state not in _MATCHED_STATES or not verification.rule_id:
            return None
        rule = eventchannel.suggest_rule(finding.sample_log, parent=verification.rule_id)
        return None if rule is None else ("Suggested Wazuh rule (eventchannel)", rule)
    # Line breaks only: a pattern is matched against one log line, and runs of
    # spaces inside it are literal text the regex must keep.
    pattern = finding.message_pattern.replace("\r", " ").replace("\n", " ").strip()
    regex_type, regex = suggest_wazuh_regex(pattern)
    return f"Suggested Wazuh regex ({regex_type})", regex


def suggest_wazuh_regex(message_pattern: str) -> Tuple[str, str]:  # noqa: UP006
    """Return a Wazuh regex type and best-effort expression for a mined pattern.

    Literal text is preserved. OSRegex is used for ordinary Drain wildcards.
    Typed values created by preprocessing use PCRE2 so the suggestion preserves
    the syntax the preprocessor actually recognized instead of broadening UUIDs,
    long numbers, hexadecimal values or timestamps to generic word tokens.
    """

    parts = _PLACEHOLDER_RE.split(message_pattern)
    use_pcre2 = any(part in _PCRE2_ONLY_PLACEHOLDERS for part in parts) or any(
        char in _OSREGEX_UNREPRESENTABLE for index, part in enumerate(parts) if index % 2 == 0 for char in part
    )

    if use_pcre2:
        body = "".join(
            _PCRE2_PLACEHOLDERS[part] if index % 2 else _escape_pcre2(part) for index, part in enumerate(parts)
        )
        return "pcre2", f"^{body}$"

    body = "".join(
        _OSREGEX_PLACEHOLDERS[part] if index % 2 else _escape_osregex(part) for index, part in enumerate(parts)
    )
    return "osregex", f"^{body}$"


def _escape_osregex(text: str) -> str:
    return "".join(f"\\{char}" if char in _OSREGEX_ESCAPES else char for char in text)


def _escape_pcre2(text: str) -> str:
    return "".join(f"\\{char}" if char in _PCRE2_SPECIALS else char for char in text)
