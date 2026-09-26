"""Best-effort Wazuh regex suggestions from mined message patterns."""

from __future__ import annotations

import re

from wazuhcoverage.preprocessing import WAZUH_TIMESTAMP_PCRE2

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


def suggest_wazuh_regex(message_pattern: str) -> tuple[str, str]:
    """Return a Wazuh regex type and best-effort expression for a mined pattern.

    Literal text is preserved. OSRegex is used for ordinary Drain wildcards.
    Typed values created by preprocessing use PCRE2 so the suggestion preserves
    the syntax the preprocessor actually recognized instead of broadening UUIDs,
    long numbers, hexadecimal values or timestamps to generic word tokens.
    """

    parts = _PLACEHOLDER_RE.split(message_pattern)
    use_pcre2 = any(part in _PCRE2_ONLY_PLACEHOLDERS for part in parts) or any(
        char in _OSREGEX_UNREPRESENTABLE
        for index, part in enumerate(parts)
        if index % 2 == 0
        for char in part
    )

    if use_pcre2:
        body = "".join(
            _PCRE2_PLACEHOLDERS[part] if index % 2 else _escape_pcre2(part)
            for index, part in enumerate(parts)
        )
        return "pcre2", f"^{body}$"

    body = "".join(
        _OSREGEX_PLACEHOLDERS[part] if index % 2 else _escape_osregex(part)
        for index, part in enumerate(parts)
    )
    return "osregex", f"^{body}$"


def _escape_osregex(text: str) -> str:
    return "".join(f"\\{char}" if char in _OSREGEX_ESCAPES else char for char in text)


def _escape_pcre2(text: str) -> str:
    return "".join(f"\\{char}" if char in _PCRE2_SPECIALS else char for char in text)
