"""Read the small part of the local Wazuh manager configuration we need."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional, Union

DEFAULT_OSSEC_CONF = Path("/var/ossec/etc/ossec.conf")
MIN_ALERT_THRESHOLD = 1
MAX_ALERT_THRESHOLD = 16

_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_LOG_ALERT_LEVEL_RE = re.compile(
    r"<log_alert_level>\s*([^<]*?)\s*</log_alert_level>"
)


def read_alert_threshold(path: Union[str, Path] = DEFAULT_OSSEC_CONF) -> Optional[int]:
    """Return log_alert_level from ossec.conf, or None when it is not set.

    Wazuh configuration is XML-like rather than a single strict XML document,
    so extract only the scalar setting needed here. File access and invalid
    values are reported to the caller rather than silently converted to the
    Wazuh default. The CLI decides when falling back to that default is
    appropriate.
    """

    config_path = Path(path)
    text = config_path.read_text(encoding="utf-8")
    text = _COMMENT_RE.sub("", text)

    match = _LOG_ALERT_LEVEL_RE.search(text)
    if match is None:
        return None

    try:
        value = int(match.group(1).strip())
    except ValueError as exc:
        raise ValueError("log_alert_level must be an integer") from exc

    if not MIN_ALERT_THRESHOLD <= value <= MAX_ALERT_THRESHOLD:
        raise ValueError(
            f"log_alert_level must be between {MIN_ALERT_THRESHOLD} and {MAX_ALERT_THRESHOLD}"
        )

    return value
