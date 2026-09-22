"""Read the small part of the local Wazuh manager configuration we need."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Union

DEFAULT_OSSEC_CONF = Path("/var/ossec/etc/ossec.conf")
MIN_ALERT_THRESHOLD = 1
MAX_ALERT_THRESHOLD = 16


def read_alert_threshold(path: Union[str, Path] = DEFAULT_OSSEC_CONF) -> Optional[int]:
    """Return log_alert_level from ossec.conf, or None when it is not set.

    File access, malformed XML, and invalid values are reported to the caller
    rather than silently converted to the Wazuh default. The CLI decides when
    falling back to that default is appropriate.
    """

    config_path = Path(path)
    try:
        root = ET.parse(config_path).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"{config_path} is not valid XML: {exc}") from exc
    element = root.find("./alerts/log_alert_level")
    if element is None or element.text is None or not element.text.strip():
        return None

    try:
        value = int(element.text.strip())
    except ValueError as exc:
        raise ValueError("log_alert_level must be an integer") from exc

    if not MIN_ALERT_THRESHOLD <= value <= MAX_ALERT_THRESHOLD:
        raise ValueError(
            f"log_alert_level must be between {MIN_ALERT_THRESHOLD} and {MAX_ALERT_THRESHOLD}"
        )

    return value
