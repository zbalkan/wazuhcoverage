from pathlib import Path

import pytest

from wazuhcoverage.config import read_alert_threshold


def test_read_alert_threshold_reads_configured_value(tmp_path: Path) -> None:
    config = tmp_path / "ossec.conf"
    config.write_text(
        "<ossec_config><alerts><log_alert_level>7</log_alert_level></alerts></ossec_config>",
        encoding="utf-8",
    )

    assert read_alert_threshold(config) == 7


def test_read_alert_threshold_reads_wazuh_xml_like_config(tmp_path: Path) -> None:
    config = tmp_path / "ossec.conf"
    config.write_text(
        """
<ossec_config>
  <integration>
    <hook_url>https://example.invalid/hook?a=1&b=2</hook_url>
  </integration>
</ossec_config>

<ossec_config>
  <alerts>
    <log_alert_level>7</log_alert_level>
  </alerts>
</ossec_config>
""".strip(),
        encoding="utf-8",
    )

    assert read_alert_threshold(config) == 7


def test_read_alert_threshold_rejects_broken_value_in_wazuh_xml_like_config(
    tmp_path: Path,
) -> None:
    config = tmp_path / "ossec.conf"
    config.write_text(
        """
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
  </global>
</ossec_config>

<ossec_config>
  <alerts>
    <log_alert_level>broken</log_alert_level>
  </alerts>
</ossec_config>
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="log_alert_level must be an integer"):
        read_alert_threshold(config)


def test_read_alert_threshold_ignores_commented_value(tmp_path: Path) -> None:
    config = tmp_path / "ossec.conf"
    config.write_text(
        """
<!-- <log_alert_level>12</log_alert_level> -->
<ossec_config>
  <alerts>
    <log_alert_level>6</log_alert_level>
  </alerts>
</ossec_config>
""".strip(),
        encoding="utf-8",
    )

    assert read_alert_threshold(config) == 6


def test_read_alert_threshold_returns_none_when_not_configured(tmp_path: Path) -> None:
    config = tmp_path / "ossec.conf"
    config.write_text("<ossec_config><alerts /></ossec_config>", encoding="utf-8")

    assert read_alert_threshold(config) is None


@pytest.mark.parametrize("value", ["zero", "0", "17"])
def test_read_alert_threshold_rejects_invalid_values(tmp_path: Path, value: str) -> None:
    config = tmp_path / "ossec.conf"
    config.write_text(
        f"<ossec_config><alerts><log_alert_level>{value}</log_alert_level></alerts></ossec_config>",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        read_alert_threshold(config)
