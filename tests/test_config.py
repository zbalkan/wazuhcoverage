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


def test_read_alert_threshold_rejects_malformed_xml(tmp_path: Path) -> None:
    config = tmp_path / "ossec.conf"
    config.write_text("<ossec_config><alerts>", encoding="utf-8")

    with pytest.raises(ValueError):
        read_alert_threshold(config)
