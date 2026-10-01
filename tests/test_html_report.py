from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Dict  # noqa: UP035

from wazuhcoverage.html_report import render_html_report
from wazuhcoverage.models import ArchiveAnalysis, Finding, LogTypeCount, StatusCount, Verification


def _analysis() -> ArchiveAnalysis:
    return ArchiveAnalysis(
        path=Path("/archives/sample.json"),
        total_events=10,
        malformed_lines=1,
        status_counts=(
            StatusCount("at_or_above_threshold", 6, 60.0),
            StatusCount("below_threshold", 2, 20.0),
            StatusCount("no_alerting_rule", 2, 20.0),
            StatusCount("no_decoder", 0, 0.0),
        ),
        log_type_counts=(
            LogTypeCount("at_or_above_threshold", "sshd", 6, 60.0, 100.0),
            LogTypeCount("below_threshold", "sshd", 2, 20.0, 100.0),
            LogTypeCount("no_alerting_rule", "auditd", 2, 20.0, 100.0),
        ),
        findings=(
            Finding(
                finding_key="gap",
                observed_status="no_alerting_rule",
                log_type="auditd",
                message_pattern="__REPORT_DATA__ <pattern>",
                event_count=2,
                affected_agents=1,
                first_seen="2026-09-24T10:00:00Z",
                last_seen="2026-09-24T11:00:00Z",
                observed_decoder="auditd",
                observed_location="syslog",
                observed_rule_id=None,
                observed_rule_level=None,
                sample_log='</script><script>alert("x")</script>',
            ),
        ),
    )


def _verification(
    state: str = "uncovered",
    *,
    decoder: str | None = "auditd",
    rule_id: str | None = None,
    rule_level: int | None = None,
    rule_description: str | None = None,
    error: str | None = None,
) -> Verification:
    return Verification(
        finding_key="gap",
        effective_state=state,
        logtest_status="RuleMatch" if rule_id is not None else "NoRule",
        decoder=decoder,
        rule_id=rule_id,
        rule_level=rule_level,
        rule_description=rule_description,
        rule_groups=(),
        error=error,
    )


def test_html_report_embeds_template_css_js_and_uses_pinned_cdns() -> None:
    rendered = render_html_report(
        _analysis(),
        (_verification(),),
        alert_threshold=3,
        threshold_source="from /var/ossec/etc/ossec.conf",
    )

    assert "<!DOCTYPE html>" in rendered
    assert "@picocss/pico@2.1.1/css/pico.min.css" in rendered
    assert "echarts@5.5.0/dist/echarts.min.js" in rendered
    assert "--wazuh-blue: rgb(61, 130, 241)" in rendered
    assert '"Segoe UI", "DejaVu Sans", "Arial", "Liberation Sans", sans-serif' in rendered
    assert 'data-tab="dashboard"' in rendered
    assert 'data-tab="findings"' in rendered
    assert "Coverage flow" in rendered
    assert 'type: "sankey"' in rendered
    assert "Effective outcomes" in rendered
    assert "Metrics by log type" in rendered
    assert "No decoder" in rendered


def test_html_report_escapes_finding_content_and_keeps_it_out_of_chart_json() -> None:
    rendered = render_html_report(_analysis(), (_verification(),))

    assert "__REPORT_DATA__ &lt;pattern&gt;" in rendered
    assert "&lt;/script&gt;&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in rendered

    report_data = rendered.split('<script id="report-data" type="application/json">', 1)[1]
    report_data = report_data.split("</script>", 1)[0]
    assert 'alert("x")' not in report_data
    assert "<script>" not in report_data


def test_html_report_uses_replay_state_for_findings_and_metrics() -> None:
    rendered = render_html_report(_analysis(), (_verification(),))

    assert "<strong>uncovered · auditd · 2 events</strong>" in rendered
    assert "<small>Uncovered</small><h2>20.00%</h2><p>2 / 10</p>" in rendered


def _report_data(rendered: str) -> Dict:  # noqa: UP006
    payload = rendered.split('<script id="report-data" type="application/json">', 1)[1]
    payload = payload.split("</script>", 1)[0]
    return json.loads(payload)


def test_findings_without_a_verdict_keep_their_observed_outcome() -> None:
    # There is one layout: replay verdicts where they exist, archive
    # observations for the rest, with rule-less events left not verified.
    rendered = render_html_report(_analysis())
    data = _report_data(rendered)

    assert data["outcome_names"] == [
        "Rule matched, alerted",
        "Rule matched, no alert",
        "No rule",
        "No decoder",
        "Not verified",
    ]
    assert "Archive ambiguity" not in rendered
    assert "Without complete replay" in rendered


def test_replay_fields_do_not_fall_back_to_stale_archive_decoder_or_rule() -> None:
    finding = replace(
        _analysis().findings[0],
        observed_rule_id="42",
        observed_rule_level=5,
    )
    analysis = replace(_analysis(), findings=(finding,))
    verification = _verification("no_decoder", decoder=None)

    rendered = render_html_report(analysis, (verification,))

    assert "<strong>no_decoder · auditd · 2 events</strong>" in rendered
    assert "<th>Decoder</th><td>—</td>" in rendered
    assert "<th>Rule</th><td>—</td>" in rendered
    assert "<th>Level</th><td>—</td>" in rendered
    assert ">42<" not in rendered


def test_replay_description_and_contribution_data_are_rendered() -> None:
    verification = _verification(
        "uncovered",
        rule_description="Current manager verdict",
    )
    rendered = render_html_report(_analysis(), (verification,))
    data = _report_data(rendered)

    assert "<th>Matched</th><td>Current manager verdict</td>" in rendered
    contributor = data["contributors"]["uncovered"][0]
    assert contributor == {
        "events": 2,
        "local_rate": 100.0,
        "name": "auditd",
        "value": 100.0,
    }
    assert "Contribution" in rendered
    assert 'renderMode: "richText"' in rendered

def test_sankey_keeps_not_verified_outside_decoder_and_rule_stages() -> None:
    rendered = render_html_report(_analysis())
    data = _report_data(rendered)
    links = {
        (link["source"], link["target"]): link["value"]
        for link in data["sankey"]["links"]
    }

    assert links[("Collected events", "Resolved outcome")] == 8
    assert links[("Collected events", "Not verified")] == 2
    assert links[("Resolved outcome", "Decoded")] == 8
    assert links[("Decoded", "Rule matched")] == 8
    assert ("Not verified", "Decoded") not in links
    assert ("Not verified", "Rule matched") not in links


def test_sankey_replay_resolution_conserves_event_counts() -> None:
    rendered = render_html_report(_analysis(), (_verification(),))
    data = _report_data(rendered)
    links = {
        (link["source"], link["target"]): link["value"]
        for link in data["sankey"]["links"]
    }

    assert links[("Collected events", "Resolved outcome")] == 10
    assert links[("Resolved outcome", "Decoded")] == 10
    assert links[("Decoded", "No rule")] == 2
    assert links[("Decoded", "Rule matched")] == 8
    assert links[("Rule matched", "Rule matched, no alert")] == 2
    assert links[("Rule matched", "Rule matched, alerted")] == 6
    assert sum(
        value
        for (source, _target), value in links.items()
        if source == "Collected events"
    ) == _analysis().total_events

