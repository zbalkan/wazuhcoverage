"""HTML rendering for interactive coverage reports."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from datetime import datetime
from html import escape
from typing import Optional

from wazuhcoverage.metrics import MetricSnapshot, MetricValue, calculate_metrics, resolve_effective_counts
from wazuhcoverage.models import ArchiveAnalysis, Finding, Verification
from wazuhcoverage.presentation import (
    FINDING_GROUPS,
    finding_group,
    outcome_counts,
    present_finding,
)
from wazuhcoverage.wazuh_regex import suggest_wazuh_regex

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wazuh Coverage Report - __ARCHIVE_TITLE__</title>
    <link
        rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/@picocss/pico@2.1.1/css/pico.min.css"
    >
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.5.0/dist/echarts.min.js"></script>
    <style>
        :root {
            --wazuh-blue: rgb(61, 130, 241);
            --wazuh-yellow: rgb(240, 191, 76);
            --wazuh-bg: rgb(40, 40, 40);
            --wazuh-surface: rgb(255, 255, 255);
            --wazuh-muted: rgb(96, 96, 100);
            --wazuh-border: rgb(220, 220, 220);
            --pico-font-family: "Segoe UI", "DejaVu Sans", "Arial", "Liberation Sans", sans-serif;
            --pico-primary: var(--wazuh-blue);
            --pico-primary-hover: var(--wazuh-yellow);
            --pico-primary-focus: rgba(61, 130, 241, 0.25);
        }

        body {
            margin: 0;
            background: var(--wazuh-bg);
        }

        .report-header {
            background: var(--wazuh-blue);
            color: white;
            padding: 1rem 0;
        }

        .report-header strong,
        .report-header small,
        .report-header a {
            color: white;
        }

        .report-title {
            font-size: 1.6rem;
        }

        .report-metadata {
            display: flex;
            flex-wrap: wrap;
            gap: 0.35rem 1.25rem;
            font-family: "Cascadia Mono", "Consolas", "DejaVu Sans Mono", monospace;
        }

        main.container {
            max-width: 1400px;
            background: var(--wazuh-surface);
            padding-top: 1rem;
            padding-bottom: 2rem;
        }

        .report-tabs {
            border-bottom: 1px solid var(--wazuh-border);
            margin-bottom: 1.25rem;
        }

        .report-tabs button {
            border-radius: 0;
            margin-bottom: -1px;
            background: transparent;
            color: var(--wazuh-muted);
            border: 0;
            border-bottom: 3px solid transparent;
        }

        .report-tabs button.active {
            color: var(--wazuh-blue);
            border-bottom-color: var(--wazuh-blue);
        }

        .metric-grid {
            grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
        }

        .metric-card h2 {
            margin-bottom: 0.2rem;
            font-size: 1.8rem;
        }

        .metric-card p,
        .metric-card small {
            color: var(--wazuh-muted);
        }

        .chart {
            width: 100%;
            height: 340px;
        }

        .chart-large {
            height: 460px;
        }

        .chart-fallback {
            display: none;
            color: var(--wazuh-muted);
        }

        .notice {
            border-left: 4px solid var(--wazuh-yellow);
        }

        article,
        [data-tab-panel] {
            min-width: 0;
        }

        figure {
            max-width: 100%;
            overflow-x: auto;
        }

        figure table {
            width: max-content;
            min-width: 100%;
            margin-bottom: 0;
        }

        table {
            font-size: 0.9rem;
        }

        th.numeric,
        td.numeric {
            text-align: right;
        }

        td.numeric {
            white-space: nowrap;
        }

        .finding summary {
            cursor: pointer;
        }

        .finding pre {
            max-height: 24rem;
            overflow: auto;
            white-space: pre-wrap;
            word-break: break-word;
        }

        code,
        pre,
        .technical {
            font-family: "Cascadia Mono", "Consolas", "DejaVu Sans Mono", monospace;
        }

        .findings-search {
            max-width: 34rem;
        }

        footer {
            max-width: none !important;
            background: black;
            color: white;
            text-align: center;
            padding: 1rem;
            font-size: 0.8rem;
        }

        footer a {
            color: white;
            font-weight: bold;
        }

        @media print {
            body,
            main.container {
                background: white;
            }

            .report-tabs,
            .print-link,
            .findings-search,
            footer {
                display: none !important;
            }

            [data-tab-panel] {
                display: block !important;
            }

            .chart {
                break-inside: avoid;
            }

            details {
                display: block;
            }

            details > summary {
                font-weight: bold;
            }

            details > *:not(summary) {
                display: block !important;
            }
        }
    </style>
    <noscript>
        <style>
            .chart { display: none; }
            .chart-fallback { display: block; }
            .report-tabs { display: none; }
            [data-tab-panel][hidden] { display: block !important; }
        </style>
    </noscript>
</head>
<body>
    <header class="report-header">
        <div class="container">
            <nav>
                <ul>
                    <li><strong class="report-title">Wazuh Coverage Report</strong></li>
                </ul>
                <ul>
                    <li><a class="print-link" href="#" onclick="window.print(); return false;">Print</a></li>
                </ul>
            </nav>
            <div class="report-metadata">
                <span>Archive: __ARCHIVE__</span>
                <span>Events: __EVENTS__</span>
                <span>Alert threshold: __THRESHOLD__</span>
                <span>Threshold source: __THRESHOLD_SOURCE__</span>
                <span>Report date: __REPORT_DATE__</span>
            </div>
        </div>
    </header>

    <main class="container">
        <nav class="report-tabs" aria-label="Report sections">
            <ul>
                <li>
                    <button class="tab-button active" data-tab="dashboard" aria-controls="dashboard">
                        Dashboard
                    </button>
                </li>
                <li>
                    <button class="tab-button" data-tab="findings" aria-controls="findings">
                        Findings
                    </button>
                </li>
            </ul>
        </nav>

        <section id="dashboard" data-tab-panel>
            <div class="grid metric-grid">
                __METRIC_CARDS__
            </div>

            <div class="grid">
                <article>
                    <header>__OUTCOME_TITLE__</header>
                    <div id="outcome-chart" class="chart"></div>
                    <p class="chart-fallback">Chart unavailable. Use the outcome table below.</p>
                </article>
                <article>
                    <header>Largest decoder-failure contributors</header>
                    <div id="decoder-chart" class="chart"></div>
                    <p class="chart-fallback">Chart unavailable. Use the log-type table below.</p>
                </article>
            </div>

            <div class="grid">
                <article>
                    <header>Largest uncovered contributors</header>
                    <div id="uncovered-chart" class="chart"></div>
                    <p class="chart-fallback">Chart unavailable or metric unavailable.</p>
                </article>
                <article>
                    <header>Largest below-threshold contributors</header>
                    <div id="threshold-chart" class="chart"></div>
                    <p class="chart-fallback">Chart unavailable. Use the log-type table below.</p>
                </article>
            </div>

            <article>
                <header>Outcomes by log type</header>
                <div id="logtype-chart" class="chart chart-large"></div>
                <p class="chart-fallback">Chart unavailable. The table below contains the same outcome counts.</p>
                __LOGTYPE_OUTCOME_TABLE__
            </article>

            <article>
                <header>Outcome counts</header>
                __OUTCOME_TABLE__
            </article>

            <article>
                <header>Metrics by log type</header>
                __LOGTYPE_TABLE__
            </article>
        </section>

        <section id="findings" data-tab-panel hidden>
            <input
                id="findings-search"
                class="findings-search"
                type="search"
                placeholder="Filter findings"
                aria-label="Filter findings"
            >
            __FINDINGS_NOTE__
            __FINDINGS__
        </section>
    </main>

    <footer>
        <p>
            Wazuh coverage analysis report generated by
            <a href="https://github.com/zbalkan/wazuhcoverage">wazuhcoverage</a>.
        </p>
        <p>
            &copy; 2026 <a href="https://zaferbalkan.com">Zafer Balkan</a>.
            The Wazuh brand and related marks belong to their respective owners.
        </p>
    </footer>

    <script id="report-data" type="application/json">__REPORT_DATA__</script>
    <script>
        (() => {
            const buttons = document.querySelectorAll(".tab-button");
            const panels = document.querySelectorAll("[data-tab-panel]");

            buttons.forEach((button) => {
                button.addEventListener("click", () => {
                    buttons.forEach((item) => item.classList.remove("active"));
                    panels.forEach((panel) => panel.hidden = panel.id !== button.dataset.tab);
                    button.classList.add("active");
                    window.dispatchEvent(new Event("resize"));
                });
            });

            const search = document.getElementById("findings-search");
            search.addEventListener("input", () => {
                const needle = search.value.toLowerCase();
                document.querySelectorAll(".finding").forEach((item) => {
                    item.hidden = !item.textContent.toLowerCase().includes(needle);
                });
            });

            const data = JSON.parse(document.getElementById("report-data").textContent);
            const showFallback = (id) => {
                const chart = document.getElementById(id);
                if (chart) {
                    chart.hidden = true;
                    const fallback = chart.nextElementSibling;
                    if (fallback && fallback.classList.contains("chart-fallback")) {
                        fallback.style.display = "block";
                    }
                }
            };

            if (!window.echarts) {
                document.querySelectorAll(".chart").forEach((item) => showFallback(item.id));
                return;
            }

            const charts = [];
            const palette = [
                "rgb(61, 130, 241)",
                "rgb(240, 191, 76)",
                "rgb(96, 96, 100)",
                "rgb(180, 180, 180)"
            ];
            const createChart = (id, option) => {
                option.color = palette;
                const element = document.getElementById(id);
                const chart = echarts.init(element);
                chart.setOption(option);
                charts.push(chart);
            };

            if (data.outcomes.some((row) => row.value > 0)) {
                createChart("outcome-chart", {
                    tooltip: { trigger: "item", renderMode: "richText" },
                    legend: { bottom: 0 },
                    series: [{
                        type: "pie",
                        radius: ["45%", "70%"],
                        data: data.outcomes
                    }]
                });
            } else {
                showFallback("outcome-chart");
            }

            const contributorChart = (id, rows) => {
                if (!rows.length) {
                    showFallback(id);
                    return;
                }
                createChart(id, {
                    tooltip: {
                        trigger: "axis",
                        renderMode: "richText",
                        axisPointer: { type: "shadow" },
                        formatter: (params) => {
                            const row = params[0].data;
                            return [
                                params[0].name,
                                "Contribution: " + row.value.toFixed(2) + "%",
                                "Local rate: " + (row.local_rate === null ? "n/a" : row.local_rate.toFixed(2) + "%"),
                                "Events: " + row.events.toLocaleString()
                            ].join("\n");
                        }
                    },
                    grid: { left: "4%", right: "4%", bottom: "4%", containLabel: true },
                    xAxis: {
                        type: "value",
                        name: "Contribution %",
                        max: 100
                    },
                    yAxis: {
                        type: "category",
                        inverse: true,
                        data: rows.map((row) => row.name)
                    },
                    series: [{
                        type: "bar",
                        data: rows
                    }]
                });
            };

            contributorChart("decoder-chart", data.contributors.decoder_failure);
            contributorChart("uncovered-chart", data.contributors.uncovered);
            contributorChart("threshold-chart", data.contributors.below_threshold);

            if (data.log_types.length) {
                createChart("logtype-chart", {
                    tooltip: { trigger: "axis", renderMode: "richText", axisPointer: { type: "shadow" } },
                    legend: { bottom: 0 },
                    grid: { left: "4%", right: "4%", bottom: "12%", containLabel: true },
                    xAxis: { type: "value" },
                    yAxis: {
                        type: "category",
                        inverse: true,
                        data: data.log_types.map((row) => row.name)
                    },
                    series: data.outcome_names.map((name) => ({
                        name: name,
                        type: "bar",
                        stack: "total",
                        data: data.log_types.map((row) => row[name])
                    }))
                });
            } else {
                showFallback("logtype-chart");
            }

            window.addEventListener("resize", () => charts.forEach((chart) => chart.resize()));
        })();
    </script>
</body>
</html>
"""


def render_html_report(
    analysis: ArchiveAnalysis,
    verifications: Sequence[Verification] = (),
    *,
    alert_threshold: Optional[int] = None,
    threshold_source: Optional[str] = None,
) -> str:
    """Render one archive as a single HTML file with CDN-backed presentation."""

    snapshot = calculate_metrics(analysis, verifications)
    statuses, log_types = resolve_effective_counts(analysis, verifications)
    resolved = bool(verifications)
    outcomes = outcome_counts(statuses, resolved=resolved)
    chart_data = {
        "outcomes": [
            {"name": name, "value": count}
            for name, count in outcomes.items()
        ],
        "outcome_names": list(outcomes),
        "contributors": {
            "decoder_failure": _contributors(snapshot, "decoder_failure"),
            "uncovered": _contributors(snapshot, "uncovered"),
            "below_threshold": _contributors(snapshot, "below_threshold"),
        },
        "log_types": _chart_log_types(log_types, resolved=resolved),
    }

    replacements = {
        "__ARCHIVE_TITLE__": escape(analysis.path.name),
        "__ARCHIVE__": escape(str(analysis.path)),
        "__EVENTS__": f"{analysis.total_events:,}",
        "__THRESHOLD__": "n/a" if alert_threshold is None else str(alert_threshold),
        "__THRESHOLD_SOURCE__": escape(threshold_source or "not supplied"),
        "__REPORT_DATE__": escape(datetime.now().astimezone().isoformat(timespec="seconds")),
        "__METRIC_CARDS__": _render_metric_cards(snapshot),
        "__OUTCOME_TITLE__": "Effective outcomes" if resolved else "Archive outcomes",
        "__OUTCOME_TABLE__": _render_outcome_table(outcomes, analysis.total_events),
        "__LOGTYPE_OUTCOME_TABLE__": _render_log_type_outcome_table(log_types, resolved=resolved),
        "__LOGTYPE_TABLE__": _render_log_type_table(snapshot),
        "__FINDINGS_NOTE__": _render_findings_note(analysis, verifications),
        "__FINDINGS__": _render_findings(analysis, verifications),
        "__REPORT_DATA__": _safe_json(chart_data),
    }

    return re.sub(
        r"__[A-Z_]+__",
        lambda match: replacements[match.group(0)],
        _HTML_TEMPLATE,
    )


def _render_metric_cards(snapshot: MetricSnapshot) -> str:
    metrics = (
        ("Malformed input", snapshot.malformed_rate),
        ("Decoder failure", snapshot.decoder_failure_rate),
        ("Uncovered", snapshot.uncovered_rate),
        ("Below threshold", snapshot.below_threshold_rate),
        ("Unresolved", snapshot.uncertainty_rate),
    )
    return "\n".join(_render_metric_card(label, metric) for label, metric in metrics)


def _render_metric_card(label: str, metric: MetricValue) -> str:
    if not metric.available:
        value = "Unavailable"
        detail = "Without complete replay"
    else:
        value = _percent(metric.ratio)
        if metric.count is None or metric.denominator is None:
            detail = "n/a"
        else:
            detail = f"{metric.count:,} / {metric.denominator:,}"

    return (
        '<article class="metric-card">'
        f"<small>{escape(label)}</small>"
        f"<h2>{escape(value)}</h2>"
        f"<p>{escape(detail)}</p>"
        "</article>"
    )


def _render_outcome_table(outcomes: dict[str, int], total: int) -> str:
    rows = []
    for name, count in outcomes.items():
        rows.append(
            "<tr>"
            f"<td>{escape(name)}</td>"
            f'<td class="numeric">{count:,}</td>'
            f'<td class="numeric">{_percent(None if total == 0 else count / total)}</td>'
            "</tr>"
        )
    return (
        "<figure><table><thead><tr>"
        "<th>Outcome</th><th class=\"numeric\">Events</th><th class=\"numeric\">Share</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></figure>"
    )


def _render_log_type_table(snapshot: MetricSnapshot) -> str:
    rows = []
    for item in snapshot.log_types:
        rows.append(
            "<tr>"
            f"<td>{escape(item.log_type or '(none)')}</td>"
            f'<td class="numeric">{item.event_count:,}</td>'
            f'<td class="numeric">{_percent(item.decoder_failure_rate.ratio)}</td>'
            f'<td class="numeric">{_percent(item.decoder_failure_contribution.ratio)}</td>'
            f'<td class="numeric">{_percent(item.uncovered_rate.ratio, item.uncovered_rate.available)}</td>'
            f'<td class="numeric">{_percent(item.uncovered_contribution.ratio, item.uncovered_contribution.available)}</td>'
            f'<td class="numeric">{_percent(item.below_threshold_rate.ratio)}</td>'
            f'<td class="numeric">{_percent(item.below_threshold_contribution.ratio)}</td>'
            "</tr>"
        )
    return (
        "<figure><table><thead><tr>"
        "<th>Log type</th>"
        "<th class=\"numeric\">Events</th>"
        "<th class=\"numeric\">Decoder failure</th>"
        "<th class=\"numeric\">Decoder contribution</th>"
        "<th class=\"numeric\">Uncovered</th>"
        "<th class=\"numeric\">Uncovered contribution</th>"
        "<th class=\"numeric\">Below threshold</th>"
        "<th class=\"numeric\">Below-threshold contribution</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></figure>"
    )


def _render_log_type_outcome_table(
    log_types: dict[Optional[str], dict[str, int]],
    *,
    resolved: bool,
) -> str:
    names = list(outcome_counts({}, resolved=resolved))
    rows = []
    for log_type, statuses in sorted(
        log_types.items(),
        key=lambda item: (-sum(item[1].values()), item[0] or ""),
    ):
        outcomes = outcome_counts(statuses, resolved=resolved)
        total = sum(outcomes.values())
        if not total:
            continue
        cells = "".join(f'<td class="numeric">{outcomes[name]:,}</td>' for name in names)
        rows.append(
            "<tr>"
            f"<td>{escape(log_type or '(none)')}</td>"
            f'<td class="numeric">{total:,}</td>'
            f"{cells}"
            "</tr>"
        )

    headings = "".join(f'<th class="numeric">{escape(name)}</th>' for name in names)
    return (
        "<figure><table><thead><tr>"
        "<th>Log type</th><th class=\"numeric\">Events</th>"
        f"{headings}"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></figure>"
    )


def _render_findings(
    analysis: ArchiveAnalysis,
    verifications: Sequence[Verification],
) -> str:
    by_key = {item.finding_key: item for item in verifications}
    grouped: dict[str, list[tuple[Finding, Optional[Verification]]]] = {
        group: [] for group in FINDING_GROUPS
    }

    for finding in analysis.findings:
        verification = by_key.get(finding.finding_key)
        state = verification.effective_state if verification is not None else finding.observed_status
        grouped[finding_group(state)].append((finding, verification))

    sections = []
    for group in FINDING_GROUPS:
        entries = sorted(grouped[group], key=lambda item: (-item[0].event_count, item[0].finding_key))
        if not entries:
            continue
        details = "".join(_render_finding(finding, verification) for finding, verification in entries)
        sections.append(f"<section><h3>{group} ({len(entries)})</h3>{details}</section>")

    if not sections:
        return "<p>No findings.</p>"
    return "".join(sections)


def _render_finding(finding: Finding, verification: Optional[Verification]) -> str:
    presented = present_finding(finding, verification)

    metadata = (
        ("Status", presented.status),
        ("Log type", presented.log_type),
        ("Events", f"{finding.event_count:,}"),
        ("Affected agents", f"{finding.affected_agents:,}"),
        ("First seen", finding.first_seen),
        ("Last seen", finding.last_seen),
        ("Decoder", presented.decoder),
        ("Rule", presented.rule_id),
        ("Level", None if presented.rule_level is None else str(presented.rule_level)),
        ("Matched", presented.rule_description),
        ("Replay error", presented.replay_error),
    )
    rows = "".join(
        "<tr>"
        f"<th>{escape(label)}</th>"
        f"<td>{escape(value) if value is not None else '—'}</td>"
        "</tr>"
        for label, value in metadata
    )

    summary = " · ".join(
        (
            presented.status,
            presented.log_type or "(none)",
            f"{finding.event_count:,} events",
        )
    )

    regex_suggestion = ""
    if finding.observed_status in ("no_decoder", "no_alerting_rule"):
        regex_type, regex = suggest_wazuh_regex(finding.message_pattern)
        regex_suggestion = (
            f"<h4>Suggested Wazuh regex ({escape(regex_type)})</h4>"
            f"<pre><code>{escape(regex)}</code></pre>"
        )

    return (
        '<details class="finding">'
        f"<summary><strong>{escape(summary)}</strong></summary>"
        f"<figure><table><tbody>{rows}</tbody></table></figure>"
        "<h4>Pattern</h4>"
        f"<pre><code>{escape(finding.message_pattern)}</code></pre>"
        f"{regex_suggestion}"
        "<h4>Sample</h4>"
        f"<pre><code>{escape(finding.sample_log)}</code></pre>"
        "</details>"
    )


def _render_findings_note(
    analysis: ArchiveAnalysis,
    verifications: Sequence[Verification],
) -> str:
    if verifications or not any(
        item.status == "no_alerting_rule" and item.event_count
        for item in analysis.status_counts
    ):
        return ""

    return (
        '<article class="notice">'
        "<strong>Archive ambiguity</strong>"
        "<p>A no_alerting_rule event carries no rule in the archive. Wazuh can write "
        "the same record when no rule matched, a level-0 rule matched, or a rule's "
        "ignore window suppressed the match. Replay the representative sample through "
        "wazuh-logtest to distinguish those states.</p>"
        "</article>"
    )


def _contributors(snapshot: MetricSnapshot, metric: str) -> list[dict[str, object]]:
    attributes = {
        "decoder_failure": ("decoder_failure_rate", "decoder_failure_contribution"),
        "uncovered": ("uncovered_rate", "uncovered_contribution"),
        "below_threshold": ("below_threshold_rate", "below_threshold_contribution"),
    }
    local_name, contribution_name = attributes[metric]
    rows = []

    for item in snapshot.log_types:
        local = getattr(item, local_name)
        contribution = getattr(item, contribution_name)
        if (
            not local.available
            or local.count is None
            or local.count == 0
            or not contribution.available
            or contribution.ratio is None
        ):
            continue
        rows.append(
            {
                "name": item.log_type or "(none)",
                "value": contribution.ratio * 100,
                "events": local.count,
                "local_rate": None if local.ratio is None else local.ratio * 100,
            }
        )

    rows.sort(key=lambda row: (-float(row["value"]), -int(row["events"]), str(row["name"])))
    return rows[:10]


def _chart_log_types(
    log_types: dict[Optional[str], dict[str, int]],
    *,
    resolved: bool,
) -> list[dict[str, object]]:
    rows = []
    for log_type, statuses in log_types.items():
        outcomes = outcome_counts(statuses, resolved=resolved)
        rows.append(
            {
                "name": log_type or "(none)",
                **outcomes,
                "total": sum(outcomes.values()),
            }
        )
    rows.sort(key=lambda item: (-int(item["total"]), str(item["name"])))
    return rows[:20]


def _percent(ratio: Optional[float], available: bool = True) -> str:
    if not available:
        return "Unavailable"
    return "n/a" if ratio is None else f"{ratio * 100:.2f}%"


def _safe_json(value: object) -> str:
    return (
        json.dumps(value, separators=(",", ":"), sort_keys=True)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
