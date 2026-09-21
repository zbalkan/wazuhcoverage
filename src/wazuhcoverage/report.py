"""Text rendering for CLI output."""

from __future__ import annotations

from wazuhcoverage.models import ArchiveAnalysis


def render_report(analysis: ArchiveAnalysis) -> str:
    """Render a compact human-readable report for one archive."""

    lines: list[str] = [
        f"Archive: {analysis.path}",
        f"Total events: {analysis.total_events:,}",
        f"Malformed lines skipped: {analysis.malformed_lines:,}",
        "",
        "Status",
        "------",
    ]

    for item in analysis.status_counts:
        percentage = 0.0 if analysis.total_events == 0 else (100.0 * item.event_count / analysis.total_events)
        lines.append(f"{item.status:<24} {item.event_count:>12,}  {percentage:>7.2f}%")

    lines.extend(["", "Log types", "---------"])
    for item in analysis.log_type_counts:
        lines.append(f"{item.status:<24} {item.log_type:<32} {item.event_count:>12,}")

    lines.extend(["", f"Findings: {len(analysis.findings):,}", ""])

    for index, finding in enumerate(analysis.findings, start=1):
        lines.extend(
            [
                f"[{index}] {finding.observed_status} | {finding.log_type or '-'}",
                f"    Events: {finding.event_count:,}",
                f"    Affected agents: {finding.affected_agents:,}",
                f"    First seen: {finding.first_seen or '-'}",
                f"    Last seen: {finding.last_seen or '-'}",
                f"    Decoder: {finding.observed_decoder or '-'}",
                f"    Rule: {finding.observed_rule_id or '-'}",
                f"    Level: {finding.observed_rule_level if finding.observed_rule_level is not None else '-'}",
                f"    Pattern: {finding.message_pattern}",
                f"    Sample: {finding.sample_log}",
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"
