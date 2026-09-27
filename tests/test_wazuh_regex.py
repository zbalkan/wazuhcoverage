from wazuhcoverage.html_report import _render_finding
from wazuhcoverage.models import Finding
from wazuhcoverage.report import _finding_rows
from wazuhcoverage.wazuh_regex import suggest_wazuh_regex


def _finding(*, status: str = "no_decoder", pattern: str) -> Finding:
    return Finding(
        finding_key="key",
        observed_status=status,
        log_type="sshd",
        message_pattern=pattern,
        event_count=5,
        affected_agents=2,
        first_seen=None,
        last_seen=None,
        observed_decoder=None,
        observed_location="syslog",
        observed_rule_id=None,
        observed_rule_level=None,
        sample_log="sample",
    )


def test_drain_wildcards_become_osregex_tokens() -> None:
    regex_type, regex = suggest_wazuh_regex(
        "Failed password for <*> from <*> port <*> ssh2"
    )

    assert regex_type == "osregex"
    assert regex == r"^Failed password for \S+ from \S+ port \S+ ssh2$"


def test_osregex_literals_are_preserved_and_escaped() -> None:
    regex_type, regex = suggest_wazuh_regex("service(foo)|bar$ <tag>.")

    assert regex_type == "osregex"
    assert regex == r"^service\(foo\)\|bar\$ \<tag>.$"


def test_unrepresentable_osregex_literals_fall_back_to_pcre2() -> None:
    regex_type, regex = suggest_wazuh_regex("C++ <*>")

    assert regex_type == "pcre2"
    assert regex == r"^C\+\+ \S+$"


def test_typed_preprocessor_placeholders_keep_their_known_shape() -> None:
    regex_type, regex = suggest_wazuh_regex("id=<NUM> uuid=<UUID> hash=<HEX>")

    assert regex_type == "pcre2"
    assert r"[0-9]{5,}" in regex
    assert r"[0-9A-Fa-f]{8}-" in regex
    assert r"(?:0x)?[0-9A-Fa-f]{16,}" in regex


def test_timestamp_placeholder_covers_supported_prefix_families() -> None:
    regex_type, regex = suggest_wazuh_regex("<TIMESTAMP> daemon <*>")

    assert regex_type == "pcre2"
    assert "Jan|Feb|Mar" in regex
    assert "Mon|Tue|Wed" in regex
    assert r"[0-9]{8}T[0-9]{6}" in regex
    assert r"/[0-9]{4}:" in regex
    assert regex.endswith(r" daemon \S+$")


def test_text_finding_shows_the_candidate_beside_the_mined_pattern() -> None:
    finding = _finding(pattern="Failed password for <*> from <*> port <*> ssh2")

    rows = _finding_rows(1, finding, None)

    assert "    Pattern: Failed password for <*> from <*> port <*> ssh2" in rows
    assert (
        r"    Suggested Wazuh regex (osregex): ^Failed password for \S+ from \S+ port \S+ ssh2$"
        in rows
    )


def test_html_finding_shows_the_candidate_beside_the_mined_pattern() -> None:
    finding = _finding(pattern="Failed password for <*> from <*> port <*> ssh2")

    rendered = _render_finding(finding, None)

    assert "<h4>Suggested Wazuh regex (osregex)</h4>" in rendered
    assert r"^Failed password for \S+ from \S+ port \S+ ssh2$" in rendered


def test_rule_grouped_findings_do_not_get_a_fake_log_regex() -> None:
    finding = _finding(status="below_threshold", pattern="rule:200")

    rows = _finding_rows(1, finding, None)
    rendered = _render_finding(finding, None)

    assert not any("Suggested Wazuh regex" in row for row in rows)
    assert "Suggested Wazuh regex" not in rendered
