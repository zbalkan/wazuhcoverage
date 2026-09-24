"""Measure Drain configurations against a labelled corpus.

The Drain parameters in ``wazuhcoverage.analysis`` are chosen with this script
rather than by feel. It builds a corpus of labelled log families, runs it
through the same pipeline the analyzer uses -- regex masking, distinct
messages, sorted feed order, templates read back after the whole pass -- and
reports two failure modes per configuration:

``impure``
    Templates holding more than one family. A coverage report that merges a
    failed logon with a successful one, or a dropped packet with an accepted
    one, hides the very gap it exists to expose.

``frag``
    Families split across several templates. Fragmentation is the defect
    mining exists to remove, so a configuration that avoids merges by
    shattering families has not solved anything.

Run it after changing the normalizer, the corpus, or the drain3 version:

    python tools/tune_drain.py

The chosen values are the midpoint of the widest threshold band that shows
neither defect on every seed.
"""

from __future__ import annotations

import random
import re
from collections import Counter, defaultdict
from typing import Callable, Optional

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

USERS = ["root", "admin", "jdoe", "postgres", "guest", "svc-backup", "alice", "bob", "mmuster", "c.wang"]
HOSTS = [f"srv-{index:03d}" for index in range(40)]
PATHS = [f"/srv/app/{index}/data-{index}.bin" for index in range(60)]
DOMAINS = ["example.com", "corp.local", "cdn.acme.io", "mail.example.net"]


def _ip() -> str:
    return f"10.{random.randint(0, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _port() -> int:
    return random.randint(1024, 65000)


# Each entry is one semantic event class. Correct grouping means one template
# per family and no template covering two. The near-miss pairs -- 4624/4625,
# ACCEPT/DROP, Failed/Accepted -- are the ones that matter most.
FAMILIES: dict[str, Callable[[], str]] = {
    "sshd_failed": lambda: f"Failed password for {random.choice(USERS)} from {_ip()} port {_port()} ssh2",
    "sshd_accepted": lambda: f"Accepted publickey for {random.choice(USERS)} from {_ip()} port {_port()} ssh2",
    "sshd_invalid": lambda: f"Invalid user {random.choice(USERS)} from {_ip()} port {_port()}",
    "sudo_cmd": lambda: (
        f"sudo: {random.choice(USERS)} : TTY=pts/{random.randint(0, 9)} ; PWD=/home/{random.choice(USERS)} ; "
        f"USER=root ; COMMAND=/usr/bin/{random.choice(['ls', 'cat', 'systemctl', 'apt'])}"
    ),
    "kernel_usb": lambda: (
        f"kernel: usb 1-{random.randint(1, 9)}: new high-speed USB device number {random.randint(1, 99)} using ehci-pci"
    ),
    "fw_accept": lambda: (
        f"iptables: IN=eth0 OUT= SRC={_ip()} DST={_ip()} PROTO=TCP SPT={_port()} DPT=443 ACTION=ACCEPT"
    ),
    "fw_drop": lambda: f"iptables: IN=eth0 OUT= SRC={_ip()} DST={_ip()} PROTO=TCP SPT={_port()} DPT=23 ACTION=DROP",
    "win_4624": lambda: (
        "WinEvtLog: Security: AUDIT_SUCCESS(4624): Microsoft-Windows-Security-Auditing: "
        f"{random.choice(USERS)}: CORP: {random.choice(HOSTS)}: An account was successfully logged on"
    ),
    "win_4625": lambda: (
        "WinEvtLog: Security: AUDIT_FAILURE(4625): Microsoft-Windows-Security-Auditing: "
        f"{random.choice(USERS)}: CORP: {random.choice(HOSTS)}: An account failed to log on"
    ),
    "nginx_get": lambda: (
        f'{_ip()} - - "GET /api/v1/{random.choice(USERS)}/items?id={random.randint(1, 999)} HTTP/1.1" '
        f"200 {random.randint(100, 9999)}"
    ),
    "nginx_post": lambda: (
        f'{_ip()} - - "POST /api/v1/{random.choice(USERS)}/orders HTTP/1.1" 201 {random.randint(100, 9999)}'
    ),
    "named_query": lambda: (
        f"named: client {_ip()}#{_port()}: query: {random.choice(HOSTS)}.{random.choice(DOMAINS)} IN A +E(0)"
    ),
    "postfix_connect": lambda: f"postfix/smtpd: connect from {random.choice(HOSTS)}.{random.choice(DOMAINS)}[{_ip()}]",
    "backup_copy": lambda: (
        f"backup: copied {random.choice(PATHS)} to {random.choice(HOSTS)} in {random.randint(1, 900)}s"
    ),
    "cron_session": lambda: (
        f"CRON[{random.randint(1000, 30000)}]: pam_unix(cron:session): session opened for user "
        f"{random.choice(USERS)} by (uid=0)"
    ),
    "app_json": lambda: (
        f'{{"level":"error","svc":"billing","user":"{random.choice(USERS)}",'
        f'"msg":"charge declined","order":{random.randint(10000, 99999)}}}'
    ),
}

# Kept in step with the normalize_log macro in wazuhcoverage.analysis.
_SYSLOG_TS = re.compile(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+[0-9]{1,2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}")
_ISO_TS = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}([.,][0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})?"
)
_UUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
_HEX = re.compile(r"\b(0x)?[0-9A-Fa-f]{16,}\b")
_NUM = re.compile(r"\b[0-9]{5,}\b")


def normalize(text: str) -> str:
    text = _SYSLOG_TS.sub("<TIMESTAMP>", text)
    text = _ISO_TS.sub("<TIMESTAMP>", text)
    text = _UUID.sub("<UUID>", text)
    text = _HEX.sub("<HEX>", text)
    text = _NUM.sub("<NUM>", text)
    return text.strip()


def build_corpus(events_per_family: int = 400, seed: int = 11) -> list[tuple[str, str]]:
    """Return (family, full_log) pairs."""

    random.seed(seed)
    return [(name, make()) for name, make in FAMILIES.items() for _ in range(events_per_family)]


def evaluate(
    rows: list[tuple[str, str]],
    *,
    sim_th: float,
    depth: int,
    max_clusters: Optional[int] = None,
    parametrize_numeric_tokens: bool = True,
) -> dict:
    config = TemplateMinerConfig()
    config.profiling_enabled = False
    config.masking_instructions = []
    config.drain_sim_th = sim_th
    config.drain_depth = depth
    config.drain_max_clusters = max_clusters
    config.parametrize_numeric_tokens = parametrize_numeric_tokens
    miner = TemplateMiner(config=config)

    events: Counter = Counter()
    for family, log in rows:
        events[(family, normalize(log))] += 1

    assigned = {message: miner.add_log_message(message)["cluster_id"] for message in sorted({m for _, m in events})}
    mined = {cluster.cluster_id: cluster.get_template() for cluster in miner.drain.clusters}

    by_template: dict[str, Counter] = defaultdict(Counter)
    for (family, message), count in events.items():
        by_template[mined[assigned[message]]][family] += count

    templates_per_family: dict[str, set] = defaultdict(set)
    for template, families in by_template.items():
        for family in families:
            templates_per_family[family].add(template)

    return {
        "templates": len(by_template),
        "impure": {template: dict(f) for template, f in by_template.items() if len(f) > 1},
        "frag": {family: len(t) for family, t in sorted(templates_per_family.items()) if len(t) > 1},
    }


def main() -> None:
    seeds = (11, 23, 42)
    corpora = {seed: build_corpus(seed=seed) for seed in seeds}
    families = len(FAMILIES)
    print(f"corpus: {len(corpora[seeds[0]]):,} events, {families} families, seeds {seeds}\n")

    header = f"{'depth':>6} {'sim_th':>7} " + " ".join(f"{'seed ' + str(seed):>18}" for seed in seeds)
    print(header)
    print("-" * len(header))
    for depth in (3, 4, 5):
        for sim_th in (0.40, 0.50, 0.53, 0.54, 0.56, 0.57, 0.58, 0.60, 0.70):
            cells = []
            for seed in seeds:
                result = evaluate(corpora[seed], sim_th=sim_th, depth=depth)
                worst_frag = max(result["frag"].values(), default=1)
                cells.append(f"{result['templates']:>4}t {len(result['impure'])}imp {worst_frag:>2}frag".rjust(18))
            print(f"{depth:>6} {sim_th:>7} " + " ".join(cells))

    print("\nCross-family merges at the drain3 default (depth 4, sim_th 0.4):")
    for template, families_in_template in evaluate(corpora[seeds[0]], sim_th=0.4, depth=4)["impure"].items():
        print(f"  {' + '.join(sorted(families_in_template))}\n    -> {template[:110]}")


if __name__ == "__main__":
    main()
