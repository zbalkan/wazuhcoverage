from __future__ import annotations

import random
from typing import Optional

from drain3.drain import Drain

from wazuhcoverage._drain import IndexedDrain


def _drain(drain_type: type[Drain], *, max_clusters: Optional[int] = None) -> Drain:
    return drain_type(depth=4, sim_th=0.56, max_clusters=max_clusters, parametrize_numeric_tokens=True)


def test_indexed_drain_matches_stock_drain_for_every_assignment() -> None:
    messages = sorted(
        {
            "<TIMESTAMP> sshd failed password for root from 10.0.0.1 port 2201",
            "<TIMESTAMP> sshd failed password for admin from 10.0.0.2 port 2202",
            "<TIMESTAMP> sshd accepted key for root from 10.0.0.1 port 2201",
            "<TIMESTAMP> kernel usb device 1 attached on host alpha",
            "<TIMESTAMP> kernel usb device 2 attached on host beta",
            "short message",
            "another short message",
        }
    )
    stock = _drain(Drain)
    indexed = _drain(IndexedDrain)

    for message in messages:
        stock_cluster, stock_change = stock.add_log_message(message)
        indexed_cluster, indexed_change = indexed.add_log_message(message)
        assert (indexed_cluster.cluster_id, indexed_cluster.get_template(), indexed_change) == (
            stock_cluster.cluster_id,
            stock_cluster.get_template(),
            stock_change,
        )

def test_indexed_drain_matches_stock_drain_through_eviction() -> None:
    messages = ["one", "two tokens", "three token message", "one", "four token message now"]
    stock = _drain(Drain, max_clusters=2)
    indexed = _drain(IndexedDrain, max_clusters=2)

    for message in messages:
        stock_cluster, stock_change = stock.add_log_message(message)
        indexed_cluster, indexed_change = indexed.add_log_message(message)
        assert (indexed_cluster.cluster_id, indexed_cluster.get_template(), indexed_change) == (
            stock_cluster.cluster_id,
            stock_cluster.get_template(),
            stock_change,
        )

    assert len(indexed._indexed_tokens) <= 2  # type: ignore[attr-defined]


def test_indexed_drain_is_differentially_equivalent_on_generated_corpus() -> None:
    random.seed(20260922)
    vocabulary = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "host1", "host2", "port22"]
    messages = sorted(
        {
            " ".join(random.choice(vocabulary) for _ in range(random.randint(3, 12)))
            for _ in range(2_000)
        }
    )
    stock = _drain(Drain)
    indexed = _drain(IndexedDrain)

    for message in messages:
        stock_cluster, stock_change = stock.add_log_message(message)
        indexed_cluster, indexed_change = indexed.add_log_message(message)
        assert (indexed_cluster.cluster_id, indexed_cluster.get_template(), indexed_change) == (
            stock_cluster.cluster_id,
            stock_cluster.get_template(),
            stock_change,
        )


def test_index_avoids_pairwise_distance_scans_on_unique_messages(monkeypatch) -> None:
    messages = ["<TIMESTAMP> " + " ".join(f"token{position}-{index}" for position in range(10)) for index in range(500)]
    stock = _drain(Drain)
    indexed = _drain(IndexedDrain)
    calls = {"stock": 0, "indexed": 0}
    stock_distance = stock.get_seq_distance
    indexed_distance = indexed.get_seq_distance

    def count_stock(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls["stock"] += 1
        return stock_distance(*args, **kwargs)

    def count_indexed(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls["indexed"] += 1
        return indexed_distance(*args, **kwargs)

    monkeypatch.setattr(stock, "get_seq_distance", count_stock)
    monkeypatch.setattr(indexed, "get_seq_distance", count_indexed)
    for message in messages:
        stock.add_log_message(message)
        indexed.add_log_message(message)

    assert calls["stock"] == len(messages) * (len(messages) - 1) // 2
    assert calls["indexed"] == 0


def test_empty_candidate_set_does_not_scan_the_prefix_leaf() -> None:
    class NoIterationList(list):
        def __iter__(self):
            raise AssertionError("candidate filtering scanned the full Drain leaf")

    indexed = _drain(IndexedDrain)
    cluster, _ = indexed.add_log_message("constant alpha bravo charlie delta")
    leaf = indexed._cluster_leaf[cluster.cluster_id]  # type: ignore[attr-defined]
    indexed._leaf_by_cluster_list.pop(id(leaf.cluster_ids))  # type: ignore[attr-defined]
    leaf.cluster_ids = NoIterationList(leaf.cluster_ids)
    indexed._leaf_by_cluster_list[id(leaf.cluster_ids)] = leaf  # type: ignore[attr-defined]

    assert indexed.fast_match(leaf.cluster_ids, ["unique", "echo", "foxtrot", "golf", "hotel"], 0.56, False) is None
