"""Drain implementation details used by the archive analyzer."""

from __future__ import annotations

import math
from collections import defaultdict
from typing import DefaultDict, Optional, Sequence

from drain3.drain import Drain, LogClusterCache, Node


class _IndexedLogClusterCache(LogClusterCache):
    """Notify an indexed Drain when the LRU policy evicts a cluster."""

    def __init__(self, maxsize: int, drain: "IndexedDrain") -> None:
        super().__init__(maxsize=maxsize)
        self._drain = drain

    def popitem(self):  # type: ignore[no-untyped-def]
        cluster_id, cluster = super().popitem()
        self._drain._remove_indexed_template(cluster_id)
        return cluster_id, cluster


class IndexedDrain(Drain):
    """Drain with an exact positional-token candidate index.

    A template must have at least ``ceil(sim_th * token_count)`` exact token
    matches to pass Drain's similarity check during mining. It must therefore
    occur in the posting list for at least one of any ``n - k + 1`` positions
    in the incoming message. Choosing the rarest such positions sharply
    reduces the candidate set while preserving Drain's original cluster order
    and, consequently, its tie-breaking semantics.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._postings: DefaultDict[tuple[int, str], set[int]] = defaultdict(set)
        self._indexed_tokens: dict[int, tuple[str, ...]] = {}
        self._cluster_leaf: dict[int, Node] = {}
        self._stale_per_leaf: DefaultDict[int, int] = defaultdict(int)
        if self.max_clusters is not None:
            self.id_to_cluster = _IndexedLogClusterCache(self.max_clusters, self)

    def _remove_indexed_template(self, cluster_id: int) -> None:
        previous = self._indexed_tokens.pop(cluster_id, None)
        self._remove_postings(cluster_id, previous)
        leaf = self._cluster_leaf.pop(cluster_id, None)
        if leaf is not None:
            leaf_key = id(leaf)
            self._stale_per_leaf[leaf_key] += 1
            if self._stale_per_leaf[leaf_key] * 2 >= len(leaf.cluster_ids):
                leaf.cluster_ids = [candidate for candidate in leaf.cluster_ids if candidate in self.id_to_cluster]
                self._stale_per_leaf[leaf_key] = 0

    def _remove_postings(self, cluster_id: int, tokens: Optional[tuple[str, ...]]) -> None:
        if tokens is None:
            return
        for position, token in enumerate(tokens):
            if token != self.param_str:
                posting = self._postings[(position, token)]
                posting.discard(cluster_id)
                if not posting:
                    del self._postings[(position, token)]

    def _replace_indexed_template(self, cluster_id: int, tokens: tuple[str, ...]) -> None:
        self._remove_postings(cluster_id, self._indexed_tokens.get(cluster_id))
        self._indexed_tokens[cluster_id] = tokens
        for position, token in enumerate(tokens):
            if token != self.param_str:
                self._postings[(position, token)].add(cluster_id)

    def add_seq_to_prefix_tree(self, root_node: Node, cluster) -> None:  # type: ignore[no-untyped-def]
        """Add a cluster without Drain's quadratic stale-ID cleanup."""

        tokens = cluster.log_template_tokens
        token_count = len(tokens)
        cur_node = root_node.key_to_child_node.setdefault(str(token_count), Node())
        if token_count == 0:
            cur_node.cluster_ids = [cluster.cluster_id]
            self._cluster_leaf[cluster.cluster_id] = cur_node
            return

        current_depth = 1
        for token in tokens:
            if current_depth >= self.max_node_depth or current_depth >= token_count:
                cur_node.cluster_ids.append(cluster.cluster_id)
                self._cluster_leaf[cluster.cluster_id] = cur_node
                return

            children = cur_node.key_to_child_node
            if token in children:
                cur_node = children[token]
            elif self.parametrize_numeric_tokens and self.has_numbers(token):
                cur_node = children.setdefault(self.param_str, Node())
            elif self.param_str in children:
                if len(children) < self.max_children:
                    cur_node = children.setdefault(token, Node())
                else:
                    cur_node = children[self.param_str]
            elif len(children) + 1 < self.max_children:
                cur_node = children.setdefault(token, Node())
            elif len(children) + 1 == self.max_children:
                cur_node = children.setdefault(self.param_str, Node())
            else:
                cur_node = children[self.param_str]
            current_depth += 1

    def fast_match(self, cluster_ids: Sequence, tokens: list, sim_th: float, include_params: bool):  # type: ignore[no-untyped-def]
        # ``match()`` can count wildcard parameters as matches. The positional
        # exact-token bound does not apply in that mode, so retain stock Drain.
        if include_params or not cluster_ids:
            return super().fast_match(cluster_ids, tokens, sim_th, include_params)

        required_matches = math.ceil(sim_th * len(tokens))
        positions_to_probe = len(tokens) - required_matches + 1
        if required_matches <= 0 or positions_to_probe <= 0:
            return super().fast_match(cluster_ids, tokens, sim_th, include_params)

        probes = sorted(
            ((len(self._postings.get((position, token), ())), position, token) for position, token in enumerate(tokens)),
            key=lambda item: (item[0], item[1]),
        )[:positions_to_probe]
        candidate_ids: set[int] = set()
        for _, position, token in probes:
            candidate_ids.update(self._postings.get((position, token), ()))

        # Filtering the leaf list, rather than iterating the set, preserves the
        # exact tie order used by stock Drain. Stale IDs left by LRU eviction
        # are harmless and are discarded here along with non-candidates.
        candidates = [cluster_id for cluster_id in cluster_ids if cluster_id in candidate_ids]
        return super().fast_match(candidates, tokens, sim_th, include_params)

    def add_log_message(self, content: str):  # type: ignore[no-untyped-def]
        cluster, update_type = super().add_log_message(content)
        if update_type != "none":
            self._replace_indexed_template(cluster.cluster_id, cluster.log_template_tokens)
        return cluster, update_type
