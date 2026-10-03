"""Cyber attack graph (Section 2): directed graph of possible attacker movements.

Nodes are hosts; an edge u -> v exists when the firewall/topology lets u reach v
and v exposes an unpatched vulnerability. Edge weight = exploit success probability.
"""
from __future__ import annotations

import heapq
import math
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

from .network import Network

Edge = Tuple[str, str]


class AttackGraph:
    def __init__(self, net: Network, attacker: str = "attacker", target: str = "core") -> None:
        self.net = net
        self.attacker = attacker
        self.target = target
        self.edges: Dict[Edge, dict] = {}
        self.out: Dict[str, List[str]] = {}
        self.inn: Dict[str, List[str]] = {}
        self.rebuild()

    # ---------------------------------------------------------------- construction
    def nodes(self) -> List[str]:
        return [h.id for h in self.net.hosts.values() if not h.infra and h.kind != "monitor"]

    def rebuild(self) -> None:
        self.net.invalidate()
        nodes = self.nodes()
        self.edges = {}
        self.out = {n: [] for n in nodes}
        self.inn = {n: [] for n in nodes}
        for u in nodes:
            for v in nodes:
                if u == v or v == self.attacker:
                    continue
                vulns = self.net.hosts[v].open_vulns()
                if not vulns or not self.net.can_reach(u, v):
                    continue
                best = max(vulns, key=lambda x: x.exploitability)
                self.edges[(u, v)] = {
                    "source": u,
                    "target": v,
                    "p": best.exploitability,
                    "technique": best.technique,
                    "cve": best.cve,
                }
                self.out[u].append(v)
                self.inn[v].append(u)

    # ---------------------------------------------------------------- path analysis
    def most_probable_path(self, sources: Set[str], target: Optional[str] = None) -> List[str]:
        """Multi-source Dijkstra on -log(p): the attacker's most likely route."""
        target = target or self.target
        dist: Dict[str, float] = {s: 0.0 for s in sources if s in self.out}
        prev: Dict[str, str] = {}
        pq = [(0.0, s) for s in dist]
        heapq.heapify(pq)
        while pq:
            d, u = heapq.heappop(pq)
            if d > dist.get(u, math.inf):
                continue
            if u == target:
                break
            for v in self.out.get(u, []):
                if v in sources:
                    continue
                nd = d - math.log(max(self.edges[(u, v)]["p"], 1e-6))
                if nd < dist.get(v, math.inf):
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(pq, (nd, v))
        if target not in dist:
            return []
        path = [target]
        while path[-1] in prev:
            path.append(prev[path[-1]])
        return list(reversed(path))

    def path_probability(self, path: List[str]) -> float:
        p = 1.0
        for a, b in zip(path, path[1:]):
            p *= self.edges[(a, b)]["p"]
        return p

    def count_simple_paths(self, src: Optional[str] = None, dst: Optional[str] = None, cap: int = 50000) -> int:
        """Combinatorics: enumerate simple attack paths with DFS (capped)."""
        src = src or self.attacker
        dst = dst or self.target
        if src not in self.out:
            return 0
        count = 0
        stack = [(src, iter(self.out[src]))]
        on_path = {src}
        while stack:
            node, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                stack.pop()
                on_path.discard(node)
                continue
            if nxt in on_path:
                continue
            if nxt == dst:
                count += 1
                if count >= cap:
                    return count
                continue
            on_path.add(nxt)
            stack.append((nxt, iter(self.out[nxt])))
        return count

    def reachable_from(self, sources: Set[str]) -> Set[str]:
        seen = set(s for s in sources if s in self.out)
        q = deque(seen)
        while q:
            u = q.popleft()
            for v in self.out[u]:
                if v not in seen:
                    seen.add(v)
                    q.append(v)
        return seen

    def compromise_probability(self, compromised: Set[str], iterations: int = 12) -> Dict[str, float]:
        """Bayesian attack graph with noisy-OR parents (loopy propagation)."""
        nodes = list(self.out)
        prob = {n: (1.0 if n in compromised else 0.0) for n in nodes}
        for _ in range(iterations):
            new = {}
            for v in nodes:
                if v in compromised:
                    new[v] = 1.0
                    continue
                miss = 1.0
                for u in self.inn[v]:
                    miss *= 1.0 - prob[u] * self.edges[(u, v)]["p"]
                new[v] = 1.0 - miss
            prob = new
        return prob

    def transitive_closure_size(self) -> int:
        """Relations: Warshall's algorithm over the reachability relation."""
        nodes = list(self.out)
        idx = {n: i for i, n in enumerate(nodes)}
        n = len(nodes)
        m = [[False] * n for _ in range(n)]
        for (u, v) in self.edges:
            m[idx[u]][idx[v]] = True
        for k in range(n):
            mk = m[k]
            for i in range(n):
                if m[i][k]:
                    mi = m[i]
                    for j in range(n):
                        if mk[j]:
                            mi[j] = True
        return sum(sum(row) for row in m)

    def bfs_tree_depth(self, root: Optional[str] = None) -> Tuple[int, int]:
        """Trees: depth and leaf count of the BFS attack tree rooted at the attacker."""
        root = root or self.attacker
        if root not in self.out:
            return 0, 0
        depth = {root: 0}
        children: Dict[str, int] = {root: 0}
        q = deque([root])
        while q:
            u = q.popleft()
            for v in self.out[u]:
                if v not in depth:
                    depth[v] = depth[u] + 1
                    children[v] = 0
                    children[u] += 1
                    q.append(v)
        leaves = sum(1 for c in children.values() if c == 0)
        return max(depth.values()), leaves

    def to_dict(self) -> dict:
        return {"edges": list(self.edges.values()), "nodes": list(self.out)}
