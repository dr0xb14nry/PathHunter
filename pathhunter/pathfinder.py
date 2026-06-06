"""
Pathfinder  (Phase 3)
=====================

This is the payoff. Given a START and a TARGET, it finds the BEST attack
path under each objective and prints it as a step-by-step chain.

It uses **Dijkstra's algorithm** (the classic shortest-path algorithm)
over the scored graph. The only thing that changes between objectives is
the COST we put on each edge (from scoring.py):

  fast      every edge costs 1     -> fewest hops win
  stealth   cost = detection       -> quietest total path wins
  reliable  cost = flakiness       -> most dependable path wins

Because the graph is in memory and small, this is instant and uses
almost no RAM — exactly the lightweight design we wanted.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass

from .scoring import COST_FUNCS, edge_smartness
from .profiles import get_profile, get_profile_technique


@dataclass
class Path:
    """A found attack path: the node ids visited and the edges used."""

    nodes: list[str]    # node ids, start .. target
    edges: list[dict]   # the edges taken between them

    @property
    def hops(self) -> int:
        return len(self.edges)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _label(full_name: str) -> str:
    """'liam.walsh@CORP.LOCAL' -> 'liam.walsh'; 'FS01.CORP.LOCAL' -> 'FS01'."""
    if "@" in full_name:               # UPN: keep the full username (real names have dots)
        return full_name.split("@")[0]
    return full_name.split(".")[0]     # host FQDN: keep just the hostname


def resolve(graph, query: str) -> str | None:
    """Turn a human query ('alice', 'daadmin') into a node id (SID).

    Matches case-insensitively against node names and returns the most
    specific (shortest-named) match, or None if nothing matches.
    """
    q = query.lower()
    matches = [n for n in graph.nodes.values() if q in n["name"].lower()]
    if not matches:
        return None
    matches.sort(key=lambda n: len(n["name"]))
    return matches[0]["id"]


def _adjacency(graph) -> dict[str, list[dict]]:
    """Build node_id -> list of outgoing edges (so Dijkstra can walk fast)."""
    adj: dict[str, list[dict]] = {}
    for edge in graph.edges:
        adj.setdefault(edge["source"], []).append(edge)
    return adj


# ---------------------------------------------------------------------------
# Dijkstra: cheapest path from start to target under a given objective.
# ---------------------------------------------------------------------------
def find_path(graph, start_id: str, target_id: str, objective: str = "stealth",
              profile: str | None = None) -> Path | None:
    cost_of = COST_FUNCS[objective]          # edge -> cost function
    adj = _adjacency(graph)

    dist: dict[str, float] = {start_id: 0.0}  # best cost found to each node
    prev_node: dict[str, str] = {}            # how we got there (for rebuild)
    prev_edge: dict[str, dict] = {}
    visited: set[str] = set()
    heap: list[tuple[float, str]] = [(0.0, start_id)]

    while heap:
        cost_here, node = heapq.heappop(heap)
        if node in visited:
            continue
        visited.add(node)
        if node == target_id:
            break
        for edge in adj.get(node, []):
            nxt = edge["target"]
            # Score the edge through the active profile, so a noisier
            # situation can make Dijkstra prefer a different route.
            new_cost = cost_here + cost_of(get_profile_technique(edge["kind"], profile))
            if new_cost < dist.get(nxt, float("inf")):
                dist[nxt] = new_cost
                prev_node[nxt] = node
                prev_edge[nxt] = edge
                heapq.heappush(heap, (new_cost, nxt))

    if target_id != start_id and target_id not in prev_node:
        return None  # target is unreachable from start

    # Walk the 'prev' links backwards to rebuild the path.
    nodes = [target_id]
    edges: list[dict] = []
    cur = target_id
    while cur != start_id:
        edges.insert(0, prev_edge[cur])
        cur = prev_node[cur]
        nodes.insert(0, cur)
    return Path(nodes, edges)


# ---------------------------------------------------------------------------
# Count how many distinct attack paths exist (capped, for "showing best 3 of N").
# ---------------------------------------------------------------------------
PATH_CAP = 25   # stop counting once this many paths are found (keeps it fast)


def count_paths(graph, start_id: str, target_id: str,
                cap: int = PATH_CAP, max_len: int = 20) -> int:
    """Count distinct simple paths start -> target, capped for speed/display.

    Returns up to `cap`; if it returns `cap`, treat it as ">= cap". A DFS with
    a visited-set (no node repeats) and an exploration budget so it stays fast
    even on dense graphs like a full GOAD forest.
    """
    if not start_id or not target_id or start_id == target_id:
        return 0
    adj = _adjacency(graph)
    found = 0
    budget = [300000]

    def dfs(node, visited, depth):
        nonlocal found
        if found >= cap or budget[0] <= 0:
            return
        budget[0] -= 1
        if node == target_id:
            found += 1
            return
        if depth >= max_len:
            return
        for e in adj.get(node, []):
            nxt = e["target"]
            if nxt not in visited:
                visited.add(nxt)
                dfs(nxt, visited, depth + 1)
                visited.discard(nxt)
                if found >= cap or budget[0] <= 0:
                    return

    dfs(start_id, {start_id}, 0)
    return found


# ---------------------------------------------------------------------------
# Pretty-print one path.
# ---------------------------------------------------------------------------
def print_path(graph, path: Path | None, label: str, profile: str | None = None) -> None:
    print("\n " + "-" * 62)
    if path is None:
        print(f" {label}: no path found")
        return

    techs = [get_profile_technique(e["kind"], profile) for e in path.edges]
    total_noise = sum(t.detection for t in techs)
    avg_smart = round(sum(edge_smartness(t) for t in techs) / len(techs), 1)

    print(f" {label}")
    print(f"   {path.hops} hops  |  total noise {total_noise}  |  avg smart {avg_smart}/10")
    for i, (edge, t) in enumerate(zip(path.edges, techs), start=1):
        src = _label(graph.nodes[edge["source"]]["name"])
        dst = _label(graph.nodes[edge["target"]]["name"])
        hop = f"{src} --{edge['kind']}--> {dst}"
        print(f"   {i}. {hop:<44}[{t.mitre:<10}] noise {t.detection}")


# ---------------------------------------------------------------------------
# Run all three objectives for a start -> target and print them.
# ---------------------------------------------------------------------------
OBJECTIVES = [
    ("fast", "FASTEST  (fewest hops)"),
    ("stealth", "STEALTHIEST  (least noise)"),
    ("reliable", "MOST RELIABLE"),
]


def analyze(graph, start_query: str, target_query: str, modes=None,
            profile: str | None = None) -> None:
    start = resolve(graph, start_query)
    target = resolve(graph, target_query)

    prof = get_profile(profile)
    line = "=" * 64
    print("\n" + line)
    print(" PathHunter  -  ranked attack paths")
    print(line)

    if not start:
        print(f" Could not find a start node matching '{start_query}'.")
        return
    if not target:
        print(f" Could not find a target node matching '{target_query}'.")
        return

    print(f" Start:   {_label(graph.nodes[start]['name'])}")
    print(f" Target:  {_label(graph.nodes[target]['name'])}")
    print(f" Profile: {prof.name}  ({prof.description})")
    total = count_paths(graph, start, target)
    print(f" Paths found: {total}{'+' if total >= PATH_CAP else ''}  (showing the 3 smartest below)")

    chosen = OBJECTIVES if not modes else [ol for ol in OBJECTIVES if ol[0] in modes]
    for objective, label in chosen:
        path = find_path(graph, start, target, objective, profile=profile)
        print_path(graph, path, label, profile=profile)

    print("\n" + line + "\n")
