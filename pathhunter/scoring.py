"""
Scoring engine  (Phase 2)
==========================

The loader gives us a graph of nodes and edges. This module adds the
*meaning*: it looks up each edge's technique (from techniques.py) and
attaches numbers PathHunter can reason about.

Two kinds of numbers:

1. A per-edge "smartness" score (0-10) for quick human reading:
   a step that is both QUIET and RELIABLE scores high.

2. Three EDGE COST functions used later by the pathfinder (Phase 3).
   In pathfinding, LOWER cost = more preferred, so:
       fast      every hop costs 1        -> fewest hops win
       stealth   cost = detection         -> least noisy path wins
       reliable  cost = penalty for flaky -> most dependable path wins

Nothing here runs a search yet; it just enriches the graph so Phase 3
can do the ranking.
"""

from __future__ import annotations

from .techniques import Technique, get_technique
from .profiles import get_profile, get_profile_technique


# ---------------------------------------------------------------------------
# Per-edge "smartness": a single friendly 0-10 number.
# ---------------------------------------------------------------------------
def edge_smartness(t: Technique) -> float:
    """Blend 'how quiet' and 'how reliable' into one 0-10 score.

    quiet    = (10 - detection) / 10   ->  1.0 when silent, 0.0 when very loud
    reliable = reliability             ->  already 0..1
    We weight them equally (50/50).
    """
    quiet = (10 - t.detection) / 10
    reliable = t.reliability
    return round((quiet * 0.5 + reliable * 0.5) * 10, 1)


# ---------------------------------------------------------------------------
# Edge COST functions, one per objective. (Used by the Phase 3 pathfinder.)
# Lower cost = the pathfinder prefers this edge.
# ---------------------------------------------------------------------------
def cost_fast(t: Technique) -> float:
    """Every hop costs the same, so the fewest-hops path wins."""
    return 1.0


def cost_stealth(t: Technique) -> float:
    """Cost equals detection, so the quietest total path wins."""
    return float(t.detection)


def cost_reliable(t: Technique) -> float:
    """Flaky steps cost more. The +0.3 keeps every hop slightly above zero
    so the search still prefers shorter routes when reliability ties."""
    return (1.0 - t.reliability) * 10 + 0.3


# Handy lookup so other code can pick a cost function by name.
COST_FUNCS = {
    "fast": cost_fast,
    "stealth": cost_stealth,
    "reliable": cost_reliable,
}


# ---------------------------------------------------------------------------
# Enrich the graph: attach technique info + scores to every edge in place.
# ---------------------------------------------------------------------------
def annotate_graph(graph, profile: str | None = None) -> None:
    """Add technique/MITRE/detection/reliability/smartness onto each edge.

    After calling this, every edge dict gains these extra keys, ready for
    pretty-printing (below) and for pathfinding in Phase 3.

    `profile` selects an environment lens (see profiles.py). With the default
    profile the numbers are the published baseline; with e.g. "edr" the
    detection/reliability of noisy families are shifted, which is what makes
    the same graph rank differently in different situations. The technique's
    *category* is also recorded so reports can group steps.
    """
    for edge in graph.edges:
        t = get_profile_technique(edge["kind"], profile)
        edge["technique"] = t.name
        edge["mitre"] = t.mitre
        edge["detection"] = t.detection
        edge["reliability"] = t.reliability
        edge["category"] = t.category
        edge["smartness"] = edge_smartness(t)
        edge["note"] = t.note
        edge["profile"] = get_profile(profile).name


# ---------------------------------------------------------------------------
# Human-readable report of the scored edges.
# ---------------------------------------------------------------------------
def _short_name(full_name: str) -> str:
    """Trim 'ALICE@CORP.LOCAL' / 'FS01.CORP.LOCAL' down to just the label."""
    return full_name.split("@")[0].split(".")[0]


def print_scored_edges(graph, limit: int = 20) -> None:
    """Print every relationship with its technique + scores.

    Call AFTER annotate_graph(). Loudest steps are shown first so the
    risky ones stand out.
    """
    line = "=" * 72
    print("\n" + line)
    print(" PathHunter  -  scored relationships (technique intelligence)")
    print(line)

    header = f" {'STEP':<40}{'MITRE':<11}{'NOISE':<7}{'SMART':<6}"
    print(header)
    print(" " + "-" * (len(header) - 1))

    # Sort loudest-first (highest detection) so the dangerous edges lead.
    ranked = sorted(graph.edges, key=lambda e: e["detection"], reverse=True)
    for e in ranked[:limit]:
        src = _short_name(graph.nodes[e["source"]]["name"])
        dst = _short_name(graph.nodes[e["target"]]["name"])
        hop = f"{src} -{e['kind']}-> {dst}"
        if len(hop) > 39:                      # keep the columns aligned
            hop = hop[:36] + "..."
        print(f" {hop:<40}{e['mitre']:<11}{e['detection']:<7}{e['smartness']:<6}")

    print(line)
    print(" NOISE: 1 = silent .. 10 = very loud   |   SMART: 0 = bad .. 10 = ideal")
    print(line + "\n")
