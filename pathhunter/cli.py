"""
Command-line interface
=======================

Turns PathHunter into a real tool you can run during an engagement:

    # rank every objective from a user to Domain Admin
    python -m pathhunter --start alice --target daadmin

    # only the quietest route, against your own BloodHound export
    python -m pathhunter --data ./bloodhound_export --start bob --target "domain admins" --mode stealth

    # just describe the data you loaded
    python -m pathhunter --summary

With no --start/--target it simply summarises the loaded graph.
Uses only the Python standard library (argparse) — still zero-dependency.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .loader import load_bloodhound
from .scoring import annotate_graph, print_scored_edges
from .pathfinder import analyze
from .profiles import list_profiles

# The bundled sample lives at  <project root>/data/sample
# (two levels up from this file: pathhunter/cli.py -> root)
DEFAULT_DATA = Path(__file__).resolve().parent.parent / "data" / "sample"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pathhunter",
        description="Rank Active Directory attack paths from BloodHound data "
                    "by fastest / stealthiest / most reliable.",
    )
    p.add_argument("--data", default=str(DEFAULT_DATA),
                   help="folder of BloodHound JSON files (default: bundled sample)")
    p.add_argument("--start", help="start principal, e.g. alice")
    p.add_argument("--target", help="target principal, e.g. 'domain admins'")
    p.add_argument("--mode", choices=["fast", "stealth", "reliable", "all"],
                   default="all", help="which objective(s) to rank (default: all)")
    p.add_argument("--profile", choices=list_profiles(), default="default",
                   help="environment profile that shifts scoring to the "
                        "situation (e.g. 'edr', 'legacy', 'audited')")
    p.add_argument("--summary", action="store_true",
                   help="print a summary of the loaded graph")
    p.add_argument("--edges", action="store_true",
                   help="print every relationship with its technique + scores")
    return p


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)

    graph = load_bloodhound(args.data)
    annotate_graph(graph, profile=args.profile)

    if args.summary:
        graph.summary()
    if args.edges:
        print_scored_edges(graph)

    if args.start and args.target:
        modes = None if args.mode == "all" else [args.mode]
        analyze(graph, args.start, args.target, modes=modes, profile=args.profile)
    elif not (args.summary or args.edges):
        # Nothing specific was asked for -> show a friendly default.
        graph.summary()
        print("Tip: add  --start alice --target daadmin  to rank attack paths.\n")


if __name__ == "__main__":
    main()
