"""
PathHunter — entry point (Phase 1)

Loads the bundled sample BloodHound data and prints a summary.

Run it from anywhere:
    python "B:\\Cybersecurity\\Projects\\Project AD\\main.py"
or, from inside the project folder:
    python main.py
"""

from pathlib import Path

from pathhunter.loader import load_bloodhound
from pathhunter.scoring import annotate_graph, print_scored_edges
from pathhunter.pathfinder import analyze

# The sample data ships next to this file, so we resolve the path
# relative to the script — it works no matter where you run it from.
SAMPLE_DATA = Path(__file__).parent / "data" / "sample"


def main() -> None:
    # Phase 1: parse BloodHound JSON into an in-memory graph and summarise it.
    graph = load_bloodhound(SAMPLE_DATA)
    graph.summary()

    # Phase 2: attach each edge's attack technique + risk/reliability scores,
    # then print the relationships ranked by how loud (detectable) they are.
    annotate_graph(graph)
    print_scored_edges(graph)

    # Phase 3: find and rank the best attack paths from a normal user to
    # Domain Admin under each objective (fastest / stealthiest / most reliable).
    analyze(graph, "alice", "daadmin")


if __name__ == "__main__":
    main()
