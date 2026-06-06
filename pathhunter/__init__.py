"""PathHunter — intelligent AD attack-path prioritization engine.

A lightweight, open-source companion to BloodHound. It reads the JSON
your team already collects with SharpHound/BloodHound and ranks attack
paths by how *smart* they are (fast / stealthy / reliable) — not just
the shortest one.

v1 design goals:
  * Zero dependencies (pure Python standard library)
  * In-memory graph — no database server, tiny RAM footprint
  * Single command to run during an engagement
"""

__version__ = "0.1.0"
