"""
Refresh the technique knowledge base from the internet.
=======================================================

PathHunter's scores live in pathhunter/techniques.py. This script keeps that
knowledge base honest by pulling two public datasets and parsing them in:

  1. MITRE ATT&CK (Enterprise)  -- the official STIX bundle. We verify every
     MITRE id used in our KB and pull its canonical technique name + URL.
  2. BloodHound CE edge index   -- the docs `llms.txt`, which lists a page per
     edge. We parse the edge names and report which ones our KB is missing,
     so coverage tracks BloodHound as new edges land.

The result is written to  data/generated/technique_intel.json  and a short
coverage report is printed. Nothing here changes techniques.py automatically
(scores are a judgement call) -- it gives you the verified, sourced data to
update it from.

Zero dependencies: only the Python standard library (urllib + json).

Usage:
    python scripts/fetch_techniques.py                 # fetch + write + report
    python scripts/fetch_techniques.py --offline       # report from local KB only
    python scripts/fetch_techniques.py --out data/generated/intel.json
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

# Make `import pathhunter` work when run as a plain script from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pathhunter.techniques import TECHNIQUES, CATEGORIES, SOURCES  # noqa: E402

# Official, stable public sources.
MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
BLOODHOUND_LLMS_URL = "https://bloodhound.specterops.io/llms.txt"

USER_AGENT = "PathHunter-fetch/1.0 (+https://github.com/)"
TIMEOUT = 60


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read()


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------
def fetch_mitre() -> dict[str, dict]:
    """Return {technique_id: {"name":..., "url":...}} from the MITRE STIX bundle."""
    print(f"[fetch] MITRE ATT&CK STIX  <- {MITRE_STIX_URL}")
    bundle = json.loads(_get(MITRE_STIX_URL))
    out: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked"):
            continue
        ext = next((r for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not ext or not ext.get("external_id"):
            continue
        out[ext["external_id"]] = {"name": obj.get("name", ""),
                                   "url": ext.get("url", "")}
    print(f"[fetch] parsed {len(out)} ATT&CK techniques")
    return out


# ---------------------------------------------------------------------------
# BloodHound edge index
# ---------------------------------------------------------------------------
def fetch_bloodhound_edges() -> set[str]:
    """Return the set of edge 'kinds' BloodHound documents, from llms.txt.

    The index lists URLs like .../resources/edges/adcs-esc1 ; we turn the slug
    back into the canonical edge kind (adcs-esc1 -> ADCSESC1, write-dacl ->
    WriteDacl) on a best-effort basis for the coverage report.
    """
    print(f"[fetch] BloodHound edge index  <- {BLOODHOUND_LLMS_URL}")
    text = _get(BLOODHOUND_LLMS_URL).decode("utf-8", "replace")
    slugs = set()
    for line in text.splitlines():
        marker = "/resources/edges/"
        if marker in line:
            slug = line.split(marker, 1)[1].split(")", 1)[0].split()[0].strip("/ ")
            if slug and slug != "overview" and "traversable" not in slug:
                slugs.add(slug)
    print(f"[fetch] found {len(slugs)} documented edge slugs")
    return slugs


def _slug_to_kind(slug: str) -> str:
    """Best-effort slug -> edge kind (for fuzzy coverage matching only)."""
    return slug.replace("-", "").lower()


def verify_sources() -> dict[str, str]:
    """HEAD each canonical source URL so the KB's references stay live.

    Returns {name: status} where status is "ok (<code>)" or an error string.
    """
    print("[verify] checking reference sources are reachable")
    status: dict[str, str] = {}
    for name, url in SOURCES.items():
        try:
            req = urllib.request.Request(url, method="HEAD",
                                         headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=20) as resp:
                status[name] = f"ok ({resp.status})"
        except Exception as exc:  # noqa: BLE001 - report, don't fail
            status[name] = f"unreachable: {exc}"
        print(f"   {name:<20} {status[name]}")
    return status


# ---------------------------------------------------------------------------
# Report + write-out
# ---------------------------------------------------------------------------
def build_intel(mitre: dict[str, dict], edge_slugs: set[str],
                sources: dict[str, str]) -> dict:
    entries = []
    mitre_misses = []
    no_refs, no_opsec, no_remediation = [], [], []
    for kind, t in sorted(TECHNIQUES.items()):
        official = mitre.get(t.mitre)
        if t.mitre not in ("-", "") and official is None:
            mitre_misses.append((kind, t.mitre))
        if not t.references:
            no_refs.append(kind)
        if not t.opsec:
            no_opsec.append(kind)
        if not t.remediation:
            no_remediation.append(kind)
        entries.append({
            "edge": kind,
            "technique": t.name,
            "mitre_id": t.mitre,
            "mitre_name": (official or {}).get("name", ""),
            "mitre_url": (official or {}).get("url", ""),
            "detection": t.detection,
            "reliability": t.reliability,
            "category": t.category,
            "note": t.note,
            "opsec": t.opsec,
            "remediation": t.remediation,
            "references": list(t.references),
        })

    # Which documented BloodHound edges are NOT in our KB yet?
    kb_norm = {k.replace("-", "").lower() for k in TECHNIQUES}
    missing_edges = sorted(s for s in edge_slugs if _slug_to_kind(s) not in kb_norm)

    return {
        "source": {"mitre": MITRE_STIX_URL, "bloodhound": BLOODHOUND_LLMS_URL,
                   "references": SOURCES},
        "source_status": sources,
        "kb_edges": len(TECHNIQUES),
        "categories": list(CATEGORIES),
        "entries": entries,
        "coverage": {
            "documented_edges": len(edge_slugs),
            "missing_from_kb": missing_edges,
            "mitre_ids_not_verified": [m for _, m in mitre_misses],
            "edges_without_references": no_refs,
            "edges_without_opsec": no_opsec,
            "edges_without_remediation": no_remediation,
        },
    }


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="data/technique_intel.json")
    ap.add_argument("--offline", action="store_true",
                    help="don't hit the network; report from the local KB only")
    args = ap.parse_args(argv)

    mitre: dict[str, dict] = {}
    edges: set[str] = set()
    sources: dict[str, str] = {}
    if not args.offline:
        try:
            mitre = fetch_mitre()
        except Exception as exc:
            print(f"[warn] MITRE fetch failed ({exc}); continuing offline.",
                  file=sys.stderr)
        try:
            edges = fetch_bloodhound_edges()
        except Exception as exc:
            print(f"[warn] BloodHound fetch failed ({exc}); continuing.",
                  file=sys.stderr)
        try:
            sources = verify_sources()
        except Exception as exc:
            print(f"[warn] source verification failed ({exc}); continuing.",
                  file=sys.stderr)

    intel = build_intel(mitre, edges, sources)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(intel, indent=2), encoding="utf-8")

    cov = intel["coverage"]
    print("\n=== coverage report ===")
    print(f" KB edges:                {intel['kb_edges']}")
    print(f" Edges w/o references:    {len(cov['edges_without_references'])}")
    print(f" Edges w/o OPSEC:         {len(cov['edges_without_opsec'])}")
    print(f" Edges w/o remediation:   {len(cov['edges_without_remediation'])}")
    print(f" Documented edges seen:   {cov['documented_edges']}")
    if cov["mitre_ids_not_verified"]:
        print(f" MITRE ids NOT verified:  {sorted(set(cov['mitre_ids_not_verified']))}")
    else:
        print(" MITRE ids:               all verified against ATT&CK"
              if mitre else " MITRE ids:               (skipped/offline)")
    if cov["missing_from_kb"]:
        print(f" BloodHound edges missing from KB ({len(cov['missing_from_kb'])}):")
        for slug in cov["missing_from_kb"]:
            print(f"   - {slug}")
    elif edges:
        print(" BloodHound edges:        KB covers all documented edges")
    print(f"\n wrote {out.resolve()}")


if __name__ == "__main__":
    main()
