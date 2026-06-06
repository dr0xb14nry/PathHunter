"""
Generate a dataset where the THREE objectives return DIFFERENT-LENGTH paths.
============================================================================

The point: show that "fewest hops" is NOT the same as "best". Here alice can
reach daadmin three ways, and each objective prefers a different one:

  FAST      4 hops  -- short but LOUD   (AdminTo + HasSession, det 5/9)
  RELIABLE  6 hops  -- medium, SOLID    (ForceChangePassword/AddMember, rel .95)
  STEALTH   9 hops  -- long but QUIET   (GpLink, det 2 -> total noise 18 < 21 < 28)

Cost maths (matches scoring.py):
  fast     = #hops                  -> 4  < 6  < 9     -> picks the 4-hop route
  stealth  = sum(detection)         -> 18 < 21 < 28    -> picks the 9-hop route
  reliable = sum((1-rel)*10 + .3)   -> 4.8 < 6.2 < 20.7 -> picks the 6-hop route

Every hop is built as an ACE edge (PrincipalSID -> object, RightName = the edge
kind), so we control the technique -- and therefore the detection/reliability --
of each individual step. It's a synthetic scoring test, not a realistic domain.

    python scripts/generate_longpaths.py            # -> data/longpaths
    python -m pathhunter --data data/longpaths --start alice --target daadmin
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

BASE = "S-1-5-21-7001-7002-7003"
DOMAIN = "CORP.LOCAL"
ALICE, DA, DAGRP = 1000, 500, 512


def sid(rid) -> str:
    return f"{BASE}-{rid}"


def ace(rid, right, ptype="User"):
    return {"PrincipalSID": sid(rid), "PrincipalType": ptype, "RightName": right, "IsInherited": False}


def build():
    names = {ALICE: "ALICE", DA: "DAADMIN"}
    edges = []   # (src_rid, dst_rid, kind)

    def route(prefix: str, base_rid: int, kinds: list[str]) -> None:
        """Lay a chain alice -> <prefix1..> -> daadmin using the given edge kinds."""
        prev = ALICE
        for i, kind in enumerate(kinds):
            last = i == len(kinds) - 1
            dst = DA if last else base_rid + i
            if not last:
                names[dst] = f"{prefix}{i + 1}"
            edges.append((prev, dst, kind))
            prev = dst

    # FAST: 4 loud hops (fewest hops -> wins "fastest")
    route("F", 1100, ["AdminTo", "HasSession", "AdminTo", "HasSession"])
    # RELIABLE: 6 solid hops (rel 0.95 -> wins "most reliable")
    route("R", 1200, ["ForceChangePassword", "AddMember", "AddSelf",
                      "ForceChangePassword", "AddMember", "ForceChangePassword"])
    # STEALTH: 9 quiet hops (det 2 -> lowest total noise -> wins "stealthiest")
    route("T", 1300, ["GpLink"] * 9)

    # Group every ACE by the object it sits on (the destination of the edge).
    aces_on = {}
    for src, dst, kind in edges:
        aces_on.setdefault(dst, []).append(ace(src, kind))

    users = []
    for rid, name in names.items():
        users.append({
            "Properties": {"name": f"{name}@{DOMAIN}", "domain": DOMAIN,
                           "objectid": sid(rid), "enabled": True},
            "ObjectIdentifier": sid(rid),
            "Aces": aces_on.get(rid, []),
        })
    groups = [{
        "Properties": {"name": f"DOMAIN ADMINS@{DOMAIN}", "domain": DOMAIN, "objectid": sid(DAGRP)},
        "ObjectIdentifier": sid(DAGRP), "Aces": [],
        "Members": [{"ObjectIdentifier": sid(DA), "ObjectType": "User"}],
    }]
    domains = [{"Properties": {"name": DOMAIN, "domain": DOMAIN, "objectid": BASE},
                "ObjectIdentifier": BASE, "Aces": []}]
    return {"users": users, "groups": groups, "domains": domains}


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Generate a different-length-paths demo dataset.")
    ap.add_argument("--out", default="data/longpaths")
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for kind, data in build().items():
        doc = {"data": data, "meta": {"type": kind, "count": len(data), "version": 5}}
        (out / f"corp_{kind}.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"Wrote different-length-paths dataset to {out.resolve()}")
    print("Expect: fast=4 hops, reliable=6 hops, stealth=9 hops.")
    print("Try:  python -m pathhunter --data", args.out, "--start alice --target daadmin")


if __name__ == "__main__":
    main()
