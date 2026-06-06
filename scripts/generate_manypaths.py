"""
Generate a demo dataset with MANY attack paths to Domain Admin.
===============================================================

Builds a small BloodHound-format domain where `alice` can reach the Domain
Admin account `daadmin` through **12 distinct routes**, so PathHunter can show
off distilling many paths down to the smartest 3 (fast / stealthy / reliable).

    python scripts/generate_manypaths.py            # -> data/manypaths
    python -m pathhunter --data data/manypaths --start alice --target daadmin

The 12 routes:
  * 1  short + LOUD  : alice -AdminTo-> SERVER01 -HasSession-> daadmin
  * 10 medium        : alice -> HELPDESK -GenericAll-> svcNN -GenericAll-> daadmin
  * 1  quiet         : alice -> HELPDESK -> IT-ADMINS -GenericAll-> daadmin
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

BASE = "S-1-5-21-9001-9002-9003"
DOMAIN = "CORP.LOCAL"


def sid(rid) -> str:
    return f"{BASE}-{rid}"


def ace(rid, right, ptype="User"):
    return {"PrincipalSID": sid(rid), "PrincipalType": ptype, "RightName": right, "IsInherited": False}


def user(rid, name, aces=None, spn=False):
    return {"Properties": {"name": f"{name}@{DOMAIN}", "domain": DOMAIN, "objectid": sid(rid),
                           "enabled": True, "hasspn": spn},
            "ObjectIdentifier": sid(rid), "Aces": aces or []}


def group(rid, name, members, aces=None):
    return {"Properties": {"name": f"{name}@{DOMAIN}", "domain": DOMAIN, "objectid": sid(rid)},
            "ObjectIdentifier": sid(rid), "Aces": aces or [],
            "Members": [{"ObjectIdentifier": sid(m), "ObjectType": t} for m, t in members]}


def computer(rid, name, admins=None, sessions=None):
    return {"Properties": {"name": f"{name}.{DOMAIN}", "domain": DOMAIN, "objectid": sid(rid)},
            "ObjectIdentifier": sid(rid), "Aces": [],
            "LocalAdmins": {"Collected": True,
                            "Results": [{"ObjectIdentifier": sid(a), "ObjectType": t} for a, t in (admins or [])]},
            "Sessions": {"Collected": True,
                         "Results": [{"UserSID": sid(u), "ComputerSID": sid(rid)} for u in (sessions or [])]}}


def build():
    ALICE, DA, HELPDESK, ITADMINS, DAGRP, SERVER01 = 1100, 500, 1300, 1301, 512, 1400
    SVC = list(range(1200, 1210))   # svc01..svc10

    # DAADMIN is controlled by all 10 service accounts AND IT-ADMINS (GenericAll).
    da_aces = [ace(s, "GenericAll") for s in SVC] + [ace(ITADMINS, "GenericAll", "Group")]
    users = [user(ALICE, "ALICE"), user(DA, "DAADMIN", aces=da_aces)]
    for i, s in enumerate(SVC, 1):
        # each service account is controlled by HELPDESK (GenericAll)
        users.append(user(s, f"SVC{i:02d}", aces=[ace(HELPDESK, "GenericAll", "Group")], spn=True))

    groups = [
        group(HELPDESK, "HELPDESK", [(ALICE, "User")]),
        group(ITADMINS, "IT-ADMINS", [(HELPDESK, "Group")]),   # HELPDESK nested in IT-ADMINS
        group(DAGRP, "DOMAIN ADMINS", [(DA, "User")]),
    ]
    computers = [computer(SERVER01, "SERVER01", admins=[(ALICE, "User")], sessions=[DA])]
    domains = [{"Properties": {"name": DOMAIN, "domain": DOMAIN, "objectid": BASE},
                "ObjectIdentifier": BASE, "Aces": []}]
    return {"users": users, "groups": groups, "computers": computers, "domains": domains}


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Generate a many-paths demo dataset.")
    ap.add_argument("--out", default="data/manypaths")
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for kind, data in build().items():
        doc = {"data": data, "meta": {"type": kind, "count": len(data), "version": 5}}
        (out / f"corp_{kind}.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"Wrote many-paths dataset to {out.resolve()}")
    print("Try:  python -m pathhunter --data", args.out, "--start alice --target daadmin")


if __name__ == "__main__":
    main()
