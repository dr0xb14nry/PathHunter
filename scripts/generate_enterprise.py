"""
Generate a realistic 500+ asset enterprise with a LONG attack path.
===================================================================

Models a well-segmented company: real employee names, real departments, per
-department user/admin groups, workstations and servers -- and ONE deliberate,
tiered escalation chain so the *fastest* route to Domain Admin is 12 hops
(>= 10). The lesson: in a properly tiered estate there is no 2-hop win; the
only way up is a long, multi-tier chain.

    python scripts/generate_enterprise.py            # -> data/enterprise
    python -m pathhunter --data data/enterprise --start liam.walsh --target daadmin
    python -m pathhunter.web --data data/enterprise --open

Synthetic data for testing only.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

DOMAIN = "CORP.LOCAL"
BASE = "S-1-5-21-5500-5501-5502"

FIRST = ("james mary john patricia robert jennifer michael linda william elizabeth "
         "david barbara richard susan joseph jessica thomas sarah charles karen "
         "christopher nancy daniel lisa matthew betty anthony margaret mark sandra "
         "donald ashley steven kimberly paul emily andrew donna joshua michelle "
         "kenneth carol kevin amanda brian dorothy george melissa timothy deborah "
         "ronald stephanie jason rebecca edward sharon jeffrey laura ryan cynthia "
         "nicholas amy eric angela jacob shirley jonathan anna larry brenda").split()
LAST = ("smith johnson williams brown jones garcia miller davis rodriguez martinez "
        "hernandez lopez gonzalez wilson anderson thomas taylor moore jackson martin "
        "lee perez thompson white harris sanchez clark ramirez lewis robinson walker "
        "young allen king wright scott torres nguyen hill flores green adams nelson "
        "baker hall rivera campbell mitchell carter roberts gomez phillips evans").split()

DEPTS = ["Finance", "HumanResources", "IT", "Engineering", "Sales", "Marketing",
         "Legal", "Operations", "Security", "Support", "Procurement", "Research"]

# Names reserved for the escalation chain (kept out of the random pool).
RESERVED = {"liam.walsh", "olivia.bennett", "ethan.brooks", "robert.king"}


def sid(rid) -> str:
    return f"{BASE}-{rid}"


def ace(rid, right, ptype="User"):
    return {"PrincipalSID": sid(rid), "PrincipalType": ptype, "RightName": right, "IsInherited": False}


def user(rid, name, dept=None, aces=None):
    props = {"name": f"{name}@{DOMAIN}", "domain": DOMAIN, "objectid": sid(rid), "enabled": True}
    if dept:
        props["department"] = dept
    return {"Properties": props, "ObjectIdentifier": sid(rid), "Aces": aces or []}


def group(rid, name, members=None, aces=None):
    return {"Properties": {"name": f"{name}@{DOMAIN}", "domain": DOMAIN, "objectid": sid(rid)},
            "ObjectIdentifier": sid(rid), "Aces": aces or [],
            "Members": [{"ObjectIdentifier": sid(m), "ObjectType": t} for m, t in (members or [])]}


def computer(rid, name, admins=None, sessions=None):
    return {"Properties": {"name": f"{name}.{DOMAIN}", "domain": DOMAIN, "objectid": sid(rid)},
            "ObjectIdentifier": sid(rid), "Aces": [],
            "LocalAdmins": {"Collected": True,
                            "Results": [{"ObjectIdentifier": sid(a), "ObjectType": t} for a, t in (admins or [])]},
            "Sessions": {"Collected": True,
                         "Results": [{"UserSID": sid(u), "ComputerSID": sid(rid)} for u in (sessions or [])]}}


def build(n_users: int, seed: int):
    rnd = random.Random(seed)
    users, groups, computers = [], [], []
    rid = 2000

    # --- department groups (USERS + ADMINS per dept) ---
    dept_user_grp, dept_admin_grp, dept_members = {}, {}, {}
    for d in DEPTS:
        dept_user_grp[d] = rid;  groups_user_rid = rid; rid += 1
        dept_admin_grp[d] = rid; rid += 1
        dept_members[d] = []

    # --- random employees, assigned to a department ---
    used = set(RESERVED)
    dept_users = {d: [] for d in DEPTS}
    for _ in range(n_users):
        while True:
            name = f"{rnd.choice(FIRST)}.{rnd.choice(LAST)}"
            if name not in used:
                used.add(name); break
        d = rnd.choice(DEPTS)
        users.append(user(rid, name, dept=d))
        dept_members[d].append((rid, "User"))
        dept_users[d].append(rid)
        rid += 1

    # --- workstations per department; dept-ADMINS are local admins; a dept user is logged in ---
    for d in DEPTS:
        tag = d[:3].upper()
        for k in range(1, 6):                                  # 5 workstations / dept
            wks = rid; rid += 1
            sess = [rnd.choice(dept_users[d])] if dept_users[d] and rnd.random() < 0.6 else []
            computers.append(computer(wks, f"WKS-{tag}-{k:02d}",
                                      admins=[(dept_admin_grp[d], "Group")], sessions=sess))

    # --- a few generic servers (noise) ---
    for i in range(1, 9):
        computers.append(computer(rid, f"SRV-FILE-{i:02d}",
                                  admins=[(dept_admin_grp['IT'], "Group")])); rid += 1

    # --- build the department group objects (with their random members) ---
    for d in DEPTS:
        groups.append(group(dept_user_grp[d], f"{d.upper()}-USERS", members=dept_members[d]))
        # a couple of random users are department admins (harmless noise)
        admins = [(u, "User") for u in rnd.sample(dept_users[d], min(2, len(dept_users[d])))] if dept_users[d] else []
        groups.append(group(dept_admin_grp[d], f"{d.upper()}-ADMINS", members=admins))

    # =========================================================================
    # THE ESCALATION CHAIN (12 hops, the ONLY route to Domain Admin)
    # liam.walsh -> HELPDESK-OPERATORS -> svc-backup -> WKS-FIN-014 ->
    #   olivia.bennett -> FINANCE-ADMINS -> svc-sql -> SRV-APP-03 ->
    #   ethan.brooks -> SERVER-ADMINS -> svc-tier0 -> DC01 -> robert.king (DA)
    # =========================================================================
    LIAM, OLIVIA, ETHAN, DA = 1000, 1001, 1002, 500
    SVC_BACKUP, SVC_SQL, SVC_TIER0 = 1010, 1011, 1012
    HELPDESK, FIN_ADMINS, SRV_ADMINS, DAGRP = 1100, 1101, 1102, 512
    WKS_FIN, SRV_APP, DC01 = 1200, 1201, 1202

    users += [
        user(LIAM, "liam.walsh", dept="Support"),
        user(OLIVIA, "olivia.bennett", dept="Finance"),
        user(ETHAN, "ethan.brooks", dept="IT"),
        user(DA, "robert.king", dept="IT"),
        # service accounts (each controlled by the previous tier)
        user(SVC_BACKUP, "svc-backup", aces=[ace(HELPDESK, "ForceChangePassword", "Group")]),
        user(SVC_SQL, "svc-sql", aces=[ace(FIN_ADMINS, "GenericAll", "Group")]),
        user(SVC_TIER0, "svc-tier0", aces=[ace(SRV_ADMINS, "GenericAll", "Group")]),
    ]
    groups += [
        group(HELPDESK, "HELPDESK-OPERATORS", members=[(LIAM, "User")]),
        group(FIN_ADMINS, "FINANCE-ADMINS", members=[(OLIVIA, "User")]),
        group(SRV_ADMINS, "SERVER-ADMINS", members=[(ETHAN, "User")]),
        group(DAGRP, "DOMAIN ADMINS", members=[(DA, "User")]),
    ]
    computers += [
        computer(WKS_FIN, "WKS-FIN-014", admins=[(SVC_BACKUP, "User")], sessions=[OLIVIA]),
        computer(SRV_APP, "SRV-APP-03", admins=[(SVC_SQL, "User")], sessions=[ETHAN]),
        computer(DC01, "DC01", admins=[(SVC_TIER0, "User")], sessions=[DA]),
    ]

    domains = [{"Properties": {"name": DOMAIN, "domain": DOMAIN, "objectid": BASE},
                "ObjectIdentifier": BASE, "Aces": []}]
    return {"users": users, "groups": groups, "computers": computers, "domains": domains}


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Generate a realistic 500+ asset enterprise dataset.")
    ap.add_argument("--out", default="data/enterprise")
    ap.add_argument("--users", type=int, default=450)
    ap.add_argument("--seed", type=int, default=2024)
    args = ap.parse_args(argv)

    data = build(args.users, args.seed)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for kind, items in data.items():
        doc = {"data": items, "meta": {"type": kind, "count": len(items), "version": 5}}
        (out / f"corp_{kind}.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    total = sum(len(v) for v in data.values())
    print(f"Generated {total} assets ({len(data['users'])} users, {len(data['groups'])} groups, "
          f"{len(data['computers'])} computers) into {out.resolve()}")
    print("Escalation: liam.walsh (Support) ---12 hops---> robert.king (Domain Admin)")
    print("Try:  python -m pathhunter --data", args.out, "--start liam.walsh --target robert.king")


if __name__ == "__main__":
    main()
