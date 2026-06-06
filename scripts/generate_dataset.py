"""
Generate a larger, realistic BloodHound-format dataset for testing.
====================================================================

Think of this as a tiny offline "BadBlood": it fills a fake domain with many
users, groups, and computers plus realistic relationships, AND embeds a known
multi-step attack path to Domain Admin -- so you can verify PathHunter on a
big, noisy graph instead of just the 14-node demo.

Usage:
    python scripts/generate_dataset.py --out data/generated --users 60 --computers 25
    python -m pathhunter --data data/generated --start alice --target daadmin
    python -m pathhunter.web --data data/generated      # view it in the dashboard

The output is the same BloodHound CE JSON format SharpHound produces, so the
exact same loader handles it -- which is the whole point: real exports just
work via  --data <folder>.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

BASE = "S-1-5-21-1111111111-2222222222-3333333333"
DOMAIN = "CORP.LOCAL"


def sid(rid: int) -> str:
    return f"{BASE}-{rid}"


def user_obj(rid, name, aces=None, spn=False):
    return {
        "Properties": {"name": f"{name}@{DOMAIN}", "domain": DOMAIN,
                       "objectid": sid(rid), "enabled": True, "hasspn": spn},
        "ObjectIdentifier": sid(rid),
        "Aces": aces or [],
    }


def group_obj(rid, name, members, aces=None):
    return {
        "Properties": {"name": f"{name}@{DOMAIN}", "domain": DOMAIN, "objectid": sid(rid)},
        "ObjectIdentifier": sid(rid),
        "Aces": aces or [],
        "Members": [{"ObjectIdentifier": sid(r), "ObjectType": t} for r, t in members],
    }


def computer_obj(rid, name, admins=None, sessions=None, aces=None):
    return {
        "Properties": {"name": f"{name}.{DOMAIN}", "domain": DOMAIN, "objectid": sid(rid)},
        "ObjectIdentifier": sid(rid),
        "Aces": aces or [],
        "LocalAdmins": {"Collected": True,
                        "Results": [{"ObjectIdentifier": sid(r), "ObjectType": t} for r, t in (admins or [])]},
        "Sessions": {"Collected": True,
                     "Results": [{"UserSID": sid(u), "ComputerSID": sid(rid)} for u in (sessions or [])]},
    }


def ace(principal_rid, right, ptype="Group"):
    return {"PrincipalSID": sid(principal_rid), "PrincipalType": ptype,
            "RightName": right, "IsInherited": False}


def generate(n_users: int, n_computers: int, seed: int):
    rnd = random.Random(seed)

    # ----- fixed RIDs for the named / golden entities -----
    DA_GROUP = 512            # DOMAIN ADMINS
    DAADMIN = 500             # the Domain Admin user
    ALICE = 1100
    SVC_BACKUP = 1201
    SERVER01 = 1401
    DEPTS = {"HELPDESK": 1300, "IT-ADMINS": 1301, "SERVER-ADMINS": 1302,
             "WORKSTATION-ADMINS": 1303, "HR": 1304, "FINANCE": 1305, "DEVELOPERS": 1306}

    users, groups, computers = [], [], []

    # ---------- the GOLDEN path (guaranteed to exist) ----------
    # FAST+LOUD : alice --AdminTo--> SERVER01 --HasSession--> DAADMIN          (2 hops, noisy)
    # STEALTH   : alice --MemberOf--> HELPDESK --MemberOf--> IT-ADMINS
    #                   --GenericAll--> DAADMIN                                 (3 hops, quiet)
    users.append(user_obj(DAADMIN, "DAADMIN",
                           aces=[ace(DEPTS["IT-ADMINS"], "GenericAll")]))   # IT-ADMINS owns DA (misconfig)
    users.append(user_obj(ALICE, "ALICE"))
    users.append(user_obj(SVC_BACKUP, "SVC_BACKUP", spn=True,
                          aces=[ace(DEPTS["HELPDESK"], "ForceChangePassword")]))

    # ---------- random employees ----------
    dept_members = {d: [] for d in DEPTS}
    dept_members["HELPDESK"].append((ALICE, "User"))
    next_rid = 2000
    spn_users = []
    for i in range(n_users):
        r = next_rid; next_rid += 1
        is_svc = (i % 19 == 0)
        name = f"SVC_{i:03d}" if is_svc else f"USER{i:03d}"
        users.append(user_obj(r, name, spn=is_svc))
        if is_svc:
            spn_users.append(r)
        dept_members[rnd.choice(list(DEPTS))].append((r, "User"))

    # ---------- groups ----------
    groups.append(group_obj(DA_GROUP, "DOMAIN ADMINS", [(DAADMIN, "User")]))
    # nested: HELPDESK -> IT-ADMINS  (gives alice the stealth route)
    dept_members["IT-ADMINS"].append((DEPTS["HELPDESK"], "Group"))
    for name, rid in DEPTS.items():
        groups.append(group_obj(rid, name, dept_members[name]))

    # ---------- computers ----------
    # SERVER01 is the pivot: alice is local admin, a DA has a session here.
    computers.append(computer_obj(
        SERVER01, "SERVER01",
        admins=[(SVC_BACKUP, "User"), (ALICE, "User"), (DEPTS["SERVER-ADMINS"], "Group")],
        sessions=[DAADMIN],
    ))
    # DC + more servers + workstations (random admins/sessions = noise)
    computers.append(computer_obj(1400, "DC01"))
    server_rids = [SERVER01]
    next_crid = 1402
    all_user_rids = [u["ObjectIdentifier"] for u in users]
    for i in range(n_computers):
        r = next_crid; next_crid += 1
        is_server = (i % 4 == 0)
        name = f"SERVER{i:02d}" if is_server else f"WKSTN{i:02d}"
        admin_grp = DEPTS["SERVER-ADMINS"] if is_server else DEPTS["WORKSTATION-ADMINS"]
        # a random ordinary user is sometimes logged in (noise, never the DA)
        sess = []
        if rnd.random() < 0.4:
            ru = rnd.choice([2000 + k for k in range(n_users)])
            sess = [ru]
        computers.append(computer_obj(r, name, admins=[(admin_grp, "Group")], sessions=sess))
        if is_server:
            server_rids.append(r)

    # ---------- domain (DCSync handed to a random service account = noise) ----------
    dcsync = ace(rnd.choice(spn_users or [SVC_BACKUP]), "GetChanges", ptype="User")
    dcsync_all = {"PrincipalSID": dcsync["PrincipalSID"], "PrincipalType": "User",
                  "RightName": "GetChangesAll", "IsInherited": False}
    domains = [{
        "Properties": {"name": DOMAIN, "domain": DOMAIN, "objectid": BASE},
        "ObjectIdentifier": BASE,
        "Aces": [dcsync, dcsync_all],
    }]

    return {
        "users": users,
        "groups": groups,
        "computers": computers,
        "domains": domains,
    }


def write(dataset: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for kind, data in dataset.items():
        doc = {"data": data, "meta": {"type": kind, "count": len(data), "version": 5}}
        (out_dir / f"corp_{kind}.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Generate a realistic BloodHound-format test dataset.")
    ap.add_argument("--out", default="data/generated", help="output folder")
    ap.add_argument("--users", type=int, default=60)
    ap.add_argument("--computers", type=int, default=25)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args(argv)

    dataset = generate(args.users, args.computers, args.seed)
    out = Path(args.out)
    write(dataset, out)
    n = sum(len(v) for v in dataset.values())
    print(f"Generated {n} objects "
          f"({len(dataset['users'])} users, {len(dataset['groups'])} groups, "
          f"{len(dataset['computers'])} computers) into {out.resolve()}")
    print("Try:  python -m pathhunter --data", args.out, "--start alice --target daadmin")


if __name__ == "__main__":
    main()
