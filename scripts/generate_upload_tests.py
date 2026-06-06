"""
Generate 3 ready-to-upload test cases under data/upload_tests/.
==============================================================

Each subfolder is a complete BloodHound-format mini-domain you can drag into
the dashboard's Upload page to verify how PathHunter handles a different
scenario. They are deliberately small so the upload, parsing and rendering
are instant -- great for manual smoke tests.

  1. basic/        ~6 nodes   single 4-hop attack chain (sanity test)
  2. multi_path/  ~14 nodes  three different routes to DA (fast / stealth / reliable diverge)
  3. enterprise/  ~30 nodes  realistic 8-hop tiered escalation (small enterprise)

    python scripts/generate_upload_tests.py
    # then upload data/upload_tests/<case>/*.json via http://localhost:8000/upload
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


BASE = "S-1-5-21-9001-9002-9003"
DOMAIN = "CORP.LOCAL"


# --------------------------------------------------------------------------- #
# BloodHound-format builders
# --------------------------------------------------------------------------- #
def sid(rid) -> str:
    return f"{BASE}-{rid}"


def ace(rid, right, ptype="User"):
    return {"PrincipalSID": sid(rid), "PrincipalType": ptype,
            "RightName": right, "IsInherited": False}


def user(rid, name, aces=None, spn=False):
    return {"Properties": {"name": f"{name}@{DOMAIN}", "domain": DOMAIN,
                           "objectid": sid(rid), "enabled": True, "hasspn": spn},
            "ObjectIdentifier": sid(rid), "Aces": aces or []}


def group(rid, name, members=(), aces=None):
    return {"Properties": {"name": f"{name}@{DOMAIN}", "domain": DOMAIN, "objectid": sid(rid)},
            "ObjectIdentifier": sid(rid), "Aces": aces or [],
            "Members": [{"ObjectIdentifier": sid(m), "ObjectType": t} for m, t in members]}


def computer(rid, name, admins=None, sessions=None):
    return {"Properties": {"name": f"{name}.{DOMAIN}", "domain": DOMAIN, "objectid": sid(rid)},
            "ObjectIdentifier": sid(rid), "Aces": [],
            "LocalAdmins": {"Collected": True,
                            "Results": [{"ObjectIdentifier": sid(a), "ObjectType": t}
                                        for a, t in (admins or [])]},
            "Sessions": {"Collected": True,
                         "Results": [{"UserSID": sid(u), "ComputerSID": sid(rid)}
                                     for u in (sessions or [])]}}


def domain_obj():
    return {"Properties": {"name": DOMAIN, "domain": DOMAIN, "objectid": BASE},
            "ObjectIdentifier": BASE, "Aces": []}


# --------------------------------------------------------------------------- #
# Case 1: BASIC -- one straight 4-hop attack chain
# --------------------------------------------------------------------------- #
def case_basic():
    HELP, DA_GRP = 1300, 512
    return {
        "users": [
            user(1100, "alice"),
            user(500, "daadmin"),
            user(1200, "svc-backup",
                 aces=[ace(HELP, "ForceChangePassword", "Group")]),
        ],
        "groups": [
            group(HELP, "HELPDESK", members=[(1100, "User")]),
            group(DA_GRP, "DOMAIN ADMINS", members=[(500, "User")]),
        ],
        "computers": [
            computer(1400, "FILESERVER", admins=[(1200, "User")], sessions=[500]),
        ],
        "domains": [domain_obj()],
    }


# --------------------------------------------------------------------------- #
# Case 2: MULTI_PATH -- three distinct routes so the 3 objectives diverge
# --------------------------------------------------------------------------- #
def case_multi_path():
    HELP, IT, FIN, DA_GRP = 1300, 1301, 1302, 512
    DA = 500
    return {
        "users": [
            user(1100, "alice"),
            user(DA, "daadmin",
                 aces=[ace(IT, "GenericAll", "Group")]),       # stealth route ends here
            # Loud fast route
            # (alice is local admin on SERVER01, a DA session is there)
            # Reliable route service account
            user(1200, "svc-backup",
                 aces=[ace(FIN, "ForceChangePassword", "Group")]),
        ],
        "groups": [
            group(HELP, "HELPDESK", members=[(1100, "User")]),
            group(IT, "IT-ADMINS", members=[(HELP, "Group")]),  # nested
            group(FIN, "FINANCE-ADMINS", members=[(1100, "User")]),
            group(DA_GRP, "DOMAIN ADMINS", members=[(DA, "User")]),
        ],
        "computers": [
            # Fast (loud): alice is local admin AND a DA session exists here -> 2 hops
            computer(1400, "SERVER01", admins=[(1100, "User")], sessions=[DA]),
            # Reliable route via svc-backup admin on this server
            computer(1401, "SERVER02", admins=[(1200, "User")], sessions=[DA]),
        ],
        "domains": [domain_obj()],
    }


# --------------------------------------------------------------------------- #
# Case 3: ENTERPRISE -- realistic 8-hop tiered escalation with departments
# --------------------------------------------------------------------------- #
def case_enterprise():
    HELP, FIN, SRV, DA_GRP = 1300, 1301, 1302, 512
    DA = 500
    return {
        "users": [
            # The escalation chain
            user(1100, "liam.walsh"),
            user(1101, "olivia.bennett"),                # mid-tier finance employee
            user(1102, "ethan.brooks"),                  # tier-1 server admin
            user(DA, "robert.king"),                     # Domain Admin
            user(1200, "svc-backup",
                 aces=[ace(HELP, "ForceChangePassword", "Group")]),
            user(1201, "svc-sql",
                 aces=[ace(FIN, "GenericAll", "Group")]),
            user(1202, "svc-tier0",
                 aces=[ace(SRV, "GenericAll", "Group")]),
            # Some random noise employees
            user(2001, "james.smith"),
            user(2002, "mary.johnson"),
            user(2003, "david.brown"),
            user(2004, "sarah.davis"),
            user(2005, "michael.garcia"),
            user(2006, "linda.miller"),
            user(2007, "emily.wilson"),
            user(2008, "thomas.moore"),
        ],
        "groups": [
            group(HELP, "HELPDESK-OPERATORS", members=[(1100, "User")]),
            group(FIN, "FINANCE-ADMINS", members=[(1101, "User")]),
            group(SRV, "SERVER-ADMINS", members=[(1102, "User")]),
            group(DA_GRP, "DOMAIN ADMINS", members=[(DA, "User")]),
            # Departmental groups (noise)
            group(1310, "FINANCE-USERS",
                  members=[(2001, "User"), (2002, "User"), (2003, "User")]),
            group(1311, "ENGINEERING-USERS",
                  members=[(2004, "User"), (2005, "User"), (2006, "User")]),
            group(1312, "SALES-USERS",
                  members=[(2007, "User"), (2008, "User")]),
        ],
        "computers": [
            # The ladder
            computer(1400, "WKS-FIN-014", admins=[(1200, "User")], sessions=[1101]),
            computer(1401, "SRV-APP-03", admins=[(1201, "User")], sessions=[1102]),
            computer(1402, "DC01", admins=[(1202, "User")], sessions=[DA]),
            # Random workstations (noise)
            computer(1403, "WKS-FIN-01"),
            computer(1404, "WKS-FIN-02"),
            computer(1405, "WKS-ENG-01"),
            computer(1406, "WKS-ENG-02"),
            computer(1407, "WKS-SAL-01"),
        ],
        "domains": [domain_obj()],
    }


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
CASES = {
    "basic": (case_basic,        "Sanity test  -- one straight 4-hop attack chain"),
    "multi_path": (case_multi_path, "Three different routes so fast/stealth/reliable diverge"),
    "enterprise": (case_enterprise, "Realistic 8-hop tiered escalation through departments"),
}


def write_case(out_dir: Path, name: str, builder, summary: str) -> int:
    folder = out_dir / name
    folder.mkdir(parents=True, exist_ok=True)
    data = builder()
    total = sum(len(v) for v in data.values())
    for kind, items in data.items():
        doc = {"data": items, "meta": {"type": kind, "count": len(items), "version": 5}}
        (folder / f"corp_{kind}.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"  {name:<13} {total:>3} objects   ({summary})")
    return total


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Generate 3 upload-test datasets.")
    ap.add_argument("--out", default="data/upload_tests")
    args = ap.parse_args(argv)
    out = Path(args.out)
    print(f"Writing test cases into {out.resolve()}:")
    for name, (builder, summary) in CASES.items():
        write_case(out, name, builder, summary)
    print()
    print("Upload these via http://localhost:8000/upload  -- drag the JSON files of any case.")


if __name__ == "__main__":
    main()
