"""
Fetch a REAL BloodHound dataset to test PathHunter against.
===========================================================

Downloads the community GOAD v2 sample data (BloodHound CE format) published by
m4lwhere and extracts the JSON, so you can point PathHunter at genuine
SharpHound / bloodhound.py output instead of only the bundled samples:

    python scripts/fetch_real_data.py                       # -> data/goad
    python -m pathhunter --data data/goad --start vagrant --target "domain admins"
    python -m pathhunter.web --data data/goad --open        # explore in the dashboard

Source (collected Apr 2024, SharpHound 2.3.3 / bloodhound.py CE branch):
    https://github.com/m4lwhere/Bloodhound-CE-Sample-Data

The data is NOT redistributed in this repo (it carries its own LICENSE); we
fetch it on demand. For authorized testing / learning only.

Pure standard library -- needs `git` on PATH (same as the rest of the tool).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

REPO = "https://github.com/m4lwhere/Bloodhound-CE-Sample-Data"


def fetch(out_dir: Path) -> int:
    """Clone the sample repo, extract the forest JSON into out_dir, return count."""
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="goad_"))
    try:
        subprocess.run(["git", "clone", "--depth", "1", REPO, str(tmp)],
                       check=True, capture_output=True, text=True)
        # The bloodhound.py CE zips together hold the full forest (3 domains).
        zips = sorted(tmp.glob("ce_branch_bloodhoundpy_*.zip"))
        if not zips:
            raise SystemExit("no sample zips found in the cloned repo")
        files = 0
        for z in zips:
            with zipfile.ZipFile(z) as zf:
                for name in zf.namelist():
                    if name.lower().endswith(".json"):
                        zf.extract(name, out_dir)
                        files += 1
        return files
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Fetch real GOAD BloodHound data for testing.")
    ap.add_argument("--out", default="data/goad", help="output folder (default: data/goad)")
    args = ap.parse_args(argv)
    out = Path(args.out)
    n = fetch(out)
    print(f"Fetched {n} JSON files into {out.resolve()}")
    print(f"Source: {REPO}  (GOAD v2, BloodHound CE format)")
    print("Try:  python -m pathhunter --data", args.out, "--start vagrant --target 'domain admins'")


if __name__ == "__main__":
    main()
