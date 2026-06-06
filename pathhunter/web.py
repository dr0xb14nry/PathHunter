"""
Zero-dependency web dashboard  (Phase B)
========================================

A small web UI for PathHunter, served by Python's *standard library*
http.server -- no FastAPI, no pip install, works offline on an engagement
box. It serves the dashboard page plus two JSON endpoints backed by the
real engine.

Run it:
    python -m pathhunter.web --data ./bloodhound_export --port 8000
then open  http://localhost:8000

Endpoints:
    GET /                              -> the dashboard (web/index.html)
    GET /api/graph                     -> {nodes, edges} for the whole graph
    GET /api/paths?start=&target=&mode=  -> ranked attack paths
"""

from __future__ import annotations

import argparse
import json
import shutil
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from .loader import load_bloodhound
from .scoring import annotate_graph
from .pathfinder import find_path, resolve, OBJECTIVES, count_paths
from .profiles import get_profile_technique, list_profiles

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"
DEFAULT_DATA = ROOT / "data" / "sample"
# Where browser-uploaded BloodHound JSON is written before (re)loading.
UPLOAD_DIR = ROOT / "data" / "_uploads"

# The loaded graph is held here once, at startup (and replaced on upload).
GRAPH = None


def load_graph(folder) -> None:
    """(Re)load the global graph from a folder of BloodHound JSON."""
    global GRAPH
    g = load_bloodhound(folder)
    annotate_graph(g)
    GRAPH = g


def save_and_load_upload(files) -> dict:
    """Write uploaded {name, content} files to UPLOAD_DIR and reload the graph.

    `files` is a list of dicts: [{"name": "users.json", "content": "<json>"}].
    Returns a small summary; raises ValueError on bad input.
    """
    if not files:
        raise ValueError("no files received")
    if UPLOAD_DIR.exists():
        shutil.rmtree(UPLOAD_DIR)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    written = 0
    for f in files:
        name = (f.get("name") or "").strip()
        content = f.get("content")
        if not name.lower().endswith(".json") or content is None:
            continue
        # keep just the base filename -- never trust a path from the browser
        safe = Path(name).name
        (UPLOAD_DIR / safe).write_text(content, encoding="utf-8")
        written += 1
    if written == 0:
        raise ValueError("no valid .json files in upload")
    load_graph(UPLOAD_DIR)            # raises SystemExit if unparseable
    return {"ok": True, "files": written,
            "nodes": len(GRAPH.nodes), "edges": len(GRAPH.edges)}


def _label(name: str) -> str:
    """'liam.walsh@CORP.LOCAL' -> 'liam.walsh'; 'FS01.CORP.LOCAL' -> 'FS01'."""
    if "@" in name:                    # UPN: keep the full username (real names have dots)
        return name.split("@")[0]
    return name.split(".")[0]          # host FQDN: keep just the hostname


def graph_to_json(graph) -> dict:
    """The whole graph as plain JSON for the browser to draw."""
    return {
        "nodes": [
            {"id": n["id"], "label": _label(n["name"]), "type": n["type"]}
            for n in graph.nodes.values()
        ],
        "edges": [
            {
                "source": e["source"],
                "target": e["target"],
                "kind": e["kind"],
                "mitre": e.get("mitre"),
                "detection": e.get("detection"),
                "smartness": e.get("smartness"),
            }
            for e in graph.edges
        ],
    }


def paths_to_json(graph, start_q: str, target_q: str, mode: str = "all",
                  profile: str = "default") -> dict:
    """Compute ranked paths from start to target and return them as JSON.

    `profile` is an optional environment lens (default/edr/legacy/audited).
    Existing frontends that don't send it simply get the default scoring, so
    the dashboard keeps working unchanged.
    """
    if profile not in list_profiles():
        profile = "default"
    start = resolve(graph, start_q)
    target = resolve(graph, target_q)
    if not start or not target:
        return {"error": "start or target not found"}

    wanted = [m for m, _ in OBJECTIVES] if mode in (None, "", "all") else [mode]
    paths = {}
    for m in wanted:
        p = find_path(graph, start, target, m, profile=profile)
        if p is None:
            paths[m] = None
            continue
        steps = []
        for e in p.edges:
            t = get_profile_technique(e["kind"], profile)
            steps.append({
                "from": _label(graph.nodes[e["source"]]["name"]),
                "to": _label(graph.nodes[e["target"]]["name"]),
                "kind": e["kind"],
                "name": t.name,         # plain-English technique name
                "note": t.note,         # 1-line explanation of what this step does
                "mitre": t.mitre,
                "detection": t.detection,
            })
        paths[m] = {
            "hops": p.hops,
            "noise": sum(s["detection"] for s in steps),
            "node_ids": p.nodes,
            "steps": steps,
        }
    return {
        "start": _label(graph.nodes[start]["name"]),
        "target": _label(graph.nodes[target]["name"]),
        "profile": profile,
        "total_paths": count_paths(graph, start, target),
        "paths": paths,
    }


# Self-contained upload page (dark theme, drag-and-drop). Kept here so we add
# the feature WITHOUT touching web/index.html -- after a successful upload the
# browser is redirected to "/", which re-charts the freshly loaded data.
UPLOAD_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>PathHunter - Upload BloodHound data</title>
<style>
 body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#0b0f1a;color:#e6edf3;
      display:flex;align-items:center;justify-content:center;height:100vh}
 .card{width:520px;background:#111827;border:1px solid #1f2937;border-radius:14px;padding:28px}
 h1{margin:0 0 4px;font-size:20px}.sub{color:#8b95a5;font-size:13px;margin-bottom:18px}
 #drop{border:2px dashed #334155;border-radius:12px;padding:34px;text-align:center;
       color:#94a3b8;cursor:pointer;transition:.15s}
 #drop.hot{border-color:#ef4444;background:#160d12;color:#fca5a5}
 .btn{display:inline-block;margin-top:16px;background:#ef4444;color:#fff;border:0;
      padding:10px 18px;border-radius:8px;font-weight:600;cursor:pointer}
 .btn.ghost{background:#1f2937}
 #status{margin-top:16px;font-size:13px;white-space:pre-line}
 a{color:#60a5fa;text-decoration:none}
</style></head><body>
<div class="card">
  <h1>Upload BloodHound data</h1>
  <div class="sub">Drop your SharpHound / BloodHound <b>.json</b> files (users, groups,
     computers, domains). PathHunter parses them and re-draws the dashboard.</div>
  <div id="drop">Drag &amp; drop .json files here, or click to choose</div>
  <input id="file" type="file" accept=".json,application/json" multiple style="display:none">
  <div>
    <button class="btn" id="go">Analyze &amp; chart</button>
    <a class="btn ghost" href="/">Back to dashboard</a>
  </div>
  <div id="status"></div>
</div>
<script>
 const drop=document.getElementById('drop'),inp=document.getElementById('file'),
       go=document.getElementById('go'),st=document.getElementById('status');
 let picked=[];
 function setList(fs){picked=[...fs];drop.textContent=picked.length?
   picked.map(f=>f.name).join(', '):'Drag & drop .json files here, or click to choose';}
 drop.onclick=()=>inp.click();
 inp.onchange=e=>setList(e.target.files);
 drop.ondragover=e=>{e.preventDefault();drop.classList.add('hot')};
 drop.ondragleave=()=>drop.classList.remove('hot');
 drop.ondrop=e=>{e.preventDefault();drop.classList.remove('hot');setList(e.dataTransfer.files)};
 const read=f=>new Promise(r=>{const x=new FileReader();x.onload=()=>r({name:f.name,content:x.result});x.readAsText(f)});
 go.onclick=async()=>{
   if(!picked.length){st.textContent='Pick at least one .json file first.';return;}
   st.textContent='Uploading '+picked.length+' file(s)...';
   try{
     const files=await Promise.all(picked.map(read));
     const res=await fetch('/api/upload',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({files})});
     const j=await res.json();
     if(j.ok){st.textContent='Loaded '+j.nodes+' nodes / '+j.edges+' edges. Opening dashboard...';
        setTimeout(()=>location.href='/',1200);}
     else{st.textContent='Error: '+(j.error||'upload failed');}
   }catch(err){st.textContent='Error: '+err;}
 };
</script></body></html>"""


def suggest(graph) -> dict:
    """Pick a sensible default start -> target for whatever graph is loaded.

    Target = the Domain Admins group (or an admin-ish / domain node). Start =
    the USER with the longest fewest-hops route to that target (the juiciest
    demo). One reverse-BFS, so it's fast even on a big forest. This is why the
    dashboard "just works" on any uploaded data instead of defaulting to names
    that may not exist.
    """
    from collections import deque
    if not graph.nodes:
        return {"error": "empty graph"}
    low = lambda n: n["name"].lower()

    target = None
    for n in graph.nodes.values():
        if "domain admins" in low(n):
            target = n["id"]; break
    if target is None:
        for n in graph.nodes.values():
            if "admin" in low(n) and n["type"] in ("User", "Group"):
                target = n["id"]; break
    if target is None:
        doms = [n for n in graph.nodes.values() if n["type"] == "Domain"]
        target = doms[0]["id"] if doms else next(iter(graph.nodes))

    # reverse adjacency -> BFS from target gives hop-distance of every node
    radj = {}
    for e in graph.edges:
        radj.setdefault(e["target"], []).append(e["source"])
    dist = {target: 0}
    q = deque([target])
    while q:
        cur = q.popleft()
        for src in radj.get(cur, []):
            if src not in dist:
                dist[src] = dist[cur] + 1
                q.append(src)

    best, best_hops = None, -1
    for n in graph.nodes.values():
        if n["type"] == "User" and n["id"] != target and dist.get(n["id"], -1) > best_hops:
            best_hops = dist[n["id"]]; best = n["id"]
    if best is None:                       # no user reaches the target
        users = [n for n in graph.nodes.values() if n["type"] == "User"]
        best = users[0]["id"] if users else target
    return {"start": _label(graph.nodes[best]["name"]),
            "target": _label(graph.nodes[target]["name"]), "hops": max(best_hops, 0)}


class Handler(BaseHTTPRequestHandler):
    """Tiny router: dashboard, upload page, and JSON endpoints."""

    def _send(self, code: int, body, ctype: str = "application/json") -> None:
        data = body if isinstance(body, bytes) else str(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            page = (WEB_DIR / "index.html").read_text(encoding="utf-8")
            return self._send(200, page, "text/html; charset=utf-8")
        if u.path == "/upload":
            return self._send(200, UPLOAD_PAGE, "text/html; charset=utf-8")
        if u.path == "/api/graph":
            return self._send(200, json.dumps(graph_to_json(GRAPH)))
        if u.path == "/api/paths":
            res = paths_to_json(
                GRAPH,
                q.get("start", [""])[0],
                q.get("target", [""])[0],
                q.get("mode", ["all"])[0],
                q.get("profile", ["default"])[0],
            )
            return self._send(200, json.dumps(res))
        if u.path == "/api/profiles":
            return self._send(200, json.dumps(list_profiles()))
        if u.path == "/api/suggest":
            return self._send(200, json.dumps(suggest(GRAPH)))
        self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self) -> None:
        u = urlparse(self.path)
        if u.path != "/api/upload":
            return self._send(404, json.dumps({"error": "not found"}))
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
            summary = save_and_load_upload(payload.get("files"))
            self._send(200, json.dumps(summary))
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, json.dumps({"error": str(exc)}))
        except SystemExit as exc:           # load_bloodhound rejects the data
            self._send(400, json.dumps({"error": str(exc)}))
        except Exception as exc:            # never take the server down
            self._send(500, json.dumps({"error": str(exc)}))

    def log_message(self, *args) -> None:  # keep the console quiet
        pass


def main(argv=None) -> None:
    global GRAPH
    ap = argparse.ArgumentParser(
        prog="pathhunter.web",
        description="Serve the PathHunter dashboard (standard library only).",
    )
    ap.add_argument("--data", default=str(DEFAULT_DATA),
                    help="folder of BloodHound JSON (default: bundled sample)")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--open", action="store_true",
                    help="open the dashboard in your default browser on startup")
    args = ap.parse_args(argv)

    load_graph(args.data)
    url = f"http://localhost:{args.port}/"
    print(f"PathHunter dashboard running -> {url}")
    print(f"  upload your own BloodHound JSON at -> {url}upload")
    print("Press Ctrl+C to stop.")
    if args.open:
        # open the browser shortly after the server starts listening
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
