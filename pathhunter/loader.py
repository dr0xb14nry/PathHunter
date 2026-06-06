"""
BloodHound data loader  (Phase 1, hardened)
-------------------------------------------

Reads BloodHound / SharpHound JSON files and builds a lightweight,
in-memory directed graph of the Active Directory environment.

WHY IN-MEMORY (no database):
  BloodHound normally loads data into a Neo4j server, which eats
  hundreds of MB to a couple of GB of RAM just sitting there. For a
  tool you want to drop into a real engagement, that's friction.
  Parsing the same JSON straight into Python objects uses ~tens of MB
  and needs nothing installed. That is the whole point of v1.

WHAT A "GRAPH" IS HERE:
  * node  = a thing in AD (a User, Group, Computer, or Domain)
  * edge  = a relationship between two things, and crucially each
            relationship maps to an attack technique
            (e.g. "alice --MemberOf--> HELPDESK").

REACTING TO DIFFERENT SITUATIONS
  Real exports are messy and vary by SharpHound/BloodHound version and by
  which collection methods were run. This loader copes with several shapes:
    * ACL edges (Aces) of ANY right name           -> generic edge
    * group Members                                 -> MemberOf
    * LocalAdmins / RemoteDesktopUsers / PSRemoteUsers / DcomUsers
                                                    -> AdminTo / CanRDP /
                                                       CanPSRemote / ExecuteDCOM
    * Sessions                                       -> HasSession
    * AllowedToAct (RBCD)                            -> AllowedToAct
    * sidhistory                                     -> HasSIDHistory
    * pre-computed edge lists (post-processed/API
      exports: doc["edges"], doc["graph"]["edges"],
      or per-object "Edges"/"Relationships")        -> ingested as-is
  It also records derived *capabilities* (Kerberoastable, ASREPRoastable,
  unconstrained delegation) as node flags, and never crashes on a single
  bad/empty file -- it skips it with a warning and keeps going.

This file only LOADS and DESCRIBES the data. Scoring and pathfinding live
in the other modules.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from collections import Counter


# BloodHound files carry a meta.type telling us what the objects are.
# We turn that plural into a singular label for our nodes.
TYPE_MAP = {
    "users": "User",
    "groups": "Group",
    "computers": "Computer",
    "domains": "Domain",
    "gpos": "GPO",
    "ous": "OU",
    "containers": "Container",
    "cas": "CA",
    "certtemplates": "CertTemplate",
    "enterprisecas": "EnterpriseCA",
    "rootcas": "RootCA",
    "ntauthstores": "NTAuthStore",
    "aiacas": "AIACA",
    "issuancepolicies": "IssuancePolicy",
}


class Graph:
    """A tiny directed graph: nodes stored by id, edges in a list."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}   # id -> {"id","name","type", ...flags}
        self.edges: list[dict] = []        # [{"source","target","kind"}]

    def add_node(self, node_id, name=None, ntype="Unknown") -> None:
        """Add a node, or enrich one we already created from an edge."""
        if not node_id:
            return
        existing = self.nodes.get(node_id)
        if existing is None:
            self.nodes[node_id] = {
                "id": node_id,
                "name": name or node_id,
                "type": ntype,
            }
        else:
            # We may have seen this id as an edge endpoint before we saw
            # its real record. Fill in the better name / type now.
            if name and existing["name"] == existing["id"]:
                existing["name"] = name
            if ntype != "Unknown" and existing["type"] == "Unknown":
                existing["type"] = ntype

    def add_edge(self, source, target, kind) -> None:
        if not source or not target or not kind:
            return
        self.add_node(source)
        self.add_node(target)
        self.edges.append({"source": source, "target": target, "kind": str(kind)})

    def flag(self, node_id, key, value=True) -> None:
        """Record a derived capability (e.g. kerberoastable) on a node."""
        if node_id and node_id in self.nodes:
            self.nodes[node_id][key] = value

    # ------------------------------------------------------------------ #
    def summary(self) -> None:
        """Print a human-readable overview of what we loaded."""
        line = "=" * 54
        print("\n" + line)
        print(" PathHunter  -  loaded attack graph")
        print(line)

        domains = [n["name"] for n in self.nodes.values() if n["type"] == "Domain"]
        print(f" Domain(s):    {', '.join(domains) or 'unknown'}")
        print(f" Total nodes:  {len(self.nodes)}")
        print(f" Total edges:  {len(self.edges)}")

        print("\n Nodes by type:")
        for ntype, count in Counter(n["type"] for n in self.nodes.values()).most_common():
            print(f"   {ntype:<13} {count}")

        print("\n Edges by kind (each = an attack technique):")
        for kind, count in Counter(e["kind"] for e in self.edges).most_common():
            print(f"   {kind:<22} {count}")

        # Derived capabilities flagged during load (only show if any exist).
        caps = [
            ("kerberoastable", "Kerberoastable (SPN) accounts"),
            ("asreproastable", "ASREP-roastable accounts"),
            ("unconstrained", "Unconstrained-delegation principals"),
        ]
        notable = [(label, sum(1 for n in self.nodes.values() if n.get(key)))
                   for key, label in caps]
        notable = [(label, count) for label, count in notable if count]
        if notable:
            print("\n Notable capabilities:")
            for label, count in notable:
                print(f"   {label:<34} {count}")

        print("\n Example relationships:")
        for e in self.edges[:8]:
            src = self.nodes[e["source"]]["name"]
            dst = self.nodes[e["target"]]["name"]
            print(f"   {src}  --{e['kind']}-->  {dst}")
        print(line + "\n")


# ---------------------------------------------------------------------- #
# Small helpers to cope with BloodHound's slightly messy JSON shapes
# ---------------------------------------------------------------------- #
def _results(value):
    """Some fields are a plain list; others are {"Results": [...]}.

    Returns a plain list no matter which shape we get.
    """
    if value is None:
        return []
    if isinstance(value, dict):
        return value.get("Results") or value.get("results") or []
    if isinstance(value, list):
        return value
    return []


def _first(d: dict, *keys):
    """Return the first present, non-empty value among several key spellings."""
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def _node_id(obj: dict):
    """The object's id can live in Properties.objectid or ObjectIdentifier,
    with assorted capitalisations across SharpHound/BloodHound versions."""
    props = obj.get("Properties") or obj.get("properties") or {}
    return _first(props, "objectid", "objectId", "ObjectID", "objectsid") \
        or _first(obj, "ObjectIdentifier", "objectIdentifier", "ObjectID", "id")


def _truthy(value) -> bool:
    """BloodHound booleans arrive as bool, "true"/"false", or 1/0."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return bool(value)


# Collection field -> edge kind, for the list-shaped lateral/RBCD fields that
# point AT this object (principal --kind--> this object).
_INBOUND_LIST_EDGES = {
    "LocalAdmins": "AdminTo",
    "RemoteDesktopUsers": "CanRDP",
    "PSRemoteUsers": "CanPSRemote",
    "DcomUsers": "ExecuteDCOM",
    "AllowedToAct": "AllowedToAct",
}


def _ingest_object(graph: Graph, obj: dict, node_type: str) -> None:
    """Parse one BloodHound object into nodes/edges + derived flags."""
    if not isinstance(obj, dict):
        return
    oid = _node_id(obj)
    props = obj.get("Properties") or obj.get("properties") or {}
    graph.add_node(oid, props.get("name"), node_type)

    # 1) ACL edges -- a principal holds a right OVER this object.
    #    Works for ANY right name (GenericAll, WriteDacl, AddKeyCredentialLink,
    #    GetChanges, ...), so new ACL abuses parse with no code change.
    for ace in obj.get("Aces") or obj.get("aces") or []:
        graph.add_edge(
            _first(ace, "PrincipalSID", "principalSID", "PrincipalID"),
            oid,
            _first(ace, "RightName", "rightName", "right") or "ACE",
        )

    # 2) Group membership -- member --MemberOf--> group
    for member in obj.get("Members") or obj.get("members") or []:
        graph.add_node(
            _first(member, "ObjectIdentifier", "objectIdentifier", "ObjectID"),
            None,
            _first(member, "ObjectType", "objectType") or "Unknown",
        )
        graph.add_edge(
            _first(member, "ObjectIdentifier", "objectIdentifier", "ObjectID"),
            oid, "MemberOf")

    # 3) List-shaped lateral / RBCD collections -- principal --kind--> object
    for field, kind in _INBOUND_LIST_EDGES.items():
        for principal in _results(obj.get(field)):
            pid = _first(principal, "ObjectIdentifier", "objectIdentifier",
                         "ObjectID")
            graph.add_node(
                pid, None,
                _first(principal, "ObjectType", "objectType") or "Unknown")
            graph.add_edge(pid, oid, kind)

    # 4) Sessions -- computer --HasSession--> user
    #    (you can steal the logged-in user's creds from this box)
    for sess in _results(obj.get("Sessions")):
        graph.add_edge(oid, _first(sess, "UserSID", "userSID", "UserID"),
                       "HasSession")

    # 5) SID history -- this principal --HasSIDHistory--> the inherited SID
    for sh in props.get("sidhistory") or obj.get("HasSIDHistory") or []:
        sid = sh if isinstance(sh, str) else _first(
            sh, "ObjectIdentifier", "objectIdentifier", "SID", "ObjectID")
        graph.add_edge(oid, sid, "HasSIDHistory")

    # 6) Pre-computed edges carried on the object (post-processed/API exports).
    for rel in (obj.get("Edges") or obj.get("Relationships") or []):
        if isinstance(rel, dict):
            graph.add_edge(
                oid,
                _first(rel, "target", "end", "ObjectIdentifier", "TargetID"),
                _first(rel, "kind", "type", "edgeType", "label"))

    # 7) Derived capability flags (NOT traversal edges -- they describe the
    #    node, and modelling them as edges would need an "attacker" root).
    if oid:
        is_computer = node_type == "Computer"
        if _truthy(props.get("hasspn")) and not is_computer:
            graph.flag(oid, "kerberoastable")
        if _truthy(props.get("dontreqpreauth")):
            graph.flag(oid, "asreproastable")
        if _truthy(props.get("unconstraineddelegation")):
            graph.flag(oid, "unconstrained")


def _ingest_precomputed_edges(graph: Graph, edges) -> None:
    """Ingest a doc-level list of already-computed edges (graph-shaped export).

    Each edge may name its endpoints as source/target, start/end, or
    StartNode/EndNode, and its type as kind/type/label.
    """
    for rel in edges or []:
        if not isinstance(rel, dict):
            continue
        graph.add_edge(
            _first(rel, "source", "start", "StartNode", "from", "PrincipalSID"),
            _first(rel, "target", "end", "EndNode", "to", "ObjectIdentifier"),
            _first(rel, "kind", "type", "label", "RightName"))


def _ingest_doc(graph: Graph, doc) -> None:
    """Ingest one parsed JSON document of any supported shape."""
    # Shape A: graph-style export {"graph": {"nodes":[...], "edges":[...]}}
    if isinstance(doc, dict) and isinstance(doc.get("graph"), dict):
        g = doc["graph"]
        for n in g.get("nodes") or []:
            graph.add_node(_node_id(n) or _first(n, "id"),
                           (n.get("Properties") or {}).get("name") or n.get("label"),
                           n.get("type") or "Unknown")
        _ingest_precomputed_edges(graph, g.get("edges"))
        return

    # Shape B: doc-level edge list {"edges": [...]} (with or without "nodes")
    if isinstance(doc, dict) and isinstance(doc.get("edges"), list):
        for n in doc.get("nodes") or []:
            graph.add_node(_node_id(n) or _first(n, "id"),
                           (n.get("Properties") or {}).get("name") or n.get("label"),
                           n.get("type") or "Unknown")
        _ingest_precomputed_edges(graph, doc["edges"])
        return

    # Shape C (the common one): SharpHound {"meta": {...}, "data": [...]}
    meta = doc.get("meta", {}) if isinstance(doc, dict) else {}
    node_type = TYPE_MAP.get(str(meta.get("type", "")).lower(), "Unknown")
    data = doc.get("data") if isinstance(doc, dict) else doc  # tolerate a bare list
    for obj in data or []:
        _ingest_object(graph, obj, node_type)


def load_bloodhound(folder) -> Graph:
    """Load every *.json BloodHound file in `folder` into a Graph.

    A single unreadable or malformed file is skipped (with a warning to
    stderr) rather than aborting the whole load -- real evidence folders
    often contain a stray or partial file.
    """
    folder = Path(folder)
    files = sorted(folder.glob("*.json"))
    if not files:
        raise SystemExit(f"No .json files found in: {folder.resolve()}")

    graph = Graph()
    loaded = 0

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            print(f"[PathHunter] skipping {filepath.name}: {exc}", file=sys.stderr)
            continue
        try:
            _ingest_doc(graph, doc)
            loaded += 1
        except Exception as exc:  # never let one weird file kill the run
            print(f"[PathHunter] error parsing {filepath.name}: {exc}",
                  file=sys.stderr)

    if loaded == 0:
        raise SystemExit(f"No parseable BloodHound JSON in: {folder.resolve()}")

    return graph
