"""
PathHunter test suite
=====================

Uses Python's built-in `unittest` (so it runs with ZERO extra installs):

    python -m unittest discover -s tests -t .

These tests pin down the behaviour we rely on: the sample data loads into
the expected graph, techniques/scores make sense, and the pathfinder
returns the right routes under each objective.
"""

import json
import tempfile
import unittest
from pathlib import Path

from pathhunter.loader import load_bloodhound
from pathhunter.techniques import TECHNIQUES, CATEGORIES, get_technique
from pathhunter.scoring import annotate_graph, edge_smartness
from pathhunter.pathfinder import find_path, resolve
from pathhunter.profiles import (
    list_profiles, get_profile_technique, adjust_technique, get_profile,
)

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample"


def _load():
    return load_bloodhound(SAMPLE)


class TestLoader(unittest.TestCase):
    def test_node_and_edge_counts(self):
        g = _load()
        self.assertEqual(len(g.nodes), 14)
        self.assertEqual(len(g.edges), 16)

    def test_node_type_breakdown(self):
        g = _load()
        types = [n["type"] for n in g.nodes.values()]
        self.assertEqual(types.count("User"), 6)
        self.assertEqual(types.count("Computer"), 4)
        self.assertEqual(types.count("Group"), 3)
        self.assertEqual(types.count("Domain"), 1)


class TestTechniques(unittest.TestCase):
    def test_known_edge(self):
        self.assertEqual(get_technique("HasSession").mitre, "T1003.001")
        self.assertEqual(get_technique("MemberOf").detection, 1)

    def test_unknown_edge_is_medium_risk(self):
        t = get_technique("ThisEdgeDoesNotExist")
        self.assertEqual(t.detection, 5)
        self.assertEqual(t.mitre, "-")


class TestScoring(unittest.TestCase):
    def test_smartness_within_range(self):
        for kind in ("MemberOf", "HasSession", "GenericAll", "AdminTo"):
            score = edge_smartness(get_technique(kind))
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 10.0)

    def test_quiet_step_scores_higher_than_loud_one(self):
        # Riding group membership should look 'smarter' than dumping LSASS.
        self.assertGreater(
            edge_smartness(get_technique("MemberOf")),
            edge_smartness(get_technique("HasSession")),
        )

    def test_annotate_adds_expected_fields(self):
        g = _load()
        annotate_graph(g)
        edge = g.edges[0]
        for field in ("technique", "mitre", "detection", "reliability", "smartness"):
            self.assertIn(field, edge)


class TestPathfinder(unittest.TestCase):
    def setUp(self):
        self.g = _load()
        self.start = resolve(self.g, "alice")
        self.target = resolve(self.g, "daadmin")

    def test_resolve_finds_principals(self):
        self.assertIsNotNone(self.start)
        self.assertIsNotNone(self.target)

    def test_fastest_route_is_two_hops(self):
        path = find_path(self.g, self.start, self.target, "fast")
        self.assertIsNotNone(path)
        self.assertEqual(path.hops, 2)

    def test_stealthiest_route_is_quieter_than_fastest(self):
        noise = lambda p: sum(get_technique(e["kind"]).detection for e in p.edges)
        fast = find_path(self.g, self.start, self.target, "fast")
        stealth = find_path(self.g, self.start, self.target, "stealth")
        self.assertLess(noise(stealth), noise(fast))

    def test_unreachable_target_returns_none(self):
        # svc_sql has no inbound edges, so alice can never reach it.
        svc_sql = resolve(self.g, "svc_sql")
        self.assertIsNotNone(svc_sql)
        self.assertIsNone(find_path(self.g, self.start, svc_sql, "fast"))


class TestKnowledgeBase(unittest.TestCase):
    """The enriched, internet-sourced technique knowledge base."""

    def test_is_comprehensive(self):
        # A spread across every family should be present after enrichment.
        for kind in ("MemberOf", "ForceChangePassword", "AddKeyCredentialLink",
                     "WriteSPN", "AllowedToAct", "AdminTo", "HasSession",
                     "ReadGMSAPassword", "ReadLAPSPassword", "HasSIDHistory",
                     "DCSync", "GetChangesInFilteredSet", "ADCSESC1",
                     "ADCSESC13", "GoldenCert", "ManageCA"):
            self.assertIn(kind, TECHNIQUES, f"missing edge: {kind}")
        self.assertGreaterEqual(len(TECHNIQUES), 40)

    def test_every_technique_is_well_formed(self):
        for kind, t in TECHNIQUES.items():
            self.assertGreaterEqual(t.detection, 1, kind)
            self.assertLessEqual(t.detection, 10, kind)
            self.assertGreaterEqual(t.reliability, 0.0, kind)
            self.assertLessEqual(t.reliability, 1.0, kind)
            self.assertIn(t.category, CATEGORIES, f"{kind}: bad category {t.category}")

    def test_lookup_is_case_insensitive(self):
        self.assertEqual(get_technique("adcsesc1").category, "certificate")
        self.assertEqual(get_technique("DCSYNC").mitre, "T1003.006")

    def test_categories_drive_families(self):
        self.assertEqual(get_technique("HasSession").category, "credential")
        self.assertEqual(get_technique("GetChanges").category, "replication")
        self.assertEqual(get_technique("GoldenCert").category, "certificate")

    def test_every_technique_is_multi_sourced(self):
        # Enrichment must reach every edge: refs + opsec + remediation.
        for kind, t in TECHNIQUES.items():
            self.assertIsInstance(t.references, tuple, kind)   # hashable
            self.assertTrue(t.references, f"{kind}: no references")
            for url in t.references:
                self.assertTrue(url.startswith("http"), f"{kind}: bad url {url}")
            self.assertTrue(t.opsec, f"{kind}: no opsec note")
            self.assertTrue(t.remediation, f"{kind}: no remediation note")

    def test_bespoke_overrides_applied(self):
        # High-value edges get edge-specific guidance, not the generic default.
        self.assertIn("LSASS", get_technique("HasSession").opsec)
        self.assertIn("4662", get_technique("DCSync").opsec)
        self.assertTrue(any("Certified_Pre-Owned" in r or "esc1" in r.lower()
                            for r in get_technique("ADCSESC1").references))


class TestProfiles(unittest.TestCase):
    """Situational scoring: same graph, different ranking per environment."""

    def test_builtin_profiles_exist(self):
        for name in ("default", "edr", "legacy", "audited"):
            self.assertIn(name, list_profiles())

    def test_default_profile_is_a_noop(self):
        base = get_technique("HasSession")
        self.assertEqual(adjust_technique(base, "default"), base)

    def test_edr_amplifies_credential_theft(self):
        base = get_technique("HasSession")
        edr = get_profile_technique("HasSession", "edr")
        self.assertGreater(edr.detection, base.detection)   # louder
        self.assertLess(edr.reliability, base.reliability)  # EDR blocks it

    def test_legacy_quietens_noisy_steps(self):
        base = get_technique("HasSession")
        legacy = get_profile_technique("HasSession", "legacy")
        self.assertLess(legacy.detection, base.detection)

    def test_adjustment_stays_in_range(self):
        for name in list_profiles():
            for kind in TECHNIQUES:
                t = get_profile_technique(kind, name)
                self.assertGreaterEqual(t.detection, 1, (name, kind))
                self.assertLessEqual(t.detection, 10, (name, kind))
                self.assertGreaterEqual(t.reliability, 0.0, (name, kind))
                self.assertLessEqual(t.reliability, 1.0, (name, kind))

    def test_structural_edges_unaffected(self):
        base = get_technique("Contains")
        self.assertEqual(adjust_technique(base, "edr"), base)

    def test_profile_preserves_enrichment(self):
        # Adjusting scores must not drop references/opsec/remediation.
        base = get_technique("HasSession")
        edr = get_profile_technique("HasSession", "edr")
        self.assertEqual(edr.references, base.references)
        self.assertEqual(edr.opsec, base.opsec)
        self.assertEqual(edr.remediation, base.remediation)

    def test_unknown_profile_falls_back_to_default(self):
        self.assertEqual(get_profile("nope").name, "default")

    def test_profile_changes_path_noise(self):
        # The FAST route (AdminTo -> HasSession) is lateral+credential, so an
        # EDR estate makes it noisier and a legacy estate makes it quieter,
        # while the SAME path is returned. This is the "react to the
        # situation" behaviour end-to-end.
        g = load_bloodhound(SAMPLE)
        start, target = resolve(g, "alice"), resolve(g, "daadmin")

        def noise(profile):
            p = find_path(g, start, target, "fast", profile=profile)
            self.assertIsNotNone(p)
            return sum(get_profile_technique(e["kind"], profile).detection
                       for e in p.edges)

        self.assertGreater(noise("edr"), noise("default"))
        self.assertLess(noise("legacy"), noise("default"))


class TestLoaderRobustness(unittest.TestCase):
    """The loader copes with varied real-world export shapes."""

    def _write(self, folder, name, doc):
        (Path(folder) / name).write_text(json.dumps(doc), encoding="utf-8")

    def test_varied_shapes_and_derived_flags(self):
        with tempfile.TemporaryDirectory() as d:
            base = "S-1-5-21-1-1-1"
            # Computers file exercising lateral lists + RBCD.
            self._write(d, "computers.json", {
                "meta": {"type": "computers"},
                "data": [{
                    "Properties": {"name": "PC1.CORP", "objectid": f"{base}-1000"},
                    "ObjectIdentifier": f"{base}-1000",
                    "RemoteDesktopUsers": {"Results": [
                        {"ObjectIdentifier": f"{base}-1100", "ObjectType": "User"}]},
                    "PSRemoteUsers": {"Results": [
                        {"ObjectIdentifier": f"{base}-1101", "ObjectType": "User"}]},
                    "AllowedToAct": {"Results": [
                        {"ObjectIdentifier": f"{base}-1102", "ObjectType": "User"}]},
                }],
            })
            # Users file with derived capabilities + sid history.
            self._write(d, "users.json", {
                "meta": {"type": "users"},
                "data": [{
                    "Properties": {"name": "ROAST@CORP", "objectid": f"{base}-1100",
                                   "hasspn": True, "dontreqpreauth": "true",
                                   "unconstraineddelegation": True,
                                   "sidhistory": [f"{base}-512"]},
                    "ObjectIdentifier": f"{base}-1100",
                }],
            })
            # Pre-computed, graph-shaped edge export.
            self._write(d, "graph.json", {"graph": {"nodes": [], "edges": [
                {"source": f"{base}-1100", "target": f"{base}-1000",
                 "kind": "AdminTo"}]}})
            # A malformed file must be skipped, not fatal.
            (Path(d) / "broken.json").write_text("{not json", encoding="utf-8")

            g = load_bloodhound(d)
            kinds = {e["kind"] for e in g.edges}
            self.assertIn("CanRDP", kinds)
            self.assertIn("CanPSRemote", kinds)
            self.assertIn("AllowedToAct", kinds)
            self.assertIn("HasSIDHistory", kinds)
            self.assertIn("AdminTo", kinds)  # from the pre-computed export

            roaster = g.nodes[f"{base}-1100"]
            self.assertTrue(roaster.get("kerberoastable"))
            self.assertTrue(roaster.get("asreproastable"))
            self.assertTrue(roaster.get("unconstrained"))

    def test_bare_list_document(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "users.json", {"meta": {"type": "users"}, "data": [
                {"Properties": {"name": "A@CORP", "objectid": "S-1-1"},
                 "ObjectIdentifier": "S-1-1"}]})
            g = load_bloodhound(d)
            self.assertIn("S-1-1", g.nodes)


class TestUpload(unittest.TestCase):
    """Browser-upload path: feed file contents, graph rebuilds in memory."""

    def test_save_and_load_upload(self):
        from pathhunter import web
        files = [{"name": p.name, "content": p.read_text(encoding="utf-8")}
                 for p in sorted(SAMPLE.glob("*.json"))]
        try:
            summary = web.save_and_load_upload(files)
            self.assertTrue(summary["ok"])
            self.assertEqual(summary["files"], len(files))
            self.assertEqual(summary["nodes"], 14)
            self.assertEqual(summary["edges"], 16)
            self.assertIsNotNone(web.GRAPH)
        finally:
            import shutil
            if web.UPLOAD_DIR.exists():
                shutil.rmtree(web.UPLOAD_DIR)

    def test_rejects_bad_upload(self):
        from pathhunter import web
        with self.assertRaises(ValueError):
            web.save_and_load_upload([])
        with self.assertRaises(ValueError):
            web.save_and_load_upload([{"name": "notes.txt", "content": "hi"}])


if __name__ == "__main__":
    unittest.main()
