import sys
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sca_reachability.contracts import (
    ReachabilityState,
    ReachabilityClassification,
    AttributionConfidence,
    ScopeType,
    ImportRecord,
    LocalAssignmentBinding,
    CallRecord,
    ImportDistributionResult,
    ImportNamespaceResult,
    VectorCFinding,
)
from sca_reachability.dist_import_map import (
    CURATED_DIST_TO_IMPORTS,
    CURATED_IMPORT_TO_DISTS,
    get_curated_imports_for_dist,
    get_curated_dists_for_import,
)

FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "vector_c"


class TestDistImportMap(unittest.TestCase):
    """Verifies bidirectional curated distribution mappings match 1:1 and handle normalization."""

    def test_curated_dist_to_imports_not_empty(self):
        self.assertGreaterEqual(len(CURATED_DIST_TO_IMPORTS), 10)

    def test_curated_import_to_dists_not_empty(self):
        self.assertGreaterEqual(len(CURATED_IMPORT_TO_DISTS), 9)

    def test_bidirectional_consistency(self):
        for dist, imports in CURATED_DIST_TO_IMPORTS.items():
            for imp in imports:
                # Top-level namespace packages or submodules
                root_part = imp.split(".")[0]
                dists = get_curated_dists_for_import(imp) or get_curated_dists_for_import(root_part)
                self.assertIsNotNone(
                    dists,
                    f"Reciprocal reverse lookup missing for import '{imp}' from dist '{dist}'"
                )
                self.assertIn(dist, dists)

    def test_normalization(self):
        self.assertEqual(get_curated_imports_for_dist("python-dateutil"), ("dateutil",))
        self.assertEqual(get_curated_imports_for_dist("Python_DateUtil "), ("dateutil",))
        self.assertEqual(get_curated_imports_for_dist("PILLOW"), ("PIL",))
        self.assertEqual(get_curated_imports_for_dist("attrs"), ("attr",))
        self.assertEqual(get_curated_dists_for_import("dateutil"), ("python-dateutil",))
        self.assertEqual(get_curated_dists_for_import("PIL"), ("pillow",))
        self.assertIsNone(get_curated_imports_for_dist("non-existent-pkg-xyz"))
        self.assertIsNone(get_curated_dists_for_import("non_existent_import_xyz"))


class TestAdvisoryFixture(unittest.TestCase):
    """Verifies the synthetic offline advisory parses cleanly without network calls."""

    def test_advisory_file_exists_and_parses(self):
        adv_path = FIXTURES_DIR / "advisory_fixture.json"
        self.assertTrue(adv_path.exists(), f"Advisory fixture missing at {adv_path}")

        data = json.loads(adv_path.read_text(encoding="utf-8-sig"))
        self.assertIn("advisories", data)
        self.assertGreater(len(data["advisories"]), 0)

        adv = data["advisories"][0]
        self.assertEqual(adv["id"], "TCS-VEC-C-001")
        self.assertEqual(adv["package"]["name"], "vulnlib")
        self.assertEqual(adv["package"]["ecosystem"], "PyPI")
        self.assertIn("affected", adv)

        aff = adv["affected"][0]
        self.assertEqual(aff["package"]["name"], "vulnlib")
        self.assertIn("ranges", aff)
        events = aff["ranges"][0]["events"]
        self.assertEqual(events[0]["introduced"], "0")
        self.assertEqual(events[1]["fixed"], "2.0.0")

        api_hints = aff["database_specific"]["api_hints"]
        self.assertIn("dangerous", api_hints["affected_functions"])
        self.assertFalse(api_hints["is_definitive"])


class TestPhase1RulesAndContracts(unittest.TestCase):
    """Verifies Rule P-1, Rule P-2, and Rule P-3 in contract models."""

    def test_rule_p2_wildcard_contract(self):
        rec_wildcard = ImportRecord(
            import_style="from_import_star",
            distribution_name="vulnlib",
            import_root="vulnlib",
            module="vulnlib",
            symbol="*",
            alias=None,
            file="app.py",
            line=1,
            column=0,
            scope_type=ScopeType.MODULE,
            scope_path="app",
            parent_scope_path=None,
            mapping_evidence="TARGET_ENVIRONMENT_METADATA",
            environment_scope="TARGET_ENVIRONMENT",
        )
        self.assertTrue(rec_wildcard.is_wildcard)

        rec_named = ImportRecord(
            import_style="from_import",
            distribution_name="vulnlib",
            import_root="vulnlib",
            module="vulnlib",
            symbol="dangerous",
            alias=None,
            file="app.py",
            line=1,
            column=0,
            scope_type=ScopeType.MODULE,
            scope_path="app",
            parent_scope_path=None,
            mapping_evidence="TARGET_ENVIRONMENT_METADATA",
            environment_scope="TARGET_ENVIRONMENT",
        )
        self.assertFalse(rec_named.is_wildcard)

    def test_rule_p3_local_assignment_binding(self):
        binding = LocalAssignmentBinding(
            variable_name="manager",
            scope_path="app.fetch",
            source_expression="urllib3.PoolManager()",
            attributed_type="urllib3.PoolManager",
            attributed_import=None,
            file="app.py",
            line=5,
            column=4,
            confidence=AttributionConfidence.PROVEN_STATIC,
        )
        d = binding.to_dict()
        self.assertEqual(d["variable_name"], "manager")
        self.assertEqual(d["attributed_type"], "urllib3.PoolManager")
        self.assertEqual(d["confidence"], "PROVEN_STATIC")


class TestVectorCFixturesSchema(unittest.TestCase):
    """Verifies all 16 golden fixture folders conform strictly to the VectorCFinding schema."""

    def setUp(self):
        self.fixture_dirs = sorted([
            d for d in FIXTURES_DIR.iterdir()
            if d.is_dir() and d.name.startswith("fixture_")
        ])

    def test_exactly_16_fixtures_present(self):
        self.assertEqual(len(self.fixture_dirs), 16, f"Expected 16 fixtures, found {len(self.fixture_dirs)}")

    def test_all_fixtures_have_required_files(self):
        for fdir in self.fixture_dirs:
            has_manifest = (fdir / "poetry.lock").exists() or (fdir / "requirements.txt").exists()
            self.assertTrue(has_manifest, f"{fdir.name} missing manifest (poetry.lock / requirements.txt)")

            has_code = (fdir / "app.py").exists() or (fdir / "target.py").exists()
            self.assertTrue(has_code, f"{fdir.name} missing code file (app.py / target.py)")

            has_expected = (fdir / "expected.json").exists()
            self.assertTrue(has_expected, f"{fdir.name} missing expected.json")

    def test_all_expected_json_conform_to_vector_c_finding(self):
        for fdir in self.fixture_dirs:
            expected_file = fdir / "expected.json"
            raw_data = json.loads(expected_file.read_text(encoding="utf-8-sig"))

            # Must instantiate cleanly via from_dict
            finding = VectorCFinding.from_dict(raw_data)
            self.assertIsInstance(finding, VectorCFinding, f"Failed parsing {fdir.name}")

            # Verify core fields
            self.assertTrue(finding.package_name, f"{fdir.name} has empty package_name")
            self.assertIn(finding.affected_status, ("CONFIRMED", "POTENTIAL", "UNRESOLVED"))
            self.assertIsInstance(finding.import_status, ReachabilityState)
            self.assertIsInstance(finding.call_status, ReachabilityState)
            self.assertIsInstance(finding.reachability_classification, ReachabilityClassification)

            # Verify round-trip serialization
            serialized = finding.to_dict()
            self.assertEqual(serialized["package_name"], raw_data["package_name"])
            self.assertEqual(serialized["reachability_classification"], raw_data["reachability_classification"])
            self.assertEqual(serialized["affected_status"], raw_data["affected_status"])
            self.assertEqual(serialized["import_status"], raw_data["import_status"])
            self.assertEqual(serialized["call_status"], raw_data["call_status"])

    def test_rule_p1_entrypoint_invocations(self):
        """Rule P-1: Fixture 05 (2-hop), Fixture 06 (3-hop), and Fixture 14 MUST include module-level invocation."""
        for fix_name, invoke_call in [
            ("fixture_05_two_hop_wrapper", "main()"),
            ("fixture_06_three_hop_wrapper", "main()"),
            ("fixture_14_nested_scope", "outer()"),
        ]:
            fdir = FIXTURES_DIR / fix_name
            code_file = fdir / "app.py"
            content = code_file.read_text(encoding="utf-8-sig")
            self.assertIn(
                invoke_call,
                content,
                f"{fix_name} missing required entrypoint invocation '{invoke_call}' (Rule P-1)"
            )

    def test_specific_fixture_behaviors(self):
        # Fixture 01: Direct Call -> REACHABLE_API_USE
        f01 = VectorCFinding.from_dict(json.loads((FIXTURES_DIR / "fixture_01_direct_call" / "expected.json").read_text(encoding="utf-8-sig")))
        self.assertEqual(f01.reachability_classification, ReachabilityClassification.REACHABLE_API_USE)
        self.assertEqual(f01.call_status, ReachabilityState.CALL_REACHABLE)

        # Fixture 02: Imported Unused -> DEPENDENCY_ACTIVE
        f02 = VectorCFinding.from_dict(json.loads((FIXTURES_DIR / "fixture_02_imported_unused" / "expected.json").read_text(encoding="utf-8-sig")))
        self.assertEqual(f02.reachability_classification, ReachabilityClassification.DEPENDENCY_ACTIVE)
        self.assertEqual(f02.call_status, ReachabilityState.REACHABILITY_UNRESOLVED)

        # Fixture 06: Three-hop Wrapper -> Phase 1 boundary (DEPENDENCY_ACTIVE / REACHABILITY_UNRESOLVED)
        f06 = VectorCFinding.from_dict(json.loads((FIXTURES_DIR / "fixture_06_three_hop_wrapper" / "expected.json").read_text(encoding="utf-8-sig")))
        self.assertEqual(f06.call_depth, 3)
        self.assertEqual(f06.call_status, ReachabilityState.REACHABILITY_UNRESOLVED)
        self.assertEqual(f06.reachability_classification, ReachabilityClassification.DEPENDENCY_ACTIVE)

        # Fixture 07: Wrong package -> DEPENDENCY_DORMANT
        f07 = VectorCFinding.from_dict(json.loads((FIXTURES_DIR / "fixture_07_wrong_package" / "expected.json").read_text(encoding="utf-8-sig")))
        self.assertEqual(f07.reachability_classification, ReachabilityClassification.DEPENDENCY_DORMANT)
        self.assertEqual(f07.import_status, ReachabilityState.PACKAGE_IMPORT_NOT_FOUND)

        # Fixture 08: Dynamic getattr -> DEPENDENCY_ACTIVE / is_dynamic True
        f08 = VectorCFinding.from_dict(json.loads((FIXTURES_DIR / "fixture_08_dynamic_getattr" / "expected.json").read_text(encoding="utf-8-sig")))
        self.assertTrue(f08.call_evidence.is_dynamic)
        self.assertEqual(f08.reachability_classification, ReachabilityClassification.DEPENDENCY_ACTIVE)

        # Fixture 09: Transitive dependency -> TRANSITIVE_VULNERABLE / is_transitive True
        f09 = VectorCFinding.from_dict(json.loads((FIXTURES_DIR / "fixture_09_transitive_dep" / "expected.json").read_text(encoding="utf-8-sig")))
        self.assertTrue(f09.is_transitive)
        self.assertEqual(f09.reachability_classification, ReachabilityClassification.TRANSITIVE_VULNERABLE)

        # Fixture 10: Heuristic mapping -> REACHABILITY_UNRESOLVED (Invariant S-2)
        f10 = VectorCFinding.from_dict(json.loads((FIXTURES_DIR / "fixture_10_heuristic_mapping" / "expected.json").read_text(encoding="utf-8-sig")))
        self.assertEqual(f10.reachability_classification, ReachabilityClassification.REACHABILITY_UNRESOLVED)
        self.assertEqual(f10.environment_scope, "NONE")

        # Fixture 13: Scope isolation
        f13 = VectorCFinding.from_dict(json.loads((FIXTURES_DIR / "fixture_13_scope_isolation" / "expected.json").read_text(encoding="utf-8-sig")))
        self.assertEqual(f13.import_evidence.scope_type, ScopeType.FUNCTION)
        self.assertEqual(f13.import_evidence.scope_path, "app.func_a")

        # Fixture 15: Alias isolation
        f15 = VectorCFinding.from_dict(json.loads((FIXTURES_DIR / "fixture_15_alias_isolation" / "expected.json").read_text(encoding="utf-8-sig")))
        self.assertEqual(f15.import_evidence.alias, "v")
        self.assertEqual(f15.reachability_classification, ReachabilityClassification.REACHABLE_API_USE)

        # Fixture 16: Class vs method scope (PEP 227)
        f16 = VectorCFinding.from_dict(json.loads((FIXTURES_DIR / "fixture_16_class_vs_method_scope" / "expected.json").read_text(encoding="utf-8-sig")))
        self.assertEqual(f16.import_evidence.scope_type, ScopeType.CLASS)
        self.assertEqual(f16.reachability_classification, ReachabilityClassification.DEPENDENCY_ACTIVE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
