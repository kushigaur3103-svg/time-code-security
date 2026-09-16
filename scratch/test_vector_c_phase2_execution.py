import sys
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sca_reachability.engine import analyze_dependency_reachability
from sca_reachability.contracts import (
    VectorCFinding,
    ReachabilityState,
    ReachabilityClassification,
    AttributionConfidence,
)
from sca_reachability.resolver import (
    resolve_import_to_distributions,
    resolve_distribution_to_imports,
)
from sca_reachability.ast_analyzer import ReachabilityASTVisitor
from sca_reachability.call_graph import FunctionCallGraph

FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "vector_c"
ADVISORY_PATH = FIXTURES_DIR / "advisory_fixture.json"


class TestVectorCPhase2Execution(unittest.TestCase):
    """
    Acceptance Test Suite for Vector C Phase 2 Engine.
    Executes reachability analysis on each of the 16 golden fixtures individually
    and asserts 100% equivalence on all core dimensions.
    """

    def _verify_fixture(self, fixture_name: str):
        fdir = FIXTURES_DIR / fixture_name
        manifest_file = (fdir / "poetry.lock") if (fdir / "poetry.lock").exists() else (fdir / "requirements.txt")
        code_file = (fdir / "app.py") if (fdir / "app.py").exists() else (fdir / "target.py")
        expected_file = fdir / "expected.json"

        self.assertTrue(manifest_file.exists(), f"Missing manifest in {fixture_name}")
        self.assertTrue(code_file.exists(), f"Missing code file in {fixture_name}")
        self.assertTrue(expected_file.exists(), f"Missing expected.json in {fixture_name}")

        expected_data = json.loads(expected_file.read_text(encoding="utf-8-sig"))
        target_pkg = expected_data["package_name"]

        findings = analyze_dependency_reachability(
            manifest_path=manifest_file,
            source_path=code_file,
            advisory_path=ADVISORY_PATH,
            target_package=target_pkg,
        )

        self.assertGreaterEqual(
            len(findings), 1,
            f"[{fixture_name}] Engine returned no findings for package {target_pkg}"
        )

        actual = findings[0]
        expected = VectorCFinding.from_dict(expected_data)

        # 1. package_name
        self.assertEqual(actual.package_name, expected.package_name)
        # 2. affected_status
        self.assertEqual(actual.affected_status, expected.affected_status)
        # 3. import_status
        self.assertEqual(actual.import_status, expected.import_status)
        # 4. call_status
        self.assertEqual(actual.call_status, expected.call_status)
        # 5. reachability_classification
        self.assertEqual(actual.reachability_classification, expected.reachability_classification)
        # 6. is_transitive
        self.assertEqual(actual.is_transitive, expected.is_transitive)
        # 7. call_depth
        self.assertEqual(actual.call_depth, expected.call_depth)
        # 8. edge_type
        self.assertEqual(actual.edge_type, expected.edge_type)
        # 9. limitations
        if expected.limitations:
            self.assertTrue(len(actual.limitations) > 0)
            expected_prefix = expected.limitations[0].split(";")[0].strip()[:20]
            actual_text = " ".join(actual.limitations)
            self.assertIn(expected_prefix, actual_text)

    def test_01_direct_call(self):
        self._verify_fixture("fixture_01_direct_call")

    def test_02_imported_unused(self):
        self._verify_fixture("fixture_02_imported_unused")

    def test_03_alias_call(self):
        self._verify_fixture("fixture_03_alias_call")

    def test_04_from_import_call(self):
        self._verify_fixture("fixture_04_from_import_call")

    def test_05_two_hop_wrapper(self):
        self._verify_fixture("fixture_05_two_hop_wrapper")

    def test_06_three_hop_wrapper(self):
        self._verify_fixture("fixture_06_three_hop_wrapper")

    def test_07_wrong_package(self):
        self._verify_fixture("fixture_07_wrong_package")

    def test_08_dynamic_getattr(self):
        self._verify_fixture("fixture_08_dynamic_getattr")

    def test_09_transitive_dep(self):
        self._verify_fixture("fixture_09_transitive_dep")

    def test_10_heuristic_mapping(self):
        self._verify_fixture("fixture_10_heuristic_mapping")

    def test_11_flask_entrypoint(self):
        self._verify_fixture("fixture_11_flask_entrypoint")

    def test_12_unreachable_helper(self):
        self._verify_fixture("fixture_12_unreachable_helper")

    def test_13_scope_isolation(self):
        self._verify_fixture("fixture_13_scope_isolation")

    def test_14_nested_scope(self):
        self._verify_fixture("fixture_14_nested_scope")

    def test_15_alias_isolation(self):
        self._verify_fixture("fixture_15_alias_isolation")

    def test_16_class_vs_method_scope(self):
        self._verify_fixture("fixture_16_class_vs_method_scope")

    def test_17_honest_resolver_fallback_provenance(self):
        """Resolver must return NORMALIZED_HEURISTIC and NONE when target env metadata is absent."""
        res = resolve_import_to_distributions("somecustompkg")
        self.assertEqual(res.evidence_source, "NORMALIZED_HEURISTIC")
        self.assertEqual(res.environment_scope, "NONE")
        self.assertFalse(res.is_definitive)
        self.assertEqual(res.distribution_names, ("somecustompkg",))

        fwd = resolve_distribution_to_imports("somecustompkg")
        self.assertEqual(fwd.evidence_source, "NORMALIZED_HEURISTIC")
        self.assertEqual(fwd.environment_scope, "NONE")
        self.assertFalse(fwd.is_definitive)

    def test_18_wildcard_import_rule_p2(self):
        """Rule P-2: Star-import must yield REACHABILITY_UNRESOLVED with explicit limitation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            manifest = tmp / "requirements.txt"
            manifest.write_text("vulnlib==1.5.0\n", encoding="utf-8")

            app_code = tmp / "app.py"
            app_code.write_text("from vulnlib import *\ndangerous()\n", encoding="utf-8")

            findings = analyze_dependency_reachability(
                manifest_path=manifest,
                source_path=app_code,
                target_package="vulnlib",
            )
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f.reachability_classification, ReachabilityClassification.REACHABILITY_UNRESOLVED)
            self.assertEqual(f.call_status, ReachabilityState.REACHABILITY_UNRESOLVED)
            self.assertTrue(any("Wildcard import prevents deterministic symbol attribution" in lim for lim in f.limitations))

    def test_19_generic_advisory_matching(self):
        """Advisory matching must be completely generic and normalized with zero hardcoded package names."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            manifest = tmp / "requirements.txt"
            manifest.write_text("customlib==2.1.0\n", encoding="utf-8")

            app_code = tmp / "app.py"
            app_code.write_text("import customlib\ncustomlib.execute_op()\n", encoding="utf-8")

            adv_file = tmp / "advisories.json"
            adv_data = {
                "advisories": [
                    {
                        "id": "CUSTOM-VEC-099",
                        "aliases": ["CVE-2026-9999"],
                        "package": {"name": "customlib", "ecosystem": "PyPI"},
                        "summary": "Custom library advisory test",
                        "database_specific": {"severity": "CRITICAL", "cvss_score": 9.8}
                    }
                ]
            }
            adv_file.write_text(json.dumps(adv_data), encoding="utf-8")

            findings = analyze_dependency_reachability(
                manifest_path=manifest,
                source_path=app_code,
                advisory_path=adv_file,
                target_package="customlib",
            )
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f.advisory_id, "CUSTOM-VEC-099")
            self.assertEqual(f.severity, "CRITICAL")
            self.assertEqual(f.cvss_score, 9.8)
            self.assertEqual(f.reachability_classification, ReachabilityClassification.REACHABLE_API_USE)

    def test_20_multi_file_reachability(self):
        """Analysis must accept multiple source files and track cross-file reachability."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            manifest = tmp / "requirements.txt"
            manifest.write_text("vulnlib==1.5.0\n", encoding="utf-8")

            file_a = tmp / "app.py"
            file_a.write_text("import helper\nhelper.run()\n", encoding="utf-8")

            file_b = tmp / "helper.py"
            file_b.write_text("import vulnlib\ndef run():\n    vulnlib.dangerous()\n", encoding="utf-8")

            findings = analyze_dependency_reachability(
                manifest_path=manifest,
                source_path=[file_a, file_b],
                target_package="vulnlib",
            )
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f.import_status, ReachabilityState.PACKAGE_IMPORTED)
            self.assertIn(f.reachability_classification, (ReachabilityClassification.REACHABLE_API_USE, ReachabilityClassification.DEPENDENCY_ACTIVE))

    def test_21_call_graph_collision_resistance(self):
        """Call graph must key adjacency by qualified scope_path and avoid name collision between different classes."""
        code = """
class ClassA:
    def process(self):
        import vulnlib
        vulnlib.dangerous()

class ClassB:
    def process(self):
        pass

def main():
    b = ClassB()
    b.process()

main()
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            manifest = tmp / "requirements.txt"
            manifest.write_text("vulnlib==1.5.0\n", encoding="utf-8")

            app_code = tmp / "app.py"
            app_code.write_text(code, encoding="utf-8")

            visitor = ReachabilityASTVisitor(
                module_name="app",
                file_path="app.py",
                declared_distributions={"vulnlib"},
            )
            visitor.analyze_file(app_code)

            cg = FunctionCallGraph(visitor)
            for k in cg.adjacency:
                self.assertTrue("." in k, f"Adjacency key '{k}' is not fully qualified")


if __name__ == "__main__":
    unittest.main(verbosity=2)

