"""
TimeCodeSecurity (TCS) Vector 2 Test Suite:
Modern Manifests (pyproject.toml PEP 621 & Poetry) + Complex Version Ranges (^ and ~)
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List, Any

# Ensure parent directory is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from manifest_parser import (
    parse_manifest,
    parse_pyproject_toml,
    detect_manifest_type,
    DependencyRecord,
    ManifestParseResult,
    ParseIssue
)
from version_matcher import (
    VersionMatcher,
    match_dependency,
    match_dependencies,
    normalize_poetry_specifiers,
    _normalize_poetry_caret,
    _normalize_poetry_tilde,
    STATUS_CONFIRMED,
    STATUS_POTENTIAL,
    STATUS_UNRESOLVED,
)
from osv_client import OSVVulnerability, OSVAffectedRange, OSVQueryResult


def make_osv_result(package_name: str, vuln_id: str, events: List[Dict[str, str]], versions: List[str] = None) -> OSVQueryResult:
    vuln = OSVVulnerability(
        vuln_id=vuln_id,
        package_name=package_name,
        summary=f"Vulnerability in {package_name}",
        details="Advisory details",
        aliases=(f"CVE-2026-{vuln_id}",),
        database_specific={"severity": "HIGH"},
        severity=({"type": "CVSS_V3", "score": 8.5},),
        affected_ranges=(
            OSVAffectedRange(
                type="ECOSYSTEM",
                events=tuple(events),
                versions=tuple(versions or [])
            ),
        )
    )
    return OSVQueryResult(
        package_name=package_name,
        vulnerabilities=[vuln],
        source="cache"
    )


class TestVector2ManifestParser(unittest.TestCase):
    """Test pyproject.toml parsing: PEP 621 and Poetry schemas."""

    def test_fixture_a_pep621_project_dependencies(self):
        content = """
[project]
name = "demo-app"
version = "1.0.0"
dependencies = [
    "requests>=2.25.0,<3.0.0",
    "urllib3==1.26.5",
    "certifi",
]
"""
        res = parse_pyproject_toml(content)
        self.assertEqual(res.source_type, "pyproject.toml")
        self.assertFalse(res.has_issues)
        self.assertEqual(len(res.dependencies), 3)

        deps = {d.name: d for d in res.dependencies}
        self.assertIn("requests", deps)
        self.assertFalse(deps["requests"].pinned)
        from packaging.specifiers import SpecifierSet
        self.assertEqual(SpecifierSet(deps["requests"].version_specifier), SpecifierSet(">=2.25.0,<3.0.0"))

        self.assertIn("urllib3", deps)
        self.assertTrue(deps["urllib3"].pinned)
        self.assertEqual(deps["urllib3"].version, "1.26.5")
        self.assertEqual(deps["urllib3"].version_specifier, "==1.26.5")

        self.assertIn("certifi", deps)
        self.assertFalse(deps["certifi"].pinned)
        self.assertIsNone(deps["certifi"].version)

    def test_fixture_b_pep621_optional_dependencies(self):
        content = """
[project]
name = "demo-app"
version = "1.0.0"
dependencies = [
    "requests==2.25.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "black",
]
security = [
    "cryptography==3.4.8",
]
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)
        self.assertEqual(len(res.dependencies), 4)

        deps = {d.name: d for d in res.dependencies}
        self.assertEqual(deps["requests"].group, None)
        self.assertEqual(deps["pytest"].group, "dev")
        self.assertEqual(deps["black"].group, "dev")
        self.assertEqual(deps["cryptography"].group, "security")
        self.assertTrue(deps["cryptography"].pinned)
        self.assertEqual(deps["cryptography"].version, "3.4.8")

    def test_fixture_c_poetry_dependencies(self):
        content = """
[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.25.0"
urllib3 = "1.26.5"
flask = { version = "~2.0.1", extras = ["dotenv"], optional = true }
pathlib2 = { version = "^2.3", python = "<3.10" }
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)
        # python should be ignored from packages
        self.assertTrue(any("python" in d for d in res.ignored_directives))
        deps = {d.name: d for d in res.dependencies}
        self.assertNotIn("python", deps)
        self.assertEqual(len(deps), 4)

        # requests = "^2.25.0"
        self.assertIn("requests", deps)
        self.assertFalse(deps["requests"].pinned)
        self.assertEqual(deps["requests"].version_specifier, "^2.25.0")
        self.assertEqual(deps["requests"].group, "main")

        # urllib3 = "1.26.5" (Poetry bare version means pinned)
        self.assertIn("urllib3", deps)
        self.assertTrue(deps["urllib3"].pinned)
        self.assertEqual(deps["urllib3"].version, "1.26.5")
        self.assertEqual(deps["urllib3"].version_specifier, "==1.26.5")

        # flask table
        self.assertIn("flask", deps)
        self.assertFalse(deps["flask"].pinned)
        self.assertEqual(deps["flask"].version_specifier, "~2.0.1")
        self.assertEqual(deps["flask"].extras, ("dotenv",))

        # pathlib2 table with marker
        self.assertIn("pathlib2", deps)
        self.assertEqual(deps["pathlib2"].environment_marker, "<3.10")

    def test_fixture_d_poetry_dependency_groups(self):
        content = """
[tool.poetry.dependencies]
requests = "^2.25.0"

[tool.poetry.group.dev.dependencies]
flake8 = "^4.0.0"

[tool.poetry.group.test.dependencies]
pytest-cov = "^3.0.0"
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)
        deps = {d.name: d for d in res.dependencies}
        self.assertEqual(deps["requests"].group, "main")
        self.assertEqual(deps["flake8"].group, "dev")
        self.assertEqual(deps["pytest-cov"].group, "test")

    def test_pep735_dependency_groups(self):
        content = """
[project]
name = "pep735-demo"
dependencies = ["requests==2.25.0"]

[dependency-groups]
test = [
    "pytest>=7.0.0",
    { include-group = "lint" }
]
lint = [
    "flake8==4.0.1",
    "black"
]
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)
        deps = {f"{d.group}:{d.name}": d for d in res.dependencies}
        self.assertIn("None:requests", deps)
        self.assertIn("test:pytest", deps)
        self.assertIn("lint:flake8", deps)
        self.assertIn("lint:black", deps)
        self.assertEqual(deps["test:pytest"].version_specifier, ">=7.0.0")
        self.assertEqual(deps["lint:flake8"].version, "4.0.1")

    def test_poetry_environment_python_filtering(self):
        content = """
[tool.poetry.dependencies]
python = "^3.9"
requests = "2.25.0"
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)
        names = [d.name for d in res.dependencies]
        self.assertNotIn("python", names, "Interpreter constraint 'python' must NOT be in dependencies")
        self.assertIn("requests", names)
        self.assertTrue(any("python" in d for d in res.ignored_directives), "'python' must be recorded in ignored_directives")

    def test_legitimate_python_prefix_packages_not_filtered(self):
        content = """
[tool.poetry.dependencies]
python = ">=3.8,<4.0"
python-dateutil = "^2.8.2"
ipython = "^8.10.0"
gitpython = "3.1.30"
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)
        names = {d.name for d in res.dependencies}
        self.assertNotIn("python", names)
        self.assertIn("python-dateutil", names, "Legitimate package 'python-dateutil' must not be filtered")
        self.assertIn("ipython", names, "Legitimate package 'ipython' must not be filtered")
        self.assertIn("gitpython", names, "Legitimate package 'gitpython' must not be filtered")

    def test_fixture_e_pinned_dependency_forms(self):
        content = """
[project]
dependencies = [
    "django==4.2.0",
    "flask===2.0.1",
]

[tool.poetry.dependencies]
gunicorn = "==20.1.0"
uvicorn = "0.17.0"
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)
        deps = {d.name: d for d in res.dependencies}
        self.assertTrue(deps["django"].pinned)
        self.assertEqual(deps["django"].version, "4.2.0")

        self.assertTrue(deps["flask"].pinned)
        self.assertEqual(deps["flask"].version, "2.0.1")

        self.assertTrue(deps["gunicorn"].pinned)
        self.assertEqual(deps["gunicorn"].version, "20.1.0")

        self.assertTrue(deps["uvicorn"].pinned)
        self.assertEqual(deps["uvicorn"].version, "0.17.0")

    def test_fixture_f_unpinned_range_dependency_forms(self):
        content = """
[project]
dependencies = [
    "requests>=2.0.0",
    "urllib3~=1.26.0",
    "six!=1.15.0",
    "certifi",
]
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)
        deps = {d.name: d for d in res.dependencies}
        self.assertFalse(deps["requests"].pinned)
        self.assertIsNone(deps["requests"].version)
        self.assertEqual(deps["requests"].version_specifier, ">=2.0.0")

        self.assertFalse(deps["urllib3"].pinned)
        self.assertEqual(deps["urllib3"].version_specifier, "~=1.26.0")

        self.assertFalse(deps["six"].pinned)
        self.assertEqual(deps["six"].version_specifier, "!=1.15.0")

        self.assertFalse(deps["certifi"].pinned)
        self.assertIsNone(deps["certifi"].version_specifier)

    def test_fixture_g_malformed_toml(self):
        content = """
[project
name = "broken"
dependencies = [
"""
        res = parse_pyproject_toml(content)
        self.assertTrue(res.has_issues)
        self.assertEqual(len(res.dependencies), 0)
        self.assertEqual(res.issues[0].issue_type, "malformed")

    def test_fixture_h_unsupported_malformed_dependency_declaration(self):
        content = """
[project]
dependencies = [
    "valid-pkg==1.0.0",
    12345,
    "bad specifier ===???",
]

[tool.poetry.dependencies]
bad-record = 9999
"""
        res = parse_pyproject_toml(content)
        # Does not crash; extracts valid dependency and logs issues for invalid items
        deps = {d.name: d for d in res.dependencies}
        self.assertIn("valid-pkg", deps)
        self.assertTrue(res.has_issues)
        self.assertGreaterEqual(len(res.issues), 2)


class TestVector2PoetryCaretTildeSemantics(unittest.TestCase):
    """Test Poetry caret (^) and tilde (~) normalization and tri-state matching."""

    def test_poetry_caret_major_gt_zero(self):
        # ^2.25.0 -> >=2.25.0,<3.0.0
        norm = normalize_poetry_specifiers("^2.25.0")
        self.assertEqual(norm, ">=2.25.0,<3.0.0")

        # ^1.2.3 -> >=1.2.3,<2.0.0
        norm2 = normalize_poetry_specifiers("^1.2.3")
        self.assertEqual(norm2, ">=1.2.3,<2.0.0")

    def test_poetry_caret_major_zero_minor_gt_zero(self):
        # ^0.2.3 -> >=0.2.3,<0.3.0 (breaking change is minor version)
        norm = normalize_poetry_specifiers("^0.2.3")
        self.assertEqual(norm, ">=0.2.3,<0.3.0")
        self.assertNotEqual(norm, ">=0.2.3,<1.0.0", "Zero-major non-zero minor must NOT upper-bound to <1.0.0")
        self.assertNotIn("<1.0.0", norm)

    def test_poetry_caret_major_zero_minor_zero(self):
        # ^0.0.3 -> >=0.0.3,<0.0.4 (breaking change is patch version)
        norm = normalize_poetry_specifiers("^0.0.3")
        self.assertEqual(norm, ">=0.0.3,<0.0.4")
        self.assertNotEqual(norm, ">=0.0.3,<1.0.0", "Zero-major zero-minor must NOT upper-bound to <1.0.0")
        self.assertNotIn("<1.0.0", norm)
        self.assertNotIn("<0.1.0", norm)

        # ^0.0 -> >=0.0,<0.1.0
        norm2 = normalize_poetry_specifiers("^0.0")
        self.assertEqual(norm2, ">=0.0,<0.1.0")

        # ^0 -> >=0,<1.0.0
        norm3 = normalize_poetry_specifiers("^0")
        self.assertEqual(norm3, ">=0,<1.0.0")

    def test_poetry_tilde_semantics(self):
        # ~2.25.0 -> >=2.25.0,<2.26.0
        self.assertEqual(normalize_poetry_specifiers("~2.25.0"), ">=2.25.0,<2.26.0")

        # ~2.25 -> >=2.25,<2.26.0
        self.assertEqual(normalize_poetry_specifiers("~2.25"), ">=2.25,<2.26.0")

        # ~2 -> >=2,<3.0.0
        self.assertEqual(normalize_poetry_specifiers("~2"), ">=2,<3.0.0")

    def test_pep440_tilde_equal_untouched(self):
        # ~=2.25.0 is PEP 440, must NOT be modified
        self.assertEqual(normalize_poetry_specifiers("~=2.25.0"), "~=2.25.0")

    def test_compound_poetry_specifier(self):
        # ^2.25.0, !=2.26.1
        norm = normalize_poetry_specifiers("^2.25.0, !=2.26.1")
        self.assertEqual(norm, ">=2.25.0,<3.0.0,!=2.26.1")

    def test_caret_matching_tri_state(self):
        matcher = VersionMatcher()
        dep_overlap = DependencyRecord(name="requests", version=None, version_specifier="^2.25.0", pinned=False)
        # Advisory: [2.0.0, 2.26.0) -> overlap with ^2.25.0 [2.25.0, 3.0.0)
        osv_res = make_osv_result("requests", "GHSA-overlap", [{"introduced": "2.0.0"}, {"fixed": "2.26.0"}])
        findings = matcher.match_dependency(dep_overlap, osv_res)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_POTENTIAL)
        self.assertEqual(findings[0].confidence, 0.6)

        # Advisory: [3.0.0, 3.5.0) -> disjoint from ^2.25.0 [2.25.0, 3.0.0)
        osv_disjoint = make_osv_result("requests", "GHSA-disjoint", [{"introduced": "3.0.0"}, {"fixed": "3.5.0"}])
        findings_disjoint = matcher.match_dependency(dep_overlap, osv_disjoint)
        self.assertEqual(len(findings_disjoint), 0)

    def test_tilde_matching_tri_state(self):
        matcher = VersionMatcher()
        dep = DependencyRecord(name="urllib3", version=None, version_specifier="~1.26.0", pinned=False)
        # ~1.26.0 -> [1.26.0, 1.27.0)
        # Advisory: [1.25.0, 1.26.5) -> Overlap
        osv = make_osv_result("urllib3", "GHSA-tilde-overlap", [{"introduced": "1.25.0"}, {"fixed": "1.26.5"}])
        findings = matcher.match_dependency(dep, osv)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_POTENTIAL)

        # Advisory: [1.27.0, 2.0.0) -> Disjoint
        osv_disjoint = make_osv_result("urllib3", "GHSA-tilde-disjoint", [{"introduced": "1.27.0"}, {"fixed": "2.0.0"}])
        findings_disjoint = matcher.match_dependency(dep, osv_disjoint)
        self.assertEqual(len(findings_disjoint), 0)


class TestVector2VersionRangeBoundaries(unittest.TestCase):
    """Test precise interval boundary conditions (introduced, fixed, below fixed, above introduced)."""

    def setUp(self):
        self.matcher = VersionMatcher()

    def test_boundary_pinned_fixed_exactly(self):
        # Advisory: [1.0.0, 2.0.0). Pinned == 2.0.0 is fixed exactly -> CLEAN
        dep = DependencyRecord(name="pkg", version="2.0.0", version_specifier="==2.0.0", pinned=True)
        osv = make_osv_result("pkg", "GHSA-bound-1", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}])
        findings = self.matcher.match_dependency(dep, osv)
        self.assertEqual(len(findings), 0)

    def test_boundary_pinned_immediately_below_fixed(self):
        # Advisory: [1.0.0, 2.0.0). Pinned == 1.9.9 -> CONFIRMED
        dep = DependencyRecord(name="pkg", version="1.9.9", version_specifier="==1.9.9", pinned=True)
        osv = make_osv_result("pkg", "GHSA-bound-2", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}])
        findings = self.matcher.match_dependency(dep, osv)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_CONFIRMED)
        self.assertEqual(findings[0].confidence, 1.0)

    def test_boundary_pinned_introduced_exactly(self):
        # Advisory: [1.0.0, 2.0.0). Pinned == 1.0.0 -> CONFIRMED
        dep = DependencyRecord(name="pkg", version="1.0.0", version_specifier="==1.0.0", pinned=True)
        osv = make_osv_result("pkg", "GHSA-bound-3", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}])
        findings = self.matcher.match_dependency(dep, osv)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_CONFIRMED)

    def test_boundary_pinned_immediately_below_introduced(self):
        # Advisory: [1.0.0, 2.0.0). Pinned == 0.9.9 -> CLEAN
        dep = DependencyRecord(name="pkg", version="0.9.9", version_specifier="==0.9.9", pinned=True)
        osv = make_osv_result("pkg", "GHSA-bound-4", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}])
        findings = self.matcher.match_dependency(dep, osv)
        self.assertEqual(len(findings), 0)

    def test_range_compound_specifiers(self):
        # >=2.25.0,<2.33.0 vs [2.0.0, 2.28.0) -> POTENTIAL
        dep1 = DependencyRecord(name="pkg", version=None, version_specifier=">=2.25.0,<2.33.0", pinned=False)
        osv1 = make_osv_result("pkg", "GHSA-rng-1", [{"introduced": "2.0.0"}, {"fixed": "2.28.0"}])
        res1 = self.matcher.match_dependency(dep1, osv1)
        self.assertEqual(len(res1), 1)
        self.assertEqual(res1[0].status, STATUS_POTENTIAL)

        # >=2.33.0,<3.0.0 vs [2.0.0, 2.28.0) -> DISJOINT (CLEAN)
        dep2 = DependencyRecord(name="pkg", version=None, version_specifier=">=2.33.0,<3.0.0", pinned=False)
        res2 = self.matcher.match_dependency(dep2, osv1)
        self.assertEqual(len(res2), 0)

    def test_unbounded_range_and_wildcards(self):
        # >=2.0.0 vs [1.0.0, 2.5.0) -> POTENTIAL
        dep1 = DependencyRecord(name="pkg", version=None, version_specifier=">=2.0.0", pinned=False)
        osv1 = make_osv_result("pkg", "GHSA-rng-2", [{"introduced": "1.0.0"}, {"fixed": "2.5.0"}])
        res1 = self.matcher.match_dependency(dep1, osv1)
        self.assertEqual(len(res1), 1)
        self.assertEqual(res1[0].status, STATUS_POTENTIAL)

        # ==2.* vs [1.0.0, 2.5.0) -> POTENTIAL
        dep2 = DependencyRecord(name="pkg", version=None, version_specifier="==2.*", pinned=False)
        res2 = self.matcher.match_dependency(dep2, osv1)
        self.assertEqual(len(res2), 1)
        self.assertEqual(res2[0].status, STATUS_POTENTIAL)

        # ==2.* vs [3.0.0, 4.0.0) -> DISJOINT
        osv2 = make_osv_result("pkg", "GHSA-rng-3", [{"introduced": "3.0.0"}, {"fixed": "4.0.0"}])
        res3 = self.matcher.match_dependency(dep2, osv2)
        self.assertEqual(len(res3), 0)

        # * bare wildcard vs [1.0.0, 2.0.0) -> POTENTIAL
        dep3 = DependencyRecord(name="pkg", version=None, version_specifier="*", pinned=False)
        res4 = self.matcher.match_dependency(dep3, osv1)
        self.assertEqual(len(res4), 1)
        self.assertEqual(res4[0].status, STATUS_POTENTIAL)

    def test_exclusion_range(self):
        # >=1.0,<2.0,!=1.5 vs [1.5.0, 1.5.1) -> outer bounds touch, witness probe:
        dep = DependencyRecord(name="pkg", version=None, version_specifier=">=1.0,<2.0,!=1.5", pinned=False)
        osv = make_osv_result("pkg", "GHSA-ex-1", [{"introduced": "1.0.0"}, {"fixed": "1.4.0"}])
        res = self.matcher.match_dependency(dep, osv)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].status, STATUS_POTENTIAL)


class TestVector2CliDiscoveryAndIntegration(unittest.TestCase):
    """Test CLI discovery and end-to-end processing of pyproject.toml."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="tcs_v2_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_fixture_i_nested_directory_discovery(self):
        from tcs_cli import discover_manifest_files

        # Create nested structure:
        # root/
        #   sub/
        #     pyproject.toml
        sub_dir = Path(self.test_dir) / "services" / "app"
        sub_dir.mkdir(parents=True)
        pyproj = sub_dir / "pyproject.toml"
        pyproj.write_text("""
[project]
dependencies = ["requests==2.25.0"]
""", encoding="utf-8")

        manifests = discover_manifest_files(Path(self.test_dir), Path(self.test_dir))
        self.assertEqual(len(manifests), 1)
        self.assertEqual(manifests[0].name, "pyproject.toml")

    def test_fixture_j_multiple_manifests_in_one_repo(self):
        from tcs_cli import discover_manifest_files

        # Create requirements.txt and pyproject.toml
        req_file = Path(self.test_dir) / "requirements.txt"
        req_file.write_text("urllib3==1.26.5\n", encoding="utf-8")

        pyproj = Path(self.test_dir) / "pyproject.toml"
        pyproj.write_text("""
[tool.poetry.dependencies]
requests = "^2.25.0"
""", encoding="utf-8")

        manifests = discover_manifest_files(Path(self.test_dir), Path(self.test_dir))
        self.assertEqual(len(manifests), 2)
        names = {m.name for m in manifests}
        self.assertEqual(names, {"requirements.txt", "pyproject.toml"})

    def test_detect_manifest_type_pyproject(self):
        self.assertEqual(detect_manifest_type("pyproject.toml"), "pyproject.toml")
        self.assertEqual(detect_manifest_type("/path/to/pyproject.toml"), "pyproject.toml")

    def test_cli_end_to_end_pyproject_scan(self):
        import subprocess
        cache_data = {
            "requests": [
                {
                    "id": "GHSA-j8r2-6x86-q33q",
                    "summary": "Requests vulnerable",
                    "affected": [
                        {
                            "package": {"name": "requests", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}]
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        cache_file = Path(self.test_dir) / "osv_cache.json"
        cache_file.write_text(json.dumps(cache_data), encoding="utf-8")

        pyproj = Path(self.test_dir) / "pyproject.toml"
        pyproj.write_text("""
[tool.poetry.dependencies]
requests = "^2.25.0"
""", encoding="utf-8")

        cmd = [
            sys.executable,
            str(REPO_ROOT / "tcs_cli.py"),
            self.test_dir,
            "--sca",
            "--sca-offline",
            "--sca-cache", str(cache_file),
            "--format", "json"
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(proc.returncode, 1)
        data = json.loads(proc.stdout)
        self.assertEqual(data["summary"]["manifests_scanned"], 1)
        self.assertEqual(data["summary"]["sca_vulnerabilities"], 1)
        self.assertEqual(data["summary"]["sca_potential"], 1)
        self.assertEqual(data["sca_findings"][0]["package_name"], "requests")
        self.assertEqual(data["sca_findings"][0]["manifest_source"], "pyproject.toml")
        self.assertEqual(data["sca_findings"][0]["status"], "POTENTIAL")

    def test_cli_end_to_end_pyproject_clean(self):
        import subprocess
        cache_data = {
            "requests": [
                {
                    "id": "GHSA-j8r2-6x86-q33q",
                    "summary": "Requests vulnerable",
                    "affected": [
                        {
                            "package": {"name": "requests", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}]
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        cache_file = Path(self.test_dir) / "osv_cache.json"
        cache_file.write_text(json.dumps(cache_data), encoding="utf-8")

        pyproj = Path(self.test_dir) / "pyproject.toml"
        pyproj.write_text("""
[project]
dependencies = [
    "requests==2.32.4"
]
""", encoding="utf-8")

        cmd = [
            sys.executable,
            str(REPO_ROOT / "tcs_cli.py"),
            self.test_dir,
            "--sca",
            "--sca-offline",
            "--sca-cache", str(cache_file),
            "--format", "json"
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["summary"]["manifests_scanned"], 1)
        self.assertEqual(data["summary"]["sca_vulnerabilities"], 0)

    def test_cli_end_to_end_pyproject_direct_target(self):
        import subprocess
        cache_data = {
            "requests": [
                {
                    "id": "GHSA-j8r2-6x86-q33q",
                    "summary": "Requests vulnerable",
                    "affected": [
                        {
                            "package": {"name": "requests", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}]
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        cache_file = Path(self.test_dir) / "osv_cache.json"
        cache_file.write_text(json.dumps(cache_data), encoding="utf-8")

        pyproj = Path(self.test_dir) / "pyproject.toml"
        pyproj.write_text("""
[tool.poetry.dependencies]
requests = "2.25.0"
""", encoding="utf-8")

        cmd = [
            sys.executable,
            str(REPO_ROOT / "tcs_cli.py"),
            str(pyproj),
            "--sca",
            "--sca-offline",
            "--sca-cache", str(cache_file),
            "--format", "json"
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(proc.returncode, 1)
        data = json.loads(proc.stdout)
        self.assertEqual(data["summary"]["manifests_scanned"], 1)
        self.assertEqual(data["summary"]["sca_confirmed"], 1)


class TestVector2Adversarial(unittest.TestCase):
    """Adversarial stress testing on pyproject.toml and ranges."""

    def test_adversarial_malformed_toml_does_not_crash(self):
        garbage = "[[[this is not valid toml %%% &&& \x00"
        # Binary NUL might be caught before or by loads
        res = parse_pyproject_toml(garbage)
        self.assertTrue(res.has_issues)

    def test_adversarial_empty_dependencies(self):
        content = """
[project]
name = "empty"
dependencies = []

[tool.poetry.dependencies]
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)
        self.assertEqual(len(res.dependencies), 0)

    def test_adversarial_duplicate_dependencies(self):
        content = """
[project]
dependencies = [
    "requests==2.25.0",
    "requests>=2.26.0",
]
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)
        self.assertEqual(len(res.dependencies), 2)

    def test_adversarial_invalid_version_specifiers(self):
        matcher = VersionMatcher()
        dep = DependencyRecord(name="bad", version=None, version_specifier="===???invalid", pinned=False)
        osv = make_osv_result("bad", "GHSA-bad", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}])
        findings = matcher.match_dependency(dep, osv)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_UNRESOLVED)

    def test_adversarial_conflicting_range(self):
        # Range internally unsatisfiable >=2.0,<1.0 -> PROVEN_DISJOINT (0 findings)
        matcher = VersionMatcher()
        dep = DependencyRecord(name="pkg", version=None, version_specifier=">=2.0,<1.0", pinned=False)
        osv = make_osv_result("pkg", "GHSA-conflict", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}])
        findings = matcher.match_dependency(dep, osv)
        self.assertEqual(len(findings), 0)


class TestVector2CaretSemanticOracles(unittest.TestCase):
    """
    Direct semantic oracle tests for Poetry caret (^) constraints.
    Verifies actual mathematical interval membership for all 6 canonical forms:
    1. ^2.25.0
    2. ^1.2.3
    3. ^0.2.3
    4. ^0.0.3
    5. ^0.0
    6. ^0
    For each:
    - exact lower boundary (INCLUDED)
    - just below lower boundary (EXCLUDED)
    - valid internal version (INCLUDED)
    - exact upper boundary (EXCLUDED)
    - just below upper boundary (INCLUDED)
    - just above upper boundary (EXCLUDED)
    """
    def _check_membership(self, spec_str: str, version_str: str) -> bool:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version
        spec = SpecifierSet(normalize_poetry_specifiers(spec_str))
        return Version(version_str) in spec

    def test_oracle_caret_2_25_0(self):
        # ^2.25.0 -> [2.25.0, 3.0.0)
        spec = "^2.25.0"
        self.assertTrue(self._check_membership(spec, "2.25.0"), "Exact lower boundary must be included")
        self.assertFalse(self._check_membership(spec, "2.24.9"), "Just below lower boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "2.28.1"), "Valid internal version must be included")
        self.assertFalse(self._check_membership(spec, "3.0.0"), "Exact upper boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "2.99.99"), "Just below upper boundary must be included")
        self.assertFalse(self._check_membership(spec, "3.0.1"), "Just above upper boundary must be excluded")

    def test_oracle_caret_1_2_3(self):
        # ^1.2.3 -> [1.2.3, 2.0.0)
        spec = "^1.2.3"
        self.assertTrue(self._check_membership(spec, "1.2.3"), "Exact lower boundary must be included")
        self.assertFalse(self._check_membership(spec, "1.2.2"), "Just below lower boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "1.7.0"), "Valid internal version must be included")
        self.assertFalse(self._check_membership(spec, "2.0.0"), "Exact upper boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "1.99.99"), "Just below upper boundary must be included")
        self.assertFalse(self._check_membership(spec, "2.0.1"), "Just above upper boundary must be excluded")

    def test_oracle_caret_0_2_3(self):
        # ^0.2.3 -> [0.2.3, 0.3.0)
        spec = "^0.2.3"
        self.assertTrue(self._check_membership(spec, "0.2.3"), "Exact lower boundary must be included")
        self.assertFalse(self._check_membership(spec, "0.2.2"), "Just below lower boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "0.2.9"), "Valid internal version must be included")
        self.assertFalse(self._check_membership(spec, "0.3.0"), "Exact upper boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "0.2.99"), "Just below upper boundary must be included")
        self.assertFalse(self._check_membership(spec, "0.3.1"), "Just above upper boundary must be excluded")

    def test_oracle_caret_0_0_3(self):
        # ^0.0.3 -> [0.0.3, 0.0.4)
        spec = "^0.0.3"
        self.assertTrue(self._check_membership(spec, "0.0.3"), "Exact lower boundary must be included")
        self.assertFalse(self._check_membership(spec, "0.0.2"), "Just below lower boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "0.0.3.post1"), "Valid internal version must be included")
        self.assertFalse(self._check_membership(spec, "0.0.4"), "Exact upper boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "0.0.3"), "Just below upper boundary must be included")
        self.assertFalse(self._check_membership(spec, "0.0.5"), "Just above upper boundary must be excluded")

    def test_oracle_caret_0_0(self):
        # ^0.0 -> [0.0, 0.1.0)
        spec = "^0.0"
        self.assertTrue(self._check_membership(spec, "0.0"), "Exact lower boundary must be included")
        self.assertTrue(self._check_membership(spec, "0.0.8"), "Valid internal version must be included")
        self.assertFalse(self._check_membership(spec, "0.1.0"), "Exact upper boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "0.0.99"), "Just below upper boundary must be included")
        self.assertFalse(self._check_membership(spec, "0.1.1"), "Just above upper boundary must be excluded")

    def test_oracle_caret_0(self):
        # ^0 -> [0, 1.0.0)
        spec = "^0"
        self.assertTrue(self._check_membership(spec, "0"), "Exact lower boundary must be included")
        self.assertTrue(self._check_membership(spec, "0.8.4"), "Valid internal version must be included")
        self.assertFalse(self._check_membership(spec, "1.0.0"), "Exact upper boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "0.99.99"), "Just below upper boundary must be included")
        self.assertFalse(self._check_membership(spec, "1.0.1"), "Just above upper boundary must be excluded")


class TestVector2TildeSemanticOracles(unittest.TestCase):
    """
    Direct semantic oracle tests for Poetry tilde (~) constraints:
    1. ~2.25.0
    2. ~2.25
    3. ~2
    For each, verifies the 6 canonical boundary conditions:
    - exact lower boundary (INCLUDED)
    - just below lower (EXCLUDED)
    - internal version (INCLUDED)
    - exact upper boundary (EXCLUDED)
    - just below upper (INCLUDED)
    - just above upper (EXCLUDED)
    """
    def _check_membership(self, spec_str: str, version_str: str) -> bool:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version
        spec = SpecifierSet(normalize_poetry_specifiers(spec_str))
        return Version(version_str) in spec

    def test_oracle_tilde_2_25_0(self):
        # ~2.25.0 -> allows patch-level updates: [2.25.0, 2.26.0)
        spec = "~2.25.0"
        self.assertTrue(self._check_membership(spec, "2.25.0"), "Exact lower boundary must be included")
        self.assertFalse(self._check_membership(spec, "2.24.9"), "Just below lower boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "2.25.5"), "Valid internal version must be included")
        self.assertFalse(self._check_membership(spec, "2.26.0"), "Exact upper boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "2.25.99"), "Just below upper boundary must be included")
        self.assertFalse(self._check_membership(spec, "2.26.1"), "Just above upper boundary must be excluded")

    def test_oracle_tilde_2_25(self):
        # ~2.25 -> allows patch-level updates: [2.25.0, 2.26.0)
        spec = "~2.25"
        self.assertTrue(self._check_membership(spec, "2.25"), "Exact lower boundary must be included")
        self.assertFalse(self._check_membership(spec, "2.24.9"), "Just below lower boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "2.25.9"), "Valid internal version must be included")
        self.assertFalse(self._check_membership(spec, "2.26.0"), "Exact upper boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "2.25.99"), "Just below upper boundary must be included")
        self.assertFalse(self._check_membership(spec, "2.26.1"), "Just above upper boundary must be excluded")

    def test_oracle_tilde_2(self):
        # ~2 -> allows minor- and patch-level updates: [2.0.0, 3.0.0)
        spec = "~2"
        self.assertTrue(self._check_membership(spec, "2"), "Exact lower boundary must be included")
        self.assertFalse(self._check_membership(spec, "1.99.99"), "Just below lower boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "2.9.1"), "Valid internal version must be included")
        self.assertFalse(self._check_membership(spec, "3.0.0"), "Exact upper boundary must be excluded")
        self.assertTrue(self._check_membership(spec, "2.99.99"), "Just below upper boundary must be included")
        self.assertFalse(self._check_membership(spec, "3.0.1"), "Just above upper boundary must be excluded")


class TestVector2SecurityInvariants(unittest.TestCase):
    """
    Rigorous verification of the 6 core VersionMatcher security invariants:
    1. Proven disjoint range -> no finding
    2. Proven exact vulnerable pin -> CONFIRMED (1.0 confidence)
    3. Overlapping non-pinned range -> POTENTIAL (0.6 confidence)
    4. Ambiguous/invalid specifier -> UNRESOLVED (0.0 confidence)
    5. Invalid specifier must never silently become CLEAN
    6. Range witness probing must not upgrade a non-pinned range to CONFIRMED
    """
    def setUp(self):
        self.matcher = VersionMatcher()

    def test_invariant_1_proven_disjoint_range_yields_no_finding(self):
        dep = DependencyRecord(name="pkg", version=None, version_specifier=">=3.0.0,<4.0.0", pinned=False)
        osv = make_osv_result("pkg", "GHSA-inv1", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}])
        findings = self.matcher.match_dependency(dep, osv)
        self.assertEqual(len(findings), 0, "Disjoint range must produce zero findings")

    def test_invariant_2_proven_exact_vulnerable_pin_yields_confirmed(self):
        dep = DependencyRecord(name="pkg", version="1.5.0", version_specifier="==1.5.0", pinned=True)
        osv = make_osv_result("pkg", "GHSA-inv2", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}])
        findings = self.matcher.match_dependency(dep, osv)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_CONFIRMED)
        self.assertEqual(findings[0].confidence, 1.0)

    def test_invariant_3_overlapping_non_pinned_range_yields_potential(self):
        dep = DependencyRecord(name="pkg", version=None, version_specifier="^1.5.0", pinned=False)
        # ^1.5.0 is [1.5.0, 2.0.0), advisory is [1.0.0, 1.8.0)
        osv = make_osv_result("pkg", "GHSA-inv3", [{"introduced": "1.0.0"}, {"fixed": "1.8.0"}])
        findings = self.matcher.match_dependency(dep, osv)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_POTENTIAL)
        self.assertEqual(findings[0].confidence, 0.6)

    def test_invariant_4_and_5_ambiguous_invalid_specifier_yields_unresolved_never_clean(self):
        dep = DependencyRecord(name="pkg", version=None, version_specifier="invalid@@@syntax!!", pinned=False)
        osv = make_osv_result("pkg", "GHSA-inv4", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}])
        findings = self.matcher.match_dependency(dep, osv)
        self.assertEqual(len(findings), 1, "Must never silently become CLEAN")
        self.assertEqual(findings[0].status, STATUS_UNRESOLVED)
        self.assertEqual(findings[0].confidence, 0.0)

    def test_invariant_6_range_witness_probing_never_upgrades_range_to_confirmed(self):
        # A range that contains an exact witness version must remain POTENTIAL, never CONFIRMED
        dep = DependencyRecord(name="pkg", version=None, version_specifier=">=1.0.0,<2.0.0", pinned=False)
        osv = make_osv_result("pkg", "GHSA-inv6", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}], versions=["1.5.0"])
        findings = self.matcher.match_dependency(dep, osv)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_POTENTIAL, "Range must never be upgraded to CONFIRMED")
        self.assertEqual(findings[0].confidence, 0.6)


class TestVector2DiscoveryIntegrationExtra(unittest.TestCase):
    """Test mixed manifest discovery and Vector 3 resource limiting on pyproject.toml."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="tcs_v2_disc_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_discovery_pyproject_and_requirements(self):
        from tcs_cli import discover_manifest_files
        (Path(self.test_dir) / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")
        (Path(self.test_dir) / "pyproject.toml").write_text('[project]\ndependencies = ["urllib3==1.26.5"]\n', encoding="utf-8")
        manifests = discover_manifest_files(Path(self.test_dir), Path(self.test_dir))
        names = {m.name for m in manifests}
        self.assertEqual(names, {"requirements.txt", "pyproject.toml"})

    def test_discovery_pyproject_and_poetry_lock(self):
        from tcs_cli import discover_manifest_files
        (Path(self.test_dir) / "pyproject.toml").write_text('[tool.poetry.dependencies]\nrequests = "^2.25.0"\n', encoding="utf-8")
        (Path(self.test_dir) / "poetry.lock").write_text('[[package]]\nname = "requests"\nversion = "2.25.0"\n', encoding="utf-8")
        manifests = discover_manifest_files(Path(self.test_dir), Path(self.test_dir))
        names = {m.name for m in manifests}
        self.assertEqual(names, {"pyproject.toml", "poetry.lock"})

    def test_coexistence_pyproject_and_poetry_lock_scan_both_json_and_sarif(self):
        # Scenario: A repo has both pyproject.toml and poetry.lock in the same directory.
        # Proves:
        # 1. Both manifests are scanned.
        # 2. Both findings are preserved with distinct manifest provenance:
        #    - pyproject.toml yields POTENTIAL (from ^2.25.0 range)
        #    - poetry.lock yields CONFIRMED (from 2.25.0 pin)
        # 3. SARIF deduplicates driver.rules for shared advisory ID and produces 2 distinct results.
        import subprocess
        (Path(self.test_dir) / "pyproject.toml").write_text('[tool.poetry.dependencies]\nrequests = "^2.25.0"\n', encoding="utf-8")
        (Path(self.test_dir) / "poetry.lock").write_text('[[package]]\nname = "requests"\nversion = "2.25.0"\n', encoding="utf-8")

        cache_file = Path(self.test_dir) / "cache.json"
        cache_file.write_text(json.dumps({
            "requests": [{
                "id": "GHSA-shared-coexist",
                "summary": "Requests CVE",
                "affected": [{
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.26.0"}]}]
                }]
            }]
        }), encoding="utf-8")

        # 1. Test JSON format
        cmd_json = [
            sys.executable,
            str(REPO_ROOT / "tcs_cli.py"),
            self.test_dir,
            "--sca",
            "--sca-offline",
            "--sca-cache", str(cache_file),
            "--format", "json"
        ]
        proc_json = subprocess.run(cmd_json, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(proc_json.returncode, 1)
        data = json.loads(proc_json.stdout)
        self.assertEqual(data["summary"]["manifests_scanned"], 2)
        self.assertEqual(data["summary"]["sca_vulnerabilities"], 2)
        self.assertEqual(data["summary"]["sca_confirmed"], 1)
        self.assertEqual(data["summary"]["sca_potential"], 1)

        # Verify distinct manifest provenance
        sources = {f["manifest_source"] for f in data["sca_findings"]}
        self.assertEqual(sources, {"pyproject.toml", "poetry.lock"})
        pyproj_f = next(f for f in data["sca_findings"] if f["manifest_source"] == "pyproject.toml")
        lock_f = next(f for f in data["sca_findings"] if f["manifest_source"] == "poetry.lock")
        self.assertEqual(pyproj_f["status"], "POTENTIAL")
        self.assertEqual(pyproj_f["confidence"], 0.6)
        self.assertEqual(lock_f["status"], "CONFIRMED")
        self.assertEqual(lock_f["confidence"], 1.0)

        # 2. Test SARIF format
        cmd_sarif = [
            sys.executable,
            str(REPO_ROOT / "tcs_cli.py"),
            self.test_dir,
            "--sca",
            "--sca-offline",
            "--sca-cache", str(cache_file),
            "--format", "sarif"
        ]
        proc_sarif = subprocess.run(cmd_sarif, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(proc_sarif.returncode, 1)
        sarif = json.loads(proc_sarif.stdout)
        run = sarif["runs"][0]
        # Rules must deduplicate the shared advisory
        sca_rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"] if r["id"] == "GHSA-shared-coexist"]
        self.assertEqual(len(sca_rule_ids), 1, "Shared SCA rule must be deduplicated in driver.rules")
        # Results must contain both distinct findings pointing to their respective files
        self.assertEqual(len(run["results"]), 2)
        result_uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]}
        self.assertEqual(result_uris, {"pyproject.toml", "poetry.lock"})

    def test_discovery_giant_pyproject_skipped_by_vector3_limit(self):
        from tcs_cli import discover_manifest_files
        giant = Path(self.test_dir) / "pyproject.toml"
        # Write >1MB file
        with open(giant, "wb") as f:
            f.write(b"# giant file\n" + b" " * (1024 * 1024 + 10))
        manifests = discover_manifest_files(Path(self.test_dir), Path(self.test_dir))
        self.assertEqual(len(manifests), 0, "Giant pyproject.toml > 1MB must be skipped by Vector 3 resource bounding")

    def test_discovery_minified_pyproject_skipped_by_vector3_limit(self):
        from tcs_cli import discover_manifest_files
        minified = Path(self.test_dir) / "pyproject.toml"
        # Write single line > 10,000 chars
        with open(minified, "w", encoding="utf-8") as f:
            f.write("# " + "x" * 10500 + "\n")
        manifests = discover_manifest_files(Path(self.test_dir), Path(self.test_dir))
        self.assertEqual(len(manifests), 0, "Minified pyproject.toml with >10k char line must be skipped by Vector 3 limit")


class TestVector2FailureSemantics(unittest.TestCase):
    """
    Ensure explicit failure classifications:
    - MALFORMED: ParseIssue logged, CLI does not crash
    - UNSUPPORTED: invalid dependency structures record ParseIssue
    - UNRESOLVED: unparseable specifiers yield UNRESOLVED finding (confidence 0.0)
    - CLEAN: proven safe version yields 0 findings
    - Path/VCS dependencies: non-versioned records do not produce phantom CLEAN when advisory exists
    """
    def test_malformed_toml_issue_type(self):
        res = parse_pyproject_toml("[unclosed table\nx = 1")
        self.assertTrue(res.has_issues)
        self.assertEqual(res.issues[0].issue_type, "malformed")

    def test_unsupported_poetry_structure_issue_type(self):
        content = """
[tool.poetry.dependencies]
invalid-num = 12345
"""
        res = parse_pyproject_toml(content)
        self.assertTrue(res.has_issues)
        self.assertEqual(res.issues[0].issue_type, "malformed")

    def test_path_vcs_dependency_not_silently_clean(self):
        # Local path dependency with no version specifier
        content = """
[tool.poetry.dependencies]
local-pkg = { path = "../local-pkg" }
"""
        res = parse_pyproject_toml(content)
        self.assertEqual(len(res.dependencies), 1)
        dep = res.dependencies[0]
        self.assertFalse(dep.pinned)
        self.assertIsNone(dep.version)

        # When matched against an advisory for local-pkg, it must be POTENTIAL (not CLEAN)
        matcher = VersionMatcher()
        osv = make_osv_result("local-pkg", "GHSA-local-1", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}])
        findings = matcher.match_dependency(dep, osv)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_POTENTIAL, "Unversioned path dep must evaluate to POTENTIAL, never false CLEAN")

    def test_unresolved_version_identity_semantics(self):
        # Explicit contract verification:
        # UNRESOLVED VERSION IDENTITY -> conservative POTENTIAL when an advisory may apply.
        content = """
[tool.poetry.dependencies]
vcs-pkg = { git = "https://github.com/example/vcs-pkg.git", branch = "main" }
"""
        res = parse_pyproject_toml(content)
        self.assertEqual(len(res.dependencies), 1)
        dep = res.dependencies[0]
        self.assertIsNone(dep.version)
        self.assertIsNone(dep.version_specifier)

        matcher = VersionMatcher()
        # Case A: Advisory exists -> conservative POTENTIAL
        osv_vuln = make_osv_result("vcs-pkg", "GHSA-vcs-1", [{"introduced": "0.1.0"}, {"fixed": "1.0.0"}])
        findings = matcher.match_dependency(dep, osv_vuln)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_POTENTIAL)

        # Case B: No advisory exists -> CLEAN (0 findings)
        from osv_client import OSVQueryResult
        osv_clean = OSVQueryResult(package_name="vcs-pkg", vulnerabilities=[], source="cache")
        clean_findings = matcher.match_dependency(dep, osv_clean)
        self.assertEqual(len(clean_findings), 0)


class TestVector2PEP735IncludeGroups(unittest.TestCase):
    """
    Dedicated tests for PEP 735 include-group functionality:
    A. direct include
    B. nested include
    C. missing included group
    D. circular include
    E. three-level circular include
    F. normalized-name collision
    G. duplicate include
    H. include mixed with ordinary requirements
    I. vulnerable dependency inside included group
    J. malformed include structure (unexpected keys, invalid values)
    """

    def test_a_direct_include(self):
        content = """
[dependency-groups]
base = ["requests==2.25.0"]
test = ["pytest", { include-group = "base" }]
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)
        test_deps = [d for d in res.dependencies if d.group == "test"]
        test_pkg_map = {d.name: d for d in test_deps}
        self.assertIn("pytest", test_pkg_map)
        self.assertIn("requests", test_pkg_map)
        self.assertEqual(test_pkg_map["requests"].version, "2.25.0")
        self.assertTrue(test_pkg_map["requests"].pinned)

    def test_b_nested_include(self):
        content = """
[dependency-groups]
base = ["requests"]
security = [{ include-group = "base" }, "bandit"]
test = [{ include-group = "security" }]
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)
        test_deps = [d for d in res.dependencies if d.group == "test"]
        test_pkgs = {d.name for d in test_deps}
        self.assertEqual(test_pkgs, {"requests", "bandit"})

    def test_c_missing_included_group(self):
        content = """
[dependency-groups]
test = ["pytest", { include-group = "nonexistent" }]
"""
        res = parse_pyproject_toml(content)
        self.assertTrue(res.has_issues)
        self.assertTrue(any("nonexistent" in issue.message for issue in res.issues))
        # Valid dependency pytest is still preserved
        test_deps = [d for d in res.dependencies if d.group == "test"]
        self.assertEqual(len(test_deps), 1)
        self.assertEqual(test_deps[0].name, "pytest")

    def test_d_circular_include(self):
        content = """
[dependency-groups]
a = [{ include-group = "b" }]
b = [{ include-group = "a" }]
unrelated = ["certifi==2023.7.22"]
"""
        res = parse_pyproject_toml(content)
        self.assertTrue(res.has_issues)
        self.assertTrue(any("Circular dependency-group include" in issue.message for issue in res.issues))
        # Unrelated valid group is preserved
        unrelated_deps = [d for d in res.dependencies if d.group == "unrelated"]
        self.assertEqual(len(unrelated_deps), 1)
        self.assertEqual(unrelated_deps[0].name, "certifi")

    def test_e_three_level_circular_include(self):
        content = """
[dependency-groups]
a = [{ include-group = "b" }]
b = [{ include-group = "c" }]
c = [{ include-group = "a" }]
"""
        res = parse_pyproject_toml(content)
        self.assertTrue(res.has_issues)
        cycle_issues = [i for i in res.issues if "Circular dependency-group include" in i.message]
        self.assertTrue(len(cycle_issues) > 0)
        self.assertIn("a -> b -> c -> a", cycle_issues[0].message)

    def test_f_normalized_name_collision(self):
        content = """
[dependency-groups]
Test = ["pytest"]
test = ["ruff"]
"""
        res = parse_pyproject_toml(content)
        self.assertTrue(res.has_issues)
        self.assertTrue(any("Duplicate or colliding" in i.message for i in res.issues))

    def test_g_duplicate_include(self):
        content = """
[dependency-groups]
base = ["requests==2.25.0"]
test = ["pytest", { include-group = "base" }, { include-group = "base" }]
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)
        test_deps = [d for d in res.dependencies if d.group == "test"]
        # Per PEP 735, include expansion is syntactic and must NOT deduplicate
        requests_in_test = [d for d in test_deps if d.name == "requests"]
        self.assertEqual(len(requests_in_test), 2, "Both occurrences of included group must be preserved")
        self.assertEqual(requests_in_test[0].version, "2.25.0")
        self.assertEqual(requests_in_test[1].version, "2.25.0")

    def test_k_diamond_include_graph(self):
        # A -> B, A -> dev(B): test includes base directly and via dev
        content = """
[dependency-groups]
base = ["foo"]
dev = [{ include-group = "base" }]
test = [{ include-group = "base" }, { include-group = "dev" }]
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues, "Diamond include graph must not trigger cycle detection")
        test_deps = [d for d in res.dependencies if d.group == "test"]
        foo_in_test = [d for d in test_deps if d.name == "foo"]
        self.assertEqual(len(foo_in_test), 2, "Both foo occurrences must be preserved in test group")
        self.assertEqual([d.name for d in foo_in_test], ["foo", "foo"])

    def test_l_diamond_four_node_cycle_defense(self):
        # Cycle defense must only trigger when currently resolving group appears in ACTIVE ancestry
        # A -> B -> D, A -> C -> D
        content = """
[dependency-groups]
d = ["dep-d"]
b = [{ include-group = "d" }]
c = [{ include-group = "d" }]
a = [{ include-group = "b" }, { include-group = "c" }]
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues, "D appearing through both branches B and C is valid, never circular")
        a_deps = [d for d in res.dependencies if d.group == "a"]
        self.assertEqual(len(a_deps), 2)
        self.assertEqual([d.name for d in a_deps], ["dep-d", "dep-d"])

    def test_m_conflicting_duplicate_requirements(self):
        # group-a = ["foo"], group-b = ["foo>1.0"], group-c = ["foo<1.0"]
        # all = ["foo", {include-group = "group-a"}, {include-group = "group-b"}, {include-group = "group-c"}]
        content = """
[dependency-groups]
group-a = ["foo"]
group-b = ["foo>1.0"]
group-c = ["foo<1.0"]
all = [
  "foo",
  { include-group = "group-a" },
  { include-group = "group-b" },
  { include-group = "group-c" }
]
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)
        all_deps = [d for d in res.dependencies if d.group == "all"]
        self.assertEqual(len(all_deps), 4, "Must preserve all individual entries")
        names = [d.name for d in all_deps]
        self.assertEqual(names, ["foo", "foo", "foo", "foo"])
        specs = [d.version_specifier for d in all_deps]
        self.assertEqual(specs, [None, None, ">1.0", "<1.0"])

    def test_n_sca_pipeline_receives_duplicates_and_conflicts_unchanged(self):
        # Verify actual SCA pipeline matching: duplicated/conflicting records reach matcher unchanged
        content = """
[dependency-groups]
group-a = ["foo"]
group-b = ["foo>1.0"]
group-c = ["foo<1.0"]
all = [
  "foo",
  { include-group = "group-a" },
  { include-group = "group-b" },
  { include-group = "group-c" }
]
"""
        res = parse_pyproject_toml(content)
        all_deps = [d for d in res.dependencies if d.group == "all"]
        self.assertEqual(len(all_deps), 4)

        matcher = VersionMatcher()
        osv = make_osv_result(
            "foo",
            "GHSA-foo-test",
            [{"introduced": "0.5.0"}, {"fixed": "2.0.0"}],
            versions=["0.8.0", "1.5.0"]
        )
        findings = matcher.match_dependencies(all_deps, {"foo": osv})

        # All 4 entries independently evaluate against the advisory
        self.assertEqual(len(findings), 4, "SCA pipeline must emit findings for each duplicated/conflicting record")
        for f in findings:
            self.assertEqual(f.package_name, "foo")
            self.assertEqual(f.status, STATUS_POTENTIAL)

    def test_o_sca_pipeline_pinned_and_unpinned_duplicate_coexistence(self):
        # Pinned vulnerable version and range version for same package in same group
        content = """
[dependency-groups]
base = ["requests==2.25.0"]
range_grp = ["requests>=2.0.0"]
combo = [{ include-group = "base" }, { include-group = "range_grp" }]
"""
        res = parse_pyproject_toml(content)
        combo_deps = [d for d in res.dependencies if d.group == "combo"]
        self.assertEqual(len(combo_deps), 2)

        matcher = VersionMatcher()
        osv = make_osv_result("requests", "GHSA-req-test", [{"introduced": "2.0.0"}, {"fixed": "2.26.0"}])
        findings = matcher.match_dependencies(combo_deps, {"requests": osv})

        self.assertEqual(len(findings), 2)
        statuses = {f.status for f in findings}
        self.assertEqual(statuses, {STATUS_CONFIRMED, STATUS_POTENTIAL})
        confirmed_f = next(f for f in findings if f.status == STATUS_CONFIRMED)
        self.assertEqual(confirmed_f.confidence, 1.0)
        self.assertEqual(confirmed_f.installed_version, "2.25.0")
        potential_f = next(f for f in findings if f.status == STATUS_POTENTIAL)
        self.assertEqual(potential_f.confidence, 0.6)
        self.assertEqual(potential_f.requested_specifier, ">=2.0.0")

    def test_h_include_mixed_with_ordinary_requirements(self):
        content = """
[dependency-groups]
base = ["requests==2.25.0", "urllib3>=1.26.0"]
test = ["pytest>=7.0.0", { include-group = "base" }, "coverage"]
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)
        test_deps = [d for d in res.dependencies if d.group == "test"]
        names = {d.name for d in test_deps}
        self.assertEqual(names, {"pytest", "requests", "urllib3", "coverage"})

    def test_i_vulnerable_dependency_inside_included_group(self):
        # SECURITY INVARIANT:
        # A dependency hidden behind an include-group must reach SCA analysis
        # and evaluate correctly.
        content = """
[dependency-groups]
core = ["requests==2.25.0"]
dev = ["black", { include-group = "core" }]
"""
        res = parse_pyproject_toml(content)
        self.assertFalse(res.has_issues)

        # Match dev group dependencies against an OSV advisory for requests
        dev_deps = [d for d in res.dependencies if d.group == "dev"]
        requests_dep = next(d for d in dev_deps if d.name == "requests")

        matcher = VersionMatcher()
        osv = make_osv_result("requests", "GHSA-j8r2-6x86-q33q", [{"introduced": "2.0.0"}, {"fixed": "2.26.0"}])
        findings = matcher.match_dependency(requests_dep, osv)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_CONFIRMED)
        self.assertEqual(findings[0].confidence, 1.0)
        self.assertEqual(findings[0].fixed_version, "2.26.0")

    def test_j_malformed_include_structure(self):
        content = """
[dependency-groups]
bad1 = [{ include-group = "base", extra_key = "forbidden" }]
bad2 = [{ include-group = 12345 }]
bad3 = [{ not_an_include = "something" }]
bad4 = [9999]
"""
        res = parse_pyproject_toml(content)
        self.assertTrue(res.has_issues)
        self.assertGreaterEqual(len(res.issues), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
