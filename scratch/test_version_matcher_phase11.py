"""
Phase 11 Step 3 Test Suite: Version Matcher & SCA Findings Engine (version_matcher.py).
All tests execute 100% offline. Sockets are blocked to guarantee zero network access.
"""

import sys
import socket
import unittest
from pathlib import Path
from typing import Dict, List, Any

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Strictly block network access
def _blocked_connect(*args, **kwargs):
    raise RuntimeError("Live network access is strictly forbidden in Phase 11 unit tests!")

socket.socket.connect = _blocked_connect
socket.create_connection = _blocked_connect

from manifest_parser import DependencyRecord
from osv_client import OSVVulnerability, OSVAffectedRange, OSVQueryResult
from version_matcher import (
    VersionMatcher,
    SCAFinding,
    match_dependency,
    match_dependencies,
    STATUS_CONFIRMED,
    STATUS_POTENTIAL,
    STATUS_UNRESOLVED,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_UNKNOWN,
)


class TestVersionMatcher(unittest.TestCase):

    def setUp(self):
        self.matcher = VersionMatcher()

    def _create_vuln(
        self,
        vuln_id: str,
        package_name: str,
        events: List[Dict[str, str]] = None,
        versions: List[str] = None,
        severity: str = "HIGH",
        cvss_score: float = 8.5,
        aliases: List[str] = None,
        summary: str = "Test advisory"
    ) -> OSVVulnerability:
        aff_range = OSVAffectedRange(
            type="ECOSYSTEM",
            events=tuple(events or []),
            versions=tuple(versions or [])
        )
        return OSVVulnerability(
            vuln_id=vuln_id,
            package_name=package_name,
            summary=summary,
            aliases=tuple(aliases or []),
            affected_ranges=(aff_range,),
            severity=({"type": "CVSS_V3", "score": cvss_score},),
            database_specific={"severity": severity}
        )

    def test_01_exact_pinned_match(self):
        """Test 1: introduced=1.0.0, fixed=2.0.0, dependency=1.5.0 => CONFIRMED, confidence=1.0."""
        vuln = self._create_vuln("GHSA-1", "requests", events=[{"introduced": "1.0.0"}, {"fixed": "2.0.0"}])
        dep = DependencyRecord(name="requests", version="1.5.0", pinned=True, source="requirements.txt", line_number=1)
        osv_res = OSVQueryResult(package_name="requests", vulnerabilities=[vuln], source="network")

        findings = self.matcher.match_dependency(dep, osv_res)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.status, STATUS_CONFIRMED)
        self.assertEqual(f.confidence, 1.0)
        self.assertEqual(f.vulnerability_id, "GHSA-1")
        self.assertEqual(f.package_name, "requests")
        self.assertEqual(f.installed_version, "1.5.0")
        self.assertEqual(f.fixed_version, "2.0.0")
        self.assertIn(">=1.0.0", f.matched_range)
        self.assertIn("<2.0.0", f.matched_range)

    def test_02_pinned_version_above_fixed(self):
        """Test 2: dependency=2.1.0 above fixed=2.0.0 => 0 findings."""
        vuln = self._create_vuln("GHSA-1", "requests", events=[{"introduced": "1.0.0"}, {"fixed": "2.0.0"}])
        dep = DependencyRecord(name="requests", version="2.1.0", pinned=True, source="requirements.txt")
        osv_res = OSVQueryResult(package_name="requests", vulnerabilities=[vuln], source="network")

        findings = self.matcher.match_dependency(dep, osv_res)
        self.assertEqual(len(findings), 0)

    def test_03_pinned_version_below_introduced(self):
        """Test 3: dependency=0.9.0 below introduced=1.0.0 => 0 findings."""
        vuln = self._create_vuln("GHSA-1", "requests", events=[{"introduced": "1.0.0"}, {"fixed": "2.0.0"}])
        dep = DependencyRecord(name="requests", version="0.9.0", pinned=True, source="requirements.txt")
        osv_res = OSVQueryResult(package_name="requests", vulnerabilities=[vuln], source="network")

        findings = self.matcher.match_dependency(dep, osv_res)
        self.assertEqual(len(findings), 0)

    def test_04_range_overlap(self):
        """Test 4: requested: >=1.25,<2.0, vulnerable: introduced=1.0, fixed=1.26.5 => POTENTIAL, confidence=0.6."""
        vuln = self._create_vuln("GHSA-1", "urllib3", events=[{"introduced": "1.0"}, {"fixed": "1.26.5"}])
        dep = DependencyRecord(name="urllib3", version_specifier=">=1.25,<2.0", pinned=False, source="requirements.txt")
        osv_res = OSVQueryResult(package_name="urllib3", vulnerabilities=[vuln], source="network")

        findings = self.matcher.match_dependency(dep, osv_res)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.status, STATUS_POTENTIAL)
        self.assertEqual(f.confidence, 0.6)
        self.assertEqual(f.fixed_version, "1.26.5")

    def test_05_zero_overlap_range(self):
        """Test 5: requested: >=2.0,<3.0, vulnerable: introduced=1.0, fixed=1.26.5 => 0 findings."""
        vuln = self._create_vuln("GHSA-1", "urllib3", events=[{"introduced": "1.0"}, {"fixed": "1.26.5"}])
        dep = DependencyRecord(name="urllib3", version_specifier=">=2.0,<3.0", pinned=False, source="requirements.txt")
        osv_res = OSVQueryResult(package_name="urllib3", vulnerabilities=[vuln], source="network")

        findings = self.matcher.match_dependency(dep, osv_res)
        self.assertEqual(len(findings), 0)

    def test_06_last_affected_semantics(self):
        """Test 6: introduced=1.0, last_affected=1.5.9 => 1.5.9 affected, 1.6.0 safe."""
        vuln = self._create_vuln("GHSA-1", "pkg", events=[{"introduced": "1.0"}, {"last_affected": "1.5.9"}])
        osv_res = OSVQueryResult(package_name="pkg", vulnerabilities=[vuln], source="network")

        # 1.5.9 is affected
        dep1 = DependencyRecord(name="pkg", version="1.5.9", pinned=True, source="requirements.txt")
        findings1 = self.matcher.match_dependency(dep1, osv_res)
        self.assertEqual(len(findings1), 1)
        self.assertEqual(findings1[0].status, STATUS_CONFIRMED)

        # 1.6.0 is safe
        dep2 = DependencyRecord(name="pkg", version="1.6.0", pinned=True, source="requirements.txt")
        findings2 = self.matcher.match_dependency(dep2, osv_res)
        self.assertEqual(len(findings2), 0)

    def test_07_exact_affected_versions_fallback(self):
        """Test 7: versions: ["2.3.0", "2.4.0"] with no events."""
        vuln = self._create_vuln("GHSA-1", "pkg", versions=["2.3.0", "2.4.0"])
        osv_res = OSVQueryResult(package_name="pkg", vulnerabilities=[vuln], source="network")

        # Pinned 2.3.0 matches
        dep1 = DependencyRecord(name="pkg", version="2.3.0", pinned=True)
        findings1 = self.matcher.match_dependency(dep1, osv_res)
        self.assertEqual(len(findings1), 1)
        self.assertEqual(findings1[0].status, STATUS_CONFIRMED)

        # Pinned 2.5.0 safe
        dep2 = DependencyRecord(name="pkg", version="2.5.0", pinned=True)
        findings2 = self.matcher.match_dependency(dep2, osv_res)
        self.assertEqual(len(findings2), 0)

    def test_08_multiple_vulnerabilities_same_package(self):
        """Test 8: Multiple distinct advisories produce multiple distinct SCAFinding objects."""
        vuln1 = self._create_vuln("GHSA-A", "requests", events=[{"introduced": "1.0"}, {"fixed": "2.0"}])
        vuln2 = self._create_vuln("CVE-B", "requests", events=[{"introduced": "1.5"}, {"fixed": "2.5"}])
        osv_res = OSVQueryResult(package_name="requests", vulnerabilities=[vuln1, vuln2], source="network")

        dep = DependencyRecord(name="requests", version="1.8.0", pinned=True, source="requirements.txt")
        findings = self.matcher.match_dependency(dep, osv_res)
        self.assertEqual(len(findings), 2)
        ids = {f.vulnerability_id for f in findings}
        self.assertEqual(ids, {"GHSA-A", "CVE-B"})

    def test_09_fixed_version_extraction(self):
        """Test 9: Extract fixed version from OSV events."""
        vuln = self._create_vuln("GHSA-1", "flask", events=[{"introduced": "2.0.0"}, {"fixed": "2.5.3"}])
        dep = DependencyRecord(name="flask", version="2.1.0", pinned=True)
        osv_res = OSVQueryResult(package_name="flask", vulnerabilities=[vuln], source="network")

        findings = self.matcher.match_dependency(dep, osv_res)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].fixed_version, "2.5.3")

    def test_10_invalid_pinned_version(self):
        """Test 10: Invalid/non-PEP-440 pinned version does not crash and produces UNRESOLVED."""
        vuln = self._create_vuln("GHSA-1", "pkg", events=[{"introduced": "1.0"}, {"fixed": "2.0"}])
        dep = DependencyRecord(name="pkg", version="weird-version", pinned=True, source="requirements.txt", line_number=5)
        osv_res = OSVQueryResult(package_name="pkg", vulnerabilities=[vuln], source="network")

        findings = self.matcher.match_dependency(dep, osv_res)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.status, STATUS_UNRESOLVED)
        self.assertEqual(f.confidence, 0.0)
        self.assertEqual(f.line_number, 5)

    def test_11_unsupported_ambiguous_unpinned_specifier(self):
        """Test 11: Malformed or unparseable unpinned specifier produces UNRESOLVED."""
        vuln = self._create_vuln("GHSA-1", "pkg", events=[{"introduced": "1.0"}, {"fixed": "2.0"}])
        dep = DependencyRecord(name="pkg", version_specifier="===!@#invalid", pinned=False, source="requirements.txt")
        osv_res = OSVQueryResult(package_name="pkg", vulnerabilities=[vuln], source="network")

        findings = self.matcher.match_dependency(dep, osv_res)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_UNRESOLVED)
        self.assertEqual(findings[0].confidence, 0.0)

    def test_12_osv_source_error(self):
        """Test 12: OSV source='error' produces UNRESOLVED, never clean 0."""
        dep = DependencyRecord(name="cryptography", version="3.4.8", pinned=True, source="Pipfile.lock", line_number=12)
        osv_res = OSVQueryResult(package_name="cryptography", vulnerabilities=[], source="error", error="HTTP 500: Server Error")

        findings = self.matcher.match_dependency(dep, osv_res)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.status, STATUS_UNRESOLVED)
        self.assertEqual(f.confidence, 0.0)
        self.assertEqual(f.vulnerability_id, "UNKNOWN")
        self.assertEqual(f.package_name, "cryptography")
        self.assertEqual(f.line_number, 12)
        self.assertIn("HTTP 500", f.summary)

    def test_13_osv_source_offline_fallback(self):
        """Test 13: OSV source='offline_fallback' with unavailable data produces UNRESOLVED."""
        dep = DependencyRecord(name="jinja2", version_specifier=">=2.11", pinned=False, source="poetry.lock", line_number=8)
        osv_res = OSVQueryResult(
            package_name="jinja2",
            vulnerabilities=[],
            source="offline_fallback",
            error="Offline mode active; package not found in local cache"
        )

        findings = self.matcher.match_dependency(dep, osv_res)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.status, STATUS_UNRESOLVED)
        self.assertEqual(f.confidence, 0.0)
        self.assertEqual(f.vulnerability_id, "UNKNOWN")

    def test_14_deterministic_ordering(self):
        """Test 14: Findings order is stable and deterministic across multiple runs."""
        vuln1 = self._create_vuln("GHSA-Z", "pkg-b", events=[{"introduced": "1.0"}, {"fixed": "2.0"}])
        vuln2 = self._create_vuln("GHSA-A", "pkg-a", events=[{"introduced": "1.0"}, {"fixed": "2.0"}])

        deps = [
            DependencyRecord(name="pkg-b", version="1.5", pinned=True, source="b.txt", line_number=2),
            DependencyRecord(name="pkg-a", version="1.5", pinned=True, source="a.txt", line_number=1)
        ]
        osv_dict = {
            "pkg-b": OSVQueryResult(package_name="pkg-b", vulnerabilities=[vuln1]),
            "pkg-a": OSVQueryResult(package_name="pkg-a", vulnerabilities=[vuln2])
        }

        res1 = match_dependencies(deps, osv_dict)
        res2 = match_dependencies(list(reversed(deps)), osv_dict)

        self.assertEqual([f.package_name for f in res1], ["pkg-a", "pkg-b"])
        self.assertEqual([f.vulnerability_id for f in res1], ["GHSA-A", "GHSA-Z"])
        self.assertEqual(res1, res2)

    def test_15_zero_network_access(self):
        """Test 15: Verify network socket connections remain strictly blocked."""
        with socket.socket() as s:
            with self.assertRaises(RuntimeError) as ctx:
                s.connect(("8.8.8.8", 80))
            self.assertIn("Live network access is strictly forbidden", str(ctx.exception))

    def test_16_pep_440_semantics(self):
        """Test 16: PEP 440 semantic cases: ~=, !=, wildcards ==1.*, combined bounds."""
        # 16A: Compatible release ~=1.2
        vuln = self._create_vuln("GHSA-1", "pkg", events=[{"introduced": "1.0"}, {"fixed": "1.26.5"}])
        dep_compat = DependencyRecord(name="pkg", version_specifier="~=1.2", pinned=False)
        osv_res = OSVQueryResult(package_name="pkg", vulnerabilities=[vuln])
        findings = self.matcher.match_dependency(dep_compat, osv_res)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_POTENTIAL)

        # 16B: Compatible release ~=2.0 (outside 1.0..1.26.5)
        dep_compat2 = DependencyRecord(name="pkg", version_specifier="~=2.0", pinned=False)
        findings2 = self.matcher.match_dependency(dep_compat2, osv_res)
        self.assertEqual(len(findings2), 0)

        # 16C: Wildcard equality ==1.4.*
        vuln_wildcard = self._create_vuln("GHSA-2", "pkg", events=[{"introduced": "1.4.0"}, {"fixed": "1.4.5"}])
        dep_wildcard = DependencyRecord(name="pkg", version_specifier="==1.4.*", pinned=False)
        osv_res_wild = OSVQueryResult(package_name="pkg", vulnerabilities=[vuln_wildcard])
        findings_wild = self.matcher.match_dependency(dep_wildcard, osv_res_wild)
        self.assertEqual(len(findings_wild), 1)
        self.assertEqual(findings_wild[0].status, STATUS_POTENTIAL)

    def test_17_crucial_interval_overlap_cases(self):
        """
        Test 17: Explicit interval validation cases from prompt:
        - requested: >=1.2,<1.3, vulnerable: >=1.4,<1.5 => NO OVERLAP
        - requested: >=1.2,<2.0, vulnerable: >=1.5,<1.6 => OVERLAP
        - requested: ==1.5.3 (pinned), vulnerable: >=1.5,<1.6 => CONFIRMED
        - requested: !=1.5.3,>=1.5,<1.6, vulnerable: ==1.5.3 => NO OVERLAP
        """
        # Case 17.1: requested: >=1.2,<1.3, vulnerable: >=1.4,<1.5 => NO OVERLAP
        vuln1 = self._create_vuln("GHSA-1", "pkg", events=[{"introduced": "1.4"}, {"fixed": "1.5"}])
        dep1 = DependencyRecord(name="pkg", version_specifier=">=1.2,<1.3", pinned=False)
        f1 = self.matcher.match_dependency(dep1, OSVQueryResult(package_name="pkg", vulnerabilities=[vuln1]))
        self.assertEqual(len(f1), 0, ">=1.2,<1.3 and >=1.4,<1.5 must produce 0 findings")

        # Case 17.2: requested: >=1.2,<2.0, vulnerable: >=1.5,<1.6 => OVERLAP
        vuln2 = self._create_vuln("GHSA-2", "pkg", events=[{"introduced": "1.5"}, {"fixed": "1.6"}])
        dep2 = DependencyRecord(name="pkg", version_specifier=">=1.2,<2.0", pinned=False)
        f2 = self.matcher.match_dependency(dep2, OSVQueryResult(package_name="pkg", vulnerabilities=[vuln2]))
        self.assertEqual(len(f2), 1, ">=1.2,<2.0 and >=1.5,<1.6 must produce POTENTIAL finding")
        self.assertEqual(f2[0].status, STATUS_POTENTIAL)

        # Case 17.3: requested: ==1.5.3 (pinned), vulnerable: >=1.5,<1.6 => CONFIRMED
        dep3 = DependencyRecord(name="pkg", version="1.5.3", pinned=True)
        f3 = self.matcher.match_dependency(dep3, OSVQueryResult(package_name="pkg", vulnerabilities=[vuln2]))
        self.assertEqual(len(f3), 1)
        self.assertEqual(f3[0].status, STATUS_CONFIRMED)
        self.assertEqual(f3[0].confidence, 1.0)

        # Case 17.4: requested: !=1.5.3,>=1.5,<1.6, vulnerable: ==1.5.3 => NO OVERLAP
        # Degenerate interval: introduced=1.5.3, last_affected=1.5.3
        vuln4 = self._create_vuln("GHSA-4", "pkg", events=[{"introduced": "1.5.3"}, {"last_affected": "1.5.3"}])
        dep4 = DependencyRecord(name="pkg", version_specifier="!=1.5.3,>=1.5,<1.6", pinned=False)
        f4 = self.matcher.match_dependency(dep4, OSVQueryResult(package_name="pkg", vulnerabilities=[vuln4]))
        self.assertEqual(len(f4), 0, "!=1.5.3,>=1.5,<1.6 and ==1.5.3 must produce NO OVERLAP")

    def test_18_missing_osv_result_produces_unresolved(self):
        """Test 18: Missing OSV query result (None) produces UNRESOLVED finding."""
        dep = DependencyRecord(name="unknown-pkg", version="1.0.0", pinned=True, source="requirements.txt", line_number=4)
        findings = self.matcher.match_dependency(dep, None)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_UNRESOLVED)
        self.assertEqual(findings[0].vulnerability_id, "UNKNOWN")
        self.assertEqual(findings[0].confidence, 0.0)

    def test_19_unconstrained_dependency_matches_vulnerability(self):
        """Test 19: Bare dependency declaration without specifier admits all versions => POTENTIAL."""
        vuln = self._create_vuln("GHSA-1", "requests", events=[{"introduced": "2.0"}, {"fixed": "2.25"}])
        dep = DependencyRecord(name="requests", version_specifier=None, pinned=False, source="requirements.txt")
        findings = self.matcher.match_dependency(dep, OSVQueryResult(package_name="requests", vulnerabilities=[vuln]))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_POTENTIAL)
        self.assertEqual(findings[0].confidence, 0.6)

    def test_20_severity_and_cvss_mapping(self):
        """Test 20: Direct OSV payload CVSS score and severity tiering without custom arithmetic."""
        # Explicit numeric score in severity array
        vuln_num = OSVVulnerability(
            vuln_id="NUM-1",
            package_name="pkg",
            severity=({"type": "CVSS_V3", "score": 9.8},),
            affected_ranges=(OSVAffectedRange(type="ECOSYSTEM", events=({"introduced": "1.0"}, {"fixed": "2.0"})),)
        )
        findings_num = self.matcher.match_dependency(
            DependencyRecord(name="pkg", version="1.5", pinned=True),
            OSVQueryResult(package_name="pkg", vulnerabilities=[vuln_num])
        )
        self.assertEqual(findings_num[0].severity, SEVERITY_CRITICAL)
        self.assertEqual(findings_num[0].cvss_score, 9.8)

        # Database-specific CVSS object and severity string
        vuln_db = OSVVulnerability(
            vuln_id="DB-1",
            package_name="pkg",
            database_specific={"severity": "HIGH", "cvss": {"score": 7.5}},
            affected_ranges=(OSVAffectedRange(type="ECOSYSTEM", events=({"introduced": "1.0"}, {"fixed": "2.0"})),)
        )
        findings_db = self.matcher.match_dependency(
            DependencyRecord(name="pkg", version="1.5", pinned=True),
            OSVQueryResult(package_name="pkg", vulnerabilities=[vuln_db])
        )
        self.assertEqual(findings_db[0].severity, SEVERITY_HIGH)
        self.assertEqual(findings_db[0].cvss_score, 7.5)

        # Raw vector string without numeric score does NOT compute custom arithmetic
        vuln_vec = OSVVulnerability(
            vuln_id="VEC-1",
            package_name="pkg",
            severity=({"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},),
            affected_ranges=(OSVAffectedRange(type="ECOSYSTEM", events=({"introduced": "1.0"}, {"fixed": "2.0"})),)
        )
        findings_vec = self.matcher.match_dependency(
            DependencyRecord(name="pkg", version="1.5", pinned=True),
            OSVQueryResult(package_name="pkg", vulnerabilities=[vuln_vec])
        )
        self.assertEqual(findings_vec[0].severity, SEVERITY_UNKNOWN)
        self.assertIsNone(findings_vec[0].cvss_score)

    def test_21_scafinding_model_serialization(self):
        """Test 21: SCAFinding properties and to_dict() serialization."""
        vuln = self._create_vuln("GHSA-1", "requests", events=[{"introduced": "1.0"}, {"fixed": "2.0"}])
        dep = DependencyRecord(name="requests", version="1.5.0", pinned=True, source="requirements.txt", line_number=10)
        finding = self.matcher.match_dependency(dep, OSVQueryResult(package_name="requests", vulnerabilities=[vuln]))[0]

        self.assertTrue(finding.is_confirmed)
        self.assertFalse(finding.is_potential)
        self.assertFalse(finding.is_unresolved)

        d = finding.to_dict()
        self.assertEqual(d["package_name"], "requests")
        self.assertEqual(d["installed_version"], "1.5.0")
        self.assertEqual(d["vulnerability_id"], "GHSA-1")
        self.assertEqual(d["status"], STATUS_CONFIRMED)
        self.assertEqual(d["confidence"], 1.0)
        self.assertEqual(d["line_number"], 10)
        self.assertEqual(d["manifest_source"], "requirements.txt")

    def test_22_adversarial_wildcard_overlap(self):
        """Adversarial 1: ==1.5.* vs [1.5.0, 1.6.0) => PROVEN_OVERLAP."""
        vuln = self._create_vuln("GHSA-W1", "pkg", events=[{"introduced": "1.5.0"}, {"fixed": "1.6.0"}])
        dep = DependencyRecord(name="pkg", version_specifier="==1.5.*", pinned=False)
        findings = self.matcher.match_dependency(dep, OSVQueryResult(package_name="pkg", vulnerabilities=[vuln]))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_POTENTIAL)
        self.assertEqual(findings[0].confidence, 0.6)

    def test_23_adversarial_wildcard_disjoint(self):
        """Adversarial 2: ==1.4.* vs [1.5.0, 1.6.0) => PROVEN_DISJOINT (0 findings)."""
        vuln = self._create_vuln("GHSA-W2", "pkg", events=[{"introduced": "1.5.0"}, {"fixed": "1.6.0"}])
        dep = DependencyRecord(name="pkg", version_specifier="==1.4.*", pinned=False)
        findings = self.matcher.match_dependency(dep, OSVQueryResult(package_name="pkg", vulnerabilities=[vuln]))
        self.assertEqual(len(findings), 0, "==1.4.* and [1.5.0, 1.6.0) must be provably disjoint")

    def test_24_adversarial_multiple_exclusions_genuine_overlap(self):
        """Adversarial 3: >=1.0,<2.0,!=1.2,!=1.3 vs [1.0, 1.5) => PROVEN_OVERLAP."""
        vuln = self._create_vuln("GHSA-EX", "pkg", events=[{"introduced": "1.0"}, {"fixed": "1.5"}])
        dep = DependencyRecord(name="pkg", version_specifier=">=1.0,<2.0,!=1.2,!=1.3", pinned=False)
        findings = self.matcher.match_dependency(dep, OSVQueryResult(package_name="pkg", vulnerabilities=[vuln]))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_POTENTIAL)
        self.assertEqual(findings[0].confidence, 0.6)

    def test_25_adversarial_prerelease_boundary_deterministic(self):
        """Adversarial 4: >=1.0rc1,<1.0 against [1.0, 2.0) => PROVEN_DISJOINT (0 findings)."""
        vuln = self._create_vuln("GHSA-PRE", "pkg", events=[{"introduced": "1.0"}, {"fixed": "2.0"}])
        dep = DependencyRecord(name="pkg", version_specifier=">=1.0rc1,<1.0", pinned=False)
        findings = self.matcher.match_dependency(dep, OSVQueryResult(package_name="pkg", vulnerabilities=[vuln]))
        self.assertEqual(len(findings), 0, ">=1.0rc1,<1.0 is strictly below 1.0, so provably disjoint from [1.0, 2.0)")

    def test_26_adversarial_indeterminate_defaults_to_unresolved(self):
        """Adversarial 5: Constraint with overlapping outer bounds where witness cannot be found defaults safely to UNRESOLVED."""
        # Exclude all standard generated probe candidates within [1.0, 1.5)
        # Specifier: >=1.0,<1.5, !=1.0.0, !=1.0.1, !=1.0.2, !=1.0.5, !=1.1.0, !=2.0.0
        # This prevents standard probing from hitting a witness, while outer bounds touch/overlap.
        # Under Tri-State soundness, this MUST NOT be marked safe; it must emit UNRESOLVED.
        spec = ">=1.0,<1.5,!=1.0,!=1.0.0,!=1.0.1,!=1.0.2,!=1.0.5,!=1.1.0,!=2.0.0"
        vuln = self._create_vuln("GHSA-IND", "pkg", events=[{"introduced": "1.0"}, {"fixed": "1.5"}])
        dep = DependencyRecord(name="pkg", version_specifier=spec, pinned=False)
        findings = self.matcher.match_dependency(dep, OSVQueryResult(package_name="pkg", vulnerabilities=[vuln]))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, STATUS_UNRESOLVED)
        self.assertEqual(findings[0].confidence, 0.0)

    def test_27_direct_osv_cvss_no_custom_arithmetic(self):
        """Adversarial 6: OSV CVSS score parsed directly from payload fields without custom scoring engine."""
        vuln = OSVVulnerability(
            vuln_id="CVSS-DIRECT",
            package_name="pkg",
            severity=({"type": "CVSS_V3", "score": 8.1},),
            database_specific={"severity": "HIGH", "cvss": {"score": 8.1}},
            affected_ranges=(OSVAffectedRange(type="ECOSYSTEM", events=({"introduced": "1.0"}, {"fixed": "2.0"})),)
        )
        dep = DependencyRecord(name="pkg", version="1.5.0", pinned=True)
        findings = self.matcher.match_dependency(dep, OSVQueryResult(package_name="pkg", vulnerabilities=[vuln]))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cvss_score, 8.1)
        self.assertEqual(findings[0].severity, SEVERITY_HIGH)


if __name__ == "__main__":
    unittest.main(verbosity=2)
