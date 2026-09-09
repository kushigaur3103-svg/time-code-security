"""
Phase 11 Step 4 Unit Tests: CLI Integration (--sca, --sca-offline) + Unified Reporting.
Tests are 100% offline with zero live network calls. Socket connections are blocked.
Covers 26 deterministic verification test cases.
"""

import sys
import os
import json
import socket
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Any

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Forbid all live socket connections in this process
def _blocked_connect(*args, **kwargs):
    raise RuntimeError("Live network access is strictly forbidden in Phase 11 unit tests!")

socket.socket.connect = _blocked_connect
socket.create_connection = _blocked_connect

PYTHON_EXE = sys.executable
CLI_PATH = str(REPO_ROOT / "tcs_cli.py")


def run_cli(*args, env_override: Dict[str, str] = None):
    """Executes tcs_cli.py in a subprocess with optional environment variables."""
    cmd = [PYTHON_EXE, CLI_PATH] + list(args)
    env = os.environ.copy()
    if env_override:
        env.update(env_override)
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env
    )
    return proc.returncode, proc.stdout, proc.stderr


def build_test_cache() -> Dict[str, List[Dict[str, Any]]]:
    """Generates deterministic local OSV cache fixtures for testing."""
    return {
        "requests": [
            {
                "id": "GHSA-j8r2-6x86-q33q",
                "summary": "Requests vulnerable to session fixation",
                "details": "Requests 2.3.0 through 2.31.0 leaks authorization headers...",
                "aliases": ["CVE-2023-32681"],
                "affected": [
                    {
                        "package": {
                            "name": "requests",
                            "ecosystem": "PyPI"
                        },
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "2.3.0"},
                                    {"fixed": "2.31.0"}
                                ]
                            }
                        ]
                    }
                ],
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"
                    },
                    {
                        "type": "CVSS_V3",
                        "score": 7.5
                    }
                ]
            }
        ],
        "urllib3": [],
        "safe-pkg": [],
        "shared-vuln-pkg-a": [
            {
                "id": "GHSA-shared-vuln-001",
                "summary": "Shared vulnerability across packages",
                "aliases": ["CVE-2024-99999"],
                "affected": [
                    {
                        "package": {
                            "name": "shared-vuln-pkg-a",
                            "ecosystem": "PyPI"
                        },
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "1.0.0"},
                                    {"fixed": "2.0.0"}
                                ]
                            }
                        ]
                    }
                ],
                "severity": [{"type": "CVSS_V3", "score": 8.1}]
            }
        ],
        "shared-vuln-pkg-b": [
            {
                "id": "GHSA-shared-vuln-001",
                "summary": "Shared vulnerability across packages",
                "aliases": ["CVE-2024-99999"],
                "affected": [
                    {
                        "package": {
                            "name": "shared-vuln-pkg-b",
                            "ecosystem": "PyPI"
                        },
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "1.0.0"},
                                    {"fixed": "2.0.0"}
                                ]
                            }
                        ]
                    }
                ],
                "severity": [{"type": "CVSS_V3", "score": 8.1}]
            }
        ],
        "unresolved-advisory-pkg": [
            {
                "id": "GHSA-unparseable-range-001",
                "summary": "Advisory with unparseable version string",
                "aliases": [],
                "affected": [
                    {
                        "package": {
                            "name": "unresolved-advisory-pkg",
                            "ecosystem": "PyPI"
                        },
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "not.a.real.version.1"},
                                    {"fixed": "not.a.real.version.2"}
                                ]
                            }
                        ]
                    }
                ],
                "severity": []
            }
        ]
    }


def main():
    print("=" * 80)
    print("TEST SUITE: PHASE 11 STEP 4 — CLI INTEGRATION & UNIFIED REPORTING")
    print("=" * 80)

    total_checks = 0
    passed_checks = 0

    def check(condition: bool, desc: str):
        nonlocal total_checks, passed_checks
        total_checks += 1
        if condition:
            passed_checks += 1
            print(f"[PASS] Check {total_checks:02d}: {desc}")
        else:
            print(f"[FAIL] Check {total_checks:02d}: {desc}")
            raise AssertionError(f"Check failed: {desc}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)

        # Write test cache file
        cache_file = tmppath / "osv_test_cache.json"
        cache_file.write_text(json.dumps(build_test_cache(), indent=2), encoding="utf-8")

        # Sample 1: Clean Python file
        clean_py = tmppath / "clean_code.py"
        clean_py.write_text("""
def add(a, b):
    return a + b
""", encoding="utf-8")

        # Sample 2: Vulnerable Python file (CWE-95)
        vuln_py = tmppath / "vuln_code.py"
        vuln_py.write_text("""from flask import request

def handler():
    data = request.args.get("data")
    eval(data)
""", encoding="utf-8")

        # Sample 3: Suppressed Python file (CWE-95)
        supp_py = tmppath / "supp_code.py"
        supp_py.write_text("""from flask import request

def handler():
    data = request.args.get("data")
    eval(data)  # tcs:ignore CWE-95: validated safe by internal filter
""", encoding="utf-8")

        # Sample 4: Vulnerable requirements.txt (requests 2.28.0)
        vuln_reqs = tmppath / "vuln_reqs"
        vuln_reqs.mkdir()
        (vuln_reqs / "clean_code.py").write_text("def test(): pass\n", encoding="utf-8")
        (vuln_reqs / "requirements.txt").write_text("requests==2.28.0\n", encoding="utf-8")

        # Sample 5: Safe requirements.txt (urllib3==2.2.0)
        safe_reqs = tmppath / "safe_reqs"
        safe_reqs.mkdir()
        (safe_reqs / "clean_code.py").write_text("def test(): pass\n", encoding="utf-8")
        (safe_reqs / "requirements.txt").write_text("urllib3==2.2.0\n", encoding="utf-8")

        # Sample 6: Combined vulnerable SAST + vulnerable SCA
        both_vuln = tmppath / "both_vuln"
        both_vuln.mkdir()
        (both_vuln / "app.py").write_text("""from flask import request
def run():
    eval(request.args.get("q"))
""", encoding="utf-8")
        (both_vuln / "requirements.txt").write_text("requests==2.28.0\n", encoding="utf-8")

        # Sample 7: Suppressed SAST + vulnerable SCA
        supp_sast_vuln_sca = tmppath / "supp_sast_vuln_sca"
        supp_sast_vuln_sca.mkdir()
        (supp_sast_vuln_sca / "app.py").write_text("""from flask import request
def run():
    eval(request.args.get("q"))  # tcs:ignore CWE-95: handled
""", encoding="utf-8")
        (supp_sast_vuln_sca / "requirements.txt").write_text("requests==2.28.0\n", encoding="utf-8")

        # Sample 8: Suppressed SAST + safe SCA
        supp_sast_safe_sca = tmppath / "supp_sast_safe_sca"
        supp_sast_safe_sca.mkdir()
        (supp_sast_safe_sca / "app.py").write_text("""from flask import request
def run():
    eval(request.args.get("q"))  # tcs:ignore CWE-95: handled
""", encoding="utf-8")
        (supp_sast_safe_sca / "requirements.txt").write_text("urllib3==2.2.0\n", encoding="utf-8")

        # Sample 9: Multi-manifest project (requirements.txt + poetry.lock)
        multi_manifest = tmppath / "multi_manifest"
        multi_manifest.mkdir()
        (multi_manifest / "main.py").write_text("def run(): pass\n", encoding="utf-8")
        (multi_manifest / "requirements.txt").write_text("shared-vuln-pkg-a==1.5.0\n", encoding="utf-8")
        (multi_manifest / "poetry.lock").write_text("""
[[package]]
name = "shared-vuln-pkg-b"
version = "1.2.0"
category = "main"
optional = false
python-versions = ">=3.8"
""", encoding="utf-8")

        # Sample 10: Nested manifest project
        nested_proj = tmppath / "nested_proj"
        nested_proj.mkdir()
        (nested_proj / "src").mkdir()
        (nested_proj / "src" / "app.py").write_text("def run(): pass\n", encoding="utf-8")
        (nested_proj / "deps").mkdir()
        (nested_proj / "deps" / "requirements.txt").write_text("requests==2.28.0\n", encoding="utf-8")

        # Sample 11: Unparseable range manifest
        unres_proj = tmppath / "unres_proj"
        unres_proj.mkdir()
        (unres_proj / "main.py").write_text("def ok(): pass\n", encoding="utf-8")
        (unres_proj / "requirements.txt").write_text("unresolved-advisory-pkg>=1.0\n", encoding="utf-8")

        # Sample 12: Uncached package in offline mode
        uncached_proj = tmppath / "uncached_proj"
        uncached_proj.mkdir()
        (uncached_proj / "main.py").write_text("def ok(): pass\n", encoding="utf-8")
        (uncached_proj / "requirements.txt").write_text("completely-unknown-pkg==1.0.0\n", encoding="utf-8")

        # Sample 13: Suppressed SAST + UNRESOLVED SCA
        supp_sast_unres_sca = tmppath / "supp_sast_unres_sca"
        supp_sast_unres_sca.mkdir()
        (supp_sast_unres_sca / "app.py").write_text("""from flask import request
def run():
    eval(request.args.get("q"))  # tcs:ignore CWE-95: handled
""", encoding="utf-8")
        (supp_sast_unres_sca / "requirements.txt").write_text("completely-unknown-pkg==1.0.0\n", encoding="utf-8")

        # ======================================================================
        # 1. Phase 10 Baseline Compatibility (Without --sca)
        # ======================================================================
        print("\n--- Group 1: Phase 10 Baseline Compatibility ---")

        # Test 1: Clean file without --sca -> Exit 0
        code, stdout, stderr = run_cli(str(clean_py))
        check(code == 0, "Test 01: Clean Python without --sca exits 0")
        check("No security vulnerabilities detected" in stdout, "Test 01: Output shows clean report")

        # Test 2: Vulnerable file without --sca -> Exit 1
        code, stdout, stderr = run_cli(str(vuln_py))
        check(code == 1, "Test 02: Vulnerable Python without --sca exits 1")
        check("CWE-95" in stdout, "Test 02: Output contains CWE-95")

        # Test 3: JSON output without --sca has NO sca_findings key
        code, stdout, stderr = run_cli(str(clean_py), "--format", "json")
        check(code == 0, "Test 03: Clean Python JSON exits 0")
        data = json.loads(stdout)
        check("findings" in data and "sca_findings" not in data, "Test 03: JSON has 'findings' but NO 'sca_findings'")

        # Test 4: SARIF output without --sca has exactly 6 rules
        code, stdout, stderr = run_cli(str(clean_py), "--format", "sarif")
        check(code == 0, "Test 04: Clean Python SARIF exits 0")
        sarif = json.loads(stdout)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        check(len(rules) == 6, f"Test 04: SARIF driver.rules has exactly 6 SAST rules (got {len(rules)})")

        # Test 5: Vulnerable requirements.txt IGNORED without --sca -> Exit 0
        code, stdout, stderr = run_cli(str(vuln_reqs))
        check(code == 0, "Test 05: Vulnerable requirements ignored when --sca is absent (exits 0)")

        # ======================================================================
        # 2. Flag Enforcement & Configuration Validation
        # ======================================================================
        print("\n--- Group 2: Flag Enforcement ---")

        # Test 6: --sca-offline without --sca must exit 2
        code, stdout, stderr = run_cli(str(clean_py), "--sca-offline")
        check(code == 2, f"Test 06: --sca-offline without --sca exits 2 (got {code})")
        check("--sca-offline requires --sca" in stderr, "Test 06: Error explains flag dependency on stderr")

        # Test 7: Nonexistent target exits 2
        code, stdout, stderr = run_cli(str(tmppath / "nonexistent_dir"), "--sca")
        check(code == 2, "Test 07: Nonexistent target with --sca exits 2")

        # Test 8: Invalid file type exits 2
        bad_file = tmppath / "photo.jpg"
        bad_file.write_text("binary", encoding="utf-8")
        code, stdout, stderr = run_cli(str(bad_file), "--sca")
        check(code == 2, "Test 08: Non-Python non-manifest target exits 2")

        # ======================================================================
        # 3. Pure SCA Direct Target Manifest Scanning
        # ======================================================================
        print("\n--- Group 3: Direct Manifest Targets ---")

        # Test 9: Direct vulnerable requirements.txt target -> Exit 1
        code, stdout, stderr = run_cli(
            str(vuln_reqs / "requirements.txt"),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file)
        )
        check(code == 1, f"Test 09: Direct vulnerable requirements.txt target exits 1 (got {code})")
        check("GHSA-j8r2-6x86-q33q" in stdout, "Test 09: Output displays vulnerable advisory ID")

        # Test 10: Direct safe requirements.txt target -> Exit 0
        code, stdout, stderr = run_cli(
            str(safe_reqs / "requirements.txt"),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file)
        )
        check(code == 0, f"Test 10: Direct safe requirements.txt target exits 0 (got {code})")
        check("No security vulnerabilities detected" in stdout, "Test 10: Output displays clean scan")

        # ======================================================================
        # 4. Multi-Manifest Discovery & Relative Provenance
        # ======================================================================
        print("\n--- Group 4: Multi-Manifest & Path Provenance ---")

        # Test 11: Multi-manifest directory (requirements.txt + poetry.lock)
        code, stdout, stderr = run_cli(
            str(multi_manifest),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file),
            "--format", "json"
        )
        check(code == 1, "Test 11: Multi-manifest project exits 1")
        multi_json = json.loads(stdout)
        sca_finds = multi_json.get("sca_findings", [])
        packages_found = {f["package_name"] for f in sca_finds}
        check("shared-vuln-pkg-a" in packages_found and "shared-vuln-pkg-b" in packages_found,
              f"Test 11: Findings include packages from both manifests: {packages_found}")

        # Test 12: Subdirectory manifest preserves relative path
        code, stdout, stderr = run_cli(
            str(nested_proj),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file),
            "--format", "json"
        )
        check(code == 1, "Test 12: Nested manifest project exits 1")
        nested_json = json.loads(stdout)
        src_path = nested_json["sca_findings"][0]["manifest_source"]
        check("deps/requirements.txt" in src_path or "deps\\requirements.txt" in src_path,
              f"Test 12: Manifest source preserves relative path: {src_path}")

        # ======================================================================
        # 5. Soundness & Exit Code Matrix
        # ======================================================================
        print("\n--- Group 5: Soundness & Exit Code Matrix ---")

        # Test 13: Clean Python + vulnerable requirements -> Exit 1
        code, stdout, stderr = run_cli(
            str(vuln_reqs),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file)
        )
        check(code == 1, "Test 13: Clean Python + vulnerable requirements exits 1")

        # Test 14: Clean Python + safe requirements -> Exit 0
        code, stdout, stderr = run_cli(
            str(safe_reqs),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file)
        )
        check(code == 0, "Test 14: Clean Python + safe requirements exits 0")

        # Test 15: Vulnerable Python + safe requirements -> Exit 1
        vuln_py_safe_reqs = tmppath / "vuln_py_safe_reqs"
        vuln_py_safe_reqs.mkdir()
        (vuln_py_safe_reqs / "app.py").write_text("""from flask import request
def run(): eval(request.args.get("q"))
""", encoding="utf-8")
        (vuln_py_safe_reqs / "requirements.txt").write_text("urllib3==2.2.0\n", encoding="utf-8")
        code, stdout, stderr = run_cli(
            str(vuln_py_safe_reqs),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file)
        )
        check(code == 1, "Test 15: Vulnerable Python + safe requirements exits 1")

        # Test 16: Vulnerable Python + vulnerable requirements -> Exit 1
        code, stdout, stderr = run_cli(
            str(both_vuln),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file)
        )
        check(code == 1, "Test 16: Vulnerable Python + vulnerable requirements exits 1")

        # Test 17: Suppressed SAST + clean SCA with --exclude-suppressed -> Exit 0
        code, stdout, stderr = run_cli(
            str(supp_sast_safe_sca),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file),
            "--exclude-suppressed"
        )
        check(code == 0, "Test 17: Suppressed SAST + clean SCA with --exclude-suppressed exits 0")

        # Test 18: Suppressed SAST + vulnerable SCA with --exclude-suppressed -> Exit 1
        code, stdout, stderr = run_cli(
            str(supp_sast_vuln_sca),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file),
            "--exclude-suppressed"
        )
        check(code == 1, "Test 18: Suppressed SAST + vulnerable SCA with --exclude-suppressed exits 1")

        # Test 18b: Suppressed SAST + UNRESOLVED SCA with --exclude-suppressed -> Exit 1
        code, stdout, stderr = run_cli(
            str(supp_sast_unres_sca),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file),
            "--exclude-suppressed"
        )
        check(code == 1, "Test 18b: Suppressed SAST + UNRESOLVED SCA with --exclude-suppressed exits 1")

        # Test 19: Suppressed SAST + clean SCA without --exclude-suppressed -> Exit 1
        code, stdout, stderr = run_cli(
            str(supp_sast_safe_sca),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file)
        )
        check(code == 1, "Test 19: Suppressed SAST + clean SCA without --exclude-suppressed exits 1")

        # ======================================================================
        # 6. Tri-State Soundness & Unresolved Handling
        # ======================================================================
        print("\n--- Group 6: Tri-State Soundness & Unresolved Handling ---")

        # Test 20: Uncached package in offline mode produces UNRESOLVED -> Exit 1
        code, stdout, stderr = run_cli(
            str(uncached_proj),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file),
            "--format", "json"
        )
        check(code == 1, f"Test 20: Uncached package in offline mode exits 1 (got {code})")
        unres_json = json.loads(stdout)
        check(len(unres_json["sca_findings"]) > 0, "Test 20: SCA findings contains finding for offline fallback")
        check(unres_json["sca_findings"][0]["status"] == "UNRESOLVED", "Test 20: Status is UNRESOLVED (Never False Clean)")
        check(unres_json["sca_findings"][0]["confidence"] == 0.0, "Test 20: Confidence is 0.0")

        # Test 21: Unparseable range advisory produces UNRESOLVED -> Exit 1
        code, stdout, stderr = run_cli(
            str(unres_proj),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file),
            "--format", "json"
        )
        check(code == 1, "Test 21: Unparseable range advisory exits 1")
        unres2_json = json.loads(stdout)
        check(unres2_json["sca_findings"][0]["status"] == "UNRESOLVED", "Test 21: Status is UNRESOLVED")

        # ======================================================================
        # 7. JSON Output Schema & Details
        # ======================================================================
        print("\n--- Group 7: JSON Output Schema ---")

        # Test 22: Complete JSON output fields and summary metrics
        code, stdout, stderr = run_cli(
            str(vuln_reqs),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file),
            "--format", "json"
        )
        check(code == 1, "Test 22: JSON scan on vulnerable requirements exits 1")
        parsed = json.loads(stdout)
        check("findings" in parsed and "sca_findings" in parsed, "Test 22: Contains both 'findings' and 'sca_findings'")
        sf = parsed["sca_findings"][0]
        required_keys = [
            "package_name", "installed_version", "requested_specifier",
            "vulnerability_id", "aliases", "severity", "cvss_score",
            "summary", "fixed_version", "matched_range", "confidence",
            "status", "manifest_source", "line_number"
        ]
        for k in required_keys:
            check(k in sf, f"Test 22: SCA finding contains required key '{k}'")

        summary = parsed["summary"]
        check("manifests_scanned" in summary and summary["manifests_scanned"] == 1, "Test 22: manifests_scanned == 1")
        check("sca_vulnerabilities" in summary and summary["sca_vulnerabilities"] == 1, "Test 22: sca_vulnerabilities == 1")
        check("sca_confirmed" in summary and summary["sca_confirmed"] == 1, "Test 22: sca_confirmed == 1")

        # ======================================================================
        # 8. SARIF 2.1.0 Verification with SCA
        # ======================================================================
        print("\n--- Group 8: SARIF v2.1.0 Verification ---")

        # Test 23: SARIF structure, dynamic rules, and physical locations
        code, stdout, stderr = run_cli(
            str(vuln_reqs),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file),
            "--format", "sarif"
        )
        check(code == 1, "Test 23: SARIF scan on vulnerable requirements exits 1")
        sarif = json.loads(stdout)
        check(sarif.get("version") == "2.1.0", "Test 23: SARIF version is 2.1.0")
        run = sarif["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        check("GHSA-j8r2-6x86-q33q" in rule_ids, "Test 23: Dynamic SCA advisory rule present in driver.rules")

        res = run["results"][0]
        check(res["ruleId"] == "GHSA-j8r2-6x86-q33q", "Test 23: Result ruleId matches advisory ID")
        check(res["properties"]["sca"] is True, "Test 23: Result properties.sca is True")
        phys_loc = res["locations"][0]["physicalLocation"]
        check(phys_loc["artifactLocation"]["uri"] == "requirements.txt", "Test 23: URI points to requirements.txt")
        check(phys_loc["region"]["startLine"] == 1, "Test 23: region.startLine matches line 1")

        rule_idx = res.get("ruleIndex")
        check(rule_idx is not None, "Test 23: Result has ruleIndex")
        check(rules[rule_idx]["id"] == res["ruleId"], f"Test 23: Rule ID identity: rules[{rule_idx}]['id'] == res['ruleId']")
        check(not rules[rule_idx]["id"].startswith("SCA/"), "Test 23: Rule ID does not contain mismatched 'SCA/' prefix")
        check(not res["ruleId"].startswith("SCA/"), "Test 23: Result ruleId does not contain mismatched 'SCA/' prefix")
        check(rules[rule_idx]["name"] == res["ruleId"], f"Test 23: Rule name matches rule ID exactly ({rules[rule_idx]['name']})")

        # Test 24: Rule deduplication across manifests
        code, stdout, stderr = run_cli(
            str(multi_manifest),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file),
            "--format", "sarif"
        )
        check(code == 1, "Test 24: Multi-manifest SARIF exits 1")
        multi_sarif = json.loads(stdout)
        multi_rules = multi_sarif["runs"][0]["tool"]["driver"]["rules"]
        shared_rules = [r for r in multi_rules if r["id"] == "GHSA-shared-vuln-001"]
        check(len(shared_rules) == 1, f"Test 24: Shared rule GHSA-shared-vuln-001 is deduplicated (got {len(shared_rules)})")
        multi_results = multi_sarif["runs"][0]["results"]
        check(len(multi_results) == 2, f"Test 24: Both findings are preserved in results (got {len(multi_results)})")
        for res_item in multi_results:
            ridx = res_item.get("ruleIndex")
            check(ridx is not None, "Test 24: Multi-manifest result has ruleIndex")
            check(multi_rules[ridx]["id"] == res_item["ruleId"], f"Test 24: Rule ID identity: multi_rules[{ridx}]['id'] == res_item['ruleId']")
            check(not multi_rules[ridx]["id"].startswith("SCA/"), "Test 24: Multi-manifest rule ID has no 'SCA/' prefix")

        # ======================================================================
        # 9. CLI File Output (-o / --output)
        # ======================================================================
        print("\n--- Group 9: --output File Writing ---")

        # Test 25: --output with json, sarif, table silences stdout
        out_json_path = tmppath / "out.json"
        code, stdout, stderr = run_cli(
            str(vuln_reqs),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file),
            "--format", "json", "-o", str(out_json_path)
        )
        check(code == 1, "Test 25: -o out.json exits 1")
        check(stdout.strip() == "", "Test 25: stdout is silenced when -o is supplied")
        check(out_json_path.exists(), "Test 25: out.json exists on disk")
        written_data = json.loads(out_json_path.read_text(encoding="utf-8"))
        check("sca_findings" in written_data, "Test 25: out.json contains valid JSON with sca_findings")

        out_sarif_path = tmppath / "out.sarif"
        code, stdout, stderr = run_cli(
            str(vuln_reqs),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file),
            "--format", "sarif", "-o", str(out_sarif_path)
        )
        check(stdout.strip() == "", "Test 25: stdout is silenced for SARIF -o")
        check(out_sarif_path.exists(), "Test 25: out.sarif exists on disk")

        # ======================================================================
        # 10. Table Output & Deterministic Alignment
        # ======================================================================
        print("\n--- Group 10: Table Output & Deterministic Alignment ---")

        # Test 26: Table displays both SAST and SCA sections with aligned columns
        code, stdout, stderr = run_cli(
            str(both_vuln),
            "--sca", "--sca-offline", "--sca-cache", str(cache_file),
            "--format", "table"
        )
        check(code == 1, "Test 26: Combined vulnerable project exits 1")
        check("[SAST CODE ANALYSIS FINDINGS]" in stdout, "Test 26: Table displays SAST section header")
        check("[SCA DEPENDENCY VULNERABILITIES]" in stdout, "Test 26: Table displays SCA section header")
        check("PACKAGE" in stdout and "INSTALLED / SPEC" in stdout and "VULN ID" in stdout,
              "Test 26: Table contains aligned SCA headers")
        check("FINDING DETAILS:" in stdout, "Test 26: Table contains details block")
        check("requests" in stdout and "GHSA-j8r2-6x86-q33q" in stdout, "Test 26: Table displays package and advisory ID")

    print("\n" + "=" * 80)
    print(f"ALL PHASE 11 STEP 4 CLI & REPORTING TESTS PASSED ({passed_checks}/{total_checks})")
    print("=" * 80)


if __name__ == "__main__":
    main()
