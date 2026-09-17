#!/usr/bin/env python3
"""
Integration test suite for Vector C Web UI and app.py integration.
Verifies:
1. Zero regression / backward compatibility for scans without manifest.
2. Direct execute_tcs_ast_scan with and without manifest.
3. HTTP /api/scan endpoint with and without manifest.
4. Correct ReachabilityClassification (REACHABLE_API_USE, DEPENDENCY_ACTIVE, DEPENDENCY_DORMANT).
5. Clean resource management (tempfile cleanup).
"""

import sys
import unittest
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app import app, execute_tcs_ast_scan
from fastapi.testclient import TestClient
from sca_reachability.contracts import ReachabilityClassification, ReachabilityState


class TestVectorCWebIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_execute_tcs_ast_scan_without_manifest_backward_compat(self):
        """execute_tcs_ast_scan without manifest returns empty sca_reachability_findings."""
        code = (
            "from flask import request\n"
            "import os\n"
            "user_val = request.args.get('cmd')\n"
            "os.system(user_val)\n"
        )
        result = execute_tcs_ast_scan(code, filename="target.py")
        self.assertIn("sca_reachability_findings", result)
        self.assertEqual(result["sca_reachability_findings"], [])
        self.assertGreaterEqual(result["summary"]["total_flaws"], 1)

    def test_api_scan_without_manifest_backward_compat(self):
        """POST /api/scan with code only returns 200 and sca_reachability_findings == []."""
        payload = {
            "code": "import os\nos.system('echo test')",
            "filename": "target.py"
        }
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("sca_reachability_findings", data)
        self.assertEqual(data["sca_reachability_findings"], [])
        self.assertIn("summary", data)
        self.assertIn("findings", data)

    def test_api_scan_with_reachable_api_use(self):
        """POST /api/scan with manifest and reachable call returns REACHABLE_API_USE."""
        code = (
            "import vulnlib\n"
            "def main():\n"
            "    vulnlib.dangerous()\n"
            "main()\n"
        )
        manifest = "vulnlib==1.2.0\n"
        payload = {
            "code": code,
            "filename": "app.py",
            "manifest": manifest
        }
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("sca_reachability_findings", data)
        sca = data["sca_reachability_findings"]
        self.assertEqual(len(sca), 1)
        finding = sca[0]
        self.assertEqual(finding["package_name"], "vulnlib")
        self.assertEqual(finding["declared_version"], "1.2.0")
        self.assertEqual(finding["reachability_classification"], ReachabilityClassification.REACHABLE_API_USE.value)
        self.assertEqual(finding["import_status"], ReachabilityState.PACKAGE_IMPORTED.value)
        self.assertEqual(finding["api_status"], ReachabilityState.API_REFERENCE_FOUND.value)
        self.assertTrue(len(finding["call_path"]) >= 2)
        self.assertEqual(finding["call_path"][-1], "vulnlib.dangerous")

    def test_api_scan_with_dependency_active(self):
        """POST /api/scan with imported package but no API call returns DEPENDENCY_ACTIVE."""
        code = (
            "import vulnlib\n"
            "def main():\n"
            "    print('no call')\n"
            "main()\n"
        )
        manifest = "vulnlib==1.2.0\n"
        payload = {
            "code": code,
            "filename": "app.py",
            "manifest": manifest
        }
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        sca = data["sca_reachability_findings"]
        self.assertEqual(len(sca), 1)
        finding = sca[0]
        self.assertEqual(finding["package_name"], "vulnlib")
        self.assertEqual(finding["reachability_classification"], ReachabilityClassification.DEPENDENCY_ACTIVE.value)
        self.assertEqual(finding["import_status"], ReachabilityState.PACKAGE_IMPORTED.value)
        self.assertEqual(finding["api_status"], ReachabilityState.REACHABILITY_UNRESOLVED.value)

    def test_api_scan_with_unreachable_package(self):
        """POST /api/scan with declared dependency never imported returns DEPENDENCY_DORMANT."""
        code = (
            "def main():\n"
            "    print('hello world')\n"
            "main()\n"
        )
        manifest = "vulnlib==1.2.0\n"
        payload = {
            "code": code,
            "filename": "app.py",
            "manifest": manifest
        }
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        sca = data["sca_reachability_findings"]
        self.assertEqual(len(sca), 1)
        finding = sca[0]
        self.assertEqual(finding["package_name"], "vulnlib")
        self.assertEqual(finding["reachability_classification"], ReachabilityClassification.DEPENDENCY_DORMANT.value)
        self.assertEqual(finding["import_status"], ReachabilityState.PACKAGE_IMPORT_NOT_FOUND.value)

    def test_api_scan_with_empty_or_whitespace_manifest(self):
        """POST /api/scan with whitespace manifest gracefully treats as no manifest."""
        code = "def main():\n    pass\nmain()\n"
        payload = {
            "code": code,
            "filename": "app.py",
            "manifest": "   \n\t  "
        }
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["sca_reachability_findings"], [])

    def test_tempfile_cleanup_after_scan(self):
        """Verify temporary directory created during analysis is removed."""
        import tempfile
        before_entries = set(Path(tempfile.gettempdir()).glob("tmp*"))
        code = "import vulnlib\ndef main():\n    vulnlib.dangerous()\nmain()\n"
        manifest = "vulnlib==1.2.0\n"
        result = execute_tcs_ast_scan(code, filename="app.py", manifest=manifest)
        self.assertEqual(len(result["sca_reachability_findings"]), 1)
        after_entries = set(Path(tempfile.gettempdir()).glob("tmp*"))
        new_dirs = [p for p in (after_entries - before_entries) if p.is_dir() and "requirements.txt" in [f.name for f in p.iterdir()]]
        self.assertEqual(new_dirs, [], "Temporary workspace was not cleaned up!")


if __name__ == "__main__":
    unittest.main()
