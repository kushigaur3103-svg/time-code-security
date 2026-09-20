import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app import app
from fastapi.testclient import TestClient


class TestVectorDWebIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_sqli_auto_remediation_success(self):
        """Vulnerable SQLi code scanned via /api/scan returns remediation SUCCESS with patched source and diff."""
        code = (
            "import sqlite3\n"
            "def get_user(uid):\n"
            "    conn = sqlite3.connect('test.db')\n"
            "    cursor = conn.cursor()\n"
            "    cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
        )
        payload = {
            "code": code,
            "filename": "app.py"
        }
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")

        findings = data.get("findings", [])
        self.assertGreaterEqual(len(findings), 1)

        sqli_finding = next((f for f in findings if f.get("cwe") == "CWE-89"), None)
        self.assertIsNotNone(sqli_finding, "Expected CWE-89 finding")

        rem = sqli_finding.get("remediation")
        self.assertIsInstance(rem, dict, "Expected remediation to be a dictionary")
        self.assertEqual(rem.get("status"), "SUCCESS")
        self.assertEqual(rem.get("rule"), "SQLI_PARAMETERIZE")
        self.assertIsNotNone(rem.get("patched_source"))
        self.assertIn("?", rem.get("patched_source"))
        self.assertIsNotNone(rem.get("unified_diff"))
        self.assertIn("cursor.execute", rem.get("unified_diff"))

    def test_02_clean_code_no_false_remediation(self):
        """Clean code returns 200, 0 findings, and no false remediation injected."""
        code = (
            "def add(a, b):\n"
            "    return a + b\n"
        )
        payload = {
            "code": code,
            "filename": "clean.py"
        }
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(len(data.get("findings", [])), 0)
        self.assertEqual(data["summary"]["total_flaws"], 0)

    def test_03_cmdi_auto_remediation_success(self):
        """Vulnerable Command Injection (CWE-78) returns remediation with CMD_INJECTION_SPLIT."""
        code = (
            "import subprocess\n"
            "def run_tool(cmd):\n"
            "    cmd = f'ping {cmd}'\n"
            "    subprocess.call(cmd, shell=True)\n"
        )
        payload = {
            "code": code,
            "filename": "tool.py"
        }
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        findings = data.get("findings", [])
        cmdi_finding = next((f for f in findings if f.get("cwe") == "CWE-78"), None)
        self.assertIsNotNone(cmdi_finding, "Expected CWE-78 finding")

        rem = cmdi_finding.get("remediation")
        self.assertIsInstance(rem, dict)
        self.assertEqual(rem.get("status"), "SUCCESS")
        self.assertEqual(rem.get("rule"), "CMD_INJECTION_SPLIT")
        self.assertIn("shell=False", rem.get("patched_source"))
        self.assertIn("cmd_list", rem.get("patched_source"))

    def test_04_path_traversal_auto_remediation_success(self):
        """Vulnerable Path Traversal (CWE-22) returns remediation with PATH_TRAVERSAL_RESOLVE."""
        code = (
            "import os\n"
            "def read_uploaded_file(base_dir, filename):\n"
            "    target_path = base_dir + filename\n"
            "    with open(target_path, 'r') as f:\n"
            "        return f.read()\n"
        )
        payload = {
            "code": code,
            "filename": "vuln.py"
        }
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        findings = data.get("findings", [])
        cwe22_finding = next((f for f in findings if f.get("cwe") == "CWE-22"), None)
        self.assertIsNotNone(cwe22_finding, "Expected CWE-22 finding")

        rem = cwe22_finding.get("remediation")
        self.assertIsInstance(rem, dict)
        self.assertEqual(rem.get("status"), "SUCCESS")
        self.assertEqual(rem.get("rule"), "PATH_TRAVERSAL_RESOLVE")
        self.assertIn("resolve()", rem.get("patched_source"))

    def test_05_non_eligible_cwe_remediation_is_null(self):
        """Non-eligible CWE (e.g. CWE-95) returns remediation: null."""
        code = (
            "def run_user_code(user_input):\n"
            "    eval(user_input)\n"
        )
        payload = {
            "code": code,
            "filename": "eval_test.py"
        }
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        findings = data.get("findings", [])
        cwe95_finding = next((f for f in findings if f.get("cwe") == "CWE-95"), None)
        self.assertIsNotNone(cwe95_finding, "Expected CWE-95 finding")
        self.assertIsNone(cwe95_finding.get("remediation"), "Non-eligible CWE must have remediation: null")

    def test_06_frontend_template_diff_viewer_elements(self):
        """templates/index.html contains the Vector D One-Click Auto Fix UI and Diff Viewer."""
        template_path = REPO_ROOT / "templates" / "index.html"
        self.assertTrue(template_path.exists())
        content = template_path.read_text(encoding="utf-8")

        # 1. Expandable section header
        self.assertIn("\u2728 One-Click Auto Fix Available (Vector D)", content)

        # 2. Apply fix button
        self.assertIn("Apply Fix to Editor", content)

        # 3. Diff renderer function
        self.assertIn("renderUnifiedDiffHtml", content)

        # 4. Patch applicator function
        self.assertIn("applyRemediationPatch", content)

        # 5. Toast notification string
        self.assertIn("Patch applied to editor! Re-scan to verify.", content)

        # 6. Web UI Safeguard for non-remediable vectors (CWE-95, CWE-502, CWE-1336)
        self.assertIn("Auto-remediation not supported for this vector", content)
        self.assertIn("['CWE-95', 'CWE-502', 'CWE-1336']", content)

    def test_07_vector_c_reachability_zero_regression(self):
        """Verify Vector C reachability still operates seamlessly alongside Vector D."""
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
        sca = data.get("sca_reachability_findings", [])
        self.assertEqual(len(sca), 1)
        self.assertEqual(sca[0]["package_name"], "vulnlib")
        self.assertEqual(sca[0]["reachability_classification"], "REACHABLE_API_USE")


if __name__ == "__main__":
    unittest.main()
