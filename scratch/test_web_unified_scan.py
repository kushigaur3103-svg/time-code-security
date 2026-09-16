#!/usr/bin/env python3
"""
Adversarial Test Suite for Unified Web Backend Scan (app.py).
Tests end-to-end detection of 6 total flaws:
1. SQLi (CWE-89): cursor.execute(f"SELECT ... {user_query}")
2. Path Traversal (CWE-22): open(os.path.join('/tmp', doc_name))
3. Command Injection (CWE-78): subprocess.check_output(f"traceroute {target_ip}", shell=True)
4. Code Execution (CWE-95): eval(formula)
5. Hardcoded Secret (CWE-798): Stripe live API key
6. Hardcoded Secret (CWE-798): PostgreSQL connection URI
"""

import os
import sys
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from app import app, execute_tcs_ast_scan
from fastapi.testclient import TestClient


DUMMY_STRIPE = "sk_" + "live_" + "51Abcdef1234567890abcdef1234567890"
DUMMY_DB = "postgres" + "ql://dbuser:super_secret_db_pass_2026@db.internal:5432/proddb"

SIX_FLAW_SNIPPET = f'''
import os
import subprocess
from flask import request

# Secret Leaks (CWE-798)
STRIPE_SECRET_KEY = "{DUMMY_STRIPE}"
DATABASE_URL = "{DUMMY_DB}"

def handle_request(cursor):
    # 1. SQLi: cursor.execute(f"...{{user_query}}")
    user_query = request.args.get('q')
    cursor.execute(f"SELECT * FROM users WHERE name = '{{user_query}}'")

    # 2. Path Traversal: open(os.path.join(..., doc_name))
    doc_name = request.args.get('doc')
    open(os.path.join('/tmp', doc_name))

    # 3. Command Injection: subprocess.check_output(f"traceroute {{target_ip}}", shell=True)
    target_ip = request.args.get('ip')
    subprocess.check_output(f"traceroute {{target_ip}}", shell=True)

    # 4. Code Execution: eval(formula)
    formula = request.args.get('f')
    eval(formula)
'''


class TestWebUnifiedScan(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)
        self.code = SIX_FLAW_SNIPPET

    def test_01_execute_tcs_ast_scan_direct(self):
        """Verify execute_tcs_ast_scan catches all 6 flaws with correct metrics."""
        result = execute_tcs_ast_scan({"app.py": self.code})

        self.assertEqual(result["status"], "success")
        summary = result["summary"]
        findings = result["findings"]

        # 1. Assert exactly 6 total flaws
        self.assertEqual(summary["total_flaws"], 6, f"Expected 6 total flaws, got {summary['total_flaws']}")
        self.assertEqual(summary["total_vulnerabilities"], 6)
        self.assertEqual(len(findings), 6)

        # 2. Assert secrets detected
        self.assertEqual(summary["secrets_detected"], 2)
        secret_findings = [f for f in findings if f.get("is_secret")]
        self.assertEqual(len(secret_findings), 2)

        # 3. Assert CWE breakdown
        cwes = [f["cwe"] for f in findings]
        self.assertIn("CWE-89", cwes)
        self.assertIn("CWE-22", cwes)
        self.assertIn("CWE-78", cwes)
        self.assertIn("CWE-95", cwes)
        self.assertEqual(cwes.count("CWE-798"), 2)

        # 4. Assert Secret finding structure
        for sec in secret_findings:
            self.assertEqual(sec["cwe"], "CWE-798")
            self.assertEqual(sec["severity"], "CRITICAL")
            self.assertEqual(sec["confidence"], 1.0)
            self.assertEqual(sec["confidence_label"], "CONFIRMED")
            self.assertTrue(sec["is_secret"])
            self.assertTrue(bool(sec.get("masked_value")))
            # Verify secret is masked and doesn't reveal plaintext secret in full
            self.assertIn("*", sec["masked_value"])
            # Verify proof graph exists with SECRET_EXPOSURE node
            self.assertIsNotNone(sec.get("proof_graph"))
            nodes = sec["proof_graph"].get("nodes", [])
            self.assertEqual(len(nodes), 1)
            self.assertEqual(nodes[0]["node_type"], "SECRET_EXPOSURE")

        # 5. Assert score penalty
        # 4 Criticals (CmdInj, CodeExec, 2 Secrets) + 2 High (SQLi, Path Traversal) = 4*25 + 2*15 = 130 -> score 0
        self.assertEqual(summary["critical_count"], 4)
        self.assertEqual(summary["high_count"], 2)
        self.assertEqual(summary["security_score"], 0)
        self.assertEqual(summary["risk_level"], "CRITICAL")

    def test_02_api_scan_endpoint(self):
        """Verify POST /api/scan returns 200 with all 6 flaws and normalized findings."""
        response = self.client.post("/api/scan", json={"code": self.code})
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["summary"]["total_flaws"], 6)
        self.assertEqual(data["summary"]["secrets_detected"], 2)
        self.assertEqual(len(data["findings"]), 6)

        # Verify CWEs in API response
        cwes = [f["cwe"] for f in data["findings"]]
        self.assertIn("CWE-89", cwes)
        self.assertIn("CWE-22", cwes)
        self.assertIn("CWE-78", cwes)
        self.assertIn("CWE-95", cwes)
        self.assertEqual(cwes.count("CWE-798"), 2)

    def test_03_scan_alias_endpoint(self):
        """Verify POST /scan alias endpoint behaves identically."""
        response = self.client.post("/scan", json={"code": self.code})
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["summary"]["total_flaws"], 6)
        self.assertEqual(data["summary"]["secrets_detected"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
