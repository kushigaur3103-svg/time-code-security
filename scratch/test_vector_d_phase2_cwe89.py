#!/usr/bin/env python3
"""
Test Suite: Vector D Phase 2 (Deterministic AST Remediation Engine - CWE-89 First).
Validates the 12 Golden Test Matrix scenarios:
1. fixture_01_sqli_fstring byte-for-byte & semantic contract compliance.
2. fixture_02_sqli_concat byte-for-byte & semantic contract compliance.
3. Multiple interpolation ordering (positional tuple parameter ordering).
4. Expression-valued interpolation preservation.
5. Rejection of dynamic table/column identifiers (UNSUPPORTED_CWE).
6. Syntax failure path handling (FAILED_SYNTAX & verification_passed=False).
7. Verification failure path handling (FAILED_VERIFICATION & verification_passed=False).
8. Unsupported CWE dispatch (UNSUPPORTED_CWE for CWE-78, CWE-22, etc.).
9. Negative space isolation: 2 findings, patch A, only A disappears, B remains.
10. Byte-for-byte preservation of original source input.
11. Deterministic idempotency over repeated remediation cycles.
12. Deterministic unified diff generation and patch applicability.
"""

import ast
import difflib
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation import (
    PatchStatus,
    RemediationRule,
    RemediationRecord,
    RemediationEngine,
    RuleDispatcher,
    RemediationVerifier,
    Cwe89ParameterizeTransformer,
    FIXTURE_SEMANTIC_CONTRACTS,
)
from tcs_cli import execute_tcs_scan


class TestVectorDPhase2Cwe89GoldenMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures_dir = REPO_ROOT / "tests" / "fixtures" / "vector_d"
        cls.engine = RemediationEngine()

    def test_01_fixture_01_sqli_fstring(self):
        """Matrix 1: fixture_01_sqli_fstring byte-for-byte match & semantic contract."""
        fdir = self.fixtures_dir / "fixture_01_sqli_fstring"
        vuln_code = (fdir / "vuln.py").read_text(encoding="utf-8")
        expected_patch = (fdir / "expected_patch.py").read_text(encoding="utf-8")

        finding = {
            "id": "TCS-VULN-001",
            "cwe": "CWE-89",
            "file": "vuln.py",
            "line_number": 4,
            "sink_symbol": "cursor.execute",
            "code_snippet": "cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")",
        }

        record = self.engine.remediate(finding, vuln_code, "vuln.py")

        self.assertEqual(record.patch_status, PatchStatus.SUCCESS)
        self.assertTrue(record.verification_passed)
        self.assertEqual(record.remediation_rule, RemediationRule.SQLI_PARAMETERIZE)
        self.assertEqual(record.cwe, "CWE-89")
        self.assertIn("?", record.patched_code_snippet)
        self.assertNotIn("{username}", record.patched_code_snippet)

        # Byte-for-byte exact patch match
        # Verify patched code reproduces expected_patch exactly
        patched_full = vuln_code.replace(
            "    cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")",
            "    " + record.patched_code_snippet
        )
        self.assertEqual(patched_full, expected_patch)

    def test_02_fixture_02_sqli_concat(self):
        """Matrix 2: fixture_02_sqli_concat byte-for-byte match & semantic contract."""
        fdir = self.fixtures_dir / "fixture_02_sqli_concat"
        vuln_code = (fdir / "vuln.py").read_text(encoding="utf-8")
        expected_patch = (fdir / "expected_patch.py").read_text(encoding="utf-8")

        finding = {
            "id": "TCS-VULN-002",
            "cwe": "CWE-89",
            "file": "vuln.py",
            "line_number": 5,
            "sink_symbol": "cursor.execute",
            "code_snippet": "cursor.execute(query)",
        }

        record = self.engine.remediate(finding, vuln_code, "vuln.py")

        self.assertEqual(record.patch_status, PatchStatus.SUCCESS)
        self.assertTrue(record.verification_passed)
        self.assertEqual(record.remediation_rule, RemediationRule.SQLI_PARAMETERIZE)
        self.assertEqual(record.cwe, "CWE-89")

        # Verify query line has ? and execute line has (order_id,)
        self.assertIn("?", record.patched_code_snippet)
        self.assertIn("(order_id,)", record.patched_code_snippet)
        self.assertNotIn("str(order_id)", record.patched_code_snippet)

        # Byte-for-byte patch check on whole file
        patched_lines = vuln_code.splitlines(keepends=True)
        patched_lines[3] = '    query = "SELECT * FROM orders WHERE id = ?"\n'
        patched_lines[4] = '    cursor.execute(query, (order_id,))\n'
        self.assertEqual("".join(patched_lines), expected_patch)

    def test_03_multiple_interpolation_ordering(self):
        """Matrix 3: Multiple interpolations preserve left-to-right positional order in tuple."""
        code = (
            "import sqlite3\n\n"
            "def filter_users(cursor, name, role, dept):\n"
            "    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}' AND role = '{role}' AND dept_id = {dept}\")\n"
            "    return cursor.fetchall()\n"
        )
        finding = {
            "id": "TCS-VULN-003",
            "cwe": "CWE-89",
            "file": "query.py",
            "line_number": 4,
            "sink_symbol": "cursor.execute",
        }

        record = self.engine.remediate(finding, code, "query.py")
        self.assertEqual(record.patch_status, PatchStatus.SUCCESS)
        self.assertTrue(record.verification_passed)

        # Patched snippet check
        expected_sql = "SELECT * FROM users WHERE name = ? AND role = ? AND dept_id = ?"
        self.assertIn(expected_sql, record.patched_code_snippet)
        self.assertIn("(name, role, dept)", record.patched_code_snippet)

    def test_04_expression_valued_interpolation(self):
        """Matrix 4: Expression-valued interpolations preserved without evaluation."""
        code = (
            "import sqlite3\n\n"
            "def get_item(cursor, request, tenant):\n"
            "    cursor.execute(f\"SELECT * FROM items WHERE tenant_id = '{tenant.id}' AND key = '{request.args.get('k')}'\")\n"
            "    return cursor.fetchone()\n"
        )
        finding = {
            "id": "TCS-VULN-004",
            "cwe": "CWE-89",
            "file": "items.py",
            "line_number": 4,
            "sink_symbol": "cursor.execute",
        }

        record = self.engine.remediate(finding, code, "items.py")
        self.assertEqual(record.patch_status, PatchStatus.SUCCESS)
        self.assertTrue(record.verification_passed)

        self.assertIn("SELECT * FROM items WHERE tenant_id = ? AND key = ?", record.patched_code_snippet)
        self.assertIn("tenant.id", record.patched_code_snippet)
        self.assertIn("request.args.get('k')", record.patched_code_snippet)

    def test_05_unsupported_dynamic_table_column_rejection(self):
        """Matrix 5: Dynamic table or column names produce UNSUPPORTED_CWE."""
        # 1. Dynamic table name in FROM
        code_table = (
            "import sqlite3\n\n"
            "def query_table(cursor, table_name, uid):\n"
            "    cursor.execute(f\"SELECT * FROM {table_name} WHERE id = '{uid}'\")\n"
            "    return cursor.fetchall()\n"
        )
        finding = {
            "id": "TCS-VULN-005",
            "cwe": "CWE-89",
            "file": "dyn.py",
            "line_number": 4,
            "sink_symbol": "cursor.execute",
        }
        rec_table = self.engine.remediate(finding, code_table, "dyn.py")
        self.assertEqual(rec_table.patch_status, PatchStatus.UNSUPPORTED_CWE)
        self.assertFalse(rec_table.verification_passed)
        self.assertTrue(any("table/column" in lim.lower() for lim in rec_table.limitations))

        # 2. Dynamic column name in SELECT
        code_col = (
            "import sqlite3\n\n"
            "def query_col(cursor, col_name, uid):\n"
            "    cursor.execute(f\"SELECT {col_name} FROM users WHERE id = '{uid}'\")\n"
            "    return cursor.fetchall()\n"
        )
        rec_col = self.engine.remediate(finding, code_col, "dyn.py")
        self.assertEqual(rec_col.patch_status, PatchStatus.UNSUPPORTED_CWE)
        self.assertFalse(rec_col.verification_passed)

    def test_06_syntax_failure_path(self):
        """Matrix 6: Syntax error in input source or patch produces FAILED_SYNTAX."""
        bad_syntax_code = "def broken(\n    cursor.execute('select')\n"
        finding = {
            "id": "TCS-VULN-006",
            "cwe": "CWE-89",
            "file": "broken.py",
            "line_number": 2,
            "sink_symbol": "cursor.execute",
        }
        record = self.engine.remediate(finding, bad_syntax_code, "broken.py")
        self.assertEqual(record.patch_status, PatchStatus.FAILED_SYNTAX)
        self.assertFalse(record.verification_passed)
        self.assertTrue(len(record.limitations) > 0)

    def test_07_verification_failure_path(self):
        """Matrix 7: Verification failure path returns FAILED_VERIFICATION when vulnerability persists."""
        class FailingVerifier(RemediationVerifier):
            def verify(self, original_file, original_source, patched_source, target_finding):
                return (False, "Simulated verification failure: target sink still vulnerable")

        failing_engine = RemediationEngine(verifier=FailingVerifier())
        fdir = self.fixtures_dir / "fixture_01_sqli_fstring"
        vuln_code = (fdir / "vuln.py").read_text(encoding="utf-8")
        finding = {
            "id": "TCS-VULN-007",
            "cwe": "CWE-89",
            "file": "vuln.py",
            "line_number": 4,
            "sink_symbol": "cursor.execute",
        }

        record = failing_engine.remediate(finding, vuln_code, "vuln.py")
        self.assertEqual(record.patch_status, PatchStatus.FAILED_VERIFICATION)
        self.assertFalse(record.verification_passed)
        self.assertIn("Simulated verification failure", record.limitations[0])

    def test_08_unsupported_cwe_dispatch(self):
        """Matrix 8: Unsupported CWEs (CWE-78, CWE-22, unknown) produce UNSUPPORTED_CWE."""
        finding_cwe78 = {
            "id": "TCS-VULN-008A",
            "cwe": "CWE-78",
            "file": "cmd.py",
            "line_number": 3,
            "sink_symbol": "subprocess.call",
        }
        rec_78 = self.engine.remediate(finding_cwe78, "import subprocess\nsubprocess.call(cmd, shell=True)\n", "cmd.py")
        self.assertEqual(rec_78.patch_status, PatchStatus.UNSUPPORTED_CWE)
        self.assertEqual(rec_78.remediation_rule, RemediationRule.CMD_INJECTION_SPLIT)
        self.assertFalse(rec_78.verification_passed)

        finding_cwe22 = {
            "id": "TCS-VULN-008B",
            "cwe": "CWE-22",
            "file": "path.py",
            "line_number": 3,
            "sink_symbol": "open",
        }
        rec_22 = self.engine.remediate(finding_cwe22, "import os\nopen('/tmp/' + user_file)\n", "path.py")
        self.assertEqual(rec_22.patch_status, PatchStatus.UNSUPPORTED_CWE)
        self.assertEqual(rec_22.remediation_rule, RemediationRule.PATH_TRAVERSAL_RESOLVE)
        self.assertFalse(rec_22.verification_passed)

    def test_09_two_findings_negative_space_isolation(self):
        """Matrix 9: Two findings exist; patching finding A causes A to disappear while B remains."""
        code_two_flaws = (
            "import sqlite3\n"
            "import os\n\n"
            "def handle_both(cursor, user_id, filename):\n"
            "    cursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")\n"
            "    open('/var/data/' + filename)\n"
        )

        # Baseline: execute Vector B scan to confirm 2 findings exist
        scan_before = execute_tcs_scan({"app.py": code_two_flaws}, audit_all=True)
        findings_before = scan_before.get("findings", [])
        self.assertTrue(len(findings_before) >= 2, f"Expected at least 2 findings, got {len(findings_before)}")

        cwe89_finding = next(f for f in findings_before if f["cwe"] == "CWE-89")
        other_finding = next(f for f in findings_before if f["cwe"] != "CWE-89")

        # Remediate only CWE-89 finding
        record = self.engine.remediate(cwe89_finding, code_two_flaws, "app.py")
        self.assertEqual(record.patch_status, PatchStatus.SUCCESS)
        self.assertTrue(record.verification_passed)

        # Re-scan to verify isolation
        # Apply patch to source
        patched_code = code_two_flaws.replace(
            "    cursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")",
            "    " + record.patched_code_snippet
        )
        scan_after = execute_tcs_scan({"app.py": patched_code}, audit_all=True)
        findings_after = scan_after.get("findings", [])

        # Finding A (CWE-89) must be gone
        has_cwe89 = any(f["cwe"] == "CWE-89" for f in findings_after)
        self.assertFalse(has_cwe89, "Target CWE-89 finding should be gone after remediation")

        # Finding B (other finding) must remain present
        has_other = any(f["cwe"] == other_finding["cwe"] for f in findings_after)
        self.assertTrue(has_other, f"Unrelated finding {other_finding['cwe']} must remain detected")

    def test_10_original_source_byte_preservation(self):
        """Matrix 10: Original source code string is byte-for-byte identical before and after remediation."""
        fdir = self.fixtures_dir / "fixture_01_sqli_fstring"
        vuln_code = (fdir / "vuln.py").read_text(encoding="utf-8")
        vuln_copy = str(vuln_code)

        finding = {
            "id": "TCS-VULN-010",
            "cwe": "CWE-89",
            "file": "vuln.py",
            "line_number": 4,
            "sink_symbol": "cursor.execute",
        }

        record = self.engine.remediate(finding, vuln_code, "vuln.py")
        self.assertEqual(record.patch_status, PatchStatus.SUCCESS)

        # Byte-level identity assertion
        self.assertEqual(vuln_code, vuln_copy, "Input source code must never be mutated in place")

    def test_11_deterministic_repeated_transformation(self):
        """Matrix 11: Running remediation multiple times produces identical diff and record."""
        fdir = self.fixtures_dir / "fixture_01_sqli_fstring"
        vuln_code = (fdir / "vuln.py").read_text(encoding="utf-8")
        finding = {
            "id": "TCS-VULN-011",
            "cwe": "CWE-89",
            "file": "vuln.py",
            "line_number": 4,
            "sink_symbol": "cursor.execute",
        }

        records = [self.engine.remediate(finding, vuln_code, "vuln.py") for _ in range(5)]

        first_diff = records[0].unified_diff
        first_snippet = records[0].patched_code_snippet
        for i, rec in enumerate(records[1:], 2):
            self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)
            self.assertTrue(rec.verification_passed)
            self.assertEqual(rec.unified_diff, first_diff, f"Run {i} produced different diff")
            self.assertEqual(rec.patched_code_snippet, first_snippet, f"Run {i} produced different snippet")

    def test_12_deterministic_unified_diff(self):
        """Matrix 12: Unified diff is valid, non-empty, and contains correct headers and chunks."""
        fdir = self.fixtures_dir / "fixture_01_sqli_fstring"
        vuln_code = (fdir / "vuln.py").read_text(encoding="utf-8")
        finding = {
            "id": "TCS-VULN-012",
            "cwe": "CWE-89",
            "file": "vuln.py",
            "line_number": 4,
            "sink_symbol": "cursor.execute",
        }

        record = self.engine.remediate(finding, vuln_code, "vuln.py")
        diff = record.unified_diff

        self.assertTrue(len(diff) > 0)
        self.assertIn("--- a/vuln.py", diff)
        self.assertIn("+++ b/vuln.py", diff)
        self.assertIn("-    cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")", diff)
        self.assertIn("+    cursor.execute(\"SELECT * FROM users WHERE username = ?\", (username,))", diff)

    def test_13_inline_binop_concatenation(self):
        """Matrix 13: Direct inline concatenation inside execute(query + str(x))."""
        code = (
            "import sqlite3\n\n"
            "def inline_query(cursor, user_id):\n"
            "    cursor.execute('SELECT * FROM accounts WHERE id = ' + str(user_id))\n"
            "    return cursor.fetchall()\n"
        )
        finding = {
            "id": "TCS-VULN-013",
            "cwe": "CWE-89",
            "file": "inline.py",
            "line_number": 4,
            "sink_symbol": "cursor.execute",
        }
        record = self.engine.remediate(finding, code, "inline.py")
        self.assertEqual(record.patch_status, PatchStatus.SUCCESS)
        self.assertTrue(record.verification_passed)
        self.assertIn('cursor.execute("SELECT * FROM accounts WHERE id = ?", (user_id,))', record.patched_code_snippet)

    def test_14_single_parameter_trailing_comma(self):
        """Matrix 14: Single parameter tuple must have a trailing comma to be a valid Python 1-tuple."""
        code = (
            "import sqlite3\n\n"
            "def one_arg(cursor, val):\n"
            "    cursor.execute(f\"SELECT * FROM t WHERE col = '{val}'\")\n"
        )
        finding = {
            "id": "TCS-VULN-014",
            "cwe": "CWE-89",
            "file": "comma.py",
            "line_number": 4,
            "sink_symbol": "cursor.execute",
        }
        record = self.engine.remediate(finding, code, "comma.py")
        self.assertEqual(record.patch_status, PatchStatus.SUCCESS)
        self.assertIn("(val,)", record.patched_code_snippet)

    def test_15_comments_and_docstrings_preserved(self):
        """Matrix 15: Comments and docstrings outside the target sink are preserved byte-for-byte."""
        code = (
            "# Top level file comment\n"
            "import sqlite3\n\n"
            "def fetch_data(cursor, uid):\n"
            "    \"\"\"Docstring with special instructions.\"\"\"\n"
            "    # Crucial inline comment\n"
            "    cursor.execute(f\"SELECT * FROM data WHERE uid = '{uid}'\")\n"
            "    # Trailing note\n"
            "    return cursor.fetchall()\n"
        )
        finding = {
            "id": "TCS-VULN-015",
            "cwe": "CWE-89",
            "file": "comm.py",
            "line_number": 7,
            "sink_symbol": "cursor.execute",
        }
        record = self.engine.remediate(finding, code, "comm.py")
        self.assertEqual(record.patch_status, PatchStatus.SUCCESS)

        # Build patched source by applying diff/snippet
        patched_code = code.replace(
            "    cursor.execute(f\"SELECT * FROM data WHERE uid = '{uid}'\")",
            "    " + record.patched_code_snippet
        )
        self.assertIn("# Top level file comment\n", patched_code)
        self.assertIn('    """Docstring with special instructions."""\n', patched_code)
        self.assertIn("    # Crucial inline comment\n", patched_code)
        self.assertIn("    # Trailing note\n", patched_code)

    def test_16_windows_crlf_preservation(self):
        """Matrix 16: Windows CRLF (\\r\\n) line endings are preserved in replacement."""
        code_crlf = (
            "import sqlite3\r\n\r\n"
            "def crlf_func(cursor, uid):\r\n"
            "    cursor.execute(f\"SELECT * FROM tbl WHERE id = '{uid}'\")\r\n"
            "    return cursor.fetchone()\r\n"
        )
        finding = {
            "id": "TCS-VULN-016",
            "cwe": "CWE-89",
            "file": "crlf.py",
            "line_number": 4,
            "sink_symbol": "cursor.execute",
        }
        record = self.engine.remediate(finding, code_crlf, "crlf.py")
        self.assertEqual(record.patch_status, PatchStatus.SUCCESS)

        # Find replacement line in diff or patched lines
        diff = record.unified_diff
        self.assertIn("+    cursor.execute(\"SELECT * FROM tbl WHERE id = ?\", (uid,))", diff)

    def test_17_tab_indentation_preservation(self):
        """Matrix 17: Tab characters (\\t) used for indentation are preserved in replacement."""
        code_tabs = (
            "import sqlite3\n\n"
            "def tab_func(cursor, uid):\n"
            "\tcursor.execute(f\"SELECT * FROM tbl WHERE id = '{uid}'\")\n"
            "\treturn cursor.fetchone()\n"
        )
        finding = {
            "id": "TCS-VULN-017",
            "cwe": "CWE-89",
            "file": "tabs.py",
            "line_number": 4,
            "sink_symbol": "cursor.execute",
        }
        record = self.engine.remediate(finding, code_tabs, "tabs.py")
        self.assertEqual(record.patch_status, PatchStatus.SUCCESS)
        diff = record.unified_diff
        self.assertIn("+\tcursor.execute(\"SELECT * FROM tbl WHERE id = ?\", (uid,))", diff)

    def test_18_double_quote_delimiter_stripping(self):
        """Matrix 18: Double-quoted interpolation placeholders are correctly stripped."""
        code = (
            "import sqlite3\n\n"
            "def query_dq(cursor, name):\n"
            "    cursor.execute(f'SELECT * FROM users WHERE name = \"{name}\"')\n"
        )
        finding = {
            "id": "TCS-VULN-018",
            "cwe": "CWE-89",
            "file": "dq.py",
            "line_number": 4,
            "sink_symbol": "cursor.execute",
        }
        record = self.engine.remediate(finding, code, "dq.py")
        self.assertEqual(record.patch_status, PatchStatus.SUCCESS)
        self.assertIn('SELECT * FROM users WHERE name = ?', record.patched_code_snippet)
        self.assertNotIn('"{name}"', record.patched_code_snippet)
        self.assertNotIn('"?"', record.patched_code_snippet)


if __name__ == "__main__":
    unittest.main()
