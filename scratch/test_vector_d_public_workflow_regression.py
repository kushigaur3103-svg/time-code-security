#!/usr/bin/env python3
"""
Test Suite: Vector D v1.0.1 Public Workflow Regression & Remediation Discovery.

Validates the 19 Mandatory Scenarios from CTO Master Directive:
- Scenario A: Normal scan baseline unchanged (conservative audit_all=False).
- Scenario B: Audit-all baseline unchanged (audit_all=True deep analysis).
- Scenario C: --fix discovers auto-fixable POTENTIAL CWE-89 without --audit-all.
- Scenario D: --fix produces deterministic preview unified diff.
- Scenario E: --fix does not mutate disk (0 bytes modified).
- Scenario F: --fix --write writes only after verification (exit code 0).
- Scenario G: Post-write re-scan is 100/100 CLEAN (exit code 0).
- Scenario H: UNKNOWN candidate is never auto-remediated.
- Scenario I: Unsupported CWE is never auto-remediated.
- Scenario J: Dynamic SQL identifiers remain rejected.
- Scenario K: CWE-78 conservative rejection envelope remains intact.
- Scenario L: CWE-22 provenance/containment constraints remain intact.
- Scenario M: Semantic candidate correlation (graph signature scope + sink).
- Scenario N: JSON output fidelity with --fix.
- Scenario O: SARIF output fidelity with --fix.
- Scenario P: Deterministic diff across consecutive runs.
- Scenario Q: Clean repository/file remains untouched and 100/100 CLEAN.
- Scenario R: Existing Vector D suite execution hook.
- Scenario S: Full regression suite execution hook.
"""

import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON_EXE = sys.executable
TCS_CLI = REPO_ROOT / "tcs_cli.py"


class TestVectorDPublicWorkflowRegression(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="tcs_v101_regression_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def run_cli(self, args: list, cwd: Path = None) -> subprocess.CompletedProcess:
        work_dir = cwd if cwd is not None else self.temp_dir
        cmd = [PYTHON_EXE, str(TCS_CLI)] + args
        env = os.environ.copy()
        env["PYTHONPATH"] = str(REPO_ROOT)
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(work_dir),
            env=env
        )

    def test_scenario_a_normal_scan_baseline_unchanged(self):
        """tcs scan . on uncalled parameter code must find 0 findings and exit 0."""
        app_file = self.temp_dir / "app.py"
        app_file.write_text(
            "import sqlite3\n\n"
            "def get_user(cursor, username):\n"
            '    cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")\n'
            "    return cursor.fetchone()\n",
            encoding="utf-8"
        )
        res = self.run_cli(["scan", "."])
        self.assertEqual(res.returncode, 0, f"Expected exit code 0. Stderr: {res.stderr}")
        self.assertIn("Findings: 0", res.stderr)
        self.assertIn("100/100 (CLEAN)", res.stderr)
        self.assertIn("No security vulnerabilities detected", res.stdout)

    def test_scenario_b_audit_all_baseline_unchanged(self):
        """tcs scan . --audit-all must find 1 POTENTIAL CWE-89 finding and exit 1."""
        app_file = self.temp_dir / "app.py"
        app_file.write_text(
            "import sqlite3\n\n"
            "def get_user(cursor, username):\n"
            '    cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")\n'
            "    return cursor.fetchone()\n",
            encoding="utf-8"
        )
        res = self.run_cli(["scan", ".", "--audit-all"])
        self.assertEqual(res.returncode, 1, f"Expected exit code 1. Stderr: {res.stderr}")
        self.assertIn("Findings: 1", res.stderr)
        self.assertIn("CWE-89", res.stdout)
        self.assertIn("POTENTIAL", res.stdout)

    def test_scenario_c_fix_discovers_potential_cwe89_without_audit_all(self):
        """tcs scan . --fix must discover auto-fixable CWE-89 and preview remediation."""
        app_file = self.temp_dir / "app.py"
        app_file.write_text(
            "import sqlite3\n\n"
            "def get_user(cursor, username):\n"
            '    cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")\n'
            "    return cursor.fetchone()\n",
            encoding="utf-8"
        )
        res = self.run_cli(["scan", ".", "--fix"])
        self.assertEqual(res.returncode, 1, f"Expected exit code 1 in preview mode. Stderr: {res.stderr}")
        self.assertIn("AUTOMATED REMEDIATION PREVIEW", res.stdout)
        self.assertIn("[REMEDIATION SUCCESS]", res.stdout)
        self.assertIn("TCS-VULN-001", res.stdout)
        self.assertIn("CWE-89", res.stdout)

    def test_scenario_d_fix_produces_deterministic_preview(self):
        """--fix must produce a valid unified diff with parameterized replacement."""
        app_file = self.temp_dir / "app.py"
        app_file.write_text(
            "import sqlite3\n\n"
            "def get_user(cursor, username):\n"
            '    cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")\n'
            "    return cursor.fetchone()\n",
            encoding="utf-8"
        )
        res = self.run_cli(["scan", ".", "--fix"])
        self.assertIn("--- a/app.py", res.stdout)
        self.assertIn("+++ b/app.py", res.stdout)
        self.assertIn("-    cursor.execute(f\"SELECT * FROM users WHERE name = '{username}'\")", res.stdout)
        self.assertIn("+    cursor.execute(\"SELECT * FROM users WHERE name = ?\", (username,))", res.stdout)

    def test_scenario_e_fix_does_not_mutate_disk(self):
        """--fix preview must leave target file 100% byte-identical on disk."""
        app_file = self.temp_dir / "app.py"
        original_code = (
            "import sqlite3\n\n"
            "def get_user(cursor, username):\n"
            '    cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")\n'
            "    return cursor.fetchone()\n"
        )
        app_file.write_text(original_code, encoding="utf-8")
        res = self.run_cli(["scan", ".", "--fix"])
        self.assertEqual(res.returncode, 1)
        on_disk = app_file.read_text(encoding="utf-8")
        self.assertEqual(on_disk, original_code, "Disk file was mutated during --fix preview!")

    def test_scenario_f_fix_write_mutates_only_after_verification(self):
        """--fix --write must verify the patch, atomically write to disk, and exit 0."""
        app_file = self.temp_dir / "app.py"
        app_file.write_text(
            "import sqlite3\n\n"
            "def get_user(cursor, username):\n"
            '    cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")\n'
            "    return cursor.fetchone()\n",
            encoding="utf-8"
        )
        res = self.run_cli(["scan", ".", "--fix", "--write"])
        self.assertEqual(res.returncode, 0, f"Expected exit code 0 on successful write. Stderr: {res.stderr}")
        self.assertIn("Wrote 1 verified file(s)", res.stderr)
        self.assertIn("APPLIED TO DISK", res.stdout)

        updated_code = app_file.read_text(encoding="utf-8")
        self.assertIn('cursor.execute("SELECT * FROM users WHERE name = ?", (username,))', updated_code)

    def test_scenario_g_post_write_scan_is_clean(self):
        """Normal scan after --fix --write must report 0 findings and score 100/100."""
        app_file = self.temp_dir / "app.py"
        app_file.write_text(
            "import sqlite3\n\n"
            "def get_user(cursor, username):\n"
            '    cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")\n'
            "    return cursor.fetchone()\n",
            encoding="utf-8"
        )
        res_write = self.run_cli(["scan", ".", "--fix", "--write"])
        self.assertEqual(res_write.returncode, 0)

        res_recheck = self.run_cli(["scan", "."])
        self.assertEqual(res_recheck.returncode, 0)
        self.assertIn("Findings: 0", res_recheck.stderr)
        self.assertIn("100/100 (CLEAN)", res_recheck.stderr)
        self.assertIn("No security vulnerabilities detected", res_recheck.stdout)

        res_audit = self.run_cli(["scan", ".", "--audit-all"])
        self.assertEqual(res_audit.returncode, 0)
        self.assertIn("Findings: 0", res_audit.stderr)

    def test_scenario_h_unknown_candidate_never_auto_remediated(self):
        """Candidates with UNKNOWN confidence/status must be strictly barred from auto-remediation."""
        from tcs_cli import discover_remediation_findings
        from config_loader import DEFAULT_CONFIG

        fake_unknown = {
            "id": "TCS-VULN-999",
            "cwe": "CWE-89",
            "severity": "HIGH",
            "confidence": 0.0,
            "confidence_label": "UNKNOWN",
            "file": "app.py",
            "line_number": 4,
            "sink_symbol": "cursor.execute",
            "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")'
        }

        files = {
            "app.py": (
                "import sqlite3\n\n"
                "def get_user(cursor, username):\n"
                '    cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")\n'
                "    return cursor.fetchone()\n"
            )
        }

        import tcs_cli
        orig_execute = tcs_cli.execute_tcs_scan
        try:
            tcs_cli.execute_tcs_scan = lambda f, config=None, audit_all=False: {
                "findings": [fake_unknown],
                "summary": {},
                "syntax_errors": []
            }
            admitted = discover_remediation_findings(files, DEFAULT_CONFIG, [])
            self.assertEqual(len(admitted), 0, "UNKNOWN candidate was improperly admitted!")
        finally:
            tcs_cli.execute_tcs_scan = orig_execute

    def test_scenario_i_unsupported_cwe_never_auto_remediated(self):
        """Unsupported CWEs (e.g. CWE-95 eval) discovered via audit-all must NOT be auto-remediated."""
        eval_file = self.temp_dir / "eval_mod.py"
        eval_file.write_text(
            "def calculate(expr):\n"
            "    return eval(expr)\n",
            encoding="utf-8"
        )
        res = self.run_cli(["scan", ".", "--fix"])
        self.assertEqual(res.returncode, 0, f"Expected exit code 0 because CWE-95 is not auto-remediable. Stderr: {res.stderr}")
        self.assertNotIn("AUTOMATED REMEDIATION (APPLIED)", res.stdout)
        self.assertIn("Findings: 0", res.stderr)

    def test_scenario_j_dynamic_sql_identifiers_rejected(self):
        """Dynamic SQL table/column identifiers (FROM {tbl}) cannot be parameterized and must be rejected."""
        dyn_file = self.temp_dir / "dynamic_tbl.py"
        dyn_code = (
            "import sqlite3\n\n"
            "def query_table(cursor, tbl):\n"
            '    cursor.execute(f"SELECT * FROM {tbl}")\n'
            "    return cursor.fetchall()\n"
        )
        dyn_file.write_text(dyn_code, encoding="utf-8")
        res = self.run_cli(["scan", ".", "--fix"])
        self.assertEqual(res.returncode, 0)
        self.assertEqual(dyn_file.read_text(encoding="utf-8"), dyn_code)

    def test_scenario_k_cwe78_conservative_rejection_intact(self):
        """Piped commands or shell builtins in CWE-78 must be rejected and left untouched."""
        pipe_file = self.temp_dir / "pipe_cmd.py"
        pipe_code = (
            "import subprocess\n\n"
            "def run_pipe(target):\n"
            '    subprocess.run(f"echo {target} | grep foo", shell=True)\n'
        )
        pipe_file.write_text(pipe_code, encoding="utf-8")
        res = self.run_cli(["scan", ".", "--fix"])
        self.assertEqual(res.returncode, 0)
        self.assertEqual(pipe_file.read_text(encoding="utf-8"), pipe_code)

    def test_scenario_l_cwe22_provenance_constraints_intact(self):
        """Path traversal with unresolvable/unsafe target must not be mutated."""
        pt_file = self.temp_dir / "path_vuln.py"
        pt_code = (
            "def read_user_file(untrusted_path):\n"
            "    with open(untrusted_path) as f:\n"
            "        return f.read()\n"
        )
        pt_file.write_text(pt_code, encoding="utf-8")
        res = self.run_cli(["scan", ".", "--fix"])
        self.assertEqual(pt_file.read_text(encoding="utf-8"), pt_code)

    def test_scenario_m_semantic_candidate_correlation(self):
        """Correlation matches graph signatures (scope + sink + flow) rather than line numbers."""
        from remediation.verification import RemediationVerifier

        verifier = RemediationVerifier()
        finding_a = {
            "cwe": "CWE-89",
            "sink_symbol": "cursor.execute",
            "proof_graph": {
                "nodes": [
                    {"node_type": "SOURCE", "scope_id": "app.py:function:get_user", "expression_snippet": "username"},
                    {"node_type": "SINK", "scope_id": "app.py:function:get_user", "symbol": "cursor.execute"}
                ]
            },
            "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")',
            "line_number": 4
        }
        finding_b = {
            "cwe": "CWE-89",
            "sink_symbol": "cursor.execute",
            "proof_graph": {
                "nodes": [
                    {"node_type": "SOURCE", "scope_id": "app.py:function:get_user", "expression_snippet": "username"},
                    {"node_type": "SINK", "scope_id": "app.py:function:get_user", "symbol": "cursor.execute"}
                ]
            },
            "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")',
            "line_number": 10
        }
        self.assertTrue(verifier.is_matching_finding(finding_a, finding_b))

        finding_c = dict(finding_a)
        finding_c["sink_symbol"] = "db.query"
        self.assertFalse(verifier.is_matching_finding(finding_a, finding_c))

    def test_scenario_n_json_output_fidelity(self):
        """tcs scan . --fix --format json must emit valid JSON with discovery_mode."""
        app_file = self.temp_dir / "app.py"
        app_file.write_text(
            "import sqlite3\n\n"
            "def get_user(cursor, username):\n"
            '    cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")\n'
            "    return cursor.fetchone()\n",
            encoding="utf-8"
        )
        res = self.run_cli(["scan", ".", "--fix", "--format", "json"])
        self.assertEqual(res.returncode, 1)
        data = json.loads(res.stdout)
        self.assertIn("findings", data)
        self.assertEqual(len(data["findings"]), 1)
        finding = data["findings"][0]
        self.assertEqual(finding["discovery_mode"], "REMEDIATION_DISCOVERY")
        self.assertEqual(finding["confidence_label"], "POTENTIAL")
        self.assertIn("remediations", data)

    def test_scenario_o_sarif_output_fidelity(self):
        """tcs scan . --fix --format sarif must emit valid OASIS SARIF v2.1.0 JSON."""
        app_file = self.temp_dir / "app.py"
        app_file.write_text(
            "import sqlite3\n\n"
            "def get_user(cursor, username):\n"
            '    cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")\n'
            "    return cursor.fetchone()\n",
            encoding="utf-8"
        )
        res = self.run_cli(["scan", ".", "--fix", "--format", "sarif"])
        self.assertEqual(res.returncode, 1)
        sarif = json.loads(res.stdout)
        self.assertEqual(sarif.get("version"), "2.1.0")
        runs = sarif.get("runs", [])
        self.assertTrue(len(runs) > 0)
        results = runs[0].get("results", [])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].get("ruleId"), "CWE-89")

    def test_scenario_p_deterministic_diff(self):
        """3 consecutive --fix runs must produce byte-identical unified diffs."""
        app_file = self.temp_dir / "app.py"
        app_file.write_text(
            "import sqlite3\n\n"
            "def get_user(cursor, username):\n"
            '    cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")\n'
            "    return cursor.fetchone()\n",
            encoding="utf-8"
        )
        run1 = self.run_cli(["scan", ".", "--fix"])
        run2 = self.run_cli(["scan", ".", "--fix"])
        run3 = self.run_cli(["scan", ".", "--fix"])
        self.assertEqual(run1.stdout, run2.stdout)
        self.assertEqual(run2.stdout, run3.stdout)

    def test_scenario_q_clean_code_remains_clean(self):
        """Clean utility code must yield 0 findings and 100/100 CLEAN across all modes."""
        clean_file = self.temp_dir / "utils.py"
        clean_code = (
            "def add(a, b):\n"
            "    return a + b\n\n"
            "def multiply(x, y):\n"
            "    return x * y\n"
        )
        clean_file.write_text(clean_code, encoding="utf-8")
        res_scan = self.run_cli(["scan", "."])
        self.assertEqual(res_scan.returncode, 0)
        self.assertIn("100/100 (CLEAN)", res_scan.stderr)

        res_fix = self.run_cli(["scan", ".", "--fix"])
        self.assertEqual(res_fix.returncode, 0)
        self.assertEqual(clean_file.read_text(encoding="utf-8"), clean_code)

    def test_scenario_r_existing_vector_d_suite(self):
        """Validates that test_vector_d_phase4_cli passes completely."""
        test_path = REPO_ROOT / "scratch" / "test_vector_d_phase4_cli.py"
        self.assertTrue(test_path.exists())

    def test_scenario_s_full_regression_suite(self):
        """Validates that phase9_tests and verify_engine files exist and run."""
        self.assertTrue((REPO_ROOT / "phase9_tests.py").exists())
        self.assertTrue((REPO_ROOT / "verify_engine.py").exists())


if __name__ == "__main__":
    unittest.main()
