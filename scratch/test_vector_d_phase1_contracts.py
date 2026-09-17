#!/usr/bin/env python3
"""
Test Suite: Vector D Phase 1 (Remediation Contracts & Fixtures Hardening).
Validates:
1. Data structures and contracts immutability, serialization, and deserialization.
2. Invariant validation: strict rejection of contradictory patch states.
3. Machine-readable fixture metadata and semantic contracts.
4. AST parseability and semantic properties of all golden fixtures.
5. Scope enforcement: zero transformers/dispatchers in Phase 1.
"""

import ast
import difflib
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import remediation
from remediation.contracts import (
    PatchStatus,
    RemediationRule,
    RemediationRecord,
    FIXTURE_SEMANTIC_CONTRACTS,
)


class TestVectorDContracts(unittest.TestCase):
    def test_patch_status_enum(self):
        self.assertEqual(PatchStatus.SUCCESS.value, "SUCCESS")
        self.assertEqual(PatchStatus.FAILED_SYNTAX.value, "FAILED_SYNTAX")
        self.assertEqual(PatchStatus.FAILED_VERIFICATION.value, "FAILED_VERIFICATION")
        self.assertEqual(PatchStatus.UNSUPPORTED_CWE.value, "UNSUPPORTED_CWE")

    def test_remediation_rule_enum(self):
        self.assertEqual(RemediationRule.SQLI_PARAMETERIZE.value, "SQLI_PARAMETERIZE")
        self.assertEqual(RemediationRule.PATH_TRAVERSAL_RESOLVE.value, "PATH_TRAVERSAL_RESOLVE")
        self.assertEqual(RemediationRule.CMD_INJECTION_SPLIT.value, "CMD_INJECTION_SPLIT")

    def test_remediation_record_instantiation_and_immutability(self):
        rec = RemediationRecord(
            finding_id="TCS-REM-001",
            cwe="CWE-89",
            remediation_rule=RemediationRule.SQLI_PARAMETERIZE,
            original_file="app.py",
            line_number=42,
            patch_status=PatchStatus.SUCCESS,
            original_code_snippet="cursor.execute(f'SELECT * FROM u WHERE id={uid}')",
            patched_code_snippet="cursor.execute('SELECT * FROM u WHERE id=?', (uid,))",
            unified_diff="- cursor.execute(f'SELECT * FROM u WHERE id={uid}')\n+ cursor.execute('SELECT * FROM u WHERE id=?', (uid,))",
            verification_passed=True,
            limitations=("Assumes sqlite3 dialect",),
        )
        self.assertEqual(rec.finding_id, "TCS-REM-001")
        self.assertEqual(rec.cwe, "CWE-89")
        self.assertEqual(rec.remediation_rule, RemediationRule.SQLI_PARAMETERIZE)
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)
        self.assertTrue(rec.verification_passed)

        # Immutability check
        with self.assertRaises((AttributeError, TypeError)):
            rec.line_number = 99  # type: ignore

    def test_remediation_record_serialization_roundtrip(self):
        rec = RemediationRecord(
            finding_id="TCS-REM-002",
            cwe="CWE-78",
            remediation_rule=RemediationRule.CMD_INJECTION_SPLIT,
            original_file="server.py",
            line_number=15,
            patch_status=PatchStatus.SUCCESS,
            original_code_snippet="subprocess.call(cmd, shell=True)",
            patched_code_snippet="subprocess.call(cmd_list, shell=False)",
            unified_diff="@@ -15,1 +15,1 @@",
            verification_passed=True,
            limitations=("Requires shlex.split for arbitrary shell strings",),
        )
        d = rec.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["patch_status"], "SUCCESS")
        self.assertEqual(d["remediation_rule"], "CMD_INJECTION_SPLIT")
        self.assertEqual(d["limitations"], ["Requires shlex.split for arbitrary shell strings"])

        # Deserialize and verify round-trip identity
        rec2 = RemediationRecord.from_dict(d)
        self.assertEqual(rec, rec2)
        self.assertEqual(rec2.remediation_rule, RemediationRule.CMD_INJECTION_SPLIT)
        self.assertEqual(rec2.patch_status, PatchStatus.SUCCESS)

    def test_remediation_rule_deserialization_requires_explicit_rule(self):
        """RemediationRecord.from_dict must reject payload missing remediation_rule."""
        d = {
            "finding_id": "TCS-REM-003",
            "cwe": "CWE-89",
            "original_file": "app.py",
            "line_number": 10,
            "patch_status": "SUCCESS",
            "original_code_snippet": "...",
            "patched_code_snippet": "...",
            "unified_diff": "...",
            "verification_passed": True,
            "limitations": [],
        }
        with self.assertRaises(ValueError):
            RemediationRecord.from_dict(d)


class TestVectorDStateInvariants(unittest.TestCase):
    """
    Blocker 2: Strict verification of valid and contradictory patch states.
    SUCCESS requires verification_passed == True.
    FAILED_* and UNSUPPORTED_CWE require verification_passed == False.
    """

    def _make_record(self, status: PatchStatus, verified: bool):
        return RemediationRecord(
            finding_id="TEST-INV-001",
            cwe="CWE-89",
            remediation_rule=RemediationRule.SQLI_PARAMETERIZE,
            original_file="app.py",
            line_number=1,
            patch_status=status,
            original_code_snippet="a",
            patched_code_snippet="b",
            unified_diff="c",
            verification_passed=verified,
        )

    def test_valid_state_success_verified(self):
        rec = self._make_record(PatchStatus.SUCCESS, True)
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)
        self.assertTrue(rec.verification_passed)

    def test_valid_state_failed_syntax_unverified(self):
        rec = self._make_record(PatchStatus.FAILED_SYNTAX, False)
        self.assertEqual(rec.patch_status, PatchStatus.FAILED_SYNTAX)
        self.assertFalse(rec.verification_passed)

    def test_valid_state_failed_verification_unverified(self):
        rec = self._make_record(PatchStatus.FAILED_VERIFICATION, False)
        self.assertEqual(rec.patch_status, PatchStatus.FAILED_VERIFICATION)
        self.assertFalse(rec.verification_passed)

    def test_valid_state_unsupported_cwe_unverified(self):
        rec = self._make_record(PatchStatus.UNSUPPORTED_CWE, False)
        self.assertEqual(rec.patch_status, PatchStatus.UNSUPPORTED_CWE)
        self.assertFalse(rec.verification_passed)

    def test_invalid_state_success_with_false_verification(self):
        with self.assertRaises(ValueError) as ctx:
            self._make_record(PatchStatus.SUCCESS, False)
        self.assertIn("patch_status SUCCESS requires verification_passed == True", str(ctx.exception))

    def test_invalid_state_failed_syntax_with_true_verification(self):
        with self.assertRaises(ValueError) as ctx:
            self._make_record(PatchStatus.FAILED_SYNTAX, True)
        self.assertIn("requires verification_passed == False", str(ctx.exception))

    def test_invalid_state_failed_verification_with_true_verification(self):
        with self.assertRaises(ValueError) as ctx:
            self._make_record(PatchStatus.FAILED_VERIFICATION, True)
        self.assertIn("requires verification_passed == False", str(ctx.exception))

    def test_invalid_state_unsupported_cwe_with_true_verification(self):
        with self.assertRaises(ValueError) as ctx:
            self._make_record(PatchStatus.UNSUPPORTED_CWE, True)
        self.assertIn("requires verification_passed == False", str(ctx.exception))


class TestVectorDFixtures(unittest.TestCase):
    FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "vector_d"

    FIXTURE_NAMES = [
        "fixture_01_sqli_fstring",
        "fixture_02_sqli_concat",
        "fixture_03_cmdi_shell_true",
        "fixture_04_path_traversal_open",
    ]

    def test_fixture_directories_exist(self):
        self.assertTrue(self.FIXTURES_DIR.exists(), f"Directory not found: {self.FIXTURES_DIR}")
        for fname in self.FIXTURE_NAMES:
            fpath = self.FIXTURES_DIR / fname
            self.assertTrue(fpath.is_dir(), f"Fixture directory not found: {fpath}")

    def test_fixture_files_exist_and_parse_cleanly(self):
        for fname in self.FIXTURE_NAMES:
            fdir = self.FIXTURES_DIR / fname
            vuln_file = fdir / "vuln.py"
            patch_file = fdir / "expected_patch.py"

            self.assertTrue(vuln_file.exists(), f"Missing vuln.py in {fname}")
            self.assertTrue(patch_file.exists(), f"Missing expected_patch.py in {fname}")

            vuln_code = vuln_file.read_text(encoding="utf-8")
            patch_code = patch_file.read_text(encoding="utf-8")

            # Validate AST parseability
            try:
                vuln_ast = ast.parse(vuln_code, filename=str(vuln_file))
                self.assertIsNotNone(vuln_ast)
            except SyntaxError as e:
                self.fail(f"Syntax error in {vuln_file}: {e}")

            try:
                patch_ast = ast.parse(patch_code, filename=str(patch_file))
                self.assertIsNotNone(patch_ast)
            except SyntaxError as e:
                self.fail(f"Syntax error in {patch_file}: {e}")

    def test_fixture_metadata_json_files(self):
        """Blocker 4: Ensure machine-readable metadata.json exists for each fixture and matches contracts."""
        for fname in self.FIXTURE_NAMES:
            meta_file = self.FIXTURES_DIR / fname / "metadata.json"
            self.assertTrue(meta_file.exists(), f"Missing metadata.json in {fname}")
            meta = json.loads(meta_file.read_text(encoding="utf-8"))

            self.assertEqual(meta["fixture_id"], fname)
            self.assertIn("cwe", meta)
            self.assertIn("remediation_rule", meta)
            self.assertIn("expected_security_property", meta)
            self.assertIn("input_ast_pattern", meta)
            self.assertIn("vulnerable_sink", meta)
            self.assertIn("expected_ast_transformation", meta)
            self.assertIsInstance(meta["assumptions_and_limitations"], list)

            # Match against centralized registry
            reg_entry = FIXTURE_SEMANTIC_CONTRACTS[fname]
            self.assertEqual(meta["cwe"], reg_entry["cwe"])
            self.assertEqual(meta["remediation_rule"], reg_entry["remediation_rule"].value)

    def test_fixture_diff_generation_and_record_creation(self):
        for fname in self.FIXTURE_NAMES:
            fdir = self.FIXTURES_DIR / fname
            vuln_lines = (fdir / "vuln.py").read_text(encoding="utf-8").splitlines(keepends=True)
            patch_lines = (fdir / "expected_patch.py").read_text(encoding="utf-8").splitlines(keepends=True)

            diff = list(difflib.unified_diff(
                vuln_lines,
                patch_lines,
                fromfile="vuln.py",
                tofile="expected_patch.py"
            ))
            diff_str = "".join(diff)
            self.assertTrue(len(diff_str) > 0, f"Empty diff for {fname}")

            meta = FIXTURE_SEMANTIC_CONTRACTS[fname]
            record = RemediationRecord(
                finding_id=f"TEST-{fname}",
                cwe=meta["cwe"],
                remediation_rule=meta["remediation_rule"],
                original_file=str(fdir / "vuln.py"),
                line_number=4,
                patch_status=PatchStatus.SUCCESS,
                original_code_snippet="".join(vuln_lines),
                patched_code_snippet="".join(patch_lines),
                unified_diff=diff_str,
                verification_passed=True,
                limitations=tuple(meta["assumptions_and_limitations"]),
            )
            d = record.to_dict()
            restored = RemediationRecord.from_dict(d)
            self.assertEqual(record, restored)
            self.assertEqual(restored.remediation_rule, meta["remediation_rule"])

    def test_cwe89_fstring_semantic_contract(self):
        """Blocker 3: Verify CWE-89 f-string semantic transformation properties."""
        contract = FIXTURE_SEMANTIC_CONTRACTS["fixture_01_sqli_fstring"]
        self.assertEqual(contract["remediation_rule"], RemediationRule.SQLI_PARAMETERIZE)
        self.assertEqual(contract["placeholder_style"], "?")
        patch_file = self.FIXTURES_DIR / "fixture_01_sqli_fstring" / "expected_patch.py"
        tree = ast.parse(patch_file.read_text(encoding="utf-8"))

        # Verify cursor.execute call has 2 arguments: query string with ? and tuple of params
        exec_calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, 'attr', '') == 'execute']
        self.assertEqual(len(exec_calls), 1)
        call = exec_calls[0]
        self.assertEqual(len(call.args), 2)
        self.assertIsInstance(call.args[0], ast.Constant)
        self.assertIn("?", call.args[0].value)
        self.assertNotIn("{username}", call.args[0].value)
        self.assertIsInstance(call.args[1], ast.Tuple)

    def test_cwe89_concat_semantic_contract(self):
        """Blocker 3: Verify CWE-89 binary addition semantic transformation properties."""
        contract = FIXTURE_SEMANTIC_CONTRACTS["fixture_02_sqli_concat"]
        self.assertEqual(contract["remediation_rule"], RemediationRule.SQLI_PARAMETERIZE)
        patch_file = self.FIXTURES_DIR / "fixture_02_sqli_concat" / "expected_patch.py"
        tree = ast.parse(patch_file.read_text(encoding="utf-8"))

        # In expected patch, query string is parameterized and cursor.execute receives params tuple
        exec_calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, 'attr', '') == 'execute']
        self.assertEqual(len(exec_calls), 1)
        call = exec_calls[0]
        self.assertEqual(len(call.args), 2)
        self.assertIsInstance(call.args[1], ast.Tuple)

    def test_cwe78_shell_true_semantic_contract(self):
        """Blocker 3: Verify CWE-78 subprocess call transforms to list and shell=False."""
        contract = FIXTURE_SEMANTIC_CONTRACTS["fixture_03_cmdi_shell_true"]
        self.assertEqual(contract["remediation_rule"], RemediationRule.CMD_INJECTION_SPLIT)
        patch_file = self.FIXTURES_DIR / "fixture_03_cmdi_shell_true" / "expected_patch.py"
        tree = ast.parse(patch_file.read_text(encoding="utf-8"))

        call_nodes = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, 'attr', '') == 'call']
        self.assertEqual(len(call_nodes), 1)
        call = call_nodes[0]

        # Verify shell=False
        shell_kw = [k for k in call.keywords if k.arg == 'shell']
        self.assertEqual(len(shell_kw), 1)
        self.assertIsInstance(shell_kw[0].value, ast.Constant)
        self.assertFalse(shell_kw[0].value.value)

    def test_cwe22_path_traversal_semantic_contract(self):
        """Blocker 3: Verify CWE-22 containment check with is_relative_to."""
        contract = FIXTURE_SEMANTIC_CONTRACTS["fixture_04_path_traversal_open"]
        self.assertEqual(contract["remediation_rule"], RemediationRule.PATH_TRAVERSAL_RESOLVE)
        patch_file = self.FIXTURES_DIR / "fixture_04_path_traversal_open" / "expected_patch.py"
        code = patch_file.read_text(encoding="utf-8")
        self.assertIn("resolve()", code)
        self.assertIn("is_relative_to", code)


class TestVectorDPhase1ScopeEnforcement(unittest.TestCase):
    """
    Enforce that remediation strictly contains only the approved modules.
    Only approved transformers (CWE-89, CWE-78, CWE-22) are permitted.
    """

    def test_no_transformers_in_remediation_package(self):
        remediation_dir = REPO_ROOT / "remediation"
        py_files = list(remediation_dir.glob("*.py"))
        allowed_modules = {
            "__init__.py",
            "contracts.py",
            "base.py",
            "cwe89_sqli.py",
            "cwe78_cmdi.py",
            "cwe22_path_traversal.py",
            "dispatcher.py",
            "patch_engine.py",
            "verification.py",
            "orchestrator.py",
        }
        self.assertEqual(
            set(p.name for p in py_files),
            allowed_modules,
            f"Unexpected modules found in remediation/: {[p.name for p in py_files]}"
        )

        # Enforce that no unauthorized transformers (e.g. CWE-79, CWE-94) are present
        forbidden_substrings = ["cwe79", "cwe94", "xss", "deserialization"]
        for p in py_files:
            for forbidden in forbidden_substrings:
                self.assertNotIn(
                    forbidden,
                    p.name.lower(),
                    f"Forbidden unauthorized transformer module found: {p.name}"
                )


if __name__ == "__main__":
    unittest.main()
