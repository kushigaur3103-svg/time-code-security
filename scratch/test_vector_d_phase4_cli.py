#!/usr/bin/env python3
"""
Test Suite: Vector D Phase 4 (TCS CLI Remediation Integration).
Validates:
1. --fix / --remediate preview safety (safe default: zero file modifications).
2. --dry-run explicit preview safety.
3. --write authorization gating (writes only verified patches).
4. --write without --fix does nothing remediation-related.
5. --dry-run + --write rejected with exit code 2.
6. Syntax failure and verification failure prevent writes.
7. Unsupported CWE does not modify file.
8. Stale source detection prevents overwrite.
9. Multi-file partial failure does not corrupt other files.
10. Deterministic unified diff generation.
11. Non-regression of existing normal scan, JSON, SARIF, and table modes.
12. Clean code remains byte-equivalent after --fix preview.
13. Already-fixed code produces no unnecessary patch.
14. End-to-end CWE-89, CWE-78, and CWE-22 CLI remediation and writing.
15. Adversarial tests: shell pipelines, dynamic SQL identifiers, verification bypass.
"""

import ast
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from remediation.contracts import RemediationRecord, PatchStatus, RemediationRule

REPO_ROOT = Path(r"c:\Users\aarti gaur\OneDrive\Desktop\time code security").resolve()
PYTHON_EXE = sys.executable
TCS_CLI = REPO_ROOT / "tcs_cli.py"


class TestVectorDPhase4CLIIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="tcs_phase4_cli_test_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def run_cli(self, args: list) -> subprocess.CompletedProcess:
        cmd = [PYTHON_EXE, str(TCS_CLI)] + args
        env = os.environ.copy()
        env["PYTHONPATH"] = str(REPO_ROOT)
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(REPO_ROOT),
            env=env
        )

    # ======================================================================
    # 1. SAFE DEFAULT & PREVIEW TESTS
    # ======================================================================

    def test_01_fix_preview_does_not_modify_file(self):
        """--fix alone runs in dry-run preview and leaves file 100% byte-identical."""
        vuln_file = self.temp_dir / "vuln_sqli.py"
        original_content = (
            "import sqlite3\n\n"
            "def get_user(cursor, username):\n"
            '    cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")\n'
            "    return cursor.fetchone()\n"
        )
        vuln_file.write_text(original_content, encoding="utf-8")

        res = self.run_cli([str(vuln_file), "--audit-all", "--fix"])
        self.assertEqual(res.returncode, 1, f"Expected exit code 1 in preview. Stderr: {res.stderr}")
        self.assertIn("TIME CODE SECURITY (TCS) - AUTOMATED REMEDIATION PREVIEW", res.stdout)
        self.assertIn("[REMEDIATION SUCCESS]", res.stdout)
        self.assertIn("--- a/", res.stdout)
        self.assertIn("+++ b/", res.stdout)
        self.assertIn("PREVIEW ONLY (Dry-Run)", res.stdout)

        # Byte-identical assertion
        self.assertEqual(vuln_file.read_text(encoding="utf-8"), original_content)

    def test_02_remediate_alias_does_not_modify_file(self):
        """--remediate is an exact alias for --fix and leaves file unchanged."""
        vuln_file = self.temp_dir / "vuln_sqli2.py"
        original_content = (
            "import sqlite3\n\n"
            "def find_item(cursor, item_id):\n"
            '    cursor.execute("SELECT * FROM items WHERE id = " + str(item_id))\n'
            "    return cursor.fetchall()\n"
        )
        vuln_file.write_text(original_content, encoding="utf-8")

        res = self.run_cli([str(vuln_file), "--audit-all", "--remediate"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("[REMEDIATION SUCCESS]", res.stdout)
        self.assertEqual(vuln_file.read_text(encoding="utf-8"), original_content)

    def test_03_dry_run_explicit_does_not_modify_file(self):
        """--dry-run preview leaves file completely unmodified."""
        vuln_file = self.temp_dir / "vuln_dry.py"
        original_content = (
            "import sqlite3\n\n"
            "def query(cursor, val):\n"
            '    cursor.execute(f"SELECT * FROM data WHERE v = {val}")\n'
        )
        vuln_file.write_text(original_content, encoding="utf-8")

        res = self.run_cli([str(vuln_file), "--audit-all", "--fix", "--dry-run"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("PREVIEW ONLY (Dry-Run)", res.stdout)
        self.assertEqual(vuln_file.read_text(encoding="utf-8"), original_content)

    # ======================================================================
    # 2. --WRITE AUTHORIZATION & INTEGRITY TESTS
    # ======================================================================

    def test_04_write_modifies_only_after_successful_verification(self):
        """--write applies patch to disk only when verification passed, exiting 0."""
        vuln_file = self.temp_dir / "vuln_apply.py"
        original_content = (
            "import sqlite3\n\n"
            "def get_account(cursor, account_id):\n"
            '    cursor.execute(f"SELECT * FROM accounts WHERE id = {account_id}")\n'
            "    return cursor.fetchone()\n"
        )
        vuln_file.write_text(original_content, encoding="utf-8")

        res = self.run_cli([str(vuln_file), "--audit-all", "--fix", "--write"])
        self.assertEqual(res.returncode, 0, f"Expected exit code 0 after successful write. Stderr: {res.stderr}")
        self.assertIn("AUTOMATED REMEDIATION (APPLIED)", res.stdout)
        self.assertIn("Mode:                    APPLIED (--write)", res.stdout)

        new_content = vuln_file.read_text(encoding="utf-8")
        self.assertNotEqual(new_content, original_content)
        self.assertIn('cursor.execute("SELECT * FROM accounts WHERE id = ?", (account_id,))', new_content)

        # Subsequent scan on the modified file must be 100% clean
        res_check = self.run_cli([str(vuln_file), "--audit-all"])
        self.assertEqual(res_check.returncode, 0)
        self.assertIn("No security vulnerabilities detected.", res_check.stdout)

    def test_05_write_without_fix_does_not_modify_file(self):
        """--write alone does NOT activate remediation and leaves files untouched."""
        vuln_file = self.temp_dir / "vuln_write_alone.py"
        original_content = (
            "import sqlite3\n\n"
            "def get_info(cursor, uid):\n"
            '    cursor.execute(f"SELECT * FROM info WHERE u = {uid}")\n'
        )
        vuln_file.write_text(original_content, encoding="utf-8")

        res = self.run_cli([str(vuln_file), "--audit-all", "--write"])
        self.assertEqual(res.returncode, 1)
        self.assertNotIn("AUTOMATED REMEDIATION", res.stdout)
        self.assertEqual(vuln_file.read_text(encoding="utf-8"), original_content)

    def test_06_dry_run_and_write_conflict_rejected(self):
        """--dry-run combined with --write is deterministically rejected with exit code 2."""
        vuln_file = self.temp_dir / "vuln_conflict.py"
        vuln_file.write_text("x = 1\n", encoding="utf-8")

        res = self.run_cli([str(vuln_file), "--dry-run", "--write"])
        self.assertEqual(res.returncode, 2)
        self.assertIn("Cannot specify both --dry-run and --write", res.stderr)

    # ======================================================================
    # 3. SAFETY ENVELOPES & ATOMIC TRANSACTION TESTS
    # ======================================================================

    def test_07_syntax_failure_prevents_write(self):
        """Files that cannot compile are not modified."""
        vuln_file = self.temp_dir / "broken.py"
        broken_content = "def invalid syntax here"
        vuln_file.write_text(broken_content, encoding="utf-8")

        res = self.run_cli([str(vuln_file), "--fix", "--write"])
        self.assertEqual(vuln_file.read_text(encoding="utf-8"), broken_content)

    def test_08_unsupported_cwe_does_not_modify_file(self):
        """Unsupported CWEs (e.g. CWE-95 eval) are not written to disk."""
        vuln_file = self.temp_dir / "vuln_eval.py"
        original_content = (
            "def evaluate(expr):\n"
            "    return eval(expr)\n"
        )
        vuln_file.write_text(original_content, encoding="utf-8")

        res = self.run_cli([str(vuln_file), "--audit-all", "--fix", "--write"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("[REMEDIATION UNSUPPORTED]", res.stdout)
        self.assertEqual(vuln_file.read_text(encoding="utf-8"), original_content)

    def test_09_true_stale_write_rejection(self):
        """
        True stale-write test:
        analyze original -> modify file externally -> attempt --write ->
        write MUST be rejected -> externally modified content MUST remain intact.
        Zero sleep-based race timing; uses deterministic orchestration seam.
        """
        vuln_file = self.temp_dir / "vuln_stale.py"
        original_content = (
            "import sqlite3\n\n"
            "def query_stale(cursor, val):\n"
            '    cursor.execute(f"SELECT * FROM tbl WHERE x = {val}")\n'
        )
        vuln_file.write_text(original_content, encoding="utf-8")

        external_modification = "# EXTERNALLY MODIFIED BEFORE WRITE\ndef unrelated():\n    pass\n"

        env = dict(os.environ)
        env["TCS_TEST_PRE_WRITE_MUTATE"] = external_modification

        proc = subprocess.run(
            [PYTHON_EXE, str(TCS_CLI), str(vuln_file), "--audit-all", "--fix", "--write"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            env=env
        )

        # 1. Write MUST be rejected, exit code MUST be 1
        self.assertEqual(proc.returncode, 1)

        # 2. Stale source warning must be emitted on stderr
        self.assertIn("stale source", proc.stderr.lower())

        # 3. Externally modified content MUST remain intact on disk (not overwritten by patch)
        content_on_disk = vuln_file.read_text(encoding="utf-8")
        self.assertEqual(content_on_disk, external_modification)

    def test_10_multi_file_partial_failure_isolation(self):
        """In a multi-file scan, an unsupported file is untouched while an eligible file is patched."""
        file_a = self.temp_dir / "mod_a.py"
        file_a_orig = (
            "import sqlite3\n\n"
            "def search(cursor, q):\n"
            '    cursor.execute(f"SELECT * FROM items WHERE name = \'{q}\'")\n'
        )
        file_a.write_text(file_a_orig, encoding="utf-8")

        file_b = self.temp_dir / "mod_b.py"
        file_b_orig = (
            "def execute_dynamic(cmd):\n"
            "    eval(cmd)\n"
        )
        file_b.write_text(file_b_orig, encoding="utf-8")

        res = self.run_cli([str(self.temp_dir), "--audit-all", "--fix", "--write"])
        self.assertEqual(res.returncode, 1)
        self.assertIn('cursor.execute("SELECT * FROM items WHERE name = ?", (q,))', file_a.read_text(encoding="utf-8"))
        self.assertEqual(file_b.read_text(encoding="utf-8"), file_b_orig)

    def test_11_deterministic_unified_diff(self):
        """Repeated --fix preview invocations produce byte-identical unified diffs with stable headers."""
        vuln_file = self.temp_dir / "vuln_diff.py"
        vuln_file.write_text(
            "import sqlite3\n\n"
            "def run_q(cursor, uid):\n"
            '    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n',
            encoding="utf-8"
        )

        outputs = []
        for _ in range(10):
            res = self.run_cli([str(vuln_file), "--audit-all", "--fix"])
            outputs.append(res.stdout)

        # Byte-deterministic across 10 repeated executions
        for out in outputs[1:]:
            self.assertEqual(out, outputs[0])

        # Stable diff headers without volatile timestamps
        self.assertIn("--- a/", outputs[0])
        self.assertIn("+++ b/", outputs[0])
        self.assertNotIn("2026-", outputs[0])
        self.assertNotIn("2025-", outputs[0])

    def test_12_clean_code_remains_byte_equivalent_after_fix(self):
        """A clean file scanned with --fix exits 0 and remains unchanged."""
        clean_file = self.temp_dir / "clean.py"
        clean_code = "def add(a, b):\n    return a + b\n"
        clean_file.write_text(clean_code, encoding="utf-8")

        res = self.run_cli([str(clean_file), "--fix"])
        self.assertEqual(res.returncode, 0)
        self.assertEqual(clean_file.read_text(encoding="utf-8"), clean_code)

    def test_13_already_fixed_code_produces_no_patch(self):
        """Code that is already remediated produces no remediation records."""
        fixed_file = self.temp_dir / "fixed.py"
        fixed_code = (
            "import sqlite3\n\n"
            "def query(cursor, uid):\n"
            '    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))\n'
        )
        fixed_file.write_text(fixed_code, encoding="utf-8")

        res = self.run_cli([str(fixed_file), "--audit-all", "--fix", "--format", "json"])
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(len(data.get("remediations", [])), 0)

    # ======================================================================
    # 4. CWE-78 & CWE-22 CLI REMEDIATION & WRITE TESTS
    # ======================================================================

    def test_14_cwe78_command_injection_fix_and_write(self):
        """CWE-78 subprocess call with shell=True is remediated to cmd_list with shell=False."""
        cmdi_file = self.temp_dir / "vuln_cmdi.py"
        original_content = (
            "import subprocess\n\n"
            "def ping(host):\n"
            '    cmd = f"ping -c 1 {host}"\n'
            "    subprocess.call(cmd, shell=True)\n"
        )
        cmdi_file.write_text(original_content, encoding="utf-8")

        res = self.run_cli([str(cmdi_file), "--audit-all", "--fix", "--write"])
        self.assertEqual(res.returncode, 0)
        patched = cmdi_file.read_text(encoding="utf-8")
        self.assertIn('cmd_list = ["ping", "-c", "1", host]', patched)
        self.assertIn("subprocess.call(cmd_list, shell=False)", patched)

        # Verification re-scan
        res_check = self.run_cli([str(cmdi_file), "--audit-all"])
        self.assertEqual(res_check.returncode, 0)

    def test_15_cwe22_path_traversal_fix_and_write(self):
        """CWE-22 path traversal open call is remediated with safe_base and containment check."""
        path_file = self.temp_dir / "vuln_path.py"
        original_content = (
            "def read_user_file(base_dir, filename):\n"
            "    target_path = base_dir + filename\n"
            '    with open(target_path, "r") as f:\n'
            "        return f.read()\n"
        )
        path_file.write_text(original_content, encoding="utf-8")

        res = self.run_cli([str(path_file), "--audit-all", "--fix", "--write"])
        self.assertEqual(res.returncode, 0)
        patched = path_file.read_text(encoding="utf-8")
        self.assertIn("from pathlib import Path", patched)
        self.assertIn("safe_base = Path(base_dir).resolve()", patched)
        self.assertIn("target_path = (safe_base / filename).resolve()", patched)
        self.assertIn("if not target_path.is_relative_to(safe_base):", patched)

        self.assertNotIn("base_dir + filename", patched)

        # Verification AST parse & compile
        tree = ast.parse(patched)
        self.assertIsNotNone(compile(tree, str(path_file), "exec"))

        # Verification re-scan proves original unconstrained concatenation is eliminated
        res_check = self.run_cli([str(path_file), "--audit-all", "--format", "json"])
        data = json.loads(res_check.stdout)
        snippets = [f.get("code_snippet", "") for f in data.get("findings", [])]
        self.assertNotIn("base_dir + filename", "".join(snippets))

    # ======================================================================
    # 5. ADVERSARIAL & EDGE CASE TESTS
    # ======================================================================

    def test_16_adversarial_cwe78_shell_pipeline_rejected(self):
        """CWE-78 command containing shell pipeline (|) is rejected as UNSUPPORTED_CWE."""
        pipe_file = self.temp_dir / "vuln_pipe.py"
        original_content = (
            "import subprocess\n\n"
            "def search(pattern):\n"
            '    cmd = f"cat file.txt | grep {pattern}"\n'
            "    subprocess.call(cmd, shell=True)\n"
        )
        pipe_file.write_text(original_content, encoding="utf-8")

        res = self.run_cli([str(pipe_file), "--audit-all", "--fix", "--write"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("[REMEDIATION UNSUPPORTED]", res.stdout)
        self.assertEqual(pipe_file.read_text(encoding="utf-8"), original_content)

    def test_17_adversarial_cwe89_dynamic_table_rejected(self):
        """CWE-89 with dynamic table identifier is rejected as UNSUPPORTED_CWE."""
        table_file = self.temp_dir / "vuln_table.py"
        original_content = (
            "import sqlite3\n\n"
            "def query_table(cursor, tbl, uid):\n"
            '    cursor.execute(f"SELECT * FROM {tbl} WHERE id = {uid}")\n'
        )
        table_file.write_text(original_content, encoding="utf-8")

        res = self.run_cli([str(table_file), "--audit-all", "--fix", "--write"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("[REMEDIATION UNSUPPORTED]", res.stdout)
        self.assertEqual(table_file.read_text(encoding="utf-8"), original_content)

    def test_18_json_output_mode_contains_remediations(self):
        """--format json outputs rich machine-readable remediations payload."""
        vuln_file = self.temp_dir / "vuln_json.py"
        vuln_file.write_text(
            "import sqlite3\n\n"
            "def q(cursor, name):\n"
            '    cursor.execute(f"SELECT * FROM u WHERE name = \'{name}\'")\n',
            encoding="utf-8"
        )

        res = self.run_cli([str(vuln_file), "--audit-all", "--fix", "--format", "json"])
        self.assertEqual(res.returncode, 1)
        data = json.loads(res.stdout)
        self.assertIn("remediations", data)
        self.assertEqual(len(data["remediations"]), 1)
        rem = data["remediations"][0]
        self.assertEqual(rem["patch_status"], "SUCCESS")
        self.assertEqual(rem["remediation_rule"], "SQLI_PARAMETERIZE")
        self.assertTrue(rem["verification_passed"])
        self.assertIn("--- a/", rem["unified_diff"])

    def test_19_sarif_output_mode_remains_functional(self):
        """--format sarif outputs compliant OASIS SARIF v2.1.0 document."""
        vuln_file = self.temp_dir / "vuln_sarif.py"
        vuln_file.write_text(
            "import sqlite3\n\n"
            "def q(cursor, name):\n"
            '    cursor.execute(f"SELECT * FROM u WHERE name = \'{name}\'")\n',
            encoding="utf-8"
        )

        res = self.run_cli([str(vuln_file), "--audit-all", "--fix", "--format", "sarif"])
        self.assertEqual(res.returncode, 1)
        data = json.loads(res.stdout)
        self.assertEqual(data["version"], "2.1.0")

    def test_20_scan_subcommand_syntax(self):
        """'tcs scan <target> --fix' works identically to 'tcs <target> --fix'."""
        vuln_file = self.temp_dir / "vuln_subcmd.py"
        vuln_file.write_text(
            "import sqlite3\n\n"
            "def q(cursor, name):\n"
            '    cursor.execute(f"SELECT * FROM u WHERE name = \'{name}\'")\n',
            encoding="utf-8"
        )

        res = self.run_cli(["scan", str(vuln_file), "--audit-all", "--fix"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("TIME CODE SECURITY (TCS) - AUTOMATED REMEDIATION PREVIEW", res.stdout)
        self.assertIn("[REMEDIATION SUCCESS]", res.stdout)

    # ======================================================================
    # 6. FILESYSTEM SAFETY TESTS (CTO GATE REVIEW)
    # ======================================================================

    def test_21_fs_regular_file_write_and_mode_preservation(self):
        """Normal regular Python file is patched atomically and original mode bits preserved."""
        vuln_file = self.temp_dir / "vuln_regular.py"
        vuln_file.write_text(
            "import sqlite3\n\ndef run(cursor, val):\n    cursor.execute(f'SELECT * FROM t WHERE x = {val}')\n",
            encoding="utf-8"
        )
        orig_stat = vuln_file.stat()

        res = self.run_cli([str(vuln_file), "--audit-all", "--fix", "--write"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("SELECT * FROM t WHERE x = ?", vuln_file.read_text(encoding="utf-8"))
        new_stat = vuln_file.stat()
        self.assertEqual(orig_stat.st_mode, new_stat.st_mode)

    def test_22_fs_executable_mode_preserved(self):
        """Executable bit is preserved when file is remediated with --write."""
        vuln_file = self.temp_dir / "vuln_exec.py"
        vuln_file.write_text(
            "import sqlite3\n\ndef run(cursor, val):\n    cursor.execute(f'SELECT * FROM t WHERE x = {val}')\n",
            encoding="utf-8"
        )
        try:
            os.chmod(vuln_file, 0o755)
        except Exception:
            pass
        expected_exec = vuln_file.stat().st_mode & 0o111

        res = self.run_cli([str(vuln_file), "--audit-all", "--fix", "--write"])
        self.assertEqual(res.returncode, 0)
        post_exec = vuln_file.stat().st_mode & 0o111
        self.assertEqual(expected_exec, post_exec)

    def test_23_fs_read_only_file_rejected_without_crash(self):
        """Read-only file write attempt is aborted safely without crashing or corrupting."""
        vuln_file = self.temp_dir / "vuln_readonly.py"
        content = (
            "import sqlite3\n\ndef run(cursor, val):\n    cursor.execute(f'SELECT * FROM t WHERE x = {val}')\n"
        )
        vuln_file.write_text(content, encoding="utf-8")
        try:
            os.chmod(vuln_file, stat.S_IREAD)
            res = self.run_cli([str(vuln_file), "--audit-all", "--fix", "--write"])
            self.assertEqual(res.returncode, 1)
            self.assertIn("read-only", res.stderr.lower())
            # Content remains 100% untouched
            self.assertEqual(vuln_file.read_text(encoding="utf-8"), content)
        finally:
            os.chmod(vuln_file, stat.S_IWRITE)

    def test_24_fs_symlink_path_rejected_and_not_replaced(self):
        """Remediation of a symlink target does not replace symlink object with regular file."""
        real_file = self.temp_dir / "real_target.py"
        content = (
            "import sqlite3\n\ndef run(cursor, val):\n    cursor.execute(f'SELECT * FROM t WHERE x = {val}')\n"
        )
        real_file.write_text(content, encoding="utf-8")
        symlink_file = self.temp_dir / "symlink_vuln.py"
        can_symlink = True
        try:
            symlink_file.symlink_to(real_file)
        except OSError:
            can_symlink = False

        if can_symlink:
            res = self.run_cli([str(symlink_file), "--audit-all", "--fix", "--write"])
            self.assertEqual(res.returncode, 1)
            self.assertIn("symlink", res.stderr.lower())
            # The symlink object MUST remain a symlink and NOT be replaced by regular file
            self.assertTrue(symlink_file.is_symlink())
        else:
            # Deterministic simulation seam on platforms where non-root cannot create real symlink
            env = dict(os.environ)
            env["TCS_TEST_FORCE_SYMLINK"] = "1"
            res = subprocess.run(
                [PYTHON_EXE, str(TCS_CLI), str(real_file), "--audit-all", "--fix", "--write"],
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                env=env
            )
            self.assertEqual(res.returncode, 1)
            self.assertIn("symlink", res.stderr.lower())
            self.assertEqual(real_file.read_text(encoding="utf-8"), content)

    def test_25_fs_hard_linked_file_rejected_and_link_preserved(self):
        """Hard-linked file (nlink > 1) is rejected from atomic replacement to preserve link structure."""
        src_file = self.temp_dir / "src_hardlink.py"
        content = (
            "import sqlite3\n\ndef run(cursor, val):\n    cursor.execute(f'SELECT * FROM t WHERE x = {val}')\n"
        )
        src_file.write_text(content, encoding="utf-8")
        hl_file = self.temp_dir / "hl_target.py"
        try:
            os.link(src_file, hl_file)
        except (OSError, AttributeError):
            self.skipTest("Hardlink creation not supported on this platform/filesystem")

        self.assertEqual(src_file.stat().st_nlink, 2)
        res = self.run_cli([str(src_file), "--audit-all", "--fix", "--write"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("hard-linked", res.stderr.lower())
        # Hard link count remains intact
        self.assertEqual(src_file.stat().st_nlink, 2)
        self.assertEqual(src_file.read_text(encoding="utf-8"), content)

    # ======================================================================
    # 7. JSON REGRESSION TESTS
    # ======================================================================

    def test_26_json_remediation_free_normal_scan_unchanged(self):
        """Normal JSON scan without --fix retains exact existing schema without remediation pollution."""
        vuln_file = self.temp_dir / "vuln_normal_json.py"
        vuln_file.write_text(
            "import sqlite3\n\ndef run(cursor, val):\n    cursor.execute(f'SELECT * FROM t WHERE x = {val}')\n",
            encoding="utf-8"
        )
        res = self.run_cli([str(vuln_file), "--audit-all", "--format", "json"])
        self.assertEqual(res.returncode, 1)
        data = json.loads(res.stdout)
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertIn("syntax_errors", data)
        # MUST NOT contain remediation fields when --fix not passed
        self.assertNotIn("remediations", data)
        self.assertNotIn("remediation_summary", data)

    def test_27_json_remediation_additive_and_authoritative(self):
        """JSON scan with --fix contains additive remediation records and preserves finding fields."""
        vuln_file = self.temp_dir / "vuln_json_fix.py"
        vuln_file.write_text(
            "import sqlite3\n\ndef run(cursor, val):\n    cursor.execute(f'SELECT * FROM t WHERE x = {val}')\n",
            encoding="utf-8"
        )
        res = self.run_cli([str(vuln_file), "--audit-all", "--format", "json", "--fix"])
        self.assertEqual(res.returncode, 1)
        data = json.loads(res.stdout)
        self.assertIn("findings", data)
        self.assertIn("remediations", data)
        self.assertIn("remediation_summary", data)

        finding = data["findings"][0]
        for field in ("id", "cwe", "severity", "confidence", "file", "line_number", "code_snippet"):
            self.assertIn(field, finding, f"Finding missing mandatory field: {field}")

        rem = data["remediations"][0]
        self.assertEqual(rem["patch_status"], "SUCCESS")
        self.assertIs(rem["verification_passed"], True)
        self.assertIn("unified_diff", rem)

    def test_28_json_remediation_record_roundtrip_serialization(self):
        """RemediationRecord serializes to dict and deserializes from dict losslessly."""
        rec = RemediationRecord(
            finding_id="TCS-VULN-001",
            cwe="CWE-89",
            remediation_rule=RemediationRule.SQLI_PARAMETERIZE,
            original_file="test.py",
            line_number=10,
            patch_status=PatchStatus.SUCCESS,
            original_code_snippet="cursor.execute(f'...{x}')",
            patched_code_snippet="cursor.execute('...', (x,))",
            unified_diff="--- a/test.py\n+++ b/test.py\n",
            verification_passed=True,
            limitations=("sqlite_only",),
            patched_source="print('safe')"
        )
        d = rec.to_dict()
        rec_back = RemediationRecord.from_dict(d)
        self.assertEqual(rec, rec_back)
        self.assertEqual(rec_back.patched_source, "print('safe')")

    # ======================================================================
    # 8. SARIF REGRESSION TESTS
    # ======================================================================

    def test_29_sarif_oasis_v210_spec_compliance(self):
        """SARIF output conforms to OASIS SARIF v2.1.0 specification with required keys."""
        vuln_file = self.temp_dir / "vuln_sarif_spec.py"
        vuln_file.write_text(
            "import sqlite3\n\ndef run(cursor, val):\n    cursor.execute(f'SELECT * FROM t WHERE x = {val}')\n",
            encoding="utf-8"
        )
        res = self.run_cli([str(vuln_file), "--audit-all", "--format", "sarif"])
        self.assertEqual(res.returncode, 1)
        data = json.loads(res.stdout)
        self.assertEqual(data["version"], "2.1.0")
        self.assertIn("sarif-schema-2.1.0.json", data["$schema"])
        self.assertEqual(len(data["runs"]), 1)
        run = data["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "TimeCodeSecurity")
        self.assertGreater(len(run["results"]), 0)
        res0 = run["results"][0]
        self.assertIn("ruleId", res0)
        self.assertIn("locations", res0)

    def test_30_sarif_remediation_does_not_pollute_sarif(self):
        """Running --fix with --format sarif does NOT inject unauthorized fields into SARIF document."""
        vuln_file = self.temp_dir / "vuln_sarif_pollute.py"
        vuln_file.write_text(
            "import sqlite3\n\ndef run(cursor, val):\n    cursor.execute(f'SELECT * FROM t WHERE x = {val}')\n",
            encoding="utf-8"
        )
        res = self.run_cli([str(vuln_file), "--audit-all", "--format", "sarif", "--fix"])
        self.assertEqual(res.returncode, 1)
        data = json.loads(res.stdout)
        self.assertEqual(data["version"], "2.1.0")
        # Ensure no remediation pollution at root of SARIF
        self.assertNotIn("remediations", data)
        self.assertNotIn("remediation_summary", data)

    def test_31_sarif_normal_scan_valid(self):
        """Normal scan output in SARIF remains valid and identical without --fix."""
        clean_file = self.temp_dir / "clean_sarif.py"
        clean_file.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        res = self.run_cli([str(clean_file), "--format", "sarif"])
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(len(data["runs"][0]["results"]), 0)

    # ======================================================================
    # 9. NORMAL CLI EXIT-CODE REGRESSION TESTS
    # ======================================================================

    def test_32_exit_code_clean_files_exit_0_across_formats(self):
        """Clean files exit 0 across table, json, and sarif formats."""
        clean_file = self.temp_dir / "clean_exit.py"
        clean_file.write_text("def compute(x):\n    return x * 2\n", encoding="utf-8")

        res_txt = self.run_cli([str(clean_file)])
        self.assertEqual(res_txt.returncode, 0)

        res_json = self.run_cli([str(clean_file), "--format", "json"])
        self.assertEqual(res_json.returncode, 0)

        res_sarif = self.run_cli([str(clean_file), "--format", "sarif"])
        self.assertEqual(res_sarif.returncode, 0)

    def test_33_exit_code_vuln_files_exit_1_across_formats(self):
        """Vulnerable files exit 1 across table, json, and sarif formats."""
        vuln_file = self.temp_dir / "vuln_exit.py"
        vuln_file.write_text(
            "import sqlite3\n\ndef run(cursor, val):\n    cursor.execute(f'SELECT * FROM t WHERE x = {val}')\n",
            encoding="utf-8"
        )

        res_txt = self.run_cli([str(vuln_file), "--audit-all"])
        self.assertEqual(res_txt.returncode, 1)

        res_json = self.run_cli([str(vuln_file), "--audit-all", "--format", "json"])
        self.assertEqual(res_json.returncode, 1)

        res_sarif = self.run_cli([str(vuln_file), "--audit-all", "--format", "sarif"])
        self.assertEqual(res_sarif.returncode, 1)

    def test_34_exit_code_write_alone_does_not_remediate(self):
        """Passing --write alone without --fix does not remediate and preserves standard exit codes."""
        vuln_file = self.temp_dir / "vuln_write_alone.py"
        vuln_content = (
            "import sqlite3\n\ndef run(cursor, val):\n    cursor.execute(f'SELECT * FROM t WHERE x = {val}')\n"
        )
        vuln_file.write_text(vuln_content, encoding="utf-8")

        # --write on vulnerable file exits 1 and leaves file untouched
        res_vuln = self.run_cli([str(vuln_file), "--audit-all", "--write"])
        self.assertEqual(res_vuln.returncode, 1)
        self.assertEqual(vuln_file.read_text(encoding="utf-8"), vuln_content)

        # --write on clean file exits 0 and leaves file untouched
        clean_file = self.temp_dir / "clean_write_alone.py"
        clean_content = "def ok():\n    return 42\n"
        clean_file.write_text(clean_content, encoding="utf-8")

        res_clean = self.run_cli([str(clean_file), "--write"])
        self.assertEqual(res_clean.returncode, 0)
        self.assertEqual(clean_file.read_text(encoding="utf-8"), clean_content)

    # ======================================================================
    # 10. CTO HARDENING GATE CORRECTIONS (BLOCKERS 1-5)
    # ======================================================================

    def test_35_blocker1_decoupled_verification_import_isolation(self):
        """Blocker 1: remediation.verification must not import tcs_cli or populate sys.modules."""
        check_code = (
            "import sys\n"
            "import remediation.verification\n"
            "assert 'tcs_cli' not in sys.modules, f'Circular dependency detected: tcs_cli found in sys.modules'\n"
            "print('ISOLATION_OK')\n"
        )
        res = subprocess.run(
            [PYTHON_EXE, "-c", check_code],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT)
        )
        self.assertEqual(res.returncode, 0, f"Import isolation check failed: {res.stderr}")
        self.assertIn("ISOLATION_OK", res.stdout)

    def test_36_blocker2_same_file_multi_finding_sequencing(self):
        """Blocker 2: Adversarial file with Line 5 CWE-78 and Line 12 CWE-89 remediated cleanly without offset drift."""
        multi_file = self.temp_dir / "multi_vuln_seq.py"
        content = (
            "import subprocess\n"
            "import sqlite3\n"
            "\n"
            "def run_cmd(host):\n"
            '    cmd = f"ping -c 1 {host}"\n'
            "    subprocess.call(cmd, shell=True)\n"
            "\n"
            "def query_db(cursor, uid):\n"
            "    # Some intervening comment lines to test offset tracking\n"
            "    info = 'internal'\n"
            "    prefix = 'SELECT * FROM users WHERE id = '\n"
            '    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
            "    return cursor.fetchall()\n"
        )
        multi_file.write_text(content, encoding="utf-8")

        res = self.run_cli([str(multi_file), "--audit-all", "--fix", "--write"])
        self.assertEqual(res.returncode, 0, f"Expected 0 exit code on complete multi-finding remediation. Stderr: {res.stderr}")

        patched = multi_file.read_text(encoding="utf-8")
        # Invariant D-1: Patched source must compile via ast.parse
        ast.parse(patched)

        # Verify CWE-78 was remediated
        self.assertNotIn("shell=True", patched)
        self.assertIn("cmd_list", patched)

        # Verify CWE-89 was remediated
        self.assertNotIn("id = {uid}", patched)
        self.assertIn("?", patched)

        # Invariant D-2: Re-scan with audit-all must detect 0 vulnerabilities
        res_recheck = self.run_cli([str(multi_file), "--audit-all"])
        self.assertEqual(res_recheck.returncode, 0)
        self.assertIn("No security vulnerabilities detected.", res_recheck.stdout)

    def test_37_blocker3_staged_and_fix_collision_guard(self):
        """Blocker 3: Running with --staged and --fix rejects with exit code 2 and user error."""
        test_repo = self.temp_dir / "test_repo"
        test_repo.mkdir()
        subprocess.run(["git", "init"], cwd=str(test_repo), capture_output=True, check=True)
        staged_file = test_repo / "staged_vuln.py"
        orig_content = "import sqlite3\ndef f(c, x):\n    c.execute(f'SELECT * FROM t WHERE x = {x}')\n"
        staged_file.write_text(orig_content, encoding="utf-8")
        subprocess.run(["git", "add", "staged_vuln.py"], cwd=str(test_repo), capture_output=True, check=True)

        res = subprocess.run(
            [PYTHON_EXE, str(TCS_CLI), "scan", "--staged", "--fix"],
            capture_output=True,
            text=True,
            cwd=str(test_repo)
        )
        self.assertEqual(res.returncode, 2)
        self.assertIn(
            "Error: --fix/--remediate is currently not supported with --staged mode. Run on working tree targets directly.",
            res.stderr
        )
        self.assertEqual(staged_file.read_text(encoding="utf-8"), orig_content)

    def test_38_blocker4_modular_orchestrator_exports(self):
        """Blocker 4: Orchestrator is extracted into remediation package and exported cleanly."""
        import remediation
        self.assertTrue(hasattr(remediation, "remediate_project"))
        self.assertTrue(hasattr(remediation, "ProjectRemediationResult"))
        self.assertTrue(hasattr(remediation, "format_remediation_section"))

    def test_39_blocker5_contract_backward_compatibility(self):
        """Blocker 5: RemediationRecord.from_dict deserializes legacy dicts without patched_source without error."""
        legacy_dict = {
            "finding_id": "TCS-LEGACY-001",
            "cwe": "CWE-89",
            "remediation_rule": "SQLI_PARAMETERIZE",
            "original_file": "legacy.py",
            "line_number": 5,
            "patch_status": "SUCCESS",
            "original_code_snippet": "cursor.execute(f'SELECT {x}')",
            "patched_code_snippet": "cursor.execute('SELECT ?', (x,))",
            "unified_diff": "--- a/legacy.py\n+++ b/legacy.py\n",
            "verification_passed": True,
            "limitations": [],
        }
        rec = RemediationRecord.from_dict(legacy_dict)
        self.assertEqual(rec.finding_id, "TCS-LEGACY-001")
        self.assertIsNone(rec.patched_source)
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)

    # ======================================================================
    # 11. IMPORT SHIFT, NEWLINE INTEGRITY & TRANSACTION ACCURACY TESTS
    # ======================================================================

    def test_40_cwe89_above_cwe22_with_import_injection(self):
        """Blocker 1: CWE-89 above CWE-22 with import injection resolves without line shift drift."""
        test_file = self.temp_dir / "vuln_cwe89_and_cwe22.py"
        content = (
            "import sqlite3\n"
            "\n"
            "def query_user(cursor, user_id):\n"
            "    # Intervening comment\n"
            '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
            "    return cursor.fetchone()\n"
            "\n"
            "\n"
            "\n"
            "\n"
            "def read_doc(base_dir, doc_name):\n"
            "    # Intervening comment\n"
            "    target = base_dir + doc_name\n"
            '    with open(target, "r") as f:\n'
            "        return f.read()\n"
        )
        test_file.write_text(content, encoding="utf-8")

        res = self.run_cli([str(test_file), "--audit-all", "--fix", "--write"])
        self.assertEqual(res.returncode, 0, f"Expected exit code 0 for fully remediated file. Stderr: {res.stderr}")

        patched = test_file.read_text(encoding="utf-8")

        # Invariant D-1: AST compiles cleanly
        ast.parse(patched)

        # Verify from pathlib import Path was safely injected at the top
        self.assertIn("from pathlib import Path", patched)

        # Verify CWE-22 at line 14 was fixed
        self.assertIn("safe_base = Path(base_dir).resolve()", patched)
        self.assertIn("is_relative_to", patched)

        # Verify CWE-89 at line 5 (now line 6+) was also correctly fixed
        self.assertIn('cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))', patched)
        self.assertNotIn("id = {user_id}", patched)

        # Invariant D-2: Closed-loop re-scan verifies both original vulnerabilities are absent
        from remediation.verification import scan_source_for_verification
        rescanned = scan_source_for_verification(str(test_file), patched)
        # Verify original CWE-89 injection is absent from re-scan
        self.assertFalse(any(f.get("cwe") == "CWE-89" for f in rescanned))
        # Verify original unconstrained path concatenation is absent from re-scan
        self.assertFalse(any("base_dir + doc_name" in f.get("code_snippet", "") for f in rescanned))
        # Verify subsequent --fix finds 0 successful patches to apply
        res_fix_again = self.run_cli([str(test_file), "--audit-all", "--format", "json", "--fix"])
        data = json.loads(res_fix_again.stdout)
        self.assertEqual(data.get("remediation_summary", {}).get("successful_remediations", 0), 0)

    def test_41_fs_unix_lf_preserved_without_crlf_leak(self):
        """Blocker 2: Unix LF files remain strictly LF on disk after --write without CRLF leak."""
        unix_file = self.temp_dir / "unix_lf.py"
        lf_bytes = b"import sqlite3\n\ndef run(cursor, val):\n    cursor.execute(f'SELECT * FROM t WHERE x = {val}')\n"
        unix_file.write_bytes(lf_bytes)

        res = self.run_cli([str(unix_file), "--audit-all", "--fix", "--write"])
        self.assertEqual(res.returncode, 0)

        written_bytes = unix_file.read_bytes()
        # Must not contain CRLF
        self.assertNotIn(b"\r\n", written_bytes, "CRLF detected in Unix LF file after --write")
        self.assertIn(b"\n", written_bytes)

    def test_42_transactional_summary_reporting_on_partial_failure(self):
        """Blocker 3: Partial failure in multi-finding file rolls back and reports accurate summary."""
        partial_file = self.temp_dir / "partial_fail.py"
        # Line 5: CWE-78 (unsupported pipeline)
        # Line 9: CWE-89 (supported parameterizable query)
        orig_content = (
            "import subprocess\n"
            "import sqlite3\n"
            "\n"
            "def run_pipe(pattern):\n"
            '    cmd = f"cat file.txt | grep {pattern}"\n'
            "    subprocess.call(cmd, shell=True)\n"
            "\n"
            "def run_db(cursor, val):\n"
            "    cursor.execute(f'SELECT * FROM t WHERE x = {val}')\n"
        )
        partial_file.write_text(orig_content, encoding="utf-8")

        # Test table output
        res_table = self.run_cli([str(partial_file), "--audit-all", "--fix", "--write"])
        self.assertEqual(res_table.returncode, 1)
        self.assertIn("[REMEDIATION ABORTED - TRANSACTION ROLLBACK]", res_table.stdout)
        self.assertIn("[REMEDIATION UNSUPPORTED]", res_table.stdout)
        self.assertIn("Successfully Verified:   0", res_table.stdout)
        self.assertEqual(partial_file.read_text(encoding="utf-8"), orig_content)

        # Test json output
        res_json = self.run_cli([str(partial_file), "--audit-all", "--format", "json", "--fix", "--write"])
        self.assertEqual(res_json.returncode, 1)
        data = json.loads(res_json.stdout)
        summary = data["remediation_summary"]
        self.assertEqual(summary["successful_remediations"], 0)
        self.assertEqual(summary["written_files"], [])
        self.assertEqual(partial_file.read_text(encoding="utf-8"), orig_content)

    def test_43_remediate_flag_alias_behavior(self):
        """Blocker 4: --remediate flag behaves identically to --fix across all modes."""
        vuln_file = self.temp_dir / "alias_test.py"
        orig_content = "import sqlite3\ndef run(cursor, val):\n    cursor.execute(f'SELECT * FROM t WHERE x = {val}')\n"
        vuln_file.write_text(orig_content, encoding="utf-8")

        # --remediate preview
        res_prev = self.run_cli([str(vuln_file), "--audit-all", "--remediate"])
        self.assertEqual(res_prev.returncode, 1)
        self.assertIn("[REMEDIATION SUCCESS]", res_prev.stdout)
        self.assertEqual(vuln_file.read_text(encoding="utf-8"), orig_content)

        # --remediate --dry-run
        res_dry = self.run_cli([str(vuln_file), "--audit-all", "--remediate", "--dry-run"])
        self.assertEqual(res_dry.returncode, 1)
        self.assertIn("PREVIEW ONLY (Dry-Run)", res_dry.stdout)

        # --remediate --staged collision check
        test_repo = self.temp_dir / "repo_alias"
        test_repo.mkdir()
        subprocess.run(["git", "init"], cwd=str(test_repo), capture_output=True, check=True)
        st_file = test_repo / "st.py"
        st_file.write_text(orig_content, encoding="utf-8")
        subprocess.run(["git", "add", "st.py"], cwd=str(test_repo), capture_output=True, check=True)
        res_staged = subprocess.run(
            [PYTHON_EXE, str(TCS_CLI), "scan", "--staged", "--remediate"],
            capture_output=True,
            text=True,
            cwd=str(test_repo)
        )
        self.assertEqual(res_staged.returncode, 2)
        self.assertIn(
            "Error: --fix/--remediate is currently not supported with --staged mode. Run on working tree targets directly.",
            res_staged.stderr
        )

        # --remediate --write
        res_write = self.run_cli([str(vuln_file), "--audit-all", "--remediate", "--write"])
        self.assertEqual(res_write.returncode, 0)
        self.assertIn('cursor.execute("SELECT * FROM t WHERE x = ?", (val,))', vuln_file.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
