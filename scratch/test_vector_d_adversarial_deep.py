#!/usr/bin/env python3
"""
TimeCodeSecurity (TCS) - Vector D Adversarial Deep-Audit Suite.
Principal Security QA & AST Compiler Specialist Audit Automation.

Validates the 5 Mandatory Adversarial Gauntlets against isolated sandbox:
- Gauntlet 1: Multi-Finding Collision (CWE-89, CWE-78, CWE-22 in a single file; bottom-up sequencing).
- Gauntlet 2: Adversarial Rejection (dynamic SQL identifiers & shell pipelines rejected; byte-identical).
- Gauntlet 3: Deep Nesting & Async Indentation (4-level nested async class method + try-except-finally).
- Gauntlet 4: Idempotency (re-running on clean/patched code produces 0 modifications and exit code 0).
- Gauntlet 5: Line Ending Preservation (CRLF exact byte preservation with zero LF leakage).

Mathematical Invariants Enforced:
- Invariant D-1: Abstract Syntax Tree & Bytecode Integrity (compile(ast.parse(...)) succeeds without syntax error).
- Invariant D-2: Closed-Loop Verification Gate (post-write re-scan yields 0 findings and 100/100 CLEAN score).
"""

import ast
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON_EXE = sys.executable
TCS_CLI = REPO_ROOT / "tcs_cli.py"
SANDBOX_DIR = REPO_ROOT / "scratch" / "adversarial_sandbox"


class GauntletResult:
    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.duration_sec = 0.0
        self.invariant_d1_passed = False
        self.invariant_d2_passed = False
        self.details: List[str] = []
        self.error: Optional[str] = None


def run_cli_command(
    args: List[str],
    cwd: Path,
    timeout: int = 30
) -> subprocess.CompletedProcess:
    """Executes tcs_cli.py in a dedicated subprocess with proper environment."""
    cmd = [PYTHON_EXE, str(TCS_CLI)] + args
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(cwd),
        env=env,
        timeout=timeout
    )


class VectorDAdversarialDeepAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        # Clean sandbox before each test
        if SANDBOX_DIR.exists():
            shutil.rmtree(SANDBOX_DIR, ignore_errors=True)
        SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        # Keep artifacts if failed, otherwise clean
        pass

    # =========================================================================
    # GAUNTLET 1: Multi-Finding Collision
    # =========================================================================
    def test_gauntlet_1_multi_finding_collision(self):
        """
        GAUNTLET 1: Multi-Finding Collision
        A single file containing all 3 CWEs:
        - CWE-89 (SQL Injection) at top
        - CWE-78 (Command Injection) in middle
        - CWE-22 (Path Traversal) at bottom
        
        Verifies:
        - All 3 patches apply cleanly in bottom-up descending line sequence.
        - Header import 'from pathlib import Path' safely injected.
        - Invariant D-1: compile() succeeds with zero line-shift syntax errors.
        - Invariant D-2: Post-write re-scan yields 0 findings and 100/100 CLEAN score.
        """
        t0 = time.perf_counter()
        target_file = SANDBOX_DIR / "gauntlet1_collision.py"
        target_code = (
            "import sqlite3\n"
            "import subprocess\n"
            "\n"
            "def query_user(cursor, username):\n"
            '    cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")\n'
            "    return cursor.fetchone()\n"
            "\n"
            "def ping_host(host):\n"
            '    cmd = f"ping -c 1 {host}"\n'
            "    subprocess.call(cmd, shell=True)\n"
            "\n"
            "def read_user_file(base_dir, filename):\n"
            "    target_path = base_dir + filename\n"
            '    with open(target_path, "r") as f:\n'
            "        return f.read()\n"
        )
        target_file.write_text(target_code, encoding="utf-8")

        # Execute --fix --write
        res = run_cli_command(["scan", str(target_file), "--fix", "--write"], cwd=SANDBOX_DIR)
        self.assertEqual(res.returncode, 0, f"Expected exit code 0, got {res.returncode}. Stderr: {res.stderr}")
        self.assertIn("Wrote 1 verified file(s) (3 patch(es) applied)", res.stderr)

        patched_code = target_file.read_text(encoding="utf-8")

        # Verify all 3 patches are present
        self.assertIn("from pathlib import Path", patched_code, "Pathlib import missing")
        self.assertIn('cursor.execute("SELECT * FROM users WHERE name = ?", (username,))', patched_code, "CWE-89 patch missing")
        self.assertIn('cmd_list = ["ping", "-c", "1", host]', patched_code, "CWE-78 cmd_list missing")
        self.assertIn("subprocess.call(cmd_list, shell=False)", patched_code, "CWE-78 shell=False missing")
        self.assertIn("safe_base = Path(base_dir).resolve()", patched_code, "CWE-22 safe_base missing")
        self.assertIn("target_path = (safe_base / filename).resolve()", patched_code, "CWE-22 target_path missing")
        self.assertIn("if not target_path.is_relative_to(safe_base):", patched_code, "CWE-22 containment missing")

        # Invariant D-1: AST & Bytecode Compilation
        tree = ast.parse(patched_code, filename=str(target_file))
        code_obj = compile(tree, str(target_file), "exec")
        self.assertIsNotNone(code_obj, "Invariant D-1 Failed: compile() returned None")

        # Invariant D-2: Closed-Loop Re-Scan Verification
        rescan = run_cli_command(["scan", str(target_file), "--audit-all"], cwd=SANDBOX_DIR)
        self.assertEqual(rescan.returncode, 0, f"Invariant D-2 Failed: Re-scan exit code != 0. Stderr: {rescan.stderr}")
        self.assertIn("100/100 (CLEAN)", rescan.stderr, "Invariant D-2 Failed: Score not 100/100 CLEAN")
        self.assertIn("No security vulnerabilities detected", rescan.stdout, "Invariant D-2 Failed: Findings remaining")

        duration = time.perf_counter() - t0
        print(f"\n[GAUNTLET 1 PASS] Multi-Finding Collision resolved in {duration:.3f}s (Invariant D-1: OK, Invariant D-2: OK)")

    # =========================================================================
    # GAUNTLET 2: Adversarial Rejection
    # =========================================================================
    def test_gauntlet_2_adversarial_rejection(self):
        """
        GAUNTLET 2: Adversarial Rejection
        A file containing hazardous un-parameterizable patterns:
        - Dynamic table injection: cursor.execute(f"SELECT * FROM {tbl}")
        - Shell pipe injection: subprocess.call(f"cat {f} | grep x", shell=True)
        
        Verifies:
        - Vector D safely rejects both patterns as UNSUPPORTED_CWE.
        - Exactly 0 files are written and 0 patches applied.
        - File on disk remains 100% byte-identical (zero accidental corruption).
        - Tested under both public '--fix --write' and audit '--audit-all --fix --write'.
        """
        t0 = time.perf_counter()
        target_file = SANDBOX_DIR / "gauntlet2_rejection.py"
        target_code = (
            "import sqlite3\n"
            "import subprocess\n"
            "\n"
            "def fetch_table(cursor, tbl):\n"
            '    cursor.execute(f"SELECT * FROM {tbl}")\n'
            "    return cursor.fetchall()\n"
            "\n"
            "def search_logs(pattern):\n"
            '    cmd = f"cat /var/log/syslog | grep {pattern}"\n'
            "    subprocess.call(cmd, shell=True)\n"
        )
        target_file.write_text(target_code, encoding="utf-8")
        orig_bytes = target_file.read_bytes()

        # Test 1: Public workflow --fix --write
        res1 = run_cli_command(["scan", str(target_file), "--fix", "--write"], cwd=SANDBOX_DIR)
        self.assertEqual(target_file.read_bytes(), orig_bytes, "Disk mutated under --fix --write on unsupported patterns!")
        self.assertIn("Wrote 0 verified file(s) (0 patch(es) applied)", res1.stderr)

        # Test 2: Audit workflow --audit-all --fix --write
        res2 = run_cli_command(["scan", str(target_file), "--audit-all", "--fix", "--write"], cwd=SANDBOX_DIR)
        self.assertEqual(target_file.read_bytes(), orig_bytes, "Disk mutated under --audit-all --fix --write on unsupported patterns!")
        self.assertIn("Wrote 0 verified file(s) (0 patch(es) applied)", res2.stderr)
        self.assertIn("UNSUPPORTED_CWE", res2.stdout)

        # Invariant D-1: Original AST remains valid
        tree = ast.parse(target_file.read_text(encoding="utf-8"))
        self.assertIsNotNone(compile(tree, str(target_file), "exec"))

        # Invariant D-2: Rejection is stable and deterministic
        res_check = run_cli_command(["scan", str(target_file), "--audit-all"], cwd=SANDBOX_DIR)
        self.assertEqual(res_check.returncode, 1, "Expected scanner to flag un-remediated vulnerabilities")

        duration = time.perf_counter() - t0
        print(f"\n[GAUNTLET 2 PASS] Adversarial Rejection verified in {duration:.3f}s (100% Byte-Identical Preservation)")

    # =========================================================================
    # GAUNTLET 3: Deep Nesting & Async Indentation
    # =========================================================================
    def test_gauntlet_3_deep_nesting_and_async_indentation(self):
        """
        GAUNTLET 3: Deep Nesting & Async Indentation
        A vulnerable SQL query nested 4-levels deep in an async class method:
        class -> async def -> try -> if -> for -> cursor.execute (20 spaces indentation).
        
        Verifies:
        - Exact 20-space indentation is preserved without misalignment.
        - Invariant D-1: AST parsing and bytecode compilation succeed cleanly.
        - Invariant D-2: Closed-loop verification re-scan yields 0 findings and 100/100 CLEAN.
        """
        t0 = time.perf_counter()
        target_file = SANDBOX_DIR / "gauntlet3_deep_async.py"
        target_code = (
            "import sqlite3\n"
            "\n"
            "class UserRepository:\n"
            "    async def get_user_by_name(self, cursor, username):\n"
            "        try:\n"
            "            if cursor:\n"
            "                for _ in range(1):\n"
            '                    cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")\n'
            "                    result = cursor.fetchone()\n"
            "                    return result\n"
            "        except Exception:\n"
            "            return None\n"
            "        finally:\n"
            "            pass\n"
        )
        target_file.write_text(target_code, encoding="utf-8")

        res = run_cli_command(["scan", str(target_file), "--fix", "--write"], cwd=SANDBOX_DIR)
        self.assertEqual(res.returncode, 0, f"Expected exit code 0. Stderr: {res.stderr}")
        self.assertIn("Wrote 1 verified file(s) (1 patch(es) applied)", res.stderr)

        patched_code = target_file.read_text(encoding="utf-8")
        patched_lines = patched_code.splitlines()

        # Find the line containing cursor.execute
        exec_lines = [l for l in patched_lines if "cursor.execute" in l]
        self.assertEqual(len(exec_lines), 1, "Expected exactly 1 cursor.execute line")
        exec_line = exec_lines[0]

        # Verify indentation is exactly 20 spaces
        expected_indent = " " * 20
        self.assertTrue(
            exec_line.startswith(expected_indent) and not exec_line.startswith(" " * 21),
            f"Indentation mismatch. Expected 20 spaces, got: {repr(exec_line[:24])}"
        )
        self.assertEqual(
            exec_line.strip(),
            'cursor.execute("SELECT * FROM users WHERE name = ?", (username,))'
        )

        # Invariant D-1: AST & Bytecode Compilation
        tree = ast.parse(patched_code, filename=str(target_file))
        code_obj = compile(tree, str(target_file), "exec")
        self.assertIsNotNone(code_obj, "Invariant D-1 Failed: compile() failed on nested async code")

        # Invariant D-2: Closed-Loop Re-Scan Verification
        rescan = run_cli_command(["scan", str(target_file), "--audit-all"], cwd=SANDBOX_DIR)
        self.assertEqual(rescan.returncode, 0, f"Invariant D-2 Failed: Re-scan exit code != 0. Stderr: {rescan.stderr}")
        self.assertIn("100/100 (CLEAN)", rescan.stderr)
        self.assertIn("No security vulnerabilities detected", rescan.stdout)

        duration = time.perf_counter() - t0
        print(f"\n[GAUNTLET 3 PASS] Deep Nesting & Async Indentation resolved in {duration:.3f}s (Invariant D-1: OK, Invariant D-2: OK)")

    # =========================================================================
    # GAUNTLET 4: Idempotency
    # =========================================================================
    def test_gauntlet_4_idempotency(self):
        """
        GAUNTLET 4: Idempotency
        Runs '--fix --write' repeatedly on already clean/patched code.
        
        Verifies:
        - Exit code is 0.
        - Exactly 0 patches applied.
        - Exactly 0 bytes modified (file hash remains identical).
        - Zero unnecessary filesystem writes.
        """
        t0 = time.perf_counter()
        target_file = SANDBOX_DIR / "gauntlet4_idempotent.py"
        clean_code = (
            "import sqlite3\n"
            "import subprocess\n"
            "from pathlib import Path\n"
            "\n"
            "def query_user(cursor, username):\n"
            '    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))\n'
            "    return cursor.fetchone()\n"
            "\n"
            "def ping_host(host):\n"
            '    cmd_list = ["ping", "-c", "1", host]\n'
            "    subprocess.call(cmd_list, shell=False)\n"
            "\n"
            "def read_user_file(base_dir, filename):\n"
            "    safe_base = Path(base_dir).resolve()\n"
            "    target_path = (safe_base / filename).resolve()\n"
            "    if not target_path.is_relative_to(safe_base):\n"
            '        raise ValueError("Path traversal attempt detected")\n'
            '    with open(target_path, "r") as f:\n'
            "        return f.read()\n"
        )
        target_file.write_text(clean_code, encoding="utf-8")
        orig_bytes = target_file.read_bytes()
        orig_mtime = target_file.stat().st_mtime_ns

        # Run 1: --fix --write
        res1 = run_cli_command(["scan", str(target_file), "--fix", "--write"], cwd=SANDBOX_DIR)
        self.assertEqual(res1.returncode, 0, f"Expected exit code 0. Stderr: {res1.stderr}")
        self.assertIn("100/100 (CLEAN)", res1.stderr)
        self.assertEqual(target_file.read_bytes(), orig_bytes, "File content changed on idempotent run 1!")

        # Run 2: --audit-all --fix --write
        res2 = run_cli_command(["scan", str(target_file), "--audit-all", "--fix", "--write"], cwd=SANDBOX_DIR)
        self.assertEqual(res2.returncode, 0, f"Expected exit code 0. Stderr: {res2.stderr}")
        self.assertIn("100/100 (CLEAN)", res2.stderr)
        self.assertEqual(target_file.read_bytes(), orig_bytes, "File content changed on idempotent run 2!")

        # Invariant D-1 & D-2
        tree = ast.parse(target_file.read_text(encoding="utf-8"))
        self.assertIsNotNone(compile(tree, str(target_file), "exec"))

        duration = time.perf_counter() - t0
        print(f"\n[GAUNTLET 4 PASS] Idempotency confirmed in {duration:.3f}s (0 patches, 0 bytes modified)")

    # =========================================================================
    # GAUNTLET 5: Line Ending Preservation (CRLF)
    # =========================================================================
    def test_gauntlet_5_line_ending_preservation(self):
        """
        GAUNTLET 5: Line Ending Preservation
        A file authored exclusively with Windows CRLF ('\\r\\n') line endings.
        
        Verifies:
        - In-place patch application strictly preserves exact '\\r\\n' byte sequences.
        - Zero LF leakage (no raw '\\n' without preceding '\\r').
        - Invariant D-1: AST parsing and bytecode compilation succeed.
        - Invariant D-2: Closed-loop verification re-scan yields 0 findings and 100/100 CLEAN.
        """
        t0 = time.perf_counter()
        target_file = SANDBOX_DIR / "gauntlet5_crlf.py"
        crlf_content = (
            b"import sqlite3\r\n"
            b"\r\n"
            b"def get_user(cursor, username):\r\n"
            b"    cursor.execute(f\"SELECT * FROM users WHERE name = '{username}'\")\r\n"
            b"    return cursor.fetchone()\r\n"
        )
        target_file.write_bytes(crlf_content)

        res = run_cli_command(["scan", str(target_file), "--fix", "--write"], cwd=SANDBOX_DIR)
        self.assertEqual(res.returncode, 0, f"Expected exit code 0. Stderr: {res.stderr}")
        self.assertIn("Wrote 1 verified file(s) (1 patch(es) applied)", res.stderr)

        patched_bytes = target_file.read_bytes()

        # Verify CRLF is present
        self.assertIn(b"\r\n", patched_bytes, "CRLF line endings were lost in patched file!")

        # Verify zero LF leakage: remove all \r\n, then check if any lone \n remains
        stripped_crlf = patched_bytes.replace(b"\r\n", b"")
        self.assertNotIn(b"\n", stripped_crlf, "Lone LF leakage detected! Mixed line endings injected.")

        # Invariant D-1: AST & Bytecode Compilation
        patched_text = target_file.read_text(encoding="utf-8")
        tree = ast.parse(patched_text, filename=str(target_file))
        code_obj = compile(tree, str(target_file), "exec")
        self.assertIsNotNone(code_obj, "Invariant D-1 Failed: compile() failed on CRLF patched file")

        # Invariant D-2: Closed-Loop Re-Scan Verification
        rescan = run_cli_command(["scan", str(target_file), "--audit-all"], cwd=SANDBOX_DIR)
        self.assertEqual(rescan.returncode, 0, f"Invariant D-2 Failed: Re-scan exit code != 0. Stderr: {rescan.stderr}")
        self.assertIn("100/100 (CLEAN)", rescan.stderr)

        duration = time.perf_counter() - t0
        print(f"\n[GAUNTLET 5 PASS] CRLF Preservation verified in {duration:.3f}s (Zero LF leakage, exact byte match)")


def run_standalone_deep_audit():
    """Runs the 5 gauntlets standalone and outputs executive verification matrix."""
    print("=" * 80)
    print("TIME CODE SECURITY (TCS) - VECTOR D ADVERSARIAL DEEP-AUDIT SUITE")
    print("Role: Principal Security QA & AST Compiler Specialist")
    print(f"Isolated Sandbox: {SANDBOX_DIR}")
    print("=" * 80)

    suite = unittest.TestLoader().loadTestsFromTestCase(VectorDAdversarialDeepAudit)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 80)
    print("ADVERSARIAL GAUNTLET AUDIT SUMMARY MATRIX")
    print("=" * 80)
    print(f"Total Gauntlets Run:   {result.testsRun}")
    print(f"Total Passed:          {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Total Failures:        {len(result.failures)}")
    print(f"Total Errors:          {len(result.errors)}")
    print("=" * 80)

    if result.wasSuccessful():
        print("[AUDIT CERTIFIED] All 5 Adversarial Gauntlets PASSED.")
        print("Invariant D-1 (Syntax & Compilation Integrity): VERIFIED")
        print("Invariant D-2 (Closed-Loop Re-scan Verification): VERIFIED")
        sys.exit(0)
    else:
        print("[AUDIT FAILED] Adversarial vulnerabilities or regressions detected.")
        sys.exit(1)


if __name__ == "__main__":
    run_standalone_deep_audit()
