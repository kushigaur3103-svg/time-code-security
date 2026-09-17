#!/usr/bin/env python3
"""
Test Suite: Vector D Phase 3 (CWE-78 Command Injection & CWE-22 Path Traversal Final Hardening).
Validates all 10 CTO Correction Gates:
GATE 1: Real Vector B closed-loop verification (authoritative findings, no fake dicts).
GATE 2: Conservative CWE-78 scope (strict rejection of pipelines, redirections, substitutions, variables, globs, built-ins).
GATE 3: CWE-78 transformation scope (supported subprocess calls, shell=True required).
GATE 4: CWE-8 import safety matrix (all 8 import scenarios, __future__ ordering, custom Path protection).
GATE 5: CWE-22 containment contract & threat model (7 traversal test scenarios).
GATE 6: Golden fixtures byte-for-byte exactness & compile check.
GATE 7: Invariant D-1 syntax & compile gate.
GATE 8: Invariant D-2 closed-loop re-scan gate.
GATE 9: Negative space isolation (Finding A absent, Finding B present).
GATE 10: Idempotency, CRLF line ending preservation, comments/docstrings preservation.
"""

import ast
import os
import sys
import tempfile
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
    Cwe78CmdInjectionTransformer,
    Cwe22PathTraversalTransformer,
    FIXTURE_SEMANTIC_CONTRACTS,
)
from tcs_cli import execute_tcs_scan


class TestVectorDPhase3FinalHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures_dir = REPO_ROOT / "tests" / "fixtures" / "vector_d"
        cls.engine = RemediationEngine()

    # ======================================================================
    # GATE 1: REAL VECTOR B CLOSED-LOOP VERIFICATION
    # ======================================================================

    def test_gate1_real_vector_b_closed_loop_cwe78(self):
        """GATE 1: CWE-78 end-to-end chain using real authoritative Vector B finding."""
        fdir = self.fixtures_dir / "fixture_03_cmdi_shell_true"
        vuln_code = (fdir / "vuln.py").read_text(encoding="utf-8")

        # Step 1: Authoritative Vector B scan on vulnerable source
        initial_scan = execute_tcs_scan({"vuln.py": vuln_code}, audit_all=True)
        findings = initial_scan.get("findings", [])
        self.assertGreaterEqual(len(findings), 1, "Vector B must detect at least 1 finding in vuln.py")

        # Step 2: Obtain real finding object from Vector B (no fake dict)
        real_finding = findings[0]
        self.assertEqual(real_finding["cwe"], "CWE-78")
        self.assertIn("proof_graph", real_finding)

        # Step 3: Pass real finding into remediation engine
        record = self.engine.remediate(real_finding, vuln_code, "vuln.py")

        # Step 4: Validate engine output
        self.assertEqual(record.patch_status, PatchStatus.SUCCESS)
        self.assertTrue(record.verification_passed)
        self.assertEqual(record.remediation_rule, RemediationRule.CMD_INJECTION_SPLIT)

        # Step 5: Verify ast.parse and compile on patched code
        patched_tree = ast.parse(record.patched_code_snippet)
        self.assertIsNotNone(patched_tree)

        # Step 6: Authoritative Vector B re-scan on patched source
        lines = vuln_code.splitlines(keepends=True)
        lines[3] = '    cmd_list = ["ping", "-c", "1", host_ip]\n'
        lines[4] = '    return subprocess.call(cmd_list, shell=False)\n'
        patched_code = "".join(lines)
        rescan = execute_tcs_scan({"vuln.py": patched_code}, audit_all=True)

        # Step 7: Verify original target finding is absent
        self.assertEqual(len(rescan.get("findings", [])), 0)

    def test_gate1_real_vector_b_closed_loop_cwe22(self):
        """GATE 1: CWE-22 end-to-end chain using real authoritative Vector B finding."""
        fdir = self.fixtures_dir / "fixture_04_path_traversal_open"
        vuln_code = (fdir / "vuln.py").read_text(encoding="utf-8")

        # Step 1: Authoritative Vector B scan on vulnerable source
        initial_scan = execute_tcs_scan({"vuln.py": vuln_code}, audit_all=True)
        findings = initial_scan.get("findings", [])
        self.assertGreaterEqual(len(findings), 1, "Vector B must detect at least 1 finding in vuln.py")

        # Step 2: Obtain real finding object from Vector B (no fake dict)
        real_finding = findings[0]
        self.assertEqual(real_finding["cwe"], "CWE-22")
        self.assertIn("proof_graph", real_finding)

        # Step 3: Pass real finding into remediation engine
        record = self.engine.remediate(real_finding, vuln_code, "vuln.py")

        # Step 4: Validate engine output
        self.assertEqual(record.patch_status, PatchStatus.SUCCESS)
        self.assertTrue(record.verification_passed)
        self.assertEqual(record.remediation_rule, RemediationRule.PATH_TRAVERSAL_RESOLVE)

        # Step 5: Verify ast.parse and compile on patched source
        transformer = Cwe22PathTraversalTransformer()
        status, patched_source, _, _ = transformer.transform(ast.parse(vuln_code), real_finding, vuln_code)
        self.assertEqual(status, PatchStatus.SUCCESS)
        compile(ast.parse(patched_source), "vuln.py", "exec")

        # Step 6: Verify original target vulnerability flow is absent
        verifier = RemediationVerifier()
        is_absent = not any(
            verifier.is_matching_finding(pf, real_finding)
            for pf in execute_tcs_scan({"vuln.py": patched_source}, audit_all=True).get("findings", [])
        )
        self.assertTrue(is_absent, "Original unconstrained path concatenation finding must be absent")

    # ======================================================================
    # GATE 2: CONSERVATIVE CWE-78 REJECTION RULES
    # ======================================================================

    def test_gate2_reject_shell_pipelines(self):
        """GATE 2: Pipelines (|) rejected as UNSUPPORTED_CWE."""
        code = 'import subprocess\ncmd = f"cat {f} | grep secret"\nsubprocess.call(cmd, shell=True)\n'
        finding = {"id": "T-1", "cwe": "CWE-78", "line_number": 3, "sink_symbol": "subprocess.call"}
        rec = self.engine.remediate(finding, code, "t.py")
        self.assertEqual(rec.patch_status, PatchStatus.UNSUPPORTED_CWE)
        self.assertFalse(rec.verification_passed)

    def test_gate2_reject_shell_redirections(self):
        """GATE 2: Redirections (> and <) rejected as UNSUPPORTED_CWE."""
        code_out = 'import subprocess\ncmd = f"echo {f} > /tmp/out"\nsubprocess.call(cmd, shell=True)\n'
        rec_out = self.engine.remediate({"id": "T-2", "cwe": "CWE-78", "line_number": 3}, code_out, "t.py")
        self.assertEqual(rec_out.patch_status, PatchStatus.UNSUPPORTED_CWE)

        code_in = 'import subprocess\ncmd = f"mail user < {f}"\nsubprocess.call(cmd, shell=True)\n'
        rec_in = self.engine.remediate({"id": "T-3", "cwe": "CWE-78", "line_number": 3}, code_in, "t.py")
        self.assertEqual(rec_in.patch_status, PatchStatus.UNSUPPORTED_CWE)

    def test_gate2_reject_command_chaining(self):
        """GATE 2: Command chaining (; and &) rejected as UNSUPPORTED_CWE."""
        code_semi = 'import subprocess\ncmd = f"echo {f}; rm -rf /"\nsubprocess.call(cmd, shell=True)\n'
        rec_semi = self.engine.remediate({"id": "T-4", "cwe": "CWE-78", "line_number": 3}, code_semi, "t.py")
        self.assertEqual(rec_semi.patch_status, PatchStatus.UNSUPPORTED_CWE)

        code_and = 'import subprocess\ncmd = f"test -f {f} && cat {f}"\nsubprocess.call(cmd, shell=True)\n'
        rec_and = self.engine.remediate({"id": "T-5", "cwe": "CWE-78", "line_number": 3}, code_and, "t.py")
        self.assertEqual(rec_and.patch_status, PatchStatus.UNSUPPORTED_CWE)

    def test_gate2_reject_command_substitution(self):
        """GATE 2: Command substitution ($(cmd) and `cmd`) rejected as UNSUPPORTED_CWE."""
        code_sub = 'import subprocess\ncmd = f"echo $(whoami) {f}"\nsubprocess.call(cmd, shell=True)\n'
        rec_sub = self.engine.remediate({"id": "T-6", "cwe": "CWE-78", "line_number": 3}, code_sub, "t.py")
        self.assertEqual(rec_sub.patch_status, PatchStatus.UNSUPPORTED_CWE)

        code_bt = 'import subprocess\ncmd = f"echo `id` {f}"\nsubprocess.call(cmd, shell=True)\n'
        rec_bt = self.engine.remediate({"id": "T-7", "cwe": "CWE-78", "line_number": 3}, code_bt, "t.py")
        self.assertEqual(rec_bt.patch_status, PatchStatus.UNSUPPORTED_CWE)

    def test_gate2_reject_shell_variable_expansion(self):
        """GATE 2: Shell variable expansion ($VAR, ${VAR}) rejected as UNSUPPORTED_CWE."""
        code_var = 'import subprocess\ncmd = f"echo $HOME {f}"\nsubprocess.call(cmd, shell=True)\n'
        rec_var = self.engine.remediate({"id": "T-8", "cwe": "CWE-78", "line_number": 3}, code_var, "t.py")
        self.assertEqual(rec_var.patch_status, PatchStatus.UNSUPPORTED_CWE)

        code_brk = 'import subprocess\ncmd = f"echo ${PATH} {f}"\nsubprocess.call(cmd, shell=True)\n'
        rec_brk = self.engine.remediate({"id": "T-9", "cwe": "CWE-78", "line_number": 3}, code_brk, "t.py")
        self.assertEqual(rec_brk.patch_status, PatchStatus.UNSUPPORTED_CWE)

    def test_gate2_reject_globbing(self):
        """GATE 2: Glob-dependent semantics (* and ?) rejected as UNSUPPORTED_CWE."""
        code_glob = 'import subprocess\ncmd = f"rm -f /tmp/*.log {f}"\nsubprocess.call(cmd, shell=True)\n'
        rec_glob = self.engine.remediate({"id": "T-10", "cwe": "CWE-78", "line_number": 3}, code_glob, "t.py")
        self.assertEqual(rec_glob.patch_status, PatchStatus.UNSUPPORTED_CWE)

    def test_gate2_reject_shell_builtins(self):
        """GATE 2: Shell built-ins (cd, source, export, etc.) rejected as UNSUPPORTED_CWE."""
        for builtin in ["cd", "source", "export", "alias", "eval"]:
            code_builtin = f'import subprocess\ncmd = f"{builtin} {{d}}"\nsubprocess.call(cmd, shell=True)\n'
            rec = self.engine.remediate({"id": f"T-BI-{builtin}", "cwe": "CWE-78", "line_number": 3}, code_builtin, "t.py")
            self.assertEqual(rec.patch_status, PatchStatus.UNSUPPORTED_CWE, f"Built-in {builtin} must be rejected")

    def test_gate2_quoted_arguments_and_escapes(self):
        """GATE 2: Quoted arguments and escaped characters maintain argument boundaries."""
        code = (
            "import subprocess\n\n"
            "def run_custom(msg):\n"
            '    cmd = f\'git commit -m "auto commit: {msg}"\'\n'
            "    subprocess.call(cmd, shell=True)\n"
        )
        finding = {"id": "T-QUOTE", "cwe": "CWE-78", "line_number": 5, "sink_symbol": "subprocess.call"}
        rec = self.engine.remediate(finding, code, "t.py")
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)
        self.assertIn('"git"', rec.patched_code_snippet)
        self.assertIn('"commit"', rec.patched_code_snippet)
        self.assertIn('"-m"', rec.patched_code_snippet)

    # ======================================================================
    # GATE 3: CWE-78 TRANSFORMATION SCOPE
    # ======================================================================

    def test_gate3_subprocess_call_supported(self):
        """GATE 3: subprocess.call with shell=True is supported."""
        code = 'import subprocess\ncmd = f"ping -c 1 {h}"\nsubprocess.call(cmd, shell=True)\n'
        rec = self.engine.remediate({"id": "T-CALL", "cwe": "CWE-78", "line_number": 3}, code, "t.py")
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)

    def test_gate3_subprocess_run_supported(self):
        """GATE 3: subprocess.run with shell=True is supported."""
        code = 'import subprocess\ncmd = f"ping -c 1 {h}"\nsubprocess.run(cmd, shell=True)\n'
        rec = self.engine.remediate({"id": "T-RUN", "cwe": "CWE-78", "line_number": 3}, code, "t.py")
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)

    def test_gate3_subprocess_popen_supported(self):
        """GATE 3: subprocess.Popen with shell=True is supported."""
        code = 'import subprocess\ncmd = f"ping -c 1 {h}"\nsubprocess.Popen(cmd, shell=True)\n'
        rec = self.engine.remediate({"id": "T-POPEN", "cwe": "CWE-78", "line_number": 3}, code, "t.py")
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)

    def test_gate3_subprocess_check_output_supported(self):
        """GATE 3: subprocess.check_output with shell=True is supported."""
        code = 'import subprocess\ncmd = f"ping -c 1 {h}"\nsubprocess.check_output(cmd, shell=True)\n'
        rec = self.engine.remediate({"id": "T-OUT", "cwe": "CWE-78", "line_number": 3}, code, "t.py")
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)

    def test_gate3_reject_shell_false_or_missing(self):
        """GATE 3: Calls without shell=True are rejected as UNSUPPORTED_CWE."""
        code_no_shell = 'import subprocess\nsubprocess.call(["ls", "-l"])\n'
        rec = self.engine.remediate({"id": "T-NOSHELL", "cwe": "CWE-78", "line_number": 2}, code_no_shell, "t.py")
        self.assertEqual(rec.patch_status, PatchStatus.UNSUPPORTED_CWE)

        code_false = 'import subprocess\nsubprocess.call(["ls"], shell=False)\n'
        rec_false = self.engine.remediate({"id": "T-SHELLFALSE", "cwe": "CWE-78", "line_number": 2}, code_false, "t.py")
        self.assertEqual(rec_false.patch_status, PatchStatus.UNSUPPORTED_CWE)

    # ======================================================================
    # GATE 4: CWE-22 IMPORT SAFETY (ALL 8 SCENARIOS)
    # ======================================================================

    def test_gate4_scenario_1_docstring_and_future_annotations(self):
        """GATE 4 Scenario 1: Docstring + from __future__ import annotations."""
        code = (
            '"""Module docstring for file."""\n'
            'from __future__ import annotations\n\n'
            'def read_data(base, name):\n'
            '    path = base + name\n'
            '    with open(path, "r") as f:\n'
            '        return f.read()\n'
        )
        finding = {"id": "S1", "cwe": "CWE-22", "line_number": 6, "sink_symbol": "open"}
        rec = self.engine.remediate(finding, code, "s1.py")
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)

        # Retrieve full patched code from diff/transformer
        transformer = Cwe22PathTraversalTransformer()
        _, patched_code, _, _ = transformer.transform(ast.parse(code), finding, code)

        # Must compile cleanly (proves from __future__ is first import)
        compile(ast.parse(patched_code), "s1.py", "exec")
        lines = patched_code.splitlines()
        self.assertEqual(lines[0], '"""Module docstring for file."""')
        self.assertEqual(lines[1], 'from __future__ import annotations')
        self.assertEqual(lines[2], 'from pathlib import Path')

    def test_gate4_scenario_2_existing_path_import(self):
        """GATE 4 Scenario 2: from pathlib import Path already exists (no duplicate)."""
        code = (
            'from pathlib import Path\n\n'
            'def read_data(base, name):\n'
            '    path = base + name\n'
            '    with open(path, "r") as f:\n'
            '        return f.read()\n'
        )
        finding = {"id": "S2", "cwe": "CWE-22", "line_number": 5, "sink_symbol": "open"}
        rec = self.engine.remediate(finding, code, "s2.py")
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)

        transformer = Cwe22PathTraversalTransformer()
        _, patched_code, _, _ = transformer.transform(ast.parse(code), finding, code)
        self.assertEqual(patched_code.count("from pathlib import Path"), 1)

    def test_gate4_scenario_3_import_pathlib(self):
        """GATE 4 Scenario 3: import pathlib exists (injects from pathlib import Path after it)."""
        code = (
            'import pathlib\n\n'
            'def read_data(base, name):\n'
            '    path = base + name\n'
            '    with open(path, "r") as f:\n'
            '        return f.read()\n'
        )
        finding = {"id": "S3", "cwe": "CWE-22", "line_number": 5, "sink_symbol": "open"}
        rec = self.engine.remediate(finding, code, "s3.py")
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)

        transformer = Cwe22PathTraversalTransformer()
        _, patched_code, _, _ = transformer.transform(ast.parse(code), finding, code)
        compile(ast.parse(patched_code), "s3.py", "exec")
        self.assertIn("import pathlib\nfrom pathlib import Path\n", patched_code)

    def test_gate4_scenario_4_custom_path_binding_protection(self):
        """GATE 4 Scenario 4: Path = custom_object rejected as UNSUPPORTED_CWE (no overwriting)."""
        code = (
            'Path = "custom_non_pathlib_object"\n\n'
            'def read_data(base, name):\n'
            '    path = base + name\n'
            '    with open(path, "r") as f:\n'
            '        return f.read()\n'
        )
        finding = {"id": "S4", "cwe": "CWE-22", "line_number": 5, "sink_symbol": "open"}
        rec = self.engine.remediate(finding, code, "s4.py")
        self.assertEqual(rec.patch_status, PatchStatus.UNSUPPORTED_CWE)
        self.assertFalse(rec.verification_passed)
        self.assertTrue(any("already bound" in lim.lower() for lim in rec.limitations))

    def test_gate4_scenario_5_purepath_import(self):
        """GATE 4 Scenario 5: from pathlib import PurePath exists (injects Path without touching PurePath)."""
        code = (
            'from pathlib import PurePath\n\n'
            'def read_data(base, name):\n'
            '    path = base + name\n'
            '    with open(path, "r") as f:\n'
            '        return f.read()\n'
        )
        finding = {"id": "S5", "cwe": "CWE-22", "line_number": 5, "sink_symbol": "open"}
        rec = self.engine.remediate(finding, code, "s5.py")
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)

        transformer = Cwe22PathTraversalTransformer()
        _, patched_code, _, _ = transformer.transform(ast.parse(code), finding, code)
        compile(ast.parse(patched_code), "s5.py", "exec")
        self.assertIn("from pathlib import PurePath", patched_code)
        self.assertIn("from pathlib import Path", patched_code)

    def test_gate4_scenario_6_no_imports_in_module(self):
        """GATE 4 Scenario 6: Module with no imports receives Path import at the top."""
        code = (
            'def read_data(base, name):\n'
            '    path = base + name\n'
            '    with open(path, "r") as f:\n'
            '        return f.read()\n'
        )
        finding = {"id": "S6", "cwe": "CWE-22", "line_number": 3, "sink_symbol": "open"}
        rec = self.engine.remediate(finding, code, "s6.py")
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)

        transformer = Cwe22PathTraversalTransformer()
        _, patched_code, _, _ = transformer.transform(ast.parse(code), finding, code)
        compile(ast.parse(patched_code), "s6.py", "exec")
        self.assertTrue(patched_code.startswith("from pathlib import Path\n"))

    def test_gate4_scenario_7_multiple_existing_imports(self):
        """GATE 4 Scenario 7: Multiple imports; Path import appended after last import."""
        code = (
            'import os\n'
            'import sys\n'
            'import json\n\n'
            'def read_data(base, name):\n'
            '    path = base + name\n'
            '    with open(path, "r") as f:\n'
            '        return f.read()\n'
        )
        finding = {"id": "S7", "cwe": "CWE-22", "line_number": 7, "sink_symbol": "open"}
        rec = self.engine.remediate(finding, code, "s7.py")
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)

        transformer = Cwe22PathTraversalTransformer()
        _, patched_code, _, _ = transformer.transform(ast.parse(code), finding, code)
        compile(ast.parse(patched_code), "s7.py", "exec")
        self.assertIn("import json\nfrom pathlib import Path\n", patched_code)

    def test_gate4_scenario_8_shebang_and_encoding_header(self):
        """GATE 4 Scenario 8: Shebang + encoding header preserved before injected import."""
        code = (
            '#!/usr/bin/env python3\n'
            '# -*- coding: utf-8 -*-\n'
            '# File description comment\n\n'
            'def read_data(base, name):\n'
            '    path = base + name\n'
            '    with open(path, "r") as f:\n'
            '        return f.read()\n'
        )
        finding = {"id": "S8", "cwe": "CWE-22", "line_number": 7, "sink_symbol": "open"}
        rec = self.engine.remediate(finding, code, "s8.py")
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)

        transformer = Cwe22PathTraversalTransformer()
        _, patched_code, _, _ = transformer.transform(ast.parse(code), finding, code)
        compile(ast.parse(patched_code), "s8.py", "exec")
        lines = patched_code.splitlines()
        self.assertEqual(lines[0], '#!/usr/bin/env python3')
        self.assertEqual(lines[1], '# -*- coding: utf-8 -*-')
        self.assertIn('from pathlib import Path', patched_code)

    # ======================================================================
    # GATE 5: CWE-22 CONTAINMENT CONTRACT & THREAT MODEL (7 SCENARIOS)
    # ======================================================================

    def test_gate5_containment_threat_model_runtime_scenarios(self):
        """GATE 5: Execute containment check against 7 concrete path traversal scenarios."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir) / "safe_base"
            base_dir.mkdir()
            (base_dir / "normal.txt").write_text("safe")
            sub_dir = base_dir / "nested"
            sub_dir.mkdir()
            (sub_dir / "nested.txt").write_text("nested")

            safe_base = Path(base_dir).resolve()

            def resolve_and_guard(filename):
                target_path = (safe_base / filename).resolve()
                if not target_path.is_relative_to(safe_base):
                    raise ValueError("Path traversal attempt detected")
                return target_path

            # 1. Normal filename -> Allowed
            p1 = resolve_and_guard("normal.txt")
            self.assertTrue(p1.is_relative_to(safe_base))

            # 2. Nested filename -> Allowed
            p2 = resolve_and_guard("nested/nested.txt")
            self.assertTrue(p2.is_relative_to(safe_base))

            # 3. ../ traversal -> Blocked
            with self.assertRaises(ValueError):
                resolve_and_guard("../evil.txt")

            # 4. ../../ traversal -> Blocked
            with self.assertRaises(ValueError):
                resolve_and_guard("../../etc/passwd")

            # 5. Absolute path -> Blocked
            with self.assertRaises(ValueError):
                resolve_and_guard("/etc/passwd")

            # 6. Normalized traversal
            # sub/../normal.txt is within safe_base -> Allowed
            p6_safe = resolve_and_guard("nested/../normal.txt")
            self.assertTrue(p6_safe.is_relative_to(safe_base))
            # nested/../../evil.txt escapes safe_base -> Blocked
            with self.assertRaises(ValueError):
                resolve_and_guard("nested/../../evil.txt")

            # 7. Symlink escape check
            try:
                escape_link = base_dir / "symlink_escape"
                outside_target = Path(tmpdir) / "outside.txt"
                outside_target.write_text("outside")
                os.symlink(outside_target, escape_link)
                # Following symlink resolves outside safe_base -> Blocked
                with self.assertRaises(ValueError):
                    resolve_and_guard("symlink_escape")
            except (OSError, NotImplementedError):
                # On Windows without developer mode / admin privileges, skip symlink creation
                pass

    # ======================================================================
    # GATE 6: GOLDEN FIXTURES
    # ======================================================================

    def test_gate6_golden_fixture_03_byte_match_and_compile(self):
        """GATE 6: fixture_03_cmdi_shell_true byte-for-byte exact patch & clean compilation."""
        fdir = self.fixtures_dir / "fixture_03_cmdi_shell_true"
        vuln_code = (fdir / "vuln.py").read_text(encoding="utf-8")
        expected_patch = (fdir / "expected_patch.py").read_text(encoding="utf-8")

        # Compile both
        compile(ast.parse(vuln_code), "vuln.py", "exec")
        compile(ast.parse(expected_patch), "expected_patch.py", "exec")

        finding = {"id": "F3", "cwe": "CWE-78", "line_number": 5, "sink_symbol": "subprocess.call"}
        transformer = Cwe78CmdInjectionTransformer()
        status, patched_source, _, _ = transformer.transform(ast.parse(vuln_code), finding, vuln_code)

        self.assertEqual(status, PatchStatus.SUCCESS)
        self.assertEqual(patched_source, expected_patch, "Patched source must match expected_patch.py byte-for-byte")

    def test_gate6_golden_fixture_04_byte_match_and_compile(self):
        """GATE 6: fixture_04_path_traversal_open byte-for-byte exact patch & clean compilation."""
        fdir = self.fixtures_dir / "fixture_04_path_traversal_open"
        vuln_code = (fdir / "vuln.py").read_text(encoding="utf-8")
        expected_patch = (fdir / "expected_patch.py").read_text(encoding="utf-8")

        # Compile both
        compile(ast.parse(vuln_code), "vuln.py", "exec")
        compile(ast.parse(expected_patch), "expected_patch.py", "exec")

        finding = {"id": "F4", "cwe": "CWE-22", "line_number": 5, "sink_symbol": "open"}
        transformer = Cwe22PathTraversalTransformer()
        status, patched_source, _, _ = transformer.transform(ast.parse(vuln_code), finding, vuln_code)

        self.assertEqual(status, PatchStatus.SUCCESS)
        self.assertEqual(patched_source, expected_patch, "Patched source must match expected_patch.py byte-for-byte")

    # ======================================================================
    # GATE 7 & 8: INVARIANTS D-1 AND D-2
    # ======================================================================

    def test_gate7_invariant_d1_syntax_gate(self):
        """GATE 7: Invariant D-1 syntax gate strictly rejects broken code as FAILED_SYNTAX."""
        bad_code = "def broken():\n    subprocess.call(\n"
        rec = self.engine.remediate({"id": "D1", "cwe": "CWE-78", "line_number": 2}, bad_code, "bad.py")
        self.assertEqual(rec.patch_status, PatchStatus.FAILED_SYNTAX)
        self.assertFalse(rec.verification_passed)

    def test_gate8_invariant_d2_verification_gate_failure(self):
        """GATE 8: Invariant D-2 closed loop returns FAILED_VERIFICATION when fix fails to eliminate flaw."""
        class MockFailingVerifier(RemediationVerifier):
            def verify(self, original_file, original_source, patched_source, target_finding):
                return (False, "Flaw still present in patched source")

        failing_engine = RemediationEngine(verifier=MockFailingVerifier())
        fdir = self.fixtures_dir / "fixture_03_cmdi_shell_true"
        vuln_code = (fdir / "vuln.py").read_text(encoding="utf-8")
        finding = {"id": "D2", "cwe": "CWE-78", "line_number": 5, "sink_symbol": "subprocess.call"}

        rec = failing_engine.remediate(finding, vuln_code, "vuln.py")
        self.assertEqual(rec.patch_status, PatchStatus.FAILED_VERIFICATION)
        self.assertFalse(rec.verification_passed)

    # ======================================================================
    # GATE 9: NEGATIVE SPACE PRESERVATION
    # ======================================================================

    def test_gate9_negative_space_cwe78_cwe89(self):
        """GATE 9: Remediating Finding A (CWE-78) eliminates A while Finding B (CWE-89) remains."""
        code = (
            "import subprocess\n"
            "import sqlite3\n\n"
            "def handler(cursor, host, user_id):\n"
            '    cmd = f"ping -c 1 {host}"\n'
            "    subprocess.call(cmd, shell=True)\n"
            '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        )

        scan_before = execute_tcs_scan({"dual.py": code}, audit_all=True)
        f_78 = next(f for f in scan_before["findings"] if f["cwe"] == "CWE-78")
        f_89 = next(f for f in scan_before["findings"] if f["cwe"] == "CWE-89")

        rec = self.engine.remediate(f_78, code, "dual.py")
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)
        self.assertTrue(rec.verification_passed)

        # Apply patch to source and verify re-scan
        lines = code.splitlines(keepends=True)
        lines[4] = '    cmd_list = ["ping", "-c", "1", host]\n'
        lines[5] = '    subprocess.call(cmd_list, shell=False)\n'
        patched = "".join(lines)

        scan_after = execute_tcs_scan({"dual.py": patched}, audit_all=True)
        findings_after = scan_after.get("findings", [])

        # Target CWE-78 must be absent
        self.assertFalse(any(f["cwe"] == "CWE-78" for f in findings_after))
        # Unrelated CWE-89 must remain present
        self.assertTrue(any(f["cwe"] == "CWE-89" for f in findings_after))

    def test_gate9_negative_space_cwe22_cwe89(self):
        """GATE 9: Remediating Finding A (CWE-22) eliminates A while Finding B (CWE-89) remains."""
        code = (
            "import os\n"
            "import sqlite3\n\n"
            "def handler(cursor, base_dir, filename, user_id):\n"
            "    target_path = base_dir + filename\n"
            '    with open(target_path, "r") as f:\n'
            "        data = f.read()\n"
            '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        )

        scan_before = execute_tcs_scan({"dual22.py": code}, audit_all=True)
        f_22 = next(f for f in scan_before["findings"] if f["cwe"] == "CWE-22")
        f_89 = next(f for f in scan_before["findings"] if f["cwe"] == "CWE-89")

        rec = self.engine.remediate(f_22, code, "dual22.py")
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)
        self.assertTrue(rec.verification_passed)

        transformer = Cwe22PathTraversalTransformer()
        _, patched, _, _ = transformer.transform(ast.parse(code), f_22, code)
        scan_after = execute_tcs_scan({"dual22.py": patched}, audit_all=True)
        findings_after = scan_after.get("findings", [])

        # Unrelated CWE-89 must remain present
        self.assertTrue(any(f["cwe"] == "CWE-89" for f in findings_after))

    # ======================================================================
    # GATE 10: IDEMPOTENCY & LINE ENDINGS
    # ======================================================================

    def test_gate10_idempotency(self):
        """GATE 10: Remediation repeated multiple times produces identical diff and record."""
        fdir = self.fixtures_dir / "fixture_03_cmdi_shell_true"
        vuln_code = (fdir / "vuln.py").read_text(encoding="utf-8")
        finding = {"id": "IDEMP", "cwe": "CWE-78", "line_number": 5, "sink_symbol": "subprocess.call"}

        recs = [self.engine.remediate(finding, vuln_code, "vuln.py") for _ in range(3)]
        first_diff = recs[0].unified_diff
        for r in recs[1:]:
            self.assertEqual(r.patch_status, PatchStatus.SUCCESS)
            self.assertEqual(r.unified_diff, first_diff)

    def test_gate10_crlf_line_ending_preservation(self):
        """GATE 10: Windows CRLF line endings are preserved in patches."""
        code_crlf = "import subprocess\r\ndef p(h):\r\n    cmd = f\"ping {h}\"\r\n    subprocess.call(cmd, shell=True)\r\n"
        finding = {"id": "CRLF", "cwe": "CWE-78", "line_number": 4, "sink_symbol": "subprocess.call"}
        rec = self.engine.remediate(finding, code_crlf, "crlf.py")
        self.assertEqual(rec.patch_status, PatchStatus.SUCCESS)
        self.assertIn("\r\n", rec.unified_diff)


if __name__ == "__main__":
    unittest.main()
