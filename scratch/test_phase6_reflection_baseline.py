#!/usr/bin/env python3
"""
Phase 6 Baseline: Metaprogramming & Dynamic Reflection Shield.
Governing Invariant: Zero modifications to production code during baseline creation.
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tcs_cli import execute_tcs_scan


class TestPhase6ReflectionBaseline(unittest.TestCase):

    def test_pattern1_getattr_direct_literal(self):
        """Pattern 1: getattr with literal sink name -> MUST flag CWE-78"""
        code = '''
from flask import request
import subprocess
user_cmd = request.args.get("cmd")
runner = getattr(subprocess, "run")
runner(user_cmd, shell=True)
'''
        res = execute_tcs_scan({"target.py": code})
        cwe78 = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78) >= 1, "Expected CWE-78 finding for getattr(subprocess, 'run')")
        self.assertEqual(cwe78[0].get("severity"), "CRITICAL")

    def test_pattern2_getattr_string_concat_folding(self):
        """Pattern 2: getattr with concatenated string expression -> MUST flag CWE-78"""
        code = '''
from flask import request
import os
user_cmd = request.args.get("cmd")
method_name = "sys" + "tem"
func = getattr(os, method_name)
func(user_cmd)
'''
        res = execute_tcs_scan({"target.py": code})
        cwe78 = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78) >= 1, "Expected CWE-78 finding for constant folded getattr(os, 'sys' + 'tem')")

    def test_pattern3_dynamic_import_invocation(self):
        """Pattern 3: __import__ reflection to sink -> MUST flag CWE-78"""
        code = '''
from flask import request
user_cmd = request.args.get("cmd")
mod = __import__("os")
mod.system(user_cmd)
'''
        res = execute_tcs_scan({"target.py": code})
        cwe78 = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78) >= 1, "Expected CWE-78 finding for __import__('os').system")

    def test_pattern4_globals_dynamic_dispatch(self):
        """Pattern 4: globals() container dispatch -> MUST flag CWE-78"""
        code = '''
from flask import request
import subprocess
user_cmd = request.args.get("cmd")
runner = globals().get("subprocess")
runner.run(user_cmd, shell=True)
'''
        res = execute_tcs_scan({"target.py": code})
        cwe78 = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78) >= 1, "Expected CWE-78 finding for globals().get('subprocess')")

    def test_pattern5_safe_dynamic_attribute_negative_space(self):
        """Pattern 5: Safe dynamic attribute access -> MUST be 0 findings"""
        code = '''
import os
safe_fn = getattr(os.path, "join")
result = safe_fn("/safe/dir", "report.txt")
'''
        res = execute_tcs_scan({"target.py": code})
        cwe78 = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertEqual(len(cwe78), 0, f"Expected 0 CWE-78 findings for safe getattr(os.path, 'join'), got {len(cwe78)}")


if __name__ == "__main__":
    unittest.main()
