#!/usr/bin/env python3
"""
Phase 5 (v1.5.0) Baseline: Cross-File & Inter-Procedural Taint Tracking.
Governing Invariant: Zero modifications to production code during baseline creation.
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tcs_cli import execute_tcs_scan


class TestPhase5CrossFileBaseline(unittest.TestCase):

    def test_pattern1_direct_cross_file_source_to_sink(self):
        """Pattern 1: Direct 1-hop module call (app.py -> utils.py) -> MUST flag CWE-78"""
        files = {
            "utils.py": """import subprocess
def execute_system_cmd(cmd):
    subprocess.run(cmd, shell=True)
""",
            "app.py": """from flask import request
import utils
def handler():
    user_cmd = request.args.get("c")
    utils.execute_system_cmd(user_cmd)
"""
        }
        res = execute_tcs_scan(files)
        cwe78 = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78) >= 1, "Expected CWE-78 finding for direct cross-file call")
        self.assertEqual(cwe78[0].get("severity"), "CRITICAL")

    def test_pattern2_callee_return_value_taint(self):
        """Pattern 2: Callee returns tainted input to caller sink -> MUST flag CWE-78"""
        files = {
            "helpers.py": """def get_user_input(req):
    return req.args.get("data")
""",
            "app.py": """from flask import request
import helpers, subprocess
def run():
    cmd = helpers.get_user_input(request)
    subprocess.run(cmd, shell=True)
"""
        }
        res = execute_tcs_scan(files)
        cwe78 = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78) >= 1, "Expected CWE-78 finding when callee returns tainted input")

    def test_pattern3_multi_hop_module_chain(self):
        """Pattern 3: Multi-hop forwarding chain (app.py -> b.py -> c.py) -> MUST flag CWE-78"""
        files = {
            "c.py": """import subprocess
def sink(cmd):
    subprocess.run(cmd, shell=True)
""",
            "b.py": """import c
def forward(data):
    c.sink(data)
""",
            "a.py": """from flask import request
import b
def handler():
    user_cmd = request.args.get("cmd")
    b.forward(user_cmd)
"""
        }
        res = execute_tcs_scan(files)
        cwe78 = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78) >= 1, "Expected CWE-78 finding across multi-hop module chain (A -> B -> C)")

    def test_pattern4_reexported_facade_alias(self):
        """Pattern 4: Re-exported / aliased import facade -> MUST flag CWE-78"""
        files = {
            "internal.py": """import subprocess
def real_exec(cmd):
    subprocess.run(cmd, shell=True)
""",
            "facade.py": """from internal import real_exec as exported_exec
""",
            "app.py": """from flask import request
from facade import exported_exec
def handler():
    user_cmd = request.args.get("c")
    exported_exec(user_cmd)
"""
        }
        res = execute_tcs_scan(files)
        cwe78 = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78) >= 1, "Expected CWE-78 finding when sink is called via re-exported facade")

    def test_pattern5_cross_file_sanitizer_negative_space(self):
        """Pattern 5: Cross-file vector-aware sanitizer -> MUST be 0 findings"""
        files = {
            "utils.py": """import subprocess, shlex
def execute_system_cmd(cmd):
    safe_cmd = shlex.quote(cmd)
    subprocess.run(safe_cmd, shell=True)
""",
            "app.py": """from flask import request
import utils
def handler():
    user_cmd = request.args.get("c")
    utils.execute_system_cmd(user_cmd)
"""
        }
        res = execute_tcs_scan(files)
        cwe78 = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertEqual(len(cwe78), 0, f"Expected 0 CWE-78 findings when cross-file sanitizer is present, got {len(cwe78)}")


if __name__ == "__main__":
    unittest.main()
