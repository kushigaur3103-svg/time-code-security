#!/usr/bin/env python3
import sys, unittest
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from tcs_cli import execute_tcs_scan

class TestPhase3SanitizersBaseline(unittest.TestCase):

    def test_cwe78_shlex_quote(self):
        """Pattern 1: CWE-78 Sanitizer via shlex.quote -> 0 CWE-78"""
        code = '''from flask import request
import subprocess, shlex
cmd = shlex.quote(request.args.get("cmd"))
subprocess.run(f"echo {cmd}", shell=True)
'''
        res = execute_tcs_scan({"target.py": code})
        findings = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertEqual(len(findings), 0, f"Expected 0 CWE-78 findings for shlex.quote, got {len(findings)}")

    def test_cwe22_path_basename(self):
        """Pattern 2: CWE-22 Sanitizer via os.path.basename -> 0 CWE-22"""
        code = '''from flask import request
import os
filename = os.path.basename(request.args.get("path"))
with open(f"/var/data/{filename}") as f:
    f.read()
'''
        res = execute_tcs_scan({"target.py": code})
        findings = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-22"]
        self.assertEqual(len(findings), 0, f"Expected 0 CWE-22 findings for os.path.basename, got {len(findings)}")

    def test_cwe89_numeric_typecast(self):
        """Pattern 3: CWE-89 Sanitizer via int() typecast -> 0 CWE-89"""
        code = '''from flask import request
import sqlite3
user_id = int(request.args.get("id"))
conn = sqlite3.connect("db.sqlite")
cur = conn.cursor()
cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        res = execute_tcs_scan({"target.py": code})
        findings = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-89"]
        self.assertEqual(len(findings), 0, f"Expected 0 CWE-89 findings for int(), got {len(findings)}")

    def test_cwe78_numeric_typecast(self):
        """Pattern 4: CWE-78 Sanitizer via int() count -> 0 CWE-78"""
        code = '''from flask import request
import subprocess
count = int(request.args.get("count"))
subprocess.run(f"ping -c {count} 127.0.0.1", shell=True)
'''
        res = execute_tcs_scan({"target.py": code})
        findings = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertEqual(len(findings), 0, f"Expected 0 CWE-78 findings for int(), got {len(findings)}")

    def test_irrelevant_sanitizer_negative_control(self):
        """Pattern 5: Contextual Negative Control - html.escape does NOT protect CWE-78 -> MUST FLAG"""
        code = '''from flask import request
import subprocess, html
cmd = html.escape(request.args.get("cmd"))
subprocess.run(f"echo {cmd}", shell=True)
'''
        res = execute_tcs_scan({"target.py": code})
        findings = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(findings) >= 1, "Expected CWE-78 finding: html.escape does not sanitize command injection")

if __name__ == "__main__":
    unittest.main()
