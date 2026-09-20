#!/usr/bin/env python3
"""
Phase 4 (v1.4.0) Baseline: Web Framework Sources, ORM Shield, and Low-Entropy Secrets.
Rule: Zero modifications to production scanner code during baseline capture.
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tcs_cli import execute_tcs_scan


class TestPhase4WebOrmBaseline(unittest.TestCase):

    def test_django_orm_safe_filter_negative_space(self):
        """Pattern 1: Django ORM parameterized filter -> Must be 0 CWE-89 findings"""
        code = '''
def get_user(request):
    username = request.GET.get("user")
    return User.objects.filter(username=username).first()
'''
        res = execute_tcs_scan({"target.py": code})
        cwe89 = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-89"]
        self.assertEqual(len(cwe89), 0, f"Expected 0 CWE-89 findings for Django ORM filter, got {len(cwe89)}")

    def test_sqlalchemy_safe_filter_negative_space(self):
        """Pattern 2: SQLAlchemy parameterized query -> Must be 0 CWE-89 findings"""
        code = '''
from flask import request
def search(session):
    name = request.args.get("name")
    return session.query(User).filter(User.username == name).all()
'''
        res = execute_tcs_scan({"target.py": code})
        cwe89 = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-89"]
        self.assertEqual(len(cwe89), 0, f"Expected 0 CWE-89 findings for SQLAlchemy filter, got {len(cwe89)}")

    def test_orm_raw_sql_positive_control(self):
        """Pattern 3: Raw SQL escape hatch (User.objects.raw) -> MUST flag CWE-89"""
        code = '''
def get_user(request):
    username = request.GET.get("user")
    return User.objects.raw(f"SELECT * FROM users WHERE name = '{username}'")
'''
        res = execute_tcs_scan({"target.py": code})
        cwe89 = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-89"]
        self.assertTrue(len(cwe89) >= 1, "Expected CWE-89 finding for unparameterized raw SQL query")

    def test_web_framework_sources_expansion(self):
        """Pattern 4: Flask request.form / request.json -> MUST flag CWE-78"""
        code = '''
from flask import request
import subprocess
cmd = request.form.get("command")
subprocess.run(cmd, shell=True)
'''
        res = execute_tcs_scan({"target.py": code})
        cwe78 = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78) >= 1, "Expected CWE-78 finding: request.form must be recognized as an untrusted SOURCE")

    def test_low_entropy_hardcoded_secret(self):
        """Pattern 5: Low-entropy hardcoded password -> MUST flag CWE-798"""
        code = '''
db_password = "admin123password"
api_secret = "my_super_secret_key"
'''
        res = execute_tcs_scan({"target.py": code}, secrets=True)
        cwe798 = [f for f in res.get("findings", []) if f.get("cwe") == "CWE-798"]
        self.assertTrue(len(cwe798) >= 1, "Expected CWE-798 finding for obvious hardcoded credential variable assignment")


if __name__ == "__main__":
    unittest.main()
