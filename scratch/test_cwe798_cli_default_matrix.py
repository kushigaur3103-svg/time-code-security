#!/usr/bin/env python3
"""
Test Secret CLI Default Matrix
Asserts exact behavior for all 3 CLI invocations specified in CTO Directive:
1. tcs scan <fixture> --audit-all -> secret finding present
2. tcs scan <fixture> --audit-all --secrets -> secret finding present
3. tcs scan <fixture> --audit-all --no-secrets -> secret finding absent
"""

import sys
import json
import tempfile
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SECRET_FIXTURE_CODE = '''# Database configuration
DB_PASSWORD = "super_secret_password_123"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
'''

def test_case(name: str, cli_flags: list[str], expect_secret_present: bool):
    with tempfile.TemporaryDirectory() as tmpdir:
        sandbox = Path(tmpdir)
        target_file = sandbox / "config.py"
        target_file.write_text(SECRET_FIXTURE_CODE, encoding="utf-8")

        cmd = [sys.executable, "-m", "tcs_cli", "scan", str(sandbox), *cli_flags, "--format", "json"]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(PROJECT_ROOT))

        data = json.loads(proc.stdout)
        secret_findings = data.get("secret_findings", [])
        has_secret = len(secret_findings) > 0

        status = "PASS" if has_secret == expect_secret_present else "FAIL"
        print(f"[{status}] {name:<45} | Secret Present: {has_secret:<5} (Expected: {expect_secret_present}) | Count: {len(secret_findings)}")
        if has_secret:
            for sf in secret_findings:
                print(f"       Secret: {sf.get('secret_type')} on Line {sf.get('line_number')} ({sf.get('masked_value')})")

        return has_secret == expect_secret_present

def run_secret_cli_default_matrix():
    print("======================================================================")
    print("SECRET CLI DEFAULT MATRIX VERIFICATION")
    print("======================================================================")
    c1 = test_case("tcs scan <fixture> --audit-all", ["--audit-all"], True)
    c2 = test_case("tcs scan <fixture> --audit-all --secrets", ["--audit-all", "--secrets"], True)
    c3 = test_case("tcs scan <fixture> --audit-all --no-secrets", ["--audit-all", "--no-secrets"], False)
    print("======================================================================")
    all_passed = c1 and c2 and c3
    if all_passed:
        print("ALL SECRET CLI DEFAULT MATRIX CASES PASSED!")
    else:
        print("SOME SECRET CLI DEFAULT MATRIX CASES FAILED!")
    print("======================================================================")
    return all_passed

if __name__ == "__main__":
    success = run_secret_cli_default_matrix()
    sys.exit(0 if success else 1)
