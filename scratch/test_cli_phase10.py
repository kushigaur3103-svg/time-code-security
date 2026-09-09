import sys
import os
import subprocess
import json
import tempfile
from pathlib import Path

PYTHON_EXE = sys.executable
CLI_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tcs_cli.py"))

def run_cli(*args):
    cmd = [PYTHON_EXE, CLI_PATH] + list(args)
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8"
    )
    return proc.returncode, proc.stdout, proc.stderr

def test_cli_phase10():
    print("=" * 80)
    print("TEST SUITE: PHASE 10 STEP 2 — PRODUCTION CI/CD CLI HARDENING")
    print("=" * 80)

    total_checks = 0
    passed_checks = 0

    def check(condition, desc):
        nonlocal total_checks, passed_checks
        total_checks += 1
        if condition:
            passed_checks += 1
            print(f"[PASS] {desc}")
        else:
            print(f"[FAIL] {desc}")
            raise AssertionError(f"Check failed: {desc}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)

        # File 1: Clean file
        clean_file = tmppath / "clean_sample.py"
        clean_file.write_text("""
def calculate(a, b):
    return a + b
""", encoding="utf-8")

        # File 2: Vulnerable file
        vuln_file = tmppath / "vuln_sample.py"
        vuln_file.write_text("""from flask import request

def handler():
    data = request.args.get("data")
    eval(data)
""", encoding="utf-8")

        # File 3: Suppressed file
        suppressed_file = tmppath / "suppressed_sample.py"
        suppressed_file.write_text("""from flask import request

def handler():
    data = request.args.get("data")
    eval(data)  # tcs:ignore CWE-95: validated safe by internal filter
""", encoding="utf-8")

        # File 4: Syntax error file
        syntax_err_file = tmppath / "syntax_err_sample.py"
        syntax_err_file.write_text("""def bad_func(
""", encoding="utf-8")

        # ----------------------------------------------------------------------
        # TEST 1: Exit code 0 on completely clean Python file
        # ----------------------------------------------------------------------
        print("\n--- Test 1: Clean file exit code 0 ---")
        code, stdout, stderr = run_cli(str(clean_file))
        check(code == 0, f"Clean file produces exit code 0 (got {code})")
        check("No security vulnerabilities detected" in stdout, "Table output declares no vulnerabilities detected")

        # ----------------------------------------------------------------------
        # TEST 2: Exit code 1 on vulnerable sample
        # ----------------------------------------------------------------------
        print("\n--- Test 2: Vulnerable sample exit code 1 ---")
        code, stdout, stderr = run_cli(str(vuln_file))
        check(code == 1, f"Vulnerable file produces exit code 1 (got {code})")
        check("CWE-95" in stdout, "Table output includes detected CWE-95")
        check("ACTIVE" in stdout, "Table output lists finding as ACTIVE")

        # ----------------------------------------------------------------------
        # TEST 3: Exit code 1 on suppressed file when --exclude-suppressed is NOT passed
        # ----------------------------------------------------------------------
        print("\n--- Test 3: Suppressed file without --exclude-suppressed produces exit code 1 ---")
        code, stdout, stderr = run_cli(str(suppressed_file))
        check(code == 1, f"Suppressed file without --exclude-suppressed produces exit code 1 (got {code})")
        check("SUPPRESSED" in stdout, "Table output indicates finding is SUPPRESSED")

        # ----------------------------------------------------------------------
        # TEST 4: Exit code 0 on suppressed file when --exclude-suppressed IS passed
        # ----------------------------------------------------------------------
        print("\n--- Test 4: Suppressed file WITH --exclude-suppressed produces exit code 0 ---")
        code, stdout, stderr = run_cli(str(suppressed_file), "--exclude-suppressed")
        check(code == 0, f"Suppressed file WITH --exclude-suppressed produces exit code 0 (got {code})")
        check("No security vulnerabilities detected" in stdout, "Table output shows no vulnerabilities displayed")

        # ----------------------------------------------------------------------
        # TEST 5: Exit code 2 on non-existent file or bad arguments
        # ----------------------------------------------------------------------
        print("\n--- Test 5: Bad arguments / missing target produces exit code 2 ---")
        # 5a: Non-existent file
        code, stdout, stderr = run_cli(str(tmppath / "non_existent_file.py"))
        check(code == 2, f"Non-existent target produces exit code 2 (got {code})")
        check("Target path does not exist" in stderr, "stderr mentions path does not exist")

        # 5b: Invalid argument / flag
        code, stdout, stderr = run_cli(str(clean_file), "--non-existent-flag")
        check(code == 2, f"Invalid flag produces exit code 2 (got {code})")

        # 5c: Invalid format choice
        code, stdout, stderr = run_cli(str(clean_file), "--format", "invalid_fmt")
        check(code == 2, f"Invalid format option produces exit code 2 (got {code})")

        # 5d: Syntax error file
        code, stdout, stderr = run_cli(str(syntax_err_file))
        check(code == 2, f"Syntax error in target produces exit code 2 (got {code})")
        check("Syntax error" in stderr, "stderr reports syntax error")

        # ----------------------------------------------------------------------
        # TEST 6: Validation of --format json
        # ----------------------------------------------------------------------
        print("\n--- Test 6: --format json validation ---")
        code, stdout, stderr = run_cli(str(vuln_file), "--format", "json")
        check(code == 1, f"--format json on vulnerable file returns exit code 1 (got {code})")
        parsed_json = json.loads(stdout)
        check("findings" in parsed_json, "JSON output contains 'findings' key")
        check("summary" in parsed_json, "JSON output contains 'summary' key")
        check(len(parsed_json["findings"]) == 1, "JSON findings array has exactly 1 finding")
        check(parsed_json["findings"][0]["cwe"] == "CWE-95", "Finding CWE is CWE-95")

        # ----------------------------------------------------------------------
        # TEST 7: Validation of --format sarif with dynamic rule metadata
        # ----------------------------------------------------------------------
        print("\n--- Test 7: --format sarif validation ---")
        code, stdout, stderr = run_cli(str(vuln_file), "--format", "sarif")
        check(code == 1, f"--format sarif on vulnerable file returns exit code 1 (got {code})")
        parsed_sarif = json.loads(stdout)
        check(parsed_sarif.get("version") == "2.1.0", "SARIF version is '2.1.0'")
        check("$schema" in parsed_sarif, "SARIF $schema header present")
        run = parsed_sarif["runs"][0]
        check(run["tool"]["driver"]["name"] == "TimeCodeSecurity", "Driver name is 'TimeCodeSecurity'")
        rules = run["tool"]["driver"]["rules"]
        check(len(rules) == 6, f"Driver contains all 6 rules from Rule Engine (got {len(rules)})")
        check(len(run["results"]) == 1, "SARIF results contains exactly 1 result")
        check(run["results"][0]["ruleId"] == "CWE-95", "Result ruleId is CWE-95")

        # ----------------------------------------------------------------------
        # TEST 8: Validation of --output writing to file cleanly (stdout silenced)
        # ----------------------------------------------------------------------
        print("\n--- Test 8: --output writing to file cleanly (stdout silenced) ---")
        output_file = tmppath / "export_report.sarif"
        code, stdout, stderr = run_cli(str(vuln_file), "--format", "sarif", "-o", str(output_file))
        check(code == 1, f"Exit code preserved with -o (got {code})")
        check(stdout.strip() == "", f"stdout is completely silenced when --output is provided (got {len(stdout)} chars)")
        check(output_file.exists(), "Output file was created")
        file_content = output_file.read_text(encoding="utf-8")
        file_sarif = json.loads(file_content)
        check(file_sarif.get("version") == "2.1.0", "Output file contains valid UTF-8 SARIF")
        check(len(file_sarif["runs"][0]["results"]) == 1, "Output file preserves scan result")

        # Also test --output with table format
        table_output_file = tmppath / "export_report.txt"
        code, stdout, stderr = run_cli(str(vuln_file), "--format", "table", "--output", str(table_output_file))
        check(stdout.strip() == "", "stdout silenced for table output to file")
        check(table_output_file.exists(), "Table output file was created")
        table_content = table_output_file.read_text(encoding="utf-8")
        check("TimeCodeSecurity (TCS) AST Security Scan Report" in table_content, "Table text file is human readable")

    print("\n" + "=" * 80)
    print(f"ALL PHASE 10 STEP 2 CLI TESTS PASSED ({passed_checks}/{total_checks})")
    print("=" * 80)

if __name__ == "__main__":
    test_cli_phase10()
