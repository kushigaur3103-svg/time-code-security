"""
CTO FINAL COMPATIBILITY GATE AUDIT
==================================
Verifies CLI backward compatibility and precedence rules:
1. python tcs_cli.py <target>
2. python tcs_cli.py <target> --sca
3. python tcs_cli.py <target> --secrets
4. python tcs_cli.py <target> --format json
5. python tcs_cli.py <target> --format sarif

Scenarios A through I:
A. no .tcs.yml + no explicit CLI options == historical default behavior
B. .tcs.yml absent + --sca == historical --sca behavior
C. .tcs.yml absent + --secrets == historical --secrets behavior
D. config.scan.sca true + CLI omission -> true
E. config.scan.sca true + --no-sca -> false
F. config.scan.secrets true + CLI omission -> true
G. config.scan.secrets true + --no-secrets -> false
H. config.output.format json + CLI omission -> json
I. config.output.format json + --format table -> table
"""

import sys
import os
import tempfile
import subprocess
import json
from pathlib import Path

WORKSPACE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI_PATH = os.path.join(WORKSPACE, "tcs_cli.py")
PYTHON_EXE = sys.executable

SAMPLE_CODE = """from flask import request
import os

def handler():
    f = request.args.get('file')
    c = request.args.get('cmd')
    open(f)
    os.system(c)
"""

SAMPLE_MANIFEST = """flask==2.0.1
requests==2.25.0
"""

SAMPLE_SECRET = """API_KEY = "AKIAIOSFODNN7EXAMPLE"
"""


def run_cli_cmd(*args, cwd=None):
    cmd = [PYTHON_EXE, CLI_PATH] + list(args)
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=cwd or WORKSPACE
    )
    return proc.returncode, proc.stdout, proc.stderr


def run_audit():
    print("=" * 85)
    print("PHASE 14D FINAL CTO COMPATIBILITY GATE AUDIT")
    print("=" * 85)

    checks = []

    def record(name, passed, detail=""):
        checks.append((name, passed, detail))
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{status} {name}: {detail}")
        if not passed:
            raise AssertionError(f"Check failed: {name} - {detail}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        target_py = tmppath / "app.py"
        target_py.write_text(SAMPLE_CODE, encoding="utf-8")

        manifest_file = tmppath / "requirements.txt"
        manifest_file.write_text(SAMPLE_MANIFEST, encoding="utf-8")

        secret_file = tmppath / "secrets.env"
        secret_file.write_text(SAMPLE_SECRET, encoding="utf-8")

        # ---------------------------------------------------------------------
        # 1. Invocations 1-5 with no .tcs.yml (Historical Compatibility)
        # ---------------------------------------------------------------------
        print("\n--- Part 1: Core Invocations 1-5 (No .tcs.yml) ---")

        # Invocation 1: python tcs_cli.py <target> (table output)
        code1, out1, err1 = run_cli_cmd(str(target_py))
        record("1. python tcs_cli.py <target>", code1 == 1, f"Exit code {code1}, finds CWE-22 and CWE-78 in table")
        record("1. table format", "TimeCodeSecurity (TCS)" in out1, "Table header found in stdout")
        record("1. stderr summary", "[TCS CLI] Scanned 1 files" in err1, "Summary written to stderr")

        # Invocation 2: python tcs_cli.py <target> --sca (offline mode via cache or empty cache)
        code2, out2, err2 = run_cli_cmd(str(tmppath), "--sca", "--sca-offline")
        record("2. python tcs_cli.py <target> --sca", code2 == 1, f"Exit code {code2}, SCA executed")
        record("2. sca summary", "manifests" in err2 or "SCA" in err2, "SCA reflected in summary")

        # Invocation 3: python tcs_cli.py <target> --secrets
        code3, out3, err3 = run_cli_cmd(str(tmppath), "--secrets")
        record("3. python tcs_cli.py <target> --secrets", code3 == 1, f"Exit code {code3}, secrets detected")
        record("3. secrets finding", "CWE-798" in out3 or "Hardcoded" in out3, "CWE-798 present in output")

        # Invocation 4: python tcs_cli.py <target> --format json
        code4, out4, err4 = run_cli_cmd(str(target_py), "--format", "json")
        data4 = json.loads(out4)
        record("4. python tcs_cli.py <target> --format json", code4 == 1 and data4["status"] == "success", "Valid JSON payload returned")
        record("4. findings count", len(data4["findings"]) == 2, f"Found {len(data4['findings'])} findings")
        record("4. CWEs matched", {f["cwe"] for f in data4["findings"]} == {"CWE-22", "CWE-78"}, "Matched CWE-22 and CWE-78")

        # Invocation 5: python tcs_cli.py <target> --format sarif
        code5, out5, err5 = run_cli_cmd(str(target_py), "--format", "sarif")
        sarif5 = json.loads(out5)
        record("5. python tcs_cli.py <target> --format sarif", code5 == 1 and sarif5["version"] == "2.1.0", "Valid SARIF v2.1.0 payload returned")
        record("5. driver rules count", len(sarif5["runs"][0]["tool"]["driver"]["rules"]) == 6, "All 6 driver rules present")

        # ---------------------------------------------------------------------
        # 2. Scenarios A through I
        # ---------------------------------------------------------------------
        print("\n--- Part 2: Explicit Verification Scenarios A through I ---")

        # Scenario A: no .tcs.yml + no explicit CLI options == historical default behavior
        code_a, out_a, err_a = run_cli_cmd(str(target_py))
        record("A. no .tcs.yml + no explicit options", code_a == 1 and "CWE-22" in out_a and "CWE-78" in out_a, "Produces standard table with all active CWEs")

        # Scenario B: .tcs.yml absent + --sca == historical --sca behavior
        code_b, out_b, err_b = run_cli_cmd(str(tmppath), "--sca", "--sca-offline", "--format", "json")
        data_b = json.loads(out_b)
        record("B. .tcs.yml absent + --sca", "sca_findings" in data_b, "SCA findings key populated in JSON")

        # Scenario C: .tcs.yml absent + --secrets == historical --secrets behavior
        code_c, out_c, err_c = run_cli_cmd(str(tmppath), "--secrets", "--format", "json")
        data_c = json.loads(out_c)
        record("C. .tcs.yml absent + --secrets", "secret_findings" in data_c, "Secret findings key populated in JSON")

        # Scenario D: config.scan.sca true + CLI omission -> true
        cfg_d = tmppath / "config_d.yml"
        cfg_d.write_text("version: 1\nscan:\n  sca: true\n", encoding="utf-8")
        code_d, out_d, err_d = run_cli_cmd(str(tmppath), "--config", str(cfg_d), "--sca-offline", "--format", "json")
        data_d = json.loads(out_d)
        record("D. config.scan.sca true + CLI omission", "sca_findings" in data_d, "SCA enabled from config without CLI flag")

        # Scenario E: config.scan.sca true + --no-sca -> false
        code_e, out_e, err_e = run_cli_cmd(str(tmppath), "--config", str(cfg_d), "--no-sca", "--format", "json")
        data_e = json.loads(out_e)
        record("E. config.scan.sca true + --no-sca", "sca_findings" not in data_e, "CLI --no-sca successfully disabled SCA")

        # Scenario F: config.scan.secrets true + CLI omission -> true
        cfg_f = tmppath / "config_f.yml"
        cfg_f.write_text("version: 1\nscan:\n  secrets: true\n", encoding="utf-8")
        code_f, out_f, err_f = run_cli_cmd(str(tmppath), "--config", str(cfg_f), "--format", "json")
        data_f = json.loads(out_f)
        record("F. config.scan.secrets true + CLI omission", "secret_findings" in data_f, "Secrets enabled from config without CLI flag")

        # Scenario G: config.scan.secrets true + --no-secrets -> false
        code_g, out_g, err_g = run_cli_cmd(str(tmppath), "--config", str(cfg_f), "--no-secrets", "--format", "json")
        data_g = json.loads(out_g)
        record("G. config.scan.secrets true + --no-secrets", "secret_findings" not in data_g, "CLI --no-secrets successfully disabled Secrets")

        # Scenario H: config.output.format json + CLI omission -> json
        cfg_h = tmppath / "config_h.yml"
        cfg_h.write_text("version: 1\noutput:\n  format: json\n", encoding="utf-8")
        code_h, out_h, err_h = run_cli_cmd(str(target_py), "--config", str(cfg_h))
        try:
            parsed_h = json.loads(out_h)
            record("H. config.output.format json + CLI omission", parsed_h.get("status") == "success", "Output formatted as JSON by config default")
        except Exception as ex:
            record("H. config.output.format json + CLI omission", False, f"JSON parse error: {ex}")

        # Scenario I: config.output.format json + --format table -> table
        code_i, out_i, err_i = run_cli_cmd(str(target_py), "--config", str(cfg_h), "--format", "table")
        record("I. config.output.format json + --format table", "TimeCodeSecurity (TCS)" in out_i, "CLI --format table overrode config json")

    all_passed = all(c[1] for c in checks)
    print("\n" + "=" * 85)
    print(f"COMPATIBILITY AUDIT RESULT: {sum(1 for c in checks if c[1])}/{len(checks)} CHECKS PASSED")
    print("=" * 85)
    return all_passed


if __name__ == "__main__":
    success = run_audit()
    sys.exit(0 if success else 1)
