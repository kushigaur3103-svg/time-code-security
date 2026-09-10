"""
PHASE 14D: TCS CONFIGURATION ENGINE TEST SUITE (.tcs.yml)
==========================================================
Tests:
1. No config -> existing defaults
2. Valid config
3. Malformed YAML
4. Non-mapping root
5. Unsupported version
6. Unknown top-level key
7. Unknown rule ID
8. enabled/disabled overlap
9. Disable one CWE
10. Enable subset
11. CLI override beats config
12. GLOBAL_RULE_REGISTRY unchanged (immutability)
13. Five repeated loads produce identical normalized config
14. Suppression enabled/disabled behavior
15. SARIF behavior under configuration
16. Explicit --config missing file
17. output.format validation
18. scan.sca precedence
19. scan.secrets precedence
20. absent config remains backward compatible
"""

import sys
import os
import tempfile
import subprocess
import json
from pathlib import Path

WORKSPACE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if WORKSPACE not in sys.path:
    sys.path.insert(0, WORKSPACE)

import rule_engine
from rule_engine import GLOBAL_RULE_REGISTRY
from config_loader import (
    parse_config,
    load_config,
    DEFAULT_CONFIG,
    ConfigValidationError,
    SUPPORTED_RULES,
    TCSConfig
)
from tcs_cli import execute_tcs_scan
from sarif_adapter import to_sarif

PYTHON_EXE = sys.executable
CLI_PATH = os.path.join(WORKSPACE, "tcs_cli.py")


def run_cli(*args, cwd=None):
    cmd = [PYTHON_EXE, CLI_PATH] + list(args)
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=cwd or WORKSPACE
    )
    return proc.returncode, proc.stdout, proc.stderr


def run_tests():
    print("=" * 80)
    print("TEST SUITE: PHASE 14D — TCS CONFIGURATION ENGINE (.tcs.yml)")
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

    # -------------------------------------------------------------------------
    # TEST 1: No config -> existing defaults
    # -------------------------------------------------------------------------
    print("\n--- Test 1: No config returns built-in defaults ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = load_config(base_dir=tmpdir)
        check(cfg == DEFAULT_CONFIG, "load_config without file returns DEFAULT_CONFIG")
        check(cfg.version == 1, "version equals 1")
        check(cfg.effective_rules == SUPPORTED_RULES, "effective_rules has all 6 rules")
        check(cfg.scan.sca is False, "scan.sca is False by default")
        check(cfg.scan.secrets is False, "scan.secrets is False by default")
        check(cfg.suppression.enabled is True, "suppression.enabled is True by default")
        check(cfg.output.format == "table", "output.format is 'table' by default")

    # -------------------------------------------------------------------------
    # TEST 2: Valid config
    # -------------------------------------------------------------------------
    print("\n--- Test 2: Valid configuration file ---")
    valid_yaml = """
version: 1

rules:
  enabled:
    - CWE-22
    - CWE-78
    - CWE-89
  disabled:
    - CWE-89

scan:
  sca: true
  secrets: false

suppression:
  enabled: true

output:
  format: json
"""
    # Wait, in valid_yaml above, CWE-89 is in both enabled and disabled which should error on contradiction!
    # Let's test proper non-overlapping valid yaml:
    valid_yaml_clean = """
version: 1

rules:
  enabled:
    - CWE-22
    - CWE-78
  disabled: []

scan:
  sca: true
  secrets: true

suppression:
  enabled: false

output:
  format: json
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir) / ".tcs.yml"
        p.write_text(valid_yaml_clean, encoding="utf-8")
        cfg = load_config(base_dir=tmpdir)
        check(cfg.version == 1, "Loaded version 1")
        check(cfg.effective_rules == {"CWE-22", "CWE-78"}, "effective_rules matches enabled subset")
        check(cfg.scan.sca is True, "scan.sca is True")
        check(cfg.scan.secrets is True, "scan.secrets is True")
        check(cfg.suppression.enabled is False, "suppression.enabled is False")
        check(cfg.output.format == "json", "output.format is json")

    # -------------------------------------------------------------------------
    # TEST 3: Malformed YAML
    # -------------------------------------------------------------------------
    print("\n--- Test 3: Malformed YAML ---")
    try:
        parse_config("version: 1\nrules: [unclosed list")
        check(False, "Should raise ConfigValidationError on malformed YAML")
    except ConfigValidationError as e:
        check("Malformed YAML" in str(e), "Caught expected malformed YAML error")

    # -------------------------------------------------------------------------
    # TEST 4: Non-mapping root
    # -------------------------------------------------------------------------
    print("\n--- Test 4: Non-mapping root ---")
    for bad_root in ["- item1\n- item2", "just a string", "42", ""]:
        try:
            parse_config(bad_root)
            check(False, f"Should raise on non-mapping root: {bad_root!r}")
        except ConfigValidationError as e:
            check("mapping/dictionary" in str(e), f"Caught expected non-mapping root error for {bad_root!r}")

    # -------------------------------------------------------------------------
    # TEST 5: Unsupported version
    # -------------------------------------------------------------------------
    print("\n--- Test 5: Unsupported version ---")
    for bad_ver in ["version: 2", "version: '1'", "rules: {}", "version: true"]:
        try:
            parse_config(bad_ver)
            check(False, f"Should raise on bad version: {bad_ver!r}")
        except ConfigValidationError as e:
            check("version" in str(e).lower(), f"Caught version error for {bad_ver!r}")

    # -------------------------------------------------------------------------
    # TEST 6: Unknown top-level key
    # -------------------------------------------------------------------------
    print("\n--- Test 6: Unknown top-level key ---")
    try:
        parse_config("version: 1\nunknown_section:\n  foo: bar")
        check(False, "Should raise on unknown top-level key")
    except ConfigValidationError as e:
        check("unknown_section" in str(e), "Caught unknown top-level key error")

    # -------------------------------------------------------------------------
    # TEST 7: Unknown rule ID
    # -------------------------------------------------------------------------
    print("\n--- Test 7: Unknown rule ID ---")
    try:
        parse_config("version: 1\nrules:\n  enabled:\n    - CWE-999")
        check(False, "Should raise on unknown rule identifier")
    except ConfigValidationError as e:
        check("CWE-999" in str(e), "Caught unknown rule identifier error")

    # -------------------------------------------------------------------------
    # TEST 8: enabled/disabled overlap
    # -------------------------------------------------------------------------
    print("\n--- Test 8: Contradictory overlap between enabled and disabled ---")
    try:
        parse_config("""
version: 1
rules:
  enabled: [CWE-22, CWE-78]
  disabled: [CWE-22]
""")
        check(False, "Should raise on enabled/disabled contradiction")
    except ConfigValidationError as e:
        check("Contradictory" in str(e) and "CWE-22" in str(e), "Caught contradictory rule error")

    # -------------------------------------------------------------------------
    # TEST 9: Disable one CWE
    # -------------------------------------------------------------------------
    print("\n--- Test 9: Disable one CWE ---")
    cfg9 = parse_config("""
version: 1
rules:
  enabled: []
  disabled:
    - CWE-22
""")
    check("CWE-22" not in cfg9.effective_rules, "CWE-22 excluded from effective_rules")
    check(len(cfg9.effective_rules) == 5, "5 rules remain active")

    sample_code = """from flask import request
import os
def vuln():
    file = request.args.get('file')
    cmd = request.args.get('cmd')
    open(file)
    os.system(cmd)
"""
    scan_res = execute_tcs_scan({"app.py": sample_code}, config=cfg9)
    cwes_found = [f["cwe"] for f in scan_res["findings"]]
    check("CWE-78" in cwes_found, "CWE-78 detected when enabled")
    check("CWE-22" not in cwes_found, "CWE-22 omitted when disabled in config")

    # -------------------------------------------------------------------------
    # TEST 10: Enable subset
    # -------------------------------------------------------------------------
    print("\n--- Test 10: Enable subset ---")
    cfg10 = parse_config("""
version: 1
rules:
  enabled:
    - CWE-22
  disabled: []
""")
    check(cfg10.effective_rules == {"CWE-22"}, "Only CWE-22 in effective_rules")
    scan_res10 = execute_tcs_scan({"app.py": sample_code}, config=cfg10)
    cwes_found10 = [f["cwe"] for f in scan_res10["findings"]]
    check("CWE-22" in cwes_found10, "CWE-22 detected when in enabled subset")
    check("CWE-78" not in cwes_found10, "CWE-78 omitted when not in enabled subset")

    # -------------------------------------------------------------------------
    # TEST 11: CLI override beats config
    # -------------------------------------------------------------------------
    print("\n--- Test 11: CLI override beats config ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_file = Path(tmpdir) / ".tcs.yml"
        cfg_file.write_text("""
version: 1
scan:
  sca: false
  secrets: false
output:
  format: table
""", encoding="utf-8")

        test_file = Path(tmpdir) / "app.py"
        test_file.write_text("x = 1\n", encoding="utf-8")

        # Config has table, CLI specifies --format json
        code, stdout, stderr = run_cli(str(test_file), "--config", str(cfg_file), "--format", "json")
        check(code == 0, f"CLI exit 0 (got {code})")
        parsed_out = json.loads(stdout)
        check(parsed_out.get("status") == "success", "CLI flag --format json overrides config table format")

    # -------------------------------------------------------------------------
    # TEST 12: GLOBAL_RULE_REGISTRY unchanged
    # -------------------------------------------------------------------------
    print("\n--- Test 12: GLOBAL_RULE_REGISTRY immutability ---")
    initial_rules = [r.cwe_id for r in GLOBAL_RULE_REGISTRY.all_rules()]
    check(len(initial_rules) == 6, "Initial registry has 6 rules")

    # Perform multiple configs and scans with disabled rules
    cfg_dis = parse_config("version: 1\nrules:\n  disabled:\n    - CWE-22\n    - CWE-78\n    - CWE-89\n    - CWE-95\n    - CWE-502")
    execute_tcs_scan({"app.py": sample_code}, config=cfg_dis)

    post_rules = [r.cwe_id for r in GLOBAL_RULE_REGISTRY.all_rules()]
    check(post_rules == initial_rules, "GLOBAL_RULE_REGISTRY rules list is byte-for-byte identical post-scan")
    for rid in SUPPORTED_RULES:
        check(GLOBAL_RULE_REGISTRY.get_rule(rid) is not None, f"Registry still holds rule {rid}")

    # -------------------------------------------------------------------------
    # TEST 13: Five repeated loads produce identical normalized config
    # -------------------------------------------------------------------------
    print("\n--- Test 13: 5 repeated loads produce identical config ---")
    loads = [parse_config(valid_yaml_clean) for _ in range(5)]
    for i in range(1, 5):
        check(loads[0] == loads[i], f"Iteration {i} identical to baseline")
        check(loads[0].effective_rules == loads[i].effective_rules, f"Iteration {i} effective_rules identical")

    # -------------------------------------------------------------------------
    # TEST 14: Suppression enabled/disabled behavior
    # -------------------------------------------------------------------------
    print("\n--- Test 14: Suppression enabled/disabled behavior ---")
    suppressed_code = """from flask import request
def handler():
    data = request.args.get('data')
    eval(data)  # tcs:ignore CWE-95: approved safe
"""
    cfg_supp_on = parse_config("version: 1\nsuppression:\n  enabled: true")
    res_on = execute_tcs_scan({"app.py": suppressed_code}, config=cfg_supp_on)
    f_on = res_on["findings"][0]
    check(f_on["suppressed"] is True, "Finding suppressed when suppression.enabled=true")
    check(f_on["active"] is False, "Finding active=False when suppressed")

    cfg_supp_off = parse_config("version: 1\nsuppression:\n  enabled: false")
    res_off = execute_tcs_scan({"app.py": suppressed_code}, config=cfg_supp_off)
    f_off = res_off["findings"][0]
    check(f_off["suppressed"] is False, "Finding NOT suppressed when suppression.enabled=false")
    check(f_off["active"] is True, "Finding active=True when suppression.enabled=false")

    # -------------------------------------------------------------------------
    # TEST 15: SARIF behavior under configuration
    # -------------------------------------------------------------------------
    print("\n--- Test 15: SARIF behavior under configuration ---")
    # Case A: Disabled rule excluded from driver.rules
    sarif_disabled = to_sarif(scan_res, enabled_rule_ids=cfg9.effective_rules)
    driver_rule_ids = [r["id"] for r in sarif_disabled["runs"][0]["tool"]["driver"]["rules"]]
    check("CWE-22" not in driver_rule_ids, "CWE-22 excluded from SARIF driver.rules when disabled")
    check(len(driver_rule_ids) == 5, "SARIF driver.rules has 5 rules")

    # Case B: Absent configuration retains all 6 rules
    scan_default = execute_tcs_scan({"app.py": sample_code})
    sarif_default = to_sarif(scan_default)
    default_rule_ids = [r["id"] for r in sarif_default["runs"][0]["tool"]["driver"]["rules"]]
    check(len(default_rule_ids) == 6, "SARIF driver.rules has all 6 rules when config absent")
    check("CWE-22" in default_rule_ids, "CWE-22 present in default SARIF driver.rules")

    # -------------------------------------------------------------------------
    # TEST 16: Explicit --config missing file
    # -------------------------------------------------------------------------
    print("\n--- Test 16: Missing file for explicit --config ---")
    try:
        load_config("/non/existent/path/.tcs.yml")
        check(False, "Should raise on missing config file")
    except ConfigValidationError as e:
        check("Configuration file not found" in str(e), "Caught missing file ConfigValidationError")

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "app.py"
        test_file.write_text("x = 1\n", encoding="utf-8")
        code, stdout, stderr = run_cli(str(test_file), "--config", "/non/existent/path/.tcs.yml")
        check(code == 2, f"CLI exits with code 2 on missing config file (got {code})")
        check("Configuration file not found" in stderr, "CLI prints error message for missing config file")

    # -------------------------------------------------------------------------
    # TEST 17: output.format validation
    # -------------------------------------------------------------------------
    print("\n--- Test 17: output.format validation ---")
    for bad_fmt in ["xml", "csv", "yaml", 123]:
        try:
            parse_config(f"version: 1\noutput:\n  format: {bad_fmt}")
            check(False, f"Should raise on bad output.format: {bad_fmt}")
        except ConfigValidationError as e:
            check("output.format" in str(e).lower(), f"Caught output.format validation error for {bad_fmt}")

    # -------------------------------------------------------------------------
    # TEST 18: scan.sca precedence
    # -------------------------------------------------------------------------
    print("\n--- Test 18: scan.sca precedence ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "app.py"
        test_file.write_text("x = 1\n", encoding="utf-8")

        # Config has sca: true -> CLI without flag enables SCA
        cfg_sca_true = Path(tmpdir) / ".tcs.yml"
        cfg_sca_true.write_text("version: 1\nscan:\n  sca: true\n", encoding="utf-8")
        code, stdout, stderr = run_cli(str(test_file), "--config", str(cfg_sca_true), "--format", "json")
        check("sca_vulnerabilities" in json.loads(stdout)["summary"], "config scan.sca: true activates SCA")

        # CLI explicit --no-sca overrides config
        code, stdout, stderr = run_cli(str(test_file), "--config", str(cfg_sca_true), "--no-sca", "--format", "json")
        check("sca_vulnerabilities" not in json.loads(stdout)["summary"], "CLI --no-sca overrides config scan.sca: true")

    # -------------------------------------------------------------------------
    # TEST 19: scan.secrets precedence
    # -------------------------------------------------------------------------
    print("\n--- Test 19: scan.secrets precedence ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "app.py"
        test_file.write_text("x = 1\n", encoding="utf-8")

        # Config has secrets: true -> CLI without flag enables secrets
        cfg_sec_true = Path(tmpdir) / ".tcs.yml"
        cfg_sec_true.write_text("version: 1\nscan:\n  secrets: true\n", encoding="utf-8")
        code, stdout, stderr = run_cli(str(test_file), "--config", str(cfg_sec_true), "--format", "json")
        check("secrets_scanned" in json.loads(stdout)["summary"], "config scan.secrets: true activates secret scanning")

        # CLI explicit --no-secrets overrides config
        code, stdout, stderr = run_cli(str(test_file), "--config", str(cfg_sec_true), "--no-secrets", "--format", "json")
        check("secrets_scanned" not in json.loads(stdout)["summary"], "CLI --no-secrets overrides config scan.secrets: true")

    # -------------------------------------------------------------------------
    # TEST 20: absent config remains backward compatible
    # -------------------------------------------------------------------------
    print("\n--- Test 20: Absent config remains 100% backward compatible ---")
    multi_vuln_code = """from flask import request
import os
import pickle

def test():
    f = request.args.get('f')
    c = request.args.get('c')
    p = request.args.get('p')
    open(f)
    os.system(c)
    pickle.loads(p)
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        f = Path(tmpdir) / "vuln.py"
        f.write_text(multi_vuln_code, encoding="utf-8")

        # Run A: Without any config file
        code_a, stdout_a, stderr_a = run_cli(str(f), "--format", "json")
        data_a = json.loads(stdout_a)

        # Run B: With an explicit default-equivalent config file
        default_cfg = Path(tmpdir) / "default.yml"
        default_cfg.write_text("""
version: 1
rules:
  enabled: []
  disabled: []
scan:
  sca: false
  secrets: false
suppression:
  enabled: true
output:
  format: json
""", encoding="utf-8")
        code_b, stdout_b, stderr_b = run_cli(str(f), "--config", str(default_cfg))
        data_b = json.loads(stdout_b)

        check(code_a == code_b, f"Exit codes match ({code_a} == {code_b})")
        check(data_a["summary"] == data_b["summary"], "Risk summaries match 100%")
        check(len(data_a["findings"]) == len(data_b["findings"]), "Findings count matches")
        for i in range(len(data_a["findings"])):
            check(data_a["findings"][i]["cwe"] == data_b["findings"][i]["cwe"], f"Finding {i} CWE matches")
            check(data_a["findings"][i]["severity"] == data_b["findings"][i]["severity"], f"Finding {i} severity matches")
            check(data_a["findings"][i]["confidence"] == data_b["findings"][i]["confidence"], f"Finding {i} confidence matches")

    print("\n" + "=" * 80)
    print(f"PHASE 14D TEST SUMMARY: {passed_checks}/{total_checks} CHECKS PASSED")
    print("=" * 80)
    return passed_checks == total_checks


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
