#!/usr/bin/env python3
"""
Comprehensive Negative Space Verification Suite
Asserts zero findings (100% false-positive rejection) across all 8 required safe patterns:
1. Safe SQL: Parameterized queries
2. Safe Subprocess: shell=False with static array args
3. Contained / Static Path: open() on static constant or guarded is_relative_to path
4. Eval of Constant: eval() on static string constant
5. Safe Pickle Absence: json.loads() instead of pickle
6. Safe YAML: yaml.load with SafeLoader
7. string.Template: standard library Template usage
8. Non-template Jinja: jinja2.escape utility without template rendering
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ast_scanner import TaintTracker

NEGATIVE_SPACE_CASES = {
    "1_safe_sql": '''import sqlite3
def get_user_safe(cursor, username):
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cursor.fetchone()
''',
    "2_safe_subprocess": '''import subprocess
def run_listing_safe(user_arg):
    # shell=False (default) with constant command array
    subprocess.run(["ls", "-l", "/tmp"])
''',
    "3_safe_path_contained": '''from pathlib import Path
def read_doc_safe(filename):
    base_dir = Path("/safe/dir").resolve()
    target = (base_dir / filename).resolve()
    if not target.is_relative_to(base_dir):
        raise ValueError("Traversal attack detected")
    with open(target, "r") as f:
        return f.read()
''',
    "4_safe_eval_constant": '''def compute_expression():
    CONSTANT_FORMULA = "10 * 20 + 5"
    return eval(CONSTANT_FORMULA)
''',
    "5_safe_pickle_absence": '''import json
def parse_payload_safe(raw_data):
    return json.loads(raw_data)
''',
    "6_safe_yaml_loader": '''import yaml
def load_config_safe(raw_yaml):
    return yaml.load(raw_yaml, Loader=yaml.SafeLoader)
''',
    "7_safe_string_template": '''from string import Template
def greet_safe(username):
    tmpl = Template("Hello, $name!")
    return tmpl.substitute(name=username)
''',
    "8_non_template_jinja": '''import jinja2
def escape_user_input(untrusted_html):
    return jinja2.escape(untrusted_html)
''',
}

def run_negative_space_suite():
    print("======================================================================")
    print("NEGATIVE SPACE VALIDATION MATRIX (8 SAFE PATTERNS)")
    print("======================================================================")
    total_cases = len(NEGATIVE_SPACE_CASES)
    passed_cases = 0
    total_unexpected_findings = 0

    results = {}
    for case_name, code in NEGATIVE_SPACE_CASES.items():
        tracker = TaintTracker({f"{case_name}.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()

        finding_count = len(edges)
        total_unexpected_findings += finding_count

        if finding_count == 0:
            passed_cases += 1
            status = "PASS (0 findings)"
        else:
            status = f"FAIL ({finding_count} unexpected findings: {[e.proof_graph.cwe for e in edges if e.proof_graph]})"

        results[case_name] = finding_count
        print(f"[{'PASS' if finding_count == 0 else 'FAIL'}] {case_name:<28} | Findings: {finding_count:<2} | Status: {status}")

    print("======================================================================")
    print(f"NEGATIVE SPACE SUMMARY: {passed_cases}/{total_cases} Passed (Total Unexpected Findings: {total_unexpected_findings})")
    print("======================================================================")
    return passed_cases == total_cases and total_unexpected_findings == 0

if __name__ == "__main__":
    success = run_negative_space_suite()
    sys.exit(0 if success else 1)
