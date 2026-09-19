#!/usr/bin/env python3
"""
Test SSTI Import-Aware Matrix
Asserts exact behavior for all 6 cases required by CTO Directive:
1. from jinja2 import Template -> Template(user_input) -> FLAGGED CWE-1336
2. import jinja2 -> jinja2.Template(user_input) -> FLAGGED CWE-1336
3. import jinja2 as j -> j.Template(user_input) -> FLAGGED CWE-1336
4. from jinja2 import Template as JinjaTemplate -> JinjaTemplate(user_input) -> FLAGGED CWE-1336
5. from string import Template -> Template(user_input) -> SAFE (0 findings)
6. Shadowed/local Template binding -> SAFE (0 findings)
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ast_scanner import TaintTracker, ProofNodeType

CASES = {
    "case_1_from_jinja2_import_Template": (
        '''from jinja2 import Template
def render(user_input):
    return Template(user_input)
''',
        True  # should be flagged
    ),
    "case_2_import_jinja2": (
        '''import jinja2
def render(user_input):
    return jinja2.Template(user_input)
''',
        True  # should be flagged
    ),
    "case_3_import_jinja2_as_j": (
        '''import jinja2 as j
def render(user_input):
    return j.Template(user_input)
''',
        True  # should be flagged
    ),
    "case_4_from_jinja2_import_as": (
        '''from jinja2 import Template as JinjaTemplate
def render(user_input):
    return JinjaTemplate(user_input)
''',
        True  # should be flagged
    ),
    "case_5_from_string_import_Template": (
        '''from string import Template
def render(user_input):
    t = Template("Hello, $name")
    return t.substitute(name=user_input)
''',
        False  # safe
    ),
    "case_6_shadowed_local_Template": (
        '''def local_sanitizer(text):
    return text.strip()

def render(user_input):
    Template = local_sanitizer
    return Template(user_input)
''',
        False  # safe
    ),
}

def run_ssti_import_matrix():
    print("======================================================================")
    print("SSTI IMPORT-AWARE MATRIX VERIFICATION")
    print("======================================================================")
    all_passed = True

    for name, (code, expect_flagged) in CASES.items():
        tracker = TaintTracker({f"{name}.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()

        ssti_edges = [e for e in edges if e.proof_graph and e.proof_graph.cwe == "CWE-1336"]
        flagged = len(ssti_edges) > 0

        status = "PASS" if flagged == expect_flagged else "FAIL"
        if status == "FAIL":
            all_passed = False

        print(f"[{status}] {name:<38} | Flagged: {flagged:<5} | Expected: {expect_flagged}")
        if flagged:
            for e in ssti_edges:
                nodes = e.proof_graph.nodes
                print(f"       Proof Path: {nodes[0].symbol} -> {nodes[-1].symbol} ({len(nodes)} hops)")

    print("======================================================================")
    if all_passed:
        print("ALL SSTI IMPORT-AWARE CASES PASSED!")
    else:
        print("SOME SSTI IMPORT-AWARE CASES FAILED!")
    print("======================================================================")
    return all_passed

if __name__ == "__main__":
    success = run_ssti_import_matrix()
    sys.exit(0 if success else 1)
