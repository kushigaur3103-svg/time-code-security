#!/usr/bin/env python3
"""
Test YAML Deserialization Matrix
Asserts exact behavior for all 7 cases required by CTO Directive:
1. yaml.load(... SafeLoader) -> SAFE (0 findings)
2. yaml.load(... CSafeLoader) -> SAFE (0 findings)
3. yaml.load(... BaseLoader) -> SAFE (0 findings)
4. yaml.load(... CBaseLoader) -> SAFE (0 findings)
5. yaml.load(... yaml.Loader) -> UNSAFE (Flagged CWE-502)
6. yaml.unsafe_load(...) -> UNSAFE (Flagged CWE-502)
7. yaml.load(...) without explicit Loader -> UNSAFE (Flagged CWE-502)
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ast_scanner import TaintTracker

CASES = {
    "case_1_yaml_load_SafeLoader": (
        '''import yaml
def deserialize(data):
    return yaml.load(data, Loader=yaml.SafeLoader)
''',
        False  # Safe
    ),
    "case_2_yaml_load_CSafeLoader": (
        '''import yaml
def deserialize(data):
    return yaml.load(data, Loader=yaml.CSafeLoader)
''',
        False  # Safe
    ),
    "case_3_yaml_load_BaseLoader": (
        '''import yaml
def deserialize(data):
    return yaml.load(data, Loader=yaml.BaseLoader)
''',
        False  # Safe
    ),
    "case_4_yaml_load_CBaseLoader": (
        '''import yaml
def deserialize(data):
    return yaml.load(data, Loader=yaml.CBaseLoader)
''',
        False  # Safe
    ),
    "case_5_yaml_load_Loader_unsafe": (
        '''import yaml
def deserialize(data):
    return yaml.load(data, Loader=yaml.Loader)
''',
        True  # Unsafe
    ),
    "case_6_yaml_unsafe_load": (
        '''import yaml
def deserialize(data):
    return yaml.unsafe_load(data)
''',
        True  # Unsafe
    ),
    "case_7_yaml_load_no_loader": (
        '''import yaml
def deserialize(data):
    return yaml.load(data)
''',
        True  # Unsafe
    ),
}

def run_yaml_matrix():
    print("======================================================================")
    print("YAML DESERIALIZATION MATRIX VERIFICATION")
    print("======================================================================")
    all_passed = True

    for name, (code, expect_flagged) in CASES.items():
        tracker = TaintTracker({f"{name}.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()

        cwe502_edges = [e for e in edges if e.proof_graph and e.proof_graph.cwe == "CWE-502"]
        flagged = len(cwe502_edges) > 0

        status = "PASS" if flagged == expect_flagged else "FAIL"
        if status == "FAIL":
            all_passed = False

        policy = "SAFE (Exempt)" if not expect_flagged else "UNSAFE (Flagged CWE-502)"
        print(f"[{status}] {name:<35} | Flagged: {flagged:<5} | Policy: {policy}")
        if flagged:
            for e in cwe502_edges:
                nodes = e.proof_graph.nodes
                print(f"       Proof Path: {nodes[0].symbol} -> {nodes[-1].symbol} ({len(nodes)} hops)")

    print("======================================================================")
    if all_passed:
        print("ALL YAML MATRIX CASES PASSED!")
    else:
        print("SOME YAML MATRIX CASES FAILED!")
    print("======================================================================")
    return all_passed

if __name__ == "__main__":
    success = run_yaml_matrix()
    sys.exit(0 if success else 1)
