#!/usr/bin/env python3
"""
Test CWE-95 Compile Matrix
Asserts exact behavior for all 3 cases required by CTO Directive:
1. compile(tainted, ...) -> FLAGGED as CWE-95
2. builtins.compile(tainted, ...) -> FLAGGED as CWE-95
3. compile(constant, ...) -> SAFE (0 findings)
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ast_scanner import TaintTracker

CASES = {
    "case_1_compile_tainted": (
        '''def exec_dyn(code_str):
    return compile(code_str, "<string>", "exec")
''',
        True  # Unsafe (Flagged)
    ),
    "case_2_builtins_compile_tainted": (
        '''import builtins
def exec_dyn(code_str):
    return builtins.compile(code_str, "<string>", "exec")
''',
        True  # Unsafe (Flagged)
    ),
    "case_3_compile_constant": (
        '''def exec_const():
    SAFE_CODE = "x = 10"
    return compile(SAFE_CODE, "<string>", "exec")
''',
        False  # Safe (0 findings)
    ),
}

def run_compile_matrix():
    print("======================================================================")
    print("CWE-95 COMPILE MATRIX VERIFICATION")
    print("======================================================================")
    all_passed = True

    for name, (code, expect_flagged) in CASES.items():
        tracker = TaintTracker({f"{name}.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()

        cwe95_edges = [e for e in edges if e.proof_graph and e.proof_graph.cwe == "CWE-95"]
        flagged = len(cwe95_edges) > 0

        status = "PASS" if flagged == expect_flagged else "FAIL"
        if status == "FAIL":
            all_passed = False

        policy = "UNSAFE (Flagged CWE-95)" if expect_flagged else "SAFE (Constant, 0 findings)"
        print(f"[{status}] {name:<35} | Flagged: {flagged:<5} | Policy: {policy}")
        if flagged:
            for e in cwe95_edges:
                nodes = e.proof_graph.nodes
                print(f"       Proof Path: {nodes[0].symbol} -> {nodes[-1].symbol} ({len(nodes)} hops)")

    print("======================================================================")
    if all_passed:
        print("ALL CWE-95 COMPILE MATRIX CASES PASSED!")
    else:
        print("SOME CWE-95 COMPILE MATRIX CASES FAILED!")
    print("======================================================================")
    return all_passed

if __name__ == "__main__":
    success = run_compile_matrix()
    sys.exit(0 if success else 1)
