#!/usr/bin/env python3
"""
Adversarial Verification Suite for Vector 2.5 (Phase 1.5: Chained Calls & Parameter Noise Suppression).
Tests:
1. Chained method calls: conn.cursor().execute(f"...{q}") -> Confirmed CWE-89.
2. Deep chained calls: db.get_conn().cursor().execute(f"...{q}") -> Confirmed CWE-89.
3. Parameter noise suppression: unbound parameters in default mode -> 0 speculative findings.
4. Aggressive audit mode: --audit-all -> emits speculative POTENTIAL findings for unbound parameters.
5. Parameterized query exemption on chained calls -> 0 findings.
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from ast_scanner import (
    TaintTracker,
    ProofNodeType,
    render_proof_graph_ascii,
)
from tcs_cli import execute_tcs_scan


CHAINED_SQLI_CODE = """
from flask import request

def chained_flow(conn):
    q = request.args.get("user")
    conn.cursor().execute(f"SELECT * FROM users WHERE name = '{q}'")
"""

DEEP_CHAINED_SQLI_CODE = """
from flask import request

def deep_chained_flow(db):
    q = request.args.get("user")
    db.get_conn().cursor().execute(f"SELECT * FROM users WHERE name = '{q}'")
"""

CLEAN_PARAM_CODE = """
def clean_param_flow(conn, user_id):
    conn.cursor().execute(f"SELECT * FROM users WHERE id = {user_id}")
"""

SAFE_PARAMETERIZED_CODE = """
from flask import request

def safe_chained_flow(conn):
    q = request.args.get("user")
    conn.cursor().execute("SELECT * FROM users WHERE name = %s", (q,))
"""


class TestVector25ChainedAndNoise(unittest.TestCase):

    def test_01_chained_cursor_execute_detected(self):
        """1. Chained call: conn.cursor().execute(...) emits CONFIRMED CWE-89 finding."""
        tracker = TaintTracker(files={"chained.py": CHAINED_SQLI_CODE})
        sources, sinks, edges = tracker.analyze()

        self.assertEqual(len(edges), 1, f"Expected exactly 1 CWE-89 finding, got {len(edges)}")
        edge = edges[0]
        self.assertEqual(edge.confidence, 1.0)
        self.assertEqual(edge.kind, "CONFIRMED_DATA_FLOW")

        pg = edge.proof_graph
        self.assertIsNotNone(pg)
        self.assertEqual(pg.cwe, "CWE-89")
        self.assertEqual(pg.confidence, 1.0)

        # Inspect proof nodes
        self.assertGreaterEqual(len(pg.nodes), 2)
        self.assertEqual(pg.nodes[0].node_type, ProofNodeType.SOURCE)
        self.assertEqual(pg.nodes[-1].node_type, ProofNodeType.SINK)
        self.assertEqual(pg.nodes[-1].symbol, "conn.cursor().execute")
        self.assertIn("conn.cursor().execute", pg.nodes[-1].expression_snippet)

    def test_02_deep_chained_call_detected(self):
        """2. Deep chained call: db.get_conn().cursor().execute(...) emits CONFIRMED CWE-89 finding."""
        tracker = TaintTracker(files={"deep.py": DEEP_CHAINED_SQLI_CODE})
        sources, sinks, edges = tracker.analyze()

        self.assertEqual(len(edges), 1, f"Expected 1 finding for deep chained call, got {len(edges)}")
        edge = edges[0]
        self.assertEqual(edge.confidence, 1.0)
        pg = edge.proof_graph
        self.assertIsNotNone(pg)
        self.assertEqual(pg.cwe, "CWE-89")
        self.assertEqual(pg.nodes[-1].symbol, "db.get_conn().cursor().execute")

    def test_03_parameter_noise_suppression_default(self):
        """3. Parameter Noise Suppression: In default mode, unbound parameters emit 0 speculative warnings."""
        tracker = TaintTracker(files={"clean_param.py": CLEAN_PARAM_CODE}, audit_all=False)
        sources, sinks, edges = tracker.analyze()

        self.assertEqual(len(edges), 0, f"Expected 0 findings in default high-signal mode, got {len(edges)}")

        # Also verify CLI scan default contract
        scan_res = execute_tcs_scan({"clean_param.py": CLEAN_PARAM_CODE}, audit_all=False)
        self.assertEqual(len(scan_res.get("findings", [])), 0, "CLI default scan must suppress unbound param noise")

    def test_04_parameter_aggressive_audit_mode(self):
        """4. Aggressive audit mode (audit_all=True): Unbound parameters emit speculative POTENTIAL warning."""
        tracker = TaintTracker(files={"clean_param.py": CLEAN_PARAM_CODE}, audit_all=True)
        sources, sinks, edges = tracker.analyze()

        self.assertEqual(len(edges), 1, f"Expected 1 POTENTIAL finding in audit-all mode, got {len(edges)}")
        edge = edges[0]
        self.assertEqual(edge.kind, "POTENTIAL_DATA_FLOW")
        self.assertEqual(edge.confidence, 0.50)

        scan_res = execute_tcs_scan({"clean_param.py": CLEAN_PARAM_CODE}, audit_all=True)
        findings = scan_res.get("findings", [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["confidence"], 0.50)
        self.assertEqual(findings[0]["confidence_label"], "POTENTIAL")

    def test_05_safe_parameterized_chained_call_exempted(self):
        """5. Safe parameterized chained call: conn.cursor().execute(query, (args,)) is exempted."""
        tracker = TaintTracker(files={"safe.py": SAFE_PARAMETERIZED_CODE})
        sources, sinks, edges = tracker.analyze()

        self.assertEqual(len(edges), 0, f"Expected 0 findings for parameterized query, got {len(edges)}")


def run_standalone_report():
    print("=" * 70)
    print("VECTOR 2.5: CHAINED CALLS & PARAMETER NOISE SUPPRESSION VERIFICATION")
    print("=" * 70)

    # 1. Chained Call Verification
    print("\n--- 1. CHAINED METHOD CALL TEST (conn.cursor().execute) ---")
    t1 = TaintTracker(files={"chained.py": CHAINED_SQLI_CODE})
    _, sinks1, edges1 = t1.analyze()
    print(f"Sinks detected: {len(sinks1)}")
    for s in sinks1:
        print(f"  * Sink: {s.symbol} (CWE: {s.metadata.get('cwe')})")
    print(f"Findings detected: {len(edges1)} (Expected: 1)")
    assert len(edges1) == 1, f"FAIL: Expected 1 finding, got {len(edges1)}"
    e1 = edges1[0]
    assert e1.confidence == 1.0, f"FAIL: Confidence expected 1.0, got {e1.confidence}"
    assert e1.proof_nodes[-1].symbol == "conn.cursor().execute", f"FAIL: Symbol mismatch: {e1.proof_nodes[-1].symbol}"
    print(f"[PASS] Chained call correctly detected as CWE-89 with symbol '{e1.proof_nodes[-1].symbol}'")
    print("\nProofGraph Structure for Chained SQLi:")
    print(render_proof_graph_ascii(e1.proof_graph))

    # 2. Deep Chained Call Verification
    print("\n--- 2. DEEP CHAINED CALL TEST (db.get_conn().cursor().execute) ---")
    t2 = TaintTracker(files={"deep.py": DEEP_CHAINED_SQLI_CODE})
    _, _, edges2 = t2.analyze()
    print(f"Findings detected: {len(edges2)} (Expected: 1)")
    assert len(edges2) == 1, f"FAIL: Expected 1 deep chained finding, got {len(edges2)}"
    assert edges2[0].proof_nodes[-1].symbol == "db.get_conn().cursor().execute"
    print(f"[PASS] Deep chained call correctly detected with symbol '{edges2[0].proof_nodes[-1].symbol}'")

    # 3. Parameter Noise Suppression (Default Mode)
    print("\n--- 3. PARAMETER NOISE SUPPRESSION (Default: audit_all=False) ---")
    t3 = TaintTracker(files={"clean_param.py": CLEAN_PARAM_CODE}, audit_all=False)
    _, _, edges3 = t3.analyze()
    print(f"Findings detected: {len(edges3)} (Expected: 0)")
    assert len(edges3) == 0, f"FAIL: Default mode emitted false-positive speculative warnings ({len(edges3)})"
    print("[PASS] Default scan successfully suppressed speculative unbound parameter noise.")

    # 4. Aggressive Audit Mode (--audit-all)
    print("\n--- 4. AGGRESSIVE AUDIT MODE (audit_all=True) ---")
    t4 = TaintTracker(files={"clean_param.py": CLEAN_PARAM_CODE}, audit_all=True)
    _, _, edges4 = t4.analyze()
    print(f"Findings detected: {len(edges4)} (Expected: 1)")
    assert len(edges4) == 1, f"FAIL: Aggressive audit mode expected 1 finding, got {len(edges4)}"
    assert edges4[0].kind == "POTENTIAL_DATA_FLOW"
    assert edges4[0].confidence == 0.50
    print("[PASS] Aggressive audit mode correctly emits speculative POTENTIAL finding (conf: 0.50).")

    # 5. Parameterized Query Exemption
    print("\n--- 5. PARAMETERIZED QUERY EXEMPTION ON CHAINED CALL ---")
    t5 = TaintTracker(files={"safe.py": SAFE_PARAMETERIZED_CODE})
    _, _, edges5 = t5.analyze()
    print(f"Findings detected: {len(edges5)} (Expected: 0)")
    assert len(edges5) == 0, f"FAIL: Parameterized query falsely flagged ({len(edges5)})"
    print("[PASS] Parameterized query correctly exempted.")

    print("\n" + "=" * 70)
    print("ALL VECTOR 2.5 PHASE 1.5 DIRECTIVES VERIFIED 100% DETERMINISTICALLY")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    run_standalone_report()
    unittest.main(argv=[""], exit=False, verbosity=2)
