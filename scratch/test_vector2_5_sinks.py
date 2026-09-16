#!/usr/bin/env python3
"""
Adversarial Test Suite for Vector 2.5 (Phase 1: CWE-78 Sink Hardening).
Tests multi-flaw sink detection including the expanded subprocess family:
1. SQLi: cursor.execute(f"...{user_query}")
2. Path Traversal: open(os.path.join(..., doc_name))
3. Command Injection: subprocess.check_output(f"traceroute {target_ip}", shell=True)
4. Code Execution: eval(formula)
"""

import os
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


FOUR_FLAW_SNIPPET = """
import os
import subprocess
from flask import request

def handle_request(cursor):
    # 1. SQLi: cursor.execute(f"...{user_query}")
    user_query = request.args.get('q')
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_query}'")

    # 2. Path Traversal: open(os.path.join(..., doc_name))
    doc_name = request.args.get('doc')
    open(os.path.join('/tmp', doc_name))

    # 3. Command Injection: subprocess.check_output(f"traceroute {target_ip}", shell=True)
    target_ip = request.args.get('ip')
    subprocess.check_output(f"traceroute {target_ip}", shell=True)

    # 4. Code Execution: eval(formula)
    formula = request.args.get('f')
    eval(formula)
"""


class TestVector25Sinks(unittest.TestCase):

    def setUp(self):
        self.code = FOUR_FLAW_SNIPPET
        self.tracker = TaintTracker(files={"target.py": self.code})
        self.sources, self.sinks, self.edges = self.tracker.analyze()

    def test_01_all_four_flaws_detected(self):
        """Assert total findings == 4 with exact CWE distribution and confidence 1.0."""
        # 1. Verify total findings count
        self.assertEqual(len(self.edges), 4, f"Expected exactly 4 findings, got {len(self.edges)}")

        cwes_found = {e.proof_graph.cwe: e for e in self.edges if e.proof_graph}
        self.assertEqual(len(cwes_found), 4, "Must contain all 4 distinct CWE findings")

        # 2. Assert CWE-89 present with confidence 1.0
        self.assertIn("CWE-89", cwes_found)
        edge_89 = cwes_found["CWE-89"]
        self.assertEqual(edge_89.confidence, 1.0)
        self.assertEqual(edge_89.proof_graph.confidence, 1.0)

        # 3. Assert CWE-22 present with confidence 1.0
        self.assertIn("CWE-22", cwes_found)
        edge_22 = cwes_found["CWE-22"]
        self.assertEqual(edge_22.confidence, 1.0)
        self.assertEqual(edge_22.proof_graph.confidence, 1.0)

        # 4. Assert CWE-78 present with confidence 1.0 (symbol: subprocess.check_output)
        self.assertIn("CWE-78", cwes_found)
        edge_78 = cwes_found["CWE-78"]
        self.assertEqual(edge_78.confidence, 1.0)
        self.assertEqual(edge_78.proof_graph.confidence, 1.0)
        cwe78_sink_node = edge_78.proof_nodes[-1]
        self.assertEqual(cwe78_sink_node.symbol, "subprocess.check_output")

        # 5. Assert CWE-95 present with confidence 1.0
        self.assertIn("CWE-95", cwes_found)
        edge_95 = cwes_found["CWE-95"]
        self.assertEqual(edge_95.confidence, 1.0)
        self.assertEqual(edge_95.proof_graph.confidence, 1.0)

        # 6. Each finding contains a valid, non-empty proof_nodes list starting at SOURCE and ending at SINK
        for edge in self.edges:
            pg = edge.proof_graph
            self.assertIsNotNone(pg, f"Edge {edge} must have proof_graph")
            p_nodes = edge.proof_nodes
            self.assertGreater(len(p_nodes), 0, f"proof_nodes must be non-empty for {pg.cwe}")

            # Must start at SOURCE
            self.assertEqual(p_nodes[0].node_type, ProofNodeType.SOURCE,
                             f"First node for {pg.cwe} must be SOURCE, got {p_nodes[0].node_type}")
            # Must end at SINK
            self.assertEqual(p_nodes[-1].node_type, ProofNodeType.SINK,
                             f"Last node for {pg.cwe} must be SINK, got {p_nodes[-1].node_type}")

    def test_02_cli_scan_contract(self):
        """Verify execute_tcs_scan returns the 4 confirmed findings with proof_nodes."""
        scan_res = execute_tcs_scan({"target.py": self.code})
        findings = scan_res.get("findings", [])
        self.assertEqual(len(findings), 4)

        by_cwe = {f["cwe"]: f for f in findings}
        self.assertIn("CWE-89", by_cwe)
        self.assertIn("CWE-22", by_cwe)
        self.assertIn("CWE-78", by_cwe)
        self.assertIn("CWE-95", by_cwe)

        for cwe_id in ("CWE-89", "CWE-22", "CWE-78", "CWE-95"):
            f = by_cwe[cwe_id]
            self.assertEqual(f["confidence"], 1.0)
            self.assertEqual(f["confidence_label"], "CONFIRMED")
            pg = f.get("proof_graph")
            self.assertIsNotNone(pg)
            nodes = pg.get("nodes", [])
            self.assertGreater(len(nodes), 0)
            self.assertEqual(nodes[0]["node_type"], "SOURCE")
            self.assertEqual(nodes[-1]["node_type"], "SINK")

        self.assertEqual(by_cwe["CWE-78"]["sink_symbol"], "subprocess.check_output")


def run_standalone_report():
    print("=" * 70)
    print("VECTOR 2.5: SINK HARDENING ADVERSARIAL VERIFICATION")
    print("=" * 70)

    tracker = TaintTracker(files={"target.py": FOUR_FLAW_SNIPPET})
    sources, sinks, edges = tracker.analyze()

    findings_count = len(edges)
    print(f"\n1. Findings detected count: {findings_count} (Expected: 4)")
    assert findings_count == 4, f"FAIL: Expected 4 findings, got {findings_count}"

    cwe78_edge = None
    for idx, e in enumerate(edges, 1):
        pg = e.proof_graph
        cwe = pg.cwe if pg else "UNKNOWN"
        sink_sym = e.proof_nodes[-1].symbol if e.proof_nodes else "UNKNOWN"
        print(f"   [{idx}] CWE: {cwe} | Confidence: {e.confidence:.1f} | Sink: {sink_sym} | Steps: {len(e.proof_nodes)}")
        if cwe == "CWE-78":
            cwe78_edge = e

    assert cwe78_edge is not None, "FAIL: CWE-78 finding missing!"
    assert cwe78_edge.proof_nodes[-1].symbol == "subprocess.check_output", "FAIL: Sink symbol mismatch for CWE-78!"

    print("\n2. ProofGraph structure for CWE-78:")
    print("-" * 70)
    print(render_proof_graph_ascii(cwe78_edge.proof_graph))
    print("-" * 70)
    print("   Nodes detail:")
    for n in cwe78_edge.proof_nodes:
        print(f"     * [{n.step_index}] {n.node_type.value}: {n.symbol} at {n.file_path}:{n.start_line} -> {n.expression_snippet}")
    print("   Edges detail:")
    for ed in cwe78_edge.proof_graph.edges:
        print(f"     * {ed.from_node_id} ===({ed.edge_type})===> {ed.to_node_id}")

    print("\n" + "=" * 70)
    print("ADVERSARIAL VERIFICATION PASSED: ALL 4 SINKS DETECTED AND PROVEN")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    run_standalone_report()
    unittest.main(argv=[""], exit=False, verbosity=2)
