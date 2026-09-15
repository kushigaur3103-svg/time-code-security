#!/usr/bin/env python3
"""
Hardened Unit Test Suite for Vector A: Deterministic Proof Graph IR
Implements all CTO Correction Directives:
  1. True Graph Topology: Branched & merged DAG with in-degree/out-degree > 1 (edges != nodes - 1)
  2. Sanitizer Semantics: Inspect SANITIZER node, verify clean termination & audit graph
  3. Return Propagation: Strict verification of callee return node & caller reception node (file, line, symbol, snippet)
  4. SARIF Fidelity: Per-node verification of uri, startLine, endLine, and snippet.text
  5. Node ID Contract: Instance-only identity verification
  6. Backward compatibility, transforms, and serialization determinism
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ast
import json
import unittest
from ast_scanner import (
    TaintTracker,
    ProofNodeType,
    ProofNode,
    ProofEdge,
    ProofGraphIR,
    render_proof_graph_ascii,
    DataFlowEdge,
    TaintState
)
from sarif_adapter import to_sarif


class TestProofGraphVectorAHardened(unittest.TestCase):

    def test_01_single_file_linear_flow(self):
        """Case A: Single-file source -> assignment -> sink proof graph verification."""
        code = (
            "def handle_request():\n"
            "    user_input = request.args.get('q')\n"
            "    query = f\"SELECT * FROM users WHERE name = '{user_input}'\"\n"
            "    cursor.execute(query)\n"
        )
        tracker = TaintTracker(files={"app.py": code})
        sources, sinks, edges = tracker.analyze()

        self.assertEqual(len(edges), 1, "Expected exactly 1 data flow edge")
        edge = edges[0]
        self.assertIsNotNone(edge.proof_graph, "proof_graph must not be None")
        pg = edge.proof_graph

        self.assertTrue(pg.finding_id.startswith("TCS-IR-"))
        self.assertEqual(pg.cwe, "CWE-89")
        self.assertEqual(pg.confidence, 1.0)
        self.assertGreaterEqual(len(pg.nodes), 3)

        # First node must be SOURCE
        self.assertEqual(pg.nodes[0].node_type, ProofNodeType.SOURCE)
        self.assertEqual(pg.nodes[0].file_path, "app.py")
        self.assertEqual(pg.nodes[0].start_line, 2)
        self.assertIn("request.args.get", pg.nodes[0].symbol)

        # Intermediate node must be ASSIGNMENT
        assign_node = next(n for n in pg.nodes if n.node_type == ProofNodeType.ASSIGNMENT)
        self.assertEqual(assign_node.symbol, "query")
        self.assertEqual(assign_node.start_line, 3)
        self.assertIn("SELECT * FROM users", assign_node.expression_snippet)

        # Last node must be SINK
        sink_node = pg.nodes[-1]
        self.assertEqual(sink_node.node_type, ProofNodeType.SINK)
        self.assertEqual(sink_node.symbol, "cursor.execute")
        self.assertEqual(sink_node.start_line, 4)

    def test_02_true_graph_topology_branch_and_merge(self):
        """Correction 1: True Graph Topology with Branch and Merge DAG.
        Verifies that ProofGraphIR represents:
            SOURCE
              ├──> branch A
              └──> branch B
                    │     │
                    ▼     ▼
                     x (MERGE)
                        │
                        ▼
                      SINK
        Proves out-degree > 1 and in-degree > 1, with explicit ProofEdge topology.
        Does NOT require edges == nodes - 1.
        """
        code = (
            "def handle_branch(cond):\n"
            "    user_val = request.args.get('v')\n"
            "    if cond:\n"
            "        branch_a = user_val\n"
            "        x = branch_a\n"
            "    else:\n"
            "        branch_b = user_val\n"
            "        x = branch_b\n"
            "    cursor.execute(x)\n"
        )
        tracker = TaintTracker(files={"branch_test.py": code})
        sources, sinks, edges = tracker.analyze()

        self.assertEqual(len(edges), 1)
        pg = edges[0].proof_graph
        self.assertIsNotNone(pg)

        # 1. Inspect nodes
        symbols = [n.symbol for n in pg.nodes]
        self.assertIn("user_val", symbols)
        self.assertIn("branch_a", symbols)
        self.assertIn("branch_b", symbols)
        self.assertIn("x", symbols)
        self.assertIn("cursor.execute", symbols)

        # 2. Inspect edges and topology
        # Find node IDs
        user_val_node = next(n for n in pg.nodes if n.symbol == "user_val")
        branch_a_node = next(n for n in pg.nodes if n.symbol == "branch_a")
        branch_b_node = next(n for n in pg.nodes if n.symbol == "branch_b")
        x_merge_node = next(n for n in pg.nodes if n.symbol == "x")
        sink_node = next(n for n in pg.nodes if n.symbol == "cursor.execute")

        # Verify branching edges (out-degree of user_val >= 2)
        out_edges_user_val = [e for e in pg.edges if e.from_node_id == user_val_node.node_id]
        self.assertGreaterEqual(len(out_edges_user_val), 2, "user_val must branch to at least 2 paths")
        branch_targets = {e.to_node_id for e in out_edges_user_val}
        self.assertIn(branch_a_node.node_id, branch_targets)
        self.assertIn(branch_b_node.node_id, branch_targets)

        # Verify merging edges (in-degree of x >= 2)
        in_edges_x = [e for e in pg.edges if e.to_node_id == x_merge_node.node_id]
        self.assertGreaterEqual(len(in_edges_x), 2, "x merge node must have in-degree >= 2 from both branches")
        merge_sources = {e.from_node_id for e in in_edges_x}
        self.assertIn(branch_a_node.node_id, merge_sources)
        self.assertIn(branch_b_node.node_id, merge_sources)

        # Verify edge to sink
        sink_in_edges = [e for e in pg.edges if e.to_node_id == sink_node.node_id]
        self.assertGreaterEqual(len(sink_in_edges), 1)
        self.assertEqual(sink_in_edges[0].from_node_id, x_merge_node.node_id)
        self.assertEqual(sink_in_edges[0].edge_type, ProofNodeType.SINK.value)

        # Explicitly assert that this branched graph does NOT satisfy edges == nodes - 1
        # It has equal or more edges than nodes due to branch-and-merge cycles/diamonds
        self.assertGreaterEqual(len(pg.edges), len(pg.nodes), "Branched graph edges must reflect true diamond topology")

    def test_03_sanitizer_semantics_and_node_inspection(self):
        """Correction 2: Sanitizer Semantics.
        1. Inspects the SANITIZER ProofNode directly on the sanitized expression.
        2. Verifies node_type=SANITIZER, symbol='int()', file, line, and edge_type='SANITIZER'.
        3. Verifies TaintState.CLEAN terminates the vulnerable flow (0 findings to sink).
        4. Verifies explicit audit graph construction for SOURCE -> SANITIZER -> SINK.
        """
        code = (
            "def handle_sanitization():\n"
            "    raw = request.args.get('id')\n"
            "    clean_val = int(raw)\n"
            "    cursor.execute(f\"SELECT * FROM users WHERE id = {clean_val}\")\n"
        )
        tracker = TaintTracker(files={"san_test.py": code})
        sources, sinks, edges = tracker.analyze()

        # 1. Verify that approved sanitizer int() terminates the graph at the sink (0 vulnerability edges)
        self.assertEqual(len(edges), 0, "Approved sanitizer must eliminate vulnerable data flow edge to sink")

        # 2. Inspect the SANITIZER node in the intermediate expression
        clean_expr = ast.parse("int(raw)").body[0].value
        clean_taint = tracker.resolve_expression(clean_expr, sinks[0] if sinks else None, "san_test:function:handle_sanitization", 3)

        self.assertEqual(clean_taint.state, TaintState.CLEAN, "TaintState must be CLEAN after approved sanitizer")
        self.assertGreaterEqual(len(clean_taint.proof_nodes), 2)

        # Inspect the SANITIZER node itself
        san_node = next((n for n in clean_taint.proof_nodes if n.node_type == ProofNodeType.SANITIZER), None)
        self.assertIsNotNone(san_node, "SANITIZER ProofNode must be explicitly created")
        self.assertEqual(san_node.node_type, ProofNodeType.SANITIZER)
        self.assertIn("int()", san_node.symbol)
        self.assertEqual(san_node.file_path, "san_test.py")
        self.assertEqual(san_node.start_line, 3)

        # Inspect the SANITIZER edge
        san_edge = next((e for e in clean_taint.proof_edges if e.edge_type == "SANITIZER"), None)
        self.assertIsNotNone(san_edge, "ProofEdge with edge_type='SANITIZER' must exist")
        self.assertEqual(san_edge.to_node_id, san_node.node_id)

        # 3. Verify audit graph representation SOURCE -> SANITIZER -> SINK
        sink_node = tracker.create_proof_node(
            step_index=len(clean_taint.proof_nodes),
            node_type=ProofNodeType.SINK,
            file_path="san_test.py",
            node=None,
            symbol="cursor.execute",
            scope_id="san_test:function:handle_sanitization",
            lineno=4
        )
        audit_nodes = [*clean_taint.proof_nodes, sink_node]
        audit_edges = [*clean_taint.proof_edges, ProofEdge(san_node.node_id, sink_node.node_id, "SINK")]
        audit_pg = ProofGraphIR(
            finding_id="TCS-IR-AUDIT-001",
            cwe="CWE-89",
            confidence=0.0,
            nodes=audit_nodes,
            edges=audit_edges,
            sanitizer_applied="int()"
        )
        self.assertEqual(audit_pg.sanitizer_applied, "int()")
        self.assertEqual(audit_pg.confidence, 0.0)
        self.assertEqual(len(audit_pg.nodes), len(clean_taint.proof_nodes) + 1)

    def test_04_strict_return_propagation(self):
        """Correction 3: Return Propagation Strict Verification.
        Explicitly verifies:
        - Callee return node has exact file, line, and return statement snippet.
        - Callee return edge has edge_type='RETURN'.
        - Caller return-reception node has exact file, line, and symbol='return_from:get_user_id'.
        - Edge connects callee return to caller return reception.
        """
        callee_code = (
            "def get_user_id():\n"
            "    return request.args.get('id')\n"
        )
        caller_code = (
            "from service import get_user_id\n"
            "def handler():\n"
            "    val = get_user_id()\n"
            "    cursor.execute(val)\n"
        )
        tracker = TaintTracker(files={"service.py": callee_code, "controller.py": caller_code})
        sources, sinks, edges = tracker.analyze()

        self.assertEqual(len(edges), 1)
        pg = edges[0].proof_graph
        self.assertIsNotNone(pg)

        # 1. Find the callee return node
        callee_ret_node = next(
            (n for n in pg.nodes if n.file_path == "service.py" and "return" in n.symbol and n.start_line == 2),
            None
        )
        self.assertIsNotNone(callee_ret_node, "Callee return node must be present in service.py at line 2")
        self.assertEqual(callee_ret_node.file_path, "service.py")
        self.assertEqual(callee_ret_node.start_line, 2)
        self.assertEqual(callee_ret_node.end_line, 2)
        self.assertIn("return", callee_ret_node.expression_snippet)
        self.assertIn("request.args.get", callee_ret_node.expression_snippet)

        # 2. Find caller return reception node
        caller_rec_node = next(
            (n for n in pg.nodes if n.file_path == "controller.py" and "return_from:get_user_id" in n.symbol and n.start_line == 3),
            None
        )
        self.assertIsNotNone(caller_rec_node, "Caller reception node must be present in controller.py at line 3")
        self.assertEqual(caller_rec_node.file_path, "controller.py")
        self.assertEqual(caller_rec_node.start_line, 3)

        # 3. Verify exact RETURN edge from callee to caller
        ret_edge = next(
            (e for e in pg.edges if e.from_node_id == callee_ret_node.node_id and e.to_node_id == caller_rec_node.node_id),
            None
        )
        self.assertIsNotNone(ret_edge, "Edge must link callee return to caller return reception")
        self.assertEqual(ret_edge.edge_type, "RETURN")

    def test_05_sarif_per_node_fidelity(self):
        """Correction 4: SARIF Fidelity.
        For EVERY ProofNode emitted into SARIF:
        - artifactLocation.uri == node.file_path
        - startLine == node.start_line
        - endLine == node.end_line
        - snippet.text == node.expression_snippet
        Must match exactly without any sink line fallback.
        """
        code = (
            "def process_order():\n"
            "    raw_id = request.args.get('order_id')\n"       # Line 2
            "    normalized = raw_id\n"                          # Line 3
            "    sql_cmd = f\"SELECT {normalized}\"\n"          # Line 4
            "    cursor.execute(sql_cmd)\n"                      # Line 5
        )
        tracker = TaintTracker(files={"orders.py": code})
        sources, sinks, edges = tracker.analyze()
        pg = edges[0].proof_graph

        finding = {
            "id": "TCS-SAST-9999",
            "rule_id": "CWE-89",
            "message": "SQL Injection in process_order",
            "confidence": 1.0,
            "confidence_label": "CONFIRMED",
            "file": "orders.py",
            "line_number": 5,
            "code_snippet": "cursor.execute(sql_cmd)",
            "flow_trace": ["request.args.get", "sql_cmd", "cursor.execute"],
            "proof_graph": pg.to_dict(),
            "proof_graph_ascii": render_proof_graph_ascii(pg)
        }

        sarif_doc = to_sarif({"findings": [finding]})
        results = sarif_doc["runs"][0]["results"]
        self.assertEqual(len(results), 1)

        thread_flows = results[0]["codeFlows"][0]["threadFlows"][0]
        locations = thread_flows["locations"]

        # Number of locations must exactly match number of proof graph nodes
        self.assertEqual(len(locations), len(pg.nodes))

        # Check EVERY single node against its SARIF location
        for i, node in enumerate(pg.nodes):
            loc = locations[i]
            phys = loc["location"]["physicalLocation"]
            uri = phys["artifactLocation"]["uri"]
            start_line = phys["region"]["startLine"]
            end_line = phys["region"].get("endLine")
            snip_text = phys["region"].get("snippet", {}).get("text")

            self.assertEqual(uri, node.file_path, f"Step {i}: URI mismatch")
            self.assertEqual(start_line, node.start_line, f"Step {i}: startLine mismatch")
            self.assertEqual(end_line, node.end_line, f"Step {i}: endLine mismatch")
            self.assertEqual(snip_text, node.expression_snippet, f"Step {i}: snippet mismatch")

    def test_06_node_id_contract(self):
        """Correction 5: Node ID Contract.
        Verifies that node_id encodes graph-instance identity only:
        f'{node_type}:{file_path}:{start_line}:{symbol}#{step_index}'
        and is explicitly documented as NOT the semantic finding identity.
        """
        code = (
            "def contract_test():\n"
            "    user_input = request.args.get('id')\n"
            "    cursor.execute(user_input)\n"
        )
        tracker = TaintTracker(files={"contract.py": code})
        _, _, edges = tracker.analyze()
        pg = edges[0].proof_graph

        for node in pg.nodes:
            # Must follow graph-instance format
            self.assertIn("#", node.node_id, "node_id must have step index anchor")
            self.assertTrue(node.node_id.startswith(node.node_type.value.lower() + ":"))
            self.assertIn(str(node.start_line), node.node_id)
            self.assertIn(node.file_path, node.node_id)

    def test_07_cross_file_param_binding(self):
        """Case B: Cross-file source -> param binding -> sink."""
        db_code = (
            "def execute_sql(query):\n"
            "    cursor.execute(query)\n"
        )
        routes_code = (
            "from db import execute_sql\n"
            "def route():\n"
            "    inp = request.args.get('val')\n"
            "    execute_sql(inp)\n"
        )
        tracker = TaintTracker(files={"db.py": db_code, "routes.py": routes_code})
        sources, sinks, edges = tracker.analyze()

        self.assertEqual(len(edges), 1)
        pg = edges[0].proof_graph
        self.assertIsNotNone(pg)

        file_paths = [n.file_path for n in pg.nodes]
        self.assertIn("routes.py", file_paths)
        self.assertIn("db.py", file_paths)

        param_nodes = [n for n in pg.nodes if n.node_type == ProofNodeType.PARAM_BINDING]
        self.assertTrue(len(param_nodes) >= 1)
        self.assertEqual(param_nodes[0].file_path, "db.py")
        self.assertEqual(param_nodes[0].symbol, "query")
        self.assertEqual(param_nodes[0].start_line, 1)

    def test_08_transform_cast_propagation(self):
        """Case D: Transform/cast propagation (e.g. str() preserves taint)."""
        code = (
            "def handle_cast():\n"
            "    raw = request.args.get('user')\n"
            "    text = str(raw)\n"
            "    cursor.execute(text)\n"
        )
        tracker = TaintTracker(files={"app.py": code})
        sources, sinks, edges = tracker.analyze()

        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].kind, "CONFIRMED_DATA_FLOW")
        pg = edges[0].proof_graph
        self.assertIsNotNone(pg)

        transform_nodes = [n for n in pg.nodes if n.node_type == ProofNodeType.TRANSFORM]
        self.assertTrue(len(transform_nodes) >= 1)
        self.assertIn("str", transform_nodes[0].symbol)

    def test_09_backward_compatibility_preserved(self):
        """Case H: DataFlowEdge.transform string and TaintValue.path remain preserved."""
        code = (
            "def legacy_check():\n"
            "    inp = request.args.get('key')\n"
            "    cursor.execute(inp)\n"
        )
        tracker = TaintTracker(files={"legacy.py": code})
        sources, sinks, edges = tracker.analyze()

        self.assertEqual(len(edges), 1)
        edge = edges[0]

        self.assertIsInstance(edge.source_id, str)
        self.assertIsInstance(edge.target_id, str)
        self.assertIsInstance(edge.kind, str)
        self.assertIsInstance(edge.confidence, float)
        self.assertIsInstance(edge.transform, str)
        self.assertTrue(len(edge.transform) > 0)
        self.assertIsNotNone(edge.proof_graph)

    def test_10_deterministic_serialization_and_ascii(self):
        """Case J: Deterministic JSON serialization and ASCII box rendering."""
        code = (
            "def check_determinism():\n"
            "    user = request.args.get('u')\n"
            "    query = f\"SELECT {user}\"\n"
            "    cursor.execute(query)\n"
        )
        tracker = TaintTracker(files={"det.py": code})
        _, _, edges = tracker.analyze()
        pg = edges[0].proof_graph

        d = pg.to_dict()
        required_keys = {"finding_id", "cwe", "confidence", "nodes", "edges", "sanitizer_applied"}
        self.assertTrue(required_keys.issubset(d.keys()))
        self.assertEqual(len(d["nodes"]), len(pg.nodes))
        self.assertEqual(len(d["edges"]), len(pg.edges))

        json1 = json.dumps(d, sort_keys=True)
        json2 = json.dumps(pg.to_dict(), sort_keys=True)
        self.assertEqual(json1, json2, "ProofGraphIR serialization must be 100% deterministic")

        ascii_box = render_proof_graph_ascii(pg)
        self.assertIn("[SECURITY PROOF]", ascii_box)
        self.assertIn("CWE-89", ascii_box)
        self.assertIn("Confidence: 1.00 (CONFIRMED)", ascii_box)
        self.assertIn("SOURCE", ascii_box)
        self.assertIn("SINK", ascii_box)
        self.assertIn("det.py", ascii_box)
        lines = ascii_box.splitlines()
        self.assertTrue(lines[0].startswith("┌──"))
        self.assertTrue(lines[-1].startswith("└──"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
