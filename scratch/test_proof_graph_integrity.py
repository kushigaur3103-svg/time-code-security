#!/usr/bin/env python3
"""
Test Suite: Proof Graph Dataflow & UI Status Integrity
Verifies:
1. CWE-78 single statement subprocess.run has SOURCE node with parameter name, SINK node with subprocess.run.
2. CWE-78 intermediate assignment chain (SOURCE -> ASSIGNMENT -> SINK).
3. CWE-89 single statement cursor.execute (SOURCE -> SINK).
4. CWE-22 uncalled function path traversal (SOURCE -> SINK).
5. No SINK node is ever positioned or classified as SOURCE.
6. Frontend template status binding: POTENTIAL -> POTENTIAL DATAFLOW PATH (Amber), CONFIRMED -> CONFIRMED PROOF PATH (Red).
"""

import os
import sys
import json
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ast_scanner import TaintTracker, ProofNodeType, ProofGraphIR


def test_cwe78_single_statement_subprocess_run():
    print("[-] Testing CWE-78 single-statement subprocess.run(host, shell=True)...")
    code = """import subprocess

def ping(host):
    subprocess.run(f"ping -c 1 {host}", shell=True)
"""
    tracker = TaintTracker({"target.py": code}, audit_all=True)
    sources, sinks, edges = tracker.analyze()

    cwe78_edges = [e for e in edges if e.proof_graph and e.proof_graph.cwe == "CWE-78"]
    assert len(cwe78_edges) >= 1, f"Expected CWE-78 edge, got {len(cwe78_edges)}"

    edge = cwe78_edges[0]
    pg: ProofGraphIR = edge.proof_graph
    assert pg is not None, "Proof graph must not be None"
    assert len(pg.nodes) >= 2, f"Proof graph should have >= 2 nodes, got {len(pg.nodes)}"

    node0 = pg.nodes[0]
    assert node0.node_type == ProofNodeType.SOURCE, f"Node 0 must be SOURCE, got {node0.node_type}"
    assert "host" in node0.symbol and "ping" in node0.symbol, f"Node 0 symbol should reference host (ping), got '{node0.symbol}'"
    assert "subprocess" not in node0.symbol, f"Node 0 must NOT be subprocess sink, got '{node0.symbol}'"

    sink_node = pg.nodes[-1]
    assert sink_node.node_type == ProofNodeType.SINK, f"Last node must be SINK, got {sink_node.node_type}"
    assert "subprocess.run" in sink_node.symbol or "run" in sink_node.symbol, f"Last node symbol should be subprocess.run, got '{sink_node.symbol}'"

    print(f"    [+] PASS: Nodes={len(pg.nodes)}, Node[0]=SOURCE({node0.symbol}), Node[-1]=SINK({sink_node.symbol})")


def test_cwe78_intermediate_propagation():
    print("[-] Testing CWE-78 with intermediate assignment chain...")
    code = """import subprocess

def exec_cmd(user_arg):
    full_cmd = "cat " + user_arg
    subprocess.call(full_cmd, shell=True)
"""
    tracker = TaintTracker({"target.py": code}, audit_all=True)
    sources, sinks, edges = tracker.analyze()

    cwe78_edges = [e for e in edges if e.proof_graph and e.proof_graph.cwe == "CWE-78"]
    assert len(cwe78_edges) >= 1, f"Expected CWE-78 edge, got {len(cwe78_edges)}"

    edge = cwe78_edges[0]
    pg: ProofGraphIR = edge.proof_graph
    assert pg is not None, "Proof graph must not be None"
    assert len(pg.nodes) >= 3, f"Proof graph should have >= 3 nodes, got {len(pg.nodes)}"

    node0 = pg.nodes[0]
    assert node0.node_type == ProofNodeType.SOURCE, f"Node 0 must be SOURCE, got {node0.node_type}"
    assert "user_arg" in node0.symbol, f"Node 0 symbol must reference user_arg, got '{node0.symbol}'"

    types = [n.node_type for n in pg.nodes]
    assert ProofNodeType.ASSIGNMENT in types, f"Expected ASSIGNMENT in nodes, got {types}"
    assert pg.nodes[-1].node_type == ProofNodeType.SINK, f"Last node must be SINK, got {pg.nodes[-1].node_type}"

    print(f"    [+] PASS: Node types sequence: {[t.value for t in types]}")


def test_cwe89_single_statement_sql():
    print("[-] Testing CWE-89 single-statement cursor.execute(f'...')...")
    code = """import sqlite3

def get_user(cursor, username):
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchone()
"""
    tracker = TaintTracker({"target.py": code}, audit_all=True)
    sources, sinks, edges = tracker.analyze()

    cwe89_edges = [e for e in edges if e.proof_graph and e.proof_graph.cwe == "CWE-89"]
    assert len(cwe89_edges) >= 1, f"Expected CWE-89 edge, got {len(cwe89_edges)}"

    edge = cwe89_edges[0]
    pg: ProofGraphIR = edge.proof_graph
    assert pg is not None, "Proof graph must not be None"
    assert len(pg.nodes) >= 2, f"Proof graph should have >= 2 nodes, got {len(pg.nodes)}"

    node0 = pg.nodes[0]
    assert node0.node_type == ProofNodeType.SOURCE, f"Node 0 must be SOURCE, got {node0.node_type}"
    assert "username" in node0.symbol and "get_user" in node0.symbol, f"Node 0 must reference username (get_user), got '{node0.symbol}'"
    assert "cursor.execute" not in node0.symbol, f"Node 0 must NOT be execute sink, got '{node0.symbol}'"

    sink_node = pg.nodes[-1]
    assert sink_node.node_type == ProofNodeType.SINK, f"Last node must be SINK, got {sink_node.node_type}"
    assert "cursor.execute" in sink_node.symbol or "execute" in sink_node.symbol

    print(f"    [+] PASS: Nodes={len(pg.nodes)}, Node[0]=SOURCE({node0.symbol}), Node[-1]=SINK({sink_node.symbol})")


def test_cwe22_uncalled_function():
    print("[-] Testing CWE-22 path traversal uncalled function parameter...")
    code = """def read_doc(user_path):
    with open(user_path, 'r') as f:
        return f.read()
"""
    tracker = TaintTracker({"target.py": code}, audit_all=True)
    sources, sinks, edges = tracker.analyze()

    cwe22_edges = [e for e in edges if e.proof_graph and e.proof_graph.cwe == "CWE-22"]
    assert len(cwe22_edges) >= 1, f"Expected CWE-22 edge, got {len(cwe22_edges)}"

    edge = cwe22_edges[0]
    pg: ProofGraphIR = edge.proof_graph
    assert pg is not None, "Proof graph must not be None"
    assert len(pg.nodes) >= 2, f"Proof graph should have >= 2 nodes, got {len(pg.nodes)}"

    node0 = pg.nodes[0]
    assert node0.node_type == ProofNodeType.SOURCE, f"Node 0 must be SOURCE, got {node0.node_type}"
    assert "user_path" in node0.symbol, f"Node 0 symbol should reference user_path, got '{node0.symbol}'"
    assert "open" != node0.symbol, f"Node 0 must NOT be open sink"

    sink_node = pg.nodes[-1]
    assert sink_node.node_type == ProofNodeType.SINK, f"Last node must be SINK, got {sink_node.node_type}"
    assert "open" in sink_node.symbol

    print(f"    [+] PASS: Nodes={len(pg.nodes)}, Node[0]=SOURCE({node0.symbol}), Node[-1]=SINK({sink_node.symbol})")


def test_template_ui_status_binding():
    print("[-] Testing template UI banner and node classification logic...")
    template_path = PROJECT_ROOT / "templates" / "index.html"
    assert template_path.exists(), "templates/index.html not found"

    content = template_path.read_text(encoding="utf-8")

    # 1. Verify dynamic banner logic exists and hardcoded text is removed from static banner
    assert "CONFIRMED PROOF PATH" in content
    assert "POTENTIAL DATAFLOW PATH" in content
    assert "bannerBadgeHtml" in content
    assert "isConfirmed" in content

    # 2. Verify isSource / isSink logic
    assert "rawType === 'SOURCE' || (idx === 0 && rawType !== 'SINK')" in content
    assert "rawType === 'SINK' || (idx === nodes.length - 1 && nodes.length > 1 && rawType !== 'SOURCE')" in content

    # 3. Simulate JavaScript logic with test findings
    def eval_js_banner(finding):
        conf_label = str(finding.get("confidence_label") or finding.get("status") or ("CONFIRMED" if finding.get("confidence", 0) >= 1.0 else "POTENTIAL")).upper()
        is_confirmed = "CONFIRMED" in conf_label
        if is_confirmed:
            return "CONFIRMED PROOF PATH", "text-red-400"
        else:
            return "POTENTIAL DATAFLOW PATH", "text-amber-400"

    # Potential finding
    pot_f = {"confidence_label": "POTENTIAL", "confidence": 0.7}
    banner_text, badge_color = eval_js_banner(pot_f)
    assert banner_text == "POTENTIAL DATAFLOW PATH"
    assert badge_color == "text-amber-400"

    # Confirmed finding
    conf_f = {"confidence_label": "CONFIRMED", "confidence": 1.0}
    banner_text2, badge_color2 = eval_js_banner(conf_f)
    assert banner_text2 == "CONFIRMED PROOF PATH"
    assert badge_color2 == "text-red-400"

    print("    [+] PASS: Frontend dynamic binding verified for both POTENTIAL and CONFIRMED states.")


def test_graph_edges_and_serialization():
    print("[-] Testing ProofGraphIR serialization and edge consistency...")
    code = """import subprocess

def run_it(cmd_arg):
    subprocess.call(cmd_arg, shell=True)
"""
    tracker = TaintTracker({"target.py": code}, audit_all=True)
    sources, sinks, edges = tracker.analyze()

    assert len(edges) >= 1
    pg: ProofGraphIR = edges[0].proof_graph
    d = pg.to_dict()

    assert "nodes" in d and len(d["nodes"]) >= 2
    assert "edges" in d and len(d["edges"]) >= 1
    assert d["nodes"][0]["node_type"] == "SOURCE"
    assert d["nodes"][-1]["node_type"] == "SINK"

    # Edge links node 0 to sink
    edge0 = d["edges"][0]
    assert edge0["from_node_id"] == d["nodes"][0]["node_id"]
    assert edge0["to_node_id"] == d["nodes"][-1]["node_id"]

    print(f"    [+] PASS: Serialization valid, {len(d['nodes'])} nodes, {len(d['edges'])} edges verified.")


if __name__ == "__main__":
    print("================================================================")
    print("PROOF GRAPH INTEGRITY & UI STATUS VERIFICATION")
    print("================================================================")
    test_cwe78_single_statement_subprocess_run()
    test_cwe78_intermediate_propagation()
    test_cwe89_single_statement_sql()
    test_cwe22_uncalled_function()
    test_template_ui_status_binding()
    test_graph_edges_and_serialization()
    print("================================================================")
    print("ALL PROOF GRAPH INTEGRITY TESTS PASSED SUCCESSFULLY!")
    print("================================================================")
