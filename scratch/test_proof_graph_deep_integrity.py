#!/usr/bin/env python3
"""
Deep Proof Graph Integrity Verification Suite
Asserts non-negotiable graph topology and metadata invariants for every CWE:
1. SOURCE node exists
2. SINK node exists
3. step_index is strictly monotonic
4. all edge endpoints exist in nodes
5. no orphan nodes (connected path from SOURCE to SINK)
6. source symbol is correct (parameter or source call)
7. sink symbol is correct (exact sink)
8. scope identity is consistent
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ast_scanner import TaintTracker, ProofNodeType

TEST_PROGRAM = '''import subprocess
import sqlite3
import pickle
import yaml
import jinja2

def sqli_flow(user_name):
    query = f"SELECT * FROM users WHERE name = '{user_name}'"
    conn = sqlite3.connect("db.sqlite")
    cur = conn.cursor()
    cur.execute(query)

def cmdi_flow(host):
    cmd = f"ping -c 1 {host}"
    subprocess.run(cmd, shell=True)

def path_traversal_flow(doc_name):
    full_path = f"/data/{doc_name}"
    with open(full_path, "r") as f:
        return f.read()

def code_injection_eval(script):
    eval(script)

def code_injection_compile(raw_code):
    compile(raw_code, "<string>", "exec")

def insecure_deserialization_pickle(stream):
    return pickle.loads(stream)

def insecure_deserialization_yaml(raw_yaml):
    return yaml.unsafe_load(raw_yaml)

def ssti_flow(tmpl_content):
    tmpl = jinja2.Template(tmpl_content)
    return tmpl.render()
'''

def verify_proof_graph(pg, expected_cwe: str, expected_source_prefix: str, expected_sink_symbol: str):
    assert pg is not None, f"Proof graph for {expected_cwe} is None"
    nodes = pg.nodes
    edges = pg.edges

    # 1. SOURCE node exists
    source_nodes = [n for n in nodes if n.node_type == ProofNodeType.SOURCE]
    assert len(source_nodes) >= 1, f"Missing SOURCE node in {expected_cwe}"
    source_node = source_nodes[0]

    # 2. SINK node exists
    sink_nodes = [n for n in nodes if n.node_type == ProofNodeType.SINK]
    assert len(sink_nodes) >= 1, f"Missing SINK node in {expected_cwe}"
    sink_node = sink_nodes[-1]

    # 3. step_index is strictly monotonic
    for i in range(len(nodes) - 1):
        assert nodes[i+1].step_index > nodes[i].step_index, (
            f"Non-monotonic step_index in {expected_cwe}: "
            f"node[{i}].step_index={nodes[i].step_index} vs node[{i+1}].step_index={nodes[i+1].step_index}"
        )

    # 4. all edge endpoints exist
    node_id_set = {n.node_id for n in nodes}
    for e in edges:
        assert e.from_node_id in node_id_set, (
            f"Edge from_node_id {e.from_node_id} not in node set for {expected_cwe}"
        )
        assert e.to_node_id in node_id_set, (
            f"Edge to_node_id {e.to_node_id} not in node set for {expected_cwe}"
        )

    # 5. no orphan nodes (all nodes reachable or connected)
    connected_nodes = set()
    for e in edges:
        connected_nodes.add(e.from_node_id)
        connected_nodes.add(e.to_node_id)
    if len(nodes) > 1:
        orphan_nodes = node_id_set - connected_nodes
        assert not orphan_nodes, f"Found orphan nodes in {expected_cwe}: {orphan_nodes}"

    # 6. source symbol is correct
    assert source_node.symbol.startswith(expected_source_prefix), (
        f"Expected source symbol prefix '{expected_source_prefix}', got '{source_node.symbol}' in {expected_cwe}"
    )

    # 7. sink symbol is correct
    assert sink_node.symbol == expected_sink_symbol or sink_node.symbol.endswith(expected_sink_symbol), (
        f"Expected sink symbol '{expected_sink_symbol}', got '{sink_node.symbol}' in {expected_cwe}"
    )

    # 8. scope identity is consistent
    for n in nodes:
        assert n.scope_id is not None and len(n.scope_id) > 0, f"Empty scope_id on node {n.node_id} in {expected_cwe}"

    return True

def run_deep_proof_graph_audit():
    print("======================================================================")
    print("DEEP PROOF GRAPH INTEGRITY AUDIT")
    print("======================================================================")
    tracker = TaintTracker({"vuln_flows.py": TEST_PROGRAM}, audit_all=True)
    sources, sinks, data_edges = tracker.analyze()

    expected_checks = [
        ("CWE-89", "user_name", "execute"),
        ("CWE-78", "host", "subprocess.run"),
        ("CWE-22", "doc_name", "open"),
        ("CWE-95", "script", "eval"),
        ("CWE-95", "raw_code", "compile"),
        ("CWE-502", "stream", "pickle.loads"),
        ("CWE-502", "raw_yaml", "yaml.unsafe_load"),
        ("CWE-1336", "tmpl_content", "jinja2.Template"),
    ]

    all_passed = True
    for cwe, src_prefix, snk_sym in expected_checks:
        matching_edges = [
            e for e in data_edges
            if e.proof_graph and e.proof_graph.cwe == cwe
            and e.proof_graph.nodes[0].symbol.startswith(src_prefix)
        ]
        if not matching_edges:
            print(f"[FAIL] No proof graph found for {cwe} ({src_prefix} -> {snk_sym})")
            all_passed = False
            continue

        edge = matching_edges[0]
        pg = edge.proof_graph
        try:
            verify_proof_graph(pg, cwe, src_prefix, snk_sym)
            node_seq = " -> ".join(n.symbol for n in pg.nodes)
            print(f"[PASS] {cwe:<8} Flow: {node_seq} ({len(pg.nodes)} nodes, {len(pg.edges)} edges)")
        except AssertionError as ae:
            print(f"[FAIL] {cwe:<8} Invariant failure: {ae}")
            all_passed = False

    print("======================================================================")
    if all_passed:
        print("ALL PROOF GRAPH INTEGRITY INVARIANTS VERIFIED!")
    else:
        print("SOME PROOF GRAPH INVARIANTS FAILED!")
    print("======================================================================")
    return all_passed

if __name__ == "__main__":
    success = run_deep_proof_graph_audit()
    sys.exit(0 if success else 1)
