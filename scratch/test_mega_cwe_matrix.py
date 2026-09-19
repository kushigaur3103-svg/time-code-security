#!/usr/bin/env python3
"""
Mega CWE Matrix Test Suite
Authoritative verification for all 6 core CWE vulnerability vectors:
1. CWE-798 (Hardcoded Secrets / Vector A)
2. CWE-89 (SQL Injection)
3. CWE-78 (Command Injection)
4. CWE-22 (Path Traversal)
5. CWE-95 (Code Injection - eval & compile)
6. CWE-502 (Insecure Deserialization - pickle.loads & yaml.unsafe_load)
7. CWE-1336 (Server-Side Template Injection - jinja2.Template)

Also asserts:
- Safe Negatives: yaml.load with SafeLoader, string.Template
- Proof Graph chronological accuracy: SOURCE (param) -> [Intermediate] -> SINK
- Zero synthetic taint graphs for CWE-798 secrets (dedicated secret evidence preserved)
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ast_scanner import TaintTracker, ProofNodeType
from secret_scanner import scan_text, mask_secret


MEGA_TARGET_CODE = '''import sqlite3
import subprocess
import pickle
import yaml
import jinja2
from string import Template as StringTemplate

# 1. Vector A / CWE-798: High-entropy AWS Access Key
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# 2. CWE-89: SQL Injection via uncalled function parameter
def get_user(cursor, username):
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchone()

# 3. CWE-78: Command Injection via uncalled function parameter
def run_ping(host):
    subprocess.run(f"ping -c 1 {host}", shell=True)

# 4. CWE-22: Path Traversal via uncalled function parameter
def read_doc(user_path):
    with open(user_path, 'r') as f:
        return f.read()

# 5. CWE-95: Code Injection via eval
def execute_code(user_code):
    eval(user_code)

# 5b. CWE-95: Code Injection via compile
def compile_dynamic(dyn_code):
    compile(dyn_code, "<string>", "exec")

# 6. CWE-502: Insecure Deserialization via pickle.loads
def deserialize_pickle(payload):
    return pickle.loads(payload)

# 6b. CWE-502: Insecure Deserialization via yaml.unsafe_load
def deserialize_yaml_unsafe(raw_yaml):
    return yaml.unsafe_load(raw_yaml)

# 7. CWE-1336: Server-Side Template Injection via jinja2.Template
def render_custom_template(template_str):
    return jinja2.Template(template_str)

# --- SAFE NEGATIVES ---

# Safe Negative 1: yaml.load with SafeLoader (Exempted by AST safety filter)
def safe_yaml_loading(safe_data):
    return yaml.load(safe_data, Loader=yaml.SafeLoader)

# Safe Negative 2: Standard library string.Template (Exempted from CWE-1336)
def safe_string_template(user_name):
    t = StringTemplate("Hello, $name")
    return t.substitute(name=user_name)
'''


def test_mega_matrix_direct_ast():
    print("[-] [TEST 1] Running Direct AST TaintTracker Mega Matrix...")
    tracker = TaintTracker({"vuln_target.py": MEGA_TARGET_CODE}, audit_all=True)
    sources, sinks, edges = tracker.analyze()

    detected_cwes = {e.proof_graph.cwe for e in edges if e.proof_graph and e.proof_graph.cwe}
    print(f"    Detected SAST CWEs: {sorted(list(detected_cwes))}")

    required_sast_cwes = {"CWE-89", "CWE-78", "CWE-22", "CWE-95", "CWE-502", "CWE-1336"}
    missing = required_sast_cwes - detected_cwes
    assert not missing, f"Missing expected SAST CWEs: {missing}"

    # Verify proof graphs for each CWE
    for edge in edges:
        pg = edge.proof_graph
        if not pg:
            continue
        cwe = pg.cwe
        nodes = pg.nodes
        assert len(nodes) >= 2, f"Proof graph for {cwe} must have >= 2 nodes, got {len(nodes)}"

        node0 = nodes[0]
        node_last = nodes[-1]

        # Invariant: Node 0 is always SOURCE
        assert node0.node_type == ProofNodeType.SOURCE, f"Node 0 for {cwe} must be SOURCE, got {node0.node_type}"
        # Invariant: Node last is always SINK
        assert node_last.node_type == ProofNodeType.SINK, f"Node -1 for {cwe} must be SINK, got {node_last.node_type}"

        # Invariant: Sink is NEVER at Node 0
        assert not node0.symbol.startswith("subprocess.")
        assert "cursor.execute" not in node0.symbol
        assert "open" != node0.symbol
        assert "eval" != node0.symbol
        assert not node0.symbol.startswith("pickle.")
        assert not node0.symbol.startswith("yaml.")

        print(f"    [+] {cwe:<8} Proof Graph Verified: {node0.symbol} -> {node_last.symbol} ({len(nodes)} hops)")

    # Assert Safe Negatives
    # safe_yaml_loading should NOT have an edge
    yaml_safe_edges = [e for e in edges if "safe_yaml_loading" in (e.proof_graph.nodes[0].symbol if e.proof_graph and e.proof_graph.nodes else "")]
    assert len(yaml_safe_edges) == 0, f"Safe yaml.load should produce 0 findings, got {len(yaml_safe_edges)}"

    # safe_string_template should NOT have an edge
    string_tmpl_edges = [e for e in edges if "safe_string_template" in (e.proof_graph.nodes[0].symbol if e.proof_graph and e.proof_graph.nodes else "")]
    assert len(string_tmpl_edges) == 0, f"Safe string.Template should produce 0 findings, got {len(string_tmpl_edges)}"

    print("    [+] Safe negatives (yaml.SafeLoader & string.Template) confirmed 0 findings.")


def test_mega_matrix_cli_audit_all():
    print("\n[-] [TEST 2] Running CLI 'tcs scan . --audit-all --secrets' on isolated sandbox...")
    with tempfile.TemporaryDirectory() as tmpdir:
        sandbox = Path(tmpdir)
        target_file = sandbox / "target.py"
        target_file.write_text(MEGA_TARGET_CODE, encoding="utf-8")

        # Run CLI with --audit-all --secrets and --format json
        cmd = [sys.executable, "-m", "tcs_cli", "scan", str(sandbox), "--audit-all", "--secrets", "--format", "json"]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(PROJECT_ROOT))

        assert proc.returncode == 1, f"Expected returncode=1 on vulnerable repo, got {proc.returncode}. Stderr: {proc.stderr}"
        data = json.loads(proc.stdout)

        sast_findings = data.get("findings", [])
        secret_findings = data.get("secret_findings", [])
        all_findings = sast_findings + secret_findings

        all_cwes = {f.get("cwe") for f in all_findings if f.get("cwe")}
        print(f"    Total Findings: {len(all_findings)} (SAST: {len(sast_findings)}, Secrets: {len(secret_findings)})")
        print(f"    All Detected CWEs: {sorted(list(all_cwes))}")

        # Assert required 6 core CWE set membership
        required_core_cwes = {"CWE-798", "CWE-89", "CWE-78", "CWE-22", "CWE-95", "CWE-502"}
        assert required_core_cwes.issubset(all_cwes), f"Missing required core CWEs: {required_core_cwes - all_cwes}"

        # Assert CWE-798 secret evidence separation
        sec_798 = [sf for sf in secret_findings if sf.get("cwe") == "CWE-798"]
        assert len(sec_798) >= 1, "Expected at least 1 CWE-798 secret finding"
        for sf in sec_798:
            assert sf.get("secret_type") == "aws_access_key"
            assert sf.get("masked_value") == mask_secret("AKIAIOSFODNN7EXAMPLE")
            assert "proof_graph" not in sf, "CWE-798 must NOT generate artificial SAST taint proof graphs"
            assert "line_number" in sf and sf["line_number"] == 9, f"Expected secret on line 9, got {sf.get('line_number')}"
            print(f"    [+] CWE-798 Secret Evidence Verified: {sf['secret_type']} on Line {sf['line_number']} (Masked: {sf['masked_value']})")

        # Assert dataflow proof graphs for each SAST finding
        for f in sast_findings:
            cwe = f.get("cwe")
            pg = f.get("proof_graph")
            assert pg is not None, f"SAST finding {cwe} must have a valid proof graph"
            nodes = pg.get("nodes", [])
            assert len(nodes) >= 2, f"Proof graph for {cwe} must have >= 2 nodes"
            assert nodes[0]["node_type"] == "SOURCE"
            assert nodes[-1]["node_type"] == "SINK"
            print(f"    [+] SAST {cwe} Verified: Line {f.get('line_number')} ({nodes[0]['symbol']} -> {nodes[-1]['symbol']})")


def test_safe_negatives_isolated():
    print("\n[-] [TEST 3] Running isolated safe negative validation...")
    safe_code = '''import yaml
from string import Template

def clean_yaml_loader(data):
    return yaml.load(data, Loader=yaml.SafeLoader)

def clean_string_template(name):
    t = Template("User: $name")
    return t.substitute(name=name)
'''
    tracker = TaintTracker({"safe_target.py": safe_code}, audit_all=True)
    sources, sinks, edges = tracker.analyze()

    assert len(edges) == 0, f"Expected 0 findings on safe target, got {len(edges)}: {[e.proof_graph.cwe for e in edges if e.proof_graph]}"
    print("    [+] Isolated Safe Target: 0 findings (100% false-positive free).")


if __name__ == "__main__":
    print("======================================================================")
    print("MEGA CWE MATRIX & SAFE NEGATIVE AUDIT SUITE")
    print("======================================================================")
    test_mega_matrix_direct_ast()
    test_mega_matrix_cli_audit_all()
    test_safe_negatives_isolated()
    print("======================================================================")
    print("ALL MEGA MATRIX AUDIT TESTS PASSED SUCCESSFULLY!")
    print("======================================================================")
