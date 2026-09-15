#!/usr/bin/env python3
"""
CONSOLIDATED VECTOR A FINAL SEAL GATE VERIFICATION
Steps 1, 2, 3, 4, 5, and 8
"""

import sys
import json
import tempfile
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
TCS_CLI = str(REPO_ROOT / "tcs_cli.py")

def step_1_cli_json():
    print("========================================================")
    print("STEP 1: CLI JSON END-TO-END")
    print("========================================================")
    code = (
        "def query_user():\n"
        "    q = request.args.get('user')\n"
        "    sql = f\"SELECT * FROM users WHERE name = '{q}'\"\n"
        "    cursor.execute(sql)\n"
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        target = Path(tmpdir) / "vuln_linear.py"
        target.write_text(code, encoding="utf-8")

        res = subprocess.run([sys.executable, TCS_CLI, str(target), "--format", "json"], capture_output=True, text=True)
        assert res.returncode == 1, f"Expected rc=1, got {res.returncode}. Stderr: {res.stderr}"

        data = json.loads(res.stdout)
        assert "findings" in data, "JSON must contain 'findings'"
        assert len(data["findings"]) == 1, f"Expected exactly 1 finding, got {len(data['findings'])}"

        f = data["findings"][0]
        assert f["cwe"] == "CWE-89", f"Expected CWE-89, got {f['cwe']}"
        assert "proof_graph" in f and f["proof_graph"] is not None, "Finding must contain proof_graph"
        assert "proof_graph_ascii" in f and f["proof_graph_ascii"] is not None, "Finding must contain proof_graph_ascii"

        pg = f["proof_graph"]
        for k in ["finding_id", "cwe", "confidence", "nodes", "edges"]:
            assert k in pg, f"proof_graph missing required key: {k}"

        assert pg["cwe"] == "CWE-89"
        assert pg["confidence"] == 1.0
        assert len(pg["nodes"]) > 0, "node count must be > 0"
        assert len(pg["edges"]) > 0, "edge count must be > 0"
        assert pg["nodes"][0]["node_type"] == "SOURCE", f"First node type must be SOURCE, got {pg['nodes'][0]['node_type']}"
        assert pg["nodes"][-1]["node_type"] == "SINK", f"Last node type must be SINK, got {pg['nodes'][-1]['node_type']}"

        print(f"[PASS] Exit Code: {res.returncode}")
        print(f"[PASS] Findings: {len(data['findings'])}")
        print(f"[PASS] CWE: {pg['cwe']}, Confidence: {pg['confidence']}")
        print(f"[PASS] Proof Nodes: {len(pg['nodes'])}")
        print(f"[PASS] Proof Edges: {len(pg['edges'])}")
        print("\n--- Serialized Proof Nodes ---")
        for n in pg["nodes"]:
            print(f"  Node ID: {n['node_id']}")
            print(f"    step_index: {n['step_index']}, type: {n['node_type']}, symbol: {n['symbol']}")
            print(f"    location: {n['file_path']}:{n['start_line']}-{n['end_line']}")
            print(f"    snippet: {n['expression_snippet']!r}")

        print("\n--- Serialized Proof Edges ---")
        for e in pg["edges"]:
            print(f"  Edge: {e['from_node_id']} -> {e['to_node_id']} [{e['edge_type']}]")

        return pg, f["proof_graph_ascii"], str(target), code

def step_2_cli_sarif(expected_pg, target_code):
    print("\n========================================================")
    print("STEP 2: CLI SARIF END-TO-END")
    print("========================================================")
    sarif_out = REPO_ROOT / "scratch" / "vectorA-final.sarif"
    sarif_out.parent.mkdir(parents=True, exist_ok=True)
    if sarif_out.exists():
        sarif_out.unlink()

    with tempfile.TemporaryDirectory() as tmpdir:
        target = Path(tmpdir) / "vuln_linear.py"
        target.write_text(target_code, encoding="utf-8")

        res = subprocess.run([sys.executable, TCS_CLI, str(target), "--format", "sarif", "-o", str(sarif_out)], capture_output=True, text=True)
        assert res.returncode == 1, f"Expected rc=1, got {res.returncode}. Stderr: {res.stderr}"
        assert sarif_out.exists(), "SARIF output file must exist"

        sarif_data = json.loads(sarif_out.read_text(encoding="utf-8"))
        results = sarif_data["runs"][0]["results"]
        assert len(results) == 1, f"Expected 1 SARIF result, got {len(results)}"

        r = results[0]
        assert r["ruleId"] == "CWE-89", f"Expected ruleId CWE-89, got {r['ruleId']}"
        assert "codeFlows" in r and len(r["codeFlows"]) > 0, "codeFlows must exist"
        cf = r["codeFlows"][0]
        assert "threadFlows" in cf and len(cf["threadFlows"]) > 0, "threadFlows must exist"
        tf = cf["threadFlows"][0]
        locations = tf["locations"]
        assert len(locations) == len(expected_pg["nodes"]), f"Location count {len(locations)} != node count {len(expected_pg['nodes'])}"

        sink_line = expected_pg["nodes"][-1]["start_line"]
        sink_snippet = expected_pg["nodes"][-1]["expression_snippet"]

        print(f"[PASS] Exit Code: {res.returncode}")
        print(f"[PASS] SARIF Results: {len(results)}, ruleId: {r['ruleId']}")
        print(f"[PASS] ThreadFlow Locations: {len(locations)}")
        print("\n--- Per-Hop Fidelity Comparison Table ---")
        print(f"{'Hop':<4} | {'Node Type':<12} | {'ProofGraph URI:Line':<22} | {'SARIF URI:Line':<22} | {'Snippet Match':<14} | {'Sink Collapse'}")
        print("-" * 95)

        for i, (loc, node) in enumerate(zip(locations, expected_pg["nodes"])):
            phys = loc["location"]["physicalLocation"]
            uri = phys["artifactLocation"]["uri"]
            s_line = phys["region"]["startLine"]
            e_line = phys["region"].get("endLine")
            snip = phys["region"].get("snippet", {}).get("text")

            assert uri == node["file_path"], f"Hop {i}: URI mismatch: {uri} != {node['file_path']}"
            assert s_line == node["start_line"], f"Hop {i}: startLine mismatch: {s_line} != {node['start_line']}"
            assert e_line == node["end_line"], f"Hop {i}: endLine mismatch: {e_line} != {node['end_line']}"
            assert snip == node["expression_snippet"], f"Hop {i}: snippet mismatch: {snip!r} != {node['expression_snippet']!r}"

            is_sink = (i == len(locations) - 1)
            collapsed = (s_line == sink_line and snip == sink_snippet and not is_sink)
            assert not collapsed, f"Hop {i} unexpectedly collapsed to sink location!"

            pg_loc = f"{node['file_path']}:{node['start_line']}-{node['end_line']}"
            sarif_loc = f"{uri}:{s_line}-{e_line}"
            print(f"{i:<4} | {node['node_type']:<12} | {pg_loc:<22} | {sarif_loc:<22} | {'EXACT MATCH':<14} | {'NO (PRESERVED)' if not collapsed else 'COLLAPSED'}")

        return sarif_data

def step_3_cross_file():
    print("\n========================================================")
    print("STEP 3: CROSS-FILE CLI PROOF")
    print("========================================================")
    routes_code = (
        "from db import execute_helper\n"
        "def route_handler():\n"
        "    param = request.args.get('q')\n"
        "    execute_helper(param)\n"
    )
    db_code = (
        "def execute_helper(sql_arg):\n"
        "    cursor.execute(sql_arg)\n"
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "routes.py").write_text(routes_code, encoding="utf-8")
        (tmp / "db.py").write_text(db_code, encoding="utf-8")

        res = subprocess.run([sys.executable, TCS_CLI, str(tmp), "--format", "json"], capture_output=True, text=True)
        assert res.returncode == 1, f"Expected rc=1, got {res.returncode}. Stderr: {res.stderr}"

        data = json.loads(res.stdout)
        findings = [f for f in data.get("findings", []) if f["cwe"] == "CWE-89"]
        assert len(findings) == 1, f"Expected 1 CWE-89 finding, got {len(findings)}"

        pg = findings[0]["proof_graph"]
        assert pg is not None, "proof_graph must be present in cross-file finding"

        file_paths = {n["file_path"] for n in pg["nodes"]}
        node_types = {n["node_type"] for n in pg["nodes"]}

        assert any("routes.py" in fp for fp in file_paths), f"routes.py missing from {file_paths}"
        assert any("db.py" in fp for fp in file_paths), f"db.py missing from {file_paths}"
        assert "PARAM_BINDING" in node_types, f"PARAM_BINDING missing from {node_types}"
        assert "SINK" in node_types, f"SINK missing from {node_types}"

        param_node = next(n for n in pg["nodes"] if n["node_type"] == "PARAM_BINDING")
        assert "db.py" in param_node["file_path"], f"PARAM_BINDING must be in db.py, got {param_node['file_path']}"
        assert param_node["symbol"] == "sql_arg"

        sink_node = pg["nodes"][-1]
        assert "db.py" in sink_node["file_path"], f"Final sink must be in db.py, got {sink_node['file_path']}"

        print(f"[PASS] Cross-File Finding: {findings[0]['id']} ({findings[0]['cwe']})")
        print(f"[PASS] Files in ProofGraph: {sorted(list(file_paths))}")
        print(f"[PASS] Node Types: {sorted(list(node_types))}")
        print(f"[PASS] PARAM_BINDING Node: symbol='{param_node['symbol']}' in {param_node['file_path']}:{param_node['start_line']}")
        print(f"[PASS] Final SINK: symbol='{sink_node['symbol']}' in {sink_node['file_path']}:{sink_node['start_line']}")
        return pg

def step_4_branch_merge():
    print("\n========================================================")
    print("STEP 4: TRUE BRANCH / MERGE CLI GRAPH")
    print("========================================================")
    code = (
        "def branch_handler(cond):\n"
        "    user_val = request.args.get('v')\n"
        "    if cond:\n"
        "        branch_a = user_val\n"
        "        x = branch_a\n"
        "    else:\n"
        "        branch_b = user_val\n"
        "        x = branch_b\n"
        "    cursor.execute(x)\n"
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        target = Path(tmpdir) / "branch_cli.py"
        target.write_text(code, encoding="utf-8")

        res = subprocess.run([sys.executable, TCS_CLI, str(target), "--format", "json"], capture_output=True, text=True)
        assert res.returncode == 1, f"Expected rc=1, got {res.returncode}. Stderr: {res.stderr}"

        data = json.loads(res.stdout)
        findings = data.get("findings", [])
        assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"

        pg = findings[0]["proof_graph"]
        nodes = pg["nodes"]
        edges = pg["edges"]

        out_degrees = {n["node_id"]: 0 for n in nodes}
        in_degrees = {n["node_id"]: 0 for n in nodes}
        for e in edges:
            out_degrees[e["from_node_id"]] = out_degrees.get(e["from_node_id"], 0) + 1
            in_degrees[e["to_node_id"]] = in_degrees.get(e["to_node_id"], 0) + 1

        max_out = max(out_degrees.values())
        max_in = max(in_degrees.values())
        branch_merge_edges = [e for e in edges if e["edge_type"] == "BRANCH_MERGE"]

        assert max_out >= 2, f"Expected node with out-degree >= 2, got max {max_out}"
        assert max_in >= 2, f"Expected node with in-degree >= 2, got max {max_in}"
        assert len(branch_merge_edges) >= 2, f"Expected >= 2 BRANCH_MERGE edges, got {len(branch_merge_edges)}"

        symbols = [n["symbol"] for n in nodes]
        assert "branch_a" in symbols
        assert "branch_b" in symbols
        assert "x" in symbols

        print(f"[PASS] Node Count: {len(nodes)}")
        print(f"[PASS] Edge Count: {len(edges)}")
        print(f"[PASS] Max Out-Degree: {max_out} (user_val branches into multiple paths)")
        print(f"[PASS] Max In-Degree: {max_in} (x merges multiple paths)")
        print(f"[PASS] BRANCH_MERGE Edges ({len(branch_merge_edges)}):")
        for bme in branch_merge_edges:
            print(f"  - {bme['from_node_id']} -> {bme['to_node_id']}")
        return pg

def step_5_sanitizer():
    print("\n========================================================")
    print("STEP 5: SANITIZER CONTRACT")
    print("========================================================")
    code = (
        "def clean_handler():\n"
        "    raw = request.args.get('id')\n"
        "    clean_val = int(raw)\n"
        "    cursor.execute(f\"SELECT * FROM users WHERE id = {clean_val}\")\n"
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        target = Path(tmpdir) / "clean_sanitizer.py"
        target.write_text(code, encoding="utf-8")

        res = subprocess.run([sys.executable, TCS_CLI, str(target), "--format", "json"], capture_output=True, text=True)
        assert res.returncode == 0, f"Expected rc=0, got {res.returncode}. Output: {res.stdout}"

        data = json.loads(res.stdout)
        findings = data.get("findings", [])
        cwe89 = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89) == 0, f"Expected 0 CWE-89 findings, got {len(cwe89)}"

    # Internal inspection
    import ast
    from ast_scanner import TaintTracker, ProofNodeType, TaintState
    tracker = TaintTracker(files={"clean_sanitizer.py": code})
    sources, sinks, edges = tracker.analyze()
    clean_expr = ast.parse("int(raw)").body[0].value
    taint_val = tracker.resolve_expression(clean_expr, sinks[0] if sinks else None, "clean_sanitizer:function:clean_handler", 3)

    assert taint_val.state == TaintState.CLEAN, f"Expected CLEAN taint state, got {taint_val.state}"
    san_node = next((n for n in taint_val.proof_nodes if n.node_type == ProofNodeType.SANITIZER), None)
    assert san_node is not None, "SANITIZER node must exist in taint_val.proof_nodes"
    assert "int()" in san_node.symbol
    assert san_node.file_path == "clean_sanitizer.py"
    assert san_node.start_line == 3

    san_edge = next((e for e in taint_val.proof_edges if e.edge_type == "SANITIZER"), None)
    assert san_edge is not None, "SANITIZER edge must exist in taint_val.proof_edges"
    assert san_edge.to_node_id == san_node.node_id

    print(f"[PASS] CLI Exit Code: {res.returncode}")
    print(f"[PASS] Active CWE-89 Findings: {len(cwe89)}")
    print(f"[PASS] Internal Taint State: {taint_val.state.value}")
    print(f"[PASS] SANITIZER Node: symbol='{san_node.symbol}' in {san_node.file_path}:{san_node.start_line}")
    print(f"[PASS] SANITIZER Edge: {san_edge.from_node_id} -> {san_edge.to_node_id} [{san_edge.edge_type}]")
    print(f"[PASS] Semantic Termination: Sanitizer rendered flow CLEAN, preventing sink emission.")

def step_8_determinism(target_code):
    print("\n========================================================")
    print("STEP 8: DETERMINISM (3 CONSECUTIVE CLI RUNS)")
    print("========================================================")
    runs = []
    sarif_runs = []
    with tempfile.TemporaryDirectory() as tmpdir:
        target = Path(tmpdir) / "det_vuln.py"
        target.write_text(target_code, encoding="utf-8")

        for run_idx in range(3):
            # JSON Run
            res_json = subprocess.run([sys.executable, TCS_CLI, str(target), "--format", "json"], capture_output=True, text=True)
            assert res_json.returncode == 1
            data = json.loads(res_json.stdout)
            runs.append(data)

            # SARIF Run
            s_file = Path(tmpdir) / f"out_{run_idx}.sarif"
            res_sarif = subprocess.run([sys.executable, TCS_CLI, str(target), "--format", "sarif", "-o", str(s_file)], capture_output=True, text=True)
            assert res_sarif.returncode == 1
            s_data = json.loads(s_file.read_text(encoding="utf-8"))
            sarif_runs.append(s_data)

    # Compare JSON across all 3 runs
    for run_idx in range(1, 3):
        assert len(runs[run_idx]["findings"]) == len(runs[0]["findings"]), "Finding count changed between runs"
        f0 = runs[0]["findings"][0]
        fi = runs[run_idx]["findings"][0]

        assert f0["cwe"] == fi["cwe"]
        assert f0["confidence"] == fi["confidence"]

        pg0 = f0["proof_graph"]
        pgi = fi["proof_graph"]

        assert len(pg0["nodes"]) == len(pgi["nodes"]), "ProofGraph node count changed between runs"
        assert len(pg0["edges"]) == len(pgi["edges"]), "ProofGraph edge count changed between runs"

        for n0, ni in zip(pg0["nodes"], pgi["nodes"]):
            assert n0["step_index"] == ni["step_index"]
            assert n0["node_type"] == ni["node_type"]
            assert n0["start_line"] == ni["start_line"]
            assert n0["end_line"] == ni["end_line"]
            assert n0["symbol"] == ni["symbol"]
            assert n0["expression_snippet"] == ni["expression_snippet"]

        for e0, ei in zip(pg0["edges"], pgi["edges"]):
            assert e0["edge_type"] == ei["edge_type"]

        # Compare SARIF threadFlows
        locs0 = sarif_runs[0]["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
        locsi = sarif_runs[run_idx]["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
        assert len(locs0) == len(locsi)
        for l0, li in zip(locs0, locsi):
            reg0 = l0["location"]["physicalLocation"]["region"]
            regi = li["location"]["physicalLocation"]["region"]
            assert reg0["startLine"] == regi["startLine"]
            assert reg0["endLine"] == regi["endLine"]
            assert reg0.get("snippet", {}).get("text") == regi.get("snippet", {}).get("text")

    print("[PASS] 3 Consecutive Runs Evaluated.")
    print("[PASS] Semantic Finding Stability: 100% Identical")
    print("[PASS] ProofGraph Topology & Node Sequences: 100% Identical")
    print("[PASS] SARIF CodeFlow & ThreadFlow Locations: 100% Identical")
    print("[PASS] Deterministic repeatability confirmed.")

if __name__ == "__main__":
    pg, ascii_proof, target_path, code = step_1_cli_json()
    step_2_cli_sarif(pg, code)
    step_3_cross_file()
    step_4_branch_merge()
    step_5_sanitizer()
    step_8_determinism(code)
    print("\n========================================================")
    print("ALL INTEGRATION GATE TESTS COMPLETED SUCCESSFULLY!")
    print("========================================================")
