#!/usr/bin/env python3
"""
Phase 2 (v1.2.0) Adversarial Baseline Test Harness
Scope: Function Aliasing & Container Taint Tracking
Role: Principal QA Architect
Rule: Zero changes to ast_scanner.py, rule_engine.py, or tcs_cli.py.

Matrix Breakdown:
Part 1: Function Aliasing (Direct, Local-Scoped, Chained, Higher-Order)
Part 2: Sinks in Containers (Dictionary dispatch, List indexing)
Part 3: Container Data Taint (Dict key assignment, Tuple unpacking positive & negative)
Part 4: Safe Negative Aliases
"""

import json
import sys
import unittest
from pathlib import Path

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tcs_cli import execute_tcs_scan


class Phase2AdversarialBaselineTests(unittest.TestCase):
    """
    Authoritative baseline suite for Phase 2: Function Aliasing & Container Data Taint.
    Isolates aliasing and container data tracking cleanly from parameter taint suppression.
    """

    # =========================================================================
    # Part 1: Function Aliasing Matrix
    # =========================================================================

    def test_global_function_alias(self):
        """Direct global function alias: exec_fn = subprocess.run; exec_fn(sys.argv[1], shell=True)"""
        code = """import sys, subprocess
exec_fn = subprocess.run
exec_fn(sys.argv[1], shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1, "Expected CWE-78 finding for direct global function alias")
        self.assertEqual(cwe78_findings[0].get("severity"), "HIGH")

    def test_attribute_alias(self):
        """Direct module attribute alias: sys_exec = os.system; sys_exec(sys.argv[1])"""
        code = """import os, sys
sys_exec = os.system
sys_exec(sys.argv[1])
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1, "Expected CWE-78 finding for direct module attribute alias")
        self.assertEqual(cwe78_findings[0].get("severity"), "HIGH")

    def test_local_scoped_alias_no_params(self):
        """Local-scoped alias inside function without external params"""
        code = """import subprocess, sys
def execute():
    p = subprocess.Popen
    p(sys.argv[1], shell=True)
execute()
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1, "Expected CWE-78 finding for local-scoped alias")
        self.assertEqual(cwe78_findings[0].get("severity"), "HIGH")

    def test_chained_alias(self):
        """Chained alias: a = subprocess.run; b = a; b(sys.argv[1], shell=True)"""
        code = """import sys, subprocess
a = subprocess.run
b = a
b(sys.argv[1], shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1, "Expected CWE-78 finding for chained function alias")
        self.assertEqual(cwe78_findings[0].get("severity"), "HIGH")

    def test_higher_order_function_alias(self):
        """Higher-order function / callback alias: runner(subprocess.run, sys.argv[1])"""
        code = """import subprocess, sys
def runner(fn, cmd):
    fn(cmd, shell=True)
runner(subprocess.run, sys.argv[1])
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1, "Expected CWE-78 finding for higher-order function / callback alias")
        self.assertEqual(cwe78_findings[0].get("severity"), "HIGH")

    def test_higher_order_call_site_isolation(self):
        """Higher-order call-site isolation: runner(os.path.join, 'safe') vs runner(subprocess.run, sys.argv[1])"""
        code = """import subprocess, os, sys
def runner(fn, cmd):
    fn(cmd, shell=True)
runner(os.path.join, "safe_path")
runner(subprocess.run, sys.argv[1])
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertEqual(len(cwe78_findings), 1, "Expected exactly 1 CWE-78 finding for isolated call-site")
        self.assertEqual(cwe78_findings[0].get("severity"), "HIGH")

    def test_higher_order_no_cross_call_site_pollution(self):
        """Higher-order anti-pollution: runner(subprocess.run, 'echo safe') and runner(os.path.join, sys.argv[1])"""
        code = """import subprocess, os, sys
def runner(fn, cmd):
    fn(cmd, shell=True)
runner(subprocess.run, "echo safe")
runner(os.path.join, sys.argv[1])
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertEqual(len(cwe78_findings), 0, "Expected zero findings when safe command is passed to sink and tainted arg to safe function")

    # =========================================================================
    # Part 2: Sinks Stored in Containers
    # =========================================================================

    def test_container_dict_sink(self):
        """Sink in dictionary container: dispatcher = {'run': subprocess.run}; dispatcher['run'](...)"""
        code = """import sys, subprocess
dispatcher = {"run": subprocess.run}
dispatcher["run"](sys.argv[1], shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1, "Expected CWE-78 finding for dictionary container sink dispatch")
        self.assertEqual(cwe78_findings[0].get("severity"), "HIGH")

    def test_container_list_sink(self):
        """Sink in list container: handlers = [subprocess.run]; handlers[0](...)"""
        code = """import sys, subprocess
handlers = [subprocess.run]
handlers[0](sys.argv[1], shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1, "Expected CWE-78 finding for list container sink dispatch")
        self.assertEqual(cwe78_findings[0].get("severity"), "HIGH")

    # =========================================================================
    # Part 3: Container Data Taint Tracking
    # =========================================================================

    def test_container_dict_data_taint(self):
        """Dictionary key assignment taint: d['cmd'] = request.args.get('payload'); subprocess.run(d['cmd'])"""
        code = """from flask import request
import subprocess
d = {}
d["cmd"] = request.args.get("payload")
subprocess.run(d["cmd"], shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1, "Expected CWE-78 finding for dictionary key data taint")
        self.assertEqual(cwe78_findings[0].get("severity"), "CRITICAL")

    def test_container_dict_get_data_taint(self):
        """Dictionary .get() parity: d = {}; d['cmd'] = request.args.get('payload'); subprocess.run(d.get('cmd'))"""
        code = """from flask import request
import subprocess
d = {}
d["cmd"] = request.args.get("payload")
subprocess.run(d.get("cmd"), shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1, "Expected CWE-78 finding for dictionary .get() data taint")
        self.assertEqual(cwe78_findings[0].get("severity"), "CRITICAL")

    def test_container_dict_get_negative_space(self):
        """Dictionary .get() negative space: d['bad'] is tainted but d.get('safe') must remain CLEAN"""
        code = """from flask import request
import subprocess
d = {}
d["bad"] = request.args.get("payload")
subprocess.run(d.get("safe"), shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertEqual(len(cwe78_findings), 0, f"Expected 0 CWE-78 findings for safe dict .get(), got {len(cwe78_findings)}")

    def test_tuple_unpacking_taint(self):
        """Tuple unpacking tainted variable: safe_val, bad_val = 'ls', payload; subprocess.run(bad_val)"""
        code = """from flask import request
import subprocess
safe_val, bad_val = "ls", request.args.get("payload")
subprocess.run(bad_val, shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1, "Expected CWE-78 finding for tuple unpacking tainted variable")
        self.assertEqual(cwe78_findings[0].get("severity"), "CRITICAL")

    def test_tuple_unpacking_negative_space(self):
        """Tuple unpacking safe variable (negative space): subprocess.run(safe_val) must NOT be flagged"""
        code = """from flask import request
import subprocess
safe_val, bad_val = "ls", request.args.get("payload")
subprocess.run(safe_val, shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertEqual(len(cwe78_findings), 0, f"Expected 0 CWE-78 findings for safe tuple variable, got {len(cwe78_findings)}")

    # =========================================================================
    # Part 4: Safe Negative Aliases
    # =========================================================================

    def test_negative_safe_alias(self):
        """Safe negative alias (os.path.join) must yield 0 CWE-78 findings"""
        code = """import os, sys
join_fn = os.path.join
join_fn("safe", sys.argv[1])
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertEqual(len(cwe78_findings), 0, f"Expected 0 CWE-78 findings, got {len(cwe78_findings)}")

    # =========================================================================
    # Part 5: Field-Sensitive Container Negative Space
    # =========================================================================

    def test_container_dict_negative_space(self):
        """Field-sensitive negative space: d['safe'] must remain CLEAN even if d['bad'] is tainted"""
        code = """from flask import request
import subprocess
d = {}
d["safe"] = "ls"
d["bad"] = request.args.get("payload")
subprocess.run(d["safe"], shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertEqual(len(cwe78_findings), 0, f"Expected 0 CWE-78 findings for safe dict key, got {len(cwe78_findings)}")

    def test_container_dict_literal_negative_space(self):
        """Dict literal field-sensitive negative space: d['safe'] must remain CLEAN when initialized with literal"""
        code = """from flask import request
import subprocess
d = {"safe": "ls", "bad": request.args.get("payload")}
subprocess.run(d["safe"], shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertEqual(len(cwe78_findings), 0, f"Expected 0 CWE-78 findings for safe dict literal key, got {len(cwe78_findings)}")

    # =========================================================================
    # Part 6: Walrus Operator (:==) Taint Tracking & Negative Space
    # =========================================================================

    def test_walrus_operator_taint(self):
        """Walrus operator taint flow: if (cmd := request.args.get('cmd')): subprocess.run(cmd)"""
        code = """from flask import request
import subprocess
if (cmd := request.args.get("cmd")):
    subprocess.run(cmd, shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1, "Expected CWE-78 finding for walrus operator tainted flow")
        self.assertEqual(cwe78_findings[0].get("severity"), "CRITICAL")

    def test_walrus_operator_negative_space(self):
        """Walrus operator negative space: if (safe_cmd := 'ls'): subprocess.run(safe_cmd)"""
        code = """import subprocess
if (safe_cmd := "ls"):
    subprocess.run(safe_cmd, shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertEqual(len(cwe78_findings), 0, f"Expected 0 CWE-78 findings for safe walrus operator, got {len(cwe78_findings)}")

    # =========================================================================
    # Part 7: Modern Syntax (Ternary Expressions & Comprehensions)
    # =========================================================================

    def test_ternary_taint_true_branch(self):
        """Ternary expression taint propagation (true branch): cmd = request.args.get('cmd') if flag else 'ls'"""
        code = """from flask import request
import subprocess
cmd = request.args.get("cmd") if flag else "ls"
subprocess.run(cmd, shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1, "Expected CWE-78 finding for ternary true-branch taint")
        self.assertEqual(cwe78_findings[0].get("severity"), "CRITICAL")

    def test_ternary_taint_false_branch(self):
        """Ternary expression taint propagation (false branch): cmd = 'ls' if flag else request.args.get('cmd')"""
        code = """from flask import request
import subprocess
cmd = "ls" if flag else request.args.get("cmd")
subprocess.run(cmd, shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1, "Expected CWE-78 finding for ternary false-branch taint")
        self.assertEqual(cwe78_findings[0].get("severity"), "CRITICAL")

    def test_ternary_safe_negative(self):
        """Ternary expression negative space: cmd = 'ls' if flag else 'pwd' (0 findings)"""
        code = """import subprocess
cmd = "ls" if flag else "pwd"
subprocess.run(cmd, shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertEqual(len(cwe78_findings), 0, f"Expected 0 CWE-78 findings for safe ternary branches, got {len(cwe78_findings)}")

    def test_list_comprehension_taint(self):
        """List comprehension taint tracking: cmds = [request.args.get('cmd') for _ in range(1)]; subprocess.run(cmds[0])"""
        code = """from flask import request
import subprocess
cmds = [request.args.get("cmd") for _ in range(1)]
subprocess.run(cmds[0], shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1, "Expected CWE-78 finding for list comprehension tainted element")
        self.assertEqual(cwe78_findings[0].get("severity"), "CRITICAL")

    # =========================================================================
    # Part 8: Proof Graph Integrity (Phase 2 Vectors)
    # =========================================================================

    def test_container_proof_graph_integrity(self):
        """Proof graph integrity for container finding: chronological order, no sink-as-source, JSON serializable"""
        code = """from flask import request
import subprocess
d = {}
d["cmd"] = request.args.get("payload")
subprocess.run(d["cmd"], shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1)
        finding = cwe78_findings[0]
        pg = finding.get("proof_graph")
        self.assertIsNotNone(pg, "Proof graph must not be None")
        nodes = pg.get("nodes", [])
        edges = pg.get("edges", [])
        self.assertGreaterEqual(len(nodes), 2, "Proof graph must have at least 2 nodes")
        self.assertEqual(nodes[0].get("node_type"), "SOURCE", "Node 0 must be SOURCE")
        self.assertEqual(nodes[-1].get("node_type"), "SINK", "Final node must be SINK")
        for i in range(len(nodes) - 1):
            self.assertLess(nodes[i]["step_index"], nodes[i + 1]["step_index"])
        self.assertTrue(any(n.get("node_type") in ("ASSIGNMENT", "TRANSFORM") for n in nodes[1:-1]))
        serialized = json.dumps(pg)
        self.assertIsInstance(serialized, str)

    def test_alias_proof_graph_integrity(self):
        """Proof graph integrity for aliased call: chronological order, no sink-as-source, JSON serializable"""
        code = """import sys, subprocess
exec_fn = subprocess.run
exec_fn(sys.argv[1], shell=True)
"""
        results = execute_tcs_scan({"target.py": code})
        cwe78_findings = [f for f in results.get("findings", []) if f.get("cwe") == "CWE-78"]
        self.assertTrue(len(cwe78_findings) >= 1)
        finding = cwe78_findings[0]
        pg = finding.get("proof_graph")
        self.assertIsNotNone(pg, "Proof graph must not be None")
        nodes = pg.get("nodes", [])
        self.assertGreaterEqual(len(nodes), 2)
        self.assertEqual(nodes[0].get("node_type"), "SOURCE", "Node 0 must be SOURCE")
        self.assertEqual(nodes[-1].get("node_type"), "SINK", "Final node must be SINK")
        for i in range(len(nodes) - 1):
            self.assertLess(nodes[i]["step_index"], nodes[i + 1]["step_index"])
        serialized = json.dumps(pg)
        self.assertIsInstance(serialized, str)


if __name__ == "__main__":
    unittest.main()
