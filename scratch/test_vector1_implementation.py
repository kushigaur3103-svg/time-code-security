import sys
import os
import unittest

sys.path.insert(0, os.getcwd())

import ast_scanner
from ast_scanner import TaintTracker

class TestVector1Hardening(unittest.TestCase):

    def test_case_1_numeric_cast_sanitizer_clean(self):
        """1. val = int(request.args.get('id')) -> cursor.execute(val): Must produce 0 findings (Clean)."""
        code = """
def main():
    val = int(request.args.get("id"))
    cursor.execute(val)
"""
        tracker = TaintTracker(source=code, file_path="case1_clean.py")
        sources, sinks, edges = tracker.analyze()
        self.assertEqual(len(edges), 0, f"Expected 0 findings for int() cast, got {len(edges)}: {edges}")

    def test_case_1b_float_math_floor_clean(self):
        """1b. Additional numeric casts: float(), math.floor() must also produce 0 findings."""
        code = """
import math
def main():
    v1 = float(request.args.get("f"))
    v2 = math.floor(float(request.args.get("g")))
    cursor.execute(v1)
    cursor.execute(v2)
"""
        tracker = TaintTracker(source=code, file_path="case1b_clean.py")
        sources, sinks, edges = tracker.analyze()
        self.assertEqual(len(edges), 0, f"Expected 0 findings for float/math.floor, got {len(edges)}: {edges}")

    def test_case_2_str_cast_preserves_taint_confirmed(self):
        """2. val = str(request.args.get('id')) -> cursor.execute(val): Must produce CONFIRMED finding (Taint kept)."""
        code = """
def main():
    val = str(request.args.get("id"))
    cursor.execute(val)
"""
        tracker = TaintTracker(source=code, file_path="case2_str.py")
        sources, sinks, edges = tracker.analyze()
        self.assertEqual(len(edges), 1, f"Expected 1 finding for str() wrapper, got {len(edges)}")
        edge = edges[0]
        self.assertEqual(edge.kind, "CONFIRMED_DATA_FLOW", f"Expected CONFIRMED_DATA_FLOW, got {edge.kind}")
        self.assertEqual(edge.confidence, 1.0, f"Expected confidence 1.0, got {edge.confidence}")
        self.assertEqual(edge.source_id, "SRC-001", f"Expected source_id SRC-001, got {edge.source_id}")

    def test_case_3_class_attribute_taint_preserved_confirmed(self):
        """3. self.data = request.args.get('x') in method A -> cursor.execute(self.data) in method B: Must produce CONFIRMED finding with src=SRC-001."""
        code = """
class Handler:
    def method_a(self):
        self.data = request.args.get("x")

    def method_b(self):
        cursor.execute(self.data)
"""
        tracker = TaintTracker(source=code, file_path="case3_class_taint.py")
        sources, sinks, edges = tracker.analyze()
        self.assertEqual(len(edges), 1, f"Expected 1 finding for class attribute taint, got {len(edges)}")
        edge = edges[0]
        self.assertEqual(edge.kind, "CONFIRMED_DATA_FLOW", f"Expected CONFIRMED_DATA_FLOW, got {edge.kind}")
        self.assertEqual(edge.confidence, 1.0, f"Expected confidence 1.0, got {edge.confidence}")
        self.assertEqual(edge.source_id, "SRC-001", f"Expected source_id SRC-001, got {edge.source_id}")
        self.assertIn("self.data", edge.transform)

    def test_case_4_class_attribute_clean_literal(self):
        """4. self.data = 'SELECT 1' in method A -> cursor.execute(self.data) in method B: Must produce 0 findings (Clean literal)."""
        code = """
class Handler:
    def method_a(self):
        self.data = "SELECT 1"

    def method_b(self):
        cursor.execute(self.data)
"""
        tracker = TaintTracker(source=code, file_path="case4_class_clean.py")
        sources, sinks, edges = tracker.analyze()
        self.assertEqual(len(edges), 0, f"Expected 0 findings for clean literal class attribute, got {len(edges)}: {edges}")

    def test_case_5_init_clean_default_with_tainted_setter_union_rule(self):
        """5. Default in __init__ is clean string, but method sets tainted input: Must produce CONFIRMED finding (Union rule)."""
        code = """
class Handler:
    def __init__(self):
        self.data = "SELECT 1"

    def set_data(self):
        self.data = request.args.get("x")

    def run(self):
        cursor.execute(self.data)
"""
        tracker = TaintTracker(source=code, file_path="case5_union.py")
        sources, sinks, edges = tracker.analyze()
        self.assertEqual(len(edges), 1, f"Expected 1 finding under union rule, got {len(edges)}")
        edge = edges[0]
        self.assertEqual(edge.kind, "CONFIRMED_DATA_FLOW", f"Expected CONFIRMED_DATA_FLOW, got {edge.kind}")
        self.assertEqual(edge.confidence, 1.0, f"Expected confidence 1.0, got {edge.confidence}")
        self.assertEqual(edge.source_id, "SRC-001", f"Expected source_id SRC-001, got {edge.source_id}")

    def test_case_6_caller_callee_chain_and_return(self):
        """6. Caller-to-callee chain (2-hop) and Callee return: Must remain 100% functional (conf=1.0)."""
        # 6a: 2-hop caller-to-callee chain
        code_chain = """
def sink_func(z):
    cursor.execute(z)

def mid_func(y):
    sink_func(y)

def top_func():
    x = request.args.get("x")
    mid_func(x)
"""
        tracker_chain = TaintTracker(source=code_chain, file_path="case6_chain.py")
        sources, sinks, edges_chain = tracker_chain.analyze()
        self.assertEqual(len(edges_chain), 1, f"Expected 1 finding for 2-hop chain, got {len(edges_chain)}")
        self.assertEqual(edges_chain[0].kind, "CONFIRMED_DATA_FLOW")
        self.assertEqual(edges_chain[0].confidence, 1.0)
        self.assertEqual(edges_chain[0].source_id, "SRC-001")

        # 6b: Callee return propagation
        code_return = """
def source_helper():
    return request.args.get("id")

def main():
    val = source_helper()
    cursor.execute(val)
"""
        tracker_ret = TaintTracker(source=code_return, file_path="case6_return.py")
        sources, sinks, edges_ret = tracker_ret.analyze()
        self.assertEqual(len(edges_ret), 1, f"Expected 1 finding for return propagation, got {len(edges_ret)}")
        self.assertEqual(edges_ret[0].kind, "CONFIRMED_DATA_FLOW")
        self.assertEqual(edges_ret[0].confidence, 1.0)
        self.assertEqual(edges_ret[0].source_id, "SRC-001")

if __name__ == "__main__":
    unittest.main(verbosity=2)
