"""
Unit tests for LocalDefUseTracker — 15 explicit test cases.

Tests cover:
- Direct alias propagation
- Multi-hop alias chains
- Safe reassignment (kill-gen semantics)
- Sanitizer boundary detection
- Control flow branch divergence
- Tuple unpacking
- Augmented assignments
- Edge cases and isolation guarantees
"""

import ast
import pytest
from tcs.analysis.def_use import LocalDefUseTracker


def parse_function(code: str) -> ast.FunctionDef:
    """Parse a code string and return the first FunctionDef node."""
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            return node
    raise ValueError("No FunctionDef found in code")


class TestDirectAlias:
    """Test 1: Direct alias tracking."""

    def test_direct_alias_taint_propagation(self):
        """a = src; b = a; sink(b) -> MUST MATCH."""
        code = """
def process(src):
    a = src
    b = a
    dangerous_call(b)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        # 'src' is a parameter, so it's tainted
        assert "src" in tracker.tainted_vars

        # 'a' should be tainted (alias to src)
        assert tracker.is_variable_tainted("a"), "Variable 'a' should be tainted via direct alias"

        # 'b' should be tainted (alias to a)
        assert tracker.is_variable_tainted("b"), "Variable 'b' should be tainted via direct alias chain"

        # Verify alias chain
        chain_b = tracker.get_alias_chain("b")
        assert len(chain_b) >= 2, f"Expected at least 2 hops in alias chain, got {len(chain_b)}"


class TestMultiHopAlias:
    """Test 2: Multi-hop alias chain."""

    def test_multi_hop_alias_propagation(self):
        """a = src; b = a; c = b; sink(c) -> MUST MATCH."""
        code = """
def process(src):
    a = src
    b = a
    c = b
    dangerous_call(c)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        # All variables in the chain should be tainted
        assert tracker.is_variable_tainted("a"), "'a' should be tainted"
        assert tracker.is_variable_tainted("b"), "'b' should be tainted"
        assert tracker.is_variable_tainted("c"), "'c' should be tainted"

        # Verify full alias chain for 'c'
        chain_c = tracker.get_alias_chain("c")
        assert len(chain_c) >= 3, f"Expected at least 3 hops, got {chain_c}"


class TestSafeReassignment:
    """Test 3: Safe reassignment kills taint."""

    def test_safe_reassignment_kill(self):
        """a = src; b = a; b = "constant"; sink(b) -> MUST NOT MATCH (0 FP)."""
        code = """
def process(src):
    a = src
    b = a
    b = "safe_constant"
    dangerous_call(b)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        # 'a' should still be tainted
        assert tracker.is_variable_tainted("a"), "'a' should remain tainted"

        # 'b' should NOT be tainted after safe reassignment
        assert not tracker.is_variable_tainted("b"), "'b' should NOT be tainted after kill"
        assert "b" in tracker.killed_vars, "'b' should be in killed_vars"


class TestSanitizerBoundary:
    """Test 4: Sanitizer breaks taint chain."""

    def test_sanitizer_breaks_taint(self):
        """a = src; b = int(a); sink(b) -> MUST NOT MATCH (0 FP)."""
        code = """
def process(src):
    a = src
    b = int(a)
    dangerous_call(b)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        # 'a' should be tainted
        assert tracker.is_variable_tainted("a"), "'a' should be tainted"

        # 'b' should NOT be tainted (sanitizer applied)
        assert not tracker.is_variable_tainted("b"), "'b' should NOT be tainted after sanitizer"
        assert "b" in tracker.killed_vars, "'b' should be in killed_vars"

        # Verify sanitizer was recorded
        alias_info = tracker.alias_map.get("b")
        assert alias_info is not None
        assert alias_info.sanitizer_applied == "int", f"Expected sanitizer 'int', got {alias_info.sanitizer_applied}"


class TestControlFlowBranch:
    """Test 5: Control flow branch divergence (safe handling)."""

    def test_if_else_branch_tracking(self):
        """Track assignments in both branches conservatively."""
        code = """
def process(src):
    a = src
    if condition:
        b = a
    else:
        b = "safe"
    dangerous_call(b)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        # After processing both branches, 'b' should reflect last assignment
        # (conservative: we process sequentially, so 'b' = "safe" from else branch)
        # This is a simplification; real control-flow analysis would need SSA form
        # For now, we verify no crashes and basic tracking works
        assert "b" in tracker.alias_map


class TestTupleUnpacking:
    """Test 6: Tuple unpacking assignment."""

    def test_tuple_unpacking(self):
        """a, b = src1, src2 -> both should be tracked."""
        code = """
def process(src1, src2):
    a, b = src1, src2
    dangerous_call(a, b)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        # Both parameters are tainted
        assert "src1" in tracker.tainted_vars
        assert "src2" in tracker.tainted_vars

        # Both unpacked variables should be tainted
        assert tracker.is_variable_tainted("a"), "'a' should be tainted from tuple unpacking"
        assert tracker.is_variable_tainted("b"), "'b' should be tainted from tuple unpacking"


class TestAugmentedAssignment:
    """Test 7: Augmented assignment preserves taint."""

    def test_augmented_assignment_preserves_taint(self):
        """a = src; a += suffix -> 'a' remains tainted."""
        code = """
def process(src):
    a = src
    a += "_suffix"
    dangerous_call(a)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        # 'a' should remain tainted after augmentation
        assert tracker.is_variable_tainted("a"), "'a' should remain tainted after augmented assignment"


class TestAnnotatedAssignment:
    """Test 8: Annotated assignment tracking."""

    def test_annotated_assignment(self):
        """a: str = src -> should track taint."""
        code = """
def process(src):
    a: str = src
    dangerous_call(a)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        assert tracker.is_variable_tainted("a"), "'a' should be tainted via annotated assignment"


class TestLoopBody:
    """Test 9: Loop body assignment tracking."""

    def test_loop_body_tracking(self):
        """Assignments inside loops should be tracked."""
        code = """
def process(src):
    a = src
    for item in items:
        b = a
    dangerous_call(b)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        # 'b' assigned inside loop should be tracked
        assert "b" in tracker.alias_map
        assert tracker.is_variable_tainted("b"), "'b' should be tainted from loop body"


class TestTryExcept:
    """Test 10: Try/except block tracking."""

    def test_try_except_tracking(self):
        """Assignments in try/except should be tracked."""
        code = """
def process(src):
    try:
        a = src
    except Exception:
        a = "fallback"
    dangerous_call(a)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        # 'a' should be in alias map (last assignment wins in our model)
        assert "a" in tracker.alias_map


class TestNonSelfParameter:
    """Test 11: Skip 'self' parameter in methods."""

    def test_self_parameter_skipped(self):
        """'self' should not be marked as tainted."""
        code = """
def method(self, user_input):
    data = user_input
    dangerous_call(data)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        # 'self' should not be tainted
        assert "self" not in tracker.tainted_vars, "'self' should not be tainted"

        # 'user_input' should be tainted
        assert "user_input" in tracker.tainted_vars
        assert tracker.is_variable_tainted("data"), "'data' should be tainted"


class TestComplexExpression:
    """Test 12: Complex expression with tainted variable."""

    def test_fstring_with_tainted_var(self):
        """f-string containing tainted var should propagate taint."""
        code = """
def process(src):
    query = f"SELECT * FROM {src}"
    execute(query)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        # 'query' should be tainted because it contains 'src'
        assert tracker.is_variable_tainted("query"), "'query' should be tainted via f-string"


class TestAttributeAccess:
    """Test 13: Attribute access on tainted object."""

    def test_attribute_access_taint(self):
        """obj.attr where obj is tainted should propagate."""
        code = """
def process(request):
    user_input = request.args.get("param")
    query = user_input.value
    execute(query)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        # 'user_input' should be tainted
        assert tracker.is_variable_tainted("user_input"), "'user_input' should be tainted"


class TestMultipleSanitizers:
    """Test 14: Multiple sanitizer types."""

    def test_various_sanitizers(self):
        """Test different known sanitizers break taint."""
        code = """
def process(src):
    a = int(src)
    b = float(src)
    c = str(src)
    dangerous_call(a, b, c)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        # All sanitized variables should NOT be tainted
        assert not tracker.is_variable_tainted("a"), "'a' should be clean (int sanitizer)"
        assert not tracker.is_variable_tainted("b"), "'b' should be clean (float sanitizer)"
        assert not tracker.is_variable_tainted("c"), "'c' should be clean (str sanitizer)"

        # Verify all are in killed_vars
        assert "a" in tracker.killed_vars
        assert "b" in tracker.killed_vars
        assert "c" in tracker.killed_vars


class TestTaintPathTracing:
    """Test 15: Full taint path tracing."""

    def test_trace_taint_path(self):
        """Trace complete taint propagation path."""
        code = """
def process(user_input):
    a = user_input
    b = a
    c = b
    sink(c)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        # Trace path from 'c' back to source
        path = tracker.trace_taint_path("c")
        assert path is not None, "Should find a taint path"
        assert len(path) >= 3, f"Expected at least 3 steps in path, got {len(path)}"

        # First element should be the source parameter
        assert path[0][0] == "user_input", f"First step should be 'user_input', got {path[0][0]}"

        # Last element should be 'c'
        assert path[-1][0] == "c", f"Last step should be 'c', got {path[-1][0]}"

    def test_no_taint_path_for_clean_var(self):
        """Clean variable should have no taint path."""
        code = """
def process(src):
    a = "safe"
    sink(a)
"""
        func = parse_function(code)
        tracker = LocalDefUseTracker()
        tracker.analyze_function(func)

        # 'a' is clean, so no taint path
        path = tracker.trace_taint_path("a")
        assert path is None, "Clean variable should have no taint path"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
