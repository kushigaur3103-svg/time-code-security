"""CI regression: `_is_static()` must never raise RecursionError.

The engine resolves a Name to its assigned value node and walks that expression again.
A self-referential assignment (`cmd = cmd + "ls"`) therefore visits the same nodes over
and over, which crashed GitHub Actions with `RecursionError: maximum recursion depth
exceeded` and left no SARIF artifact behind.
"""
import sys

from ast_scanner import TaintTracker


def _analyze(source: str) -> int:
    _s, sinks, _e = TaintTracker(files={"t.py": source}).analyze()
    return len(sinks)


def test_self_referential_concatenation_does_not_recurse_forever():
    assert _analyze('cmd = cmd + "ls"\neval(cmd)\n') >= 0


def test_self_referential_fstring_does_not_recurse_forever():
    assert _analyze('cmd = f"{cmd} -la"\nos.system(cmd)\n') >= 0


def test_mutually_referential_assignments_terminate():
    assert _analyze('a = b + "x"\nb = a + "y"\nos.system(a)\n') >= 0


def test_assignment_chain_longer_than_max_depth_terminates():
    source = "".join(f"v{i} = v{i + 1} + 'x'\n" for i in range(80)) + "os.system(v0)\n"
    assert _analyze(source) >= 0


def test_deeply_nested_binary_expression_terminates():
    source = 'q = "' + "x+" * 2000 + 'y"\nos.system(q)\n'
    assert _analyze(source) >= 0


def test_self_referential_container_expression_terminates():
    assert _analyze('p = [p] + [payload]\nos.system(p)\n') >= 0


def test_guarded_recursion_keeps_real_taint_detection():
    """The depth/cycle guard must not blind the engine to genuinely dynamic payloads."""
    findings_source = 'cmd = user_input + "ls"\nos.system(cmd)\n'
    _s, sinks, edges = TaintTracker(files={"t.py": findings_source}).analyze()
    by_id = {x.id: x for x in sinks}
    cwes = {
        (by_id[edge.target_id].metadata or {}).get("cwe")
        for edge in edges
        if edge.target_id in by_id
    }
    assert "CWE-78" in cwes


def test_scan_survives_default_recursion_limit():
    """Run under CI's stock limit of 1000 frames, which is what GitHub Actions uses."""
    assert sys.getrecursionlimit() >= 1000
    _analyze('cmd = cmd + "ls"\neval(cmd)\n')


def _cwe_lines(source, cwe="CWE-78"):
    """Lines carrying an edge into a sink of *cwe*, so each dataflow route is visible."""
    _s, sinks, edges = TaintTracker(files={"t.py": source}).analyze()
    by_id = {x.id: x for x in sinks}
    return sorted(
        by_id[e.target_id].location.line_start
        for e in edges
        if e.target_id in by_id and by_id[e.target_id].metadata.get("cwe") == cwe
    )


def test_second_sibling_route_into_same_helper_is_not_blocked():
    """The cycle guard is path-scoped, so a sibling call to the same helper still resolves.

    Both `wrap(...)` calls sit on one line and resolve to one callee scope, and the tainted route is
    the second one. A callee-level "already visited" set that leaked between siblings would stop at
    the clean first route and lose the payload behind the second: a false negative.
    """
    source = (
        "import os\n"
        "def wrap(v):\n"
        "    return v\n"
        "os.system(wrap('safe') + wrap(input()))\n"
    )
    assert _cwe_lines(source) == [4]


def test_distinct_call_sites_into_one_helper_are_all_reported():
    """Separate valid paths to the same function must each produce their own finding."""
    source = (
        "import os\n"
        "def run(c):\n"
        "    os.system(c)\n"
        "run(input() + ' ls')\n"
        "run(os.environ['CMD'])\n"
    )
    # Line 3 is the sink inside the helper, lines 4 and 5 are the two routes into it.
    assert _cwe_lines(source) == [3, 4, 5]
