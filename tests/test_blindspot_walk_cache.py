"""The blindspot stage's per-module AST caches must not outlive the module they describe.

`_module_nodes` memoises a module's whole `ast.walk`, and `_module_calls` memoises the `ast.Call`
subsequence built from it. Both are lists of live node references, so the stage releases them at the
end of every module - and, because one collector raising half-way through the list must not pin them
either, in a `finally`. That release was never asserted: a missing `pop` changes no finding, no sink
id and no order, it just pins every module's AST down at once, which is exactly what a 10k-file scan
cannot afford.

The other half is the property the bucket rests on. It is a straight filter of the cached walk, so it
keeps that walk's order and multiplicity - which is why the collectors hand out the same sink ids as
before. That safety holds only while each repointed collector rejects every non-call node as the very
first thing it does. If one ever grew a statement in front of that test, the bucket would hide nodes
from it.

Run it either way:
    python tests/test_blindspot_walk_cache.py
    python -m pytest tests/test_blindspot_walk_cache.py -q
"""
from __future__ import annotations

import ast
import contextlib
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ast_scanner import TaintTracker  # noqa: E402

SRC_PATH = ROOT / "ast_scanner.py"
SRC = SRC_PATH.read_text(encoding="utf-8")
ENGINE_TREE = ast.parse(SRC)

# Mixed node kinds on purpose: the module holds imports, assignments, a docstring, a class and names
# that the Call bucket has to discard.
MIXED_MODULE = '''import os
import subprocess

LIMIT = 4


def run(cmd):
    """Fetch a command built at runtime."""
    parts = cmd.split(" ")
    return subprocess.run(parts, shell=True, cwd=os.getcwd())


class Holder:
    def emit(self, value):
        return str(value).strip()
'''

EXPECTED_BUCKET_LOOPS = 13


def _bucket_loops() -> list:
    """Every `for ... in self._module_calls(...)` loop in the engine."""
    return [node for node in ast.walk(ENGINE_TREE)
            if isinstance(node, ast.For) and isinstance(node.iter, ast.Call)
            and isinstance(node.iter.func, ast.Attribute)
            and node.iter.func.attr == "_module_calls"]


def test_bucket_is_the_walk_order_call_subsequence_and_is_memoised():
    tree = ast.parse(MIXED_MODULE)
    walk = list(ast.walk(tree))
    tracker = TaintTracker(files={"mixed_module.py": MIXED_MODULE}, audit_all=True)
    calls = tracker._module_calls(tree)
    assert calls == [node for node in walk if isinstance(node, ast.Call)], "bucket must be the subsequence"
    assert calls is tracker._module_calls(tree), "a second request must hit the memo"
    # Replacing the walk must rebuild the bucket rather than serve the stale one.
    reversed_walk = list(reversed(walk))
    tree.__dict__["_cached_all_nodes"] = reversed_walk
    assert tracker._module_calls(tree) == [n for n in reversed_walk if isinstance(n, ast.Call)], \
        "bucket must follow the walk it was built from"


def test_each_bucket_collector_rejects_non_calls_before_anything_else():
    loops = _bucket_loops()
    assert len(loops) == EXPECTED_BUCKET_LOOPS, \
        f"expected the {EXPECTED_BUCKET_LOOPS} reviewed Call-only loops, found {len(loops)}"
    for loop in loops:
        guard = loop.body[0]
        assert isinstance(guard, ast.If) and len(guard.body) == 1 \
            and isinstance(guard.body[0], ast.Continue), \
            f"line {loop.lineno}: first statement must be a bare reject-and-continue: {ast.unparse(guard)}"
        assert f"not isinstance({loop.target.id}, ast.Call)" in ast.unparse(guard.test), \
            f"line {loop.lineno}: guard must reject non-calls: {ast.unparse(guard.test)}"


def test_bucket_release_sits_with_the_walk_release_inside_a_finally():
    """Both keys are popped in one `finally`, and that `finally` wraps the whole collector sequence."""
    def _popped_keys(body):
        keys = set()
        for node in ast.walk(ast.Module(body=body, type_ignores=[])):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "pop" and isinstance(node.func.value, ast.Attribute) \
                    and node.func.value.attr == "__dict__" \
                    and node.args and isinstance(node.args[0], ast.Constant):
                keys.add(f"{ast.unparse(node.func.value.value)}.{node.args[0].value}")
        return keys

    wanted = {"_bs_tree._cached_all_nodes", "_bs_tree._cached_node_buckets"}
    guarded = [ast.unparse(ast.Module(body=try_node.body, type_ignores=[]))
               for try_node in ast.walk(ENGINE_TREE)
               if isinstance(try_node, ast.Try) and wanted <= _popped_keys(try_node.finalbody)]
    assert len(guarded) == 1, f"exactly one finally must release both keys, found {len(guarded)}"
    assert "_collect_cwe78_subprocess_calls(" in guarded[0] \
        and "_collect_cwe319_raw_socket_cleartext(" in guarded[0], \
        "the finally must wrap the per-module collector sequence, not just the release"


def test_caches_are_released_after_a_full_analysis():
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        tracker = TaintTracker(files={"mixed_module.py": MIXED_MODULE,
                                      "second_module.py": "import os\n\nprint(os.getcwd())\n"},
                               audit_all=True)
        tracker.analyze()
    leaked = [mod for mod, tree in tracker.modules.items()
              if "_cached_all_nodes" in tree.__dict__ or "_cached_node_buckets" in tree.__dict__]
    assert leaked == [], f"per-module AST caches survived analyze(): {leaked}\n{err.getvalue()[-300:]}"


def test_a_raising_collector_still_releases_both_caches_and_propagates():
    """Half-way through the per-module sequence, the release must still happen and the error must still leave."""
    err = io.StringIO()
    tracker = TaintTracker(files={"mixed_module.py": MIXED_MODULE}, audit_all=True)
    boom = RuntimeError("injected collector failure")
    # (tree, walk cached?, bucket cached?) captured at the instant the stage dies.
    at_raise = []

    def _raise(tree, filename, source_lines):
        at_raise.append((tree, "_cached_all_nodes" in tree.__dict__,
                         "_cached_node_buckets" in tree.__dict__))
        raise boom

    # CWE-93 is the fourth pass, so the three Call-only passes before it have filled both caches.
    tracker._collect_cwe93_header_injection = _raise
    try:
        with contextlib.redirect_stderr(err):
            tracker.analyze()
    except RuntimeError as exc:
        assert exc is boom, f"the original exception must propagate untouched, got {exc!r}"
    else:
        raise AssertionError("the injected collector failure was swallowed; analyze() must re-raise it")
    assert len(at_raise) == 1, at_raise
    tree, walk_was_cached, bucket_was_cached = at_raise[0]
    assert walk_was_cached and bucket_was_cached, \
        "the caches were never filled before the failure, so this test would prove nothing"
    leaked = [key for key in ("_cached_all_nodes", "_cached_node_buckets") if key in tree.__dict__]
    assert leaked == [], f"{leaked} survived a collector raising mid-sequence on {tree!r}"


if __name__ == "__main__":
    failures = 0
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            try:
                _fn()
                print(f"  PASS  {_name}")
            except AssertionError as exc:
                failures += 1
                print(f"  FAIL  {_name}: {exc}")
    sys.exit(1 if failures else 0)
