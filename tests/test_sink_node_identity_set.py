"""Equivalence locks for `_sink_node_unrecorded`, the O(1) replacement of the 18532 linear scan.

The sink-detection re-scan of `raw_calls` guarded its direct branch with

    elif not any(r.node is call_node for r in self.sink_records):

which walked the whole record list once per call site -- ~46 k records per call on a 231,815-call
repo, i.e. the entire 628.66 s of that profiled section. The replacement keeps a node-identity set.

Two things must hold, and both are tested: the set must answer *exactly* what the scan answered
(including after the list is appended to, rebound, pruned or refilled), and running the real engine
with either implementation must produce the same sink records in the same order.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from ast_scanner import TaintTracker

REPO = Path(__file__).resolve().parent.parent
_REAL_UNRECORDED = TaintTracker._sink_node_unrecorded


class _Node:
    """Stand-in for an AST node: identity is all the index ever looks at."""

    def __init__(self, tag):
        self.tag = tag


class _Record:
    def __init__(self, node):
        self.node = node


def _linear_scan(tracker, node):
    """The exact expression that used to sit at line 18532."""
    return not any(r.node is node for r in tracker.sink_records)


@pytest.fixture
def tracker():
    instance = TaintTracker(files={"seed.py": "import os\n"})
    instance.sink_records = []
    return instance


def test_absent_node_is_unrecorded_and_present_node_is_not(tracker):
    a, b = _Node("a"), _Node("b")
    tracker.sink_records = [_Record(a)]
    assert tracker._sink_node_unrecorded(b) is True
    assert tracker._sink_node_unrecorded(a) is False


def test_records_appended_after_the_first_query_are_absorbed(tracker):
    records = [_Node(i) for i in range(5)]
    tracker.sink_records = [_Record(records[0])]
    assert tracker._sink_node_unrecorded(records[0]) is False
    for node in records[1:]:
        tracker.sink_records.append(_Record(node))
    for node in records:
        assert tracker._sink_node_unrecorded(node) is False
    assert tracker._sink_node_unrecorded(_Node("never")) is True


def test_rebind_of_the_list_does_not_leave_retired_nodes_marked(tracker):
    a, b = _Node("a"), _Node("b")
    tracker.sink_records = [_Record(a), _Record(b)]
    assert tracker._sink_node_unrecorded(a) is False
    # `self.sink_records = [r for r in ... if ...]` -- the pattern at ast_scanner.py:14819.
    tracker.sink_records = [_Record(b)]
    assert tracker._sink_node_unrecorded(a) is True
    assert tracker._sink_node_unrecorded(b) is False


def test_in_place_shrink_refilled_to_the_same_length_is_not_left_stale(tracker):
    a, b = _Node("a"), _Node("b")
    fresh = _Node("b-fresh")
    tracker.sink_records = [_Record(a), _Record(b)]
    assert tracker._sink_node_unrecorded(a) is False
    tracker.sink_records.pop(1)
    tracker.sink_records.append(_Record(fresh))
    assert len(tracker.sink_records) == 2
    assert tracker._sink_node_unrecorded(b) is True
    assert tracker._sink_node_unrecorded(fresh) is False


def test_clear_then_refill_to_the_same_length_is_not_left_stale(tracker):
    a, b = _Node("a"), _Node("b")
    tracker.sink_records = [_Record(a), _Record(b)]
    assert tracker._sink_node_unrecorded(a) is False
    tracker.sink_records.clear()
    tracker.sink_records.append(_Record(_Node("x")))
    tracker.sink_records.append(_Record(_Node("y")))
    assert tracker._sink_node_unrecorded(a) is True


def test_the_same_node_recorded_twice_still_counts_as_recorded(tracker):
    # The CWE-295 twin path appends a second record for one node, so duplicates must be normal.
    node = _Node("dup")
    tracker.sink_records = [_Record(node), _Record(node)]
    assert tracker._sink_node_unrecorded(node) is False
    tracker.sink_records.pop()
    assert tracker._sink_node_unrecorded(node) is False
    tracker.sink_records.pop()
    assert tracker._sink_node_unrecorded(node) is True


def test_real_ast_nodes_are_hashable_and_consistent_with_the_scan(tracker):
    tree = ast.parse("import os\nos.system('ls')\nopen('/etc/passwd')\n")
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    assert len(calls) == 2
    tracker.sink_records = [_Record(calls[0])]
    assert tracker._sink_node_unrecorded(calls[1]) == _linear_scan(tracker, calls[1])
    assert tracker._sink_node_unrecorded(calls[0]) == _linear_scan(tracker, calls[0])


def _small_corpus_files():
    files = {}
    for directory in ("fixtures", "tests/fixtures", "apps"):
        for path in sorted((REPO / directory).rglob("*.py")):
            if any(part in {".git", "__pycache__"} for part in path.parts):
                continue
            try:
                files[path.as_posix()] = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if len(files) >= 25:
                return files
    return files


def _record_signature(tracker):
    return [
        (record.lineno, record.scope_id, record.security_node.id,
         record.security_node.location.file, record.security_node.metadata.get("cwe"))
        for record in tracker.sink_records
    ]


def _analyze_with(unrecorded_impl):
    """Run the real pipeline with a chosen dedup implementation, then restore the shipped one."""
    TaintTracker._sink_node_unrecorded = unrecorded_impl
    try:
        instance = TaintTracker(files=dict(_small_corpus_files()))
        instance.analyze()
        return _record_signature(instance), len(instance.edges)
    finally:
        TaintTracker._sink_node_unrecorded = _REAL_UNRECORDED


def _linear_scan_impl(self, node):
    return _linear_scan(self, node)


def test_whole_engine_produces_identical_sink_records_with_the_old_linear_scan():
    """End-to-end drift proof: restore the O(N) scan, run the real pipeline, compare everything."""
    files = _small_corpus_files()
    assert len(files) >= 10, "corpus too small to exercise the dedup branch"
    with_set, edges_with_set = _analyze_with(_REAL_UNRECORDED)
    with_scan, edges_with_scan = _analyze_with(_linear_scan_impl)
    assert with_set, "the corpus produced no sink records at all"
    assert with_set == with_scan
    assert edges_with_set == edges_with_scan
