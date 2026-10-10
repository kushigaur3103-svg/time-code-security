"""CI regression: the O(1) sink dedup index must answer exactly like the linear scan it replaced.

`_add_blindspot_sink` dedups on `(location.file, location.line_start, metadata["cwe"])`. An
incremental index may only replace that scan if two properties hold, and both are locked here:

1. First-match semantics: when several records share a key, the earliest one in list order wins.
2. Invalidation: any mutation that can retire a record -- a filter rebind, a shrink, or a shrink
   refilled to the same length -- must drop the keys that record set.
"""
import ast as _ast

import pytest

from ast_scanner import NodeType, SecurityNode, SinkRecord, TaintTracker, location


def _node(file, line, cwe):
    """A sink node whose location reports `line` (Location is frozen, so place the call there)."""
    stmt = _ast.parse("\n" * (line - 1) + "f()").body[0].value
    return SecurityNode(
        id="SNK-X", node_type=NodeType.SINK, symbol="s", operation="OP",
        location=location(stmt, file),
        metadata={"cwe": cwe} if cwe is not None else {},
    )


def _record(file, line, cwe):
    return SinkRecord(node=None, security_node=_node(file, line, cwe), lineno=line, scope_id="x")


def _scan(records, file, line, cwe):
    """The replaced linear scan, verbatim."""
    return next((r.security_node for r in records
                 if r.security_node.location.file == file
                 and r.security_node.location.line_start == line
                 and r.security_node.metadata.get("cwe") == cwe), None)


def _tracker():
    return TaintTracker(files={"a.py": "x = 1\n"})


def _assert_matches_index(tracker, file, line, cwe):
    assert tracker._sink_index_find(file, line, cwe) is _scan(
        tracker.sink_records, file, line, cwe)


def test_first_record_for_a_key_wins():
    t = _tracker()
    first, second = _record("a.py", 2, "CWE-78"), _record("a.py", 2, "CWE-78")
    t.sink_records.extend([first, second])
    assert t._sink_index_find("a.py", 2, "CWE-78") is first.security_node
    _assert_matches_index(t, "a.py", 2, "CWE-78")


@pytest.mark.parametrize("cwe", ["CWE-78", "CWE-22", None])
def test_key_is_file_line_and_cwe(cwe):
    t = _tracker()
    t.sink_records.extend([_record("a.py", 2, "CWE-78"), _record("a.py", 2, "CWE-22"),
                           _record("b.py", 2, "CWE-78")])
    if cwe is None:
        # Documented divergence: CWE-less records are not indexed, and no `_add_blindspot_sink`
        # call site queries with cwe=None.
        assert t._sink_index_find("a.py", 2, None) is None
        return
    assert t._sink_index_find("a.py", 2, cwe) is _scan(t.sink_records, "a.py", 2, cwe)
    assert t._sink_index_find("a.py", 3, cwe) is None


def test_rebind_that_drops_the_key_owner_clears_the_key():
    t = _tracker()
    t.sink_records.extend([_record("a.py", 2, "CWE-78"), _record("a.py", 2, "CWE-22")])
    assert t._sink_index_find("a.py", 2, "CWE-78") is not None
    # The six prune sites all rebind like this: `self.sink_records = [r for r in ... if ...]`.
    t.sink_records = [r for r in t.sink_records
                      if r.security_node.metadata.get("cwe") != "CWE-78"]
    assert t._sink_index_find("a.py", 2, "CWE-78") is None
    assert t._sink_index_find("a.py", 2, "CWE-22") is not None


def test_in_place_shrink_refilled_to_the_same_length_is_not_left_stale():
    """A clear() plus appends restores the length, so a length check alone would miss it."""
    t = _tracker()
    t.sink_records.extend([_record("a.py", 2, "CWE-78"), _record("a.py", 2, "CWE-22")])
    assert t._sink_index_find("a.py", 2, "CWE-78") is not None
    t.sink_records.clear()
    t.sink_records.extend([_record("c.py", 1, "CWE-78"), _record("c.py", 1, "CWE-78")])
    assert t._sink_index_find("a.py", 2, "CWE-78") is None
    assert t._sink_index_find("c.py", 1, "CWE-78") is t.sink_records[0].security_node


def test_head_pop_followed_by_append_keeps_every_answer_equal_to_the_scan():
    t = _tracker()
    t.sink_records.extend([_record("a.py", 1, "CWE-78"), _record("b.py", 2, "CWE-78"),
                           _record("c.py", 3, "CWE-78")])
    for lookup in [("a.py", 1), ("c.py", 3)]:
        _assert_matches_index(t, lookup[0], lookup[1], "CWE-78")
    t.sink_records.pop(0)
    t.sink_records.append(_record("d.py", 4, "CWE-78"))
    for file, line in [("a.py", 1), ("b.py", 2), ("c.py", 3), ("d.py", 4)]:
        _assert_matches_index(t, file, line, "CWE-78")


def test_blindspot_sink_is_still_deduplicated_by_the_index():
    """Behaviour lock for the caller: a second sink on the same line+CWE is not added twice."""
    t = _tracker()
    tree = _ast.parse("import os\nos.system('ls')\n")
    call = tree.body[1].value
    before = len(t.sink_records)
    t._add_blindspot_sink(call, "a.py", "CWE-78", "OS_COMMAND", "CMD_INJECTION",
                          "msg", "SRC-X")
    t._add_blindspot_sink(call, "a.py", "CWE-78", "OS_COMMAND", "CMD_INJECTION",
                          "msg", "SRC-X")
    assert len(t.sink_records) == before + 1


def test_reuse_existing_adopts_an_unreached_sink_on_the_same_line():
    t = _tracker()
    tree = _ast.parse("import os\nos.system('ls')\n")
    call = tree.body[1].value
    t._add_blindspot_sink(call, "a.py", "CWE-78", "OS_COMMAND", "CMD_INJECTION",
                          "first message", "SRC-X")
    adopted = t.sink_records[-1].security_node
    t._add_blindspot_sink(call, "a.py", "CWE-78", "OTHER_OP", "CATEGORY",
                          "second message", "SRC-Y", reuse_existing=True)
    assert len(t.sink_records) == 1
    assert adopted.metadata["message"] == "second message"
