"""Guards for the parse fan-out and the CWE-89 emit index: order, identity and no re-scan.

Two properties these tests exist to keep:
1. `modules` insertion order is the order later phases hand out sink ids in, so every parse policy
   (in-process, pool, sequential fallback) must produce the same keys in the same order.
2. The CWE-89 query-builder collector answers "is there already a record on this file:line" from an
   index that is maintained beside `sink_records`. It must decide exactly what the old
   whole-list re-scan decided, and it must never go back to copying the list per emit.
"""
from __future__ import annotations

import ast
import inspect
import io
import contextlib
import tempfile
import textwrap
from pathlib import Path

from tcs.parallel_scanner import BATCH_SIZE, _parse_files_sequential, parse_files_parallel
from ast_scanner import TaintTracker


ROOT = Path(__file__).resolve().parents[1]


def _quiet(fn, *args, **kwargs):
    """Run *fn* with the governor chatter swallowed; returns its value."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*args, **kwargs)


def _make_tree(count: int) -> dict[str, str]:
    """`count` distinct throwaway modules, each substantive enough to survive the fast path."""
    files: dict[str, str] = {}
    for i in range(count):
        path = f"/tmp/perf_tree/mod_{i:04d}.py"
        files[path] = f"def handler_{i}(event):\n    return process(event)\n"
    return files


class TestParsePolicyOrdering:
    """Every parse policy must agree on content AND on insertion order."""

    def test_single_worker_matches_the_sequential_fallback(self):
        files = _make_tree(BATCH_SIZE + 5)
        with_pool = _quiet(parse_files_parallel, files, 1)
        without = _parse_files_sequential(files)
        assert list(with_pool[0]) == list(without[0])
        assert with_pool[1] == without[1]
        assert with_pool[2] == without[2]
        assert with_pool[3]["parsed"] == without[3]["parsed"]

    def test_in_process_parse_never_builds_a_pool(self):
        files = _make_tree(BATCH_SIZE + 5)
        stats = _quiet(parse_files_parallel, files, 1)[3]
        assert stats["parse_mode"] == "inline", "one worker must not pay a spawn per slice"
        assert stats["workers_final"] == 1

    def test_results_are_collected_in_submission_order_not_completion_order(self):
        """`as_completed` handed back whichever worker finished first, which made the dict order
        that sink ids are derived from depend on process timing."""
        source = (ROOT / "tcs" / "parallel_scanner.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        slice_fn = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == "_parse_slice")
        called = {getattr(node.func, "id", getattr(node.func, "attr", ""))
                  for node in ast.walk(slice_fn) if isinstance(node, ast.Call)}
        assert "as_completed" not in called
        assert "zip" in called, "results must be zipped back onto the submitted file order"
        assert "_process_batch" not in source, "one pool per run, not one pool per 40 files"
        run_fn = next(node for node in tree.body
                      if isinstance(node, ast.FunctionDef) and node.name == "parse_files_parallel")
        creations = [node for node in ast.walk(run_fn)
                     if isinstance(node, ast.Call)
                     and getattr(node.func, "id", getattr(node.func, "attr", "")) == "ProcessPoolExecutor"]
        assert len(creations) == 1, f"pool must be built once, found {len(creations)}"


class TestCwe89EmitIndex:
    """The index must decide what the whole-list scan decided, without re-scanning."""

    SAME_LINE = textwrap.dedent("""
        import sqlite3

        def handler(request, user_id, table):
            conn = sqlite3.connect("app.db")
            cur = conn.cursor()
            cur.execute("SELECT * FROM " + table + " WHERE id = " + user_id)
            cur.execute("DELETE FROM " + table + " WHERE id = " + user_id)
            query = "SELECT * FROM logs WHERE u = '" + user_id + "'"
            cur.execute(query)
            return cur.fetchall()
    """)

    def _tracker(self, source: str):
        tracker = TaintTracker(files={"/repo/same_line.py": source.lstrip("\n")})
        _quiet(tracker.analyze)
        return tracker

    def _cwe89_locations(self, tracker):
        return sorted((record.security_node.location.file,
                       record.security_node.location.line_start)
                      for record in tracker.sink_records
                      if record.security_node.metadata.get("cwe") == "CWE-89")

    def test_emitted_records_are_the_ordinary_cwe89_set(self):
        tracker = self._tracker(self.SAME_LINE)
        assert [line for _file, line in self._cwe89_locations(tracker)] == [6, 7, 9]

    def test_second_pass_repairs_nothing_new(self):
        """A re-run sees every record the first pass appended: an index that only knew the state at
        collector entry would re-emit records here and shift every later sink id."""
        tracker = self._tracker(self.SAME_LINE)
        before = self._cwe89_locations(tracker)
        ids_before = [record.security_node.id for record in tracker.sink_records]
        _quiet(tracker._collect_cwe89_driver_querybuilder_findings)
        assert self._cwe89_locations(tracker) == before
        assert [record.security_node.id for record in tracker.sink_records] == ids_before

    def test_emit_path_does_not_copy_the_sink_list(self):
        source = inspect.getsource(TaintTracker._collect_cwe89_driver_querybuilder_findings)
        emit_start = source.index("def _emit89")
        emit_body = source[emit_start:source.index("# P1 edge-repair", emit_start)] \
            if "# P1 edge-repair" in source[emit_start:] else source[emit_start:]
        assert "list(self.sink_records)" not in emit_body, \
            "per-emit copies of the growing sink list are the quadratic cost under test"
        assert "cwe89_by_location" in emit_body
        # The index is kept in step with the list at the one place the list grows.
        assert "cwe89_by_location.setdefault" in emit_body


class TestMemoryBudget:
    def test_parse_fanout_stays_light_on_a_small_tree(self):
        import psutil
        files = _make_tree(BATCH_SIZE + 5)
        before = psutil.Process().memory_info().rss
        _quiet(parse_files_parallel, files, 1)
        growth_mb = (psutil.Process().memory_info().rss - before) / (1024 ** 2)
        assert growth_mb < 40, f"parse grew RSS by {growth_mb:.1f} MB"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
