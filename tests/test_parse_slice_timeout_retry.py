"""WS3: a parse that finished after its timeout must not be thrown away for free.

`_parse_slice` collects slice results in file order; a future that reports TimeoutError
may still complete while later files of the same slice are being collected. The bounded
retry takes those finished results at ZERO added wall time (it only accepts `future.done()`)
and keeps the original `[WARN] ... timeout skipped` policy for anything still running.
No timeout value is changed and no waiting is added.
"""
from __future__ import annotations

import sys

from tcs.parallel_scanner import _parse_slice


class _FakeFuture:
    """Scripted future: the first timed `result()` of a `times_out` future always raises
    TimeoutError (that is the check the slice loop makes); whether it is subsequently
    `done()` is what separates a recoverable file from a genuinely-stuck worker."""

    def __init__(self, value=None, *, times_out=False, done_after_timeout=True, exc=None):
        self._value = value
        self._exc = exc
        self._times_out = times_out
        self._first = True
        self._finished = (not times_out) or done_after_timeout

    def result(self, timeout=None):
        if self._times_out and self._first and timeout is not None:
            self._first = False
            raise TimeoutError
        if self._exc is not None:
            raise self._exc
        return self._value

    def done(self):
        return self._finished


class _FakeExecutor:
    def __init__(self, futures):
        self._futures = iter(futures)

    def submit(self, fn, arg):
        return next(self._futures)


def _ok(path):
    return {"filepath": path, "mod_name": "m", "tree": "T", "skipped_fast_path": False,
            "error": None}


def _run(futures, batch):
    return _parse_slice(_FakeExecutor(futures), batch, free_ram_mb=999_999)


def test_timed_out_but_done_future_is_recovered(capsys):
    late = _FakeFuture(_ok("b.py"), times_out=True, done_after_timeout=True)
    futures = [_FakeFuture(_ok("a.py")), late]
    results = _run(futures, [("a.py", "x"), ("b.py", "y")])
    assert [r["filepath"] for r in results] == ["a.py", "b.py"]
    assert results[1]["tree"] == "T" and results[1]["error"] is None
    err = capsys.readouterr().err
    assert "timeout skipped" not in err
    assert "Recovered timed-out parse: b.py" in err


def test_still_running_future_keeps_the_skip_policy(capsys):
    stuck = _FakeFuture(times_out=True, done_after_timeout=False)
    results = _run([_FakeFuture(_ok("a.py")), stuck], [("a.py", "x"), ("b.py", "y")])
    assert results[1]["filepath"] == "b.py"
    assert results[1]["tree"] is None
    assert results[1]["error"].startswith("Timeout after ")
    assert "File analysis timeout skipped: b.py" in capsys.readouterr().err


def test_exception_path_still_reparses_in_parent(capsys):
    dead = _FakeFuture(exc=RuntimeError("worker died"))
    results = _run([dead, _FakeFuture(_ok("b.py"))], [("a.py", "src"), ("b.py", "y")])
    assert results[0]["filepath"] == "a.py"
    # re-parsed in the parent from the batch source, exactly like before
    assert results[0]["tree"] is not None or results[0].get("error")
    assert "worker lost" in capsys.readouterr().err


def test_done_future_raising_worker_loss_reparses_in_parent(capsys):
    """Completed-but-errored future: the pre-existing lost-worker policy must apply."""
    from concurrent.futures.process import BrokenProcessPool
    src = "import os\n\n\ndef h(cmd):\n    os.system(cmd)\n"
    dead_late = _FakeFuture(times_out=True, exc=BrokenProcessPool("worker pipe closed"))
    results = _run([dead_late, _FakeFuture(_ok("b.py"))], [("a.py", src), ("b.py", "y")])
    err = capsys.readouterr().err
    assert "worker lost for a.py (BrokenProcessPool); re-parsing in parent" in err
    assert "Recovered timed-out parse" not in err
    assert "timeout skipped" not in err
    # recovered by the parent from the batch's own source: a real tree, not an error entry
    assert results[0]["filepath"] == "a.py" and results[0]["tree"] is not None
    assert results[0]["error"] in (None, "") or "Timeout" not in str(results[0]["error"])
    # ordering preserved, exactly one entry per file, no duplicate emission
    assert [r["filepath"] for r in results] == ["a.py", "b.py"]


def test_parser_failure_via_worker_loss_path_still_fails_closed(capsys):
    """`_parse_here` may itself find a genuine SyntaxError - that must stay an error entry,
    never a silently successful parse."""
    dead_late = _FakeFuture(times_out=True, exc=RuntimeError("transport broke"))
    results = _run([dead_late], [("broken_syntax.py", "def (:")])
    assert len(results) == 1
    assert results[0]["filepath"] == "broken_syntax.py"
    assert results[0]["tree"] is None and results[0]["error"]


def test_file_order_is_preserved_with_mixed_outcomes():
    late = _FakeFuture(_ok("c.py"), times_out=True, done_after_timeout=True)
    stuck = _FakeFuture(times_out=True, done_after_timeout=False)
    futures = [_FakeFuture(_ok("a.py")), stuck, late, _FakeFuture(_ok("d.py"))]
    results = _run(futures, [(p, "s") for p in ["a.py", "b.py", "c.py", "d.py"]])
    assert [r["filepath"] for r in results] == ["a.py", "b.py", "c.py", "d.py"]
    assert results[1]["tree"] is None and results[2]["tree"] is not None
