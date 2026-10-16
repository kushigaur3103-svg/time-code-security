"""WS3: a parse that finished after its timeout must not be thrown away for free.

`_parse_slice` collects slice results in file order; a future that reports TimeoutError
may still complete while later files of the same slice are being collected. The bounded
retry takes those finished results at ZERO added wall time (it only accepts `future.done()`)
and keeps the original `[WARN] ... timeout skipped` policy for anything still running.
No timeout value is changed and no waiting is added.

Blocker 2 adds the other half of the same story: the budget handed to `future.result()` now
excludes executor queue wait, so a sub-millisecond file queued behind its slice neighbours is
no longer killed, and the skip record reports the real numbers instead of "(low memory)".
"""
from __future__ import annotations

import sys

import pytest

from tcs.parallel_scanner import (
    PER_FILE_TIMEOUT_S,
    QUEUE_BUDGET_SLACK_S,
    _parse_slice,
)


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


class _BudgetSpy:
    """Future that never finishes, but records the `timeout=` the slice loop asked for."""

    def __init__(self, sink):
        self._sink = sink

    def result(self, timeout=None):
        self._sink.append(timeout)
        raise TimeoutError

    def done(self):
        return False


def _budgets(count, workers, free_ram_mb=999_999):
    """The per-file `result(timeout=…)` budget for file indices 0..count-1 at W workers."""
    seen = []
    batch = [(f"f{i}.py", "x") for i in range(count)]
    _parse_slice(_FakeExecutor([_BudgetSpy(seen) for _ in batch]), batch,
                 free_ram_mb=free_ram_mb, workers=workers)
    return seen


def test_queue_depth_is_part_of_the_budget_not_of_the_parse_limit():
    """The bug: `result(timeout=4.0)` also counted the time the file sat in the queue, so a
    0.8 ms file was killed for waiting behind its neighbours. The budget now scales with the
    number of predecessors that must finish first (`idx // workers`) and nothing else."""
    budgets = _budgets(9, workers=4)

    def near(value):
        # The deadline is measured against `perf_counter`, so each recorded budget is the nominal
        # value minus the microseconds the loop took to get here.
        return pytest.approx(value, abs=0.05)

    # slack is 1.0s on top of the 4.0s base, so the first four files (queue depth 1) each get 5.0s.
    assert budgets[:4] == [near(5.0)] * 4, budgets
    # files 4..7 are the second row of the queue: one predecessor set must clear first.
    assert budgets[4:8] == [near(9.0)] * 4, budgets
    # file 8 is third in its row: two predecessor sets.
    assert budgets[8] == near(13.0), budgets
    # With a single worker every file waits behind all the earlier ones.
    assert _budgets(3, workers=1) == [near(5.0), near(9.0), near(13.0)]


def test_parse_limit_still_binds_the_first_row_and_low_memory_still_raises_it():
    """The cap is a cap: a file at the head of the queue still gets exactly one parse budget, and
    the memory governor still multiplies it (never removes it)."""
    budgets = _budgets(1, workers=4)
    assert budgets[0] == pytest.approx(PER_FILE_TIMEOUT_S + QUEUE_BUDGET_SLACK_S, abs=0.05)
    # 1400 MB free -> x2 multiplier; 800 MB -> x3. Depth 0, so only the multiplier moves.
    assert _budgets(1, workers=4, free_ram_mb=1400)[0] == pytest.approx(9.0, abs=0.05)
    assert _budgets(1, workers=4, free_ram_mb=800)[0] == pytest.approx(13.0, abs=0.05)


def test_timeout_record_states_the_budget_workers_and_ram_instead_of_blaming_memory(capsys):
    """`Timeout after 4.0s (low memory)` was printed with 14,893 MB free. The entry now carries
    the numbers that actually produced it, and no unconditional memory claim."""
    stuck = _FakeFuture(times_out=True, done_after_timeout=False)
    results = _run([_FakeFuture(_ok("a.py")), stuck],
                   [("a.py", "x"), ("b.py", "y")])
    err = results[1]["error"]
    assert err.startswith("Timeout after ")
    assert "low memory" not in err, err
    assert "999999 MB free" in err, err
    assert "queue depth 2" in err, err          # index 1 at 1 worker => depth 2
    assert "1 worker(s)" in err, err
    assert "File analysis timeout skipped: b.py" in capsys.readouterr().err
