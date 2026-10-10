"""CI regression: a kill part-way through graph evaluation must keep everything found so far.

The SaltStack run lost its whole result to a timeout inside graph evaluation. Two properties make
that impossible, and both are locked here:

1. Stage-1 emission -- pure structural sinks get their edge at collection time, so they are already
   in the graph before graph evaluation starts.
2. Live per-sink flush -- `_findings_for(tracker, list(tracker.edges))`, which is exactly what the
   SIGTERM handler flushes, grows sink by sink. Nothing is buffered until all modules finish.

The corpus uses cross-module flows (`u{i}.py` -> `common.py`) because a sink whose argument is a
plain in-file expression is resolved by the fast path and never enters the deep resolver; only the
cross-module sinks drive `resolve_expression` and `_build_proof_graph`.
"""
from ast_scanner import TaintTracker
from cli import _findings_for


class _Interrupt(Exception):
    """BaseException-free stop marker; raised from the patched hook to cut the run short."""


N_FUNCTIONS = 4

COMMON = "import os\n" + "".join(
    f"\ndef r{i}(p):\n    os.system(p)\n" for i in range(N_FUNCTIONS)
)

FILES = {"common.py": COMMON}
for _i in range(N_FUNCTIONS):
    FILES[f"u{_i}.py"] = f"from common import r{_i}\nr{_i}('ls ' + input())\n"
FILES["perms.py"] = "import os\nos.chmod('/tmp/drop', 0o777)\n"

# Measured on this corpus: 12 resolve_expression calls and 4 _build_proof_graph calls per full run.
RESOLVER_CALLS = 12
PROOF_GRAPH_CALLS = 4


def _run_interrupting(hook_name, budget):
    """Analyze, raising after `budget` calls of *hook_name*; return the flushable finding set."""
    tracker = TaintTracker(files=dict(FILES))
    real = getattr(TaintTracker, hook_name)
    state = {"calls": 0, "stopped": False}

    def counting(self, *args, **kwargs):
        state["calls"] += 1
        if state["calls"] > budget:
            state["stopped"] = True
            raise _Interrupt
        return real(self, *args, **kwargs)

    setattr(TaintTracker, hook_name, counting)
    try:
        tracker.analyze()
    except _Interrupt:
        pass
    finally:
        setattr(TaintTracker, hook_name, real)
    keys = {(f["file"], f["line"], f["cwe"]) for f in _findings_for(tracker, list(tracker.edges))}
    return keys, state["stopped"], state["calls"], len(tracker.edges)


def _resolver_run(budget):
    return _run_interrupting("resolve_expression", budget)


def _cascade_run(budget):
    """`_build_proof_graph` is called only from the per-sink cascade, so this kills graph evaluation
    part-way, with every collector already done."""
    return _run_interrupting("_build_proof_graph", budget)


def test_corpus_reaches_the_deep_resolver():
    """Guard the premise: if the fast path swallowed every sink, the budgets below would be no-ops."""
    full, stopped, calls, _edges = _resolver_run(RESOLVER_CALLS - 1)
    assert stopped, "this corpus must enter resolve_expression"
    assert calls == RESOLVER_CALLS, "interrupt must land exactly one call past the budget"
    assert len(full) > 0


def test_finding_set_grows_sink_by_sink_inside_graph_evaluation():
    full, stopped_full, _, _ = _resolver_run(10 * RESOLVER_CALLS)
    assert stopped_full is False

    stages = [_resolver_run(budget) for budget in (1, 3, 6, 9)]
    previous = set()
    for budget, (keys, stopped, _calls, _edges) in zip((1, 3, 6, 9), stages):
        assert stopped, f"budget {budget} must cut the run short"
        assert keys, f"budget {budget}: some findings must already be flushable"
        assert keys <= full, f"budget {budget} emitted a finding the completed run lacks"
        assert previous < keys, f"budget {budget}: each resolved sink must add findings immediately"
        previous = keys
    assert previous < full, "the finding set must still be growing at the last sampled budget"


def test_partial_flush_never_invents_a_finding():
    full, _s, _c, _e = _resolver_run(10 * RESOLVER_CALLS)
    for budget in (1, 2, 3, 4, 6, 8, 9, RESOLVER_CALLS - 1):
        keys, _stopped, _calls, _edges = _resolver_run(budget)
        assert keys <= full, f"partial flush at budget {budget} reported a finding the full run lacks"


def test_structural_single_file_finding_is_live_before_graph_evaluation():
    """Kill graph evaluation at its first proof-graph build: the chmod finding must already be in."""
    full, _s, _c, _e = _cascade_run(10 * PROOF_GRAPH_CALLS)
    partial, stopped, calls, _edges = _cascade_run(1)

    assert stopped, "graph evaluation must have been reached and cut short"
    assert calls == 2, "the interrupt must land on the second of the four proof-graph builds"
    assert ("perms.py", 2, "CWE-732") in partial, (
        "Stage-1 structural findings must be in the graph before graph evaluation starts"
    )
    assert partial < full, "the taint findings must not all be resolved yet"
