"""CI regression: a killed scan must say *where* it died, without disturbing the partial artefacts.

The SaltStack timeout produced a report with "0 findings" and no way to tell whether the engine had
read three files or three thousand. PART 1 adds an execution checkpoint (active phase, collector
timings recorded so far, elapsed time) that `cli.py` writes to stderr *before* the partial JSON goes
to stdout and before the SARIF file is written.

Three properties are locked here:

1. The checkpoint is real: it names the pipeline phase executing at the interrupt, the collector
   running inside that phase, and the timings accumulated up to that second.
2. Ordering: telemetry reaches stderr before the payload reaches stdout.
3. It is purely additive: the JSON keeps exactly its previous keys, the SARIF document still
   validates, and a broken checkpoint cannot suppress either artefact.
"""
import ast
import contextlib
import io
import json
import signal
from pathlib import Path
from types import SimpleNamespace

import cli
from ast_scanner import TaintTracker
from cli import _flush_partial, _install_partial_flush, _PARTIAL

SCANNER_SRC = Path(cli.__file__).with_name("ast_scanner.py").read_text(encoding="utf-8")

FILES = {
    "common.py": "import os\n\n\ndef run_it(p):\n    os.system(p)\n",
    "app.py": "from common import run_it\nrun_it('ls ' + input())\nos.chmod('/tmp/x', 0o777)\n",
}


class _Stop(Exception):
    """Raised out of a patched engine hook to cut a run short at a known point."""


class _Tagged(io.StringIO):
    """StringIO that also records which stream each write came from, so ordering is testable."""

    def __init__(self, tag, sink):
        super().__init__()
        self.tag = tag
        self.sink = sink

    def write(self, s):
        self.sink.append((self.tag, s))
        return super().write(s)


def _interrupt_on(hook_name):
    """Analyze FILES, raising `_Stop` the first time `hook_name` runs, and hand back the tracker."""
    tracker = TaintTracker(files=dict(FILES))
    real = getattr(TaintTracker, hook_name)
    seen = []

    def hook(self, *args, **kwargs):
        seen.append(self.termination_checkpoint())
        raise _Stop

    def wrapper(self, *a, **k):
        if not seen:
            return hook(self, *a, **k)
        return real(self, *a, **k)

    setattr(TaintTracker, hook_name, wrapper)
    try:
        tracker.analyze()
    except _Stop:
        pass
    finally:
        setattr(TaintTracker, hook_name, real)
    return tracker, seen


def _flush(tracker, sarif=None):
    """Drive the real flush path with captured streams; return (stdout, stderr, ordered writes)."""
    order = []
    out, err = _Tagged("out", order), _Tagged("err", order)
    args = SimpleNamespace(format="json", scope="all", sarif=sarif)
    saved = dict(_PARTIAL)
    _PARTIAL.update({"args": args, "findings": [], "tracker": tracker, "files": dict(FILES),
                     "written": False, "current_file": None, "t0": 0.0})
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            _flush_partial("SIGTERM")
    finally:
        _PARTIAL.clear()
        _PARTIAL.update(saved)
    return out.getvalue(), err.getvalue(), order


def test_checkpoint_before_analyze_is_preparse():
    point = TaintTracker(files=dict(FILES)).termination_checkpoint()
    assert point["phase"] == "pre-analysis (discovery/parse)"
    assert point["analyze_elapsed_s"] is None
    assert point["collector_profile_s"] == {}


def test_checkpoint_names_the_cascade_phase_and_carries_timings():
    # `_build_proof_graph` only runs inside the per-sink graph evaluation cascade, so interrupting
    # there proves the marker for the longest phase is placed before the loop, not after it.
    tracker, _seen = _interrupt_on("_build_proof_graph")
    point = tracker.termination_checkpoint()
    assert point["phase"].startswith("Graph evaluation cascade"), point["phase"]
    assert point["analyze_elapsed_s"] >= 0.0
    assert point["collector_profile_s"], "collector profile was empty at the cascade"
    assert "batch2" in point["collector_profile_s"]


def test_checkpoint_reports_the_executing_collector():
    # Same trick one phase earlier: the first collector batch has not run yet, so the checkpoint read
    # from inside it must name both the phase and the collector.
    _tracker, seen = _interrupt_on("_collect_batch2_structural_findings")
    assert seen[0]["phase"] == "Collectors (23 structural batches) [batch2]"


def test_telemetry_is_written_to_stderr_before_the_json_payload():
    tracker, _seen = _interrupt_on("_build_proof_graph")
    out, err, order = _flush(tracker)
    first_telemetry = next(i for i, (_t, s) in enumerate(order) if "[telemetry]" in s)
    first_payload = next(i for i, (_t, s) in enumerate(order) if '"findings"' in s)
    assert order[first_telemetry][0] == "err", "telemetry must go to stderr"
    assert order[first_payload][0] == "out", "the payload must stay on stdout"
    assert first_telemetry < first_payload
    assert "[telemetry] Active phase: Graph evaluation cascade" in err
    assert "[telemetry] Collector timings so far (s):" in err
    assert "[telemetry] Elapsed since scan start:" in err


def test_json_payload_keys_are_unchanged():
    tracker, _seen = _interrupt_on("_build_proof_graph")
    out, _err, _order = _flush(tracker)
    payload = json.loads(out)
    assert set(payload) == {"scope", "status", "terminated_by", "total_discovered_files",
                            "scanned_files", "findings"}
    assert payload["status"] == "partial"
    assert payload["terminated_by"] == "SIGTERM"


def test_sarif_is_still_written_and_valid(tmp_path):
    sarif = tmp_path / "partial.sarif"
    tracker, _seen = _interrupt_on("_build_proof_graph")
    _flush(tracker, sarif=str(sarif))
    document = json.loads(sarif.read_text(encoding="utf-8"))
    assert document["runs"] and document["runs"][0]["results"] is not None
    assert document["$schema"].endswith("sarif-schema-2.1.0.json")


def test_a_broken_checkpoint_cannot_suppress_the_artefacts(tmp_path):
    sarif = tmp_path / "partial.sarif"
    tracker, _seen = _interrupt_on("_build_proof_graph")
    real = TaintTracker.termination_checkpoint
    TaintTracker.termination_checkpoint = lambda self: (_ for _ in ()).throw(
        RuntimeError("checkpoint exploded"))
    try:
        out, err, _order = _flush(tracker, sarif=str(sarif))
    finally:
        TaintTracker.termination_checkpoint = real
    assert json.loads(out)["status"] == "partial"
    assert "[telemetry] Checkpoint unavailable: RuntimeError: checkpoint exploded" in err
    assert json.loads(sarif.read_text(encoding="utf-8"))["runs"]


def test_flush_without_a_tracker_still_reports_a_phase():
    out, err, _order = _flush(None)
    assert "[telemetry] Active phase: pre-analysis (discovery/parse)" in err
    assert json.loads(out)["findings"] == []


def test_install_partial_flush_stamps_the_scan_start(monkeypatch):
    monkeypatch.setattr(signal, "signal", lambda *a: None)
    saved = dict(_PARTIAL)
    try:
        _install_partial_flush(SimpleNamespace(format="json", sarif=None, scope="all"))
        assert _PARTIAL["t0"] is not None and _PARTIAL["t0"] > 0
    finally:
        _PARTIAL.clear()
        _PARTIAL.update(saved)


def test_every_phase_marker_is_a_literal_and_all_are_reachable():
    """A checkpoint that prints a stale label from the previous boundary is worse than none, so the
    full set of labels the pipeline can report is pinned here."""
    labels = []
    for node in ast.walk(ast.parse(SCANNER_SRC)):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Attribute) and t.attr == "_checkpoint_phase"
                for t in node.targets):
            assert isinstance(node.value, ast.Constant), "phase markers must be literals"
            labels.append(node.value.value)
    assert set(labels) >= {
        "pre-analysis (discovery/parse)",
        "Phase 1 (Import resolution)",
        "Phase 2 (Statement collection)",
        "Phase 4.3 (Function contracts)",
        "Call site indexing",
        "Sink detection (callbacks+direct)",
        "Source detection",
        "Collectors (23 structural batches)",
        "Blindspot collectors (14 CWE passes per module)",
        "SSL verification-disabled sinks",
        "Graph evaluation cascade (per-sink taint resolution)",
        "Analysis complete (reconcile/report serialization)",
    }
