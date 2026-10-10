"""Prove that the parallel Phase 2 fan-out changes nothing.

Gate 1 runs 20 small fixtures, so it stays green even if a per-module fan-out drops a sink on a
multi-file corpus. This harness is the check that actually matters: it scans the same corpus twice -
once through the serial statement-collection loop, once through the worker pool - and requires the
two engines to agree exactly on sink/source/edge counts, on the id series (which is order-sensitive
by construction), and on the resulting finding set. Any difference exits non-zero.

Usage:
    python scripts/phase2_equivalence_check.py [corpus_dir ...] [--workers N]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ast_scanner  # noqa: E402
from cli import _findings_for  # noqa: E402

IGNORED = {".git", ".venv", "venv", "__pycache__", "node_modules", "build", "dist"}
MAX_FILES = 120


def collect_corpus(directories):
    """Up to MAX_FILES .py files, as (path → source), in deterministic sorted order."""
    paths = []
    for directory in directories:
        root = Path(directory)
        if not root.is_dir():
            raise SystemExit(f"corpus directory not found: {root}")
        for path in sorted(root.rglob("*.py")):
            if any(part in IGNORED for part in path.parts):
                continue
            paths.append(path)
    if not paths:
        raise SystemExit("corpus is empty")
    files = {}
    for path in paths[:MAX_FILES]:
        try:
            files[path.relative_to(Path.cwd()).as_posix() if path.is_absolute() else str(path)] = \
                path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"skipping unreadable {path}: {exc}", file=sys.stderr)
    if len(files) < 2:
        raise SystemExit("need at least two modules to make a multi-module equivalence claim")
    return files


def run(files, phase2_workers):
    """One full analyze() pass with Phase 2 pinned to `phase2_workers`."""
    original = ast_scanner._phase2_worker_count
    ast_scanner._phase2_worker_count = lambda count: phase2_workers
    try:
        tracker = ast_scanner.TaintTracker(files=dict(files), max_workers=1)
        tracker.analyze()
    finally:
        ast_scanner._phase2_worker_count = original
    return tracker


def fingerprint(tracker):
    """Everything a fan-out could plausibly disturb: counts, id series, finding set."""
    return {
        "modules": len(tracker.modules),
        "sources": len(tracker.sources),
        "sinks": len(tracker.sinks),
        "sink_records": len(tracker.sink_records),
        "edges": len(tracker.edges),
        "source_ids": [source.id for source in tracker.sources],
        "sink_ids": [sink.id for sink in tracker.sinks],
        "findings": {(item["file"], item["line"], item["cwe"])
                     for item in _findings_for(tracker, tracker.edges)},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog="phase2_equivalence_check.py")
    parser.add_argument("corpus", nargs="*", default=["fixtures", "tests/fixtures"])
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args(argv)

    files = collect_corpus(args.corpus)
    print(f"corpus: {len(files)} modules")

    serial = fingerprint(run(files, 1))
    parallel = fingerprint(run(files, max(2, args.workers)))

    rows = []
    failures = 0
    for key in ("modules", "sources", "sinks", "sink_records", "edges"):
        same = serial[key] == parallel[key]
        failures += not same
        rows.append(f"{key:<14} serial={serial[key]:<7} parallel={parallel[key]:<7} "
                    f"{'equal' if same else 'DIFFERENT'}")
    for key in ("source_ids", "sink_ids"):
        same = serial[key] == parallel[key]
        failures += not same
        rows.append(f"{key:<14} identical series: {same} "
                    f"({len(serial[key])} ids, first diff at "
                    f"{next((i for i, (a, b) in enumerate(zip(serial[key], parallel[key])) if a != b), '-')})")
    missing = serial["findings"] - parallel["findings"]
    extra = parallel["findings"] - serial["findings"]
    rows.append(f"{'findings':<14} serial={len(serial['findings'])} parallel={len(parallel['findings'])} "
                f"missing_in_parallel={len(missing)} new_in_parallel={len(extra)}")
    failures += len(missing) + len(extra)

    print("\n".join(rows))
    for label, items in (("MISSING", missing), ("NEW", extra)):
        for site in sorted(items)[:10]:
            print(f"{label}: {site}")
    if failures:
        print(f"RESULT: FAIL - {failures} difference(s). Do not ship the fan-out.")
        return 1
    print("RESULT: PASS - parallel Phase 2 is byte-equivalent to serial on this corpus.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
