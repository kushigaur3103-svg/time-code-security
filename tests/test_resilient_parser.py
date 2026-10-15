"""Tolerant AST recovery: a file `ast.parse` rejects is retried block-by-block, never dropped whole.

The engine's fast path is one bare `ast.parse`. The recovery helpers in `ast_scanner` run *only* when
that call has already raised SyntaxError: the offending top-level statement (with its indented suite)
is swapped for `pass` at its own line and indent, the rest of its lines are blanked, and the file is
re-parsed. Line count is preserved, so every surviving node keeps its real source line.

Fixtures are 1-12 lines each, so the whole suite fits a laptop with ~400 MB free RAM.

Run it either way:
    python tests/test_resilient_parser.py
    python -m pytest tests/test_resilient_parser.py -q
"""
from __future__ import annotations

import ast
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ast_scanner import (  # noqa: E402
    TOLERANT_PARSE_MAX_BLOCKS,
    TaintTracker,
    _tolerant_line_spans,
    _tolerant_substitute,
    parse_source_tolerant,
)

PY = f"{sys.version_info[0]}.{sys.version_info[1]}"

VALID = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"

# Whichever of these two newer-syntax forms this interpreter rejects is the one that must be bypassed.
# CI runners are on 3.12 and both parse there; local 3.11 rejects both, so the same file proves both
# directions.
MODERN = {
    "PEP 695 type alias": "import os\n\n\ndef helper(user_input):\n    os.system(user_input)\n\n\n"
                          "type Config = int\n",
    "PEP 701 nested quotes": 'import os\n\n\ndef helper(user_input):\n    os.system(user_input)\n\n\n'
                             'def render(row):\n    return f"{row["name"]}"\n',
}

BROKEN = (
    "import os\n"
    "import subprocess\n"
    "\n"
    "def safe_logger(user_input):\n"
    "    print(user_input)\n"
    "\n"
    "def exec_it(user_input):\n"
    "    os.system(user_input)\n"
    "\n"
    "def broken(:\n"
    "    x = 1\n"
)

SHIFTED = (
    "import os\n"
    "def a(x):\n"
    "    os.system(x)\n"
    "def bad(:\n"
    "    y = 1\n"
    "def b(x):\n"
    "    os.popen(x)\n"
)


def scan(files: dict[str, str], **kwargs) -> TaintTracker:
    with contextlib.redirect_stderr(io.StringIO()) as err:
        tracker = TaintTracker(files=files, audit_all=True, **kwargs)
        tracker.analyze()
    tracker._stderr = err.getvalue()
    return tracker


def sink_lines(tracker: TaintTracker) -> list[tuple[int, str]]:
    return sorted({(s.location.line_start, s.operation) for s in tracker.sinks})


def funcs(tree) -> dict[str, int]:
    return {n.name: n.lineno for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def rejected_line(source: str) -> int:
    """0 when the file parses, else the line number the parser complained about."""
    try:
        ast.parse(source)
        return 0
    except SyntaxError as exc:
        return exc.lineno or 0


def recovered_lines(src: str, bypassed: list[int]) -> list[str]:
    """The substituted source, rebuilt through the same helpers the engine uses."""
    spans = _tolerant_line_spans(src)
    lines = src.splitlines(keepends=True)
    for start in sorted(bypassed):
        span = next((s, e) for s, e in spans if s == start)
        lines = _tolerant_substitute(lines, span[0], span[1])
    return lines


def fanout_driver(tmp: Path) -> dict:
    """Recovery through the real worker-pool parse path, in a child process."""
    driver = tmp / "fanout_driver.py"
    driver.write_text(textwrap.dedent(f"""
        import contextlib, io, json, sys
        sys.path.insert(0, {str(ROOT)!r})
        import ast_scanner
        files = {{f"f{{i:02d}}.py": "import os\\nos.system(user_input)\\n" for i in range(11)}}
        files["f99_broken.py"] = "import os\\nos.system(user_input)\\ndef bad(:\\n"
        with contextlib.redirect_stderr(io.StringIO()) as err:
            tracker = ast_scanner.TaintTracker(files=files, audit_all=True, max_workers=1)
            tracker.analyze()
        print(json.dumps({{
            "mode": tracker.execution_mode,
            "recovered": tracker.recovered_files,
            "skipped": sorted(tracker.skipped_files),
            "lines": sorted(s.location.line_start for s in tracker.sinks),
            "log": [l for l in err.getvalue().splitlines() if "RECOVERED" in l],
        }}))
    """))
    out = subprocess.run([sys.executable, str(driver)], capture_output=True, text=True, timeout=600)
    assert out.returncode == 0, out.stderr[-2000:]
    return json.loads(out.stdout[out.stdout.index("{"):])


def test_resilient_ast_recovery():
    # ─── 1. Fast path: a valid file is returned untouched, and recovery never runs ───
    tree, bypassed = parse_source_tolerant(VALID, "valid.py")
    assert tree is not None and bypassed == [], f"valid file edited: {bypassed}"
    tr = scan({"valid.py": VALID})
    assert tr.recovered_files == {}, tr.recovered_files
    assert tr.skipped_files == {}, tr.skipped_files
    assert tr.rescued_files == {}, "valid file must never reach the shield"
    assert "RECOVERED" not in tr._stderr, tr._stderr
    assert "RESCUED" not in tr._stderr, tr._stderr
    # The retry loop's only work on a healthy corpus is iterating an empty dict.
    assert tr.parse_stats.get("recovered") is None, "no recovery -> no new telemetry field"
    assert tr.parse_stats.get("rescued") is None, "no rescue -> no new telemetry field"

    # ─── 2. Positive control: sinks around a newer-syntax line are still extracted ───
    # Phase 2 hands a newer-syntax file to the tree-sitter shield, which reads it whole and therefore
    # bypasses nothing. Where the shield is not installed the block sweep is still the mechanism, so
    # each ledger is asserted against whichever one actually produced the tree.
    exercised = 0
    for label, src in MODERN.items():
        bad_line = rejected_line(src)
        if not bad_line:
            print(f"  Python {PY}: {label} parses cleanly - nothing to recover")
            continue
        exercised += 1
        tree2, bypassed2 = parse_source_tolerant(src, "modern.py")
        assert tree2 is not None, f"{label}: recovery gave up"
        assert "helper" in funcs(tree2), funcs(tree2)
        tr2 = scan({"modern.py": src})
        if bypassed2:
            assert tr2.recovered_files.get("modern.py") == bypassed2, tr2.recovered_files
            assert f"bypassed unparseable line {bad_line}" in tr2._stderr, (tr2._stderr, bad_line)
        else:
            assert tr2.rescued_files.get("modern.py") == "treesitter", tr2.rescued_files
            assert tr2.recovered_files == {}, tr2.recovered_files
            assert "[RESCUED-TREESITTER] modern.py" in tr2._stderr, tr2._stderr
        assert any(ln == 5 for ln, _ in sink_lines(tr2)), sink_lines(tr2)
    print(f"  Python {PY}: {exercised} modern-syntax fixture(s) exercised recovery")

    # ─── 3. Fault injection: a malformed def does not sink the rest of the file ───
    assert rejected_line(BROKEN) in (10, 11), rejected_line(BROKEN)
    tree3, bypassed3 = parse_source_tolerant(BROKEN, "broken.py")
    assert tree3 is not None, "malformed def took the whole file down"
    assert set(bypassed3) <= {10, 11}, f"only the broken statement may go: {bypassed3}"
    assert funcs(tree3) == {"safe_logger": 4, "exec_it": 7}, funcs(tree3)
    tr3 = scan({"broken.py": BROKEN})
    assert 8 in [ln for ln, _ in sink_lines(tr3)], sink_lines(tr3)
    assert tr3.recovered_files.get("broken.py") == bypassed3, tr3.recovered_files
    assert "broken.py" not in tr3.skipped_files, tr3.skipped_files
    assert tr3.parse_stats["recovered"] == 1 and tr3.parse_stats["unparseable"] == 0, tr3.parse_stats

    # ─── 4. Line-number integrity: nothing below a removal shifts ───
    tree4, bypassed4 = parse_source_tolerant(SHIFTED, "shift.py")
    assert tree4 is not None and bypassed4 == [4], bypassed4
    assert funcs(tree4) == {"a": 2, "b": 6}, funcs(tree4)
    rebuilt = "".join(recovered_lines(SHIFTED, bypassed4)).splitlines()
    assert rebuilt[5] == "def b(x):", f"line 6 must still be line 6: {rebuilt[5]!r}"
    assert rebuilt[6] == "    os.popen(x)", f"line 7 shifted: {rebuilt[6]!r}"
    tr4 = scan({"shift.py": SHIFTED})
    found = {ln for ln, _ in sink_lines(tr4)}
    assert 3 in found and 7 in found, sorted(found)

    # ─── 5. Recovery gives up honestly when it cannot prove a parse ───
    # 40 malformed defs: one block per round, so the budget is spent and the file stays unparseable.
    hopeless = "".join(f"def f{i}(:\n" for i in range(40))
    tree5, bypassed5 = parse_source_tolerant(hopeless, "hopeless.py")
    assert tree5 is None, "budget exhausted must not yield a module"
    assert len(bypassed5) == TOLERANT_PARSE_MAX_BLOCKS, bypassed5
    tr5 = scan({"hopeless.py": hopeless})
    assert tr5.recovered_files == {} and "hopeless.py" in tr5.skipped_files

    # A NUL byte is not a syntax error, so it is never handed to the recovery path at all.
    tr6 = scan({"nul.py": "import os\nos.system(cmd)\n\x00\n"})
    assert tr6.recovered_files == {} and "nul.py" in tr6.skipped_files
    assert tr6.skipped_files["nul.py"].startswith("ValueError"), tr6.skipped_files["nul.py"]

    # ─── 6. The worker-pool parse path recovers exactly like the inline loop ───
    with tempfile.TemporaryDirectory() as td:
        data = fanout_driver(Path(td))
    assert data["mode"] == "parallel", data["mode"]
    assert data["recovered"] == {"f99_broken.py": [3]}, data["recovered"]
    assert data["skipped"] == [], data["skipped"]
    assert len(data["log"]) == 1 and "bypassed unparseable line 3" in data["log"][0], data["log"]
    assert data["lines"].count(2) == 12, data["lines"]

    # ─── 7. Determinism: the same file bypasses the same lines in every run ───
    assert sink_lines(scan({"broken.py": BROKEN})) == sink_lines(tr3)
    assert parse_source_tolerant(BROKEN, "broken.py")[1] == bypassed3
    assert _tolerant_line_spans(BROKEN) == _tolerant_line_spans(BROKEN)


if __name__ == "__main__":
    test_resilient_ast_recovery()
    print(f"\nresilient parser: all assertions passed on Python {PY}")
