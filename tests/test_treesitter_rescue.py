"""Phase 2: the tree-sitter packer wired in as the SyntaxError rescue shield.

The engine's fast path is still one bare `ast.parse`. The shield is consulted only from the
`except SyntaxError:` branch of `parse_source_tolerant()`, and only a file whose source the tolerant
grammar reads as *complete, valid Python* is rescued from there - which is precisely the newer-syntax
case this interpreter's parser predates (PEP 695 generics, PEP 701 nested quotes). A file that is
genuinely damaged is still recovered by the proven block-level `pass` substitution, so no scan is ever
run against a guessed-at tree.

Both mechanisms are recorded separately (`rescued_files` vs `recovered_files`) so a report can always
say which one produced which module.

Run it either way:
    python tests/test_treesitter_rescue.py
    python -m pytest tests/test_treesitter_rescue.py -q
"""
from __future__ import annotations

import ast
import contextlib
import io
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ast_scanner  # noqa: E402
from ast_scanner import (  # noqa: E402
    TREESITTER_RESCUE_AVAILABLE,
    TaintTracker,
    _treesitter_packer,
    parse_source_tolerant,
)
from tcs.treesitter_packer import clean_parse  # noqa: E402

PY = f"{sys.version_info[0]}.{sys.version_info[1]}"

VALID = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"

# A generic def (PEP 695, line 5) and a nested double-quoted f-string (PEP 701, line 12): on Python
# 3.11 `ast.parse` stops at line 5 with "expected '('".
MODERN = '''import os
from flask import request


def run[T](cmd: T) -> T:
    os.system(cmd)
    return cmd


def render(row):
    return f"{row["name"]}"


def handler():
    value = request.form["cmd"]
    run(value)
    return render({"name": value})
'''

MODERN_FUNCS = {"run": 5, "render": 10, "handler": 14}
MODERN_SINKS = [(6, "OS_COMMAND_EXECUTION"), (16, "OS_COMMAND_EXECUTION")]
MODERN_SOURCES = [(15, "HTTP_PARAMETER_ACCESS")]

# Damage the grammar itself reports as incomplete: every one of these must be declined by the shield
# and left to the block sweep, which is the behaviour those fixtures had before Phase 2.
DAMAGED = {
    "broken_def": "import os\n\n\ndef safe(user_input):\n    print(user_input)\n\n\n"
                  "def broken(:\n    x = 1\n",
    "unclosed_bracket": "import os\nx = [1, 2\nos.system(cmd)\n",
    "missing_body": "import os\ndef f():\n",
    "hopeless": "".join(f"def g{i}(:\n" for i in range(40)),
    "star_target": "* = 3\n",
    "nul_in_source": "import os\nos.system(cmd)\n\x00\n",
}


def run_tracker(files: dict, **kwargs):
    """Build and analyse a tracker with every engine log line captured for assertion."""
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        tracker = TaintTracker(files=files, audit_all=True, **kwargs)
        tracker.analyze()
    tracker._stderr = err.getvalue()
    return tracker


def sink_pairs(tracker):
    return sorted({(s.location.line_start, s.operation) for s in tracker.sinks})


def source_pairs(tracker):
    return sorted({(s.location.line_start, s.operation) for s in tracker.sources})


def id_map(tracker):
    """Every source and sink id with what it points at - the node-id series determinism checks."""
    return sorted((n.id, n.node_type, n.operation, n.location.file, n.location.line_start)
                  for n in list(tracker.sources) + list(tracker.sinks))


class Tripwire:
    """Counts how often the shield is consulted, and can delegate to the real packer or refuse."""

    def __init__(self, delegate=None):
        self.calls = []
        self.delegate = delegate

    def clean_parse(self, source, filename="<treesitter>"):
        self.calls.append(filename)
        return self.delegate(source, filename) if self.delegate is not None else None


def test_treesitter_rescue_shield():
    assert TREESITTER_RESCUE_AVAILABLE is True, "tree-sitter wheels are declared in requirements.txt"

    # ─── 1. Zero fast-path overhead: a valid file never reaches the shield ───
    wire = Tripwire(delegate=clean_parse)
    real, ast_scanner._treesitter_packer = _treesitter_packer, wire
    try:
        tree, bypassed = parse_source_tolerant(VALID, "valid.py")
        assert tree is not None and bypassed == []
        assert wire.calls == [], f"valid file consulted the shield: {wire.calls}"
        # 200 valid parses through the same entry point, still not one shield call.
        for _ in range(200):
            parse_source_tolerant(VALID, "valid.py")
        assert wire.calls == [], wire.calls
        # And a SyntaxError file does reach it - the only other door in the function.
        bad = "import os\ndef broken(:\n"
        parse_source_tolerant(bad, "bad.py")
        assert wire.calls == ["bad.py"], wire.calls
    finally:
        ast_scanner._treesitter_packer = real

    # ─── 2. The shield is the primary rescue: newer syntax is read whole, nothing bypassed ───
    native_rejects = True
    try:
        ast.parse(MODERN)
        native_rejects = False
    except SyntaxError:
        pass
    tree2, bypassed2 = parse_source_tolerant(MODERN, "modern.py")
    assert tree2 is not None, "newer-syntax file was not rescued"
    funcs2 = {n.name: n.lineno for n in tree2.body if isinstance(n, ast.FunctionDef)}
    if native_rejects:
        assert bypassed2 == [], "a lossless rescue removes nothing"
        assert funcs2 == MODERN_FUNCS, funcs2
    else:
        assert bypassed2 == [] and funcs2 == MODERN_FUNCS, funcs2
    tr2 = run_tracker({"modern.py": MODERN})
    assert sink_pairs(tr2) == MODERN_SINKS, sink_pairs(tr2)
    assert source_pairs(tr2) == MODERN_SOURCES, source_pairs(tr2)
    if native_rejects:
        assert tr2.rescued_files == {"modern.py": "treesitter"}, tr2.rescued_files
        assert tr2.recovered_files == {}, "a rescued file must not also be logged as block-recovered"
        assert tr2.skipped_files == {}, tr2.skipped_files
        assert tr2.parse_stats["rescued"] == 1 and "recovered" not in tr2.parse_stats, tr2.parse_stats
        assert "[RESCUED-TREESITTER] modern.py: recovered complete AST via tree-sitter packer" \
            in tr2._stderr, tr2._stderr
    else:
        assert tr2.rescued_files == {} and tr2.recovered_files == {}, "3.12 parsed it natively"

    # ─── 3. Damaged source is declined, and the proven block sweep still handles it ───
    for label, src in DAMAGED.items():
        assert clean_parse(src, label) is None, f"{label}: shield accepted damaged source"
    tr3 = run_tracker({"broken.py": DAMAGED["broken_def"]})
    assert tr3.rescued_files == {}, tr3.rescued_files
    assert tr3.recovered_files == {"broken.py": [8]}, tr3.recovered_files
    assert "RESCUED-TREESITTER" not in tr3._stderr, tr3._stderr
    assert "bypassed unparseable line 8" in tr3._stderr, tr3._stderr
    tree3, _ = parse_source_tolerant(DAMAGED["broken_def"], "broken.py")
    assert {n.name: n.lineno for n in tree3.body if isinstance(n, ast.FunctionDef)} == {"safe": 4}
    # 40 broken defs still give up honestly - the shield never turns garbage into a "recovered" file.
    tr4 = run_tracker({"hopeless.py": DAMAGED["hopeless"]})
    assert tr4.rescued_files == {} and tr4.recovered_files == {}, (tr4.rescued_files,
                                                                  tr4.recovered_files)
    assert "hopeless.py" in tr4.skipped_files, tr4.skipped_files
    # A NUL byte is not a syntax error, so it never reaches any recovery path.
    tr5 = run_tracker({"nul.py": DAMAGED["nul_in_source"]})
    assert tr5.rescued_files == {} and "nul.py" in tr5.skipped_files, tr5.skipped_files

    # ─── 4. Without the shield the file is still analysed - the shield only adds coverage ───
    real, ast_scanner._treesitter_packer = _treesitter_packer, None
    try:
        tree6, bypassed6 = parse_source_tolerant(MODERN, "modern.py")
        assert tree6 is not None, "block sweep alone must still produce a module"
        if native_rejects:
            # Measured on 3.11: both newer-syntax blocks are swept, so `run` and its os.system are
            # gone. This is exactly the gap the shield closes, and the reason it is tried first.
            assert bypassed6 == [5, 11], bypassed6
            assert {n.name for n in tree6.body if isinstance(n, ast.FunctionDef)} \
                == {"render", "handler"}, tree6.body
            tr6 = run_tracker({"modern.py": MODERN})
            assert tr6.rescued_files == {}, tr6.rescued_files
            assert tr6.recovered_files == {"modern.py": [5, 11]}, tr6.recovered_files
            assert 6 not in [ln for ln, _ in sink_pairs(tr6)], sink_pairs(tr6)
        else:
            assert bypassed6 == [], bypassed6
    finally:
        ast_scanner._treesitter_packer = real
    if native_rejects:
        assert len(sink_pairs(tr2)) > len(sink_pairs(tr6)), "rescue found no more than the sweep"
        assert sink_pairs(tr6) == [], sink_pairs(tr6)

    # ─── 5. Determinism: same bytes, same tree, same node ids, at any worker count ───
    dumps = {ast.dump(parse_source_tolerant(MODERN, "modern.py")[0]) for _ in range(3)}
    assert len(dumps) == 1, "rescue is not deterministic"
    corpus = {f"f{i:02d}.py": VALID for i in range(12)}
    corpus["modern.py"] = MODERN
    runs = []
    for workers in (1, 2):
        tr = run_tracker(dict(corpus), max_workers=workers)
        assert tr.execution_mode in ("parallel", "serial_fallback"), tr.execution_mode
        if native_rejects:
            assert tr.rescued_files == {"modern.py": "treesitter"}, (workers, tr.rescued_files)
        runs.append((id_map(tr), sink_pairs(tr), sorted(tr.modules), sorted(tr.file_paths.values())))
    assert runs[0][0] == runs[1][0], "source/sink node ids moved between worker counts"
    assert runs[0][1] == runs[1][1], "sinks differ between worker counts"
    assert runs[0][2] == runs[1][2] and runs[0][3] == runs[1][3], "module order is not canonical"

    # ─── 6. Memory stays bounded: rescuing 100 files holds no CST ───
    import gc
    import psutil
    import time

    run_tracker({"warm.py": MODERN})
    gc.collect()
    rss0 = psutil.Process().memory_info().rss
    elapsed = []
    with contextlib.redirect_stderr(io.StringIO()):
        for i in range(100):
            start = time.perf_counter()
            assert parse_source_tolerant(MODERN, f"modern_{i}.py")[0] is not None
            elapsed.append(time.perf_counter() - start)
    gc.collect()
    grew = psutil.Process().memory_info().rss - rss0
    assert grew < 20 * 1024 * 1024, f"100 rescues grew RSS by {grew / 1e6:.1f} MB"
    assert statistics.median(elapsed) < 0.05, statistics.median(elapsed)
    parked = [k for k, v in vars(ast_scanner._treesitter_packer).items() if isinstance(v, ast.AST)]
    assert parked == [], f"the packer cached parsed AST nodes globally: {parked}"


if __name__ == "__main__":
    test_treesitter_rescue_shield()
    print(f"tree-sitter rescue shield: all assertions passed on Python {PY}")
