"""Phase 3: parser mode orchestration - `hybrid`, `treesitter` and `ast` must be provable, not hoped for.

Three claims this file locks down, each measured on Python 3.11 with tree-sitter 0.26.0 and
tree-sitter-python 0.25.0 installed:

1. Pure mode equivalence. On every snippet of a 20-file corpus of valid Python, the tree a `hybrid`
   scan builds and the tree a `treesitter` scan builds are *byte-identical* (`ast.dump` equality, not
   a digest), and both produce the same sinks, sources, node ids, module names and file paths. Choosing
   a parser cannot change what the engine reports.
2. Zero speed degradation in the default mode. `hybrid` still parses a healthy file with exactly one
   `ast.parse`: no packer call and no tolerant-parse call for any valid file, only for the ones that
   raise SyntaxError.
3. Mode isolation is real. `ast` never touches tree-sitter - not once, even when a file is broken -
   and `treesitter` routes every file through `clean_parse` (`parse_stats["parsed_by_packer"]`).

Run it either way:
    python tests/test_parser_modes.py
    python -m pytest tests/test_parser_modes.py -q
"""
from __future__ import annotations

import ast
import contextlib
import gc
import io
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ast_scanner  # noqa: E402
from ast_scanner import (  # noqa: E402
    DEFAULT_PARSER_MODE,
    PARSER_MODES,
    TREESITTER_RESCUE_AVAILABLE,
    TaintTracker,
    _normalise_parser_mode,
    _treesitter_packer,
    parse_source_tolerant,
)
from tcs.treesitter_packer import clean_parse, tree_sitter_available  # noqa: E402

try:
    import psutil
except ImportError:  # pragma: no cover - the guard is the point
    psutil = None

try:
    import pytest
except ImportError:
    pytest = None

PY = f"{sys.version_info[0]}.{sys.version_info[1]}"
MB = 1024 * 1024

# Twenty valid, deliberately boring snippets: one sink family each, several CWEs shared, a class
# method, a comprehension, a decorator, a docstring-only file and an import-only file so the corpus
# is not "one function per file" for the mode comparison.
CORPUS = {
    "c01_os_system": "import os\n\n\ndef h(cmd):\n    os.system(cmd)\n",
    "c02_subprocess": "import subprocess\n\n\ndef h(cmd):\n    subprocess.call(cmd, shell=True)\n",
    "c03_eval": "def h(expr):\n    return eval(expr)\n",
    "c04_exec": "def h(body):\n    exec(body)\n",
    "c05_pickle": "import pickle\n\n\ndef h(blob):\n    return pickle.loads(blob)\n",
    "c06_yaml": "import yaml\n\n\ndef h(doc):\n    return yaml.load(doc)\n",
    "c07_sql": "import sqlite3\n\n\ndef h(cur, name):\n    cur.execute('SELECT * FROM t WHERE n = ' + name)\n",
    "c08_ssrf": "import requests\n\n\ndef h(url):\n    return requests.get(url)\n",
    "c09_md5": "import hashlib\n\n\ndef h(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n",
    "c10_random": "import random\n\n\ndef h():\n    return random.randint(1, 100)\n",
    "c11_secret": "API_KEY = \"sk-live-aaaaaaaaaaaaaaaaaaaa\"\n",
    "c12_path": "def h(base, name):\n    return open(base + \"/\" + name).read()\n",
    "c13_mktemp": "import tempfile\n\n\ndef h():\n    return tempfile.mktemp()\n",
    "c14_xml": "import xml.etree.ElementTree as ET\n\n\ndef h(src):\n    return ET.parse(src)\n",
    "c15_jinja": "import jinja2\n\n\ndef h(tpl, ctx):\n    return jinja2.Template(tpl).render(ctx)\n",
    "c16_popen": "import os\n\n\ndef h(cmd):\n    return os.popen(cmd).read()\n",
    "c17_rmtree": "import shutil\n\n\ndef h(target):\n    shutil.rmtree(target)\n",
    "c18_comprehension": "def h(rows, tpl):\n    return [tpl.format(r) for r in rows]\n",
    "c19_decorated": "import functools\n\n\ndef deco(f):\n    return functools.wraps(f)(f)\n\n\n@deco\ndef h(cmd):\n    import os\n    return os.popen(cmd).read()\n",
    "c20_class": "class S:\n    def h(self, cmd):\n        import os\n        os.system(cmd)\n",
}
assert len(CORPUS) == 20, len(CORPUS)

# The exact ledger one tracker over all 20 files produces: every sink and source coordinate plus its
# operation. Hardcoding the whole pair list (not just a count) is what makes the mode comparison
# unambiguous - a mode that drops, invents or re-lines one node fails here.
AGGREGATE_SINKS = [
    (2, "ARBITRARY_CODE_EXECUTION"), (2, "FILE_ACCESS"), (4, "OS_COMMAND_EXECUTION"),
    (5, "DESERIALIZATION"), (5, "DIRECT_USE_OF_JINJA2"), (5, "FILE_ACCESS"),
    (5, "INSECURE_RANDOM"), (5, "INSECURE_TEMP_FILE"), (5, "OS_COMMAND_EXECUTION"),
    (5, "SQL_EXECUTION"), (5, "SQL_QUERY_EXECUTION"), (5, "SSRF_REQUEST"),
    (5, "TEMPLATE_RENDERING"), (5, "UNSALTED_PASSWORD_HASH"), (5, "WEAK_HASH"),
    (5, "WEAK_PASSWORD_HASH"), (5, "XML_ENTITY_EXPANSION"), (5, "XML_PARSING"),
    (11, "OS_COMMAND_EXECUTION"),
]
AGGREGATE_SOURCES = [(1, "PARAMETER_INPUT"), (4, "PARAMETER_INPUT"), (9, "PARAMETER_INPUT")]
AGGREGATE_OPERATIONS = sorted({op for _, op in AGGREGATE_SINKS} | {op for _, op in AGGREGATE_SOURCES})

# PEP 695 generic def (line 5) + PEP 701 nested double-quoted f-string (line 11): this 3.11
# interpreter's own parser stops at line 5, so `ast` mode has to sweep and loses the sink below it.
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
MODERN_SWEPT_BLOCKS = [5, 11]

# Damage the tolerant grammar reports as incomplete, so every mode must end at the same block sweep.
DAMAGED = "import os\n\n\ndef safe(u):\n    print(u)\n\n\ndef broken(:\n    x = 1\n"
DAMAGED_RECOVERED = {"broken.py": [8]}


def scan(files, mode, **kwargs):
    """Build and analyse a tracker with every engine log line captured, and time the whole parse+analyse."""
    err = io.StringIO()
    started = time.perf_counter()
    with contextlib.redirect_stderr(err):
        tracker = TaintTracker(files=files, audit_all=True, parser_mode=mode, **kwargs)
        tracker.analyze()
    tracker._elapsed = time.perf_counter() - started
    tracker._stderr = err.getvalue()
    return tracker


def pairs(tracker):
    return (sorted({(s.location.line_start, s.operation) for s in tracker.sinks}),
            sorted({(s.location.line_start, s.operation) for s in tracker.sources}))


def id_map(tracker):
    return sorted((n.id, n.node_type, n.operation, n.location.file, n.location.line_start)
                  for n in list(tracker.sources) + list(tracker.sinks))


def dumps(tracker):
    """Full `ast.dump` of every module, keyed by file path - the strictest tree comparison available."""
    return {tracker.file_paths[m]: ast.dump(tracker.modules[m], include_attributes=False)
            for m in tracker.modules}


def funcs(tree):
    return {n.name: n.lineno for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


class Wire:
    """Stands in for the packer: records every consultation, delegates to the real one by default."""

    def __init__(self, delegate=None):
        self.calls = []
        self.delegate = delegate

    def clean_parse(self, source, filename="<treesitter>"):
        self.calls.append(filename)
        return self.delegate(source, filename) if self.delegate is not None else None

    def parse_to_ast(self, source, filename="<treesitter>"):
        self.calls.append(filename)
        return self.delegate.parse_to_ast(source, filename) if self.delegate is not None else None


def test_parser_modes():
    if not tree_sitter_available():
        if pytest is not None:
            pytest.skip("tree-sitter wheels not installed; the two packer modes cannot be exercised")
        print(f"SKIP: tree-sitter not installed on Python {PY}")
        return
    assert PARSER_MODES == ("hybrid", "treesitter", "ast"), PARSER_MODES
    assert DEFAULT_PARSER_MODE == "hybrid", DEFAULT_PARSER_MODE
    assert TREESITTER_RESCUE_AVAILABLE is True, "the packer wheels are declared in requirements.txt"
    # Every site that reads a mode compares against these literals; a typo would silently disable a mode.
    assert parse_source_tolerant.__defaults__ == (DEFAULT_PARSER_MODE,), parse_source_tolerant.__defaults__

    # ─── 1. Pure mode equivalence, per snippet, on byte-identical trees ───
    for name, source in sorted(CORPUS.items()):
        files = {f"{name}.py": source}
        a, h, t = (scan(files, mode) for mode in ("ast", "hybrid", "treesitter"))
        assert pairs(h) == pairs(t) == pairs(a), name
        assert id_map(h) == id_map(t) == id_map(a), name
        assert sorted(h.modules) == sorted(t.modules) == sorted(a.modules), name
        assert dumps(h) == dumps(t) == dumps(a), f"{name}: the trees themselves differ"
        assert h.parse_stats["parser_mode"] == "hybrid", h.parse_stats
        assert t.parse_stats["parser_mode"] == "treesitter", t.parse_stats
        # treesitter mode must really have used the packer - not quietly fallen back to CPython.
        assert t.parse_stats["parsed_by_packer"] == 1, t.parse_stats
        assert "parsed_by_packer" not in h.parse_stats, h.parse_stats
        # And no mode may report a rescued or recovered module for a file that is simply valid.
        for tracker in (a, h, t):
            assert tracker.rescued_files == {} and tracker.recovered_files == {}, (name, tracker)
    print(f"  {len(CORPUS)} snippets: identical sinks, ids and ast.dump in all three modes")

    # ─── 2. The aggregate corpus reports the same numbers in every mode ───
    files = {f"{name}.py": src for name, src in CORPUS.items()}
    per_mode = {}
    for mode in ("ast", "hybrid", "treesitter"):
        tracker = scan(files, mode)
        sinks, sources = pairs(tracker)
        per_mode[mode] = ((sinks, sources), sorted({op for _, op in sinks} | {op for _, op in sources}),
                          id_map(tracker), dumps(tracker), len(tracker.modules))
        assert tracker.execution_mode == ("treesitter" if mode == "treesitter" else "parallel"), \
            (mode, tracker.execution_mode)
    for mode in ("ast", "treesitter"):
        assert per_mode[mode] == per_mode["hybrid"], f"{mode} differs from hybrid on the same corpus"
    assert per_mode["hybrid"][0] == (AGGREGATE_SINKS, AGGREGATE_SOURCES), per_mode["hybrid"][0]
    assert per_mode["hybrid"][1] == AGGREGATE_OPERATIONS, per_mode["hybrid"][1]
    assert per_mode["hybrid"][4] == 20, per_mode["hybrid"][4]
    print(f"  20-file corpus: {len(AGGREGATE_SINKS)} sinks + {len(AGGREGATE_SOURCES)} sources across "
          f"{len(AGGREGATE_OPERATIONS)} operations, identical in all three modes")

    # ─── 3. Zero default-mode overhead: hybrid never consults a second reader for valid code ───
    wire = Wire(delegate=clean_parse)
    tolerant_calls = []
    real_tolerant = ast_scanner.parse_source_tolerant

    def spy(source, filename, parser_mode=DEFAULT_PARSER_MODE):
        tolerant_calls.append((filename, parser_mode))
        return real_tolerant(source, filename, parser_mode)

    healthy = {f"{name}.py": src for name, src in sorted(CORPUS.items())[:9]}
    real, ast_scanner._treesitter_packer = _treesitter_packer, wire
    ast_scanner.parse_source_tolerant = spy
    try:
        tracker = scan(healthy, "hybrid")
        assert wire.calls == [], f"a valid file consulted the packer: {wire.calls}"
        assert tolerant_calls == [], f"a valid file reached the tolerant parser: {tolerant_calls}"
        assert len(tracker.modules) == 9, len(tracker.modules)
        # The one door that is allowed to open: a file that raises SyntaxError.
        tracker = scan(dict(healthy, **{"broken.py": DAMAGED}), "hybrid")
        assert wire.calls == ["broken.py"], wire.calls
        assert tolerant_calls == [("broken.py", "hybrid")], tolerant_calls
        assert tracker.recovered_files == DAMAGED_RECOVERED, tracker.recovered_files
    finally:
        ast_scanner._treesitter_packer = real
        ast_scanner.parse_source_tolerant = real_tolerant
    print("  hybrid: 0 packer calls and 0 tolerant-parse calls over 9 valid files, "
          "1 each for a SyntaxError file")

    # ─── 4. Legacy mode integrity: `ast` never touches tree-sitter, and stays deterministic ───
    wire = Wire(delegate=clean_parse)
    real, ast_scanner._treesitter_packer = _treesitter_packer, wire
    try:
        corpus = dict(healthy, **{"broken.py": DAMAGED, "modern.py": MODERN})
        ast_tracker = scan(corpus, "ast")
        assert wire.calls == [], f"`ast` mode consulted the packer: {wire.calls}"
        assert ast_tracker.rescued_files == {}, ast_tracker.rescued_files
        assert "modern.py" in ast_tracker.recovered_files, ast_tracker.recovered_files
        assert ast_tracker.recovered_files["modern.py"] == MODERN_SWEPT_BLOCKS, ast_tracker.recovered_files
        assert ast_tracker.parse_stats["parser_mode"] == "ast", ast_tracker.parse_stats
        # Deterministic: the same corpus, twice, gives the same node ids and the same sweep ledger.
        again = scan(corpus, "ast")
        assert id_map(again) == id_map(ast_tracker)
        assert again.recovered_files == ast_tracker.recovered_files, (again.recovered_files,
                                                                      ast_tracker.recovered_files)
        # And fan-out eligibility is mode-aware. Proved without paying for two process spawns: a
        # recording stub that refuses to run shows the attempt was made in `ast` and `hybrid`, the
        # documented serial fallback then still produces all twelve modules, and `treesitter` never
        # asks for a pool at all.
        class NoPool(RuntimeError):
            pass

        attempts = []

        def fake_parallel(files, max_workers=None):
            attempts.append(len(files))
            raise NoPool("stub pool")

        assert ast_scanner.PARALLEL_PARSING_AVAILABLE is True
        twelve = {f"p{i:02d}.py": src for i, src in enumerate(sorted(CORPUS.values())[:12])}
        real_pf = ast_scanner.parse_files_parallel
        ast_scanner.parse_files_parallel = fake_parallel
        try:
            for mode in ("ast", "hybrid"):
                attempts.clear()
                wire.calls.clear()
                tracker = scan(twelve, mode)
                assert attempts == [12], (mode, attempts)
                assert tracker.execution_mode == "serial_fallback", (mode, tracker.execution_mode)
                assert "stub pool" in tracker.parallel_fallback_reason, tracker.parallel_fallback_reason
                assert len(tracker.modules) == 12, (mode, len(tracker.modules))
                assert wire.calls == [], (mode, wire.calls)
                assert "[RESCUED" not in tracker._stderr, tracker._stderr[:300]
            attempts.clear()
            tracker = scan(twelve, "treesitter")
            assert attempts == [], f"`treesitter` asked for a pool: {attempts}"
            assert tracker.execution_mode == "treesitter", tracker.execution_mode
            assert len(tracker.modules) == 12, len(tracker.modules)
            assert tracker.parse_stats["parsed_by_packer"] == 12, tracker.parse_stats
        finally:
            ast_scanner.parse_files_parallel = real_pf
    finally:
        ast_scanner._treesitter_packer = real
    print("  `ast`: zero packer consultations, sweep ledger identical run to run")

    # ─── 5. Modern syntax: hybrid and treesitter both keep every statement and sink ───
    native_rejects = False
    try:
        ast.parse(MODERN, filename="modern.py")
    except SyntaxError:
        native_rejects = True
    for mode in ("hybrid", "treesitter"):
        tracker = scan({"modern.py": MODERN}, mode)
        tree = next(iter(tracker.modules.values()))
        assert funcs(tree) == MODERN_FUNCS, (mode, funcs(tree))
        assert pairs(tracker) == (MODERN_SINKS, MODERN_SOURCES), (mode, pairs(tracker))
        assert len(tree.body) == 5, (mode, len(tree.body))  # 2 imports + 3 functions, none swept
        if mode == "treesitter":
            # The packer produced it as the *primary* reader, so it is not a rescue ledger entry.
            assert tracker.parse_stats["parsed_by_packer"] == 1, tracker.parse_stats
            assert tracker.rescued_files == {} and tracker.recovered_files == {}, tracker.recovered_files
        else:
            assert tracker.rescued_files == {"modern.py": "treesitter"}, tracker.rescued_files
    if native_rejects:
        legacy = scan({"modern.py": MODERN}, "ast")
        assert legacy.recovered_files == {"modern.py": MODERN_SWEPT_BLOCKS}, legacy.recovered_files
        assert pairs(legacy) == ([], []), pairs(legacy)
        assert set(funcs(next(iter(legacy.modules.values())))) == {"render", "handler"}
        print(f"  Python {PY}: `ast` mode loses the sink under the PEP 695 line - the two packer "
              f"modes keep both")
    else:
        assert pairs(scan({"modern.py": MODERN}, "ast")) == (MODERN_SINKS, MODERN_SOURCES)
        print(f"  Python {PY}: all three modes parse the modern fixture natively")

    # ─── 6. Damaged source lands on the same sweep in every mode ───
    ledgers = {}
    for mode in ("ast", "hybrid", "treesitter"):
        tracker = scan({"broken.py": DAMAGED}, mode)
        ledgers[mode] = (tracker.recovered_files, tracker.rescued_files,
                         sorted(tracker.skipped_files), pairs(tracker))
        assert "RESCUED" not in tracker._stderr, (mode, tracker._stderr)
    assert ledgers["ast"] == ledgers["hybrid"] == ledgers["treesitter"], ledgers
    print(f"  damaged file: identical sweep ledger in all three modes "
          f"({DAMAGED_RECOVERED['broken.py']})")

    # ─── 7. Bad configuration is ignored loudly, never honoured silently ───
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        assert _normalise_parser_mode("TreeSitter ") == "treesitter"
        assert _normalise_parser_mode(None) == "hybrid"
        assert _normalise_parser_mode("ast-first") == "hybrid"
        assert _normalise_parser_mode(7) == "hybrid"
    notes = err.getvalue()
    # Three refusals, one acceptance: casing and padding are tolerated, an unknown word is not.
    assert notes.count("[PARSER-MODE] ignored unknown parser mode") == 3, notes
    for bad in ("None", "'ast-first'", "7"):
        assert f"ignored unknown parser mode {bad}; using 'hybrid'" in notes, bad
    assert "TreeSitter" not in notes, notes
    # The same rule one level up: a tracker built with a nonsense mode runs the default and says so.
    tracker = scan({"x.py": CORPUS["c01_os_system"]}, "nonsense-mode")
    assert tracker.parse_stats["parser_mode"] == "hybrid", tracker.parse_stats
    assert "ignored unknown parser mode 'nonsense-mode'" in tracker._stderr, tracker._stderr[:200]
    assert "[RESCUED" not in tracker._stderr, tracker._stderr[:200]
    print("  4 bad mode values: 3 ignored with a stderr note, 1 accepted after normalising, none raised")

    # ─── 8. Memory boundary: 60 treesitter-mode scans do not accumulate ───
    if psutil is not None:
        gc.collect()
        rss0 = psutil.Process().memory_info().rss
        wall = {mode: [] for mode in ("hybrid", "ast")}
        for _ in range(30):
            tracker = scan(healthy, "treesitter")
            assert len(tracker.modules) == 9, len(tracker.modules)
            for mode in wall:
                wall[mode].append(scan(healthy, mode)._elapsed)
        gc.collect()
        grew = psutil.Process().memory_info().rss - rss0
        assert grew < 25 * MB, f"30 treesitter-mode scans of 9 files grew RSS by {grew / MB:.1f} MB"
        parked = [k for k, v in vars(ast_scanner._treesitter_packer).items() if isinstance(v, ast.AST)]
        assert parked == [], f"the packer cached parsed AST nodes globally: {parked}"
        # Same-corpus wall clock: the default mode must not become the expensive one.
        med_h = statistics.median(wall["hybrid"])
        med_a = statistics.median(wall["ast"])
        assert med_h <= med_a * 1.5 + 0.002, (med_h, med_a)
        print(f"  30 treesitter scans grew RSS {grew / MB:.1f} MB; hybrid median "
              f"{med_h * 1000:.1f} ms vs ast median {med_a * 1000:.1f} ms on the same 9 files")


if __name__ == "__main__":
    if not tree_sitter_available():
        print(f"SKIP: tree-sitter not installed on Python {PY}")
        sys.exit(0)
    test_parser_modes()
    print(f"parser modes: all assertions passed on Python {PY}")
