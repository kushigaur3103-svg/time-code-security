"""Fail-loud lock: the CWE-22 sink-argument (in-memory buffer) exemption, and the three proposals it refuses.

    python benchmark/gates/cwe22_sink_argument_probe.py

The proposal came from the odoo arena: 165 CWE-22 findings over 2,128 results in 7,191 files, of which
**78 rows are `PIL.Image.open`** and **75 of those 78 pass a stream, not a path** - `Image.open(io.BytesIO(resp.content))`.
PIL reads the bytes it is handed; no filename participates in resolving anything on disk, so the
traversal sink the callee *name* suggests is unreachable from that argument. Five candidate predicates
were written and measured over the 165 rows (`scratch/_c22_predicates.py`, arena rows in
`scratch/_c22/rows.json`):

| predicate | arena rows hit | blessed CWE-22 keys hit | verdict |
|---|---|---|---|
| **P1** `args[0]` is an inline `io.BytesIO`/`io.StringIO` construction | 73 | 0 | **shipped** |
| **P2** one hop: `s = io.BytesIO(d)` then `sink(s)`, unique nearest binding | 1 | 0 | **shipped** |
| **P3** the path hangs off a `tempfile.TemporaryDirectory` / `mkdtemp` root | 4 | **3** | **refused** |
| **P4** every path segment is a compile-time string constant | 2 | 0 | **refused** |
| **P5** exempt by sink *method name* (`remove`, `extract`, `open`) | 3 | **1** | **refused** |

**P3 is refused because it deletes blessed true positives**, measured key by key: it flags
`tests__generation__test_utils.py:5537`, `:5539` and `:5565` - three of the sixteen blessed Big-8 CWE-22
keys. This is also why no temp-dir rule may be written later: those three keys are named in TIER 1 and
in `REFUSED_TARGETS` below, and the same predicate that quieted 4 arena rows would have taken them.

**P4 is refused on yield *and* on two concrete false-negative vectors.** Yield: every literal-path
shape is *already* silent on the clean engine - measured over TIER 3, `open("base/static/img/x.png")`
-> 0 CWE-22 rows, `open(os.path.join("base", "static", "x.png"))` -> 0, `Path("data/x.csv").read_text()`
-> 0, `open("../secret/app.env")` -> 0. The engine skips pure-string literals at
`ast_scanner.py:20423` and the pathlib receivers never reach a path sink, so a P4 rule buys nothing.
What it would cost: `zipfile.ZipFile(tainted_bytes).extractall("/tmp/out")` reports today
(`zip_slip_literal_dest` in `SEAL_BUDGET`) - the destination is literal, the *members* come from the
archive, which is the whole zip-slip bug - and `extractor.extract()` at the blessed
`tests__models__markuplm__test_tokenization_markuplm.py:138` has **no path argument at all**, so
"all segments are constants" is vacuously true for it and the rule would delete a blessed key on a
technicality. A rule with zero measured yield and two named FN vectors is not a precision fix.

**P5 is refused by the task itself** ("DO NOT exempt based on generic method names") and is locked by
`list_remove_collision` (`fields.remove(request.args["f"])`, reported as `PATH_TRAVERSAL_REMOVE`) and
by `no_arg_extract_method` - the arena has 8 `shutil.rmtree`, 7 `os.unlink` and 4 `shutil.move` rows
whose *first* argument is a real path, so a name-keyed exemption has nothing to trade.

The shipped rule (P1+P2) is deliberately narrower than "the callee got a stream". It fires only when
*all four* hold: the call has a **positional** `args[0]` (so a no-argument sink such as `extract()` or
`tekken_path.read_bytes()` can never be exempted); `args[0]` is a `BytesIO`/`StringIO` construction,
either through an `io`/`_io` receiver or through a bare name this module imported from `io`; or one
unique nearest prior binding of that name; and **every other positional argument and keyword value is
a literal** - `send_file(io.BytesIO(d), download_name=request.args["n"])` keeps the request read in a
non-first slot and must keep reporting (`send_file_bytesio_with_name`), as does
`open(io.BytesIO(d), user_mode)` and `open(os.path.join("/srv", io.BytesIO(d)))`, where the buffer is
buried inside the path expression instead of being it.

Three engine addresses emit this shape, found by wiring the rule one address at a time and
re-running this file: the registry sinks that reach `_collect_cwe22_path_traversal_findings` (prune
loop, `ast_scanner.py:20196`), that collector's own walk (`:20533`), and
`_collect_cwe22_parameter_path_sinks` (`:12178`) - the last only for `open(buf)` and `io.open(buf)`,
because `FILE_OPEN_FUNCS` is `{"open", "io.open", "builtins.open"}` and `Image.open` is not in it.
With two of the three wired, `open_bytesio_param` and `io_open_bytesio_param` still reported, which is
why they are separate `SEAL_TARGETS`: the promise is per *address*, not per callee name.

A CWE-22 sink node can carry another CWE's finding, so the exemption removes **only the CWE-22
records** and drops a `SecurityNode` once nothing refers to it - the `_remove_existing` discipline at
`ast_scanner.py:21646`, not the whole-sink prune at `:20194` that `# ok` and the sanitizer guard use.
Measured on the arena: 74 CWE-22 rows went silent and the row count of every other CWE in the same run
(`CWE-78`, `CWE-434`, `CWE-116`, `CWE-117`, `CWE-611`, `CWE-295`, `CWE-79`, `CWE-601`, `CWE-770`,
`CWE-209`) did not move by one.

    cwe22_sink_argument_probe.py     PASS - 24 blessed keys, 9 live derivations, 14/14 report,
                                     7/7 targets silent                                    (49.7 MB)
    aa_parity.py                     baseline=425 now=425 MISSING=0 NEW=0 exact-set       (141.3 MB)
    big8_ab.py                       baseline=119 now=119 MISSING=0 NEW=0 exact-set       (140.6 MB)
    cross_runner.py                  12 TP / 0 FP / 0 FN, F1 1.0000, exact-set YES         (34.9 MB)
    cwe22_dirent_closure_probe.py    PASS - 16 blessed                                     (44.3 MB)
    cwe117_cwe22_unknown_source...   PASS - 59/59 (43 CWE-117 + 16 CWE-22 placeholder)    (32.4 MB)
    cwe117_builtin_seal_probe.py     PASS - 49 blessed                                     (32.7 MB)
    cwe117_numeric_provenance...     PASS - 17 tainted reported, 8 silent                 (155.8 MB)
    cwe338_ml_math_probe.py          PASS - 62 cases, 0 failures                           (23.5 MB)
    cwe338_prng_context_probe.py     PASS - 16 blessed, 12 exempted                       (157.9 MB)
    cwe434_local_serialization...    PASS - 7 uploads blessed, 425/425, 17 live           (70.6 MB)
    cwe611_xml_entity_probe.py       PASS - 16 blessed, 14 reported, 3 silent            (152.9 MB)
    cwe798_credential_concreteness   PASS - 6 blessed, 12 fixtures exact-set              (33.8 MB)
    odoo arena - 47 files, 1,426,446 bytes at the pinned sha, scanned with the same
     `cli.py scan` on a byte-identical copy of the pre-change engine (`1b533f98963755a2`):
     CWE-22 165 -> 91, i.e. 74 rows retired (44.8%), 0 rows gained, other CWEs identical
    paired clock, 609 files, 3 pairs - traversal collector median +4.90 ms, parameter-path
     collector median +2.80 ms, retained population identical: 15/15 CWE-22 sinks of 583
     sinks, 603 records, 508 edges                                                       (118.4 MB)

Falsification, in both directions, run for real. With the exemption on disk and this file left at
`SINK_ARG_SEAL = 'pending'` it prints `buffer targets silent: 7/7` and exits 1, so an exemption this
file does not know about cannot land. With the seal at `'shipped'` and `TCS_SINK_ARG_ENGINE` pointed at
the pre-change engine it prints `buffer targets silent: 0/7` and exits 1, so a later refactor that
deletes the rule cannot pass unnoticed either. Both the 14 contract rows and the 9 live derivations
report in every one of those runs - the failure is always the promise, never a finding.

Tiers: TIER 1 asserts the blessed CWE-22 population key by key from both tracked baselines (8 parity +
16 Big-8 = 24). TIER 2 re-scans the nine files that carry those keys, in memory, on the engine that is
on disk. TIER 3 re-measures every escape shape and the exemption promise.
"""
from __future__ import annotations

import collections
import contextlib
import importlib.util
import io
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

if os.environ.get('TCS_SINK_ARG_ENGINE'):
    # falsification hook: load an alternative ast_scanner.py and let the gate argue against it. With
    # `SINK_ARG_SEAL = 'shipped'` and the pre-exemption engine, 0/7 targets go silent and the gate
    # exits 1, so deleting the exemption from ast_scanner.py cannot pass unnoticed. The module is
    # registered under its real name because `dataclass(slots=True)` and `cli` both resolve the engine
    # through sys.modules, so an override that is not registered cannot even be imported.
    _spec = importlib.util.spec_from_file_location(
        'ast_scanner', os.environ['TCS_SINK_ARG_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, corpus_dir, load_keys, verify_corpus  # noqa: E402

SINK_ARG_SEAL = 'shipped'   # 'shipped' only once ast_scanner.py carries the in-memory-buffer exemption

LOCKED_CWE22 = {'parity': 8, 'big8': 16}

# (relative path, blessed CWE-22 lines) - every file that carries a blessed CWE-22 key, measured to
# reproduce exactly that line set when scanned alone in memory.
BLESSED_FILES = [
    ('benchmark/corpus/cwe_22_traversal/bad.py', [5]),
    ('benchmark/corpus/cwe_22_traversal/test_v01_bad.py', [5]),
    ('benchmark/corpus/cwe_22_traversal/test_v02_bad.py', [8]),
    ('benchmark/corpus/cwe_22_traversal/test_v03_bad.py', [5]),
    ('benchmark/corpus/cwe_22_traversal/test_v05_bad.py', [8]),
    ('benchmark/corpus/cwe_937_insecure_protocol/test_v06_bad.py', [6]),
    ('benchmark/corpus/cwe_937_insecure_protocol/test_v06_good.py', [7]),
    ('benchmark/runner.py', [105]),
]
BIG8_LEAF = 'tests__models__markuplm__test_tokenization_markuplm.py'
BLESSED_BIG8_LINES = [73, 75, 77, 138]
EXTRACT_LINE = 138      # extractor.extract() - no argument at all, so no path can be inspected
NO_ARG_FLOOR = [
    ('src__transformers__modeling_utils.py', 3494),   # os.remove, 1 arg, a listdir-derived path
    ('src__transformers__trainer.py', 2008),          # shutil.rmtree(checkpoint, ignore_errors=True)
]

BLESSED_PARITY_22 = [
    ('bad.py', 5), ('test_v01_bad.py', 5), ('test_v02_bad.py', 8), ('test_v03_bad.py', 5),
    ('test_v05_bad.py', 8), ('test_v06_bad.py', 6), ('test_v06_good.py', 7), ('runner.py', 105),
]
BLESSED_BIG8_22 = [
    ('src__transformers__modeling_utils.py', 336),
    ('src__transformers__modeling_utils.py', 3494),
    ('src__transformers__modeling_utils.py', 3564),
    ('src__transformers__trainer.py', 2008),
    ('src__transformers__trainer.py', 4301),
    ('tests__generation__test_utils.py', 5537),
    ('tests__generation__test_utils.py', 5539),
    ('tests__generation__test_utils.py', 5565),
    (BIG8_LEAF, 138),
    (BIG8_LEAF, 73),
    (BIG8_LEAF, 75),
    (BIG8_LEAF, 77),
    ('tests__test_modeling_common.py', 1279),
    ('tests__test_tokenization_mistral_common.py', 263),
    ('tests__test_tokenization_mistral_common.py', 274),
    ('tests__test_tokenization_mistral_common.py', 280),
]

REQ = 'from flask import request\n'
IMP = 'import io, os, pathlib, tempfile, zipfile\n'
PIL = 'from PIL import Image\n'

# Every row below was measured to REPORT on the clean engine, so each one is a real contract: a
# buffer exemption must still report all of them. Three rows exist to pin the refusals -
# `zip_slip_literal_dest` (P4), `no_arg_extract_method` (P4 vacuity, blessed :138) and
# `list_remove_collision` (P5) - and the rest pin the four clauses of the shipped rule.
SEAL_BUDGET = [
    # plain traversal surface: nothing here is a stream, so none of it may be exempted
    ('param_path_open', REQ + IMP + 'def h(user_path):\n    return open(user_path).read()\n', 'report'),
    ('fstring_hole_path', REQ + IMP + 'def h():\n    name = request.args.get("n")\n'
     '    return open(f"/var/log/{name}").read()\n', 'report'),
    ('dict_subscript_path', REQ + IMP + 'def h():\n    cfg = {"p": request.args.get("n")}\n'
     '    return open(cfg["p"]).read()\n', 'report'),
    ('helper_return_path', REQ + IMP + 'def build(n):\n    return f"/var/app/{n}"\n'
     'def h():\n    return open(build(request.args.get("n"))).read()\n', 'report'),
    ('join_with_request', REQ + IMP + 'def h():\n'
     '    return open(os.path.join("/srv", request.args["f"])).read()\n', 'report'),
    # zip-slip: the destination is a literal, the members come out of the archive. This is the row P4
    # would have deleted for "all path segments are compile-time constants".
    ('zip_slip_literal_dest', REQ + IMP + 'def h():\n    data = request.args.get("d")\n'
     '    z = zipfile.ZipFile(io.BytesIO(data))\n    z.extractall("/tmp/out")\n', 'report'),
    ('zip_slip_namelist_members', REQ + IMP + 'def h(dest):\n    data = request.args.get("d")\n'
     '    z = zipfile.ZipFile(io.BytesIO(data))\n'
     '    z.extractall(dest, [m for m in z.namelist() if m.startswith("f/")])\n', 'report'),
    # blessed :138 shape - a no-argument sink has no args[0] to inspect, so the rule must not fire
    ('no_arg_extract_method', REQ + IMP + 'class Tok:\n    def __init__(self, p):\n        self.p = p\n'
     '    def extract(self):\n        return self.p\n'
     'def h():\n    t = Tok(request.args.get("p"))\n    return t.extract()\n', 'report'),
    # P5 lock: a generic method name carrying a real first argument
    ('list_remove_collision', REQ + IMP + 'def h():\n    fields = ["a", "b"]\n'
     '    fields.remove(request.args.get("f"))\n    return fields\n', 'report'),
    # the binding must be the *nearest* one: a stream that later becomes a path is a path
    ('buffer_then_path_reassign', REQ + IMP + PIL + 'def h():\n    d = request.args.get("d")\n'
     '    stream = io.BytesIO(d)\n    stream = request.args.get("p")\n    return Image.open(stream)\n',
     'report'),
    # a buffer in args[0] does not make the rest of the call inert
    ('send_file_bytesio_with_name', REQ + IMP + 'from werkzeug.utils import send_file\n'
     'def h():\n    d = request.args.get("d")\n'
     '    return send_file(io.BytesIO(d), download_name=request.args["n"])\n', 'report'),
    ('open_bytesio_dynamic_mode', REQ + IMP + 'def h(data, mode):\n'
     '    return open(io.BytesIO(data), mode).read()\n', 'report'),
    # the buffer has to *be* the path argument, not sit inside it
    ('bytesio_into_join', REQ + IMP + 'def h():\n    d = request.args.get("d")\n'
     '    return open(os.path.join("/srv", io.BytesIO(d)))\n', 'report'),
    # a module-local class answering to the buffer name is not io.BytesIO
    ('user_class_bytesio', IMP + PIL + 'class BytesIO:\n    def __init__(self, x):\n        self.x = x\n'
     + REQ + 'def h():\n    d = request.args.get("d")\n    return Image.open(BytesIO(d))\n', 'report'),
]

# The exemption's own promise: a stream handed to a path-named sink. All seven were measured to REPORT
# on the clean engine (the arena shape is the majority of its 165 CWE-22 rows), so each one is a live
# false positive today and a row a shipped exemption must silence.
SEAL_TARGETS = [
    ('image_open_inline_buffer', REQ + IMP + PIL + 'def h():\n    d = request.args.get("d")\n'
     '    return Image.open(io.BytesIO(d))\n'),
    ('image_open_bound_buffer', REQ + IMP + PIL + 'def h():\n    d = request.args.get("d")\n'
     '    stream = io.BytesIO(d)\n    return Image.open(stream)\n'),
    ('image_open_stringio', REQ + IMP + PIL + 'def h():\n    d = request.args.get("d")\n'
     '    return Image.open(io.StringIO(d))\n'),
    ('image_open_bare_imported_buffer', REQ + IMP + PIL + 'from io import BytesIO\n'
     'def h():\n    d = request.args.get("d")\n    return Image.open(BytesIO(d))\n'),
    ('image_open_buffer_with_literal_mode', REQ + IMP + PIL + 'def h():\n    d = request.args.get("d")\n'
     '    s = io.BytesIO(d)\n    return Image.open(s, "r")\n'),
    # registry + walk address (`open` is a CWE-22 sink symbol): `Image.open` is not in FILE_OPEN_FUNCS,
    # so these two exercise the *other* emission address instead of the same one twice.
    ('open_bytesio_param', IMP + REQ + 'def h(data):\n    return open(io.BytesIO(data), "rb").read()\n'),
    ('io_open_bytesio_param', IMP + REQ + 'def h(data):\n'
     '    return io.open(io.BytesIO(data), "rb").read()\n'),
]

# Measured and deliberately kept out of SEAL_BUDGET/SEAL_TARGETS: these are already silent on the clean
# engine, so they prove nothing about a future rule (the dirent probe's rule for contract rows).
ALREADY_SILENT = ['tempdir_path', 'literal_parent_escape', 'open_literal_path', 'open_literal_via_join',
                  'read_text_receiver_literal', 'shadowed_bytesio']


def scan(label, source):
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={f'{label}.py': source})
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return [row for row in rows if row['cwe'] == 'CWE-22']


def read_source(path):
    """Read a tracked file through a sanitized path, so this harness adds no CWE-22 key of its own."""
    with open(os.path.abspath(path), encoding='utf-8', errors='replace') as handle:
        return handle.read()


def scan_file(path, label):
    return scan(label, read_source(path))


def check_floors():
    """TIER 1: 24 blessed CWE-22 keys, named, still in the baselines."""
    failures = []
    for kind, want, blessed in (('parity', LOCKED_CWE22['parity'], BLESSED_PARITY_22),
                                ('big8', LOCKED_CWE22['big8'], BLESSED_BIG8_22)):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        split = collections.Counter(row[2] for row in rows)
        cwe22 = [(os.path.basename(str(row[0])), row[1]) for row in rows if row[2] == 'CWE-22']
        print(f'  {"ok  " if len(rows) == META[kind]["expected_keys"] else "FAIL"} {kind:6s} '
              f'total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-22={split["CWE-22"]} (want {want})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if split['CWE-22'] != want:
            failures.append((kind, 'CWE-22', want, split['CWE-22'],
                             'the CWE-22 population moved - nothing may be re-blessed'))
        absent = [f'{leaf}:{line}' for leaf, line in blessed if (leaf, line) not in cwe22]
        print(f'  {"ok  " if not absent else "FAIL"} {kind:6s} blessed keys accounted '
              f'{len(blessed) - len(absent)}/{len(blessed)} {absent}')
        if absent:
            failures.append((kind, 'blessed keys', len(blessed), len(blessed) - len(absent), absent))
    # the two keys whose argument list is what protects them
    rows = load_keys(os.path.join(GATES_DIR, META['big8']['keys_file']), 'big8')
    present = {(os.path.basename(str(r[0])), r[1]) for r in rows if r[2] == 'CWE-22'}
    for leaf, line in [(BIG8_LEAF, EXTRACT_LINE)] + NO_ARG_FLOOR:
        ok = (leaf, line) in present
        print(f'  {"ok  " if ok else "FAIL"} no-arg/one-arg floor {leaf}:{line} blessed={ok}')
        if not ok:
            failures.append(('arg-count floor', f'{leaf}:{line}', 'blessed', 'absent',
                             'a sink whose protection is its argument list is gone'))
    temp = [f'{leaf}:{line}' for leaf, line in BLESSED_BIG8_22
            if leaf == 'tests__generation__test_utils.py' and (leaf, line) in present]
    print(f'  {"ok  " if len(temp) == 3 else "FAIL"} P3 temp-dir floor: test_utils keys blessed '
          f'{len(temp)}/3 {temp}')
    if len(temp) != 3:
        failures.append(('P3 refusal', '3 temp-dir keys blessed', len(temp), temp,
                         'the keys that forbid a tempfile-root exemption are gone - investigate'))
    return failures


def check_live_derivation():
    """TIER 2: the nine blessed-carrier files, scanned from disk by the engine on disk.

    Independent of `SINK_ARG_SEAL`: the exemption may not touch any of these derivations, so the
    assertion is the same whether or not it is shipped - which is what makes it a lock.
    """
    failures = []
    for rel, want in BLESSED_FILES:
        path = os.path.join(ROOT, *rel.split('/'))
        lines = sorted(row['line'] for row in scan_file(path, os.path.basename(rel)))
        ok = lines == sorted(want)
        print(f'  {"ok  " if ok else "FAIL"} live {rel:58s} lines={lines} want={sorted(want)}')
        if not ok:
            failures.append((rel, sorted(want), lines, 'a blessed CWE-22 derivation stopped reporting'))
    directory = corpus_dir('big8')
    verify_corpus('big8', directory)
    path = os.path.join(directory, BIG8_LEAF)
    rows = scan_file(path, BIG8_LEAF)
    lines = sorted(row['line'] for row in rows)
    ok_lines = lines == sorted(BLESSED_BIG8_LINES)
    print(f'  {"ok  " if ok_lines else "FAIL"} live corpus {BIG8_LEAF} lines={lines} '
          f'want={sorted(BLESSED_BIG8_LINES)}')
    if not ok_lines:
        failures.append((BIG8_LEAF, sorted(BLESSED_BIG8_LINES), lines,
                         'the literal-path or no-argument exemption deleted a blessed true positive'))
    message = {row['line']: row['message'] for row in rows}.get(EXTRACT_LINE, '')
    ok_extract = 'extract' in message.lower()
    print(f'  {"ok  " if ok_extract else "FAIL"} vacuity floor {BIG8_LEAF}:{EXTRACT_LINE} '
          f'message={message!r}')
    if not ok_extract:
        failures.append((f'{BIG8_LEAF}:{EXTRACT_LINE}', 'extract sink', message,
                         '"all segments are constants" is vacuously true when there are no segments'))
    return failures


def check_seal_budget():
    """TIER 3: the escape shapes must report, and the exemption promise must be kept or refused loudly."""
    failures = []
    for label, source, want in SEAL_BUDGET:
        got = 'report' if scan(label, source) else 'silent'
        ok = (got == want)
        print(f'  {"ok  " if ok else "FAIL"} {label:30s} want={want:6s} got={got}')
        if not ok:
            failures.append((label, want, got,
                             'the buffer exemption silenced a shape that carries a real path argument'
                             if SINK_ARG_SEAL == 'shipped' else
                             'a must-report shape went silent on the clean engine - the contract rows '
                             'are no longer live findings'))
    silent = [label for label, source in SEAL_TARGETS if not scan(label, source)]
    if SINK_ARG_SEAL == 'pending':
        print(f'  seal pending; buffer targets silent: {len(silent)}/{len(SEAL_TARGETS)} {silent}')
        if silent:
            failures.append(('SINK_ARG_SEAL', 'pending', 'buffer targets silent', silent,
                             'an in-memory-buffer exemption exists in ast_scanner.py but this file '
                             'still says pending'))
        return failures
    print(f'  seal shipped; buffer targets silent: {len(silent)}/{len(SEAL_TARGETS)} {silent}')
    if len(silent) != len(SEAL_TARGETS):
        failures.append(('SINK_ARG_SEAL', 'shipped',
                         f'{len(SEAL_TARGETS) - len(silent)} still reported', silent,
                         'the exemption is incomplete at one of the emission addresses'))
    return failures


def main() -> int:
    print('TIER 1 - blessed CWE-22 floor, 24 keys asserted from the tracked baselines:')
    failures = check_floors()
    print('TIER 2 - blessed derivations scanned live on the engine on disk:')
    failures += check_live_derivation()
    print('TIER 3 - shapes that must report, plus the in-memory-buffer promise:')
    failures += check_seal_budget()
    print(f'\nsink_arg_seal={SINK_ARG_SEAL} locked_cwe22={sum(LOCKED_CWE22.values())} '
          f'budget={len(SEAL_BUDGET)} targets={len(SEAL_TARGETS)} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-22 sink-argument decision no longer matches its evidence. '
              'Restoring the finding is the fix; re-blessing a baseline is not.')
        return 1
    print('VERDICT: PASS - 24 blessed CWE-22 keys, the no-argument and literal-destination shapes a '
          'broader rule would have deleted, and the buffer exemption at every emission address.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
