"""Truth table for the CWE-117 numeric-provenance pitch: the lock that fails if it is ever shipped blind.

    python benchmark/gates/cwe117_numeric_provenance_probe.py

The pitch this file exists to test, in its own words: "a hole whose f-string carries a numeric format
specifier (`{x:.4f}`, `{n:d}`) or a `range()` loop counter cannot carry CR/LF, so stop reporting
CWE-117 on it." Measured against the exact code this gate ships with, the pitch has **zero yield and
a real cost**, and the three tiers below assert both halves of that sentence rather than arguing it.

What was measured, and where it came from:

* the real-world corpus the pitch targets -- the odoo arena scan in `benchmark_results/tcs.sarif`
  (40,096 files, `--scope all`, engine at dispatch sha f7d144f2) holds **39** CWE-117 rows. All 39
  were re-produced by a whole-tree scan of the 16 source files at odoo sha dca5cd22 (exact-set match,
  arena-only=0 live-only=0) and **0 of 39 are f-string log calls**: they are lazy `%`-arguments
  (`_logger.info("... %s", auth_type)`), `%`-format (`"Fail to upload %s" % ufile.filename`),
  `.format()` (`"Removing '{}'".format(addon_path)`), and bare names (`logger.warning(e)`). Every one
  of them is string-bearing today and stays string-bearing under the pitch;
* the blessed population -- all **49** CWE-117 keys (6 parity + 43 Big-8) were classified hole by
  hole against the proposed rule: `WOULD-BECOME-FN = 0`, `already-safe-today = 0`, `stays-reported
  = 44`, `non-f-string = 5`. So the rule deletes no blessed key **and collapses no FP either**;
* the three shapes the pitch names as its own examples (`f"Loss: {loss:.4f} - Step: {step:d}"`,
  `f"Progress: {skipped / (2**20)} MB"`, `for i in range(epochs): f"Epoch {i}"`) are **already SILENT
  in the shipped engine** -- not because a numeric exemption catches them, but because CWE-117 needs a
  taint source at the sink and an unbound metric name is not one. There is no finding there to remove.

The same rule applied to a hole that *is* reached by a taint source does silence a live finding:
`rows = request.args.get("q"); logger.info(f"n={rows:d}")` reports today and would go quiet, because
`str` rejects the `d` type only by *raising at runtime*. A value whose class defines `__format__` --
or an `int` subclass that overrides it -- answers to the same specifier and returns whatever its author
chose, so the specifier proves the shape the author hoped for, not the type that arrives. That is the
false negative this table freezes, and it is why `SEAL` is `'refused'`: the exemption budget below is
what any future implementation must re-prove against a measured corpus before a single key moves.

Sources are assembled by concatenating string constants, so the parity gate -- which scans this whole
tree -- finds no `logger.info(...)` call node inside this harness. Same convention as
`cwe117_builtin_seal_probe.py`.

Falsification, which is the point of the file: set `TCS_NUMERIC_PROV_ENGINE` to an `ast_scanner.py`
that implements the numeric-specifier / range-counter exemption and this gate FAILS on the rows named
in `SPEC_SHAPES`. Run it that way before ever believing a "+N precision" claim.
"""
from __future__ import annotations

import collections
import contextlib
import importlib.util
import io
import os
import re
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

SEAL = 'refused'          # 'refused' = engine has no numeric-specifier/range exemption; 'implemented' = it does
SEAL_TARGETS = ('refused', 'implemented')

if os.environ.get('TCS_NUMERIC_PROV_ENGINE'):
    # falsification hook: load an alternative ast_scanner.py and let the gate argue against it. The
    # module is registered under its real name because `dataclass(slots=True)` and `cli` both resolve
    # the engine through sys.modules, so an override that is not registered cannot even be imported.
    _spec = importlib.util.spec_from_file_location(
        'ast_scanner', os.environ['TCS_NUMERIC_PROV_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys, scan_rows  # noqa: E402

LOCKED = {'parity': 6, 'big8': 43}
PRESENTATION = frozenset('deEfgGnboxX')          # int/float-only types; `%` and `c` are NOT in here

REQ = 'from flask import request\n'
LOG = 'import logging\nlogger = logging.getLogger(__name__)\n'
TAINT = '    rows = request.args.get("q")\n'

# (label, source, verdict-at-refused, verdict-at-implemented, note)
SHAPES = [
    # --- the holes the pitch would quiet, all of which report today --------------------------
    ('tainted_int_spec', REQ + LOG + 'def h():\n' + TAINT + '    logger.info(f"n={rows:d}")\n',
     'report', 'silent', 'the headline pitch: a `d` spec on a value that is a str at runtime'),
    ('tainted_float_spec', REQ + LOG + 'def h():\n' + TAINT + '    logger.info(f"v={rows:.4f}")\n',
     'report', 'silent', '`.4f` spec, same bet on a runtime TypeError'),
    ('tainted_grouped_spec', REQ + LOG + 'def h():\n' + TAINT + '    logger.info(f"n={rows:,d}")\n',
     'report', 'silent', 'grouping option in front of the type still proves nothing about the type'),
    ('tainted_hex_spec', REQ + LOG + 'def h():\n' + TAINT + '    logger.info(f"n={rows:x}")\n',
     'report', 'silent', '`x` is int-only, and an int subclass can still override __format__'),
    ('tainted_range_counter', REQ + LOG + 'def h():\n' + TAINT +
     '    for i in range(rows):\n        logger.info(f"step {i}")\n',
     'report', 'silent', 'the range() counter clause, with a tainted bound'),
    ('custom_format_class', REQ + LOG + 'class Blob:\n    def __format__(self, spec):\n'
     '        return "a\\r\\nb"\n' + 'def h():\n    blob = Blob(request.args.get("q"))\n'
     '    logger.info(f"n={blob:d}")\n',
     'report', 'silent', 'a class in this module answers to the spec itself and emits CRLF'),
    ('tainted_attr_spec', REQ + LOG + 'def h(args):\n    logger.info(f"Config: {args.n:.1f}")\n',
     'report', 'silent', 'attribute hole -- the task\'s own must-report shape once a spec is added'),
    # --- the boundary the shipped seal already holds ---------------------------------------
    ('bare_hole', REQ + LOG + 'def h():\n' + TAINT + '    logger.info(f"n={rows}")\n',
     'report', 'report', 'no spec, nothing to argue about'),
    ('str_of_exception', REQ + LOG + 'def h():\n    e = request.args.get("q")\n'
     '    logger.error(str(e))\n', 'report', 'report', 'parity floor test_v01_good.py:12'),
    ('abs_hole', REQ + LOG + 'def h():\n    o = request.args.get("q")\n    logger.info(f"n={abs(o)}")\n',
     'report', 'report', 'abs returns whatever __abs__ returns'),
    ('mixed_hole', REQ + LOG + 'def h():\n' + TAINT + '    logger.info(f"a={len(rows)} b={rows}")\n',
     'report', 'report', 'all-or-nothing: one unsafe hole keeps the whole message'),
    ('dict_subscript', REQ + LOG + 'def h():\n    user = request.args.get("u")\n'
     '    entry = {"msg": f"login {user}"}\n    logging.info(entry["msg"])\n',
     'report', 'report', 'the blessed fixture shape, test_v03_bad.py:5'),
    ('helper_return', REQ + LOG + 'def build_log_msg(u):\n    return u\n'
     'def h():\n    logging.error(build_log_msg(request.args.get("q")))\n',
     'report', 'report', 'the task must-report fixture shape (test_v02_bad.py)'),
    ('lazy_percent_args', REQ + LOG + 'def h():\n' + TAINT + '    logger.info("cfg: %s", rows)\n',
     'report', 'report', 'the shape that actually dominates the real-world 39'),
    ('percent_format', REQ + LOG + 'def h():\n    f = request.args.get("q")\n'
     '    logger.exception("Fail to upload %s" % f)\n', 'report', 'report',
     ' `%`-interpolated message, second real-world family'),
    ('dot_format', REQ + LOG + 'def h():\n    p = request.args.get("q")\n'
     '    logging.info("Removing {}".format(p))\n', 'report', 'report',
     '.format message, third real-world family'),
    ('exception_object', REQ + LOG + 'def h():\n' + TAINT +
     '    try:\n        int(rows)\n    except ValueError as e:\n        logger.warning(e)\n',
     'report', 'report', 'bare exception argument, fourth real-world family'),
    # --- what the pitch calls its FP cluster: already quiet, and for a different reason ------
    ('metric_spec_no_source', LOG + 'def train(loss, step):\n'
     '    logger.info(f"Loss: {loss:.4f} - Step: {step:d}")\n', 'silent', 'silent',
     'task example 1 -- silent today because no taint source reaches the sink'),
    ('mb_binop_no_source', LOG + 'def run(skipped):\n    logger.info(f"Progress: {skipped / (2**20)} MB")\n',
     'silent', 'silent', 'task example 2 -- same'),
    ('range_loop_no_source', LOG + 'def loop(epochs):\n    for i in range(epochs):\n'
     '        logger.info(f"Epoch {i}")\n', 'silent', 'silent', 'task example 3 -- same'),
    # --- already exempted by the shipped builtin-scalar seal --------------------------------
    ('len_only_hole', REQ + LOG + 'def h():\n' + TAINT + '    logger.info(f"n={len(rows)}")\n',
     'silent', 'silent', 'the seal that exists, and covers the only real-world-safe family'),
    ('int_only_hole', REQ + LOG + 'def h():\n' + TAINT + '    logger.info(f"n={int(rows)}")\n',
     'silent', 'silent', 'int() returns a builtin int or raises'),
    ('float_bool_ord_holes', REQ + LOG + 'def h():\n    x = request.args.get("q")\n'
     '    logger.info(f"{float(x)}{bool(x)}{ord(x)}")\n', 'silent', 'silent', 'three sealed scalars'),
    ('arithmetic_over_sealed', REQ + LOG + 'def h():\n' + TAINT +
     '    logger.info(f"n={len(rows) + 1}")\n', 'silent', 'silent',
     'BinOp operands both proven -- the pitch\'s clause 3, already shipped'),
    ('pure_literal', LOG + 'def h():\n    logger.info("cache warmed")\n', 'silent', 'silent',
     'constant message cannot carry injected CR/LF'),
]

SPEC_SHAPES = [s[0] for s in SHAPES if s[2] != s[3]]


def scan(label, source):
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={f'{label}.py': source})
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return [row for row in rows if row['cwe'] == 'CWE-117']


def check_floors():
    """TIER 1: the blessed CWE-117 population, and the two floor keys that bound any exemption."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        c117 = [row for row in rows if row[2] == 'CWE-117']
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-117={len(c117)} (want {LOCKED[kind]})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(c117) != LOCKED[kind]:
            failures.append((kind, 'CWE-117', LOCKED[kind], len(c117),
                             'the blessed CWE-117 floor moved - 49 keys are the minimum'))
    floors = [('parity', 'benchmark/corpus/cwe_200_info_exposure/test_v01_good.py', 12),
              ('big8', 'corpus_big8/src__transformers__modeling_utils.py', 3567)]
    for kind, leaf, line in floors:
        hit = [r for r in load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
               if str(r[0]).endswith(leaf) and r[1] == line and r[2] == 'CWE-117']
        print(f'  {kind:7s} floor {leaf}:{line} present={bool(hit)}')
        if not hit:
            failures.append((kind, f'{leaf}:{line}', 'blessed', 'absent',
                             'the key that bounds a numeric-hole exemption is no longer blessed'))
    return failures


def check_parity_corpus():
    """TIER 2: the parity CWE-117 population re-produced by a real tree scan, as an exact key set."""
    failures = []
    rows = load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
    frozen = {row for row in rows if row[2] == 'CWE-117'}
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    with contextlib.redirect_stderr(io.StringIO()):
        live = {row for row in scan_rows('parity', tree) if row[2] == 'CWE-117'}
    missing, extra = sorted(frozen - live), sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    for row in sorted(frozen):
        print(f'  {"held" if row in live else "MISSING":8s} {str(row[0])[-52:]}:{row[1]}')
    for row in extra:
        print(f'  NEW      {row[0]}:{row[1]}')
    if missing:
        failures.append((len(missing), 'blessed parity CWE-117 keys no longer reported'))
    if extra:
        failures.append((len(extra), 'CWE-117 keys appeared that the baseline never held'))
    return failures


def check_shapes():
    """TIER 3: the truth table, asserted against the seal the engine is actually standing under."""
    failures = []
    silenced = []
    for label, source, at_refused, at_shipped, note in SHAPES:
        want = at_refused if SEAL == 'refused' else at_shipped
        found = scan(label, source)
        got = 'report' if found else 'silent'
        ok = got == want
        if label in SPEC_SHAPES and got == 'silent' and want == 'report':
            silenced.append(label)
        detail = '; '.join(f'L{r["line"]}' for r in found)[:30]
        print(f'  {label:22s} want={want:6s} got={got:6s} {"ok" if ok else "MISMATCH":8s} '
              f'{detail:14s} {note[:44]}')
        if not ok:
            failures.append((label, SEAL, want, got,
                             'the answer moved without the seal, or the seal moved without the answer'))
    if silenced:
        print(f'  !! {len(silenced)} shape(s) the numeric-specifier clause would quiet: {silenced}')
    return failures


def check_vocabulary():
    """TIER 4: the parts of the rule that must never be widened by a well-meant cleanup."""
    failures = []
    tracker = ast_scanner.TaintTracker(files={'v.py': LOG})
    sealed = set(tracker.CWE117_BUILTIN_SEALED_NAMES)
    for banned in ('str', 'abs', 'format', 'vars', 'repr'):
        ok = banned not in sealed
        print(f'  {"ok" if ok else "MISMATCH":8s} {banned!r} absent from CWE117_BUILTIN_SEALED_NAMES')
        if not ok:
            failures.append((banned, 'not sealed', 'sealed', 'str()/abs() each have a blessed key behind them'))
    for forbidden in ('%', 'c', 's'):
        ok = forbidden not in PRESENTATION
        print(f'  {"ok" if ok else "MISMATCH":8s} format type {forbidden!r} absent from the numeric types')
        if not ok:
            failures.append((forbidden, 'not numeric', 'numeric', 'str and datetime accept it'))
    # all-or-nothing is the load-bearing property, so it is asserted on a live message
    mixed = scan('vocab_mixed', REQ + LOG + 'def h():\n' + TAINT +
                 '    logger.info(f"a={len(rows)} b={rows}")\n')
    print(f'  {"ok" if mixed else "MISMATCH":8s} one unsafe hole still reports the whole message')
    if not mixed:
        failures.append(('all-or-nothing', 'report', 'silent',
                         'per-hole exemption was introduced - deletes modeling_utils.py:3567'))
    dyn = scan('vocab_dynamic', REQ + LOG + 'def h():\n' + TAINT +
               '    fmt = request.args.get("f")\n    logger.info(f"v={rows:{fmt}}")\n')
    print(f'  {"ok" if dyn else "MISMATCH":8s} a dynamic format spec is not a numeric proof')
    if not dyn:
        failures.append(('dynamic-spec', 'report', 'silent', 'format_spec holes were trusted'))
    return failures


def main() -> int:
    if SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-117 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the parity corpus behind those keys, scanned live:')
    failures += check_parity_corpus()
    print(f'TIER 3 - truth table under seal={SEAL!r}:')
    failures += check_shapes()
    print('TIER 4 - the vocabulary and all-or-nothing edges:')
    failures += check_vocabulary()
    must_report = sum(1 for s in SHAPES if s[2] == 'report')
    silent = sum(1 for s in SHAPES if s[2] == 'silent')
    print(f'\nseal={SEAL} shapes={len(SHAPES)} must_report={must_report} already_quiet={silent} '
          f'clause_sensitive={len(SPEC_SHAPES)} locked_cwe117={sum(LOCKED.values())} '
          f'failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-117 numeric-provenance boundary no longer matches its measured '
              'evidence. Restore the finding, or re-measure the corpus and rewrite this table; never '
              're-bless a baseline.')
        return 1
    print(f'VERDICT: PASS - {sum(LOCKED.values())} blessed CWE-117 keys held, parity corpus exact-set, '
          f'{must_report} tainted shapes reported (including the {len(SPEC_SHAPES)} a numeric-specifier '
          f'clause would quiet) and {silent} provably-numeric or already-sealed shapes silent.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
