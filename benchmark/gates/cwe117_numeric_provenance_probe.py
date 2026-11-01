"""Truth table for the CWE-117 numeric-provenance pitch: the lock that fails if it is ever shipped blind.

    python benchmark/gates/cwe117_numeric_provenance_probe.py

The pitch this file exists to test, in its own words: "a hole whose f-string carries a numeric format
specifier (`{x:.4f}`, `{n:d}`) or a `range()` loop counter cannot carry CR/LF, so stop reporting
CWE-117 on it." Measured against the exact code this gate ships with, the pitch has **zero yield and
a real cost**, and the tiers below assert both halves of that sentence rather than arguing it.

TIER 5 guards the shape of the rule that *is* shipped -- the pure-literal and numeric seal. It exists
because that seal is consulted from two record paths (the registry sink test and the blindspot
collector) and a message quieted on one and reported on the other is a precision bug nobody can see in
a row count. Both paths now reach it through `_cwe117_message_is_sealed` alone, and the tier proves the
sharing rather than trusting it: widen the shared helper to `True` and all seven string-bearing shapes
must go silent, while rebinding the registry to its own copy of the two predicates -- the form the code
had before the delegation -- must fail. Verified by falsification against a patched copy of the engine
through `TCS_NUMERIC_PROV_ENGINE`, measured on the shipped code: `registry re-inlines the predicates`
CAUGHT with `failures=8` (3 source-shape mismatches -- `registry delegates`, `registry restates
nothing`, `two call sites` -- plus the 5 shapes whose CWE-117 row rides the registry path:
`dot_format`, `bare_hole`, `mixed_hole`, `dict_subscript`, `helper_return`; the other 2 shapes are
collector-only, so they do go silent and are not evidence of sharing), `shared helper stops consulting
the literal seal` CAUGHT with `failures=1` (`shared answer intact`), shipped engine `failures=0`.

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
import inspect
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


def _frag(obj):
    """Source text of *obj*, or '' when it carries none.

    A falsification run rebinds `_sink_context_exempt` to a function with no file behind it, and an
    OSError there would abort the gate instead of failing it. The fragment checks read as MISMATCH on
    an empty source, so the lock still goes loud, and the behavioural half never needs the source.
    """
    try:
        return inspect.getsource(obj)
    except (OSError, TypeError):
        return ''


def check_one_answer():
    """TIER 5: one exemption answer for both CWE-117 record paths, proved behaviorally.

    The registry path reaches the literal/numeric seal only through `_cwe117_message_is_sealed`, and so
    does the blindspot collector. That sharing is the whole defence against a narrowing that quiets a
    message on one path and keeps reporting it on the other, and it is not visible in a row count: an
    inlined copy of the two predicates gives the same answers *today*. So this tier does not compare
    answers, it compares **dependencies** -- widen the shared helper to `True` and every CWE-117 row of
    a string-bearing message must disappear. If any path still carries its own copy, that path keeps
    speaking and the tier fails on the named shape.
    """
    failures = []
    tracker_src = _frag(ast_scanner.TaintTracker._sink_context_exempt)
    shared_src = _frag(ast_scanner.TaintTracker._cwe117_message_is_sealed)
    module_src = _frag(ast_scanner)
    calls = module_src.count('self._cwe117_message_is_sealed(')
    for label, ok, note in (
            ('registry delegates', '_cwe117_message_is_sealed(' in tracker_src,
             'the registry path restates the predicates instead of sharing them'),
            ('registry restates nothing', '_log_message_is_pure_literal(' not in tracker_src
             and '_log_message_is_numeric_only(' not in tracker_src,
             'an inlined copy is back, so a future narrowing half-applies'),
            ('shared answer intact', '_log_message_is_pure_literal(node)' in shared_src
             and '_log_message_is_numeric_only(node, shadowed)' in shared_src,
             'the shared helper stopped consulting one of the two seals'),
            ('two call sites', calls == 2,
             f'_cwe117_message_is_sealed is called {calls} time(s), expected 2 (registry + collector)')):
        print(f'  {"ok" if ok else "MISMATCH":8s} {label}')
        if not ok:
            failures.append((label, 'shared', 'restated', note))
    shared = ast_scanner.TaintTracker._cwe117_message_is_sealed
    try:
        ast_scanner.TaintTracker._cwe117_message_is_sealed = lambda self, node, shadowed: True
        for label in ('lazy_percent_args', 'percent_format', 'dot_format', 'bare_hole',
                      'mixed_hole', 'dict_subscript', 'helper_return'):
            src = next(s[1] for s in SHAPES if s[0] == label)
            rows = scan(f'widened_{label}', src)
            ok = not rows
            print(f'  {"ok" if ok else "MISMATCH":8s} widened helper silences {label} on both paths'
                  f' (rows={len(rows)})')
            if not ok:
                failures.append((label, 'silent when widened', 'still reports',
                                 'that path has its own copy of the CWE-117 seal'))
    finally:
        ast_scanner.TaintTracker._cwe117_message_is_sealed = shared
    still = scan('restored_lazy_percent', next(s[1] for s in SHAPES
                                               if s[0] == 'lazy_percent_args'))
    ok = bool(still)
    print(f'  {"ok" if ok else "MISMATCH":8s} patch restored: lazy % args report again'
          f' (rows={len(still)})')
    if not ok:
        failures.append(('restore', 'report', 'silent', 'the monkeypatch leaked into the next tier'))
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
    print('TIER 5 - one shared answer for both CWE-117 record paths:')
    failures += check_one_answer()
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
