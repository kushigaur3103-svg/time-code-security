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

TIER 6 and TIER 7 guard the second numeric pass -- a hole that is a bare name sealed only when the module
writes that name *exactly once* and the one write is itself numeric-safe, with the whole census refused
for a module that can rewrite names from outside the AST (`exec`, `eval`, `compile`, `__import__`,
`setattr`/`delattr`, `builtins.X = ...`, `globals()[...] = ...`, `globals().update(...)`,
`from x import *`) and with the value walk capped at `CWE117_NUMERIC_BINDING_DEPTH` so `A = B` next to
`B = A` fails closed. That pass was written, measured and **withdrawn** in the same session, because its
cost measured real (29.7 ms of census walks = 1.73 % of a 1.72 s in-process scan of the three Big-8
modules, plus +0.119 us per hole-bearing ask) while its yield measured zero (0 of 119 real asks changed
answer, 0 of 49 blessed keys sealed, 55 reachable holes in 25,005 local files and 0 of them in either
frozen corpus). TIER 5 therefore asserts the *state* it finds -- census present or absent -- so a
re-ship without a re-measured cost/yield pair cannot pass quietly, and TIER 6 lists the five holes the
census used to quiet as **reported** rows: the false-positive price of the withdrawal, kept on the table
instead of hidden. The mandate also asked for names *called* loss / lr / epoch / step / shape to count
as numbers; that reading is what this file refuses, and TIER 7 proves the refusal is not hypothetical by
asking the 49 blessed lines themselves: `sealed_by_shipped_binding_seal=0`,
`reachable_by_state_name_rule=5` -- the five blessed `src__transformers__trainer.py` keys at `:1603
:1604 :1610 :1614 :1618`, whose holes really are named `num_train_epochs`,
`num_update_steps_per_epoch`, `max_steps`, `epochs_trained` and `steps_trained_in_current_epoch`, and
whose values are not. Seven in-memory falsifications run through `--mutate=<name>`; the six whose
guard symbol the withdrawal removed exit 2 with the honest reason printed (`binding_map_neutralised`,
`census_accepts_any_name`, `rebinding_accepted`, `bindings_membership_decides`, `dynamic_doors_blanked`,
`depth_cap_raised` -- no census, no guard to falsify), and the one that still ships its answer today,
`state_name_rule_shipped`, is CAUGHT with exit 1 on the three name-rule rows.

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

import ast
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

# The second numeric pass -- the unique-binding census that could seal a bare-name hole -- shipped in
# this session and was withdrawn in this session, on measured grounds, so this file asserts both of its
# possible states from the engine rather than from a comment:
#
#   cost, measured paired and order-alternating on the three Big-8 modules that hold all 43 blessed
#     CWE-117 keys (751,485 bytes, one in-process scan = CPU 1.72 s): one cold census walk is
#     8.59 / 9.38 / 11.72 ms, 29.7 ms for the three together = **1.73 % of that scan**, plus
#     +0.119 us per hole-bearing ask (predicate CPU ratio median 1.0153, new <= head in 1/6 legs);
#   yield, measured on the same corpus: **0 of 119 real asks** of the seal change answer, the census
#     finds **0 numeric bindings** in all three modules, TIER 7 reports `sealed_by_shipped_binding_seal
#     =0` on 49/49 blessed keys, and a whole-tree census of 25,005 local files finds **55** logged
#     f-string holes the rule can reach -- 0 of them inside either frozen baseline, the rest in the
#     harnesses of this repository itself.
#
# Rule 15.3 makes the CPU ratio the invariant and FP reduction the thing that may wait, so the engine
# keeps HEAD: a bare-name hole is unsafe unless a sealed builtin answers for it.
BINDING_SEAL_ROWS = ('hole_bound_literal', 'hole_bound_sealed_call', 'hole_bound_float_env',
                     'hole_bound_chain', 'hole_bound_local_in_other_scope')


def binding_seal_shipped() -> bool:
    """Does this engine carry the unique-binding census? Read from the module, never from a comment."""
    return hasattr(ast_scanner.TaintTracker, '_c117_uniquely_bound_numerics')


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
from gate_common import (META, corpus_dir, load_keys, relativise, scan_rows,  # noqa: E402
                         verify_corpus)

LOCKED = {'parity': 6, 'big8': 43}
PRESENTATION = frozenset('deEfgGnboxX')          # int/float-only types; `%` and `c` are NOT in here
# The mandate D item-1 vocabulary: "resolve to known numeric/ML state types (integers, floats, loss,
# lr, epoch, step, shape)". Kept here as the reading the gate refuses, so the refusal stays measured.
STATE_NAME_RE = re.compile(r'loss|\blr\b|epoch|step|shape', re.I)

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

# --- the unique-binding numeric seal (mandate D item 1) --------------------------------------
# Each row is the shipped answer plus the one mutation that is allowed to move it. A quiet row is
# only evidence if neutralising the seal brings the finding back; a loud row is only evidence for the
# guard named in `caught_by`, and every guard has at least one row.
MODULE_NUM = 'SIZE = 0\n'
TAINTED_STR = '    rows = request.args.get("q")\n'

# (label, source, verdict, caught_by, note)
BINDING_SHAPES = [
    ('hole_bound_literal', REQ + LOG + 'SIZE = 0\n' + 'def h():\n' + TAINTED_STR
     + '    logger.info(f"n={len(rows)} size={SIZE}")\n', 'silent', 'binding_map_neutralised',
     'the module writes SIZE once, to 0, so the hole cannot carry CR/LF'),
    ('hole_bound_sealed_call', REQ + LOG + 'SIZE = int(request.args.get("n"))\n' + 'def h():\n'
     + '    logger.info(f"size={SIZE}")\n', 'silent', 'binding_map_neutralised',
     'int() returns a builtin int whatever its argument is'),
    ('hole_bound_float_env', REQ + LOG + 'import os\nLR = float(os.environ["LR"])\n' + 'def h():\n'
     + '    logger.info(f"lr={LR:.4f}")\n', 'silent', 'binding_map_neutralised',
     'the task example: a metric read from the environment through a sealed builtin'),
    ('hole_bound_chain', REQ + LOG + 'W = 2\nH = 3\nAREA = W * H\n' + 'def h():\n' + TAINTED_STR
     + '    logger.info(f"n={len(rows)} a={AREA}")\n', 'silent', 'binding_map_neutralised',
     'two hops of unique binding, still inside CWE117_NUMERIC_BINDING_DEPTH'),
    ('hole_bound_local_in_other_scope', REQ + LOG + 'def a():\n    SIZE = 0\n' + 'def h():\n'
     + TAINTED_STR + '    logger.info(f"n={len(rows)} size={SIZE}")\n', 'silent',
     'binding_map_neutralised',
     'the only write in the module is a literal, so no reader of this name can hold text'),
    ('bound_written_twice', REQ + LOG + 'def h():\n' + TAINTED_STR
     + '    V = rows\n    V = 0\n    logger.info(f"n={len(rows)} v={V}")\n', 'report',
     'rebinding_accepted', 'a second write makes the first one no longer a fact'),
    ('bound_aug_assign', REQ + LOG + 'CODE = 0\nCODE += 1\n' + 'def h():\n' + TAINTED_STR
     + '    logger.info(f"n={len(rows)} c={CODE}")\n', 'report', 'rebinding_accepted',
     'augmented assignment is a write the census counts'),
    ('bound_walrus', REQ + LOG + 'def h():\n' + TAINTED_STR
     + '    if (count := len(rows)) > 0:\n        logger.info(f"n={len(rows)} c={count}")\n',
     'report', 'census_accepts_any_name', 'a NamedExpr target is a Store the census sees'),
    ('bound_for_counter', REQ + LOG + 'def h():\n' + TAINTED_STR
     + '    for i in range(rows):\n        logger.info(f"n={len(rows)} i={i}")\n', 'report',
     'census_accepts_any_name', 'a loop target is written by the interpreter, not by one literal'),
    ('bound_parameter', REQ + LOG + 'def h(count):\n' + TAINTED_STR
     + '    logger.info(f"n={len(rows)} c={count}")\n', 'report', 'census_accepts_any_name',
     'the task must-report shape: a request parameter is never a known number'),
    ('bound_holds_text', REQ + LOG + 'NAME = request.args.get("n")\n' + 'def h():\n' + TAINTED_STR
     + '    logger.info(f"n={len(rows)} s={NAME}")\n', 'report', 'bindings_membership_decides',
     'one write, but the write carries the attacker string'),
    ('bound_holds_str_constant', REQ + LOG + 'NAME = "ada"\n' + 'def h():\n' + TAINTED_STR
     + '    logger.info(f"n={len(rows)} s={NAME}")\n', 'report', 'bindings_membership_decides',
     'a string literal is not a number -- str is where CR/LF lives'),
    ('bound_holds_attribute', REQ + LOG + 'COUNT = self.n\n' + 'def h():\n' + TAINTED_STR
     + '    logger.info(f"n={len(rows)} c={COUNT}")\n', 'report', 'bindings_membership_decides',
     'an attribute read resolves to nothing, so it stays unsafe'),
    ('module_uses_exec', REQ + LOG + 'CODE = 0\n' + 'def h():\n    exec("CODE = 1")\n'
     + TAINTED_STR + '    logger.info(f"n={len(rows)} c={CODE}")\n', 'report',
     'dynamic_doors_blanked', 'exec can rewrite the name with bytes the AST never saw'),
    ('module_uses_star_import', REQ + LOG + 'from os import *\nCODE = 0\n' + 'def h():\n'
     + TAINTED_STR + '    logger.info(f"n={len(rows)} c={CODE}")\n', 'report',
     'dynamic_doors_blanked', 'a star import can hand the module any name at any value'),
    ('module_writes_globals', REQ + LOG + 'CODE = 0\n' + 'def h():\n'
     '    globals()["CODE"] = rows\n' + TAINTED_STR
     + '    logger.info(f"n={len(rows)} c={CODE}")\n', 'report', 'dynamic_doors_blanked',
     'a subscript store into globals() is a write the census cannot see'),
    ('module_updates_globals', REQ + LOG + 'CODE = 0\n' + 'def h():\n'
     '    globals().update({"CODE": rows})\n' + TAINTED_STR
     + '    logger.info(f"n={len(rows)} c={CODE}")\n', 'report', 'dynamic_doors_blanked',
     'the same door through dict.update'),
    ('module_setsattr_builtins', REQ + LOG + 'import builtins\nCODE = 0\n' + 'def h():\n'
     '    setattr(builtins, "CODE", rows)\n' + TAINTED_STR
     + '    logger.info(f"n={len(rows)} c={CODE}")\n', 'report', 'dynamic_doors_blanked',
     'setattr onto builtins reaches every scope in the process'),
    ('module_stores_builtins_attr', REQ + LOG + 'import builtins\nCODE = 0\n'
     'builtins.CODE = request.args.get("q")\n' + 'def h():\n' + TAINTED_STR
     + '    logger.info(f"n={len(rows)} c={CODE}")\n', 'report', 'dynamic_doors_blanked',
     'an attribute store the Name census never counts'),
    ('binding_cycle_fails_closed', REQ + LOG + 'A = B\nB = A\n' + 'def h():\n' + TAINTED_STR
     + '    logger.info(f"n={len(rows)} a={A}")\n', 'report', 'depth_cap_raised',
     'two unique writes that point at each other: the depth cap answers unsafe instead of spinning'),
    # the mandate s own reading: a hole whose *name* says loss / epoch / step. Each of these three
    # spells a blessed Big-8 line (trainer.py:1603 / :1610 / :1618) with a tainted binding behind it.
    ('name_rule_epoch_from_request', REQ + LOG + 'def h():\n'
     '    num_train_epochs = request.args.get("e")\n'
     + '    logger.info(f"  Num Epochs = {num_train_epochs:,}")\n', 'report',
     'state_name_rule_shipped', 'blessed trainer.py:1603 spelling, value from a request'),
    ('name_rule_step_from_request', REQ + LOG + 'def h():\n'
     '    max_steps = request.args.get("s")\n'
     + '    logger.info(f"  Total optimization steps = {max_steps:,}")\n', 'report',
     'state_name_rule_shipped', 'blessed trainer.py:1610 spelling'),
    ('name_rule_loss_from_request', REQ + LOG + 'def h():\n    loss = request.args.get("l")\n'
     + '    logger.info(f"Loss: {loss:.4f}")\n', 'report', 'state_name_rule_shipped',
     'the task example 1, with the taint source the example did not have'),
]

QUIET_BINDING_ROWS = [s[0] for s in BINDING_SHAPES if s[2] == 'silent']


def _rows_for(mutation):
    return [s[0] for s in BINDING_SHAPES if s[3] == mutation]



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


def _sealed_call_arities(module_src: str) -> list:
    """Argument count of every `self._cwe117_message_is_sealed(...)` call, paren-balanced.

    The seal takes the module tree now, and a call site that quietly drops that third argument keeps
    working -- it just answers about names as if they were never assigned anywhere. Counting the
    arguments of each real call is what makes losing the tree loud instead of invisible.
    """
    needle = 'self._cwe117_message_is_sealed('
    arities = []
    start = 0
    while True:
        i = module_src.find(needle, start)
        if i < 0:
            return arities
        depth, args, j = 1, 1, i + len(needle)
        while j < len(module_src) and depth:
            ch = module_src[j]
            if ch in '([':
                depth += 1
            elif ch in ')]':
                depth -= 1
            elif ch == ',' and depth == 1:
                args += 1
            j += 1
        arities.append(args)
        start = j


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
    shipped = binding_seal_shipped()
    tracker_src = _frag(ast_scanner.TaintTracker._sink_context_exempt)
    shared_src = _frag(ast_scanner.TaintTracker._cwe117_message_is_sealed)
    module_src = _frag(ast_scanner)
    calls = module_src.count('self._cwe117_message_is_sealed(')
    numeric_src = _frag(ast_scanner.TaintTracker._log_message_is_numeric_only)
    arity_wanted = 3 if shipped else 2
    if shipped:
        census_rows = (
            ('binding map asked only through the tree',
             '_c117_uniquely_bound_numerics(tree)' in numeric_src,
             'the numeric pass stopped consulting the unique-binding census'),
            ('census fails closed on no tree',
             'if tree is None' in _frag(ast_scanner.TaintTracker._c117_uniquely_bound_numerics),
             'a missing tree now means an empty map, not an answer'))
    else:
        # The withdrawn state has its own lock: a bare name must stay unsafe, and it stays unsafe
        # because nothing consults a binding map at all. If the census comes back, `shipped` flips and
        # the rows above take over -- the table follows the engine, in either direction.
        census_rows = (
            ('no census in the engine', not shipped,
             'the census is back without a re-measured cost/yield pair -- see the block above '
             'BINDING_SEAL_ROWS'),
            ('a bare name is asked for nothing', 'bindings' not in numeric_src
             and '_c117_uniquely_bound_numerics' not in numeric_src,
             'the numeric pass resolves names again, which is the withdrawn rule'),
            ('no per-module walk in the numeric pass', '_module_nodes' not in numeric_src,
             'a full module pass was re-added inside the seal, which is the 8.6-11.7 ms cost'))
    for label, ok, note in (
            ('registry delegates', '_cwe117_message_is_sealed(' in tracker_src,
             'the registry path restates the predicates instead of sharing them'),
            ('registry restates nothing', '_log_message_is_pure_literal(' not in tracker_src
             and '_log_message_is_numeric_only(' not in tracker_src,
             'an inlined copy is back, so a future narrowing half-applies'),
            ('shared answer intact', '_log_message_is_pure_literal(node)' in shared_src
             and '_log_message_is_numeric_only(node, shadowed' in shared_src,
             'the shared helper stopped consulting one of the two seals'),
            ('two call sites', calls == 2,
             f'_cwe117_message_is_sealed is called {calls} time(s), expected 2 (registry + collector)'),
            ('both sites agree on the arity', calls == 2
             and all(a == arity_wanted for a in _sealed_call_arities(module_src)),
             f'a call site answers with a different arity than {arity_wanted}, so the two record '
             'paths can disagree about the same log statement'),
            *census_rows):
        print(f'  {"ok" if ok else "MISMATCH":8s} {label}')
        if not ok:
            failures.append((label, 'shared', 'restated', note))
    shared = ast_scanner.TaintTracker._cwe117_message_is_sealed
    try:
        ast_scanner.TaintTracker._cwe117_message_is_sealed = \
            lambda self, node, shadowed, tree=None: True
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


def check_binding_shapes():
    """TIER 6: the unique-binding shapes -- what the census quieted, what it refused, and what HEAD does.

    Every row is asserted twice over: against the answer of the engine in front of it, and against the
    mutation named in `BINDING_SHAPES` (see `MUTATIONS`), which must move it when its guard exists. A
    quiet row that no mutation can bring back is not an exemption, it is a shape that was never
    reported, and this tier says so. With the census withdrawn the five `BINDING_SEAL_ROWS` are expected
    to **report** -- that is the false-positive side of the withdrawal, kept visible instead of tidied
    away, and it is the direction the standing rules allow (FP may rise, TP may not).
    """
    failures = []
    shipped = binding_seal_shipped()
    print(f'  binding seal present in engine={shipped}')
    for label, source, want, caught_by, note in BINDING_SHAPES:
        expected = want if shipped or label not in BINDING_SEAL_ROWS else 'report'
        try:
            got = 'report' if scan(label, source) else 'silent'
        except RecursionError:
            failures.append((label, expected, 'spun',
                             'the binding walk had no depth cap and followed a->b->a'))
            print(f'  {label:30s} want={expected:6s} got=SPIN     MISMATCH  {note[:40]}')
            continue
        ok = got == expected
        print(f'  {"ok" if ok else "MISMATCH":8s} {label:30s} want={expected:6s} got={got:6s} '
              f'{caught_by:26s} {note[:34]}')
        if not ok:
            failures.append((label, expected, got,
                             'the binding shapes answered differently from their measured truth table'))
    return failures


def _blessed_c117_rows():
    """Every blessed CWE-117 key, with the source file that carries it."""
    rows = []
    for kind in ('parity', 'big8'):
        keys = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        c117 = [row for row in keys if row[2] == 'CWE-117']
        if kind == 'big8':
            corpus = corpus_dir('big8')
            verify_corpus('big8', corpus)
            for row in c117:
                leaf = str(row[0]).rsplit('/', 1)[-1]
                rows.append((kind, leaf, row[1], os.path.abspath(os.path.join(corpus, leaf))))
            continue
        recorded = META['parity'].get('recorded_root')
        for row in c117:
            rel = relativise(row[0], recorded)
            rows.append((kind, rel, row[1], os.path.abspath(os.path.join(ROOT, rel))))
    return rows


def _calls_at(tree, line):
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == line]


def check_blessed_reach():
    """TIER 7: ask the shipped seal about every blessed key, before any baseline can move.

    Three numbers come out of the 49 real source lines: how many the shipped seal answers `sealed`
    for (must be 0 -- that is the zero-FN proof, measured on the corpus rather than asserted), how
    many the *name* reading would quiet (must be > 0, because that is the refusal this file exists to
    freeze), and how many the any-name census would quiet.
    """
    failures = []
    tracker = ast_scanner.TaintTracker(files={'reach.py': LOG})
    sealed, name_rule, any_name, located = [], [], [], 0
    trees: dict = {}
    for kind, leaf, line, path in _blessed_c117_rows():
        if path not in trees:
            try:
                with open(path, encoding='utf-8') as handle:
                    trees[path] = ast.parse(handle.read())
            except (OSError, SyntaxError, ValueError):
                trees[path] = None
        tree = trees[path]
        if tree is None:
            failures.append((f'{leaf}:{line}', 'source readable', 'missing',
                             'the blessed line cannot be re-parsed, so its reach is unproven'))
            continue
        calls = _calls_at(tree, line)
        if not calls:
            failures.append((f'{leaf}:{line}', 'a call on the blessed line', 'none',
                             'the key no longer sits on a call, so this tier stopped measuring it'))
            continue
        located += 1
        shadowed = tracker._shadowed_names_in_tree(tree)
        holes = []
        for call in calls:
            if binding_seal_shipped():
                answered = tracker._cwe117_message_is_sealed(call, shadowed, tree)
            else:
                answered = tracker._cwe117_message_is_sealed(call, shadowed)
            if answered:
                sealed.append((kind, leaf, line))
            for arg in call.args:
                if isinstance(arg, ast.JoinedStr):
                    holes.extend(v.value for v in arg.values
                                 if isinstance(v, ast.FormattedValue))
        names = [h.id for h in holes if isinstance(h, ast.Name)]
        if any(STATE_NAME_RE.search(name) for name in names):
            name_rule.append((kind, leaf, line, [n for n in names if STATE_NAME_RE.search(n)]))
        if names:
            any_name.append((kind, leaf, line))
    print(f'  blessed CWE-117 keys located on their real line={located} of {sum(LOCKED.values())}')
    print(f'  sealed_by_shipped_binding_seal={len(sealed)}')
    for item in sealed:
        print(f'  !! SEELED {item}')
    print(f'  reachable_by_state_name_rule={len(name_rule)} '
          f'(the mandate as written - these blessed keys would die)')
    for kind, leaf, line, matched in name_rule[:8]:
        print(f'  NAME-REACHES {kind:7s} {leaf[-40:]}:{line} {",".join(matched)[:44]}')
    print(f'  reachable_by_any_name_census={len(any_name)}')
    if sealed:
        failures.append((len(sealed), 'a blessed CWE-117 key is answered sealed by the shipped engine'))
    if located != sum(LOCKED.values()):
        failures.append((located, 'every blessed key re-parsed', sum(LOCKED.values()), located))
    if not name_rule:
        failures.append((len(name_rule), 'the name reading must still be provably out of reach',
                         'a blessed key it quiets', 0,
                         'the refusal lost its evidence - re-measure before believing any +N'))
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
    shipped = binding_seal_shipped()
    print(f'TIER 6 - the unique-binding shapes (census {"shipped" if shipped else "withdrawn"}):')
    failures += check_binding_shapes()
    print('TIER 7 - the seal asked about every blessed CWE-117 line, in the real corpus:')
    failures += check_blessed_reach()
    must_report = sum(1 for s in SHAPES if s[2] == 'report')
    silent = sum(1 for s in SHAPES if s[2] == 'silent')
    binding_quiet = len(QUIET_BINDING_ROWS) if shipped else 0
    print(f'\nseal={SEAL} binding_seal={"shipped" if shipped else "withdrawn"} shapes={len(SHAPES)} '
          f'must_report={must_report} already_quiet={silent} '
          f'clause_sensitive={len(SPEC_SHAPES)} binding_rows={len(BINDING_SHAPES)} '
          f'binding_quiet={binding_quiet} binding_loud={len(BINDING_SHAPES) - binding_quiet} '
          f'locked_cwe117={sum(LOCKED.values())} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-117 numeric-provenance boundary no longer matches its measured '
              'evidence. Restore the finding, or re-measure the corpus and rewrite this table; never '
              're-bless a baseline.')
        return 1
    print(f'VERDICT: PASS - {sum(LOCKED.values())} blessed CWE-117 keys held, parity corpus exact-set, '
          f'{must_report} tainted shapes reported (including the {len(SPEC_SHAPES)} a numeric-specifier '
          f'clause would quiet) and {silent} provably-numeric or already-sealed shapes silent, plus the '
          f'{binding_quiet} unique-binding holes the census quiets in this engine against '
          f'{len(BINDING_SHAPES) - binding_quiet} shapes it refuses.')
    return 0


def _apply_census_accepts_any_name():
    """Every name the module merely *reads* answers as a number -- the census is gone."""
    def patched(self, tree):
        if tree is None:
            return {}
        out = {}
        for node in self._module_nodes(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                out.setdefault(node.id, ast.Constant(value=0))
        return out

    ast_scanner.TaintTracker._c117_uniquely_bound_numerics = patched


def _apply_state_name_rule():
    """Mandate D item 1 read literally: a hole whose *name* says loss/lr/epoch/step/shape is numeric."""
    pristine = ast_scanner.TaintTracker._numeric_safe_expr

    def patched(self, expr, shadowed=None, bindings=None, depth=0):
        if isinstance(expr, ast.Name) and STATE_NAME_RE.search(expr.id):
            return True
        return pristine(self, expr, shadowed, bindings, depth)

    ast_scanner.TaintTracker._numeric_safe_expr = patched


def _apply_bindings_membership_decides():
    """Trust the map instead of the value: accept a name the census happens to hold, whatever the
    census put there. This is the design a future "simplify: one lookup" refactor would ship, and the
    value test is asked twice today (once to build the map, once at the hole) precisely so that
    replacing either half alone changes nothing -- so the mutation has to bypass both to be honest.
    """
    pristine = ast_scanner.TaintTracker._numeric_safe_expr

    def patched(self, expr, shadowed=None, bindings=None, depth=0):
        if isinstance(expr, ast.Name):
            if bindings is not None and expr.id in bindings:
                return True
            return expr.id in ("True", "False", "None")
        return pristine(self, expr, shadowed, bindings, depth)

    ast_scanner.TaintTracker._c117_binding_is_numeric = \
        lambda self, value, shadowed, candidates: True
    ast_scanner.TaintTracker._numeric_safe_expr = patched


MUTATIONS = {
    'binding_map_neutralised': {
        'what': 'answer no bindings at all -- the five quiet holes must come back, which is what '
                'proves the seal is the reason they are quiet and not a shape that never reported',
        'rows': QUIET_BINDING_ROWS,
        'requires': '_c117_uniquely_bound_numerics',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c117_uniquely_bound_numerics',
                                 lambda self, tree: {}),
    },
    'census_accepts_any_name': {
        'what': 'keep the numeric test but drop the exactly-once census, so any name the module reads '
                'counts as a number -- loop targets, parameters and walrus names go quiet',
        'rows': _rows_for('census_accepts_any_name'),
        'requires': '_c117_uniquely_bound_numerics',
        'apply': _apply_census_accepts_any_name,
    },
    'rebinding_accepted': {
        'what': 'accept a name the module writes more than once (only the last write is read)',
        'rows': _rows_for('rebinding_accepted'),
        'requires': '_c117_written_exactly_once',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c117_written_exactly_once',
                                 staticmethod(lambda name, counts: True)),
    },
    'bindings_membership_decides': {
        'what': 'trust the census map instead of re-reading the value, and let the census accept any '
                'value -- `NAME = "ada"` and the A/B cycle become "numbers"',
        'rows': _rows_for('bindings_membership_decides') + ['binding_cycle_fails_closed'],
        'requires': '_c117_binding_is_numeric',
        'apply': _apply_bindings_membership_decides,
    },
    'dynamic_doors_blanked': {
        'what': 'empty the four veto tables, so a module that can rewrite names with exec, setattr, '
                'globals() or a star import still answers the census',
        'rows': _rows_for('dynamic_doors_blanked'),
        'requires': 'CWE117_DYNAMIC_BINDING_CALLS',
        'apply': lambda: [setattr(ast_scanner.TaintTracker, name, frozenset()) for name in (
            'CWE117_DYNAMIC_BINDING_CALLS', 'CWE117_ATTR_BINDING_CALLS',
            'CWE117_NAME_INJECTION_CALLS', 'CWE117_DYNAMIC_IMPORTS',
            'CWE117_DYNAMIC_STORE_ROOTS')],
    },
    'depth_cap_raised': {
        'what': 'remove the hop cap, so `A = B` next to `B = A` is followed instead of refused',
        'rows': _rows_for('depth_cap_raised'),
        'requires': 'CWE117_NUMERIC_BINDING_DEPTH',
        'apply': lambda: setattr(ast_scanner.TaintTracker, 'CWE117_NUMERIC_BINDING_DEPTH', 1_000_000),
    },
    'state_name_rule_shipped': {
        'what': 'ship the mandate as written: a hole whose name says loss / lr / epoch / step / shape '
                'is a number -- this is the reading the five blessed trainer lines die under',
        'rows': _rows_for('state_name_rule_shipped'),
        'requires': '_numeric_safe_expr',
        'apply': _apply_state_name_rule,
    },
}


def run_mutation(name: str) -> int:
    """Apply one in-memory mutation and run the real tiers over it. Exit 1 = the mutation was caught."""
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print(f"  rows that must move: {', '.join(spec['rows']) or '(none named in the table)'}")
    if spec['requires'] and not hasattr(ast_scanner.TaintTracker, spec['requires']):
        print(f"  SKIP - the guard symbol {spec['requires']} does not exist in this engine, so there "
              f"is nothing to delete or widen. NOT counted as a falsification.")
        return 2
    spec['apply']()
    # TIER 1/2 read the frozen baselines and re-scan the whole parity tree; an in-memory patch is
    # falsified on the truth tables and on the blessed lines (TIER 3/6/7), not on a tree scan.
    print(f'TIER 3 - truth table under seal={SEAL!r}:')
    failures = check_shapes()
    print('TIER 6 - the unique-binding numeric seal:')
    failures += check_binding_shapes()
    print('TIER 7 - every blessed CWE-117 line, asked directly:')
    try:
        failures += check_blessed_reach()
    except Exception as exc:  # a mutation that spins or dies is a caught mutation, not a skipped tier
        failures.append(('blessed-reach', 'an answer', type(exc).__name__,
                         'the widened seal could not answer the blessed lines at all'))
    for item in failures[:12]:
        print(f'  !! {item}')
    caught = bool(failures)
    print(f"\nFALSIFICATION VERDICT ({name}): "
          + (f'CAUGHT on {len(failures)} row(s) -- '
             + ', '.join(sorted({str(f[0]) for f in failures})[:6])
             if caught else 'MISSED - the guard is decorative, the engine still answers its own truth '
                            'table'))
    return 1 if caught else 0


if __name__ == '__main__':
    wanted = [a.split('=', 1)[1] for a in sys.argv[1:] if a.startswith('--mutate=')]
    if wanted:
        unknown = [w for w in wanted if w not in MUTATIONS]
        if unknown:
            print(f'BAD MUTATION: {unknown} is not one of {sorted(MUTATIONS)}')
            sys.exit(1)
        sys.exit(run_mutation(wanted[0]))
    sys.exit(main())
