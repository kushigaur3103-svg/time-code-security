"""Fail-loud lock on the two CWE-117 true positives that a "numeric log hole" exemption would delete.

    python benchmark/gates/cwe117_builtin_seal_probe.py

The claim this protects, measured rather than assumed:

* `parity_before.keys` blesses **6** CWE-117 keys and `big8_before.keys` blesses **43**, so 49
  hand-written findings are the floor this rule must never move;
* one of the parity keys is `cwe_1004_cookies/test_v01_good.py:12`, whose statement is
  `logger.error(str(e))` -- a *call*, and `str()` of an exception can span lines, because exception
  messages carry the text the raiser put in them;
* one of the Big-8 keys is `src__transformers__modeling_utils.py:3567`, a `logger.info(` whose
  multi-line message interpolates `{len(state_dict_split.filename_to_tensors)}` **and**
  `{max_shard_size}` **and** `{save_index_file}`. It is reported today only because
  `_log_message_is_numeric_only` (ast_scanner.py:5141) is all-or-nothing: one unsafe hole keeps the
  whole message reported.

Why that must be a gate and not a comment: the obvious precision pitch is "a hole that calls a
numeric builtin like `len()` cannot carry CRLF, so exempt it". Measured against the blessed baselines
that pitch is safe *only while all-or-nothing survives*, and it is silently fatal for `str()` -- the
parity key at line 12 is exactly a `str()` call hole. So the two shapes above are frozen here, and
the exemption budget below lists what any seal may never touch.

Assertion tiers, so this file can be committed before it is ever run:

* TIER 1 asserts facts already proven from the tracked baselines. It cannot fail spuriously.
* TIER 2 prints, but does not assert, in-memory replicas of the blessed shapes. Replicas are not the
  corpus; asserting them before their first measured run would be guessing. `REPLICA_ASSERT` is the
  one-way switch, flipped only after a run shows every replica behaving as the baseline says it must.
* TIER 3 is the seal budget -- the shapes a future exemption must keep reporting. It is asserted only
  once the seal exists (`STATE == 'sealed'`), and in `pending` it loudly fails if all of them already
  behave sealed, because that would mean the fix landed and this lock was never flipped.
"""
from __future__ import annotations

import collections
import contextlib
import io
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys  # noqa: E402

STATE = 'sealed'           # 'pending' = no builtin-scalar seal exists yet; 'sealed' = ast_scanner has one
REPLICA_ASSERT = True      # flip to True only after a measured run agrees with TIER 1

LOCKED = {'parity': 6, 'big8': 43}
FLOORS = {
    'parity': (META['parity']['expected_keys'], 'CWE-117', ('test_v01_good.py', 12)),
    'big8': (META['big8']['expected_keys'], 'CWE-117',
             ('src__transformers__modeling_utils.py', 3567)),
}

LOG_HEAD = 'import logging\nlogger = logging.getLogger(__name__)\n'
REQ_HEAD = 'from flask import request\n'

# (label, source, expectation) -- expectation 'report' means a CWE-117 finding must exist.
REPLICAS = [
    ('blessed_parity_str_e', REQ_HEAD + LOG_HEAD + 'def h(exc_text):\n'
     '    try:\n        raise ValueError(request.args.get("m"))\n'
     '    except ValueError as e:\n        logger.error(str(e))\n', 'report'),
    ('blessed_big8_mixed_fstring', LOG_HEAD + 'def h(args, state_dict_split, save_index_file, max_shard_size):\n'
     '    logger.info(\n'
     '        f"The model is bigger ({max_shard_size}) and is going to be "\n'
     '        f"split in {len(state_dict_split.filename_to_tensors)} checkpoint shards. "\n'
     '        f"index located at {save_index_file}."\n'
     '    )\n', 'report'),
]

SEAL_BUDGET = [
    ('shadowed_len_by_def', REQ_HEAD + LOG_HEAD + 'def len(x):\n    return "\\r\\nINJECTED"\n'
     'def h():\n    rows = request.args.get("q")\n    logger.info(f"n={len(rows)}")\n', 'report'),
    ('shadowed_len_by_assignment', REQ_HEAD + LOG_HEAD + 'len = lambda x: "\\r\\nINJECTED"\n'
     'def h():\n    rows = request.args.get("q")\n    logger.info(f"n={len(rows)}")\n', 'report'),
    ('shadowed_len_by_parameter', REQ_HEAD + LOG_HEAD + 'def h(len):\n'
     '    rows = request.args.get("q")\n    logger.info(f"n={len(rows)}")\n', 'report'),
    ('shadowed_len_by_loop_target', REQ_HEAD + LOG_HEAD + 'def h():\n    for len in request.args:\n        pass\n'
     '    rows = request.args.get("q")\n    logger.info(f"n={len(rows)}")\n', 'report'),
    ('shadowed_len_by_import', REQ_HEAD + LOG_HEAD + 'from tools import count as len\n'
     'def h():\n    rows = request.args.get("q")\n    logger.info(f"n={len(rows)}")\n', 'report'),
    ('str_of_exception', REQ_HEAD + LOG_HEAD + 'def h():\n    e = request.args.get("q")\n    logger.error(str(e))\n',
     'report'),
    ('abs_is_not_sealed', REQ_HEAD + LOG_HEAD + 'def h():\n    o = request.args.get("q")\n    logger.info(f"n={abs(o)}")\n',
     'report'),
    ('one_unsafe_hole_reports_all', REQ_HEAD + LOG_HEAD + 'def h():\n    rows = request.args.get("q")\n'
     '    logger.info(f"a={len(rows)} b={rows}")\n', 'report'),
    ('bare_name_hole', REQ_HEAD + LOG_HEAD + 'def h():\n    name = request.args.get("q")\n    logger.info(f"v={name}")\n',
     'report'),
    ('comparison_hole', REQ_HEAD + LOG_HEAD + 'def h():\n    a = request.args.get("q")\n'
     '    logger.info(f"same={a == 1}")\n', 'report'),
    ('non_fstring_tainted_arg', REQ_HEAD + LOG_HEAD + 'def h():\n    msg = request.args.get("q")\n'
     '    logger.info(msg)\n', 'report'),
]

SEAL_TARGETS = [
    ('len_only_hole', REQ_HEAD + LOG_HEAD + 'def h():\n    rows = request.args.get("q")\n'
     '    logger.info(f"n={len(rows)}")\n'),
    ('int_only_hole', REQ_HEAD + LOG_HEAD + 'def h():\n    n = request.args.get("q")\n'
     '    logger.info(f"n={int(n)}")\n'),
    ('float_bool_ord_holes', REQ_HEAD + LOG_HEAD + 'def h():\n    x = request.args.get("q")\n'
     '    logger.info(f"{float(x)}{bool(x)}{ord(x)}")\n'),
]


def scan(label, source):
    """One in-memory module through the real record path -- tracker, edges, then finding rows."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={f'{label}.py': source})
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return [row for row in rows if row['cwe'] == 'CWE-117']


def check_floors():
    """TIER 1: the blessed CWE-117 population and the two named keys that decide the seal."""
    failures = []
    for kind, (expected_total, cwe, (leaf, line)) in FLOORS.items():
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        split = collections.Counter(row[2] for row in rows)
        print(f'  {kind:7s} total={len(rows)} (want {expected_total})  {cwe}={split[cwe]} (want {LOCKED[kind]})')
        if len(rows) != expected_total:
            failures.append((kind, 'baseline total', expected_total, len(rows)))
        if split[cwe] != LOCKED[kind]:
            failures.append((kind, cwe, LOCKED[kind], split[cwe],
                             'this population moved - 49 blessed CWE-117 keys are the floor'))
        hit = [row for row in rows
               if os.path.basename(str(row[0])) == leaf and row[1] == line and row[2] == cwe]
        print(f'  {kind:7s} floor key {leaf}:{line} present={bool(hit)}')
        if not hit:
            failures.append((kind, f'{leaf}:{line}', 'blessed', 'absent',
                             'the key that forbids a str()/mixed-hole exemption is no longer blessed'))
    return failures


def check_replicas():
    """TIER 2: in-memory copies of the blessed shapes. Printed always, asserted only once proven."""
    mismatches = []
    for label, source, want in REPLICAS:
        got = scan(label, source)
        status = 'report' if got else 'silent'
        ok = (status == want)
        tag = 'ok  ' if ok else ('FAIL' if REPLICA_ASSERT else 'note')
        print(f'  {tag} {label:26s} want={want:6s} got={status}')
        if not ok and REPLICA_ASSERT:
            mismatches.append((label, want, status, 'replica contradicts the blessed baseline'))
    if REPLICA_ASSERT and not mismatches:
        print('  REPLICA_ASSERT is True and every replica matches - the replicas may now gate.')
    elif not REPLICA_ASSERT:
        print('  replicas informational only (REPLICA_ASSERT=False); TIER 1 is what gates today.')
    return mismatches


def check_seal_budget():
    """TIER 3: the shapes any builtin-scalar seal must keep reporting, plus the pending/sealed tripwire."""
    failures = []
    for label, source, want in SEAL_BUDGET:
        got = 'report' if scan(label, source) else 'silent'
        active = STATE == 'sealed'
        tag = 'ok  ' if got == want else ('FAIL' if active else 'note')
        print(f'  {tag} {label:28s} want={want:6s} got={got}')
        if got != want and active:
            failures.append((label, want, got,
                             'the seal silenced a shape that can still carry CR/LF - false negative'))
    exempted = [label for label, source in SEAL_TARGETS if not scan(label, source)]
    print(f'  seal targets currently silent: {len(exempted)}/{len(SEAL_TARGETS)} {exempted}')
    if STATE == 'pending' and len(exempted) == len(SEAL_TARGETS):
        failures.append(('STATE', 'pending', 'sealed',
                         'the builtin-scalar seal exists in ast_scanner.py but STATE was never flipped'))
    if STATE == 'sealed' and len(exempted) != len(SEAL_TARGETS):
        missing = len(SEAL_TARGETS) - len(exempted)
        failures.append(('STATE', 'sealed', f'{missing} seal target(s) still reported', 'all exempted',
                         'the seal regressed or was never completed'))
    return failures


def main() -> int:
    print('TIER 1 - blessed CWE-117 floors (asserted):')
    failures = check_floors()
    print('TIER 2 - blessed shapes replicated in memory:')
    failures += check_replicas()
    print('TIER 3 - seal budget for a builtin-scalar exemption:')
    failures += check_seal_budget()
    print(f'\nstate={STATE} replica_assert={REPLICA_ASSERT} locked_cwe117={sum(LOCKED.values())} '
          f'failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-117 numeric-hole exemption spec no longer matches its evidence. '
              'Restoring the finding is the fix; re-blessing a baseline is not.')
        return 1
    print('VERDICT: PASS - 49 blessed CWE-117 keys and the str()/mixed-message shapes that bound any seal.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
