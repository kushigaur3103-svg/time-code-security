"""Fail-loud lock: the CWE-22 dirent-closure seal is ABSTAINED, and this file says why in numbers.

    python benchmark/gates/cwe22_dirent_closure_probe.py

Proposal B was: treat a path component that came out of an operating-system directory listing
(`os.listdir`, `os.scandir` + `.name`, `Path.iterdir`, `os.walk` filenames) as traversal-free, because
such a name cannot contain a separator. Two variants were written into `_is_safe_path`
(`ast_scanner.py:20533`), measured, and reverted byte-exactly (engine hash before and after
`d757f9bc8a1cdc97`).

**Strict** - all three proposed conditions (safe base AND bare, unconcatenated component AND canonical
dotted name):

    big8_ab.py    baseline=136 now=136 MISSING=0 NEW=0   (peak RSS 140.6 MB)
    aa_parity.py  baseline=425 now=425 MISSING=0 NEW=0   (peak RSS 132.4 MB)

Not one key moved in either direction. Traced, the reason is an address error, not a condition error:
the branch does fire (`join branch names={'os.path.join'} base_safe=True comps=[True]`), but the
finding for that very shape is emitted by the sink registry, which already holds the sink
(`metadata={'sink_type': 'PATH_TRAVERSAL', 'cwe': 'CWE-22', 'p5_source_id': 'UNTRUSTED_PATH_TRAVERSAL'}`)
before `_is_safe_path` is asked anything. All four `SEAL_TARGETS` below still reported under the strict
seal - a rule planted in `_is_safe_path` cannot reduce this FP class at any strength.

**Loose** - condition 1 (safe base) dropped, the argument the proposal actually makes:

    big8_ab.py    baseline=136 now=135 MISSING=1 NEW=0
      MISSING: ('corpus_big8/src__transformers__modeling_utils.py', 3494, 'CWE-22',
                'PATH_TRAVERSAL', 'CWE-22: os.remove', 'HIGH')      VERDICT: FAIL (exit 1)

So the only thing this rule demonstrably changes, at the address proposed, is one blessed true
positive: `src__transformers__modeling_utils.py:3494`, a `os.remove` of a name read out of the
`os.listdir` loop at `:3477` and joined at `:3478`. That is a false negative bought with a true
positive, so the Zero-FN Shield refuses it and `DIRENT_SEAL` stays `'abstained'`.

TIER 2 is the tier that bites: it scans the sha-verified corpus file in memory and asserts the
derivation still reports, so the next attempt fails here even before the baseline diff can be
re-blessed into invisibility.

Where a dirent exemption *would* belong, if this FP class is ever really pursued: the CWE-22 collector
`_collect_cwe22_path_traversal_findings` (`ast_scanner.py:19758`), whose own guard
`_sanitized_path_arg` (`:19782`) already prunes sanitizer-wrapped first arguments at `:19812`. That
guard runs on the emission path; `_is_safe_path` does not. It prunes a whole sink, so it can also drop
findings of other CWEs riding the same sink, which is why it needs the full gate suite, not a probe.

Also measured, and kept so nobody re-derives it: six escape-shaped cases (`entry_path_delete`,
`walk_root_write`, `name_reassigned_scope2_write` and the read-mode `entry_path_not_entry_name`,
`walk_root_is_dynamic`) are already silent on the clean engine, so they are not contract rows and are
not listed in `SEAL_BUDGET` - a row that does not report today proves nothing about a future seal.

Tiers: TIER 1 asserts the blessed CWE-22 population from the tracked baseline. TIER 2 asserts the live
corpus derivation. TIER 3 is the contract any future seal must satisfy, dormant while abstained.
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
from gate_common import META, corpus_dir, load_keys, verify_corpus  # noqa: E402

DIRENT_SEAL = 'abstained'   # 'shipped' only if a dirent-closure exemption lands on the CWE-22 emission path

LOCKED_CWE22 = 16
BLESSED_DIRENT_KEY = ('src__transformers__modeling_utils.py', 3494)
DIRENT_SINK_MESSAGE = 'CWE-22: os.remove'
# Every CWE-22 line this corpus file contributes to the blessed baseline, measured live.
BLESSED_CORPUS_22_LINES = [336, 3494, 3564]

# The 16 blessed keys, as measured from big8_before.keys. TIER 1 checks every one is still blessed.
BLESSED_22 = [
    ('src__transformers__modeling_utils.py', 336),
    ('src__transformers__modeling_utils.py', 3494),
    ('src__transformers__modeling_utils.py', 3564),
    ('src__transformers__trainer.py', 2008),
    ('src__transformers__trainer.py', 4301),
    ('tests__generation__test_utils.py', 5537),
    ('tests__generation__test_utils.py', 5539),
    ('tests__generation__test_utils.py', 5565),
    ('tests__models__markuplm__test_tokenization_markuplm.py', 138),
    ('tests__models__markuplm__test_tokenization_markuplm.py', 73),
    ('tests__models__markuplm__test_tokenization_markuplm.py', 75),
    ('tests__models__markuplm__test_tokenization_markuplm.py', 77),
    ('tests__test_modeling_common.py', 1279),
    ('tests__test_tokenization_mistral_common.py', 263),
    ('tests__test_tokenization_mistral_common.py', 274),
    ('tests__test_tokenization_mistral_common.py', 280),
]

REQ_HEAD = 'from flask import request\n'

# Every row below was measured to REPORT on the clean engine, so each one is a real contract: a
# shipped dirent seal must still report all of them.
SEAL_BUDGET = [
    ('tainted_base', REQ_HEAD + 'import os\n'
     'def h():\n    base = request.args.get("d")\n'
     '    for name in os.listdir(base):\n        open(os.path.join(base, name))\n', 'report'),
    ('name_plus_user_text', REQ_HEAD + 'import os\n'
     'def h():\n    user = request.args.get("u")\n'
     '    for name in os.listdir("/srv"):\n        open(os.path.join("/srv", name + user))\n', 'report'),
    ('name_in_fstring_with_user', REQ_HEAD + 'import os\n'
     'def h():\n    user = request.args.get("u")\n'
     '    for name in os.listdir("/srv"):\n        open(f"/srv/{name}/{user}")\n', 'report'),
    ('second_dynamic_component', REQ_HEAD + 'import os\n'
     'def h():\n    user = request.args.get("u")\n'
     '    for name in os.listdir("/srv"):\n        open(os.path.join("/srv", name, user))\n', 'report'),
    ('glob_multi_component', 'import glob\n'
     'def h():\n    for p in glob.glob("/srv/*/*"):\n        open(p)\n', 'report'),
    ('bare_user_path', REQ_HEAD + 'def h():\n    open(request.args.get("p"))\n', 'report'),
    ('rmtree_tainted_dir', REQ_HEAD + 'import shutil\n'
     'def h():\n    shutil.rmtree(request.args.get("d"))\n', 'report'),
    ('extractall_tainted_archive', REQ_HEAD + 'import tarfile\n'
     'def h():\n    tarfile.open(request.args.get("p")).extractall("/srv")\n', 'report'),
    # entry.path is already absolute, so joining it can leave the base: not a closure case.
    ('entry_path_join_write', REQ_HEAD + 'import os\n'
     'def h():\n    base = os.path.abspath(request.args.get("d"))\n'
     '    for entry in os.scandir(base):\n'
     '        with open(os.path.join(base, entry.path), "w") as f:\n            f.write("x")\n', 'report'),
    # The name is a dirent target, then reassigned from the request inside the same loop: a seal keyed
    # on the name instead of the assignment would hide this.
    ('name_reassigned_in_loop_delete', REQ_HEAD + 'import os\n'
     'def h():\n    base = os.path.abspath(request.args.get("d"))\n'
     '    for name in os.listdir(base):\n        name = request.args["f"]\n'
     '        os.remove(os.path.join(base, name))\n', 'report'),
    ('dirent_name_plus_user_text_write', REQ_HEAD + 'import os\n'
     'def h():\n    base = os.path.abspath(request.args.get("d"))\n'
     '    user = request.args.get("u")\n    for name in os.listdir(base):\n'
     '        with open(os.path.join(base, name + user), "w") as f:\n            f.write("x")\n', 'report'),
    ('dirent_name_in_fstring_write', REQ_HEAD + 'import os\n'
     'def h():\n    base = os.path.abspath(request.args.get("d"))\n'
     '    user = request.args.get("u")\n    for name in os.listdir(base):\n'
     '        with open(f"{base}/{name}/{user}", "w") as f:\n            f.write("x")\n', 'report'),
]

# The exemption's own promise: a write into a sanitized base of a name the OS listed. All four were
# measured to REPORT on the clean engine - and all four still reported under the strict `_is_safe_path`
# seal, which is the address error recorded in this file's docstring.
SEAL_TARGETS = [
    ('abspath_base_listdir_write', REQ_HEAD + 'import os\n'
     'def h():\n    base = os.path.abspath(request.args.get("d"))\n'
     '    for name in os.listdir(base):\n'
     '        with open(os.path.join(base, name), "w") as f:\n            f.write("x")\n'),
    ('abspath_base_scandir_name_write', REQ_HEAD + 'import os\n'
     'def h():\n    base = os.path.abspath(request.args.get("d"))\n'
     '    for entry in os.scandir(base):\n'
     '        with open(os.path.join(base, entry.name), "w") as f:\n            f.write("x")\n'),
    ('abspath_base_iterdir_path_write', REQ_HEAD + 'from pathlib import Path\n'
     'def h():\n    base = os.path.abspath(request.args.get("d"))\n'
     '    for p in Path(base).iterdir():\n'
     '        with open(str(p), "w") as f:\n            f.write("x")\n'),
    ('abspath_base_iterdir_name_write', REQ_HEAD + 'from pathlib import Path\nimport os\n'
     'def h():\n    base = os.path.abspath(request.args.get("d"))\n'
     '    for p in Path(base).iterdir():\n'
     '        with open(os.path.join(base, p.name), "w") as f:\n            f.write("x")\n'),
]


def scan(label, source):
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={f'{label}.py': source})
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return [row for row in rows if row['cwe'] == 'CWE-22']


def scan_corpus_file(name):
    """One sha-verified corpus file, scanned in memory - no temp files, no re-blessing.

    The path is wrapped in `os.path.abspath` because the gates scan this directory: an unwrapped
    `os.path.join(directory, name)` here is a dynamic path argument to `open`, and the harness would
    then contribute a CWE-22 key of its own to the parity baseline.
    """
    directory = corpus_dir('big8')
    verify_corpus('big8', directory)
    path = os.path.abspath(os.path.join(directory, name))
    with open(path, encoding='utf-8', errors='replace') as handle:
        source = handle.read()
    return scan(name, source)


def check_floors():
    """TIER 1: the blessed CWE-22 population, key by key, and the dirent-derived one in particular."""
    failures = []
    rows = load_keys(os.path.join(GATES_DIR, META['big8']['keys_file']), 'big8')
    split = collections.Counter(row[2] for row in rows)
    cwe22 = [(os.path.basename(str(r[0])), r[1]) for r in rows if r[2] == 'CWE-22']
    print(f'  big8    total={len(rows)} (want {META["big8"]["expected_keys"]})  '
          f'CWE-22={split["CWE-22"]} (want {LOCKED_CWE22})')
    if len(rows) != META['big8']['expected_keys']:
        failures.append(('big8', 'baseline total', META['big8']['expected_keys'], len(rows)))
    if split['CWE-22'] != LOCKED_CWE22:
        failures.append(('CWE-22', LOCKED_CWE22, split['CWE-22'],
                         'the CWE-22 population moved - 16 blessed keys are the floor'))
    absent = [f'{leaf}:{line}' for leaf, line in BLESSED_22
              if (leaf, line) not in cwe22]
    print(f'  blessed CWE-22 keys accounted: {len(BLESSED_22) - len(absent)}/{len(BLESSED_22)} '
          f'{"" if not absent else absent}')
    if absent:
        failures.append(('blessed keys', len(BLESSED_22), len(BLESSED_22) - len(absent), absent,
                         'a named blessed key is no longer in the baseline - nothing may be re-blessed'))
    dirent_present = BLESSED_DIRENT_KEY in cwe22
    print(f'  dirent-derived floor {BLESSED_DIRENT_KEY[0]}:{BLESSED_DIRENT_KEY[1]} '
          f'blessed={dirent_present}')
    if not dirent_present:
        failures.append(('dirent floor', 'blessed', 'absent',
                         'the key that forbids the dirent-closure seal is gone - stop and investigate'))
    return failures


def check_corpus_derivation():
    """TIER 2: the real listdir -> join -> os.remove chain, reported by the engine that is on disk.

    Independent of `DIRENT_SEAL`: a correct seal keeps these rows, so the assertion is the same either
    way, which is what makes it a lock instead of book-keeping. Measured to FAIL (line set minus 3494)
    under the loose seal described in the docstring.
    """
    failures = []
    rows = scan_corpus_file(BLESSED_DIRENT_KEY[0])
    lines = sorted(row['line'] for row in rows)
    ok_lines = lines == sorted(BLESSED_CORPUS_22_LINES)
    print(f'  {"ok  " if ok_lines else "FAIL"} live scan {BLESSED_DIRENT_KEY[0]} '
          f'CWE-22 lines={lines} want={sorted(BLESSED_CORPUS_22_LINES)}')
    if not ok_lines:
        failures.append((BLESSED_DIRENT_KEY[0], BLESSED_CORPUS_22_LINES, lines,
                         'a dirent-shaped exemption deleted a blessed true positive'))
    message = {row['line']: row['message'] for row in rows}.get(BLESSED_DIRENT_KEY[1])
    ok_sink = message == DIRENT_SINK_MESSAGE
    print(f'  {"ok  " if ok_sink else "FAIL"} dirent derivation {BLESSED_DIRENT_KEY[0]}:'
          f'{BLESSED_DIRENT_KEY[1]} message={message!r} want={DIRENT_SINK_MESSAGE!r}')
    if not ok_sink:
        failures.append((f'{BLESSED_DIRENT_KEY[0]}:{BLESSED_DIRENT_KEY[1]}', DIRENT_SINK_MESSAGE, message,
                         'the listdir-derived os.remove no longer reaches the delete sink'))
    return failures


def check_seal_budget():
    """TIER 3: dormant while the seal is abstained; the contract the moment anyone ships one."""
    failures = []
    if DIRENT_SEAL == 'abstained':
        exempted = [label for label, source in SEAL_TARGETS if not scan(label, source)]
        print(f'  seal abstained; dirent write targets silent: {len(exempted)}/{len(SEAL_TARGETS)} '
              f'{exempted}')
        if exempted:
            failures.append(('DIRENT_SEAL', 'abstained', 'all dirent targets reported', exempted,
                             'a dirent-closure exemption exists but this file still says abstained'))
        return failures
    for label, source, want in SEAL_BUDGET:
        got = 'report' if scan(label, source) else 'silent'
        print(f'  {"ok  " if got == want else "FAIL"} {label:32s} want={want:6s} got={got}')
        if got != want:
            failures.append((label, want, got,
                             'the dirent seal silenced an escaping shape - false negative'))
    exempted = [label for label, source in SEAL_TARGETS if not scan(label, source)]
    print(f'  seal shipped; dirent write targets silent: {len(exempted)}/{len(SEAL_TARGETS)}')
    if len(exempted) != len(SEAL_TARGETS):
        failures.append(('DIRENT_SEAL', 'shipped', f'{len(SEAL_TARGETS) - len(exempted)} still reported',
                         'all exempted', 'the seal is incomplete'))
    return failures


def main() -> int:
    print('TIER 1 - blessed CWE-22 floor (asserted):')
    failures = check_floors()
    print('TIER 2 - dirent derivation scanned live from the vendored corpus (the tier that bites):')
    failures += check_corpus_derivation()
    print('TIER 3 - contract for a dirent-closure seal:')
    failures += check_seal_budget()
    print(f'\ndirent_seal={DIRENT_SEAL} locked_cwe22={LOCKED_CWE22} '
          f'budget={len(SEAL_BUDGET)} targets={len(SEAL_TARGETS)} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-22 dirent-closure decision no longer matches its evidence. '
              'Restoring the finding is the fix; re-blessing a baseline is not.')
        return 1
    print('VERDICT: PASS - 16 blessed CWE-22 keys, and the live listdir-derived os.remove a dirent '
          'seal would have deleted.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
