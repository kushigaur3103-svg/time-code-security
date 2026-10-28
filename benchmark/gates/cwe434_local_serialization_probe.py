"""Fail-loud lock on CWE-434: the local-serialization exemption is ABSTAINED, and this file says why in numbers.

    python benchmark/gates/cwe434_local_serialization_probe.py

The proposal was: stop reporting CWE-434 (Unrestricted File Upload) on offline model serialization -
`torch.save(model.state_dict(), local_path)`, `pickle.dump(obj, open("model.bin", "wb"))`, standalone
checkpoint saving - because no bytes arrive from a web request, so the CWE definition does not fit.
Measured on the engine on disk, the defect is real and the cure is not, in that order:

    torch.save(model.state_dict(), local_path)                    -> CWE-434 at line 5   (reported)
    torch.save(sd, os.path.join(output_dir, "rng_state.pth"))      -> CWE-434 at line 6   (reported)
    np.save(path, a)                                               -> CWE-434 at line 5   (reported)
    model.save("mystyle.h5")                                       -> CWE-434 at line 2   (reported)
    pickle.dump(obj, open("model.bin", "wb"))                      -> silent
    open("model.bin", "wb").write(data)                             -> silent
    super().save(update_fields=["x"]) with no upload sink in file   -> silent

The emission is `ast_scanner.py:16027`: any call whose dotted name ends in `.save` with at least one
argument enters the branch, and the only guards are `is_model_super_save` (`:16030`) plus two
*module-wide* booleans, `module_has_upload_sanitizer` and `has_extension_whitelist` (`:16040`, both
accumulated by the pre-scan at `:15916` and `:15927`). Nothing anywhere on that path asks where the
bytes came from, so `torch.save` is reported for one reason: it is spelled `.save`.

**Why the exemption is refused.** The frozen baselines bless **24** CWE-434 keys - 7 in
`parity_before.keys`, 17 in `big8_before.keys` - and **all 17** Big-8 keys *are* the proposed exempt
shape, line by line: 16 `torch.save` / `xm.save` / `smp.save` state-dict writes and one
`model_card.save(...)`:

    src__transformers__trainer.py        3472 3474 3527 3539 3560 4155 4419 4653 4654  torch.save(...)
    src__transformers__trainer.py        3485 3493 3495 3501 3554                      xm.save / smp.save(...)
    src__transformers__modeling_utils.py 3578  model_card.save(os.path.join(save_directory, "README.md"))
    tests__test_modeling_common.py       1506 1508  torch.save(state_dict, pt_checkpoint_path, ...)

So a rule that exempts `torch.save(model.state_dict(), local_path)` does not fix a false positive in
isolation - it deletes the entire blessed CWE-434 Big-8 population at once, and `big8_ab.py` re-blessed
afterwards would show an empty diff. That is exactly what the Zero-FN Shield forbids (`AGENTS.md`: "no
agent shall implement an exemption ... that drops a True Positive ... even if explicitly instructed"),
and exactly the failure mode the Big-8 154->136 retirement had to prove its way out of. `LOCAL_SERIALIZATION_SEAL`
therefore stays `'abstained'` until a human retires those 17 keys with a truth table behind them.

**Why there is no cheap discriminator either.** The obvious narrower rule - "the destination is not
tainted, so it is not an upload" - cannot save the parity floor, and the obvious "no web source in this
module" rule *kills* it: all 7 blessed parity keys are `file.save(<dest>)` where `<dest>` comes from
`input()` in a module with no `request`, no `FILES`, no multipart stream at all. The fixture
`benchmark/corpus/cwe_434_upload/test_v01_bad.py` is two lines, and they are

    filename = input("f: ")
    file.save(filename)

so a web-source reachability gate reports nothing there and deletes a blessed true positive. That key
is the floor asserted in TIER 1, which is the measured form of the invariant "no blanket web-source
reachability checks".

**The stated fallback collides the same way.** "Restrict the exemption strictly to recognized ML
serializers" was measured against the baselines: `numpy.save(path, a)` reports CWE-434 with **zero**
blessed keys on it, while `torch.save` is blessed 16 times - so a serializer allow-list would exempt
numpy and keep torch, two calls of one shape distinguished only by which library the name happens to
say. That is a brittle name check, not an AST semantic, and it is the semantic ambiguity the mandate
refuses, so nothing landed for this cluster either.

Tiers: TIER 1 asserts the blessed CWE-434 population, key by key, from both tracked baselines. TIER 2
re-scans the three corpus files that produce those keys, in memory, sha-verified - it is a set equality,
so a line that a future exemption stops reporting fails the tier before any re-bless can hide it.
TIER 3 is the contract: the must-report shapes (every one measured to report on the engine on disk)
plus the two exempt groups. `ALREADY_EXEMPT` is asserted always, because the engine already keeps those
silent and a future "any serialize-to-file is an upload" rule would break them for free.
`SEAL_TARGETS` is asserted only once the exemption exists; while abstained, any one of them going
silent is itself the failure, because it means a seal landed while 17 keys are still blessed.

Falsification, measured with this file left at `'abstained'`: flipping the flag to `'shipped'` with no
engine change exits 1 on `the seal is incomplete (0/5 exempted)`. TIER 2 does not depend on the flag at
all, so the engine-side half of the promise cannot be kept quietly.
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

LOCAL_SERIALIZATION_SEAL = 'abstained'   # 'shipped' only if a local-serialization exemption lands AND 434_big8 is retired

LOCKED_434 = {'parity': 7, 'big8': 17}
SINK_MESSAGE = 'CWE-434: UNRESTRICTED_FILE_UPLOAD'

BLESSED_434 = {
    'parity': [
        ('test_v01_bad.py', 2), ('test_v02_bad.py', 7), ('test_v03_bad.py', 3), ('test_v04_bad.py', 6),
        ('test_v05_bad.py', 3), ('test_v05_bad.py', 5), ('test_v06_bad.py', 2),
    ],
    'big8': [
        ('src__transformers__trainer.py', 3472), ('src__transformers__trainer.py', 3474),
        ('src__transformers__trainer.py', 3485), ('src__transformers__trainer.py', 3493),
        ('src__transformers__trainer.py', 3495), ('src__transformers__trainer.py', 3501),
        ('src__transformers__trainer.py', 3527), ('src__transformers__trainer.py', 3539),
        ('src__transformers__trainer.py', 3554), ('src__transformers__trainer.py', 3560),
        ('src__transformers__trainer.py', 4155), ('src__transformers__trainer.py', 4419),
        ('src__transformers__trainer.py', 4653), ('src__transformers__trainer.py', 4654),
        ('src__transformers__modeling_utils.py', 3578),
        ('tests__test_modeling_common.py', 1506), ('tests__test_modeling_common.py', 1508),
    ],
}

# The key that forbids a web-source reachability gate: `file.save(input-derived)` with no request at all.
NO_WEB_SOURCE_FLOOR = ('test_v01_bad.py', 2)
# The key that forbids a local-serialization seal: it is literally the proposed exempt shape, blessed.
TORCH_SAVE_FLOOR = ('tests__test_modeling_common.py', 1506)

# Per-file CWE-434 line sets as blessed, so TIER 2 can be run file by file.
BLESSED_CORPUS_434 = {
    'src__transformers__trainer.py': [3472, 3474, 3485, 3493, 3495, 3501, 3527, 3539, 3554, 3560,
                                      4155, 4419, 4653, 4654],
    'src__transformers__modeling_utils.py': [3578],
    'tests__test_modeling_common.py': [1506, 1508],
}

REQ_HEAD = 'from flask import request\n'

# Replicas of the blessed parity fixtures. Every row here is a true positive: the destination is
# user-derived and the module never sanitizes it, so CWE-434 must keep firing with no web source present.
CONTRACT = [
    ('dest_from_input_bare', 'filename = input("f: ")\nfile.save(filename)\n', 'report'),
    ('dest_through_helper', 'import os\n\n\ndef dest(name):\n    return os.path.join(UPLOAD_DIR, name)\n\n'
     'filename = input("f: ")\nfile.save(dest(filename))\n', 'report'),
    ('dest_through_dict', 'filename = input("f: ")\ncfg = {"path": filename}\nfile.save(cfg["path"])\n', 'report'),
    ('dest_through_attr', 'class UploadHandler:\n    def __init__(self, filename):\n'
     '        self.filename = filename\n\n    def store(self):\n        file.save(self.filename)\n', 'report'),
    ('dest_in_both_branches', 'filename = input("f: ")\nif production:\n'
     '    file.save("/var/uploads/" + filename)\nelse:\n    file.save("/tmp/uploads/" + filename)\n', 'report'),
    ('dest_by_concatenation', 'filename = input("f: ")\nfile.save(UPLOAD_DIR + "/" + filename)\n', 'report'),
    ('multipart_flask_save', REQ_HEAD + '@app.route("/u", methods=["POST"])\ndef h():\n'
     '    f = request.files["file"]\n    f.save("/var/uploads/" + f.filename)\n', 'report'),
    ('multipart_django_save', 'def h(request):\n    for up in request.FILES.values():\n'
     '        up.save(request.POST["dest"])\n', 'report'),
    ('arbitrary_dest_from_query', REQ_HEAD + 'def h(upload):\n    upload.save(request.args.get("dest"))\n',
     'report'),
]

# Good shapes the engine already keeps silent. Asserted always - a future broadening to "writing a
# serialized object to disk is an upload" would delete these for free, and nothing else catches it.
ALREADY_EXEMPT = [
    ('pickle_dump_inline_open', 'import pickle\n\n\ndef dump(obj):\n'
     '    pickle.dump(obj, open("model.bin", "wb"))\n', 'silent'),
    ('pickle_dump_with_open', 'import pickle\n\n\ndef dump(obj):\n    with open("model.bin", "wb") as fh:\n'
     '        pickle.dump(obj, fh)\n', 'silent'),
    ('model_super_save_no_upload', 'class M(Base):\n    def save(self):\n'
     '        super().save(update_fields=["x"])\n', 'silent'),
    # Not a CWE-434 defect today: `open(..., "wb").write(...)` reaches no `.save()` branch at all.
    ('open_wb_write_with', 'def store(data):\n    with open("model.bin", "wb") as fh:\n'
     '        fh.write(data)\n', 'silent'),
    ('open_wb_write_inline', 'def store(data):\n    open("ckpt.bin", "wb").write(data)\n', 'silent'),
]

# The proposed exemption's own promise. All five rows below were measured to REPORT on the engine on
# disk, which is the whole reason the tier is abstained: rows 1 and 2 are the blessed Big-8 shape.
SEAL_TARGETS = [
    ('torch_save_state_dict', 'import torch\n\n\ndef save_ckpt(model, local_path):\n'
     '    torch.save(model.state_dict(), local_path)\n'),
    ('torch_save_join_constant', 'import os\nimport torch\n\n\ndef save_ckpt(model, output_dir):\n'
     '    torch.save(model.state_dict(), os.path.join(output_dir, "rng_state.pth"))\n'),
    ('numpy_save_checkpoint', 'import numpy as np\n\n\ndef dump(a, path):\n    np.save(path, a)\n'),
    ('keras_model_save', 'def store(model):\n    model.save("mystyle.h5")\n'),
    ('tensorflow_saver_save', 'def store(saver, session):\n    saver.save(session, "/var/ckpt/model")\n'),
]


def scan(label, source):
    """One in-memory module through the real record path - tracker, edges, then finding rows."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={f'{label}.py': source})
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return [row for row in rows if row['cwe'] == 'CWE-434']


def scan_corpus_file(name):
    """One sha-verified corpus file, scanned in memory - no temp files, no re-blessing.

    `os.path.abspath` wraps the path because the gates scan this directory: a bare dynamic `open` of a
    joined path would make this harness contribute a finding of its own to the parity baseline.
    """
    directory = corpus_dir('big8')
    verify_corpus('big8', directory)
    path = os.path.abspath(os.path.join(directory, name))
    with open(path, encoding='utf-8', errors='replace') as handle:
        source = handle.read()
    return scan(name, source)


def check_floors():
    """TIER 1: the blessed CWE-434 population in both baselines, key by key."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        split = collections.Counter(row[2] for row in rows)
        keys = {(os.path.basename(str(row[0])), row[1]) for row in rows if row[2] == 'CWE-434'}
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-434={split["CWE-434"]} (want {LOCKED_434[kind]})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if split['CWE-434'] != LOCKED_434[kind]:
            failures.append((kind, 'CWE-434', LOCKED_434[kind], split['CWE-434'],
                             'the blessed CWE-434 population moved - 24 keys are the floor'))
        absent = sorted(f'{leaf}:{line}' for leaf, line in BLESSED_434[kind] if (leaf, line) not in keys)
        print(f'  {kind:7s} blessed keys accounted: {len(BLESSED_434[kind]) - len(absent)}'
              f'/{len(BLESSED_434[kind])} {"" if not absent else absent}')
        if absent:
            failures.append((kind, 'blessed keys', len(BLESSED_434[kind]),
                             len(BLESSED_434[kind]) - len(absent), absent,
                             'a named blessed key is no longer in the baseline - nothing may be re-blessed'))
        for name, floor, why in (('no-web-source floor', NO_WEB_SOURCE_FLOOR,
                                  'the key that forbids a web-source reachability gate'),
                                 ('torch.save floor', TORCH_SAVE_FLOOR,
                                  'the blessed key that is the proposed exempt shape')):
            if floor not in BLESSED_434[kind]:
                continue
            present = floor in keys
            print(f'  {kind:7s} {name:20s} {floor[0]}:{floor[1]} blessed={present}')
            if not present:
                failures.append((name, floor, 'blessed', 'absent', f'{why} is gone - stop and investigate'))
    return failures


def check_corpus():
    """TIER 2: the corpus files that produce the 17 keys, re-scanned live. Independent of the flag."""
    failures = []
    for name, want in sorted(BLESSED_CORPUS_434.items()):
        rows = scan_corpus_file(name)
        lines = sorted(row['line'] for row in rows)
        ok = lines == sorted(want)
        print(f'  {"ok  " if ok else "FAIL"} live scan {name} CWE-434 lines={lines} want={sorted(want)}')
        if not ok:
            failures.append((name, sorted(want), lines,
                             'a local-serialization exemption deleted blessed true positives'))
        wrong = sorted({row['message'] for row in rows} - {SINK_MESSAGE})
        if wrong:
            print(f'  note  {name} messages outside the sink label: {wrong}')
    return failures


def check_contract():
    """TIER 3: must-report shapes, already-silent locks, and the abstained exemption promise."""
    failures = []
    for label, source, want in CONTRACT:
        got = 'report' if scan(label, source) else 'silent'
        ok = (got == want)
        print(f'  {"ok  " if ok else "FAIL"} {label:28s} want={want:6s} got={got}')
        if not ok:
            failures.append((label, want, got,
                             'a blessed CWE-434 true-positive shape went silent on the engine on disk'))
    for label, source, want in ALREADY_EXEMPT:
        got = 'report' if scan(label, source) else 'silent'
        ok = (got == want)
        print(f'  {"ok  " if ok else "FAIL"} {label:28s} want={want:6s} got={got}')
        if not ok:
            failures.append((label, want, got,
                             'serialization to a local file is now reported as an upload - false positive'))
    exempted = [label for label, source in SEAL_TARGETS if not scan(label, source)]
    reported = len(SEAL_TARGETS) - len(exempted)
    print(f'  measured false positives still reported: {reported}/{len(SEAL_TARGETS)} '
          f'{[label for label, _ in SEAL_TARGETS if label not in exempted]}')
    if LOCAL_SERIALIZATION_SEAL == 'abstained':
        if exempted:
            failures.append(('LOCAL_SERIALIZATION_SEAL', 'abstained', 'all targets still reported', exempted,
                             'a local-serialization exemption exists while 17 CWE-434 Big-8 keys are blessed'))
        return failures
    if reported:
        failures.append(('LOCAL_SERIALIZATION_SEAL', 'shipped', f'{reported} still reported',
                         'all exempted', 'the seal is incomplete'))
    return failures


def main() -> int:
    print('TIER 1 - blessed CWE-434 floors from both baselines (asserted):')
    failures = check_floors()
    print('TIER 2 - the corpus files that produce the 17 Big-8 keys, scanned live (the tier that bites):')
    failures += check_corpus()
    print('TIER 3 - must-report contract, already-silent locks, exemption promise:')
    failures += check_contract()
    print(f'\nseal={LOCAL_SERIALIZATION_SEAL} locked_cwe434={sum(LOCKED_434.values())} '
          f'contract={len(CONTRACT)} already_exempt={len(ALREADY_EXEMPT)} '
          f'targets={len(SEAL_TARGETS)} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-434 local-serialization decision no longer matches its evidence. '
              'Restoring the finding is the fix; re-blessing a baseline is not.')
        return 1
    print('VERDICT: PASS - 24 blessed CWE-434 keys, and the 16 torch/xm/smp writes plus '
          'model_card.save(...) that any local-serialization seal would delete.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
