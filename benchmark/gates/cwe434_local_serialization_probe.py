"""Fail-loud lock on CWE-434: the local-serialization exemption is SHIPPED, and this file says so in numbers.

    python benchmark/gates/cwe434_local_serialization_probe.py

CWE-434 (Unrestricted File Upload) is about **bytes a client sent** landing on disk. Until this seal,
the emitter asked only how the call is spelled: `ast_scanner.py` entered the branch for any call whose
dotted name ends in `.save` with at least one argument, and its only guards were `is_model_super_save`
plus two *module-wide* booleans (`module_has_upload_sanitizer`, `has_extension_whitelist`). Nothing on
that path asked where the bytes came from, so `torch.save(state_dict, os.path.join(output_dir, "rng_state.pth"))`
was reported for one reason - it is spelled `.save`.

**What shipped.** `TaintTracker._is_local_serialization_save` is a *positive* whitelist consulted inside
that branch. It exempts only when all of: the canonical receiver names a serialisation namespace
(`torch`, `torch_xla`, `smdistributed`) or is a model-card object; the module touches no upload source;
and no argument mentions a web source. The module test is deliberately wider than the engine's existing
`module_has_upload_sink`, which only sees Call nodes - `request.FILES["f"]` is a Subscript, so that flag
stays False in exactly the Django view the exemption must not enter. The engine's own alias fold supplies
the namespaces - measured, not assumed: `xm.save` resolves to `torch_xla.core.xla_model.save` and
`smp.save` to `smdistributed.modelparallel.torch.save` - so there is no bare-alias spelling list to rot.
Every refusal only
*narrows the exemption*; nothing here gates a report. That asymmetry is the point:
reporting must never require a web source, because all 7 blessed parity keys are

    filename = input("f: ")
    file.save(filename)

in modules with no `request`, no `FILES`, no multipart stream - a web-source *reachability* gate would
delete them. That is the invariant this file calls `NO_WEB_SOURCE_FLOOR`.

**The retirement, measured.** The 17 Big-8 CWE-434 keys *were* the exempt shape, line by line: 11
`torch.save`, 4 `xm.save`, 1 `smp.save`, 1 `model_card.save`, and those 3 corpus files contain exactly
17 `.save(` occurrences in total - so the whitelist cannot reach anything else in them. Each key's code,
enclosing scope, payload and destination binding is documented in `docs/cwe434_big8_fp_evidence.md`, and
the per-key audit is what authorises the re-bless (never the instruction alone). Engine-only first, with
both baselines still at their old sizes, so the moved set is visible before any re-bless can hide it:

    big8_ab.py    baseline=136 now=119 MISSING=17 NEW=0                  (peak RSS 141.6 MB)
    aa_parity.py  baseline=425 now=425 MISSING=0 NEW=0                   (peak RSS 135.3 MB)
    cross_runner.py                F1=1.0000, OVERALL VERDICT: PASS      (peak RSS  35.3 MB)
    cwe117_cwe22_unknown_source_probe.py      59/59 locked keys PASS      (peak RSS  27.0 MB)
    cwe338_ml_math_probe.py                   62 cases, 0 failures        (peak RSS  22.5 MB)
    cwe117_builtin_seal_probe.py              PASS, 49 blessed CWE-117    (peak RSS  32.6 MB)
    cwe22_dirent_closure_probe.py             PASS, 16 blessed CWE-22     (peak RSS  42.8 MB)
    live scan of the 3 corpus files: CWE-434 lines=[] in each             (peak RSS  63.9 MB)
    this probe, still flagged 'abstained'     exit 1 on TIER 2 + the tripwire

MISSING=17 with NEW=0, a baseline whose CWE-434 population is exactly 17, and an empty live CWE-434 set
in each of those files: the moved set is the audited set, so no other CWE moved and nothing extra went
silent. `aa_parity` staying 425/425 is the proof that the 7 parity uploads survived. That probe run
failing was the point of the tripwire: an exemption on disk while 17 keys are still blessed is exactly
the state this file was written to refuse.

After the coordinated re-bless (119-key baseline, `gate_meta.json`, this file) all eight gates ran
sequentially, and the same numbers came back clean:

    aa_parity.py                     425/425 MISSING=0 NEW=0              (peak RSS 119.2 MB)
    big8_ab.py                       119/119 MISSING=0 NEW=0              (peak RSS 139.2 MB)
    cross_runner.py                  F1=1.0000, OVERALL VERDICT: PASS     (peak RSS  34.2 MB)
    this probe                     contract=17 targets=5/5 failures=0      (peak RSS  63.9 MB)
    cwe117_cwe22_unknown_source_probe.py      59/59 locked keys PASS       (peak RSS  23.4 MB)
    cwe338_ml_math_probe.py                   62 cases, 0 failures         (peak RSS  22.3 MB)
    cwe117_builtin_seal_probe.py              PASS, 49 blessed CWE-117     (peak RSS  32.6 MB)
    cwe22_dirent_closure_probe.py             PASS, 16 blessed CWE-22      (peak RSS  43.3 MB)

Highest of those is 139.2 MB, against a 400 MB budget. Speed was clocked on the collector that was
touched, `_collect_batch3a_structural_findings`, paired against the HEAD snapshot of the engine over the
609 tracked benchmark files, 5 alternating pairs: median **+2.57 ms** (shipped 48.77 ms, HEAD 39.59 ms,
deltas -0.35 to +9.17 ms - the spread is wider than the median, so the honest reading is "inside noise,
certainly not a regression"), peak RSS 100.5 MB. The same run is a second FN proof: the collector retained
7 of 7 CWE-434 sinks on that corpus under both engines, with sinks 518/518, sink records 518/518 and
edges 53/53 identical.

**What is deliberately NOT exempt.** `numpy.save(path, a)`, `model.save("mystyle.h5")` and
`saver.save(session, "/var/ckpt/model")` still report. They were the "ML-serializer fallback" in the
original proposal, but zero blessed keys sit on them, so claiming them would widen the exemption's FN
surface for no measured precision gain. They are contract rows here instead, and if a future change
retires them it must arrive with its own truth table.

Tiers: TIER 1 asserts the CWE-434 population from both tracked baselines - 7 parity keys still present,
big8 CWE-434 now 0, the total at 119, and the 17 retired keys absent (a re-bless back in would be a
silent revert of the seal). TIER 2 re-scans the three sha-verified corpus files in memory and asserts
each reports *no* CWE-434 line; those files' other CWEs are asserted key by key by `big8_ab.py`. It is a
set equality, so a retired line coming back fails here before any baseline diff can hide it. TIER 3 is
the contract: 17 must-report shapes - the 6 parity-fixture replicas, 4 web upload shapes (including the
literal-destination write the rejected narrowing would have silenced), 4 serializer calls whose payload,
destination or module mentions a web source, and the 3 serializers this seal does not claim - plus the
5 already-silent good shapes and the 5 exemption targets measured silent.

Falsification. This file was compiled in memory with `__file__` pointed at its real path and
`_is_local_serialization_save` swapped for each mutation, so the tracked file never moved (5 runs, 30.8 s,
peak RSS 83.2 MB). Every mutation fails, each naming its own row - "failing lines" counts the `FAIL` rows
plus the `!!` items the verdict prints:

    helper -> always False (seal rolled back)      exit 1, 7 failing lines: TIER 2 prints all 17
                                                   audited lines again, in all three files
    helper -> always True (any .save(payload))     exit 1, 29 failing lines, starting at
                                                   `dest_from_input_bare` - the parity floor dies
    module upload vocabulary ignored               exit 1, 2 failing lines: `serializer_in_upload_module`
    argument web markers ignored                   exit 1, 2 failing lines: `serializer_payload_named_upload`

Measured on the first attempt, the fourth row did *not* fail: with the argument test deleted the probe
still passed, because every other web-tainted serializer row is already caught by the module test alone.
`serializer_payload_named_upload` exists to make that belt load-bearing instead of decorative - a guard
no row can fail is book-keeping, not protection. To reproduce without any harness: put `return False` as
the whole body of `_is_local_serialization_save` and run this file.
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

LOCAL_SERIALIZATION_SEAL = 'shipped'   # the whitelist is in ast_scanner.py and big8 CWE-434 is retired

LOCKED_434 = {'parity': 7, 'big8': 0}
SINK_MESSAGE = 'CWE-434: UNRESTRICTED_FILE_UPLOAD'

BLESSED_434 = {
    'parity': [
        ('test_v01_bad.py', 2), ('test_v02_bad.py', 7), ('test_v03_bad.py', 3), ('test_v04_bad.py', 6),
        ('test_v05_bad.py', 3), ('test_v05_bad.py', 5), ('test_v06_bad.py', 2),
    ],
    'big8': [],
}

# The 17 keys retired by the seal. Asserted ABSENT from `big8_before.keys` (TIER 1) and silent in the
# live corpus scan (TIER 2) - a baseline that grows them back, or an engine that reports them again,
# both fail.
RETIRED_434 = [
    ('src__transformers__trainer.py', 3472), ('src__transformers__trainer.py', 3474),
    ('src__transformers__trainer.py', 3485), ('src__transformers__trainer.py', 3493),
    ('src__transformers__trainer.py', 3495), ('src__transformers__trainer.py', 3501),
    ('src__transformers__trainer.py', 3527), ('src__transformers__trainer.py', 3539),
    ('src__transformers__trainer.py', 3554), ('src__transformers__trainer.py', 3560),
    ('src__transformers__trainer.py', 4155), ('src__transformers__trainer.py', 4419),
    ('src__transformers__trainer.py', 4653), ('src__transformers__trainer.py', 4654),
    ('src__transformers__modeling_utils.py', 3578),
    ('tests__test_modeling_common.py', 1506), ('tests__test_modeling_common.py', 1508),
]

# The key that forbids a web-source reachability gate: `file.save(input-derived)` with no request at all.
NO_WEB_SOURCE_FLOOR = ('test_v01_bad.py', 2)
# The retired exemplar: it is literally the exempt shape, and it must stay out of the baseline.
RETIRED_EXEMPLAR = ('tests__test_modeling_common.py', 1506)

# Per-file CWE-434 line sets after the seal: empty, by proof rather than hope - the files still hold
# their other CWEs, which `big8_ab.py` asserts key by key.
CORPUS_434_WANT = {
    'src__transformers__trainer.py': [],
    'src__transformers__modeling_utils.py': [],
    'tests__test_modeling_common.py': [],
}

REQ_HEAD = 'from flask import request\n'

# Must report. Rows 1-6 are exact replicas of the blessed parity fixtures, so this tier re-proves the
# true positives rather than trusting a baseline that could be re-blessed away. Rows 7-10 are the web
# upload shapes, including the two the rejected narrowings would have silenced: a literal destination
# does not make an upload safe, and a serializer name does not make a web-tainted write safe. Rows 11-13
# are the serializers this seal deliberately does NOT claim.
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
    ('upload_literal_dest_still_report', REQ_HEAD + 'def h():\n'
     '    request.files["file"].save("/tmp/name.exe")\n', 'report'),
    ('serializer_with_web_destination', REQ_HEAD + 'import torch\n\n\ndef h(sd):\n'
     '    torch.save(sd, request.args.get("p"))\n', 'report'),
    ('serializer_with_web_payload', REQ_HEAD + 'import torch\n\n\ndef h():\n'
     '    upload = request.files["f"].read()\n    torch.save(upload, "/tmp/ckpt.pt")\n', 'report'),
    ('serializer_in_upload_module', 'import torch\n\n\ndef h(request):\n    up = request.FILES["f"]\n'
     '    torch.save(up, "/tmp/ckpt.pt")\n', 'report'),
    # The argument belt's own row: no `request` Name anywhere, so only the payload's web vocabulary
    # refuses the exemption. Without this row the argument test is unfalsifiable - the three rows
    # above are all caught by the module test alone.
    ('serializer_payload_named_upload', 'import torch\n\n\ndef h(fs):\n    upload = fs\n'
     '    torch.save(upload, "/tmp/ckpt.pt")\n', 'report'),
    ('numpy_save_not_claimed', 'import numpy as np\n\n\ndef dump(a, path):\n    np.save(path, a)\n', 'report'),
    ('keras_model_save_not_claimed', 'def store(model):\n    model.save("mystyle.h5")\n', 'report'),
    ('tensorflow_saver_save_not_claimed', 'def store(saver, session):\n'
     '    saver.save(session, "/var/ckpt/model")\n', 'report'),
]

# Good shapes the engine keeps silent. Asserted always - a future broadening to "writing a serialized
# object to disk is an upload" would delete these for free, and nothing else catches it.
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

# The exemption's own promise: the five receiver shapes the 17 retired keys are made of. The two alias
# rows are what the canonical fold is paid for - they only go silent if `xm` / `smp` resolve.
SEAL_TARGETS = [
    ('torch_save_state_dict', 'import torch\n\n\ndef save_ckpt(model, local_path):\n'
     '    torch.save(model.state_dict(), local_path)\n'),
    ('torch_save_join_constant', 'import os\nimport torch\n\n\ndef save_ckpt(model, output_dir):\n'
     '    torch.save(model.state_dict(), os.path.join(output_dir, "rng_state.pth"))\n'),
    ('torch_xla_alias_save', 'import os\nimport torch_xla.core.xla_model as xm\n\n\n'
     'def save_ckpt(optimizer, output_dir):\n'
     '    xm.save(optimizer.state_dict(), os.path.join(output_dir, "optimizer.pt"))\n'),
    ('smdistributed_alias_save', 'import os\nimport smdistributed.modelparallel.torch as smp\n\n\n'
     'def save_ckpt(optimizer, output_dir):\n'
     '    smp.save(optimizer.state_dict(), os.path.join(output_dir, "optimizer.pt"))\n'),
    ('model_card_save_readme', 'import os\n\n\ndef store(model_card, save_directory):\n'
     '    model_card.save(os.path.join(save_directory, "README.md"))\n'),
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
    """TIER 1: the CWE-434 population in both baselines - 7 parity blessed, big8 retired to zero."""
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
                             'the CWE-434 population moved again - 7 parity and 0 big8 are the floor'))
        absent = sorted(f'{leaf}:{line}' for leaf, line in BLESSED_434[kind] if (leaf, line) not in keys)
        print(f'  {kind:7s} blessed keys accounted: {len(BLESSED_434[kind]) - len(absent)}'
              f'/{len(BLESSED_434[kind])} {"" if not absent else absent}')
        if absent:
            failures.append((kind, 'blessed keys', len(BLESSED_434[kind]),
                             len(BLESSED_434[kind]) - len(absent), absent,
                             'a named blessed key is no longer in the baseline - nothing may be re-blessed'))
        leaked = sorted(f'{leaf}:{line}' for leaf, line in RETIRED_434 if (leaf, line) in keys)
        if leaked:
            print(f'  {kind:7s} RETIRED keys back in the baseline: {leaked}')
            failures.append((kind, 'retired keys', 'absent', leaked,
                             'a retired CWE-434 key was re-blessed back while the seal is shipped'))
        if NO_WEB_SOURCE_FLOOR in BLESSED_434[kind]:
            present = NO_WEB_SOURCE_FLOOR in keys
            print(f'  {kind:7s} no-web-source floor {NO_WEB_SOURCE_FLOOR[0]}:{NO_WEB_SOURCE_FLOOR[1]} '
                  f'blessed={present}')
            if not present:
                failures.append(('no-web-source floor', NO_WEB_SOURCE_FLOOR, 'blessed', 'absent',
                                 'the key that forbids a web-source reachability gate is gone'))
        if RETIRED_EXEMPLAR in RETIRED_434 and kind == 'big8':
            present = RETIRED_EXEMPLAR in keys
            print(f'  {kind:7s} retired exemplar {RETIRED_EXEMPLAR[0]}:{RETIRED_EXEMPLAR[1]} '
                  f'blessed={present} (want False)')
            if present:
                failures.append(('retired exemplar', RETIRED_EXEMPLAR, 'absent', 'blessed',
                                 'the exempt shape is blessed again while the seal is shipped'))
    return failures


def check_corpus():
    """TIER 2: the three corpus files that produced the 17 keys, re-scanned live. Independent of the flag."""
    failures = []
    for name, want in sorted(CORPUS_434_WANT.items()):
        rows = scan_corpus_file(name)
        lines = sorted(row['line'] for row in rows)
        ok = lines == sorted(want)
        print(f'  {"ok  " if ok else "FAIL"} live scan {name} CWE-434 lines={lines} want={sorted(want)}')
        if not ok:
            failures.append((name, sorted(want), lines,
                             'the local-serialization seal reports again on the audited false positives'))
    return failures


def check_contract():
    """TIER 3: must-report shapes, already-silent locks, and the shipped exemption promise."""
    failures = []
    for label, source, want in CONTRACT:
        got = 'report' if scan(label, source) else 'silent'
        ok = (got == want)
        print(f'  {"ok  " if ok else "FAIL"} {label:34s} want={want:6s} got={got}')
        if not ok:
            failures.append((label, want, got,
                             'a must-report CWE-434 shape went silent on the engine on disk - false negative'))
    for label, source, want in ALREADY_EXEMPT:
        got = 'report' if scan(label, source) else 'silent'
        ok = (got == want)
        print(f'  {"ok  " if ok else "FAIL"} {label:34s} want={want:6s} got={got}')
        if not ok:
            failures.append((label, want, got,
                             'serialization to a local file is now reported as an upload - false positive'))
    exempted = [label for label, source in SEAL_TARGETS if not scan(label, source)]
    still_reported = [label for label, _ in SEAL_TARGETS if label not in exempted]
    print(f'  seal targets exempted: {len(exempted)}/{len(SEAL_TARGETS)} '
          f'{"" if not still_reported else "still reported: " + str(still_reported)}')
    if LOCAL_SERIALIZATION_SEAL == 'abstained':
        if exempted:
            failures.append(('LOCAL_SERIALIZATION_SEAL', 'abstained', 'no target silent', exempted,
                             'a local-serialization exemption exists while this file says abstained'))
        return failures
    if still_reported:
        failures.append(('LOCAL_SERIALIZATION_SEAL', 'shipped',
                         f'{len(still_reported)} still reported', 'all exempted',
                         'the seal is incomplete - the audited false positives are back'))
    return failures


def main() -> int:
    print('TIER 1 - CWE-434 floors from both baselines (7 parity blessed, 17 big8 retired):')
    failures = check_floors()
    print('TIER 2 - the corpus files that produced the 17 keys, scanned live (the tier that bites):')
    failures += check_corpus()
    print('TIER 3 - must-report contract, already-silent locks, shipped exemption promise:')
    failures += check_contract()
    print(f'\nseal={LOCAL_SERIALIZATION_SEAL} locked_cwe434={sum(LOCKED_434.values())} '
          f'retired={len(RETIRED_434)} contract={len(CONTRACT)} already_exempt={len(ALREADY_EXEMPT)} '
          f'targets={len(SEAL_TARGETS)} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-434 local-serialization decision no longer matches its evidence. '
              'Restoring the finding is the fix; re-blessing a baseline is not.')
        return 1
    print('VERDICT: PASS - 7 parity uploads still blessed and 425/425 parity, the 17 audited Big-8 '
          'false positives silent in the corpus and out of the 119-key baseline, 17 must-report shapes live.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
