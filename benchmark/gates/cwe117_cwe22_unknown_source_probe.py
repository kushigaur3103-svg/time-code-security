"""Fail-loud lock on the 59 Big-8 true positives that ride a placeholder-source edge.

    python benchmark/gates/cwe117_cwe22_unknown_source_probe.py

The claim this protects, measured rather than assumed:

* `big8_before.keys` holds **43 CWE-117 + 16 CWE-22** keys - 59 of its blessed 136;
* scanning each corpus file on its own reports all 59, and every one of them reaches its sink
  through an edge whose `source_id` is **not a node in `tracker.sources`** (those files register 0-3
  real sources between them). CWE-117 gets the edge at `ast_scanner.py:23599`, which writes the
  literal `"UNKNOWN"` when an f-string resolves to UNKNOWN taint with no source; CWE-22 gets it from
  the phase-5 collector's own placeholder `UNTRUSTED_PATH_TRAVERSAL`.

Why that must be a gate and not a comment: the tempting one-line "precision" cleanup - *emit an edge
only when a real source node exists* - deletes all 59 findings at once. On real code that is a 43 + 16
finding false negative, and a gate whose baseline is re-blessed afterwards cannot see it: the diff
would come back empty. The same measurement is why the two CWE-117 exemptions that were rejected on
2026-10-28 stay rejected: "needs a real source" costs all 59 keys, and "log arguments come from
argparse/dataclasses" costs 4 (`src__transformers__trainer.py` 736, 1604, 1609, 1618) - one of which,
`f"  Gradient Accumulation steps = {args.gradient_accumulation_steps}"`, is character-identical to an
example-script false positive, so no expression-shape rule can separate the two populations.

This file asserts the contract on sources parsed in memory, never on files it opens: the parity gate
scans this directory, and every content-read of a path assembled at runtime inside it is reported as
CWE-22 - an earlier draft of this probe proved that with `NEW=2`. Presence of the 59 keys in the live
scan is `big8_ab.py`'s job (it diffs the whole 136-key set against the sha256-verified corpus); the
split and the mechanism are this probe's. It writes nothing anywhere.
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

LOCKED = {'CWE-117': 43, 'CWE-22': 16}

# (label, source, cwe, sink line, placeholder source_id the engine must use)
PLACEHOLDER_CASES = [
    ('args_from_parser', (
        'import logging\nfrom transformers import HfArgumentParser\n'
        'logger = logging.getLogger(__name__)\n'
        'def main():\n'
        '    parser = HfArgumentParser(TrainingArguments)\n'
        '    args = parser.parse_args_into_dataclasses()[0]\n'
        '    logger.info(f"  Steps = {args.max_train_steps}")\n'),
     'CWE-117', 7, 'UNKNOWN'),
    ('param_attribute', (
        'import logging\nlogger = logging.getLogger(__name__)\n'
        'def main(args):\n'
        '    logger.info(f"  Epochs = {args.num_train_epochs}")\n'),
     'CWE-117', 4, 'UNKNOWN'),
    ('attribute_product', (
        'import logging\nlogger = logging.getLogger(__name__)\n'
        'def main(args, accelerator):\n'
        '    total = args.per_device_train_batch_size * accelerator.num_processes\n'
        '    logger.info(f"  Total batch size = {total}")\n'),
     'CWE-117', 5, 'UNKNOWN'),
    ('parameter_derived_path_write', (
        'import os\n'
        'def save(output_dir, name):\n'
        '    target = os.path.join(output_dir, name)\n'
        '    with open(target, "w", encoding="utf-8") as fh:\n'
        '        fh.write("x")\n'),
     'CWE-22', 4, 'UNTRUSTED_PATH_TRAVERSAL'),
]

# (label, source, line that must NOT be reported) - the same statements with nothing to interpolate.
CONTROL_CASES = [
    ('pure_literal_log', (
        'import logging\nlogger = logging.getLogger(__name__)\n'
        'def main():\n'
        '    logger.info("***** Running training *****")\n'), 4),
    ('int_literal_log', (
        'import logging\nlogger = logging.getLogger(__name__)\n'
        'def main():\n'
        '    epochs = 3\n'
        '    logger.info(f"  Num Epochs = {epochs}")\n'), 5),
    ('len_call_log', (
        'import logging\nlogger = logging.getLogger(__name__)\n'
        'def main(train_dataset):\n'
        '    logger.info(f"  Num examples = {len(train_dataset)}")\n'), 4),
    ('literal_path_open', (
        'with open("notes.txt", "w", encoding="utf-8") as fh:\n'
        '    fh.write("x")\n'), 1),
]


def scan(label, source):
    """One in-memory module: findings, and the source ids of the edges that produced them."""
    noise = io.StringIO()
    with contextlib.redirect_stderr(noise):
        tracker = ast_scanner.TaintTracker(files={f'{label}.py': source})
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    real = {node.id for node in tracker.sources}
    reaching = collections.defaultdict(list)
    for edge in edges:
        reaching[edge.target_id].append(edge)
    return tracker, rows, real, reaching


def check_baseline():
    """The tracked file must still carry the locked split, and the total it was blessed with."""
    rows = load_keys(os.path.join(GATES_DIR, META['big8']['keys_file']), 'big8')
    split = collections.Counter(row[2] for row in rows)
    print(f'tracked baseline: total={len(rows)} '
          + '  '.join(f'{cwe}={split[cwe]}' for cwe in sorted(LOCKED)))
    failures = []
    expected = META['big8']['expected_keys']
    if len(rows) != expected:
        failures.append(('baseline total', expected, len(rows),
                         'big8_before.keys no longer holds the blessed findings'))
    for cwe, want in sorted(LOCKED.items()):
        if split[cwe] != want:
            failures.append((cwe, want, split[cwe],
                             'this population moved - 59 keys are the locked floor'))
    return failures


def check_placeholders():
    """Each placeholder-carried shape must still report, on the same placeholder id, with no source."""
    failures = []
    for label, source, cwe, line, placeholder in PLACEHOLDER_CASES:
        tracker, rows, real, reaching = scan(label, source)
        hit = [row for row in rows if row['line'] == line and row['cwe'] == cwe]
        ids = {edge.source_id for sink in tracker.sinks
               for edge in reaching.get(sink.id, ())
               if sink.location.line_start == line and (sink.metadata or {}).get('cwe') == cwe}
        phantom = sorted(i for i in ids if i not in real)
        ok = bool(hit) and phantom == [placeholder] and not real
        print(f'  {"ok  " if ok else "FAIL"} {label:28s} {cwe:9s} L{line} '
              f'reported={bool(hit)} placeholder={phantom} real_sources={len(real)}')
        if not hit:
            failures.append((label, cwe, 'reported', 'missing',
                             'the placeholder edge that carried this finding was dropped'))
        elif phantom != [placeholder]:
            failures.append((label, cwe, placeholder, phantom,
                             'the finding survives on a different route than the one this lock names'))
        elif real:
            failures.append((label, cwe, 'no registered source', len(real),
                             'a source appeared, so this case no longer isolates the placeholder'))
    return failures


def check_controls():
    """And the inert shapes must stay silent - otherwise 'never drop an edge' is bought with noise."""
    failures = []
    for label, source, line in CONTROL_CASES:
        _, rows, _, _ = scan(label, source)
        hit = [row for row in rows if row['line'] == line]
        print(f'  {"ok  " if not hit else "FAIL"} {label:28s} L{line} reported={bool(hit)}')
        if hit:
            failures.append((label, line, 'silent', [row['cwe'] for row in hit],
                             'a provably inert message became a finding'))
    return failures


def main() -> int:
    failures = check_baseline()
    failures += check_placeholders()
    failures += check_controls()
    cases = len(PLACEHOLDER_CASES) + len(CONTROL_CASES)
    print(f'\nlocked_keys={sum(LOCKED.values())} cases={cases} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the placeholder-sourced true-positive population moved. '
              'Restoring it is the fix; re-blessing the baseline is not.')
        return 1
    print('VERDICT: PASS - 59/59 locked keys and the placeholder-edge contract they ride on.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
