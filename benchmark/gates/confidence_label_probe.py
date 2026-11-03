"""Confidence-label probe: the three-clause bucketing law, its blessed distribution, and the
proof that the two frozen baselines are BLIND to that column.

Why this gate exists, in one line: `benchmark/gates/scan_child.py` builds a finding key from
`(file, line, cwe, category, message, severity)` -- confidence is not in it. So `aa_parity.py` and
`big8_ab.py` stay green if a label moves from HIGH to LOW or from MEDIUM to HIGH, and `--min-confidence`
is the one CLI switch that turns a label into a hidden finding. That combination is a false-negative
path with no lock on it, and the mandate that asked for "confidence: low on unproven taint, high on
direct traces" is asking to widen exactly that surface.

Measured on the shipped engine, this tier by tier:

* TIER 1 -- the law is already in the file, as text: HIGH iff an edge of kind
  ``CONFIRMED_DATA_FLOW``, MEDIUM iff a POTENTIAL edge, LOW iff the sink's ``sink_type`` (or its
  ``category`` fallback) is a member of ``LOW_CONFIDENCE_SINK_TYPES`` = {``TIMING_ATTACK``}, the
  loudest label wins at a site, and ``_filter_by_confidence`` has exactly ONE call site, after
  emission, with ``--min-confidence`` ``default=None``.
* TIER 2 -- the law behaves that way: 11 synthetic (sinks, edges) shapes through the real
  ``cli._findings_for``, each asserting its label and that the message is untouched.
* TIER 3 -- the filter is display-only: a fixed row list at floors None/low/medium/high, the
  missing-label default, purity (subset, never mutation), and the unknown-label fallback.
* TIER 4 -- the blessed distribution, recomputed from both frozen corpora and joined to the frozen
  keys: parity ``HIGH=404 MEDIUM=15 LOW=6`` over 425, Big-8 ``HIGH=18 MEDIUM=71 LOW=30`` over 119.
  The mandate's "all 119 and all 425 retain high" is FALSE by 422-of-544, and the two families it
  names are the reason: CWE-208 is 36/36 LOW and Big-8 CWE-117 is 43/43 MEDIUM.
* TIER 5 -- the blindness proof, both directions: two rows differing only in ``confidence`` yield
  the SAME canonical key (so a label drift is invisible to the baselines), and two rows differing in
  ``message`` yield DIFFERENT keys (so a label that ever leaked into the message would be loud).

Five falsifications, all in-memory, each CAUGHT on a named tier: ``low_sink_bucket_dropped``,
``confidence_order_inverted``, ``filter_runs_when_not_asked``, ``medium_promoted_to_high``,
``label_leaks_into_the_message``. With ``--with-corpus`` the first one is also priced against TIER 4,
where it empties the LOW bucket of 30 blessed Big-8 rows.

Usage: python benchmark/gates/confidence_label_probe.py [--mutate=NAME] [--with-corpus]
Exit 0 = every tier passes; 1 = a named failure; 2 = the tier cannot speak (missing symbol).
"""
from __future__ import annotations

import collections
import contextlib
import inspect
import io
import json
import os
import sys
import types

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, '..', '..'))
sys.path.insert(0, GATES_DIR)
sys.path.insert(0, ROOT)

from gate_common import (META, GatePathError, canon_key, corpus_dir, load_keys,  # noqa: E402
                         verify_corpus)

import cli  # noqa: E402

FAILURES = []
TIMING = 'TIMING_ATTACK'


def fail(label, detail):
    FAILURES.append(f'{label}: {detail}')


def _sink(sid, cwe, line, **metadata):
    meta = {'cwe': cwe, 'message': f'{cwe}: compare of two local values', 'category': 'Security'}
    meta.update(metadata)
    return types.SimpleNamespace(
        id=sid, symbol='left_value', location=types.SimpleNamespace(file='pkg/mod.py',
                                                                    line_start=line),
        metadata=meta)


def _edge(sid, kind):
    return types.SimpleNamespace(target_id=sid, kind=kind, proof_graph=None)


def _labels(sinks, edges):
    """Run the real builder and return {line: (confidence, message)} for what it emitted."""
    findings = cli._findings_for(types.SimpleNamespace(sinks=sinks), edges)
    return {item['line']: (item['confidence'], item['message']) for item in findings}


CONFIRMED = 'CONFIRMED_DATA_FLOW'
POTENTIAL = 'POTENTIAL_DATA_FLOW'

SHAPES = [
    ('direct traced flow', [_sink('S1', 'CWE-22', 10)], [_edge('S1', CONFIRMED)], 'HIGH'),
    ('heuristic edge, no confirmed flow', [_sink('S2', 'CWE-22', 11)],
     [_edge('S2', POTENTIAL)], 'MEDIUM'),
    ('in-process compare, confirmed edge', [_sink('S3', 'CWE-208', 12, sink_type=TIMING)],
     [_edge('S3', CONFIRMED)], 'LOW'),
    ('in-process compare, potential edge', [_sink('S4', 'CWE-208', 13, sink_type=TIMING)],
     [_edge('S4', POTENTIAL)], 'LOW'),
    ('same site, quiet edge first', [_sink('S5', 'CWE-22', 14), _sink('S5', 'CWE-22', 14)],
     [_edge('S5', POTENTIAL), _edge('S5', CONFIRMED)], 'HIGH'),
    ('same site, loud edge first', [_sink('S6', 'CWE-22', 15), _sink('S6', 'CWE-22', 15)],
     [_edge('S6', CONFIRMED), _edge('S6', POTENTIAL)], 'HIGH'),
    ('a name that merely contains the bucket word',
     [_sink('S7', 'CWE-208', 16, sink_type='TIMING_ATTACK_VARIANT')],
     [_edge('S7', CONFIRMED)], 'HIGH'),
    ('category carries the bucket word, no sink_type',
     [_sink('S8', 'CWE-208', 17, sink_type=None, category=TIMING)],
     [_edge('S8', CONFIRMED)], 'LOW'),
]


def check_law_source():
    """TIER 1: the clauses the mandate asked for are the clauses the file already carries."""
    src = inspect.getsource(cli._findings_for)
    for label, needle, want in (
        ('LOW clause tests the sink type first', f'if sink_type in LOW_CONFIDENCE_SINK_TYPES:', 1),
        ('HIGH clause is the confirmed-edge kind', f'elif edge.kind == "{CONFIRMED}":', 1),
        ('MEDIUM clause is the else of that pair', 'confidence = "MEDIUM"', 1),
        ('loudest label wins at a site',
         'CONFIDENCE_ORDER[confidence] > CONFIDENCE_ORDER[existing["confidence"]]', 1),
        ('severity comes from the rule table', 'rule.get_severity(confidence_label)', 1),
    ):
        got = src.count(needle)
        if got != want:
            fail('T1 ' + label, f'found {got}x in cli._findings_for, want {want}x')
    if cli.LOW_CONFIDENCE_SINK_TYPES != frozenset({TIMING}):
        fail('T1 the LOW bucket holds one sink type',
             f'got {sorted(cli.LOW_CONFIDENCE_SINK_TYPES)}')
    if cli.CONFIDENCE_ORDER != {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}:
        fail('T1 the order table is a total order', f'got {cli.CONFIDENCE_ORDER}')
    with open(os.path.join(GATES_DIR, '..', '..', 'cli.py'), encoding='utf-8') as handle:
        whole = handle.read()
    if whole.count('_filter_by_confidence(') != 2:
        fail('T1 the filter has one call site and one definition',
             f'found {whole.count("_filter_by_confidence(")} mentions, want 2')
    flag_at = whole.find('"--min-confidence"')
    if flag_at < 0 or 'default=None' not in whole[flag_at:flag_at + 400]:
        fail('T1 --min-confidence ships a default of None',
             'the add_argument call following the flag does not read default=None')
    child_path = os.path.join(GATES_DIR, 'scan_child.py')
    with open(child_path, encoding='utf-8') as handle:
        child = handle.read()
    if 'confidence' in child:
        fail('T1 the frozen baselines still cannot see the column',
             'scan_child.py now reads confidence, so this gate is no longer the only lock')


def check_label_table():
    """TIER 2: the same law, asked of the real builder."""
    for label, sinks, edges, want in SHAPES:
        got = _labels(sinks, edges)
        line = sinks[0].location.line_start
        if line not in got:
            fail('T2 ' + label, 'the builder emitted nothing for this shape')
            continue
        seen, message = got[line]
        if seen != want:
            fail('T2 ' + label, f'label={seen}, want={want}')
        if ' [' in message or message.count(':') != 1:
            fail('T2 ' + label, f'message moved out of shape: {message!r}')
    orphan = _labels([], [_edge('S9', CONFIRMED)])
    if orphan:
        fail('T2 an edge whose sink the tracker never registered',
             f'emitted {len(orphan)} rows, want 0')
    if len(SHAPES) < 8:
        fail('T2 the table has a floor', f'{len(SHAPES)} shapes, want >= 8')


FILTER_ROWS = [
    {'file': 'a.py', 'confidence': 'HIGH'},
    {'file': 'b.py', 'confidence': 'MEDIUM'},
    {'file': 'c.py', 'confidence': 'LOW'},
    {'file': 'd.py'},
    {'file': 'e.py', 'confidence': 'unheard-of'},
]
FILTER_LAW = [
    (None, 5), ('low', 5), ('medium', 4), ('high', 1),
]


def check_filter_purity():
    """TIER 3: the switch hides rows from a report; it never reaches emission."""
    original = [dict(row) for row in FILTER_ROWS]
    for minimum, want in FILTER_LAW:
        kept = cli._filter_by_confidence(list(FILTER_ROWS), minimum)
        names = sorted(row['file'] for row in kept)
        if len(kept) != want:
            fail(f'T3 floor {minimum!r}', f'kept {len(kept)} {names}, want {want}')
        if [dict(row) for row in FILTER_ROWS] != original:
            fail(f'T3 floor {minimum!r}', 'the input list was mutated')
    untouched = cli._filter_by_confidence(FILTER_ROWS, None)
    if len(untouched) != len(FILTER_ROWS) or untouched is not FILTER_ROWS:
        fail('T3 no floor returns the engine list untouched',
             f'len {len(untouched)} vs {len(FILTER_ROWS)}, same object '
             f'{untouched is FILTER_ROWS}')
    missing = cli._filter_by_confidence([{'file': 'x.py'}], 'high')
    if missing:
        fail('T3 an unlabelled row is not treated as high', 'a row with no label survived')


def _run_cli(argv, cwd):
    out, err = io.StringIO(), io.StringIO()
    previous = os.getcwd()
    os.chdir(cwd)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            cli.main(argv)
    finally:
        os.chdir(previous)
    text = out.getvalue()
    start = text.find('{')
    if start < 0:
        raise GatePathError(f'scan in {cwd!r} printed no payload: {err.getvalue()[-400:]}')
    return json.loads(text[start:])


EXPECTED_MIX = {'parity': {'HIGH': 404, 'MEDIUM': 15, 'LOW': 6},
                'big8': {'HIGH': 18, 'MEDIUM': 71, 'LOW': 30}}


def _corpus_labels(kind, cwd):
    payload = _run_cli(['scan', '.', '--format', 'json', '--workers', '1'], cwd)
    labels, rows = {}, []
    for finding in payload['findings']:
        row = (finding['file'], finding['line'], finding['cwe'], finding.get('category', ''),
               finding['message'], finding['severity'])
        labels[canon_key(row, kind)] = str(finding.get('confidence') or 'MISSING').upper()
        rows.append((canon_key(row, kind), finding['cwe']))
    return labels, rows


def check_blessed_distribution():
    """TIER 4: what the two frozen baselines really carry, per rule."""
    pmeta = META['parity']
    parity_cwd = os.path.join(ROOT, pmeta['scan_root'])
    big8_dir = corpus_dir('big8')
    verify_corpus('big8', big8_dir)
    corpora = {
        'parity': (parity_cwd, load_keys(os.path.join(GATES_DIR, pmeta['keys_file']), 'parity')),
        'big8': (big8_dir, load_keys(os.path.join(GATES_DIR, META['big8']['keys_file']), 'big8')),
    }
    for kind, (cwd, frozen) in corpora.items():
        labels, rows = _corpus_labels(kind, cwd)
        asked = [key for key in frozen if key in labels]
        if len(asked) != len(frozen):
            fail(f'T4 {kind} asks every blessed key',
                 f'joined {len(asked)} of {len(frozen)}')
            continue
        mix = collections.Counter(labels[key] for key in asked)
        want = EXPECTED_MIX[kind]
        if dict(mix) != want:
            fail(f'T4 {kind} label mix', f'got {dict(mix)}, want {want}')
        if len(frozen) != int(META[kind]['expected_keys']):
            fail(f'T4 {kind} baseline size', f'{len(frozen)} keys, want {META[kind]["expected_keys"]}')
        by_cwe = collections.defaultdict(collections.Counter)
        for key, cwe in rows:
            if key in labels:
                by_cwe[cwe][labels[key]] += 1
        if kind == 'big8':
            for cwe, want_label, want_n in (('CWE-208', 'LOW', 30), ('CWE-117', 'MEDIUM', 43),
                                             ('CWE-338', 'MEDIUM', 7)):
                got = dict(by_cwe.get(cwe, {}))
                if got != {want_label: want_n}:
                    fail(f'T4 {kind} {cwe} is 100% {want_label}', f'got {got}')
            c22 = dict(by_cwe.get('CWE-22', {}))
            if c22 != {'HIGH': 11, 'MEDIUM': 5}:
                fail(f'T4 {kind} CWE-22 keeps both buckets', f'got {c22}')
        else:
            for cwe, want_label, want_n in (('CWE-208', 'LOW', 6), ('CWE-338', 'MEDIUM', 9),
                                             ('CWE-22', 'HIGH', 8), ('CWE-798', 'HIGH', 6)):
                got = dict(by_cwe.get(cwe, {}))
                if got != {want_label: want_n}:
                    fail(f'T4 {kind} {cwe} is 100% {want_label}', f'got {got}')
            high = sum(1 for key in asked if labels[key] == 'HIGH')
            print(f'    T4 blessed at HIGH: parity={high} of {len(asked)}')


def _key_of(finding, kind):
    return canon_key((finding['file'], finding['line'], finding['cwe'],
                      finding.get('category', ''), finding['message'], finding['severity']), kind)


def check_blindness():
    """TIER 5: a label that stays out of the key is invisible; a leak would not be."""
    finding = {'file': 'pkg/mod.py', 'line': 12, 'cwe': 'CWE-208', 'category': 'Security',
               'message': 'CWE-208: compare of two local values', 'severity': 'HIGH',
               'confidence': 'HIGH'}
    before = _key_of(finding, 'parity')
    finding['confidence'] = 'LOW'
    after = _key_of(finding, 'parity')
    if before != after:
        fail('T5 the key ignores the confidence column', f'{before!r} moved to {after!r}')
    finding['message'] = finding['message'] + ' [LOW]'
    leaked = _key_of(finding, 'parity')
    if leaked == before:
        fail('T5 a message change still moves the key',
             'the scrubber swallowed a message difference, so a leak would be invisible too')
    print(f'    T5 confidence is not a key field (blind) and message is (leak-loud): '
          f'{before == after and leaked != before}')


MUTATIONS = {}


def _mutation(name, what, apply, tiers):
    MUTATIONS[name] = {'what': what, 'apply': apply, 'tiers': tiers}


def _drop_low_bucket():
    cli.LOW_CONFIDENCE_SINK_TYPES = frozenset()


def _invert_order():
    cli.CONFIDENCE_ORDER = {'LOW': 3, 'MEDIUM': 2, 'HIGH': 1}


def _filter_always_runs():
    def patched(findings, minimum):
        floor = cli.CONFIDENCE_ORDER[(minimum or 'high').upper()]
        return [row for row in findings
                if cli.CONFIDENCE_ORDER.get(
                    str(row.get('confidence') or 'MEDIUM').upper(), 2) >= floor]
    cli._filter_by_confidence = patched


def _promote_medium():
    pristine = cli._findings_for

    def patched(tracker, edges):
        findings = pristine(tracker, edges)
        for finding in findings:
            if finding['confidence'] == 'MEDIUM':
                finding['confidence'] = 'HIGH'
        return findings
    cli._findings_for = patched


def _leak_into_message():
    pristine = cli._findings_for

    def patched(tracker, edges):
        findings = pristine(tracker, edges)
        for finding in findings:
            finding['message'] = f"{finding['message']} [{finding['confidence']}]"
        return findings
    cli._findings_for = patched


_mutation('low_sink_bucket_dropped',
          'delete the TIMING_ATTACK bucket, so an in-process compare is reported as a traced flow',
          _drop_low_bucket, [check_label_table, check_blessed_distribution])
_mutation('confidence_order_inverted',
          'rank LOW above HIGH, which flips the per-site merge and every floor',
          _invert_order, [check_label_table, check_filter_purity])
_mutation('filter_runs_when_not_asked',
          'apply a hidden high floor even when --min-confidence was never given',
          _filter_always_runs, [check_filter_purity])
_mutation('medium_promoted_to_high',
          'quietly relabel every heuristic edge as a confirmed flow',
          _promote_medium, [check_label_table])
_mutation('label_leaks_into_the_message',
          'append the label to the message, the one route by which a label could reach a key',
          _leak_into_message, [check_label_table])

TIERS = [check_law_source, check_label_table, check_filter_purity, check_blindness]


def main(argv) -> int:
    mutate = None
    with_corpus = '--with-corpus' in argv
    for token in argv:
        if token.startswith('--mutate='):
            mutate = token.split('=', 1)[1]
    if mutate:
        entry = MUTATIONS.get(mutate)
        if entry is None:
            print(f'unknown mutation {mutate!r}; ship one of {sorted(MUTATIONS)}')
            return 2
        print(f'MUTATION {mutate}: {entry["what"]}')
        entry['apply']()
        tiers = list(entry['tiers'])
        if not with_corpus:
            tiers = [tier for tier in tiers if tier is not check_blessed_distribution]
        for tier in tiers:
            tier()
        if FAILURES:
            for item in FAILURES:
                print(f'  !! {item}')
            print(f'CAUGHT on {len(FAILURES)} failure(s)')
            return 1
        print('MISSED -- the guard is decorative')
        return 0

    for tier in TIERS:
        tier()
    check_blessed_distribution()
    print(f'law sinks bucket={sorted(cli.LOW_CONFIDENCE_SINK_TYPES)} '
          f'order={cli.CONFIDENCE_ORDER} shapes={len(SHAPES)} '
          f'filter_rows={len(FILTER_ROWS)} mutations={len(MUTATIONS)}')
    if FAILURES:
        for item in FAILURES:
            print(f'  !! {item}')
        print(f'failures={len(FAILURES)}')
        return 1
    print('failures=0')
    print('VERDICT: PASS - confidence bucketing law pinned, blessed mix 404/15/6 + 18/71/30, '
          'key blindness proved')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
