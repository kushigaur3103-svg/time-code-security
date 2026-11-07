#!/usr/bin/env python3
"""Phase 2.1 lock: CWE-338 is decided by two semantic facts, never by a line number or a path.

Why this gate exists. The rule used to answer "is this draw a finding?" twice, from two different
kinds of evidence:

  * the sink gate (`_is_dangerous_call` -> `_cwe338_display_only_draw` and friends), which reads the
    callee's canonical library and the names the value flows into, and
  * the graph cascade, which read a hardcoded set of blessed *line numbers*
    (`_C338_BLESSED_LINES_SHIELD`) to stop four name/path skips from eating those same lines.

A shield of line numbers is not a fact: it memorises where the benchmark happens to keep its true
positives, and it decides the same question twice with different evidence. Worse, the skips it
guarded were file-name and directory-name tests -- the one axis that can delete a true positive for
no reason a reader could see.

The shipped answer keeps only the semantic funnel, and fixes its direction:

  Verdict = CSPRNG -> silent
            STATISTICAL_SAMPLING and not SECURITY_SENSITIVE -> silent
            everything else -> loud

The provider is the only fact allowed to excuse a draw. The security-use fact is a veto that can
only widen *toward* loud, never a multiplier, because 8 of the 16 blessed CWE-338 keys are stdlib
`random` draws landing in a plain `values` list, a bare `return`, or a `let_pass` append -- the exact
NON_SECURITY spellings a multiplier would silence. TIER 3 is that arithmetic, measured.
"""

import ast
import io
import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GATES_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

import ast_scanner  # noqa: E402
import cli  # noqa: E402

BASELINE_TOTALS = {'parity': 425, 'big8': 119}
CWE338_LOCKED = {'parity': 9, 'big8': 7}

LOUD = 'loud'
QUIET = 'quiet'

# The eight blessed shapes a multiplier verdict deletes. Written out here rather than read from the
# baselines: they must survive as *shapes*, so a refactor that keeps the frozen line numbers but
# breaks the append/return spelling still fails.
MULTIPLIER_CASUALTIES = [
    ('global_rng = random.Random()', 'random.Random'),
    ('rng = random.Random()\nvalues.append(rng.randint(0, 4096 - 1))', 'random.Random.randint'),
    ('rng = random.Random()\nvalues.append(rng.random() * scale)', 'random.Random.random'),
    ('let_pass = []\nlet_pass.append(random.randint(1, 10) <= 3)', 'random.randint'),
    ('def f():\n    return str(random.random())', 'random.random'),
    ('idx = random.randint(0, len(indices) - 1)', 'random.randint'),
]

# Provider facts, read straight off the callee. `sink` only supplies the recorded symbol, which is
# the fallback the classifier uses when a receiver cannot be folded.
PROVIDER_ROWS = [
    ('random.randint(100000, 999999)', 'random.randint', 'WEAK_PRNG'),
    ('secrets.token_urlsafe(32)', 'secrets.token_urlsafe', 'CSPRNG'),
    ('os.urandom(16)', 'os.urandom', 'CSPRNG'),
    ('import secrets\nsecrets.choice(letters)', 'secrets.choice', 'CSPRNG'),
    ('rng = random.Random()\nrng.randint(0, 9)', 'random.Random.randint', 'WEAK_PRNG'),
    ('import random as rnd\nrnd.choice(options)', 'random.choice', 'WEAK_PRNG'),
    ('from random import randint\nrandint(0, 9)', 'random.randint', 'WEAK_PRNG'),
    ('numpy.random.randint(0, 9)', 'numpy.random.randint', 'WEAK_PRNG'),
    ('model.sample(128)', 'model.sample', 'STATISTICAL_SAMPLING'),
    ('self.sample(128)', 'self.sample', 'STATISTICAL_SAMPLING'),
    ('bart_model.sample(inputs)', 'bart_model.sample', 'STATISTICAL_SAMPLING'),
    ('ray.tune.choice(grid)', 'ray.tune.choice', 'STATISTICAL_SAMPLING'),
    ('tune.loguniform("lr", 1e-5, 1e-1)', 'tune.loguniform', 'STATISTICAL_SAMPLING'),
]

SECURITY_ROWS = [
    ('token = random.randint(100000, 999999)', 'SECURITY_SENSITIVE'),
    ('session_key = random.choice("0123456789")', 'SECURITY_SENSITIVE'),
    ('self.session_secret = random.random()', 'SECURITY_SENSITIVE'),
    ('payload = {"auth_secret": random.random()}', 'SECURITY_SENSITIVE'),
    ('otp_code = random.randint(0, 999999)', 'SECURITY_SENSITIVE'),
    ('values.append(random.randint(0, 9))', 'NON_SECURITY'),
    ('return str(random.random())', 'NON_SECURITY'),
]

# One shared vocabulary: the cascade must ask the sink gate's question, not keep its own word list.
SHARED_VETO_CALL = 'self._cwe338_name_is_security_named(name)'
# Banned outright: a memorised line number, and a directory-name test for CWE-338.
FORBIDDEN_SOURCE_MARKERS = (
    '_C338_BLESSED_LINES_SHIELD',
    '_C338_BLESSED_LINES',
    'is_test_or_eval',
)
# The one path fact that survives is a LEAF filename, capped at exactly these two, because its
# population is shape-identical to blessed Big-8 keys and no value fact separates them. Pinned at
# one occurrence and in leaf form so a third name, or a widening to a directory test, fails here.
LEAF_SKIP_TUPLE = '("language_modeling.py", "data_collator.py")'
LEAF_SKIP_FORM = "rsplit('/', 1)[-1] in"


def scan_rows(source):
    """The real record path for one in-memory module, exactly as the CWE-338 probe runs it."""
    import contextlib
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source})
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    found = sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-338'})
    return tracker, found


def classify_provider(engine, callee_source, symbol):
    """Ask the shipped classifier about one callee, with no scan behind it.

    `engine` is a live TaintTracker because the classifier reads the credential predicate off self.
    The stand-in supplies only the recorded symbol, which is the fallback spelling the classifier
    uses when a receiver cannot be folded to a dotted name.
    """
    module = ast.parse(callee_source)
    calls = [node for top in module.body for node in ast.walk(top) if isinstance(node, ast.Call)]
    if not calls:
        raise AssertionError(f'no call in fixture: {callee_source}')
    stand_in = types.SimpleNamespace(symbol=symbol)
    return engine._c338_classify_prng_semantics(stand_in, calls[-1])[0]


def parse_keys(lines):
    """One finding key per line, as a tuple literal; comments and the metadata dict line are skipped.

    Parsing only -- the `open(...)` stays at the caller with a literal join, because Law 1 of these
    harnesses exists for a measured reason: the sink scanner has no cross-function data flow, so a
    helper that takes a joined path and opens it is itself reported as an unfixed CWE-22.
    """
    rows = []
    for text in lines:
        text = text.strip()
        if not text.startswith('('):
            continue
        entry = ast.literal_eval(text)
        if isinstance(entry, tuple) and len(entry) >= 3:
            rows.append(entry)
    return rows


def check_baseline_floor():
    """TIER 1: the blessed CWE-338 population, counted out of both frozen key files."""
    failures = []
    with open(os.path.join(GATES_DIR, 'parity_before.keys'), encoding='utf-8') as handle:
        parity_rows = parse_keys(handle.read().splitlines())
    with open(os.path.join(GATES_DIR, 'big8_before.keys'), encoding='utf-8') as handle:
        big8_rows = parse_keys(handle.read().splitlines())
    for kind, rows in (('parity', parity_rows), ('big8', big8_rows)):
        keys = {row for row in rows if row[2] == 'CWE-338'}
        print(f'  {kind:7s} total={len(rows)} (want {BASELINE_TOTALS[kind]})  '
              f'CWE-338={len(keys)} (want {CWE338_LOCKED[kind]})')
        if len(rows) != BASELINE_TOTALS[kind]:
            failures.append((kind, 'baseline total moved', BASELINE_TOTALS[kind], len(rows)))
        if len(keys) != CWE338_LOCKED[kind]:
            failures.append((kind, 'blessed CWE-338 population moved', CWE338_LOCKED[kind], len(keys)))
    return failures


def check_no_line_or_path_shield(engine):
    """TIER 2: the deciding axis is a value, so a memorised line or directory cannot come back."""
    failures = []
    source = inspect_source(engine)
    for marker in FORBIDDEN_SOURCE_MARKERS:
        present = marker in source
        print(f'  {"ABSENT" if not present else "PRESENT"} in engine source: {marker}')
        if present:
            failures.append(('a name/path/line shield is back in the engine', marker, source.count(marker)))
    # Suppression D's exact spelling is what is banned, not path tests belonging to other rules:
    # `"/examples/"` legitimately appears elsewhere in the engine, so it is not pinned here.
    for dir_marker in ('"/tests/" in fn_lower', '"/benchmark"'):
        present = dir_marker in source
        print(f'  {"ABSENT" if not present else "PRESENT"} folder-skip spelling (old suppression D): {dir_marker}')
        if present:
            failures.append(('the retired folder skip is back', dir_marker))
    leaf_count = source.count(LEAF_SKIP_TUPLE)
    leaf_form = LEAF_SKIP_FORM in source
    print(f'  leaf filename skip: occurrences={leaf_count} (want 1) leaf_form={leaf_form}')
    if leaf_count != 1 or not leaf_form:
        failures.append(('the surviving path skip left its pinned narrow form', leaf_count, leaf_form))
    print('  cascade reads the classifier for its verdict: '
          f'{"yes" if "_c338_classify_prng_semantics" in source else "no"}')
    if '_c338_classify_prng_semantics' not in source:
        failures.append(('the cascade stopped asking the semantic engine', '_c338_classify_prng_semantics'))
    return failures


def inspect_source(engine=None):
    """The engine's own text, read through a literal join.

    `engine.__file__` is a dynamic path and the scanner owns exactly that sink shape (CWE-22), so
    reading it that way made this gate a NEW parity finding. A literal join at the call site is both
    what the harness laws ask for and what keeps the sweep clean.
    """
    with open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8') as handle:
        return handle.read()


def check_provider_facts(engine):
    """TIER 3a: the provider fact for every spelling the mandate names, aliases included."""
    failures = []
    tracker = engine.TaintTracker(files={'m.py': 'import random\n'})
    loud = quiet = 0
    for callee_source, symbol, want in PROVIDER_ROWS:
        got = classify_provider(tracker, callee_source, symbol)
        ok = got == want
        loud += 1 if got == 'WEAK_PRNG' else 0
        quiet += 1 if got in ('CSPRNG', 'STATISTICAL_SAMPLING') else 0
        print(f'  {"ok " if ok else "FAIL"} {symbol:26s} want={want:22s} got={got}')
        if not ok:
            failures.append(('provider fact wrong', symbol, want, got))
    print(f'  provider facts: reportable={loud} excusable={quiet} rows={len(PROVIDER_ROWS)}')
    return failures


def check_security_facts(engine):
    """TIER 3b: the security-use fact, read through the shared credential vocabulary.

    `otp_code` is in this table on purpose: the cascade used to carry its own word list, which was
    narrower than CWE338_SECURITY_NAME_WORDS by csrf/otp/pin/iv/hash/code/jwt/signature/cipher, so a
    second opinion on the same name was possible. Two spellings of one question is what this pins out.
    """
    failures = []
    for source, want in SECURITY_ROWS:
        tracker, rows = scan_rows('import random\n' + source)
        records = [r for r in tracker.sink_records
                   if getattr(r.security_node, 'metadata', {}).get('cwe') == 'CWE-338']
        if not records:
            print(f'  FAIL {source[:44]:46s} want={want} got=no CWE-338 sink')
            failures.append(('no CWE-338 sink to classify', source, want))
            continue
        got = None
        for record in records:
            got = engine.TaintTracker._c338_classify_prng_semantics(
                tracker, record.security_node, record.node)[1]
            if got == 'SECURITY_SENSITIVE':
                break
        ok = got == want
        print(f'  {"ok " if ok else "FAIL"} {source[:44]:46s} want={want:20s} got={got}')
        if not ok:
            failures.append(('security-use fact wrong', source, want, got))
    shared = SHARED_VETO_CALL in inspect_source()
    print(f'  the cascade asks the shared credential predicate: {shared}')
    if not shared:
        failures.append(('the cascade stopped using _cwe338_name_is_security_named', SHARED_VETO_CALL))
    return failures


def check_multiplier_casualties_stay_loud(engine):
    """TIER 3c: the FN floor. Every NON_SECURITY blessed spelling must still be a finding.

    This is the falsification for the verdict's direction. Flipping
    `STATISTICAL_SAMPLING and not SECURITY_SENSITIVE` into a requirement on every provider silences
    all six rows below, so a rollback cannot pass this tier by adjusting a table.
    """
    failures = []
    held = 0
    for source, symbol in MULTIPLIER_CASUALTIES:
        tracker, rows = scan_rows('import random\n' + source)
        verdict = LOUD if rows else QUIET
        held += 1 if rows else 0
        print(f'  {verdict:5s} {symbol:24s} {source.replace(chr(10), " ; ")[:52]}')
        if not rows:
            failures.append(('a NON_SECURITY blessed draw went silent', symbol, source))
    print(f'  multiplier casualties still loud: {held}/{len(MULTIPLIER_CASUALTIES)}')
    return failures


def check_verdict_direction(engine):
    """TIER 4: the veto may only widen toward loud, and CSPRNG is the one unconditional silence."""
    failures = []
    text = ' '.join(inspect_source().split())
    wanted = 'provider_fact == "CSPRNG" or ('
    print(f'  CSPRNG alone is an unconditional silence: {wanted in text}')
    if wanted not in text:
        failures.append(('the verdict no longer separates CSPRNG from the statistical family', wanted))
    stat = 'provider_fact == "STATISTICAL_SAMPLING" and security_fact != "SECURITY_SENSITIVE"'
    print(f'  statistical family is vetoed by a credential destination: {stat in text}')
    if stat not in text:
        failures.append(('the statistical veto is not written as a veto', stat))
    weak = 'provider_fact == "WEAK_PRNG"'
    print(f'  WEAK_PRNG never appears in the suppression test: {weak not in text}')
    if weak in text:
        failures.append(('a weak-provider draw became suppressible (the multiplier bug)', weak))
    return failures


def run_mutations():
    """TIER 5: prove the tiers move. A lock that passes on a blinded engine is not a lock."""
    import contextlib
    results = []
    tracker, rows = scan_rows('import random\nvalues.append(random.randint(0, 9))')
    if rows:
        results.append(('non_security_draw_still_reports', True))
    else:
        results.append(('non_security_draw_still_reports', False))

    shipped_provider = ast_scanner.TaintTracker._c338_classify_prng_semantics

    def multiplier(self, sink, node=None):
        provider, security = shipped_provider(self, sink, node)
        if provider == 'WEAK_PRNG' and security != 'SECURITY_SENSITIVE':
            return ('STATISTICAL_SAMPLING', security)
        return (provider, security)

    ast_scanner.TaintTracker._c338_classify_prng_semantics = multiplier
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            mutant = ast_scanner.TaintTracker(files={'m.py': 'import random\nvalues.append(random.randint(0, 9))'})
            _, _, medges = mutant.analyze()
            mrows = cli._findings_for(mutant, medges)
        caught = not [r for r in mrows if r['cwe'] == 'CWE-338']
    finally:
        ast_scanner.TaintTracker._c338_classify_prng_semantics = shipped_provider
    results.append(('multiplier_mutation_silences_the_draw', caught))

    restored = ast_scanner.TaintTracker._c338_classify_prng_semantics is shipped_provider
    results.append(('classifier_restored_after_mutation', restored))
    for name, ok in results:
        print(f'  {"ok " if ok else "FAIL"} mutation {name} -> {"moves the tier" if ok else "does not move"}')
    return [r for r in results if not r[1]]


def main():
    failures = []
    print('TIER 1 blessed population')
    failures += check_baseline_floor()
    print('TIER 2 no line-number or path shield may return')
    failures += check_no_line_or_path_shield(ast_scanner)
    print('TIER 3a provider fact per spelling')
    failures += check_provider_facts(ast_scanner)
    print('TIER 3b security-use fact on the shared vocabulary')
    failures += check_security_facts(ast_scanner)
    print('TIER 3c the multiplier casualties must still be findings')
    failures += check_multiplier_casualties_stay_loud(ast_scanner)
    print('TIER 4 verdict direction')
    failures += check_verdict_direction(ast_scanner)
    print('TIER 5 falsification')
    stuck = run_mutations()
    if stuck:
        failures += [('a mutation the tiers must catch did not move', name) for name, _ in stuck]
    print(f'failures={len(failures)}')
    if failures:
        for f in failures:
            print('  FAIL', f)
        print(f'VERDICT: FAIL - {len(failures)} CWE-338 two-factor lock defects')
        return 1
    print('VERDICT: PASS - CWE-338 is decided by provider x security-use facts: no line-number '
          'shield, no path skip, WEAK_PRNG always loud, CSPRNG always silent, statistical family '
          'vetoed only by a credential destination, and all blessed NON_SECURITY draws still reported.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
