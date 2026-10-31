"""CWE-798 truth table: which hardcoded literal declares itself a fixture, and which one is a key.

Why this gate exists
--------------------
The mandate asked for a "high-speed dummy/mock credential filter for string literals in tests/ and
fixtures", with the extra rule that assignments to variables named `dummy_*`, `mock_*`, `fake_*` and
`test_sample_*` be exempt. Measured on the recorded LiteLLM baseline, the two rules that read the
*value or the name* reach a small part of the population and the part that reads the *directory* is
not reachable at all:

  * 593 CWE-798 rows exist; 591 of them already sit under a tests/-fixture-looking path, so a path
    test says nothing the engine is not already sure of;
  * reading the source line behind every one of those 593 rows, 69 carry a value or a target the
    shipped prefix/name rules accept and 40 more carry the same shape but are stopped by the
    credential fence (`sk-test-key-456`, `test-api-key-12345`, `FAKE_OAUTH_TOKEN =
    "sk-ant-oat01-fake-...-123456789abcdef"`) -- so the fence, not the prefix, is what keeps the
    population honest;
  * a path-based exemption was refused, and the numbers that refuse it are in AGENTS.md: 6 of 6
    blessed parity CWE-798 keys, 14 of 15 blessed CWE-78 keys and 6 of 8 / 11 of 16 blessed CWE-22
    keys live in a `test_`/`tests/` module. A directory rule would have deleted blessed true
    positives, which the Zero-FN Shield forbids at any price.

What the rule proves, and only that
-----------------------------------
`_is_cwe798_dummy_string(value, target_name)` (ast_scanner.py:1861) answers True on three passes, in
this order, and the order is the safety property:

  1. an *exact* member of `CWE798_EXAMPLE_SECRET_VALUES` -- the strings AWS and OpenAI publish in
     their own documentation. Equality is the proof, so `AKIAIOSFODNN7EXAMPLE` can be silenced even
     though it carries the `akia` fingerprint, while a real AKIA with different bytes cannot;
  2. the placeholder shapes this module has always recognised (the blessed `CWE798_DUMMY_STRINGS`
     table, a value whose own characters repeat, `<your-...-here>`);
  3. a fixture *declaration*: the value starts with `dummy-`/`mock_`/`fake-`/`example-`/`test-` (or
     `sk-dummy`, `api_test-`, `secret-mock` and friends), or the assignment target starts with
     `dummy_`/`mock_`/`fake_`/`test_sample_` -- and only after `TaintTracker._c798_fingerprinted`
     (ast_scanner.py:11590) has said the literal carries neither a secret shape (`sk-`, `sk_live`,
     `AKIA`, `gh[pousr]_`, `eyJ`, `-----BEGIN`, `ya29.`, `AIza`, `xox[baprs]-`) nor a run of four
     digits. The digit run is not overridden on purpose: `test-api-key-12345` is a fixture that
     *looks* like a key, and the mandate's "real random high-entropy strings stay LOUD" is answered
     by the fence rather than by the prefix.

Anchored, not substring: `^(?:dummy|mock|fake|example|test)[-_]` cannot match inside
`my-mock-token-value` and `asmocktokenvalue`, so a value that merely contains a marker word is still
a credential. `test_` is deliberately *not* in the target table (only `test_sample_`), because
`test_api_key` is the name a pytest fixture gives to a value that came from a vault.

Measured evidence behind the numbers
------------------------------------
  blessed overlap   : CWE-798 keys -- 6 in parity, 0 in Big-8 (TIER 1). TIER 5 reads all six blessed
                      lines back, takes the literal and the target name the emitter used, and asks
                      this predicate: it answers dummy on 0 of them, and the same ask answers True on
                      the 11 fixture rows the guard silences, so the zero is a refusal.
  fixtures          : 34 shapes, every one measured against 697a58e and against this engine --
                      11 loud->quiet rows the rule earns, 16 must-report rows and 7 quiet at both
                      seals (already silent at HEAD: `aws_example_access_key_id`, `mock_named_secret`,
                      `test_sample_named_password`, `real_akia_with_digits`, `real_ghp_token`,
                      `sk_shape_after_dummy_prefix`, `mock_impostor_word` -- listed as ALREADY_QUIET,
                      never as wins). ADDED (quiet->loud) is 0.
  LiteLLM census    : 593 CWE-798 rows; 69 text-reachable by the shipped value/name rules, 40 stopped
                      by the fence (`scratch/_fx798_line_bucket.py`). The engine-level A/B is reported
                      with the commit.

Seal semantics - `CWE798_FIXTURE_SEAL`
--------------------------------------
  'shipped'   : the declared-fixture rows MUST be silent and every credential-shaped row MUST stay
                loud.
  'abstained' : the engine before this rule landed -- every row that is not already quiet MUST be
                loud. A row that goes quiet while the seal says abstained means an exemption landed
                without a contract.
Override with TCS_CWE798_FIXTURE_SEAL=abstained and point TCS_CWE798_FIXTURE_ENGINE at an alternative
ast_scanner.py. This file locks the fixture-declaration axis only; the nameplate, storage-key and
enum axes belong to `cwe798_credential_concreteness_probe.py`.
"""
from __future__ import annotations

import ast
import contextlib
import inspect
import io as _io
import os
import re
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

if os.environ.get('TCS_CWE798_FIXTURE_ENGINE'):
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        'ast_scanner', os.environ['TCS_CWE798_FIXTURE_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys, scan_rows  # noqa: E402

SEAL_TARGETS = ('abstained', 'shipped')
CWE798_FIXTURE_SEAL = os.environ.get('TCS_CWE798_FIXTURE_SEAL', 'shipped')

# The blessed CWE-798 population, counted from the frozen baselines themselves.
CWE798_LOCKED = {'parity': 6, 'big8': 0}

# (label, source, expect_when_abstained, expect_when_shipped)
# 'loud' = a CWE-798 finding is required in that module, 'quiet' = none is allowed.
SHAPES = [
    # ---- a literal that declares itself a fixture, or is a vendor's own published example ----
    ('aws_example_secret_key', 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
                               'print(AWS_SECRET_ACCESS_KEY)\n', 'loud', 'quiet'),
    ('sts_example_secret', 'SECRET_KEY = "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"\n'
                           'print(SECRET_KEY)\n', 'loud', 'quiet'),
    ('aws_example_access_key_id', 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
                                  'print(AWS_ACCESS_KEY_ID)\n', 'quiet', 'quiet'),
    ('test_prefixed_api_key', 'api_key = "test-api-key"\nprint(api_key)\n', 'loud', 'quiet'),
    ('test_prefixed_password', 'password = "test-password"\nprint(password)\n', 'loud', 'quiet'),
    ('test_prefixed_underscore', 'api_key = "test_proxy_key"\nprint(api_key)\n', 'loud', 'quiet'),
    ('uppercase_test_prefix', 'API_KEY = "TEST-KEY-ABC"\nprint(API_KEY)\n', 'loud', 'quiet'),
    ('mock_prefixed_secret', 'secret_key = "mock-secret-key"\nprint(secret_key)\n', 'loud', 'quiet'),
    ('example_prefixed_api_key', 'api_key = "example-api-key"\nprint(api_key)\n', 'loud', 'quiet'),
    ('fake_prefixed_access_token', 'access_token = "fake-access-token"\nprint(access_token)\n',
     'loud', 'quiet'),
    ('dummy_named_target', 'dummy_api_key = "abc123def456"\nprint(dummy_api_key)\n', 'loud', 'quiet'),
    ('fake_named_auth_token', 'fake_auth_token = "qwe123rty456"\nprint(fake_auth_token)\n',
     'loud', 'quiet'),
    ('mock_named_secret', 'mock_client_secret = "abcdefghij"\nprint(mock_client_secret)\n',
     'quiet', 'quiet'),
    ('test_sample_named_password', 'test_sample_password = "abcdefghij"\n'
                                   'print(test_sample_password)\n', 'quiet', 'quiet'),
    # ---- tripwires: a name cannot outrun a fingerprint, and a prefix cannot outrun a digit run ----
    ('blessed_hunter2', 'password = "hunter2secret"\nprint(password)\n', 'loud', 'loud'),
    ('blessed_sk_live', 'api_key = "sk_live_51abcdef"\nprint(api_key)\n', 'loud', 'loud'),
    ('blessed_supersecret', 'config.secret_key = "supersecret123"\nprint(config.secret_key)\n',
     'loud', 'loud'),
    ('blessed_eyj', 'self.access_token = "eyJhbGciOiJIUzI1NiJ9"\nprint(self.access_token)\n',
     'loud', 'loud'),
    ('blessed_mysecretkey', 'secret_key: str = "mysecretkey123"\nprint(secret_key)\n', 'loud', 'loud'),
    ('blessed_correcthorse', 'passwd = "correcthorsebatterystaple"\nprint(passwd)\n', 'loud', 'loud'),
    ('digit_run_after_test_prefix', 'api_key = "test-api-key-12345"\nprint(api_key)\n',
     'loud', 'loud'),
    ('example_prefixed_with_digits', 'api_key = "example-key-0001"\nprint(api_key)\n', 'loud', 'loud'),
    ('digit_run_after_mock_prefix', 'auth_token = "mock-bearer-token-67890"\n'
                                    'print(auth_token)\n', 'loud', 'loud'),
    ('marker_not_at_start', 'api_key = "my-mock-token-value"\nprint(api_key)\n', 'loud', 'loud'),
    ('mock_impostor_word', 'api_key = "asmocktokenvalue"\nprint(api_key)\n', 'quiet', 'quiet'),
    ('dummy_named_real_value', 'dummy_api_key = "sk_live_51HxQabcdef"\nprint(dummy_api_key)\n',
     'loud', 'loud'),
    ('test_named_real_jwt', 'test_access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOi"\n'
                            'print(test_access_token)\n', 'loud', 'loud'),
    ('jwt_shaped_dummy', 'api_key = "fake.eyJhbGciOiJIUzI1NiJ9.sig"\nprint(api_key)\n',
     'loud', 'loud'),
    ('ya29_after_test_prefix', 'access_token = "test-ya29.a0AfH6SMB"\nprint(access_token)\n',
     'loud', 'loud'),
    ('test_named_plain_value', 'test_api_key = "abc123def456"\nprint(test_api_key)\n',
     'loud', 'loud'),
    ('migration_id_named_secret', 'API_KEY_INDEX_MIGRATION = "20260823000000_add_spend_logs"\n'
                                  'print(API_KEY_INDEX_MIGRATION)\n', 'loud', 'loud'),
    ('sk_shape_after_dummy_prefix', 'api_key = "dummy-sk-live-9f3a"\nprint(api_key)\n',
     'quiet', 'quiet'),
    ('real_akia_with_digits', 'aws_access_key_id = "AkiaI44F792EXAMPLE01"\n'
                              'print(aws_access_key_id)\n', 'quiet', 'quiet'),
    ('real_ghp_token', 'github_token = "ghp_aBcDeFgHiJkLmNoPqRsT1234567890"\n'
                       'print(github_token)\n', 'quiet', 'quiet'),
]

FP_ROWS = [row for row in SHAPES if row[2] == 'loud' and row[3] == 'quiet']
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == 'loud']
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == 'quiet']
_BY_LABEL = {row[0]: row[1] for row in SHAPES}

# One axis per row, arms on opposite sides of it. Every clean arm is measured loud on 697a58e's bytes
# and quiet here, so a pair cannot agree just because both arms went silent for another reason.
PAIRS = [
    ('a vendor example vs a fixture prefix over a real Google token', 'aws_example_secret_key',
     'ya29_after_test_prefix'),
    ('fixture word at the front vs fixture word inside the value', 'mock_prefixed_secret',
     'marker_not_at_start'),
    ('fixture prefix with no digits vs the same prefix plus a digit run', 'test_prefixed_api_key',
     'digit_run_after_test_prefix'),
    ('dummy-named value that is not a key vs dummy-named value that is', 'dummy_named_target',
     'dummy_named_real_value'),
    ('fake-prefixed JWT-less value vs fake-prefixed value holding a JWT', 'fake_prefixed_access_token',
     'jwt_shaped_dummy'),
]

# Value prefixes that must and must not declare a fixture. The `^` anchors are the whole rule, so the
# must-not-match arm is a spelling test, not a style preference.
VALUE_PREFIXES_REQUIRED = ('dummy-key', 'mock_token', 'fake-access-token', 'example-api-key',
                           'test-proxy-key', 'TEST-KEY-ABC', 'sk-dummy-x', 'api-mock-key',
                           'token_test_value', 'secret-fake', 'dummy_token_value')
VALUE_PREFIXES_FORBIDDEN = ('my-mock-token-value', 'asmocktokenvalue', 'not_a_fake_one',
                            'tested-key', 'example', 'mock', 'latest-key', 'bigtest-key',
                            'best_value')
NAME_PREFIXES_REQUIRED = ('dummy_api_key', 'mock_client_secret', 'fake_auth_token',
                          'test_sample_password')
# `test_` is the name a fixture gives to a value pulled from a vault, so it is refused by the target
# rule and only the value can declare itself a fixture.
NAME_PREFIXES_FORBIDDEN = ('test_api_key', 'test_access_token', 'example_key', 'password',
                           'API_KEY', 'secret_key', 'dummy')
EXAMPLE_VALUES_REQUIRED = ('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                           'je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY')
# Anything that is a credential shape *and* not one of the vendor's published strings must never be in
# the table: membership is the only reason the fingerprint fence is stepped over. The AKIA fixture is
# spelled `Akia...` on purpose -- the engine fence is case-insensitive, but a secret scanner's
# `AKIA[0-9A-Z]{16}` is not, so the tripwire stays load-bearing without looking like a live key.
EXAMPLE_VALUES_FORBIDDEN = ('AkiaI44F792EXAMPLE01', 'sk_live_51abcdef', 'hunter2secret',
                            'ghp_aBcDeFgHiJkLmNoPqRsT1234567890', 'eyJhbGciOiJIUzI1NiJ9')
FINGERPRINTED_EXAMPLES = ('sk_live_51HxQabcdef', 'AkiaI44F792EXAMPLE01', 'test-api-key-12345',
                          'eyJ0eXAiOiJKV1QiLCJhbGciOi', 'test-ya29.a0AfH6SMB')
NOT_FINGERPRINTED = ('test-api-key', 'hunter2secret', 'supersecret123', 'my-mock-token-value',
                     'correcthorsebatterystaple')


def scan_source(source):
    """One in-memory module through the real record path, as both baselines were built."""
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-798'})


def literal_and_target(source, lineno):
    """The (literal, target-name) pair the CWE-798 emitter reads at this line, by name or attribute."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.lineno == lineno:
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                for target in ([node.target] if isinstance(node, ast.AnnAssign) else node.targets):
                    if isinstance(target, ast.Name):
                        found.append((value.value, target.id))
                    elif isinstance(target, ast.Attribute):
                        found.append((value.value, target.attr))
    return found


def check_floors():
    """TIER 1: the blessed CWE-798 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-798'}
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-798={len(keys)} (want {CWE798_LOCKED[kind]})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != CWE798_LOCKED[kind]:
            failures.append((kind, 'CWE-798', CWE798_LOCKED[kind], len(keys),
                             'the blessed CWE-798 population moved'))
    return failures


def check_corpus():
    """TIER 2: the CWE-798 keys re-produced by a real tree scan, as an exact key set."""
    failures = []
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    live = {row for row in scan_rows('parity', tree) if row[2] == 'CWE-798'}
    frozen = {row for row in load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
              if row[2] == 'CWE-798'}
    missing = sorted(frozen - live)
    extra = sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    for row in missing:
        print(f'  MISSING  {row[0]}:{row[1]} {row[4]}')
    for row in extra:
        print(f'  NEW      {row[0]}:{row[1]} {row[4]}')
    if missing:
        failures.append((len(missing), 'frozen CWE-798 keys no longer reported'))
    if extra:
        failures.append((len(extra), 'CWE-798 keys appeared that the baseline never held'))
    return failures


def check_shapes():
    """TIER 3: the truth table, asserted against the seal this file is standing under."""
    failures = []
    for label, source, when_abstained, when_shipped in SHAPES:
        try:
            ast.parse(source)
        except SyntaxError as exc:
            print(f'  {label:30} UNPARSEABLE {type(exc).__name__}')
            failures.append((label, 'shape syntax', 'parses', type(exc).__name__))
            continue
        expected = when_abstained if CWE798_FIXTURE_SEAL == 'abstained' else when_shipped
        found = scan_source(source)
        status = 'loud' if found else 'quiet'
        note = '; '.join(f'L{n}' for n, _m in found)[:60]
        marker = 'ok' if status == expected else 'MISMATCH'
        print(f'  {label:30} want={expected:5s} got={status:5s} {marker:8s} {note}')
        if status != expected:
            failures.append((label, 'seal', expected, status,
                             'the answer moved without the seal, or the seal moved without the answer'))
    return failures


def check_pairs():
    """TIER 4: one axis, two arms, and both arms proven to be moved by this rule."""
    failures = []
    fp_labels = {row[0] for row in FP_ROWS}
    loud_labels = {row[0] for row in MUST_REPORT_ROWS}
    for label, clean, dirty in PAIRS:
        if clean not in fp_labels:
            failures.append((label, 'clean arm is a loud->quiet row (the rule moves it)', clean))
        if dirty not in loud_labels:
            failures.append((label, 'tripwire arm is a must-report row', dirty))
        a = bool(scan_source(_BY_LABEL[clean]))
        b = bool(scan_source(_BY_LABEL[dirty]))
        want_clean = CWE798_FIXTURE_SEAL == 'abstained'
        agree = (a == want_clean) and b
        print(f'  {label:56} clean_loud={a} (want {want_clean})  tripwire_loud={b} (want True)  '
              f'{"agree" if agree else "DISAGREE"}')
        if not agree:
            failures.append((label, 'pair provenance', (want_clean, True), (a, b)))
    return failures


def check_blessed_lines():
    """TIER 5: the 6 blessed parity CWE-798 lines, read back and asked about directly.

    A corpus re-scan shows a lost key after the fact. This asks the one question the exemption can
    answer -- does the predicate call itself "dummy" on a blessed literal -- so a widen that reaches a
    true positive fails here before a baseline moves. Big-8 holds 0 CWE-798 keys, which is exactly why
    this file exists: `MISSING=0` on that baseline could not notice the rule being deleted.
    """
    failures = []
    controls = [row[0] for row in FP_ROWS]
    hits = sum(1 for label in controls if any(
        ast_scanner._is_cwe798_dummy_string(value, name)
        for value, name in literal_and_target(_BY_LABEL[label], 1)))
    if hits != len(controls):
        failures.append(('control', 'the predicate must answer dummy on every retired fixture',
                         len(controls), hits))
    print(f'  control (retired fixtures the predicate must answer True on): {hits}/{len(controls)}')
    for kind in ('parity', 'big8'):
        rows = sorted((row for row in load_keys(
            os.path.join(GATES_DIR, META[kind]['keys_file']), kind) if row[2] == 'CWE-798'),
            key=lambda r: (str(r[0]), r[1]))
        asked = answered = fenced = 0
        for row in rows:
            relative = row[0]
            path = os.path.abspath(os.path.join(ROOT, str(relative)))
            if not os.path.exists(path):
                failures.append((row[0], 'blessed fixture file is not in the tree'))
                continue
            with open(path, encoding='utf-8', errors='replace') as handle:
                source = handle.read()
            pairs = literal_and_target(source, row[1])
            if not pairs:
                failures.append((row[0], row[1], 'no string assignment could be read at the '
                                                 'blessed line -- the ask would be vacuous'))
                continue
            for value, name in pairs:
                asked += 1
                if ast_scanner._is_cwe798_dummy_string(value, name):
                    answered += 1
                    print(f'  REACHABLE  {row[0]}:{row[1]}  {name} = {value[:40]!r}')
                if ast_scanner.TaintTracker._c798_fingerprinted(value):
                    fenced += 1
        print(f'  {kind:7s} blessed_lines={len(rows)}  predicate_asks={asked}  '
              f'answers_dummy={answered}  literals_fingerprinted={fenced}')
        if answered:
            failures.append((kind, 'a blessed CWE-798 line is reachable by the fixture rule',
                             0, answered))
        if rows and asked != len(rows):
            failures.append((kind, 'every blessed line must be asked at least once',
                             len(rows), asked))
    return failures


def check_vocabulary():
    """TIER 6: the three tables, the fence, the fence's position, and the wiring."""
    failures = []
    module = ast_scanner
    tracker = module.TaintTracker

    values = set(module.CWE798_EXAMPLE_SECRET_VALUES)
    absent = [text for text in EXAMPLE_VALUES_REQUIRED if text not in values]
    present = [text for text in EXAMPLE_VALUES_FORBIDDEN if text in values]
    unexplained = [text for text in values if 'EXAMPLE' not in text.upper()
                   and not text.lower().startswith(('sk-', 'pk-', 'api-'))]
    print(f'  example table      n={len(values):2}  absent_required={absent}  '
          f'present_forbidden={present}  unexplained={unexplained}')
    if absent or present or unexplained:
        failures.append(('example table', (EXAMPLE_VALUES_REQUIRED, EXAMPLE_VALUES_FORBIDDEN, 'shape'),
                         (absent, present, unexplained)))

    prefix_re = module.CWE798_DUMMY_VALUE_PREFIX_RE
    matched = [text for text in VALUE_PREFIXES_FORBIDDEN if prefix_re.match(text)]
    missed = [text for text in VALUE_PREFIXES_REQUIRED if not prefix_re.match(text)]
    print(f'  value prefix       matched_forbidden={matched}  missed_required={missed}')
    if matched or missed:
        failures.append(('value prefix', 'anchored only', (matched, missed)))

    name_re = module.CWE798_DUMMY_NAME_PREFIX_RE
    matched = [text for text in NAME_PREFIXES_FORBIDDEN if name_re.match(text)]
    missed = [text for text in NAME_PREFIXES_REQUIRED if not name_re.match(text)]
    print(f'  target name prefix matched_forbidden={matched}  missed_required={missed}')
    if matched or missed:
        failures.append(('target name prefix', 'dummy/mock/fake/test_sample only', (matched, missed)))

    fence = tracker._c798_fingerprinted
    bad = [text for text in FINGERPRINTED_EXAMPLES if not fence(text)]
    over = [text for text in NOT_FINGERPRINTED if fence(text)]
    print(f'  fingerprint fence  missed={bad}  overblocks={over}')
    if bad or over:
        failures.append(('fingerprint fence', 'secrets yes, plain words no', (bad, over)))
    for text in FINGERPRINTED_EXAMPLES:
        if module.CWE798_DUMMY_VALUE_PREFIX_RE.match(text) and module._is_cwe798_dummy_string(text):
            failures.append(('fence position', text, 'loud', 'silent',
                             'a fingerprinted value is only ever silenced by the example table'))

    body = inspect.getsource(module._is_cwe798_dummy_string)
    for fragment, why in (
            ('CWE798_EXAMPLE_SECRET_VALUES', 'the exact-example pass must read the table'),
            ('_c798_fingerprinted', 'the credential fence must run inside this predicate'),
            ('CWE798_DUMMY_VALUE_PREFIX_RE', 'the value declaration must read the table'),
            ('CWE798_DUMMY_NAME_PREFIX_RE', 'the target declaration must read the table'),
    ):
        if fragment not in body:
            failures.append(('predicate body', fragment, 'present', 'absent', why))
    fence_at = body.find('_c798_fingerprinted')
    prefix_at = body.find('CWE798_DUMMY_VALUE_PREFIX_RE')
    print(f'  fence before prefix match: {0 <= fence_at < prefix_at} '
          f'(fence={fence_at} prefix={prefix_at})')
    if not (0 <= fence_at < prefix_at):
        failures.append(('fence order', 'the credential fence must be tested first'))

    source = inspect.getsource(tracker)
    gate = source.split('def _collect_phase9_structural_findings', 1)
    asks = source.count('_is_cwe798_dummy_string(')
    concrete = len(re.findall(r'_credential_is_concrete\(cred_literal, cred_name\)',
                              gate[-1] if len(gate) > 1 else ''))
    print(f'  wiring: asks inside TaintTracker={asks} (want 2: registry + gatekeeper)  '
          f'gatekeeper passes the target name={concrete == 1}')
    if asks != 2 or concrete != 1:
        failures.append(('wiring', 'two asks, and the gatekeeper passes the target name',
                         (2, 1), (asks, concrete)))
    return failures


MUTATIONS = {
    'delete_fixture_rule': {
        'what': 'the predicate always answers "not a fixture" -- every retired row comes back',
        'rows': [row[0] for row in FP_ROWS],
        'apply': lambda: setattr(ast_scanner, '_is_cwe798_dummy_string',
                                 lambda value, target_name='': False),
    },
    'fixture_rule_always_true': {
        'what': 'the predicate answers "fixture" for every literal -- the widest version of what the '
                'prompt asked for, and the reason the credential fence exists',
        'rows': ['blessed_hunter2', 'blessed_sk_live', 'blessed_supersecret', 'blessed_eyj',
                 'blessed_mysecretkey', 'blessed_correcthorse', 'digit_run_after_test_prefix',
                 'dummy_named_real_value', 'test_named_real_jwt', 'ya29_after_test_prefix'],
        'apply': lambda: setattr(ast_scanner, '_is_cwe798_dummy_string',
                                 lambda value, target_name='': True),
    },
    'blank_example_table': {
        'what': 'empty the vendor-example table -- the two AWS example secrets come back as findings',
        'rows': ['aws_example_secret_key', 'sts_example_secret'],
        'apply': lambda: setattr(ast_scanner, 'CWE798_EXAMPLE_SECRET_VALUES', frozenset()),
    },
    'prefix_matches_anywhere': {
        'what': 'drop the `^` anchors, so `my-mock-token-value` and `asmocktokenvalue` read as '
                'fixtures -- a substring is not a declaration',
        'rows': ['marker_not_at_start', 'mock_impostor_word', 'blessed_mysecretkey'],
        'apply': lambda: setattr(ast_scanner, 'CWE798_DUMMY_VALUE_PREFIX_RE',
                                 re.compile(r'(?i)(dummy|mock|fake|example|test)[-_]')),
    },
    'drop_credential_fence': {
        'what': 'stop asking whether the literal carries secret bytes, so a `sk_live` value sitting '
                'behind a `dummy_` name is silenced',
        'rows': ['dummy_named_real_value', 'test_named_real_jwt', 'ya29_after_test_prefix',
                 'digit_run_after_test_prefix', 'digit_run_after_mock_prefix', 'jwt_shaped_dummy'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c798_fingerprinted',
                                 staticmethod(lambda value: False)),
    },
    'drop_digit_run_fence': {
        'what': 'keep the secret-shape fence but retire the four-digit test, so `test-api-key-12345` '
                'and `example-key-0001` become fixtures',
        'rows': ['digit_run_after_test_prefix', 'digit_run_after_mock_prefix',
                 'example_prefixed_with_digits', 'migration_id_named_secret'],
        'apply': lambda: setattr(ast_scanner, 'CWE798_LONG_DIGIT_RUN_RE', re.compile(r'(?!x)x')),
    },
    'name_rule_ignores_value_fence': {
        'what': 'test the prefix and name tables *before* the credential fence: the same shapes are '
                'accepted, in the unsafe order',
        'rows': ['dummy_named_real_value', 'test_named_real_jwt', 'ya29_after_test_prefix',
                 'digit_run_after_test_prefix', 'jwt_shaped_dummy'],
        'apply': lambda: setattr(
            ast_scanner, '_is_cwe798_dummy_string',
            lambda value, target_name='': bool(
                ast_scanner.CWE798_DUMMY_VALUE_PREFIX_RE.match(value)
                or (target_name and ast_scanner.CWE798_DUMMY_NAME_PREFIX_RE.match(target_name)))),
    },
    'widen_name_rule_to_any_test_prefix': {
        'what': 'put bare `test_` into the target table, which is the name a pytest fixture gives a '
                'vault-read value -- `test_api_key = "abc123def456"` goes silent',
        'rows': ['test_named_plain_value', 'test_named_real_jwt'],
        'apply': lambda: setattr(ast_scanner, 'CWE798_DUMMY_NAME_PREFIX_RE',
                                 re.compile(r'(?i)^(?:dummy|mock|fake|test)[_-]')),
    },
}


def run_mutation(name: str) -> int:
    """Apply one in-memory mutation and run the real gate over it. Exit 1 = the mutation was caught."""
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print(f"  rows that must move: {', '.join(spec['rows'])}")
    tiers = []
    # TIER 1 and 2 read the frozen baselines and re-scan the whole `benchmark/` tree; an in-memory
    # patch cannot move a blessed key the corpus does not hold, and running them here would make each
    # mutation cost a full tree scan. The truth table, the pairs, the blessed lines and the tables are
    # what a rule is falsified on.
    try:
        # Applying the patch is inside the try: a mutation anchor that no longer matches the shipped
        # code would otherwise leave a traceback whose exit code 1 reads exactly like a real catch.
        spec['apply']()
        print(f'TIER 3 - truth table under seal={CWE798_FIXTURE_SEAL!r}:')
        tiers.append(('T3', check_shapes()))
        print('TIER 4 - one axis, two arms, both moved by this rule:')
        tiers.append(('T4', check_pairs()))
        print('TIER 5 - the 6 blessed lines, asked about directly:')
        tiers.append(('T5', check_blessed_lines()))
        print('TIER 6 - example table, prefix tables, fence and wiring:')
        tiers.append(('T6', check_vocabulary()))
    except Exception as exc:  # a mutation that cannot even run is not a falsification
        print('MUTATION ERROR: ' + type(exc).__name__ + ': ' + str(exc))
        print('\nFALSIFICATION VERDICT (' + name + '): ERROR - the mutation is broken, '
              'so it proves nothing either way (exit 2, not a pass)')
        return 2
    failures = [item for _label, rows in tiers for item in rows]
    for item in failures[:12]:
        print(f'  !! {item}')
    caught = bool(failures)
    counts = ' '.join(f'{label}={len(rows)}' for label, rows in tiers if rows)
    print('FALSIFICATION VERDICT (' + name + '): '
          + (f'CAUGHT on {len(failures)} row(s) [{counts}] -- '
             + ', '.join(sorted({str(f[0]) for f in failures})[:6])
             if caught else 'MISSED - the rule is decorative, the engine still answers its own '
                            'truth table'))
    return 1 if caught else 0


def main() -> int:
    if CWE798_FIXTURE_SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {CWE798_FIXTURE_SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-798 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the corpus behind those keys, scanned live:')
    failures += check_corpus()
    print(f'TIER 3 - truth table under seal={CWE798_FIXTURE_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4 - one axis, two arms, both moved by this rule:')
    failures += check_pairs()
    print('TIER 5 - the 6 blessed lines, asked about directly:')
    failures += check_blessed_lines()
    print('TIER 6 - example table, prefix tables, fence and wiring:')
    failures += check_vocabulary()
    print(f'\nseal={CWE798_FIXTURE_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'pairs={len(PAIRS)} locked_cwe798={sum(CWE798_LOCKED.values())} '
          f'failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-798 fixture-declaration rule no longer matches its measured '
              'evidence. Restore the answer or update the seal with a re-measured truth table; never '
              're-bless a baseline -- all 6 blessed parity CWE-798 keys are plain-word secrets and '
              'the rule must stay blind to every one of them.')
        return 1
    print(f'VERDICT: PASS - all {sum(CWE798_LOCKED.values())} blessed CWE-798 keys still reported, '
          f'parity corpus exact-set, {len(FP_ROWS)} declared-fixture shapes silent, '
          f'{len(MUST_REPORT_ROWS)} fingerprinted/digit-run/substring shapes reported, '
          f'{len(PAIRS)} pairs agreeing.')
    return 0


if __name__ == '__main__':
    wanted = [a.split('=', 1)[1] for a in sys.argv[1:] if a.startswith('--mutate=')]
    if wanted:
        unknown = [w for w in wanted if w not in MUTATIONS]
        if unknown:
            print(f'BAD MUTATION: {unknown} is not one of {sorted(MUTATIONS)}')
            sys.exit(1)
        sys.exit(run_mutation(wanted[0]))
    sys.exit(main())
