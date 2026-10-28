"""Fail-loud lock on CWE-798: what keeps `PASSWORD = "password"` silent, and on which path it is still a false positive.

    python benchmark/gates/cwe798_credential_concreteness_probe.py

The reported defect was: "`PASSWORD = \"password\"` inside an Enum/constant class in `sessions.py` is
flagged as a hardcoded secret". Measured on the engine on disk, that claim splits in two, and the two
halves are not the same scanner:

**Path A - the gate path (`ast_scanner.py` + `cli._findings_for`, which is what both frozen baselines
are made of): does NOT reproduce.** All four enum/self-referential shapes are silent, and every
must-report shape reports:

    PASSWORD = "password"                          -> silent   (class AuthMode(Enum) / (str, Enum): silent too)
    PASSWORD = "PASSWORD"                          -> silent
    PASSWORD = "SuperSecret123"       + print      -> CWE-798 at line 1
    class Cfg(Enum): PASSWORD = "SuperSecret123"   -> CWE-798 at line 5
    API_KEY = "live_token_abc"        + print      -> CWE-798 at line 1

The reason is *not* Enum awareness and *not* a name-equals-literal check. `ast_scanner.py` has no Enum
awareness at all (`grep -n "Enum" ast_scanner.py` yields only its own four class definitions at
`:35 :40 :45 :155`) and no `var_name == value` guard. What silences those lines is a concreteness test
inside `_collect_phase9_structural_findings` (`:22171`): `_credential_is_concrete` (`:22247`) demands
`entropy >= 3.0` plus at least two character classes (`:22277`), and when it fails the collector calls
`_remove_existing(node, "CWE-798", mod_name)` (`:22378`) on whatever the batch-2 emitter (`:10318`)
already recorded. `password` measures 2.5 bits - below the floor - so it never reaches a baseline.
That is a *general* weak-literal suppression, so it also keeps `SECRET_KEY = "secret_key"` and
`PASSWORD = "PASSWORD"` silent, and it is why a concrete enum member is still a true positive.

**Path B - the product path (`secret_scanner.py`, reached from `app.py`, `tcs_cli.py`, `tcs_gui.py`,
never from `cli.py`): DOES reproduce**, and the emitter is a regex, not an AST rule. The rule
`hashicorp-tf-password` (`master_rules_bank.py:232`) is Terraform/HCL-shaped - `<name ending in
password>` `=` `"` `<8..20 chars>` `"` - and its character class is case-folded by `(?i)`, so it
matches Python assignments:

    PASSWORD = "password"        -> (1, 'hashicorp-tf-password')     FALSE POSITIVE
    class AuthMode(Enum): PASSWORD = "password"        -> (5, 'hashicorp-tf-password')  FALSE POSITIVE
    class AuthMode(str, Enum): PASSWORD = "password"   -> (5, 'hashicorp-tf-password')  FALSE POSITIVE
    PASSWORD = 'password'        -> silent                (single quotes: the rule needs double)
    PASSWORD = "change_me_please" -> (1, 'hashicorp-tf-password')  FALSE POSITIVE (its own placeholder)

`secret_scanner.py:839-842` *does* skip self-referential names ("enum members like
`PASSWORD = \"password\"`", shipped in `34c9d81`), but that guard is inside the
`hardcoded_credential_variable` detector, so it cannot suppress a finding raised by a different
detector over the same line. The quote-dependence above is the proof that this is a spelling test.

**Why no true positive is anywhere near this.** `parity_before.keys` blesses exactly 6 CWE-798 keys and
`big8_before.keys` blesses 0; TIER 1 re-counts both and asserts that **no baseline row** carries a
`secret_scanner` detector name, which is what makes a path-B rule change FN-safe *for the gates* - and
also what makes it unverifiable by them, which is why this probe asserts path B directly. TIER 2
re-scans the 12 `benchmark/corpus/cwe_798_hardcoded/` fixtures with per-file line-set equality, so the
6 blessed true positives and the 6 good variants are pinned at the emitter, not in a comment.

**No engine file was modified to produce this page.** `PATTERN_ENUM_SEAL` stays `'abstained'`: the fix
belongs in `secret_scanner.py` / `master_rules_bank.py`, both of which are outside the gate-blessed
surface and outside what this repository commits from the secret-scanner side. While abstained, TIER 4
asserts the false positives are *still there* - a rule that quietly changed shape (broadening to single
quotes, or a fix nobody documented) fails here first. When the fix lands, flip the flag and the tier
turns those same rows into silence assertions, with the must-report rows unchanged.

Tiers: TIER 1 - the blessed CWE-798 population of both baselines plus "zero baseline rows come from
path B". TIER 2 - the 12 CWE-798 corpus fixtures re-scanned in memory, line sets equal to the blessed
lines (bad) and empty (good). TIER 3 - path A: must-exempt weak/enum shapes silent, must-report concrete
shapes present, and both halves of the storage-key suppression at `:10185` (same literal, read vs
unread) pinned. TIER 4 - path B: the enum guard of `hardcoded_credential_variable`, the four live
`hashicorp-tf-password` false positives, the quote asymmetry, and the concrete values that must stay
flagged.

Falsification, all four measured with `scratch/_falsify_798.py` - it exec's this file in a private
namespace with `__file__` pointed at the tracked path and mutates the engine/scanner singletons in
memory, so no tracked file is edited and the baseline run still exits 0:

    phase-9 credential layer disabled              exit=1  FAIL selfref_module_level want=silent got=[1]
    storage-key proof always true                  exit=1  FAIL test_v01_bad.py lines=[] want=[1]   (all 6 blessed TPs vanish)
    hashicorp-tf-password rule neutered            exit=1  FAIL selfref_double_quote want=(1, hashicorp-tf-password) got=silent
    hashicorp-tf-password broadened to 1 quotes    exit=1  FAIL selfref_single_quote want=silent got=[(1, hashicorp-tf-password)]

The second row is the zero-FN proof of this file: the cheapest way to "fix the enum false positive" -
make `_c798_value_is_storage_key` answer "yes" - deletes all 6 blessed CWE-798 true positives at once,
and the corpus tier fails on the fixture bytes before any baseline can be re-blessed around it.
"""
from __future__ import annotations

import contextlib
import io
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

import ast_scanner  # noqa: E402
import cli  # noqa: E402
import secret_scanner  # noqa: E402
from gate_common import META, load_keys  # noqa: E402

PATTERN_ENUM_SEAL = 'abstained'   # 'shipped' only when secret_scanner stops matching Python assignments

CWE_MESSAGE = 'CWE-798: HARDCODED_CREDENTIAL'
CORPUS_SUBDIR = os.path.join('corpus', 'cwe_798_hardcoded')

CWE798_LOCKED = {'parity': 6, 'big8': 0}
BLESSED_798 = {
    'parity': [
        ('test_v01_bad.py', 1), ('test_v02_bad.py', 1), ('test_v03_bad.py', 1), ('test_v04_bad.py', 3),
        ('test_v05_bad.py', 1), ('test_v06_bad.py', 1),
    ],
    'big8': [],
}
# Corpus fixture -> the CWE-798 line set blessed for it. `[]` rows are the good variants.
FIXTURE_LINES = {
    'test_v01_bad.py': [1], 'test_v01_good.py': [],
    'test_v02_bad.py': [1], 'test_v02_good.py': [],
    'test_v03_bad.py': [1], 'test_v03_good.py': [],
    'test_v04_bad.py': [3], 'test_v04_good.py': [],
    'test_v05_bad.py': [1], 'test_v05_good.py': [],
    'test_v06_bad.py': [1], 'test_v06_good.py': [],
}

ENUM_HEAD = 'from enum import Enum\n\n\n'

# Path A: silent because `_credential_is_concrete` (`ast_scanner.py:22247`) rejects the literal, not
# because anyone recognised an Enum. Each row was measured silent on the engine on disk.
MUST_EXEMPT = [
    ('selfref_module_level', 'PASSWORD = "password"\nprint(PASSWORD)\n'),
    ('selfref_upper_name', 'PASSWORD = "PASSWORD"\nprint(PASSWORD)\n'),
    ('selfref_lowercase', 'password = "password"\nprint(password)\n'),
    ('enum_member', ENUM_HEAD + 'class AuthMode(Enum):\n    PASSWORD = "password"\n\n\nprint(AuthMode.PASSWORD.value)\n'),
    ('strenum_member', ENUM_HEAD + 'class AuthMode(str, Enum):\n    PASSWORD = "password"\n\n\nprint(AuthMode.PASSWORD.value)\n'),
    ('enum_secret_key', ENUM_HEAD + 'class AuthMode(str, Enum):\n    SECRET_KEY = "secret_key"\n'),
]

# Path A: the TP surface. The last three rows are replicas of blessed fixtures, so this tier and TIER 2
# cannot disagree without one of them failing.
MUST_REPORT = [
    ('concrete_password', 'PASSWORD = "SuperSecret123"\nprint(PASSWORD)\n', [1]),
    ('concrete_api_key', 'API_KEY = "live_token_abc"\nprint(API_KEY)\n', [1]),
    ('enum_concrete_member', ENUM_HEAD + 'class Cfg(Enum):\n    PASSWORD = "SuperSecret123"\n'
     '\n\nprint(Cfg.PASSWORD.value)\n', [5]),
    ('admin_password_read', 'password = "admin_password"\nconnect(password)\n', [1]),
    ('mixed_class_password', 'PASSWORD = "Admin#Passw0rd!"\nprint(PASSWORD)\n', [1]),
    ('replica_v01_bad', 'password = "hunter2secret"\nprint(password)\n', [1]),
    ('replica_v04_bad', 'class Client:\n    def __init__(self):\n        self.access_token = '
     '"eyJhbGciOiJIUzI1NiJ9"\n', [3]),
    ('replica_v06_bad', 'passwd = "correcthorsebatterystaple"\nprint(passwd)\n', [1]),
]

# Both halves of `_c798_value_is_storage_key` (`ast_scanner.py:10185`): one literal, two files. The
# unread name is a mapping key, the read name is a value handed to something - so the pair is asserted
# together and neither half may move alone.
STORAGE_KEY_PAIR = [
    ('field_path_unread', 'API_KEY = "live_token_abc"\n', []),
    ('field_path_read', 'API_KEY = "live_token_abc"\nprint(API_KEY)\n', [1]),
]

# Path B: `secret_scanner` detectors this probe cares about, by name, so a rename shows up as a
# missing row instead of a silently empty tier.
CRED_DETECTORS = ('hashicorp-tf-password', 'hardcoded_credential_variable')

# The guard shipped in 34c9d81 (`secret_scanner.py:839-842`): asserted so a refactor cannot drop it and
# make the self-referential shape report twice over.
PATTERN_ENUM_GUARD = [
    ('guard_selfref', 'PASSWORD = "password"\n'),
    ('guard_lowercase', 'password = "password"\n'),
]

# Live path-B false positives, measured on the engine on disk. Asserted *present* while abstained.
PATTERN_FALSE_POSITIVES = [
    ('selfref_double_quote', 'PASSWORD = "password"\n', 1),
    ('enum_double_quote', ENUM_HEAD + 'class AuthMode(Enum):\n    PASSWORD = "password"\n', 5),
    ('strenum_double_quote', ENUM_HEAD + 'class AuthMode(str, Enum):\n    PASSWORD = "password"\n', 5),
    ('placeholder_double_quote', 'PASSWORD = "change_me_please"\n', 1),
]

# Quote asymmetry: the HCL rule requires double quotes, which is what proves it is a spelling test.
PATTERN_QUOTE_ASYMMETRY = [
    ('selfref_single_quote', "PASSWORD = 'password'\n"),
    ('enum_single_quote', ENUM_HEAD + "class AuthMode(Enum):\n    PASSWORD = 'password'\n"),
]

PATTERN_TRUE_POSITIVES = [
    ('pattern_concrete_password', 'PASSWORD = "SuperSecret123"\nprint(PASSWORD)\n', 'hashicorp-tf-password'),
    ('pattern_concrete_api_key', 'API_KEY = "live_token_abc"\nprint(API_KEY)\n', 'hardcoded_credential_variable'),
    ('pattern_env_read', 'import os\n\nAPI_KEY = os.environ.get("API_KEY")\n', None),
]


def scan_ast(label, source):
    """Path A: one in-memory module through the real record path, as both baselines are built."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={f'{label}.py': source})
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted(row['line'] for row in rows if row['cwe'] == 'CWE-798')


def scan_patterns(label, source):
    """Path B: the product scanner, filtered to the credential detectors named above."""
    with contextlib.redirect_stderr(io.StringIO()):
        findings = secret_scanner.scan_text(source, f'{label}.py')
    return sorted({(f.line_number, f.detector) for f in findings if (f.detector or '') in CRED_DETECTORS})


def fixture_source(name):
    path = os.path.abspath(os.path.join(ROOT, 'benchmark', CORPUS_SUBDIR, name))
    with open(path, encoding='utf-8', errors='replace') as handle:
        return handle.read()


def check_floors():
    """TIER 1: the blessed CWE-798 population, and the fact that none of it comes from path B."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {(os.path.basename(str(row[0])), row[1]) for row in rows if row[2] == 'CWE-798'}
        from_path_b = [row for row in rows
                       if any(detector in str(row[4]) for detector in CRED_DETECTORS)]
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-798={len(keys)} (want {CWE798_LOCKED[kind]})  '
              f'rows carrying a secret_scanner detector={len(from_path_b)} (want 0)')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != CWE798_LOCKED[kind]:
            failures.append((kind, 'CWE-798', CWE798_LOCKED[kind], len(keys),
                             'the blessed CWE-798 population moved'))
        absent = sorted(f'{leaf}:{line}' for leaf, line in BLESSED_798[kind] if (leaf, line) not in keys)
        if absent:
            failures.append((kind, 'blessed keys', len(BLESSED_798[kind]),
                             len(BLESSED_798[kind]) - len(absent), absent,
                             'a named blessed CWE-798 key is gone - nothing may be re-blessed'))
        if from_path_b:
            failures.append((kind, 'path-B rows', 0, len(from_path_b),
                             'a baseline now blesses a secret_scanner detector: TIER 4 is no longer '
                             'the only lock on that path'))
    return failures


def check_fixtures():
    """TIER 2: the 12 CWE-798 corpus fixtures, re-scanned in memory, per-file line-set equality."""
    failures = []
    for name, want in sorted(FIXTURE_LINES.items()):
        lines = scan_ast(name[:-3], fixture_source(name))
        ok = lines == sorted(want)
        print(f'  {"ok  " if ok else "FAIL"} {name:20s} CWE-798 lines={lines or "[]"} want={sorted(want) or "[]"}')
        if not ok:
            failures.append((name, sorted(want), lines,
                             'a blessed CWE-798 fixture moved - the concrete/storage-key layer changed '
                             'what the baseline holds'))
    return failures


def check_path_a():
    """TIER 3: the enum/self-referential claim, measured on the gate path."""
    failures = []
    for label, source in MUST_EXEMPT:
        lines = scan_ast(label, source)
        print(f'  {"ok  " if not lines else "FAIL"} {label:24s} want=silent  got={lines or "silent"}')
        if lines:
            failures.append((label, 'silent', lines,
                             'a weak/self-referential literal is reported as a hardcoded credential - '
                             'the `_credential_is_concrete` floor moved (ast_scanner.py:22247)'))
    for label, source, want in MUST_REPORT:
        lines = scan_ast(label, source)
        ok = lines == want
        print(f'  {"ok  " if ok else "FAIL"} {label:24s} want={want}  got={lines or "silent"}')
        if not ok:
            failures.append((label, want, lines,
                             'a true-positive credential shape went silent on the gate path - zero-FN '
                             'violation, stop and restore it'))
    for label, source, want in STORAGE_KEY_PAIR:
        lines = scan_ast(label, source)
        ok = lines == want
        print(f'  {"ok  " if ok else "FAIL"} {label:24s} want={want or "silent"}  got={lines or "silent"}')
        if not ok:
            failures.append((label, want, lines,
                             'the storage-key pair diverged (ast_scanner.py:10185): one half moved, so '
                             'the "is this name ever read" proof is no longer what it was measured to be'))
    return failures


def check_path_b():
    """TIER 4: the product path, where the reported false positive actually lives."""
    failures = []
    for label, source in PATTERN_ENUM_GUARD:
        hits = [hit for hit in scan_patterns(label, source) if hit[1] == 'hardcoded_credential_variable']
        print(f'  {"ok  " if not hits else "FAIL"} {label:24s} hardcoded_credential_variable={hits or "silent"}')
        if hits:
            failures.append((label, 'silent', hits,
                             'the self-referential guard of secret_scanner.py:839-842 is gone'))
    flagged = []
    want_silent = PATTERN_ENUM_SEAL == 'shipped'
    for label, source, line in PATTERN_FALSE_POSITIVES:
        hits = scan_patterns(label, source)
        is_fp = (line, 'hashicorp-tf-password') in hits
        ok = (not is_fp) if want_silent else is_fp
        want = 'silent' if want_silent else f'({line}, hashicorp-tf-password)'
        print(f'  {"ok  " if ok else "FAIL"} {label:24s} want={want:34s} got={hits or "silent"}')
        if want_silent:
            if is_fp:
                failures.append((label, 'silent', hits, 'a documented path-B false positive is back'))
        elif not is_fp:
            flagged.append(label)
    if flagged:
        failures.append(('PATTERN_ENUM_SEAL', 'abstained', f'all {len(PATTERN_FALSE_POSITIVES)} still flagged',
                         f'{len(PATTERN_FALSE_POSITIVES) - len(flagged)} still flagged', flagged,
                         'the hashicorp-tf-password rule changed shape while this tier says it has not: '
                         're-measure, and if the false positives are gone flip PATTERN_ENUM_SEAL to '
                         "'shipped' rather than deleting these rows"))
    for label, source in PATTERN_QUOTE_ASYMMETRY:
        hits = scan_patterns(label, source)
        print(f'  {"ok  " if not hits else "FAIL"} {label:24s} want=silent  got={hits}')
        if hits:
            failures.append((label, 'silent', hits,
                             'the HCL rule now matches single-quoted Python too - its false-positive '
                             'surface grew on the path this probe says is not blessed anywhere'))
    for row in PATTERN_TRUE_POSITIVES:
        label, source, want = row
        hits = scan_patterns(label, source)
        if want is None:
            ok = not hits
            print(f'  {"ok  " if ok else "FAIL"} {label:26s} want=silent  got={hits or "silent"}')
            if not ok:
                failures.append((label, 'silent', hits, 'an env-var read is now flagged as a credential'))
            continue
        ok = any(detector == want for _, detector in hits)
        print(f'  {"ok  " if ok else "FAIL"} {label:26s} want={want}  got={hits or "silent"}')
        if not ok:
            failures.append((label, want, hits,
                             'a concrete credential went silent on the product path - a real missed finding'))
    return failures


def main() -> int:
    print('TIER 1 - blessed CWE-798 floors, and who owns each detector:')
    failures = check_floors()
    print('TIER 2 - the 12 cwe_798_hardcoded fixtures scanned live:')
    failures += check_fixtures()
    print('TIER 3 - path A (ast_scanner + cli, the baselines):')
    failures += check_path_a()
    print('TIER 4 - path B (secret_scanner pattern rules, app/tcs_cli/tcs_gui):')
    failures += check_path_b()
    print(f'\nseal={PATTERN_ENUM_SEAL} locked_cwe798={sum(CWE798_LOCKED.values())} '
          f'fixtures={len(FIXTURE_LINES)} must_exempt={len(MUST_EXEMPT)} must_report={len(MUST_REPORT)} '
          f'storage_key={len(STORAGE_KEY_PAIR)} path_b_fp={len(PATTERN_FALSE_POSITIVES)} '
          f'failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-798 credential layer no longer matches its evidence. Restoring '
              'the finding is the fix; re-blessing a baseline is not.')
        return 1
    print('VERDICT: PASS - 6 blessed CWE-798 keys held, 12 fixtures exact-set, 6 weak/enum shapes '
          'silent and 8 concrete shapes reported on path A, path B measured as documented.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
