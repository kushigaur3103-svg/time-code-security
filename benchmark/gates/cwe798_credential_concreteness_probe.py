"""Fail-loud lock on CWE-798: what keeps `PASSWORD = "password"` silent on the gate path, and the file-type scope that closed the same shape on the product path.

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

**Path B - the product path (`secret_scanner.py`, reached from `app.py:2217` and `tcs_cli.py:513`,
never from `cli.py`) - DID reproduce, from a regex, and that is what this seal closed.** The rule
`hashicorp-tf-password` (`master_rules_bank.py:232`) is Terraform/HCL-shaped - `<name ending in
password>` `=` `"` `<8..20 chars>` `"` - and its value class is case-folded by `(?i)`, so before the
scope it matched Python assignments:

    PASSWORD = "password"        -> (1, 'hashicorp-tf-password')     FALSE POSITIVE
    class AuthMode(Enum): PASSWORD = "password"        -> (5, 'hashicorp-tf-password')  FALSE POSITIVE
    class AuthMode(str, Enum): PASSWORD = "password"   -> (5, 'hashicorp-tf-password')  FALSE POSITIVE
    PASSWORD = "PASSWORD"        -> (1, 'hashicorp-tf-password')     FALSE POSITIVE
    PASSWORD = "change_me_please" -> (1, 'hashicorp-tf-password')    FALSE POSITIVE (its own placeholder)
    PASSWORD = 'password'        -> silent                (single quotes: the rule needs double)

`secret_scanner.py:839-842` *did* already skip self-referential names ("enum members like
`PASSWORD = \"password\"`", shipped in `34c9d81`), but that guard is inside the
`hardcoded_credential_variable` detector, so it could not suppress a finding raised by a different
detector over the same line. The quote-dependence above is the proof that it was a spelling test.

**The shipped fix is a file-type scope, not a rule change.** `_gitleaks_detectors_for(filename)`
(`secret_scanner.py`, next to `_GITLEAKS_DETECTORS`) drops `_HCL_SCOPED_GITLEAKS_RULES` =
`{'hashicorp-tf-password'}` when the file is Python (`.py`, `.pyi`, `.pyw`, `.pyz`), and returns the
whole bank untouched for anything else. It is resolved once per file, above the line loop, so no line
pays an extra test. `master_rules_bank.py` is untouched: the bank is vendored rule data, and *where a
rule may run* is scanner policy.

**Why a Python deny-list and not the ".tf/.tfvars only" allow-list the request named - measured,
because an allow-list is a false negative.** `scratch/_hcl_scope_measure.py` runs a 30-case matrix
(shape x filename) through both paths; the diff before vs after the fix is exactly ten rows and no
more:

    5 false-positive rows      -> silent on path B and still silent on path A   (sessions.py / auth.py x2 / settings.py / const.py)
    4 handover rows            -> 1:hashicorp-tf-password became 1:hardcoded_credential_variable, same line,
                                  path A CWE-798 unchanged                     (hunter2secret, SuperSecret123, gui.pyw, app.pyz)
    1 Python row               -> `db_password = "Test-Value-1234"` keeps only the path A CWE-798 at line 1, because
                                  the dummy regex at `secret_scanner.py:808` calls the value a placeholder
    11 non-Python rows         -> byte-equal before and after, 219/219 bank rules still offered

The reason an allow-list was refused is those last eleven rows: on `values.yaml`, `config.json` and
`main.go` the HCL rule is the *only* detector that fires at all - the AST credential pass is skipped
for the config extensions (`secret_scanner.py:804`) and cannot parse Go - so "run only on .tf/.tfvars"
would have deleted real credential detections. TIER 5 asserts those files still fire.

**Why no true positive is anywhere near this.** `parity_before.keys` blesses exactly 6 CWE-798 keys and
`big8_before.keys` blesses 0; TIER 1 re-counts both and asserts that **no baseline row** carries a
`secret_scanner` detector name, which is what makes a path-B change FN-safe *for the gates* - and also
what makes it unverifiable by them, which is why this probe asserts path B directly. TIER 2 re-scans
the 12 `benchmark/corpus/cwe_798_hardcoded/` fixtures with per-file line-set equality, so the 6 blessed
true positives and the 6 good variants are pinned at the emitter, not in a comment. All 6 keep their
path A CWE-798 finding after the scope, and 3 of them additionally keep a path B finding via
`hardcoded_credential_variable`.

Tiers: TIER 1 - the blessed CWE-798 population of both baselines plus "zero baseline rows come from
path B". TIER 2 - the 12 CWE-798 corpus fixtures re-scanned in memory, line sets equal to the blessed
lines (bad) and empty (good). TIER 3 - path A: must-exempt weak/enum shapes silent, must-report concrete
shapes present, and both halves of the storage-key suppression at `:10185` (same literal, read vs
unread) pinned. TIER 4 - path B: the enum guard of `hardcoded_credential_variable`, the five closed
false positives asserted **silent**, the quote asymmetry asserted on `main.tf`, and the concrete values
that must stay flagged by the AST detector. TIER 5 - the scope itself: one real credential per Python
suffix must lose the HCL rule and *keep* a finding on both paths, the bank must be 219/219 rules for
non-Python names, and 9 HCL/config/Go/env/txt/no-extension/stdin detections must still fire.

Falsification, all seven measured with `scratch/_falsify_798.py` - it exec's this file in a private
namespace with `__file__` pointed at the tracked path and mutates the engine/scanner singletons in
memory, so no tracked file is edited and the unmodified baseline still exits 0:

    phase-9 credential layer disabled                  exit=1  FAIL selfref_module_level want=silent got=[1]
    storage-key proof always true                      exit=1  FAIL test_v01_bad.py lines=[] want=[1]   (all 6 blessed TPs vanish)
    hashicorp-tf-password rule neutered                exit=1  FAIL tf_password_line main.tf got=[(1, hardcoded_credential_variable)]
    hashicorp-tf-password broadened to single quotes   exit=1  FAIL selfref_single_quote want=silent got=[(1, hashicorp-tf-password)]
    HCL rule dropped for every file (removal)          exit=1  FAIL main.tf bank rules offered=218/219
    Python scope reverted                              exit=1  FAIL selfref_double_quote want=silent got=[(1, hashicorp-tf-password)]
    HCL allow-list instead of Python deny-list         exit=1  FAIL yaml_credential values.yaml got=silent

Row 2 is the path-A zero-FN proof: the cheapest way to "fix the enum false positive" - make
`_c798_value_is_storage_key` answer "yes" - deletes all 6 blessed CWE-798 true positives at once, and
the corpus tier fails on the fixture bytes before any baseline can be re-blessed around it. Rows 5 and
7 are the path-B zero-FN proof: the fix may scope the rule, never shrink the bank. Row 4 also records a
tier that had to be re-keyed - with the quote-asymmetry rows on a `.py` filename, the broadening
mutation measured exit=0 (unfalsifiable), because the scoped rule does not execute on Python at all;
moving the rows to `main.tf` is what made them bite.
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

PATTERN_ENUM_SEAL = 'shipped'   # HCL bank rules are scoped away from Python by _gitleaks_detectors_for()

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

# The five path-B false positives this seal closes. Each was measured flagged by `hashicorp-tf-password`
# before the scope landed (same shapes, same `.py` filenames) and is now measured silent on both paths.
PATTERN_FALSE_POSITIVES = [
    ('selfref_double_quote', 'PASSWORD = "password"\n', 1),
    ('enum_double_quote', ENUM_HEAD + 'class AuthMode(Enum):\n    PASSWORD = "password"\n', 5),
    ('strenum_double_quote', ENUM_HEAD + 'class AuthMode(str, Enum):\n    PASSWORD = "password"\n', 5),
    ('placeholder_double_quote', 'PASSWORD = "change_me_please"\n', 1),
    ('upper_selfref_double_quote', 'PASSWORD = "PASSWORD"\n', 1),
]

# Quote asymmetry: the HCL rule requires double quotes, which is what proves it is a spelling test.
# Asserted on a `.tf` filename, not a Python one - after the scope the rule does not execute on `.py`,
# so a Python filename would make this row unfalsifiable (measured: broadening the rule to single
# quotes passed the whole probe while the tier was keyed on `.py`).
PATTERN_QUOTE_ASYMMETRY = [
    ('selfref_single_quote', "PASSWORD = 'password'\n"),
    ('enum_single_quote', ENUM_HEAD + "class AuthMode(Enum):\n    PASSWORD = 'password'\n"),
]
PATTERN_QUOTE_ASYMMETRY_FILE = 'main.tf'

# Concrete credentials in Python: after the scope, the AST detector carries them. Measured as a
# handover on the same line (1:hashicorp-tf-password -> 1:hardcoded_credential_variable), never as a
# deletion, and path A still reports CWE-798 on every one of them (TIER 3).
PATTERN_TRUE_POSITIVES = [
    ('pattern_concrete_password', 'PASSWORD = "SuperSecret123"\nprint(PASSWORD)\n', 'hardcoded_credential_variable'),
    ('pattern_concrete_api_key', 'API_KEY = "live_token_abc"\nprint(API_KEY)\n', 'hardcoded_credential_variable'),
    ('pattern_blessed_hunter2', 'password = "hunter2secret"\nprint(password)\n', 'hardcoded_credential_variable'),
    ('pattern_env_read', 'import os\n\nAPI_KEY = os.environ.get("API_KEY")\n', None),
]

# The zero-false-negative half of this seal. The scope is a Python deny-list, not a
# ".tf/.tfvars only" allow-list, because on these files `hashicorp-tf-password` is the ONLY detector
# that fires: the AST credential pass at the foot of `scan_text` is skipped for the config extensions
# (`secret_scanner.py:804`) and cannot parse Go at all. Measured before and after the fix, byte-equal.
HCL_STILL_RUNS = [
    ('tf_password_line', 'main.tf', 'password = "hunter2secret"\n', 1),
    ('tfvars_admin_login', 'terraform.tfvars', 'administrator_login_password = "Abc12345xyz"\n', 1),
    ('yaml_credential', 'values.yaml', 'db_password: "SuperSecretValue1"\n', 1),
    ('json_credential', 'config.json', '{"password": "SuperSecretValue1"}\n', 1),
    ('go_credential', 'main.go', 'const dbPassword = "SuperSecretValue1"\n', 1),
    ('env_credential', '.env', 'password="SuperSecretValue1"\n', 1),
    ('txt_credential', 'notes.txt', 'password = "SuperSecretValue1"\n', 1),
    ('no_extension', 'Dockerfile', 'password = "SuperSecretValue1"\n', 1),
    ('stdin_default', '<string>', 'password = "SuperSecretValue1"\n', 1),
]

# Every Python spelling the deny-list covers, one real credential line each: the rule must be gone and
# the AST detector must be there, so scoping cannot become silencing.
PYTHON_SUFFIXES = ['sessions.py', 'stub.pyi', 'gui.pyw', 'app.pyz']


def scan_ast(label, source):
    """Path A: one in-memory module through the real record path, as both baselines are built."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={f'{label}.py': source})
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted(row['line'] for row in rows if row['cwe'] == 'CWE-798')


def scan_patterns(label, source, filename=None):
    """Path B: the product scanner, filtered to the credential detectors named above."""
    with contextlib.redirect_stderr(io.StringIO()):
        findings = secret_scanner.scan_text(source, filename or f'{label}.py')
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
        hits = scan_patterns(label, source, PATTERN_QUOTE_ASYMMETRY_FILE)
        print(f'  {"ok  " if not hits else "FAIL"} {label:24s} want=silent  got={hits}')
        if hits:
            failures.append((label, 'silent', hits,
                             'the HCL rule now matches single-quoted values too - its false-positive '
                             'surface grew, on every file type that still runs it'))
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


def check_python_scope():
    """TIER 5: the scope is a scope, not a mute - Terraform keeps its rule and Python keeps a finding."""
    failures = []
    source = 'password = "hunter2secret"\nprint(password)\n'
    for filename in PYTHON_SUFFIXES:
        hits = scan_patterns('python_scoped', source, filename)
        by_hcl = [hit for hit in hits if hit[1] == 'hashicorp-tf-password']
        carried = any(hit[1] == 'hardcoded_credential_variable' for hit in hits)
        engine_lines = scan_ast('python_scoped', source)
        ok = not by_hcl and carried and engine_lines == [1]
        print(f'  {"ok  " if ok else "FAIL"} {filename:24s} hcl_rule={by_hcl or "absent"} '
              f'ast_detector={carried} path_a={engine_lines or "silent"}')
        if not ok:
            failures.append((filename, 'HCL rule absent + hardcoded_credential_variable present + CWE-798 at 1',
                             (by_hcl, carried, engine_lines),
                             'scoping the HCL rule off Python removed the finding instead of the false '
                             'positive - a real credential would now be missed'))
    full = secret_scanner._GITLEAKS_DETECTORS
    for filename in ('main.tf', 'terraform.tfvars', 'values.yaml', 'config.json', 'Dockerfile', '<string>'):
        active = secret_scanner._gitleaks_detectors_for(filename)
        ok = len(active) == len(full)
        print(f'  {"ok  " if ok else "FAIL"} {filename:24s} bank rules offered={len(active)}/{len(full)}')
        if not ok:
            failures.append((filename, f'{len(full)} rules', f'{len(active)} rules',
                             'the deny-list grew into an allow-list: this file lost bank rules it never '
                             'had a Python-semantics excuse to lose'))
    for label, filename, source, line in HCL_STILL_RUNS:
        hits = scan_patterns(label, source, filename)
        ok = (line, 'hashicorp-tf-password') in hits
        print(f'  {"ok  " if ok else "FAIL"} {label:24s} {filename:18s} '
              f'want=({line}, hashicorp-tf-password)  got={hits or "silent"}')
        if not ok:
            failures.append((label, filename, f'({line}, hashicorp-tf-password)', hits or 'silent',
                             'the rule no longer fires on a real HCL/config file - the fix became a '
                             'removal, and on these files nothing else detects this line'))
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
    print('TIER 5 - the Python deny-list scoped the rule away without removing the finding:')
    failures += check_python_scope()
    print(f'\nseal={PATTERN_ENUM_SEAL} locked_cwe798={sum(CWE798_LOCKED.values())} '
          f'fixtures={len(FIXTURE_LINES)} must_exempt={len(MUST_EXEMPT)} must_report={len(MUST_REPORT)} '
          f'storage_key={len(STORAGE_KEY_PAIR)} path_b_fp={len(PATTERN_FALSE_POSITIVES)} '
          f'hcl_locks={len(HCL_STILL_RUNS)} py_suffixes={len(PYTHON_SUFFIXES)} '
          f'failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-798 credential layer no longer matches its evidence. Restoring '
              'the finding is the fix; re-blessing a baseline is not.')
        return 1
    print('VERDICT: PASS - 6 blessed CWE-798 keys held, 12 fixtures exact-set, 6 weak/enum shapes silent '
          'and 8 concrete shapes reported on path A, 5 path-B false positives closed on Python while '
          f'{len(HCL_STILL_RUNS)} HCL/config/Go/stdin detections still fire.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
