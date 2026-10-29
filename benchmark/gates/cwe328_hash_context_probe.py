"""CWE-328 truth table: the weak-hash boundary, recorded so no narrowing can be guessed at later.

Why this gate exists
--------------------
CWE-328 `WEAK_HASH` is 23 of 2,128 findings on odoo/odoo@17.0. The 32 source files behind those rows
and the 15 CWE-704 rows were fetched to `scratch/_328_704/src` (odoo/odoo@17.0) and re-scanned with
the working engine at `b450f0a`. Split by what the digest is *for*:

    ~17  integrity checksum, cache key, protocol handshake, fixture, display id   -> noise
     ~5  password / API-signature / session-token material                        -> the finding
     1   undecidable at the line (`pos_hr/hr_employee.py:21` sha1(barcode), one line above the
         sha1(pin) that is unambiguously a credential)

Unlike every other rule retired so far, **this one has no blessed population to lean on**: 0 CWE-328
keys in parity (425) and 0 in Big-8 (119), counted from the frozen files themselves. A parity run
therefore cannot tell the difference between a careful narrowing and one that deletes the payment
signature checks - both show `MISSING=0`. That is precisely the shape of decision the Zero-FN Shield
forbids taking on inference, so this file records the boundary *before* anyone is tempted.

The emitter
-----------
  ast_scanner.py:22934-22942 (inside `_collect_phase8_structural_findings`, def :22497)
    * `weak_hash_sinks` (:22505-22508) = hashlib.md5 / sha1 / sha224, Crypto.Hash.MD5 / SHA1;
      `_names_for_call` (:22525-22530) also resolves `from hashlib import md5`, so the bare name
      matches.
    * the only guard is a statically `False` `usedforsecurity` keyword (:22935-22937), which then calls
      `_remove_existing` for CWE-328.
    * there is no use-context predicate at all: the engine never asks what happens to the digest.

Measured facts that decide the seal
-----------------------------------
  guard coverage                : `usedforsecurity` appears **0 times in all 32 fetched files**
                                  (`grep -c usedforsecurity scratch/_328_704/src/*` -> no matches), so
                                  the one narrowing the rule already supports has never fired on real
                                  Odoo. Any exemption keyed on it would be dead code.
  escape hatch (pre-existing)   : `hashlib.md5(secret, usedforsecurity=False)` is silent today. The
                                  flag says "not for security" and the engine believes it, so a
                                  password hash can be hidden by one keyword. Recorded below as a
                                  must-stay-silent row *and* as a standing risk: the honest fix is a
                                  credential-context check, not a wider suppression.
  what a real narrowing needs   : one hop of data flow past the call - "the digest is written to a
                                  checksum column / used as a dict key / handed to a protocol" versus
                                  "the digest is compared against a signature, stored as a token, or
                                  returned as an authentication material". Nothing in the current
                                  predicate sees that, so the seal below is the only lock that exists.
  two misses found while        : (1) `Crypto.Hash.MD5.new(payload)` is invisible to this rule.
  building this file               `_names_for_call` (:22528) yields the dotted callee and its
                                  canonical form - `MD5.new` -> `Crypto.Hash.MD5.new` - while
                                  `weak_hash_sinks` holds `Crypto.Hash.MD5` with no `.new`, and
                                  `MD5.new(...)` is the only way pycryptodome builds an MD5. Measured:
                                  the shape is quiet. Recorded in `KNOWN_FN_ROWS`, asserted quiet, and
                                  the gate turns `GAP-CLOSED` + exit 1 the day it starts reporting, so
                                  nobody can fix it without also re-measuring the contract.
                                  (2) `hashlib.new("md5", ...)` is likewise not a CWE-328 row; the
                                  CWE-327 sibling covers it, and that claim is asserted here too
                                  rather than assumed.

Seal semantics - `CWE328_SEAL`
------------------------------
  'locked' (today)  : every shape is loud except the strong digests and the `usedforsecurity=False`
                      case. If any row goes quiet while this file still says locked, a CWE-328
                      narrowing landed without re-measuring the boundary - exit 1.
  'narrowed'        : reserved. Moving here requires a new truth table over real code, the credential
                      rows proven loud, and the arena re-run. The 17 noise rows may go quiet; not one
                      credential row may.
Either way a mismatch is exit 1, and this gate never changes the engine.
"""
from __future__ import annotations

import ast
import contextlib
import io
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

if os.environ.get('TCS_CWE328_ENGINE'):
    # falsification hook: load an alternative ast_scanner.py and let the gate argue against it. Run
    # this file against an engine that suppresses CWE-328 by name, and the credential rows below go
    # quiet while the seal still says 'locked' - exit 1. The point of the hook is that a blind
    # narrowing cannot pass this file even though no frozen baseline would notice.
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        'ast_scanner', os.environ['TCS_CWE328_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys, scan_rows  # noqa: E402

CWE328_SEAL = 'locked'   # 'narrowed' = a proven use-context predicate has landed and is asserted here
SEAL_TARGETS = ('locked', 'narrowed')

# The blessed CWE-328 population, counted from the frozen baselines themselves. Zero is the reason
# this file exists: a baseline diff cannot protect a rule nobody blessed.
CWE328_LOCKED = {'parity': 0, 'big8': 0}

HASHLIB = 'import hashlib\n'
HASHLIB_FROM = 'from hashlib import md5, sha1\n'
CRYPTO = 'from Crypto.Hash import MD5\n'
ODOO_HTTP = 'import hashlib\nfrom odoo import http\n'


def wrap(header: str, body: str) -> str:
    return header + '\n\ndef handler(cr, uid, name):\n    ' + body.replace('\n', '\n    ') + '\n'


# (label, source, expect_when_locked, expect_when_narrowed)
# 'loud' = a CWE-328 finding is required on that module, 'quiet' = none is allowed.
SHAPES = [
    # ---- credential material: loud at both seals, forever ----
    ('md5_payload_plus_secret', wrap(HASHLIB, "return hashlib.md5((name + secret).encode()).hexdigest()"),
     'loud', 'loud'),
    ('sha1_payment_sign_string', wrap(HASHLIB, "sign_str = '&'.join(parts) + key\n"
                                              "return hashlib.sha1(sign_str.encode()).hexdigest()"),
     'loud', 'loud'),
    ('md5_api_key', wrap(HASHLIB, "return hashlib.md5(api_key.encode('utf-8')).hexdigest()"),
     'loud', 'loud'),
    ('md5_password_no_salt', wrap(HASHLIB, "return hashlib.md5(password.encode()).hexdigest()"),
     'loud', 'loud'),
    ('sha1_session_id', wrap(HASHLIB, "return hashlib.sha1(sid.encode('ascii')).hexdigest()"),
     'loud', 'loud'),
    ('sha1_pin_code', wrap(HASHLIB, "return hashlib.sha1(pin.encode()).hexdigest()"), 'loud', 'loud'),
    ('sha224_access_token', wrap(HASHLIB, "return hashlib.sha224(str(uid).encode()).hexdigest()"),
     'loud', 'loud'),
    ('sha1_from_import_bare', wrap(HASHLIB_FROM, "return sha1((name + secret).encode()).hexdigest()"),
     'loud', 'loud'),
    ('md5_from_import_bare', wrap(HASHLIB_FROM, "return md5(password.encode()).hexdigest()"),
     'loud', 'loud'),
    ('crypto_md5_signature', wrap(CRYPTO, "return MD5.new(payload + secret).hexdigest()"),
     'quiet', 'quiet'),
    ('crypto_sha1_signature', wrap('from Crypto.Hash import SHA1\n',
                                   "return SHA1.new(payload + secret).hexdigest()"),
     'quiet', 'quiet'),
    ('md5_of_secret_via_config', wrap(ODOO_HTTP, "secret = request.env['ir.config_parameter']"
                                                 ".sudo().get_param('payment_alipay.secret')\n"
                                                 "return hashlib.md5((name + secret).encode())"
                                                 ".hexdigest()"), 'loud', 'loud'),
    # ---- recorded non-crypto population: loud today, the only half a narrowing may silence ----
    ('sha1_filestore_checksum', wrap(HASHLIB, "return hashlib.sha1((dbname + '/' + path).encode())"
                                             ".hexdigest()"), 'loud', 'quiet'),
    ('sha1_websocket_handshake', wrap(HASHLIB, "GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'\n"
                                              "return hashlib.sha1((key + GUID).encode()).digest()"),
     'loud', 'quiet'),
    ('md5_gravatar_hash', wrap(HASHLIB, "return hashlib.md5(email.strip().lower().encode('utf-8'))"
                                        ".hexdigest()"), 'loud', 'quiet'),
    ('md5_cache_key', wrap(HASHLIB, "return hashlib.md5(repr(args).encode()).hexdigest()"),
     'loud', 'quiet'),
    ('md5_participant_identifier', wrap(HASHLIB_FROM, "return md5(edi_identification.lower()"
                                                     ".encode()).hexdigest()"), 'loud', 'quiet'),
    ('sha1_document_id', wrap(HASHLIB_FROM, "return f'Document-{sha1(data).hexdigest()}'"),
     'loud', 'quiet'),
    ('md5_test_fixture_digest', wrap(HASHLIB, "return hashlib.md5(b'fixture-payload').hexdigest()"),
     'loud', 'quiet'),
    ('sha1_dirent_index_key', wrap(HASHLIB, "return hashlib.sha1(relative_path.encode()).hexdigest()"
                                            ".replace('/', '_')"), 'loud', 'quiet'),
    # ---- already silent, and required to stay silent at both seals ----
    ('usedforsecurity_false', wrap(HASHLIB, "return hashlib.md5(payload, usedforsecurity=False)"
                                            ".hexdigest()"), 'quiet', 'quiet'),
    ('sha256_digest', wrap(HASHLIB, "return hashlib.sha256(payload).hexdigest()"), 'quiet', 'quiet'),
    ('blake2b_digest', wrap(HASHLIB, "return hashlib.blake2b(payload).hexdigest()"), 'quiet', 'quiet'),
    ('sha512_file_hash', wrap(HASHLIB, "return hashlib.sha512(data).hexdigest()"), 'quiet', 'quiet'),
    ('hashlib_new_md5_is_cwe327', wrap(HASHLIB, "return hashlib.new('md5', payload).hexdigest()"),
     'quiet', 'quiet'),
]

FP_ROWS = [row for row in SHAPES if row[2] == 'loud' and row[3] == 'quiet']
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == 'loud']
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == 'quiet']

# Shapes the engine does not report today and a security reviewer would expect it to. They are
# asserted quiet so this file stays green on the shipped engine, and they fail loudly the day the
# gap closes - which is the point: a miss that nobody wrote down is a miss nobody schedules.
KNOWN_FN_ROWS = {
    'crypto_md5_signature': 'MD5.new(...) resolves to Crypto.Hash.MD5.new, and weak_hash_sinks '
                            '(ast_scanner.py:22505-22508) holds "Crypto.Hash.MD5" without the .new '
                            'suffix, so pycryptodome hashing never matches. MD5.new is the only way '
                            'to build an MD5 in that library.',
    'crypto_sha1_signature': 'same suffix gap, SHA1 side.',
    'hashlib_new_md5_is_cwe327': 'hashlib.new("md5", ...) is a hashlib.new call, not hashlib.md5; '
                                 'it is covered by the CWE-327 sibling rule, so it is a spelling '
                                 'difference rather than a hole. Asserted here so the claim is '
                                 'measured, not assumed.',
}

# The same `hashlib.md5(<expr>).hexdigest()` call over a secret and over a filename. The engine cannot
# tell these apart, and that equality is the finding: until it can, no use-based exemption is admissible.
# The credential arm must be loud at every seal; the non-crypto arm follows the seal.
PAIRS = [
    ('secret digest vs filestore digest',
     wrap(HASHLIB, "return hashlib.md5((name + secret).encode()).hexdigest()"),
     wrap(HASHLIB, "return hashlib.md5((dbname + '/' + path).encode()).hexdigest()")),
    ('password sha1 vs protocol sha1',
     wrap(HASHLIB, "return hashlib.sha1(pin.encode()).hexdigest()"),
     wrap(HASHLIB, "GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'\n"
                   "return hashlib.sha1((key + GUID).encode()).digest()")),
    ('token sha1 vs cache-key sha1',
     wrap(HASHLIB, "return hashlib.sha1(sid.encode('ascii')).hexdigest()"),
     wrap(HASHLIB, "return hashlib.sha1(repr(args).encode()).hexdigest()")),
]


def scan_source(source):
    """One in-memory module through the real record path, as both baselines were built."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-328'})


def check_floors():
    """TIER 1: the blessed CWE-328 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-328'}
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-328={len(keys)} (want {CWE328_LOCKED[kind]})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != CWE328_LOCKED[kind]:
            failures.append((kind, 'CWE-328', CWE328_LOCKED[kind], len(keys),
                             'the blessed CWE-328 population moved'))
    return failures


def check_corpus():
    """TIER 2: the CWE-328 keys re-produced by a real tree scan, as an exact key set.

    0 on both sides today, so this tier is a tripwire: a narrowing that silences a fixture, or a new
    weak-hash call added to the harness tree, moves `live` away from `frozen` and fails here rather
    than in a future audit.
    """
    failures = []
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    live = {row for row in scan_rows('parity', tree) if row[2] == 'CWE-328'}
    frozen = {row for row in load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
              if row[2] == 'CWE-328'}
    missing = sorted(frozen - live)
    extra = sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    for row in extra:
        print(f'  NEW      {row[0]}:{row[1]} {row[4]}')
    if missing:
        failures.append((len(missing), 'frozen CWE-328 keys no longer reported'))
    if extra:
        failures.append((len(extra), 'CWE-328 keys appeared that the baseline never held'))
    return failures


def check_shapes():
    """TIER 3: the truth table, asserted against the seal the file is standing under."""
    failures = []
    for label, source, when_locked, when_narrowed in SHAPES:
        ast.parse(source)  # an unparseable shape would look "quiet" for the wrong reason
        expected = when_locked if CWE328_SEAL == 'locked' else when_narrowed
        found = scan_source(source)
        status = 'loud' if found else 'quiet'
        note = '; '.join(f'L{n}:{m.replace("CWE-328: ", "")}' for n, m in found)[:60]
        marker = 'ok' if status == expected else 'MISMATCH'
        if label in KNOWN_FN_ROWS and status == 'loud':
            marker = 'GAP-CLOSED'
            print(f'  {label:34s} want={expected:5s} got={status:5s} {marker:10s} '
                  f'{KNOWN_FN_ROWS[label]} Move this row into the credential block and re-measure.')
            failures.append((label, 'known gap closed without updating this contract'))
            continue
        print(f'  {label:34s} want={expected:5s} got={status:5s} {marker:8s} {note}')
        if status != expected:
            failures.append((label, 'seal', expected, status,
                             'the answer moved without the seal, or the seal moved without the answer'))
    return failures


def check_pairs():
    """TIER 4: identical call text, opposite purpose.

    This tier is what makes the seal mean something. At 'locked' both arms of every pair answer the
    same way and both are loud - so the day someone claims a use-context proof, the *only* honest
    evidence is a pair that finally splits. Until then the noise rows cannot be called FPs the engine
    is able to avoid, and the credential rows cannot be silenced.
    """
    failures = []
    for label, credential, noncrypto in PAIRS:
        a = bool(scan_source(credential))
        b = bool(scan_source(noncrypto))
        want_noncrypto = CWE328_SEAL == 'locked'
        agree = a and (b == want_noncrypto)
        print(f'  {label:34s} credential_loud={a} (want True)  noncrypto_loud={b} '
              f'(want {want_noncrypto})  {"agree" if agree else "DISAGREE"}')
        if not agree:
            failures.append((label, 'purpose arm', (True, want_noncrypto), (a, b)))
    return failures


def main() -> int:
    if CWE328_SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {CWE328_SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-328 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the corpus behind those keys, scanned live:')
    failures += check_corpus()
    print(f'TIER 3 - truth table under seal={CWE328_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4 - credential digest vs non-crypto digest, same call text:')
    failures += check_pairs()
    print(f'\nseal={CWE328_SEAL} shapes={len(SHAPES)} recorded_noise={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'pairs={len(PAIRS)} locked_cwe328={sum(CWE328_LOCKED.values())} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-328 boundary no longer matches its recorded truth table. This '
              'rule has 0 blessed keys, so a baseline diff will never tell you what moved here; this '
              'file is the only lock. Restore the answer or re-measure the seal with a new truth '
              'table - never re-bless a baseline.')
        return 1
    print(f'VERDICT: PASS - 0 blessed CWE-328 keys held (nothing to lose, nothing silenced), '
          f'corpus exact-set, {len(MUST_REPORT_ROWS)} credential/signature/token shapes reported at '
          f'seal={CWE328_SEAL!r}, {len(FP_ROWS)} non-crypto shapes '
          f'{"recorded silent under a proven use predicate" if CWE328_SEAL == "narrowed" else "still reported - exemption refused, no data-flow proof exists"}, '
          f'{len(ALREADY_QUIET_ROWS)} strong-digest shapes silent, all purpose pairs agreeing.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
