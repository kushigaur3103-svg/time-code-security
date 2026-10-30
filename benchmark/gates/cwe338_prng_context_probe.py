"""CWE-338 truth table: which PRNG draws the engine may be talked out of, and which it may never be.

    python benchmark/gates/cwe338_prng_context_probe.py

Why this gate exists
--------------------
CWE-338 is the second largest cluster in the tracked real-world artifact: 298 findings on odoo/odoo@17.0
(7,191 python files, engine rev f7d144f2, GitHub run 39999081384), out of 2,128 total. The emitter says
so in its own words -- `ast_scanner.py:6544` "All random.* calls are flagged unconditionally (insecure
PRNG)" and `:6568` "no security context gate" -- so every one of those 298 is reported by design, not by
accident. Three receiver-shaped exemptions already live in that branch (`SystemRandom` :6562,
`_is_dataset_shuffle_call` :5474, `_is_ml_math_random_draw` :5572) and each of them is a *proof about the
callee*, never a guess about the destination. This gate holds the same line for a context exemption.

Measured evidence (86 odoo files fetched at the pinned sha, scanned one module at a time: 298 of 298
rows reproduced, identical messages, peak 56.4 MB / 9.5 s)
---------------------------------------------------------------------------------------------------
  destination census of the 298 : 72 assigned to a plain name, 64 returned, 45 argument of another
                                call, 39 inside a list/tuple literal, 37 condition only, 16 used as
                                an index, 9 dict value under a plain key, 4+3 security-named,
                                3 loop bound, 2 self-calls, 2 discarded, 1 feeds `time.sleep`,
                                1 reported on a class-definition line with no call on it at all
  path split                    : 230 of 298 under a `/populate/` directory (odoo's fake-data
                                generators), 68 spread over 53 other files
  callee as written             : 140 rows whose written root is a third-party alias
                                (`populate.Random.choice`, `tools.populate.randint`), 154 rows on a
                                proven `random.*` root, 5 bare-leaf rows
  name vocabulary that actually occurs: color/delay markers touch 20 of 298 rows (6.7%) -- 14
                                `_default_color` / `_get_default_color` ORM default providers,
                                3 `get_delay`, 1 `html_color` dict key, 1 `time.sleep` jitter,
                                1 `colorize` tuple

The rule this gate refuses, and the numbers that refuse it
---------------------------------------------------------
"require a security-relevant sink or credential-adjacent naming context before emitting CWE-338" was
run as an experiment against the shipped engine, on a revertible local patch. Two results, both measured:

  * the unwired detector for exactly that question, `_is_security_sensitive_random` (`ast_scanner.py:5057`),
    is defined and NEVER called -- `grep -n "_is_security_sensitive_random(" ast_scanner.py` returns the
    definition only -- and when it is wired up and asked about all 298 rows it calls **4** of them
    security-sensitive. So the rule silences 294 of 298 (98.7%).
  * `python benchmark/gates/big8_ab.py` under that patch: `baseline=119 now=112 MISSING=7 NEW=0`,
    VERDICT FAIL. The 7 keys it deletes are the entire blessed CWE-338 Big-8 population:
    `tests__generation__test_utils.py:3352/:3367/:3384`, `tests__test_modeling_common.py:6606/:6698/:6722`,
    `tests__models__whisper__test_modeling_whisper.py:97`. `aa_parity` still said 425/425, because all
    9 blessed parity CWE-338 keys *are* credential-named (`token`, `session_key`, `auth_secret`,
    `csrf_token`, `session_secret`) -- which is exactly why parity alone is not evidence here.

Those seven keys are the shape the request asked to exempt: `global_rng = random.Random()` is a PRNG
"assigned to a plain name", and `values.append(rng.randint(0, vocab_size - 1))` is a PRNG output
"strictly confined to non-security arithmetic/indices". A rule that eats them is a false negative with a
blessed number on it, so it is refused, not shipped.

The line the exemption must not cross
-------------------------------------
Two boundaries, both locked below.

  1. **Absence of a credential name is not proof of a display value.** `index` and `page` are in the
     requested suppression vocabulary and are deliberately NOT in the shipped one: a paginated
     credential lookup is written `page_token = ...` and an OTP is built by indexing an alphabet with a
     draw, `otp = "".join(digits[random.randint(0, 9)] for _ in range(6))`. In the measured 298 those
     two words carry zero rows, so they buy no reduction and only add exposure.
  2. **A marker name must be a whole segment, and a security name always wins.** `color_password`
     matches both; it stays reported. The matcher never does substring work, because the engine's own
     `iv`-as-in-`alive` and `pass`-as-in-`let_pass` collisions are exactly what segment matching avoids
     -- and `let_pass` is a blessed Big-8 line.

Seal semantics - `PRNG_CTX_SEAL`
--------------------------------
  * `abstained` -- no context exemption is wired. Every PRNG draw in the table is loud, including the
    12 display-value rows this gate wants quiet. That is the red baseline the fix has to move.
  * `shipped` -- the display-value rule is wired at `ast_scanner.py:6551` next to the other three
    receiver proofs: the 12 display rows go quiet, all 16 must-report rows stay loud, the 3 CSPRNG
    shapes stay silent, and both frozen baselines keep every blessed CWE-338 key.

Falsification - run a mutation, do not edit this file to run it
--------------------------------------------------------------
    python benchmark/gates/cwe338_prng_context_probe.py                    # clean -> exit 0
    python benchmark/gates/cwe338_prng_context_probe.py --mutate=NAME      # exit 1 = CAUGHT

`--mutate` patches the engine in memory and runs TIER 3/4/5 only: an in-memory veto patch is
falsified by the truth table, and re-scanning the whole tree for it would cost minutes and prove
nothing new. Exit 1 means the gate failed under the mutation, which is the point; exit 0 under a
mutation would mean the guard is decorative; exit 2 means the mutation tests a guard this step does
not ship. Measured on the shipped engine, one process each:

  rollback_markers      exit=1 CAUGHT on 9 rows  (interval_target, seconds_kwarg, timeout_kwarg,
                                   budget_interval_annassign, timedelta_seconds_arg,
                                   batch_writing_interval, cooldown_target, keepalive_target,
                                   backoff_target) + TIER 4 'duration vocabulary not shipped'
  add_seed_marker       exit=1 CAUGHT on 1 row   ('seed' lands in the forbidden-word check)
  widen_banned_markers  exit=1 CAUGHT on 1 row   (index/page/items land in the same check)
  no_credential_veto    exit=1 CAUGHT on 9 rows  (color_named_secret and timeout_named_token go
                                   quiet, and TIER 4's veto list breaks for session_key,
                                   color_password, page_token, let_pass, otp, salt)
  no_join_veto          exit=1 CAUGHT on 3 rows  (seconds_join_digits and wait_alphabet_index_join
                                   go quiet, and the `.join` table check breaks)
  no_populate_segment   exit=2 SKIP - `ast_scanner.CWE338_DEMO_PATH_SEGMENTS` is not shipped.
  widen_to_tests_segment exit=2 SKIP - same guard; it is the Step-2 row, and TIER 5 already holds
                                   the evidence that it must stay narrow (below).

`wait_time_target` is deliberately kept in the table even though rolling the new words back does not
move it: its enclosing function is named `_retry_sleep`, so the shipped `sleep` marker already covers
it. Ten rows measured, nine attributable to the new vocabulary, one already covered -- and the
attribution is what the mutation prints, not what this comment assumes.

Why a directory name is not on the exempt side of this gate
----------------------------------------------------------
The 277 arena CWE-338 rows were classified from real AST on the 86 pinned files
(`scratch/_c338_fast.py`, 1.01 s, 76.1 MB): 261 math/sampling, 10 credential, 3 ambiguous, 2 timing,
0 colour (the colour family is already retired -- the shipped rule ate them), 1 on a line with no
call. 231 of those 277 sit under an odoo `populate/` directory and 14 under a `tests/` path or
`test_` leaf. Measured against the 16 blessed keys themselves: **0 of 16 live in a `populate/` path
and 14 of 16 live in a `test_`/`tests/` path** (8 parity keys are `test_v0*_bad.py`, all 7 Big-8 keys
are `tests__*`). So a path rule may be proposed for `populate/` and is refused for `tests/`, and TIER
5 pins that no path exemption exists today at all.

The seal switch is still there for the old rollback test: `python scratch/_c338_sealrun.py abstained`
moves `PRNG_CTX_SEAL` in memory without editing this file, and the display rows come back loud.
"""

from __future__ import annotations

import contextlib
import io
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, '..', '..'))
sys.path.insert(0, ROOT)
sys.path.insert(0, GATES_DIR)

import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys, scan_rows  # noqa: E402

PRNG_CTX_SEAL = 'shipped'
SEAL_TARGETS = ('abstained', 'shipped')

# The blessed CWE-338 population in each frozen baseline. Counted, not assumed: 9 rows in
# `parity_before.keys` (all credential-named) and 7 in `big8_before.keys` (all plain-named, which is
# why the require-context rule passes parity and fails Big-8).
CWE338_LOCKED = {'parity': 9, 'big8': 7}

REPORT, QUIET = 'loud', 'quiet'

# (label, source, answer at seal='abstained', answer at seal='shipped')
# Verdicts in the third column were measured against the shipped engine with
# `python scratch/_c338_shapes.py`; nothing here is asserted from the emitter's comments.
SHAPES = [
    # --- display-value rows: loud today, the only thing the fix is allowed to move -----------
    ('choice_color_list', 'import random\n\nCOLOR_LIST = ["red", "blue"]\n\n\ndef pick():\n    return random.choice(COLOR_LIST)\n',
     REPORT, QUIET),
    ('randint_color_range', 'import random\n\nCOLORS = ["a"] * 12\n\n\ndef pick():\n    return random.randint(0, len(COLORS) - 1)\n',
     REPORT, QUIET),
    ('sleep_jitter', 'import random\nimport time\n\n\ndef retry(attempt):\n    delay = attempt * 2\n    time.sleep(delay + random.random())\n',
     REPORT, QUIET),
    ('shuffle_display_items', 'import random\n\n\ndef render(display_items):\n    random.shuffle(display_items)\n    return display_items\n',
     REPORT, QUIET),
    ('default_color_fn', 'import random\n\n\ndef _default_color():\n    return random.randint(1, 15)\n',
     REPORT, QUIET),
    ('get_default_color_randrange', 'import random\n\n\ndef _get_default_color():\n    return random.randrange(0, 255)\n',
     REPORT, QUIET),
    ('preview_target', 'import random\n\nIMAGES = ["a", "b"]\n\n\ndef build():\n    preview = random.choice(IMAGES)\n    return preview\n',
     REPORT, QUIET),
    ('delay_target', 'import random\n\n\ndef schedule():\n    delay = random.uniform(0.5, 2.0)\n    return delay\n',
     REPORT, QUIET),
    ('jitter_kwarg', 'import random\n\n\ndef run():\n    schedule(job, jitter=random.random())\n',
     REPORT, QUIET),
    ('dict_html_color', 'import random\n\n\ndef row():\n    return {"html_color": random.randint(0, 255)}\n',
     REPORT, QUIET),
    ('display_rows', 'import random\n\nrows = [1, 2, 3]\n\n\ndef page():\n    display_rows = random.sample(rows, 2)\n    return display_rows\n',
     REPORT, QUIET),
    ('populate_get_delay', 'from odoo.tools import populate\n\n\ndef get_delay():\n    return populate.Random.randint(48, 72)\n',
     REPORT, QUIET),
    # --- duration / cadence rows: the 7 words added on top of the colour+delay family -----------
    # Every one of these is a real LiteLLM or odoo line, copied as written, so the bucket the audit
    # measured is the bucket the gate proves. None of them is reachable by a credential name.
    ('interval_target', 'import random\n\n\ndef _jitter_loop(attempt):\n    interval = random.randint(1, 5)\n'
                        '    return interval\n',
     REPORT, QUIET),
    ('wait_time_target', 'import random\n\n\ndef _retry_sleep(tryno):\n    wait_time = random.uniform(0.0, 2 ** tryno)\n'
                         '    return wait_time\n',
     REPORT, QUIET),
    ('seconds_kwarg', 'import random\n\n\ndef _poll(worker):\n    schedule(worker, seconds=random.randint(0, 60))\n',
     REPORT, QUIET),
    ('timeout_kwarg', 'import random\n\n\ndef _fetch(url):\n    fetch_with_timeout(url, timeout=random.uniform(0.1, 0.5))\n',
     REPORT, QUIET),
    ('budget_interval_annassign', 'import random\n\n\ndef _reschedule(base, proxy_budget_rescheduler_min_time):\n'
                                  '    budget_interval: Final = proxy_budget_rescheduler_min_time + random.randint(0, 5)\n'
                                  '    return budget_interval\n',
     REPORT, QUIET),
    ('timedelta_seconds_arg', 'import random\nfrom datetime import timedelta\n\n\ndef _next_run():\n'
                              '    next_run_time = timedelta(seconds=10 + random.randint(0, 300))\n'
                              '    return next_run_time\n',
     REPORT, QUIET),
    ('batch_writing_interval', 'import random\n\n\ndef _flusher():\n    batch_writing_interval = random.randrange(0, 30)\n'
                               '    return batch_writing_interval\n',
     REPORT, QUIET),
    ('cooldown_target', 'import random\n\n\ndef _throttle(state):\n    state.cooldown = random.randint(1, 3)\n'
                       '    return state\n',
     REPORT, QUIET),
    ('keepalive_target', 'import random\n\n\ndef _keepalive_ping(timeout):\n    keepalive = random.uniform(0, timeout / 2)\n'
                          '    return keepalive\n',
     REPORT, QUIET),
    ('backoff_target', 'import random\n\n\ndef _backoff(attempt):\n    backoff = random.uniform(0, attempt * 2)\n'
                       '    return backoff\n',
     REPORT, QUIET),
    # --- credential rows: loud at both seals --------------------------------------------------
    ('password_join', 'import random\n\nchars = "abc123"\npassword = "".join(random.choice(chars) for _ in range(12))\n',
     REPORT, REPORT),
    ('reset_token', 'import random\n\nreset_token = str(random.randint(100000, 999999))\n',
     REPORT, REPORT),
    ('salt_getrandbits', 'import random\n\nsalt = hex(random.getrandbits(64))\n', REPORT, REPORT),
    ('randbytes_draw', 'import random\n\nblob = random.randbytes(16)\n', REPORT, REPORT),
    ('otp_from_digits_index', 'import random\n\ndigits = "0123456789"\notp = "".join(digits[random.randint(0, 9)] for _ in range(6))\n',
     REPORT, REPORT),
    ('token_dict_key', 'import random\n\npayload = {"access_token": random.randrange(0, 10 ** 8)}\n',
     REPORT, REPORT),
    ('session_attr', 'import random\n\n\nclass Session:\n    def __init__(self):\n        self.session_secret = random.random()\n',
     REPORT, REPORT),
    ('page_token', 'import random\n\npage_token = random.randrange(0, 10 ** 8)\n', REPORT, REPORT),
    ('color_named_secret', 'import random\n\ncolor_password = random.choice("abc")\n', REPORT, REPORT),
    ('secure_kwarg', 'import random\n\nalphabet = "abc"\ncreate_session(token=random.choice(alphabet))\n',
     REPORT, REPORT),
    ('seed_draw', 'import random\n\nseed = random.randint(0, 2 ** 31)\n', REPORT, REPORT),
    ('csrf_in_dict', 'import random\n\n\ndef make():\n    return {"csrf_token": random.random()}\n',
     REPORT, REPORT),
    # --- tripwires for the duration words: each one is loud for a different structural reason ----
    # The marker is present in the name; what saves these is a veto, not luck. If a veto is deleted,
    # the row named in the MUTATIONS table below goes quiet and the gate has to say so.
    ('seconds_join_digits', 'import random\n\ninterval = "".join(str(random.randint(0, 9)) for _ in range(6))\n',
     REPORT, REPORT),
    ('timeout_named_token', 'import random\n\ntimeout_token = random.choice("0123456789abcdef")\n',
     REPORT, REPORT),
    ('cooldown_getrandbits', 'import random\n\ncooldown = hex(random.getrandbits(64))\n',
     REPORT, REPORT),
    # The 6-digit-code generator with a duration name, spelled the way an OTP is really built
    # (index an alphabet with a draw, then join). Marker word, no credential word, join shape.
    ('wait_alphabet_index_join', 'import random\n\nalphabet = "ABCDEFGH12345678"\n'
                                 'wait = "".join(alphabet[random.randint(0, 15)] for _ in range(8))\n',
     REPORT, REPORT),
    # --- the seven blessed Big-8 shapes, stood up as sources ----------------------------------
    ('big8_global_rng_ctor', 'import random\n\nglobal_rng = random.Random()\n', REPORT, REPORT),
    ('big8_vocab_append', ('import random\n\n\ndef ids(rng, vocab_size, total_dims):\n    values = []\n'
                           '    for _ in range(total_dims):\n        values.append(rng.randint(0, vocab_size - 1))\n'
                           '    return values\n'),
     REPORT, REPORT),
    ('big8_random_instance_ctor', 'import random\n\n\ndef build(seed):\n    rng = random.Random(seed)\n    return rng.random() * 4\n',
     REPORT, REPORT),
    ('big8_let_pass_compare', ('import random\n\n\nclass Gate:\n    def __init__(self):\n'
                               '        self.let_pass = {}\n\n    def roll(self, k):\n'
                               '        self.let_pass[k].append(random.randint(1, 10) <= 3)\n'),
     REPORT, REPORT),
    # --- CSPRNG substitutes: already silent, must stay silent ---------------------------------
    ('secrets_token', 'import secrets\n\ntoken = secrets.token_hex(32)\n', QUIET, QUIET),
    ('systemrandom', 'import random\n\nvalue = random.SystemRandom().randint(1, 9)\n', QUIET, QUIET),
    ('os_urandom', 'import os\n\nkey = os.urandom(32)\n', QUIET, QUIET),
]

FP_ROWS = [row for row in SHAPES if row[2] == REPORT and row[3] == QUIET]
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == REPORT]
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == QUIET]

# The Step-2 precondition, locked before Step 2 exists. A `populate/` directory is odoo's fake-data
# generator and the audit measured 231 of the 277 arena rows inside one, with 0 of the 16 blessed keys
# there -- so the path is a real boundary. It is NOT wired yet, and these rows are what prove that
# today nothing in the engine trades a finding for a directory name: the same plain-named draw is loud
# whether the module is `m.py` or `addons/sale/populate/x.py`. When the path guard ships, the
# `path-buys-nothing-*` rows are the ones that move, and moving them without updating this table is a
# gate failure.
PATH_ROWS = [
    ('path-buys-nothing-populate-plain', 'addons/sale/populate/res_partner.py',
     'import random\n\n\ndef _fill(batch_size):\n    count = random.randint(1, batch_size)\n    return count\n',
     REPORT),
    ('path-buys-nothing-tests-plain', 'tests/generation/test_utils.py',
     'import random\n\n\ndef _ids(rng, vocab_size, total_dims):\n    values = []\n'
     '    for _ in range(total_dims):\n        values.append(rng.randint(0, vocab_size - 1))\n'
     '    return values\n',
     REPORT),
]

# The duration family the fix is allowed to add, and the words it is forbidden to add. A table, so a
# mutation can widen or shrink it in memory and the truth tier has to notice.
TIMING_MARKERS = ('interval', 'seconds', 'timeout', 'backoff', 'wait', 'cooldown', 'keepalive')
FORBIDDEN_MARKERS = ('seed', 'index', 'page', 'items', 'data', 'value', 'rows', 'list')


def scan_cwe338(source, modname='m.py'):
    """The real record path, one in-memory module -- the same call the CWE-611 gate makes."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={modname: source})
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-338'})


def check_floors():
    """TIER 1: the blessed CWE-338 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-338'}
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-338={len(keys)} (want {CWE338_LOCKED[kind]})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != CWE338_LOCKED[kind]:
            failures.append((kind, 'CWE-338', CWE338_LOCKED[kind], len(keys),
                             'the blessed CWE-338 population moved'))
    return failures


def check_corpus():
    """TIER 2: the frozen CWE-338 keys re-produced by a whole-tree scan, as an exact key set."""
    failures = []
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    live = {row for row in scan_rows('parity', tree) if row[2] == 'CWE-338'}
    frozen = {row for row in load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
              if row[2] == 'CWE-338'}
    missing = sorted(frozen - live)
    extra = sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    for row in sorted(frozen):
        tag = 'held' if row in live else 'MISSING'
        label = str(row[0])[str(row[0]).find('corpus'):][:52]
        print(f'  {tag:8s} {label}:{row[1]} {row[4]}')
    for row in extra:
        print(f'  NEW      {row[0]}:{row[1]} {row[4]}')
    if missing:
        failures.append((len(missing), 'frozen CWE-338 keys no longer reported'))
    if extra:
        failures.append((len(extra), 'CWE-338 keys appeared that the baseline never held'))
    return failures


def check_shapes():
    """TIER 3: the truth table, asserted against the seal the file is standing under."""
    failures = []
    for label, source, when_abstained, when_shipped in SHAPES:
        expected = when_abstained if PRNG_CTX_SEAL == 'abstained' else when_shipped
        found = scan_cwe338(source)
        status = 'loud' if found else 'quiet'
        note = '; '.join(f'L{n}:{m.replace("CWE-338: ", "")}' for n, m in found)[:52]
        marker = 'ok' if status == expected else 'MISMATCH'
        print(f'  {label:28s} want={expected:5s} got={status:5s} {marker:8s} {note}')
        if status != expected:
            failures.append((label, 'seal', expected, status,
                             'the answer moved without the seal, or the seal moved without the answer'))
    return failures


def check_vocabulary():
    """TIER 4: the marker list, the leaf list and the veto order -- tables a refactor cannot widen.

    TIER 1-3 prove what the engine answers. This tier proves *why* it may answer that way: a later
    widening that adds `index`/`page`/`items` to the markers, or lets a byte-oriented draw be exempt,
    or checks the marker before the credential name, has to fail here and not in a baseline diff.
    """
    failures = []
    markers = set(getattr(ast_scanner, 'CWE338_DISPLAY_VALUE_MARKERS', frozenset()))
    leaves = set(getattr(ast_scanner, 'CWE338_DISPLAY_VALUE_LEAVES', frozenset()))
    join_leaves = set(getattr(ast_scanner, 'CWE338_CODE_JOIN_SINK_LEAVES', frozenset()))
    banned = set(FORBIDDEN_MARKERS)
    leaked = sorted(markers & banned)
    print(f'  markers={sorted(markers) if markers else "<none wired>"}')
    print(f'  banned words present in marker table: {leaked or "none"}')
    if leaked:
        failures.append(('index/page/items/seed class words in CWE338_DISPLAY_VALUE_MARKERS', leaked))
    absent = [w for w in TIMING_MARKERS if w not in markers]
    print(f'  timing words missing from marker table: {absent or "none"}')
    if absent:
        failures.append(('duration vocabulary not shipped', absent))
    print(f'  .join veto table: {sorted(join_leaves) or "<none wired>"}')
    if 'join' not in join_leaves:
        failures.append(('CWE338_CODE_JOIN_SINK_LEAVES no longer holds "join"', sorted(join_leaves)))
    byte_leaves = {'getrandbits', 'randbytes'}
    overlap = sorted(leaves & byte_leaves)
    print(f'  byte-oriented leaves exemptible: {overlap or "none"}')
    if overlap:
        failures.append(('getrandbits/randbytes are credential-shape leaves', overlap))
    for name in ('session_key', 'color_password', 'page_token', 'let_pass', 'otp', 'salt'):
        if not ast_scanner.TaintTracker._cwe338_name_is_security_named(name):
            failures.append(('security veto lost', name))
            print(f'  veto LOST for {name}')
    print(f'  veto holds for session_key/color_password/page_token/let_pass/otp/salt: '
          f'{not any(f[0] == "security veto lost" for f in failures)}')
    # The veto must beat the marker: a name carrying both is a credential.
    both = ast_scanner.TaintTracker._cwe338_name_is_security_named('color_password')
    marker_hit = bool({'color'} & {s.lower() for s in
                                   __import__('re').split(ast_scanner._CWE338_NAME_SPLIT, 'color_password')
                                   if s})
    print(f'  color_password: marker={marker_hit} veto={both} -> reported={both}')
    if not (marker_hit and both):
        failures.append(('marker/veto ordering not exercised by any name', 'color_password'))
    return failures


def check_path_rows():
    """TIER 5: a directory name buys nothing yet. See `PATH_ROWS` for why this row is the Step-2 seed."""
    failures = []
    for label, modname, source, expected in PATH_ROWS:
        found = scan_cwe338(source, modname)
        status = REPORT if found else QUIET
        note = '; '.join(f'L{n}:{m.replace("CWE-338: ", "")}' for n, m in found)[:44]
        print(f'  {label:32s} module={modname[:34]:34s} want={expected:5s} got={status:5s} '
              f'{"ok" if status == expected else "MISMATCH"} {note}')
        if status != expected:
            failures.append((label, 'path exemption exists but is not shipped', expected, status))
    return failures


def main() -> int:
    if PRNG_CTX_SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {PRNG_CTX_SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-338 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the corpus behind those keys, scanned live:')
    failures += check_corpus()
    print(f'TIER 3 - truth table under seal={PRNG_CTX_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4 - marker table, leaf table and veto order:')
    failures += check_vocabulary()
    print('TIER 5 - a directory name alone is not an exemption (Step-2 precondition):')
    failures += check_path_rows()
    print(f'\nseal={PRNG_CTX_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'path_rows={len(PATH_ROWS)} '
          f'locked_cwe338={sum(CWE338_LOCKED.values())} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-338 context rule no longer matches its measured evidence. '
              'Restore the answer or update the seal with a re-measured truth table; never re-bless a '
              'baseline -- the 7 blessed Big-8 CWE-338 keys are plain-named draws and a require-'
              'security-context rule deletes exactly those 7.')
        return 1
    print('VERDICT: PASS - 16 blessed CWE-338 keys held (9 parity + 7 Big-8), corpus exact-set, '
          f'{len(MUST_REPORT_ROWS)} credential and blessed-draw shapes reported, '
          f'{len(ALREADY_QUIET_ROWS)} CSPRNG shapes silent, '
          f'{len(FP_ROWS)} display-value rows '
          + ('still loud at seal=abstained' if PRNG_CTX_SEAL == 'abstained' else 'exempted')
          + '.')
    return 0


MUTATIONS = {
    'rollback_markers': {
        'what': 'drop the 7 duration words from the marker table',
        'rows': ['interval_target', 'wait_time_target', 'seconds_kwarg', 'timeout_kwarg',
                 'budget_interval_annassign', 'timedelta_seconds_arg', 'batch_writing_interval',
                 'cooldown_target', 'keepalive_target', 'backoff_target'],
        'requires': None,
        'apply': lambda: setattr(ast_scanner, 'CWE338_DISPLAY_VALUE_MARKERS',
                                 frozenset(set(ast_scanner.CWE338_DISPLAY_VALUE_MARKERS)
                                          - set(TIMING_MARKERS))),
    },
    'add_seed_marker': {
        'what': 'widen the table with the forbidden word "seed" (the prompt\'s own DO-NOT-ADD)',
        'rows': ['seed_draw'],
        'requires': None,
        'apply': lambda: setattr(ast_scanner, 'CWE338_DISPLAY_VALUE_MARKERS',
                                 frozenset(set(ast_scanner.CWE338_DISPLAY_VALUE_MARKERS) | {'seed'})),
    },
    'widen_banned_markers': {
        'what': 'widen the table with index/page/items, the words that carry 0 rows and real exposure',
        'rows': ['page_token', 'otp_from_digits_index'],
        'requires': None,
        'apply': lambda: setattr(ast_scanner, 'CWE338_DISPLAY_VALUE_MARKERS',
                                 frozenset(set(ast_scanner.CWE338_DISPLAY_VALUE_MARKERS)
                                           | {'index', 'page', 'items'})),
    },
    'no_credential_veto': {
        'what': 'make the credential-name veto always answer "not a credential"',
        'rows': ['timeout_named_token', 'color_named_secret', 'page_token', 'token_dict_key',
                 'session_attr'],
        'requires': None,
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_cwe338_name_is_security_named',
                                 staticmethod(lambda name: False)),
    },
    'no_join_veto': {
        'what': 'empty the .join veto table, so a duration-named code generator is exempt',
        'rows': ['seconds_join_digits', 'wait_alphabet_index_join'],
        'requires': None,
        'apply': lambda: setattr(ast_scanner, 'CWE338_CODE_JOIN_SINK_LEAVES', frozenset()),
    },
    # Both of these are Step 2. They name the engine symbol each one would have to patch; the driver
    # checks the symbol exists and refuses to claim a falsification when it does not, so neither can
    # ever be reported as "the gate proved this" before the guard it tests is actually shipped.
    'no_populate_segment': {
        'what': 'remove the odoo demo-data directory guard (Step 2)',
        'rows': ['path-buys-nothing-populate-plain'],
        'requires': 'CWE338_DEMO_PATH_SEGMENTS',
        'apply': lambda: setattr(ast_scanner, 'CWE338_DEMO_PATH_SEGMENTS', frozenset()),
    },
    'widen_to_tests_segment': {
        'what': 'widen the path guard to tests/ (Step 2) -- measured to delete 14 of the 16 blessed keys',
        'rows': ['path-buys-nothing-tests-plain'],
        'requires': 'CWE338_DEMO_PATH_SEGMENTS',
        'apply': lambda: setattr(ast_scanner, 'CWE338_DEMO_PATH_SEGMENTS',
                                 frozenset({'populate', 'tests', 'test'})),
    },
}


def run_mutation(name: str) -> int:
    """Apply one in-memory mutation and run the real gate over it. Exit 1 = the mutation was caught."""
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print(f"  rows that must go quiet: {', '.join(spec['rows'])}")
    if spec['requires'] and not hasattr(ast_scanner, spec['requires']):
        print(f"  SKIP - not shipped in this step: the guard symbol ast_scanner.{spec['requires']} does "
              f"not exist, so there is nothing to delete or widen. NOT counted as a falsification.")
        return 2
    spec['apply']()
    # TIER 1 and 2 read the frozen baselines and re-scan the whole `benchmark/` tree; an in-memory veto
    # patch cannot move a blessed key that the corpus does not hold, and running them here would make
    # each mutation cost a full tree scan. The truth table, the tables and the path rows are what a
    # guard is falsified on.
    print('TIER 3 - truth table under the mutation:')
    failures = check_shapes()
    print('TIER 4 - marker table, leaf table and veto order:')
    failures += check_vocabulary()
    print('TIER 5 - a directory name alone is not an exemption:')
    failures += check_path_rows()
    for item in failures[:12]:
        print(f'  !! {item}')
    caught = bool(failures)
    print(f"\nFALSIFICATION VERDICT ({name}): "
          + (f'CAUGHT on {len(failures)} row(s) -- ' + ', '.join(sorted({str(f[0]) for f in failures})[:6])
             if caught else 'MISSED - the guard is decorative, the engine still answers its own truth '
                            'table'))
    # The exit code keeps the gate's own convention, so `--mutate` reads like a rollback test: 1 = the
    # gate fails under the mutation (the guard is load-bearing); 0 = the mutation slipped through and
    # that is the alarm condition. 2 = this mutation tests a guard that is not shipped yet.
    return 1 if caught else 0


if __name__ == '__main__':
    wanted = [a.split('=', 1)[1] for a in sys.argv[1:] if a.startswith('--mutate=')]
    if wanted:
        unknown = [w for w in wanted if w not in MUTATIONS]
        if unknown:
            print(f'BAD MUTATION: {unknown} is not one of {sorted(MUTATIONS)}')
            sys.exit(1)
        sys.exit(run_mutation(wanted[0]))
    sys.exit(main())
