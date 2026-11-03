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
  no_credential_veto    exit=1 CAUGHT on 10 rows (color_named_secret, timeout_named_token and
                                   demo-populate-plain-credential go quiet, and TIER 4's veto list
                                   breaks for session_key, color_password, page_token, let_pass, otp,
                                   salt)
  no_join_veto          exit=1 CAUGHT on 4 rows  (seconds_join_digits, wait_alphabet_index_join and
                                   demo-populate-join-code go quiet, and the `.join` table check breaks)
  no_populate_segment   exit=1 CAUGHT on 7 rows  (all six demo_quiet rows come back loud, plus the
                                   TIER 4 exact-allow-set check)
  widen_to_tests_segment exit=1 CAUGHT on 5 rows (tests-plain-stays-loud and
                                   populate-under-tests-stays-loud go quiet, and TIER 4 breaks the
                                   allow set, the veto words and the `test_` prefixes)

Thirteen mutations, thirteen exits of 1, zero skips: the two path mutations used to exit 2 because no path
guard existed, and they exit 1 now that Step 2 shipped it; the nine mutations that used to patch the
loop-bound axis in the engine are rebuilt as six self-contained pitch variants (see the withdrawal note at
the bottom of this docstring), so every one of them runs against the shipped engine today.

  loop_bound_pitch_shipped  exit=1 CAUGHT on 7 rows  (exactly the 7 count-shaped draws -- the FP price of
                                   the withdrawal, and nothing else)
  bound_pitch_accepts_selection exit=1 CAUGHT on 11 (the 7 + subscript_select, slice_select and, decisively,
                                   otp_from_digits_index + wait_alphabet_index_join -- the mandate's own
                                   literal reading silences two code-assembling rows)
  bound_pitch_accepts_any_call  exit=1 CAUGHT on 18 (the 7 + other_call, shadowed_range, list_append,
                                   str_concat + reset_token, salt_getrandbits, seconds_join_digits,
                                   cooldown_getrandbits, big8_vocab_append, demo-populate-join-code,
                                   tests-plain-stays-loud)
  bound_pitch_always_true   exit=1 CAUGHT on 50 rows (all 21 bound shapes + 29 credential, blessed-line,
                                   CSPRNG and demo rows -- what a rule delete looks like here)
  bound_pitch_accepts_unread exit=1 CAUGHT on 25 (the 7 + 14 assigned-shape look-alikes incl. module_scope
                                   and never_read + randbytes_draw, big8_global_rng_ctor,
                                   demo-populate-rng-ctor/getrandbits and three test-tree tripwires)
  bound_pitch_drops_credential_veto exit=1 CAUGHT on 8 (the 7 + credential_named, so the veto inside the
                                   axis is load-bearing and not only the guard-level one)

`test-prefix-module-stays-loud` does NOT move under `widen_to_tests_segment` even though the mutation adds
`test` to the allow set -- the segment in that path is `test_populate`, and whole-segment matching cannot
see it. That row is protected by the matching rule itself, which no table mutation in this list can soften.

The 231-vs-221 arithmetic
-------------------------
232 arena rows live under a `populate` path segment; Step 1 had already retired 1 of them
(`odoo/tools/populate.py:180`), so 231 were reachable by the path axis and
`scratch/_c338_timing_ab.py` measures 221 retired. The 10-row gap is the guard *refusing*, and every
refusal is a leaf-table decision, not a path one (`scratch/_c338_demo_left.py` lists them by line):
5 `getrandbits`, 1 `random.Random()` and 4 `gauss`/`expovariate` draws -- none of the three is in
`CWE338_DISPLAY_VALUE_LEAVES`, so the path is never even consulted for them. The credential-name and
`.join` refusals are additionally reproduced as TIER 5 tripwires (`demo-populate-plain-credential`,
`demo-populate-join-code`, `demo-populate-rng-ctor`, `demo-populate-getrandbits`) so the shape is
locked even where the arena happens to contain none of it.

`wait_time_target` is deliberately kept in the table even though rolling the new words back does not
move it: its enclosing function is named `_retry_sleep`, so the shipped `sleep` marker already covers
it. Ten rows measured, nine attributable to the new vocabulary, one already covered -- and the
attribution is what the mutation prints, not what this comment assumes.

Why exactly one directory name is on the exempt side, and `tests/` never is
--------------------------------------------------------------------------
The 277 arena CWE-338 rows were classified from real AST on the 86 pinned files
(`scratch/_c338_fast.py`, 1.01 s, 76.1 MB): 261 math/sampling, 10 credential, 3 ambiguous, 2 timing,
0 colour (the colour family is already retired -- the shipped rule ate them), 1 on a line with no
call. 232 of those 277 sit under an odoo `populate` path segment and 14 under a `tests/` path or
`test_` leaf. Measured against the 16 blessed keys themselves: **0 of 16 live in a `populate` path
and 14 of 16 live in a `test_`/`tests/` path** (8 parity keys are `test_v0*_bad.py`, all 7 Big-8 keys
are `tests__*`), and 0 of the 552 files in the parity scan corpus carry the demo segment at all. That
asymmetry is the whole argument: the demo segment has an empty blessed population behind it and the
test segment has almost all of it, so one may be exempted and the other may not be exempted *under any
circumstance*, including when it is nested inside a demo directory. TIER 5 pins both halves of that
sentence, and `widen_to_tests_segment` is the mutation that proves the `tests` half is load-bearing.

The seal switch is still there for the old rollback test: `python scratch/_c338_sealrun.py abstained`
moves `PRNG_CTX_SEAL` in memory without editing this file, and the display rows come back loud.

The loop-bound def-use axis: written, measured, and withdrawn on its own numbers
---------------------------------------------------------------------------------
The mandate asked for a CWE-338 exemption decided by the *use* of the draw rather than by its name: a
draw consumed only as a loop bound is a count, not a secret. It was built (`range`/`xrange` argument
role proven by a parent climb for the direct spelling and by a bounded `ast.walk` of the enclosing
function for an assigned name -- **every** load must land in a `range` argument, so a `Subscript`, a
`Slice` or an unread draw fails closed), it was greened across six tiers, and then it was costed.

  arena yield    : `scratch/_c338_bound_ab.py rows` -> head 260 rows / shipped 258,
                   CWE-338 156 -> 154, RETIRED=2 ADDED=0 over the 67 CWE-338-bearing files
                   (4,374,330 bytes). The two are `_arena/src/transformers/data/datasets/
                   language_modeling.py:280` and `:488`, both the assigned-name shape.
  blessed reach  : `scratch/_c338_bound_ab.py blessed` -> both arms `blessed_lines=16
                   draw_calls_located=16 predicate_asks=16 silenced_by_bound_axis=0` -> PASS, so no
                   blessed key moved in either direction.
  cost           : `scratch/_c338_bound_clock.py` (paired, order-alternating, block-min over 8 windows
                   of ~0.35 s CPU, 5 legs per bucket, 10 files / 1,410,767 bytes, 59 guard asks and 35
                   axis calls per scan, 55 rows reported):
                     axis never reached (control)  3.906 -> 3.906 us  ADDED +0.000  ratio 1.0000
                     axis reached, refused        15.121 -> 70.060 us  ADDED +54.940 ratio 4.6610 (0/5 legs <= head)
                     axis reached, exempted       25.391 -> 511.719 us ADDED +486.328 ratio 19.3077 (0/5)
                   The control is exactly zero, so the delta is the walk and not the machine.

Rule 15.3 is a shape law as well as a ratio law -- "all filter checks must be O(1) or single-pass AST
lookups, no multi-hop recursive graph walks" -- and this check is a per-ask O(scope) walk that measures
4.66x at the site it sits on, for 2 rows out of a 2,319-row report (0.086 %). There is no cheaper variant
that keeps those 2 rows: the O(1) direct-climb half alone measures 0 arena rows, and lowering the node cap
below the two real scopes (516 and 528 nodes) also measures 0. An index of every `ast.Name` load per scope
would make the test O(occurrences), but it is a new per-module table of AST references -- the memory
direction the standing RAM law points the other way -- and no version of it is worth 2 rows.

So the engine is byte-identical to HEAD (`git hash-object ast_scanner.py` = `git rev-parse
HEAD:ast_scanner.py` = `8bcdbad93659170b...`), the work is kept as
`scratch/mandate_defuse_cwe338_loop_bound.patch` (git-ignored) so a re-ship starts from measured code, and
the 2 FPs stay loud -- which is the allowed direction. `BOUND_SEAL` below states that state, TIER 4 and
TIER 6 refuse to let it lie, and `loop_bound_pitch_shipped` installs the withdrawn guard in memory so the
gate fails on the 7 shapes it would silence. This is the same disposition the CWE-117 binding census got
(`cwe117_numeric_provenance_probe.py`, `binding_seal=withdrawn`): a guard whose cost is measured real and
whose benefit is measured tiny does not ship.
"""

from __future__ import annotations

import contextlib
import ast
import inspect
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

# The loop-bound axis is a separate decision from the display-value and demo-path rules, so it carries its
# own state flag -- and the flag is checked against the module, not trusted. `withdrawn` is the shipped
# state: the guard was built, measured at 2 arena rows and 4.66x on its own ask, and reverted.
BOUND_SEAL = 'withdrawn'
BOUND_SEAL_TARGETS = ('withdrawn', 'shipped')


def bound_axis_shipped() -> bool:
    """Ask the engine whether the loop-bound axis exists. Reads the module, never a comment."""
    return (hasattr(ast_scanner.TaintTracker, '_cwe338_draw_is_loop_bound_only')
            and hasattr(ast_scanner, 'CWE338_BOUND_ONLY_CALLS'))

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

# The demo-data path axis, shipped in Step 2, and the only directory this gate will ever trade a
# finding for. Measured on the 86 pinned arena files: 34 files / 232 of the 277 rows carry a `populate`
# segment -- 229 of them still loud after Step 1, which is what the path axis retires -- while **0 of
# the 552 blessed parity-corpus files and 0 of the 16 locked CWE-338 keys** carry it. The mirror image
# is the trap: 14 of those 16 keys live in a `test_`/`tests/` module and 7 under a `tests` directory, so
# a path rule that reached `tests/` would delete most of the blessed population in one line. Both
# spellings are rows below, because odoo ships nested (`addons/sale/populate/x.py`), the pinned arena
# is flattened (`addons__sale__populate__x`), and odoo itself is Windows-friendly (`...\populate\`).
DEMO_PATH_WORDS = ('populate', 'populators')
DEMO_PATH_VETO_WORDS = ('tests', 'test', 'testing', 'conftest', 'fixtures')
DEMO_PATH_VETO_PREFIXES = ('test_', 'tests_')

PATH_ROWS = [
    # --- the exemption, in every spelling the guard has to speak -------------------------------
    ('demo-nested-populate-plain', 'addons/sale/populate/res_partner.py',
     'import random\n\n\ndef _fill(batch_size):\n    count = random.randint(1, batch_size)\n    return count\n',
     QUIET),
    ('demo-flattened-populate-plain', 'addons__sale__populate__res_partner.py',
     'import random\n\n\ndef _fill(batch_size):\n    count = random.randint(1, batch_size)\n    return count\n',
     QUIET),
    ('demo-windows-populate-plain', 'addons\\sale\\populate\\res_partner.py',
     'import random\n\n\ndef _fill(batch_size):\n    count = random.randint(1, batch_size)\n    return count\n',
     QUIET),
    # A module-level draw with no enclosing function and no marker word: the name axis is blind here, so
    # this row is the proof that the path axis is a separate boundary and not a synonym for a marker.
    ('demo-populate-module-level', 'addons/sale/populate/res_partner.py',
     'import random\n\nbatch = random.randrange(1, 40)\n',
     QUIET),
    # `populate.py` as a FILE, not a directory: the segment must still read `populate`, which is why the
    # guard strips the suffix before comparing. This is odoo's own faker module.
    ('demo-populate-module-file', 'odoo/tools/populate.py',
     'import random\n\nvalue = random.choice(range(100))\n',
     QUIET),
    ('demo-populate-dict-value', 'addons/sale/populate/res_partner.py',
     'import random\n\n\ndef _partner():\n    return {"phone": random.choice("0123456789"),'
     ' "zip": random.randint(100000, 999999)}\n',
     QUIET),
    # --- the tripwires: a directory never outruns a credential, a join, a byte draw or a test -----
    ('demo-populate-credential-name', 'addons/sale/populate/res_partner.py',
     'import random\n\nCHARS = "abcdef0123456789"\n\n\ndef _partner():\n'
     '    session_token = "".join(random.choice(CHARS) for _ in range(16))\n'
     '    return session_token\n',
     REPORT),
    ('demo-populate-plain-credential', 'addons/sale/populate/res_partner.py',
     'import random\n\n\ndef _fill():\n    password = random.choice("abcdefgh0123456789")\n'
     '    return password\n',
     REPORT),
    ('demo-populate-join-code', 'addons/sale/populate/res_partner.py',
     'import random\n\n\ndef _fill():\n    count = "".join(str(random.randint(0, 9)) for _ in range(6))\n'
     '    return count\n',
     REPORT),
    ('demo-populate-rng-ctor', 'addons/sale/populate/res_partner.py',
     'import random\n\n\ndef _fill():\n    rng = random.Random()\n    return rng.random()\n',
     REPORT),
    ('demo-populate-getrandbits', 'addons/sale/populate/res_partner.py',
     'import random\n\nbits = random.getrandbits(256)\n',
     REPORT),
    ('tests-plain-stays-loud', 'tests/generation/test_utils.py',
     'import random\n\n\ndef _ids(rng, vocab_size, total_dims):\n    values = []\n'
     '    for _ in range(total_dims):\n        values.append(rng.randint(0, vocab_size - 1))\n'
     '    return values\n',
     REPORT),
    # A test *module* whose own name contains the demo word. Whole-segment matching plus the `test_`
    # prefix veto hold this; a substring path rule would silence it. Measured: 1 arena row.
    ('test-prefix-module-stays-loud', 'odoo/addons/test_populate/models.py',
     'import random\n\nvalue = random.randint(1, 10)\n',
     REPORT),
    ('populate-under-tests-stays-loud', 'addons/sale/populate/tests/faker.py',
     'import random\n\nvalue = random.randint(1, 10)\n',
     REPORT),
    # No scope -> no path -> no exemption. This is the fail-closed half of the guard.
    ('no-scope-plain-draw-stays-loud', 'm.py',
     'import random\n\nvalue = random.randint(1, 10)\n',
     REPORT),
]

DEMO_QUIET_ROWS = [row[0] for row in PATH_ROWS if row[3] == QUIET]
DEMO_TRIPWIRE_ROWS = [row[0] for row in PATH_ROWS if row[3] == REPORT]

# The def-use loop-bound axis (Step 3). The mandate asked for "subscript / index usage provenance": if a
# draw's value is used as an array index, silence it. That half was REFUSED and is measured here as loud
# rows -- `pool[idx]` and `img[top:top + h]` are a draw *selecting material out of a container*, which is
# exactly how a weak-randomness OTP or a shuffled secret is assembled, and the same argument is why a
# slice bound stays reported. What ships instead is the only consumer in Python that turns a number into
# "how many times", and nothing else: a `range(...)` argument. 21 shapes, measured through the real record
# path (`python scratch/_bound_rows_finding.py`): 7 quiet, 14 loud, and every quiet row is quiet *because
# of this axis* (TIER 6 re-scans each with the axis blinded and requires it loud), so the silence is
# attributed rather than asserted.
# (label, source, expected under seal='shipped')
BOUND_ROWS = [
    ('bound_direct', 'import random\n\n\ndef f():\n    for i in range(random.randint(1, 9)):\n        pass\n', QUIET),
    ('bound_assigned', 'import random\n\n\ndef f(c):\n    a_end = random.randint(1, len(c) - 1)\n'
                       '    for i in range(a_end):\n        pass\n', QUIET),
    ('bound_arith', 'import random\n\n\ndef f(i):\n    n = random.randrange(5)\n    for j in range(i, n + 1):\n        pass\n', QUIET),
    ('bound_two_loads', 'import random\n\n\ndef f():\n    n = random.randint(1, 9)\n    for a in range(n):\n        pass\n'
                        '    for b in range(n):\n        pass\n', QUIET),
    ('bound_choice', 'import random\n\n\ndef f(k):\n    for i in range(random.choice(k)):\n        pass\n', QUIET),
    ('bound_xrange', 'import random\n\n\ndef f():\n    for i in xrange(random.randint(0, 9)):\n        pass\n', QUIET),
    ('bound_unary_neg', 'import random\n\n\ndef f():\n    k = random.randint(1, 3)\n    for i in range(-k):\n        pass\n', QUIET),
    # --- the mandate's own examples, kept loud because a selection is not a count -----------------
    ('subscript_select', 'import random\n\n\ndef f(pool):\n    idx = random.randint(0, len(pool) - 1)\n'
                         '    return pool[idx]\n', REPORT),
    ('slice_select', 'import random\n\n\ndef f(img, h):\n    top = random.randint(0, 9)\n'
                     '    return img[top:top + h]\n', REPORT),
    # --- every other way a bound-looking number can leave the function ----------------------------
    ('other_call', 'import random\n\n\ndef f():\n    n = random.randint(1, 9)\n    return do(n)\n', REPORT),
    ('never_read', 'import random\n\n\ndef f():\n    n = random.randint(1, 9)\n    return 1\n', REPORT),
    ('module_scope', 'import random\n\nN = random.randint(1, 9)\nfor i in range(N):\n    pass\n', REPORT),
    ('shadowed_range', 'import random\n\n\ndef range(x):\n    return [1, 2, 3]\n\n\ndef f():\n'
                       '    n = random.randint(1, 9)\n    for i in range(n):\n        pass\n', REPORT),
    ('credential_named', 'import random\n\n\ndef f():\n    token_index = random.randint(1, 5)\n'
                         '    for i in range(token_index):\n        pass\n', REPORT),
    ('tuple_unpack', 'import random\n\n\ndef f():\n    a, b = random.randint(1, 2), 5\n'
                     '    for i in range(a):\n        pass\n', REPORT),
    ('returned_value', 'import random\n\n\ndef f():\n    n = random.randint(1, 9)\n    return n\n', REPORT),
    ('augassign', 'import random\n\n\ndef f():\n    n = 0\n    n += random.randint(1, 9)\n'
                  '    for i in range(n):\n        pass\n', REPORT),
    ('list_append', 'import random\n\n\ndef f(out):\n    n = random.randint(1, 9)\n    out.append(n)\n', REPORT),
    ('str_concat', 'import random\n\n\ndef f():\n    n = random.randint(1, 9)\n'
                   "    for i in range(len('a' + str(n))):\n        pass\n", REPORT),
    ('starred_args', 'import random\n\n\ndef f(nums):\n    n = random.randint(1, 9)\n'
                     '    for i in range(*nums):\n        pass\n', REPORT),
    ('keyword_slot', 'import random\n\n\ndef f():\n    n = random.randint(1, 9)\n'
                     '    for i in enumerate(seq, start=n):\n        pass\n', REPORT),
]

BOUND_QUIET_ROWS = [row[0] for row in BOUND_ROWS if row[2] == QUIET]
BOUND_LOUD_ROWS = [row[0] for row in BOUND_ROWS if row[2] == REPORT]

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
    # The path axis, pinned as tables and not as prose: exact allow-set, veto coverage, and the one
    # argument the guard is fed. A refactor that widens `populate` to `tests`, drops the test veto, or
    # stops passing scope_id has to break here.
    allow = set(getattr(ast_scanner, 'CWE338_DEMO_PATH_SEGMENTS', frozenset()))
    veto = set(getattr(ast_scanner, 'CWE338_DEMO_PATH_VETO_SEGMENTS', frozenset()))
    prefixes = tuple(getattr(ast_scanner, 'CWE338_DEMO_PATH_VETO_PREFIXES', ()))
    print(f'  demo path segments={sorted(allow) or "<none wired>"} veto={sorted(veto) or "<none wired>"} '
          f'prefixes={list(prefixes) or "<none wired>"}')
    if allow != set(DEMO_PATH_WORDS):
        failures.append(('CWE338_DEMO_PATH_SEGMENTS is not exactly ' + str(DEMO_PATH_WORDS), sorted(allow)))
    missing_veto = [w for w in DEMO_PATH_VETO_WORDS if w not in veto]
    if missing_veto:
        failures.append(('demo path veto lost', missing_veto))
    missing_prefix = [w for w in DEMO_PATH_VETO_PREFIXES if w not in prefixes]
    if missing_prefix:
        failures.append(('test_ prefix veto lost', missing_prefix))
    try:
        params = list(inspect.signature(ast_scanner.TaintTracker._cwe338_display_only_draw).parameters)
    except (TypeError, ValueError):
        params = []
    print(f'  _cwe338_display_only_draw signature={params}')
    if 'scope_id' not in params:
        failures.append(('the path guard has no scope to read', params))
    if not hasattr(ast_scanner.TaintTracker, '_cwe338_module_is_demo_generator'):
        failures.append(('demo path helper missing', '_cwe338_module_is_demo_generator'))
    # --- the def-use loop-bound axis ---------------------------------------------------------------
    # Its state is read from the module, and the state decides which pins run: the shipped pins would all
    # pass on a half-reverted engine (a missing table makes `getattr` return the default, and the default
    # answers False on every row), so a blind axis and an absent axis have to be told apart by shape.
    axis_in_engine = bound_axis_shipped()
    print(f'  loop-bound axis in the engine: {axis_in_engine}  declared BOUND_SEAL={BOUND_SEAL!r}')
    if BOUND_SEAL not in BOUND_SEAL_TARGETS or (BOUND_SEAL == 'shipped') != axis_in_engine:
        failures.append(('the bound seal does not describe the engine', (BOUND_SEAL, axis_in_engine)))
        return failures
    if BOUND_SEAL == 'withdrawn':
        # The refusal is machine-checked, so a re-ship has to flip BOUND_SEAL on purpose and a half-revert
        # that leaves one helper or one table behind fails here instead of quietly widening the rule.
        left = [name for name in ('_cwe338_bound_consumer_calls', '_cwe338_load_is_bound',
                                  '_cwe338_enclosing_function', '_cwe338_draw_is_loop_bound_only')
                if hasattr(ast_scanner.TaintTracker, name)]
        tables = [name for name in ('CWE338_BOUND_ONLY_CALLS', '_CWE338_BOUND_ARITH_OPS',
                                    '_CWE338_BOUND_SCOPE_NODE_LIMIT', '_CWE338_BOUND_CLIMB_LIMIT',
                                    '_CWE338_BOUND_SCOPE_HOP_LIMIT')
                  if hasattr(ast_scanner, name)]
        wired = inspect.getsource(ast_scanner).count('self._cwe338_draw_is_loop_bound_only(')
        print(f'  withdrawn state: helpers left={left or "none"} tables left={tables or "none"} '
              f'call sites={wired}')
        if left or tables or wired:
            failures.append(('the loop-bound axis is still partly in the engine', (left, tables, wired)))
        return failures
    # Shipped pins: a name table is the cheapest thing for a refactor to widen, so it is pinned exactly;
    # the rest read the method's own source, because "it asks the right question" is a property of the
    # code, not of a row count -- a blind axis and an axis that never gets asked both move 0 rows.
    bound_calls = set(getattr(ast_scanner, 'CWE338_BOUND_ONLY_CALLS', frozenset()))
    print(f'  bound consumer calls={sorted(bound_calls) or "none wired"}')
    if bound_calls != {'range', 'xrange'}:
        failures.append(('CWE338_BOUND_ONLY_CALLS is not exactly {range, xrange}', sorted(bound_calls)))
    arith = tuple(getattr(ast_scanner, '_CWE338_BOUND_ARITH_OPS', ()))
    selection = [op.__name__ for op in arith
                 if op in (ast.Subscript, ast.Slice, ast.List, ast.Tuple, ast.Set, ast.Dict,
                           ast.Compare, ast.Call, ast.JoinedStr, ast.Starred)]
    print(f'  bound arithmetic ops={sorted(op.__name__ for op in arith)} non-numeric={selection or "none"}')
    if selection:
        failures.append(('a selecting/boolean type joined the bound climb', selection))
    missing_helpers = [h for h in ('_cwe338_bound_consumer_calls', '_cwe338_load_is_bound',
                                   '_cwe338_enclosing_function', '_cwe338_draw_is_loop_bound_only')
                       if not hasattr(ast_scanner.TaintTracker, h)]
    if missing_helpers:
        failures.append(('bound axis helper missing', missing_helpers))
        print(f'  bound axis helpers missing: {missing_helpers}')
        return failures
    load_src = inspect.getsource(ast_scanner.TaintTracker._cwe338_load_is_bound)
    axis_src = inspect.getsource(ast_scanner.TaintTracker._cwe338_draw_is_loop_bound_only)
    draw_src = inspect.getsource(ast_scanner.TaintTracker._cwe338_display_only_draw)
    flat_load = ' '.join(load_src.split())
    arg_slot = 'any(arg is current for arg in parent.args)'
    print(f'  load binds an argument slot by identity: {arg_slot in flat_load}')
    if arg_slot not in flat_load:
        failures.append(('the bound test stopped requiring an argument slot', arg_slot))
    flat_axis = ' '.join(axis_src.split())
    if 'isinstance(parent, ast.AugAssign): return False' not in flat_axis:
        failures.append(('aug-assign refusal lost from the bound axis', 'ast.AugAssign'))
    veto_recheck = 'self._cwe338_name_is_security_named(name) for name in names'
    print(f'  bound axis re-checks the credential veto: {veto_recheck in flat_axis}')
    if veto_recheck not in flat_axis:
        failures.append(('the bound axis no longer re-checks the credential veto', veto_recheck))
    # Indentation-agnostic: the pin is about the control flow (a refusal inside the loop), not about how
    # many spaces the method happens to sit at.
    short_circuit = ('if not self._cwe338_load_is_bound(child, allowed): return False')
    print(f'  bound axis short-circuits on the first unbound load: {short_circuit in flat_axis}')
    if short_circuit not in flat_axis:
        failures.append(('the bound axis collects every load before testing (the 108 us refusal path)',
                         'short-circuit'))
    cap = getattr(ast_scanner, '_CWE338_BOUND_SCOPE_NODE_LIMIT', None)
    climb = getattr(ast_scanner, '_CWE338_BOUND_CLIMB_LIMIT', None)
    hops = getattr(ast_scanner, '_CWE338_BOUND_SCOPE_HOP_LIMIT', None)
    print(f'  bound scope node cap={cap} climb={climb} scope hops={hops}')
    if not isinstance(cap, int) or not 0 < cap <= 2000:
        failures.append(('bound scope node cap missing or unbounded', cap))
    if not isinstance(climb, int) or not 0 < climb <= 8:
        failures.append(('bound arithmetic climb limit missing or unbounded', climb))
    if not isinstance(hops, int) or not 0 < hops <= 64:
        failures.append(('bound scope hop limit missing or unbounded', hops))
    if 'visited > ' not in flat_axis or '_CWE338_BOUND_SCOPE_NODE_LIMIT: return False' not in flat_axis:
        failures.append(('the cap is not enforced inside the walk', '_CWE338_BOUND_SCOPE_NODE_LIMIT'))
    # Wiring: asked exactly once, from inside the display-draw guard, after the marker loop and ahead of
    # the path axis -- so a module path can never be the reason a draw is quiet when its own chain is
    # unproven, and so no second emitter can fork this answer.
    module_lines = inspect.getsource(ast_scanner).splitlines()
    n_axis = sum(1 for line in module_lines if 'self._cwe338_draw_is_loop_bound_only(' in line)
    after_marker = draw_src.find('CWE338_DISPLAY_VALUE_MARKERS for segment in segments')
    at_axis = draw_src.find('self._cwe338_draw_is_loop_bound_only(')
    before_path = draw_src.find('self._cwe338_module_is_demo_generator(')
    print(f'  wiring: call sites={n_axis} in-guard={at_axis >= 0} '
          f'after-marker={0 <= after_marker < at_axis} ahead-of-path={0 <= at_axis < before_path}')
    if n_axis != 1 or not (0 <= after_marker < at_axis < before_path):
        failures.append(('bound axis wiring moved', (n_axis, after_marker, at_axis, before_path)))
    return failures


def check_path_rows():
    """TIER 5: the demo path exempts fake data and nothing else -- 6 quiet spellings, 9 tripwires.

    Every row here is scanned through the real record path with its own module name, so this tier is
    the behavioural proof for `CWE338_DEMO_PATH_SEGMENTS`: the three spellings of `populate` must go
    quiet, and a credential name, a `.join`, a byte-shape leaf, a `tests/` directory, a `test_` module
    or a missing scope must all stay loud.
    """
    failures = []
    for label, modname, source, expected in PATH_ROWS:
        found = scan_cwe338(source, modname)
        status = REPORT if found else QUIET
        note = '; '.join(f'L{n}:{m.replace("CWE-338: ", "")}' for n, m in found)[:44]
        print(f'  {label:34s} module={modname[:34]:34s} want={expected:5s} got={status:5s} '
              f'{"ok" if status == expected else "MISMATCH"} {note}')
        if status != expected:
            failures.append((label, 'the demo-path boundary moved', expected, status))
    return failures


def check_bound_rows():
    """TIER 6: the loop-bound boundary, decided by the seal -- 7 count shapes and 14 look-alikes.

    Scanned through the real record path, so this is the behavioural proof of the def-use rule. At
    `BOUND_SEAL='shipped'` the 7 count-shaped draws are quiet and the attribution half runs: each is
    re-scanned with the axis blinded and must go loud, because a row could otherwise be quiet on a marker
    word or the demo path and the gate would be crediting an axis that never fired (the law this repository
    already wrote for the CWE-22 prune: "a gate that explains a silence must be able to name which
    disjunct bought it").

    At `BOUND_SEAL='withdrawn'` -- the shipped state -- every one of the 21 rows must report. The 7 are
    then the false-positive price of the withdrawal, kept on the table rather than tidied away, and the 14
    tripwires mean the same thing in both states. `loop_bound_pitch_shipped` re-installs the withdrawn
    guard in memory and is caught by exactly these 7 rows.
    """
    failures = []
    shipped = BOUND_SEAL == 'shipped'
    if shipped:
        blinded = []
        original = ast_scanner.TaintTracker._cwe338_draw_is_loop_bound_only
        try:
            ast_scanner.TaintTracker._cwe338_draw_is_loop_bound_only = (
                lambda self, node, scope_id: False)
            for label, source, _expected in BOUND_ROWS:
                if label in BOUND_QUIET_ROWS and scan_cwe338(source):
                    blinded.append(label)
        finally:
            ast_scanner.TaintTracker._cwe338_draw_is_loop_bound_only = original
        print(f'  silence bought by this axis (loud when blinded): {len(blinded)} of {len(BOUND_QUIET_ROWS)}')
        if blinded != BOUND_QUIET_ROWS:
            failures.append(('a bound row is quiet for a reason other than the axis',
                             sorted(set(BOUND_QUIET_ROWS) - set(blinded))))
    else:
        print(f'  axis withdrawn: {len(BOUND_QUIET_ROWS)} count-shaped draws stay loud (the measured '
              f'price: 2 arena rows, at +54.940 us per refused ask) -- no silence to attribute')
    for label, source, pitch_want in BOUND_ROWS:
        expected = pitch_want if shipped else REPORT
        found = scan_cwe338(source)
        status = REPORT if found else QUIET
        note = '; '.join(f'L{n}:{m.replace("CWE-338: ", "")}' for n, m in found)[:44]
        print(f'  {label:20s} pitch={pitch_want:5s} want={expected:5s} got={status:5s} '
              f'{"ok" if status == expected else "MISMATCH"} {note}')
        if status != expected:
            failures.append((label, 'the loop-bound boundary moved', expected, status))
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
    print('TIER 5 - the demo path exempts fake data only, in all three spellings:')
    failures += check_path_rows()
    print('TIER 6 - the loop-bound boundary, by BOUND_SEAL:')
    failures += check_bound_rows()
    print(f'\nseal={PRNG_CTX_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'path_rows={len(PATH_ROWS)} demo_quiet={len(DEMO_QUIET_ROWS)} '
          f'demo_tripwires={len(DEMO_TRIPWIRE_ROWS)} '
          f'bound_seal={BOUND_SEAL} bound_rows={len(BOUND_ROWS)} '
          f'bound_quiet={len(BOUND_QUIET_ROWS)} '
          f'bound_loud={len(BOUND_LOUD_ROWS)} '
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
          + f', {len(DEMO_QUIET_ROWS)} demo-data paths exempted and {len(DEMO_TRIPWIRE_ROWS)} '
            'demo-path tripwires still loud, '
          + (f'{len(BOUND_QUIET_ROWS)} loop-bound draws exempted on their def-use chain and '
             f'{len(BOUND_LOUD_ROWS)} bound-looking shapes still loud' if BOUND_SEAL == 'shipped' else
             f'the loop-bound axis WITHDRAWN (2 arena rows for +54.940 us per refused ask), so all '
             f'{len(BOUND_ROWS)} shapes report: {len(BOUND_QUIET_ROWS)} count draws stay reported -- the '
             f'measured price of the withdrawal -- and the {len(BOUND_LOUD_ROWS)} look-alikes (subscript, '
             'slice, other call, return, never-read, module scope, shadowed range, credential name, tuple '
             'unpack, aug-assign, container append, starred and keyword slots) are refused on their own '
             'right') + '.')
    return 0


# --- the withdrawn loop-bound axis, kept here so the refusal stays falsifiable -------------------------
# The engine no longer carries this guard (`BOUND_SEAL='withdrawn'`: 2 arena rows for +54.940 us on every
# ask that refused it). The implementation is restated below -- self-contained, over the same primitives
# the engine still ships (`_scope_module`, `_module_shadowed_names`, `_cwe338_name_is_security_named`,
# the `.parent` links) -- and `loop_bound_pitch_shipped` installs it over the live display-draw guard. So
# the truth table bites the pitch on exactly the rows the pitch would silence, which is Rule 15.5 rung 6:
# a refusal handed back with a falsification of the pitch's own row, not with a comment.
PITCH_BOUND_CALLS = frozenset({'range', 'xrange'})
PITCH_ARITH_OPS = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow)
PITCH_CLIMB_LIMIT = 6
PITCH_SCOPE_HOPS = 64
PITCH_NODE_LIMIT = 800

# Captured at import, before any mutation is installed, so the pitch is a *second* answer layered over the
# shipped one rather than a replacement of it.
_PRISTINE_DISPLAY_ONLY_DRAW = ast_scanner.TaintTracker._cwe338_display_only_draw


def _pitch_consumers(tracker, scope_id):
    """`PITCH_BOUND_CALLS` minus what the scanned module binds itself; unresolved module means no axis."""
    mod_name = tracker._scope_module(scope_id)
    if not mod_name:
        return frozenset()
    return PITCH_BOUND_CALLS - tracker._module_shadowed_names(mod_name)


def _pitch_consumer_hit(expr, allowed, accept_selection=False, accept_any_call=False):
    """Is this value an argument of a recognised bound consumer, through arithmetic only?"""
    current = expr
    for _ in range(PITCH_CLIMB_LIMIT):
        parent = getattr(current, 'parent', None)
        if parent is None:
            return False
        if isinstance(parent, ast.BinOp) and isinstance(parent.op, PITCH_ARITH_OPS):
            current = parent
            continue
        if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, (ast.UAdd, ast.USub)):
            current = parent
            continue
        break
    parent = getattr(current, 'parent', None)
    if accept_selection and isinstance(parent, (ast.Subscript, ast.Slice)):
        return True
    if not isinstance(parent, ast.Call):
        return False
    if accept_any_call:
        return any(arg is current for arg in list(parent.args) + [kw.value for kw in parent.keywords])
    if not isinstance(parent.func, ast.Name) or parent.func.id not in allowed:
        return False
    return any(arg is current for arg in parent.args)


def _pitch_enclosing_function(node):
    current = node
    for _ in range(PITCH_SCOPE_HOPS):
        parent = getattr(current, 'parent', None)
        if parent is None:
            return None
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return parent
        current = parent
    return None


def _pitch_axis(tracker, node, scope_id, accept_selection=False, accept_any_call=False,
                credential_veto=True, accept_unread=False):
    """The withdrawn guard, verbatim in its control flow, with each refused door toggleable.

    Every door here was a mutation when the axis shipped, and each one is still a mutation now: a variant
    that goes on to silence a tripwire row is the proof that the door was load-bearing.
    """
    allowed = _pitch_consumers(tracker, scope_id)
    if not allowed:
        return False
    if _pitch_consumer_hit(node, allowed, accept_selection, accept_any_call):
        return True
    parent = getattr(node, 'parent', None)
    if isinstance(parent, ast.AugAssign):
        return False
    if not isinstance(parent, (ast.Assign, ast.AnnAssign)):
        return False
    targets = list(getattr(parent, 'targets', None) or [parent.target])
    names = [t.id for t in targets if isinstance(t, ast.Name)]
    if not names or len(names) != len(targets):
        return False
    if credential_veto and any(tracker._cwe338_name_is_security_named(name) for name in names):
        return False
    if accept_unread:
        return True
    scope = _pitch_enclosing_function(node)
    if scope is None:
        return False
    wanted = frozenset(names)
    seen = False
    visited = 0
    for child in ast.walk(scope):
        visited += 1
        if visited > PITCH_NODE_LIMIT:
            return False
        if not isinstance(child, ast.Name) or child.id not in wanted:
            continue
        if not isinstance(child.ctx, ast.Load):
            continue
        if not _pitch_consumer_hit(child, allowed, accept_selection, accept_any_call):
            return False
        seen = True
    return seen


def _pitch_display_draw(**flags):
    """A `_cwe338_display_only_draw` that keeps the shipped answer and adds the withdrawn axis under it."""
    def _patched(self, node, scope_id):
        if _PRISTINE_DISPLAY_ONLY_DRAW(self, node, scope_id):
            return True
        return _pitch_axis(self, node, scope_id, **flags)

    return _patched


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
    # Both path mutations patch the shipped Step-2 guard. `requires` still names the symbol, so if the
    # guard is ever removed the driver refuses to claim a falsification and exits 2 instead of 1.
    'no_populate_segment': {
        'what': 'delete the odoo demo-data path guard (populate rows come back loud)',
        'rows': list(DEMO_QUIET_ROWS),
        'requires': 'CWE338_DEMO_PATH_SEGMENTS',
        'apply': lambda: setattr(ast_scanner, 'CWE338_DEMO_PATH_SEGMENTS', frozenset()),
    },
    'widen_to_tests_segment': {
        'what': 'widen the path guard to tests/test and delete both test vetoes -- measured to reach '
                '14 of the 16 blessed keys',
        'rows': ['tests-plain-stays-loud', 'populate-under-tests-stays-loud',
                 'test-prefix-module-stays-loud'],
        'requires': 'CWE338_DEMO_PATH_SEGMENTS',
        'apply': lambda: (
            setattr(ast_scanner, 'CWE338_DEMO_PATH_SEGMENTS',
                    frozenset({'populate', 'populators', 'tests', 'test'})),
            setattr(ast_scanner, 'CWE338_DEMO_PATH_VETO_SEGMENTS', frozenset()),
            setattr(ast_scanner, 'CWE338_DEMO_PATH_VETO_PREFIXES', ())),
    },
    # --- the withdrawn loop-bound axis -------------------------------------------------------------
    # Nine mutations used to patch this guard's own methods in the engine. The guard is not in the engine,
    # so they would all have exited 2; they are rebuilt as six self-contained variants of `_pitch_axis`
    # installed over the live display-draw guard, which means every one of them runs and bites today. Each
    # `rows` list is the set the variant silences, measured by running it -- not assumed.
    'loop_bound_pitch_shipped': {
        'what': 'install the withdrawn loop-bound def-use axis exactly as it was built (this is the '
                'refusal: 2 arena rows for +54.940 us per refused ask, so TIER 6 must call these 7 loud)',
        'rows': list(BOUND_QUIET_ROWS),
        'requires': None,
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_cwe338_display_only_draw',
                                 _pitch_display_draw()),
    },
    'bound_pitch_accepts_selection': {
        'what': "ship the mandate's literal reading -- a subscript index or a slice bound counts as a "
                'bound. This is the refusal, and it is a false negative, not a style choice: the same '
                'door silences two OTP/code-assembling rows that have nothing to do with a loop',
        'rows': list(BOUND_QUIET_ROWS) + ['subscript_select', 'slice_select',
                 'otp_from_digits_index', 'wait_alphabet_index_join'],
        'requires': None,
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_cwe338_display_only_draw',
                                 _pitch_display_draw(accept_selection=True)),
    },
    'bound_pitch_accepts_any_call': {
        'what': 'widen the consumer from range/xrange to any callee, positional or keyword slot',
        'rows': list(BOUND_QUIET_ROWS) + ['other_call', 'shadowed_range', 'list_append', 'str_concat',
                 'reset_token', 'salt_getrandbits', 'seconds_join_digits', 'cooldown_getrandbits',
                 'big8_vocab_append', 'demo-populate-join-code', 'tests-plain-stays-loud'],
        'requires': None,
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_cwe338_display_only_draw',
                                 _pitch_display_draw(accept_any_call=True)),
    },
    'bound_pitch_always_true': {
        'what': 'answer "just a count" for every draw -- a rule delete dressed as a provenance test '
                '(measured: all 21 bound shapes plus 29 credential, blessed-line, CSPRNG and demo rows)',
        'rows': list(BOUND_QUIET_ROWS) + list(BOUND_LOUD_ROWS) + ['+ 29 TIER 3/5 rows'],
        'requires': None,
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_cwe338_display_only_draw',
                                 lambda self, node, scope_id: True),
    },
    'bound_pitch_accepts_unread': {
        'what': 'exempt an assigned draw that is never read -- a decision taken on an absence, and it '
                'then over-reaches to every assigned shape (module scope included)',
        'rows': list(BOUND_QUIET_ROWS) + ['subscript_select', 'slice_select', 'other_call', 'never_read',
                 'module_scope', 'shadowed_range', 'returned_value', 'list_append', 'str_concat',
                 'starred_args', 'keyword_slot', 'randbytes_draw', 'big8_global_rng_ctor',
                 'demo-populate-rng-ctor', 'demo-populate-getrandbits', 'test-prefix-module-stays-loud',
                 'populate-under-tests-stays-loud', 'no-scope-plain-draw-stays-loud'],
        'requires': None,
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_cwe338_display_only_draw',
                                 _pitch_display_draw(accept_unread=True)),
    },
    'bound_pitch_drops_credential_veto': {
        'what': 'remove the credential veto re-check that lives inside the axis (defence in depth: the '
                'guard-level veto holds the same row, so this variant proves the in-body one is real)',
        'rows': ['credential_named'],
        'requires': None,
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_cwe338_display_only_draw',
                                 _pitch_display_draw(credential_veto=False)),
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
    print('TIER 5 - the demo path exempts fake data only:')
    failures += check_path_rows()
    print('TIER 6 - the loop-bound def-use axis exempts a count, never a selection:')
    failures += check_bound_rows()
    for item in failures:
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
