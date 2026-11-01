"""CWE-208 truth table: which `==`/`!=` on a token-named value is a secret check and which is an LLM
usage counter.

Why this gate exists
--------------------
`TIMING_ATTACK` fires on any comparison whose operand *names* contain "token". "token" is also the
substring of every LLM usage counter in existence, which makes CWE-208 the largest false-positive
family on the pinned LiteLLM tree: 2,780 rows over 762 files (scratch/_litellm_scan.json), and
scratch/_p208size.py partitions the lines that carry a trigger name into

      1381  LOUD   security-flavoured name on the line
       848  LOUD   trigger name present, but not a metric shape
       351  SUPPRESS all triggering names are metric shapes
       200  --     no trigger name on the line at all (not reachable from this emitter)

The emitter
-----------
  ast_scanner.py `_collect_batch4_structural_findings` (:18621) walks every `ast.Compare` and emits
  when all four hold: the operator is `Eq`/`NotEq`, no `compare_digest` appears in the subtree, at
  least one `ast.Name` id carries a sensitive marker (`token`, `secret`, `signature`, `hmac`,
  `api_key`, `auth_token`), and `_compares_two_secrets(node)` says no operand is a literal. That is
  the only CWE-208 emitter in the engine, so there is one place to answer the question and no
  multi-path mirroring to keep in step.

The narrowing this gate locks
-----------------------------
`_c208_timing_is_llm_token_metric` (:18604) may only silence a comparison that is *nothing but* a
usage counter, and it fails closed in three separate ways:

  * credential veto first: if any name or attribute tail of the comparison carries a credential word
    (`CWE208_CREDENTIAL_NAME_WORDS` -- auth, access, session, csrf, bearer, api, signature, secret,
    hash, salt, hmac, password, credential, private, digest, verify, jwt, oauth), the answer is loud,
    whatever the shapes say. This is what keeps `prompt_tokens == response.api_key` reported;
  * every triggering name must be metric-shaped, not one of them -- so
    `prompt_tokens == auth_token` is loud, and so is `total_tokens == session_token_count`;
  * "metric-shaped" is structural (`_c208_name_is_llm_token_metric`, :18584): `<...>_<role>_<token|
    tokens>` with `<role>` one of the six words the mandate named (prompt, completion, total, max,
    chunk, usage), or one of the four whole-name counter spellings (`token_count`, `token_usage`,
    `tokens_used`, `token_sum`), with trailing digits dropped so `prompt_tokens_1` still reads.

The structural rule, not the substring rule the mandate drafted, is the load-bearing choice and this
gate is where it is argued: `re.search(r"(prompt|completion|total|max|chunk|usage)_tokens?", name)`
matches `generated_tokens`, `old_num_tokens`, `special_tokens_mask` and `next_tokens` -- and those four
names sit on blessed Big-8 true positives. TIER 2 re-reads every one of the 30 frozen timing lines and
refuses if *any* identifier on it would pass the metric test, so the mutation
`metric_rule_to_substring` (which installs exactly that substring reading) fails here rather than in
production. The same mutation is why `input_tokens` / `output_tokens` / `reasoning_tokens` deliberately
stay LOUD: they are real usage counters, but an `output_token` can also be an issued credential, so
widening the prefix table is a follow-up with its own measurement, not a free win inside this change.

Measured evidence behind the numbers
-----------------------------------
  blessed overlap            : CWE-208 keys -- 6 in parity, 30 in Big-8, counted from the frozen key
                               files (TIER 1). All 30 Big-8 lines were read back from the hash-verified
                               corpus and none carries a metric-shaped identifier (TIER 2); all 6
                               parity fixtures are `request_token == stored_token`-shaped secret
                               comparisons, which fail the shape test and are covered by the credential
                               veto a second time.
  fixtures                   : 30 shapes, each pair verified against HEAD's bytes before this file
                               claimed them (scratch/_abstained_check.py -- all 20 of the first batch
                               are LOUD on HEAD, and the 3 dimension shapes are LOUD on the shipped
                               engine): 6 counter shapes go LOUD->QUIET and 23 stay LOUD, which
                               includes the 6 blessed parity spellings, the 5 Big-8 name shapes TIER 3
                               re-reads from the corpus, the honest `input_tokens == output_tokens`
                               residual, the 3 refused dimension/`len()`/integer shapes and the 7
                               refused sentinel shapes of TIER 3b. One shape
                               (`sentinel_literal_zero`) is quiet under both seals because the emitter
                               itself rejects a bare-Constant operand, which is a fact about the rule
                               and not about any exemption.

A third pitch, refused the same way
----------------------------------
  The mandate after that asked for a narrower-sounding rule: "in the CWE-208 compare collector, silence
  a comparison ONLY when one operand is a known constant/special-token sentinel (e.g. 0, -1, -100,
  None) and neither operand traces to cryptographic secrets", with an explicit local verification
  request that whisper:314 (`dim_shape_compare`) must not go quiet. TIER 3b scores four readings of
  "is a sentinel" on the *emitting* compare of all 36 blessed CWE-208 lines and freezes the counts:
  `literal=0, bound=0, named=12, contains=9` on Big-8 and all four at 0 on parity. The two readings the
  mandate names first are empty for a structural reason the engine itself explains -- a compare with a
  bare `ast.Constant` operand is rejected by `_compares_two_secrets` before any exemption is asked, and
  no blessed module binds a sentinel name -- and a census of the same two readings over every .py file
  on this machine (670 files: both corpora, the gates, pygoat, the demo project) also returns 0 rows.
  So the pitch has no false-positive population to retire here at all; its only reach is the 12 blessed
  lines the `named` reading takes (`input_ids == bos_token_id`, `batch_ids == pad_token_id`,
  `out != tokenizer.pad_token_id`, `special_tokens_mask == not_padded_special_tokens_mask`, the four
  markuplm padding rows, `sep_token_id == self.config.pad_token_id`), plus 9 more under a looser
  "operand merely contains one" reading (`selected_tokens[:, :-1]`, `decoder_start_token_id.shape[0]`).
  The rescue clause does work -- `auth_token == INVALID_TOKEN` stays loud under the installed pitch,
  which is why `sentinel_vs_credential` is a keeps-loud row and not a failure -- and it does not help:
  none of the 12 blessed names carries a credential word. The mandate's own verification request is
  answered twice: TIER 3b prints `whisper:314 reached_by=[]`, and the `sentinel_pitch_shipped`
  mutation re-scans `dim_shape_compare` with the pitch installed and must find it loud.
  Measured on the shipped engine: `seal=shipped shapes=30 fp_rows=6 must_report=23 already_quiet=1
  pairs=2 name_rows=36 sentinel_rows=7 locked_cwe208=36 failures=0`, and 7 falsifications exit 1.

A second pitch, refused the same way
------------------------------------
  The next mandate asked for a different rule: "suppress a comparison of array dimensions, tensor
  attributes (`.shape`) or integer constants, unless a variable name holds one of secret/key/auth/
  nonce/hash/password/signature/mac". TIER 3 now measures that predicate against the 30 frozen Big-8
  lines themselves (`reachable_by_dimension_rule=2`, `reachable_by_nonstring_rule=28`, and one more of
  the 6 parity lines), and the `dimension_pitch_shipped` mutation proves the reach is not a paper
  claim: installing the rule in the engine silences `dim_shape_compare`, which is
  `tests__models__whisper__test_modeling_whisper.py:314` spelled verbatim. The rescue clause does not
  save it -- no name on that line (`next_tokens`, `output_from_past_slice`, `shape`) holds any of the
  eight words. A rule whose blessed-key reach is nonzero is refused, so this file freezes both numbers
  and the third mutation count.

Seal semantics - `CWE208_SEAL`
------------------------------
  'shipped'   : the 6 counter shapes MUST be silent, `sentinel_literal_zero` MUST be silent under both
                seals (the emitter rejects it), and every other row MUST stay loud.
  'abstained' : the engine before the metric test landed -- the 6 counter shapes are loud again and
                every tripwire stays loud. A counter shape that goes quiet while the seal says
                abstained means a narrowing landed without a contract.
Either way a mismatch is exit 1.
"""
from __future__ import annotations

import ast
import collections
import contextlib
import inspect
import io as _io
import os
import re
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

if os.environ.get('TCS_CWE208_ENGINE'):
    # falsification hook: load an alternative ast_scanner.py and let the gate argue against it. The
    # module is registered under its real name because `dataclass(slots=True)` and `cli` both resolve
    # the engine through sys.modules.
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        'ast_scanner', os.environ['TCS_CWE208_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, corpus_dir, load_keys, scan_rows, verify_corpus  # noqa: E402

CWE208_SEAL = 'shipped'   # 'abstained' = the engine before the metric test landed
SEAL_TARGETS = ('abstained', 'shipped')

# The blessed CWE-208 population, counted from the frozen baselines themselves.
CWE208_LOCKED = {'parity': 6, 'big8': 30}

_IDENTIFIER_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')

# (label, source, expect_when_abstained, expect_when_shipped)
SHAPES = [
    # ---- usage counters: every triggering name is a metric, and no credential word is in sight ----
    ('prompt_vs_completion', '''
def quota(prompt_tokens, completion_tokens):
    return prompt_tokens == completion_tokens
''', 'loud', 'quiet'),
    ('total_vs_max', '''
def fits(total_tokens, max_tokens):
    return total_tokens != max_tokens
''', 'loud', 'quiet'),
    ('attr_and_name_metric', '''
def check(usage, total_tokens):
    return usage.total_tokens == total_tokens
''', 'loud', 'quiet'),
    ('token_count_word', '''
def over(token_count, limit):
    return token_count == limit
''', 'loud', 'quiet'),
    ('digit_suffix', '''
def diff(prompt_tokens_1, prompt_tokens_2):
    return prompt_tokens_1 == prompt_tokens_2
''', 'loud', 'quiet'),
    ('both_prefixed_metrics', '''
def audit(request_max_tokens, reported_max_tokens):
    return request_max_tokens == reported_max_tokens
''', 'loud', 'quiet'),
    # ---- the six blessed parity shapes, spelled as the corpus spells them ----
    ('blessed_request_token', '''
def check(request_token, stored_token):
    return request_token == stored_token
''', 'loud', 'loud'),
    ('blessed_secret', '''
def check(provided_secret, expected_secret):
    return provided_secret != expected_secret
''', 'loud', 'loud'),
    ('blessed_api_key', '''
VALID_API_KEY = "x"

def check(api_key):
    return api_key == VALID_API_KEY
''', 'loud', 'loud'),
    ('blessed_signature', '''
def check(computed_signature, request_signature):
    return computed_signature == request_signature
''', 'loud', 'loud'),
    ('blessed_hmac', '''
def check(received_hmac, expected_hmac):
    return received_hmac == expected_hmac
''', 'loud', 'loud'),
    ('blessed_auth_token', '''
def check(auth_token):
    return auth_token == SESSION_TOKEN
''', 'loud', 'loud'),
    # ---- the tripwires the vetoes exist for ----
    ('metric_vs_credential', '''
def check(prompt_tokens, auth_token):
    return prompt_tokens == auth_token
''', 'loud', 'loud'),
    ('metric_with_api_attr', '''
def check(prompt_tokens, response):
    return prompt_tokens == response.api_key
''', 'loud', 'loud'),
    ('session_token_count', '''
def check(total_tokens, session_token_count):
    return total_tokens == session_token_count
''', 'loud', 'loud'),
    # ---- blessed Big-8 spellings, read from the corpus lines TIER 2 re-checks ----
    ('generated_tokens_count', '''
def check(expectation, generated_tokens):
    return expectation == len(generated_tokens[0])
''', 'loud', 'loud'),
    ('special_tokens_mask', '''
def check(special_tokens_mask, not_padded_special_tokens_mask):
    return special_tokens_mask == not_padded_special_tokens_mask
''', 'loud', 'loud'),
    ('old_num_tokens', '''
def check(old_num_tokens, new_num_tokens):
    return old_num_tokens == new_num_tokens
''', 'loud', 'loud'),
    ('pad_token_id', '''
def check(sep_token_id):
    return sep_token_id == self.config.pad_token_id
''', 'loud', 'loud'),
    # honest residual: a real usage counter this change deliberately does NOT exempt, so a future
    # widening of the prefix table has to be a decision, not a typo.
    ('input_output_residual', '''
def check(input_tokens, output_tokens):
    return input_tokens == output_tokens
''', 'loud', 'loud'),
    # ---- the shape pitch of the next mandate, refused on measurement and frozen here ----
    # "suppress a compare of array dimensions / tensor attributes / integer constants unless a name
    # holds one of secret,key,auth,nonce,hash,password,signature,mac". TIER 3 measures the predicate
    # against the blessed corpus lines: 2 of 30 Big-8 lines are dimension-shaped with no rescue word,
    # and 28 of 30 (29 of all 36) are "no string operand". Engine level, the `dimension_pitch_shipped`
    # mutation proves `dim_shape_compare` (blessed whisper:314) is emittable *and* dimension-shaped, so
    # the pitch deletes a real finding. It also bounds the other row honestly: on
    # `len_over_mask_compare_int` the emitter is asked twice and answers False on the outer compare, so
    # that finding rides the inner `batch_ids != pad_token_id`, which no dimension reading of the pitch
    # reaches. One proven death is still a false negative, and the refusal does not need the second.
    # All three rows stay 'loud' under BOTH seals, so shipping the pitch moves TIER 4.
    ('dim_shape_compare', '''
def check(next_tokens, output_from_past_slice):
    return output_from_past_slice.shape[1] == next_tokens.shape[1]
''', 'loud', 'loud'),      # blessed tests__models__whisper__test_modeling_whisper.py:314
    ('len_over_mask_compare_int', '''
def check(batch_ids, pad_token_id):
    return len(batch_ids[batch_ids != pad_token_id]) == 1
''', 'loud', 'loud'),      # blessed src__transformers__generation__utils.py:3103
    ('shape_zero_vs_batch_size', '''
def check(decoder_start_token_id, batch_size):
    return decoder_start_token_id.shape[0] != batch_size
''', 'loud', 'loud'),      # blessed src__transformers__generation__utils.py:1077, wide reading only
    # ---- the sentinel pitch of the mandate after that one, refused by TIER 3b and frozen here ----
    # `pad_token_id == -100` looks like the pitch's own example, yet the shipped engine reports it: a
    # negative literal parses as UnaryOp(USub, Constant(100)), so `_compares_two_secrets` does not see a
    # Constant and the row reaches the guards. It stays loud whatever the sentinel reading says.
    ('sentinel_literal_negative', '''
def check(pad_token_id):
    return pad_token_id == -100
''', 'loud', 'loud'),
    # ... while the *positive* spelling is already silent, and always was: a bare Constant operand is
    # rejected by the emitter itself, which is why the `literal` reading measures 0 blessed lines.
    ('sentinel_literal_zero', '''
def check(total_tokens):
    return total_tokens == 0
''', 'quiet', 'quiet'),
    ('sentinel_bound_pad', '''
PAD_TOKEN_ID = -100

def check(input_ids):
    return input_ids == PAD_TOKEN_ID
''', 'loud', 'loud'),
    # the blessed parity spelling with a `None` initialiser: the pitch's own sentinel, on a real secret
    # comparison. This is the row that makes the refusal a false-negative argument, not a taste one.
    ('sentinel_bound_none', '''
stored_token = None

def check(request_token):
    return request_token == stored_token
''', 'loud', 'loud'),
    ('sentinel_batch_vs_pad', '''
def check(batch_ids, pad_token_id):
    return batch_ids == pad_token_id
''', 'loud', 'loud'),      # blessed src__transformers__generation__utils.py:3074 verbatim
    ('sentinel_slice_contains', '''
def check(selected_tokens, candidate_new_tokens):
    return candidate_new_tokens == selected_tokens[:, :-1]
''', 'loud', 'loud'),      # blessed :4120 - reached only by the looser "operand contains one" reading
    # the pitch's rescue clause, shown working: a credential word on the line holds this loud even
    # under the pitch, so the refusal is "the veto does not cover the blessed names", not "no veto".
    ('sentinel_vs_credential', '''
INVALID_TOKEN = -1

def check(auth_token):
    return auth_token == INVALID_TOKEN
''', 'loud', 'loud'),
]

FP_ROWS = [row for row in SHAPES if row[2] == 'loud' and row[3] == 'quiet']
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == 'loud']
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == 'quiet']
SENTINEL_SHAPES = [row for row in SHAPES if row[0].startswith('sentinel_')]

# The same counter with and without a credential in the comparison. A narrowing keyed on the shape of
# one operand alone would answer both arms alike.
PAIRS = [
    ('both operands metric vs one secret', '''
def check(prompt_tokens, completion_tokens):
    return prompt_tokens == completion_tokens
''', '''
def check(prompt_tokens, auth_token):
    return prompt_tokens == auth_token
'''),
    ('bare counter vs counter with a credential-tailed attribute', '''
def check(prompt_tokens, response):
    return prompt_tokens == response.length
''', '''
def check(prompt_tokens, response):
    return prompt_tokens == response.api_key
'''),
]

# The vocabulary, pinned so a later edit has to argue with this file before it can widen the rule.
PREFIXES_REQUIRED = frozenset({'prompt', 'completion', 'total', 'max', 'chunk', 'usage'})
TAILS_REQUIRED = frozenset({'token', 'tokens'})
CREDENTIAL_WORDS_REQUIRED = ('auth', 'access', 'session', 'csrf', 'bearer', 'api', 'signature',
                             'secret', 'hash', 'salt', 'hmac')
# name -> must the engine read it as a usage counter? Every False below is a blessed Big-8 name.
NAME_SHAPE_ROWS = [
    ('prompt_tokens', True), ('completion_tokens', True), ('total_tokens', True),
    ('max_tokens', True), ('chunk_tokens', True), ('usage_tokens', True),
    ('request_max_tokens', True), ('prompt_tokens_1', True), ('token_count', True),
    ('token_usage', True), ('tokens_used', True), ('token_sum', True),
    ('generated_tokens', False), ('old_num_tokens', False), ('new_num_tokens', False),
    ('special_tokens_mask', False), ('next_tokens', False), ('validated_tokens', False),
    ('selected_tokens', False), ('pad_token_id', False), ('sep_token_id', False),
    ('token_type_ids', False), ('request_token', False), ('stored_token', False),
    ('auth_token', False), ('access_token', False), ('session_token', False),
    ('csrf_token', False), ('bearer_token', False), ('api_token', False),
    ('token_state', False), ('input_tokens', False), ('output_tokens', False),
    ('reasoning_tokens', False), ('special_token', False), ('token_id_key', False),
]


def scan_source(source):
    """One in-memory module through the real record path, as both baselines were built."""
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-208'})


def is_metric(name: str) -> bool:
    """The shipped shape test, reached the way the collector reaches it."""
    return bool(ast_scanner.TaintTracker._c208_name_is_llm_token_metric(name))


def check_floors():
    """TIER 1: the blessed CWE-208 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-208'}
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-208={len(keys)} (want {CWE208_LOCKED[kind]})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != CWE208_LOCKED[kind]:
            failures.append((kind, 'CWE-208', CWE208_LOCKED[kind], len(keys),
                             'the blessed CWE-208 population moved'))
    return failures


def check_corpus():
    """TIER 2: the CWE-208 keys re-produced by a real tree scan, as an exact key set."""
    failures = []
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    live = {row for row in scan_rows('parity', tree) if row[2] == 'CWE-208'}
    frozen = {row for row in load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
              if row[2] == 'CWE-208'}
    missing = sorted(frozen - live)
    extra = sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    for row in missing:
        print(f'  MISSING  {row[0]}:{row[1]} {row[4]}')
    for row in extra:
        print(f'  NEW      {row[0]}:{row[1]} {row[4]}')
    if missing:
        failures.append((len(missing), 'frozen CWE-208 keys no longer reported'))
    if extra:
        failures.append((len(extra), 'CWE-208 keys appeared that the baseline never held'))
    return failures


# ---- the refused shape pitch, evaluated as a *predicate over the corpus*, not as engine code ----
# Reaching a blessed key is what makes a pitch a false negative, and a baseline can only show that
# after the fact. So the two readings of the pitch are re-evaluated here on the blessed lines
# themselves, from their AST, and the counts are frozen: `2` rows for the strict ".shape / len() /
# integer constant" reading, `28` of 30 for the wide "non-string operand" reading. The same predicate
# over the six blessed parity lines adds one more wide hit (`request_token == stored_token`), i.e. 29
# of all 36 blessed timing lines. Any change to either number is a change to the argument, and has to
# be made deliberately.
PITCH_RESCUE_WORDS = ('secret', 'key', 'auth', 'nonce', 'hash', 'password', 'signature', 'mac')
PITCH_DIM_RE = re.compile(r'\.shape\b|\blen\(|\.size\b|\bdims\b')
PITCH_REACH = {'dimension': 2, 'nonstring': 28}

# ---- the third pitch, from the mandate after it: the pad/constant sentinel shape ----
# "In the CWE-208 compare collector, silence a comparison ONLY when one operand is a known
# constant/special-token sentinel (e.g. 0, -1, -100, None) and neither operand traces to a
# cryptographic secret." "Is a sentinel" has four defensible readings, and TIER 3b scores all four on
# the *emitting* compare of every blessed CWE-208 line. The frozen counts say the pitch has no
# population except the true positives it would delete:
#
#   literal  an operand really is `0` / `-1` / `-100` / `None`   -> 0 blessed lines
#   bound    an operand is a name written exactly once, at module level, to one of those -> 0
#   named    an operand's own name reads like a special-token id (pad/eos/bos/sep/...) -> 12
#   contains an operand merely *holds* one of them (`[:, :-1]`, `[0]`, `[1] * padding`) -> 9
#
# `literal` and `bound` measure 0 because a bare-`Constant` compare never reaches the guards at all
# (`_compares_two_secrets` rejects it) and no blessed line binds a module-level sentinel name -- a
# census of the same two readings over all 670 .py files on this machine (both baselines, the gates,
# pygoat, the demo project) also returns 0. So the only reading with a population is `named`, and all
# 12 of its rows are blessed Big-8 keys: `input_ids == bos_token_id`, `batch_ids == pad_token_id`,
# `out != tokenizer.pad_token_id`, `special_tokens_mask == not_padded_special_tokens_mask`, the four
# markuplm padding rows. Refused, and frozen here so the next attempt has to move these numbers
# deliberately rather than by accident.
SENTINEL_VALUES = (0, -1, -100, None)
SENTINEL_NAME_WORDS = ('pad', 'eos', 'bos', 'sep', 'cls', 'ignore', 'unknown', 'sentinel')
SENTINEL_READINGS = ('literal', 'bound', 'named', 'contains')
SENTINEL_REACH = {'parity': {'literal': 0, 'bound': 0, 'named': 0, 'contains': 0},
                  'big8': {'literal': 0, 'bound': 0, 'named': 12, 'contains': 9}}
SENTINEL_PITCH_REACH = {'parity': 0, 'big8': 12}
# The mandate's own verification request, spelled as an assertion: the whisper dimension compare must
# not be reachable by any sentinel reading (it is reachable by the *dimension* pitch above, which is
# why that one was refused first).
WHISPER_LEAF = 'tests__models__whisper__test_modeling_whisper.py'
WHISPER_LINE = 314
# The emitter's own trigger tuple, mirrored so TIER 3b scores the compare the emitter would score.
CWE208_EMIT_MARKERS = ("token", "secret", "signature", "hmac", "api_key", "auth_token")


def _pitch_operand_dim(node) -> bool:
    """The strict reading: a numeric constant, arithmetic over those, or a shape/dimension read."""
    if isinstance(node, ast.Constant):
        return not isinstance(node.value, str) and isinstance(node.value, (int, float, complex, bool))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        return _pitch_operand_dim(node.operand)
    if isinstance(node, ast.BinOp):
        return _pitch_operand_dim(node.left) and _pitch_operand_dim(node.right)
    try:
        return bool(PITCH_DIM_RE.search(ast.unparse(node)))
    except Exception:
        return False


def _pitch_operand_nonstring(node) -> bool:
    """The wide reading from the earlier mandate: any operand that is not a string literal."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return False
    return not isinstance(node, ast.JoinedStr)


def _pitch_reaches(compare) -> tuple:
    """(dimension_quiet, nonstring_quiet) for one `ast.Compare`, with the rescue clause applied."""
    parts = [compare.left, *compare.comparators]
    rescued = any(any(word in name.lower() for word in PITCH_RESCUE_WORDS)
                  for name in (n.id for n in ast.walk(compare) if isinstance(n, ast.Name)))
    narrow = all(_pitch_operand_dim(part) for part in parts)
    wide = all(_pitch_operand_nonstring(part) for part in parts)
    return (narrow and not rescued, wide and not rescued)


def _compares_at(tree, line: int) -> list:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Compare)
            and any(getattr(part, 'lineno', None) == line
                    for part in (node.left, *node.comparators, node))]


def _const_of(node):
    """The literal value of an expression, reading `-100` as the sentinel it spells.

    `ast.parse` gives a negative literal as `UnaryOp(USub, Constant(100))`, so a test that only looks
    at `ast.Constant` misses the two spellings the mandate names by name (-1 and -100) -- and those two
    are exactly the ones that *do* reach the guards, because `_compares_two_secrets` also only looks at
    `ast.Constant`. Measured: `pad_token_id == -100` is reported CWE-208 by the shipped engine today.
    """
    if isinstance(node, ast.Constant):
        return node.value, True
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) \
            and isinstance(node.operand, ast.Constant):
        return -node.operand.value, True
    return None, False


def _is_sentinel_value(value) -> bool:
    if value is None:
        return True
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and value in SENTINEL_VALUES)


def _operand_sentinels(node, bindings) -> set:
    """Which of the four readings call this operand a sentinel."""
    found = set()
    value, is_literal = _const_of(node)
    if is_literal and _is_sentinel_value(value):
        found.update(('literal', 'contains'))
    text = ''
    if isinstance(node, ast.Name):
        text = node.id.lower()
        if node.id in bindings:
            found.add('bound')
    elif isinstance(node, ast.Attribute):
        text = node.attr.lower()
    if text and any(word in text for word in SENTINEL_NAME_WORDS):
        found.add('named')
    for child in ast.walk(node):
        child_value, child_literal = _const_of(child)
        if child_literal and _is_sentinel_value(child_value):
            found.add('contains')
    return found


def _sentinel_bindings(tree) -> frozenset:
    """Names a module writes exactly once, at module level, to one of the mandate's sentinels.

    The census counts every store of the name anywhere in the tree, so a parameter, a `global`
    rebinding or a second assignment drops it -- a name that can be written twice does not have a
    value that is a fact about the source text.
    """
    if tree is None:
        return frozenset()
    writes: dict = {}
    counts: dict = {}

    def _bump(name):
        counts[name] = counts.get(name, 0) + 1

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            _bump(node.id)
        elif isinstance(node, ast.arg):
            _bump(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _bump(node.name)
        elif isinstance(node, ast.alias):
            _bump(node.asname or node.name.split('.')[0])
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                _bump(name)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            _bump(node.name)
    for stmt in getattr(tree, 'body', ()):
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                and isinstance(stmt.targets[0], ast.Name):
            writes.setdefault(stmt.targets[0].id, []).append(stmt.value)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) \
                and stmt.value is not None:
            writes.setdefault(stmt.target.id, []).append(stmt.value)
    out = set()
    for name, values in writes.items():
        if counts.get(name) != 1 or len(values) != 1:
            continue
        value, is_literal = _const_of(values[0])
        if is_literal and _is_sentinel_value(value):
            out.add(name)
    return frozenset(out)


def _compare_names(compare) -> list:
    """Names and attribute tails on a comparison -- the evidence the credential veto reads."""
    out = []
    for child in ast.walk(compare):
        if isinstance(child, ast.Name):
            out.append(child.id.lower())
        elif isinstance(child, ast.Attribute):
            out.append(child.attr.lower())
    return out


def _sentinel_pitch(compare, bindings) -> bool:
    """The pitch as written: *any* operand is a sentinel, and no credential word is in sight."""
    names = _compare_names(compare)
    if any(any(word in name for word in ast_scanner.CWE208_CREDENTIAL_NAME_WORDS)
           for name in names):
        return False
    return any({'literal', 'bound', 'named'} & _operand_sentinels(part, bindings)
               for part in (compare.left, *compare.comparators))


def _emitting_compare(compare) -> bool:
    """Would the shipped emitter reach its two guards on this compare, guards aside?

    Mirrors `ast_scanner.py:19282-19309`: `Eq`/`NotEq`, no `compare_digest` in the subtree, a trigger
    marker among the `ast.Name` ids, and no bare `ast.Constant` operand. TIER 3b asserts the marker
    tuple still reads exactly as the copy kept here, so this cannot drift into scoring a shape the
    emitter no longer emits.
    """
    if not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in compare.ops):
        return False
    names = []
    for child in ast.walk(compare):
        if isinstance(child, ast.Call) and 'compare_digest' in (ast.unparse(child.func) or ''):
            return False
        if isinstance(child, ast.Name):
            names.append(child.id.lower())
        elif isinstance(child, ast.Attribute):
            names.append(child.attr.lower())
    if not any(any(marker in name for marker in CWE208_EMIT_MARKERS) for name in names):
        return False
    return not any(isinstance(o, ast.Constant) for o in (compare.left, *compare.comparators))


def check_sentinels():
    """TIER 3b: the four sentinel readings, scored on the emitting compare of every blessed line.

    A predicate count is not a finding count, so the tier also reports how many blessed lines have an
    emitting compare at all (`emitting`) and proves the mandate's own verification request: the whisper
    dimension line is reached by no reading, so it survives this pitch -- and the refusal still stands,
    because 12 other blessed lines do not.
    """
    failures = []
    module_source = ''
    try:
        module_source = inspect.getsource(ast_scanner)
    except (OSError, TypeError):
        failures.append(('emitter source', 'readable', 'unreadable',
                         'the marker tuple cannot be checked against the emitter'))
    lock = 'sensitive_markers = ("token", "secret", "signature", "hmac", "api_key", "auth_token")'
    if module_source and lock not in module_source:
        failures.append(('emitter marker tuple', lock, 'absent from ast_scanner.py',
                         'the shape TIER 3b scores is no longer the shape the emitter gates on'))
    corpus = corpus_dir('big8')
    verify_corpus('big8', corpus)
    for kind in ('parity', 'big8'):
        keys = sorted((row for row in load_keys(
            os.path.join(GATES_DIR, META[kind]['keys_file']), kind) if row[2] == 'CWE-208'),
            key=lambda r: (r[0], r[1]))
        trees: dict = {}
        counts = dict.fromkeys(SENTINEL_READINGS, 0)
        pitch, emitting, touched = 0, 0, collections.defaultdict(list)
        for row in keys:
            leaf = row[0].replace('\\', '/').rsplit('/', 1)[-1]
            if row[0] not in trees:
                # The join is spelled at the `open()` site on purpose: the CWE-22 prune answers from the
                # expression it can anchor, so a path handed over by a helper call reads as unvalidated
                # and this harness would contribute a CWE-22 key of its own to the parity baseline.
                if kind == 'big8':
                    path = os.path.abspath(os.path.join(corpus, os.path.basename(row[0])))
                else:
                    path = os.path.abspath(os.path.join(ROOT, row[0]))
                try:
                    with open(path, encoding='utf-8', errors='replace') as handle:
                        trees[row[0]] = ast.parse(handle.read())
                except (OSError, SyntaxError, ValueError):
                    trees[row[0]] = None
            tree = trees[row[0]]
            if tree is None:
                failures.append((kind, leaf, 'parses', 'unreadable', 'blessed line cannot be scored'))
                continue
            bindings = _sentinel_bindings(tree)
            found = set()
            line_emits = False
            for compare in _compares_at(tree, row[1]):
                if not _emitting_compare(compare):
                    continue
                line_emits = True
                for part in (compare.left, *compare.comparators):
                    found |= _operand_sentinels(part, bindings)
                if _sentinel_pitch(compare, bindings):
                    pitch += 1
                break
            emitting += int(line_emits)
            for reading in sorted(found):
                counts[reading] += 1
                touched[reading].append((leaf, row[1]))
        print(f'  {kind:7s} blessed={len(keys)} emitting={emitting} '
              + ' '.join(f'{name}={counts[name]}' for name in SENTINEL_READINGS)
              + f' pitch={pitch}')
        for reading, rows in sorted(touched.items()):
            for leaf, line in rows:
                print(f'    SENTINEL-REACHES {reading:8s} {leaf[-38:]}:{line}')
        if emitting != len(keys):
            failures.append((kind, 'emitting compares', len(keys), emitting,
                             'a blessed CWE-208 line no longer has the shape this tier scores - '
                             're-measure before quoting these reach numbers'))
        for reading in SENTINEL_READINGS:
            want = SENTINEL_REACH[kind][reading]
            if counts[reading] != want:
                failures.append((kind, reading, want, counts[reading],
                                 'the frozen reachability of the sentinel pitch moved - re-measure '
                                 'before anyone ships or retires this reading'))
        want_pitch = SENTINEL_PITCH_REACH[kind]
        if pitch != want_pitch:
            failures.append((kind, 'pitch', want_pitch, pitch,
                             'the sentinel pitch as written reaches a different number of blessed '
                             'lines than the refusal records'))
        if kind == 'big8':
            whisper_rows = [(reading, line) for reading, rows in touched.items()
                            for (leaf, line) in rows if leaf == WHISPER_LEAF]
            print(f'  {WHISPER_LEAF[-28:]}:{WHISPER_LINE} reached_by={whisper_rows} '
                  f'(mandate asks for [])')
            if whisper_rows:
                failures.append(('whisper:314', 'reached by no sentinel reading', whisper_rows,
                                 'the one line the mandate asked to protect is now in reach'))
        trees.clear()
    return failures


def check_big8_lines():
    """TIER 3: every blessed Big-8 timing line, read back from the hash-verified corpus.

    `big8_ab.py` re-scans those eight files for the whole baseline, but a re-scan only shows a lost key
    after the fact. This reads the 30 blessed lines themselves and asks the one question the exemption
    could answer: could any identifier on a blessed line be read as a usage counter? If yes, the
    narrowing reaches a true positive and the gate fails before a baseline moves.
    """
    failures = []
    corpus = corpus_dir('big8')
    verify_corpus('big8', corpus)
    rows = load_keys(os.path.join(GATES_DIR, META['big8']['keys_file']), 'big8')
    keys = sorted((row for row in rows if row[2] == 'CWE-208'), key=lambda r: (r[0], r[1]))
    cache: dict = {}
    reached = []
    for row in keys:
        leaf = row[0].rsplit('/', 1)[-1]
        if leaf not in cache:
            # `os.path.abspath` for the same reason `cwe22_dirent_closure_probe.scan_corpus_file` uses
            # it: this directory is scanned by the product, so an unwrapped join of a data-derived name
            # would make the harness contribute a CWE-22 key of its own to the parity baseline.
            path = os.path.abspath(os.path.join(corpus, os.path.basename(leaf)))
            with open(path, encoding='utf-8', errors='replace') as handle:
                cache[leaf] = handle.read().splitlines()
        lines = cache[leaf]
        index = row[1] - 1
        if not 0 <= index < len(lines):
            failures.append((row[0], row[1], 'blessed line is not in the corpus'))
            continue
        text = lines[index]
        hits = [name for name in _IDENTIFIER_RE.findall(text) if is_metric(name)]
        if hits:
            reached.append((leaf, row[1], hits, text.strip()[:70]))
    print(f'  corpus={corpus} sha256 verified  blessed CWE-208 lines={len(keys)}  '
          f'reachable_by_metric_rule={len(reached)}')
    for leaf, line, hits, text in reached:
        print(f'  REACHES  {leaf[-42:]}:{line} {hits} :: {text}')
    if reached:
        failures.append((len(reached), 'the metric rule reaches blessed Big-8 timing lines'))
    # the refused pitch, re-evaluated on those same 30 lines from their AST
    trees: dict = {}
    dims, nonstrings, named = 0, 0, []
    for row in keys:
        leaf = row[0].rsplit('/', 1)[-1]
        if leaf not in trees:
            path = os.path.abspath(os.path.join(corpus, os.path.basename(leaf)))
            try:
                with open(path, encoding='utf-8', errors='replace') as handle:
                    trees[leaf] = ast.parse(handle.read())
            except (OSError, SyntaxError):
                trees[leaf] = None
        if trees[leaf] is None:
            continue
        for compare in _compares_at(trees[leaf], row[1]):
            quiet_dim, quiet_wide = _pitch_reaches(compare)
            dims += int(quiet_dim)
            nonstrings += int(quiet_wide)
            if quiet_dim:
                named.append((leaf, row[1]))
            break
    print(f'  refused pitch on the same lines: reachable_by_dimension_rule={dims} '
          f'reachable_by_nonstring_rule={nonstrings}')
    for leaf, line in named:
        print(f'  DIm-REACHES  {leaf[-46:]}:{line}')
    for label, got in (('dimension', dims), ('nonstring', nonstrings)):
        want = PITCH_REACH[label]
        ok = got == want
        print(f'  {"ok" if ok else "MISMATCH":8s} {label} reading reaches {got} blessed lines '
              f'(frozen at {want})')
        if not ok:
            failures.append((label, want, got,
                             'the frozen reachability of a refused pitch moved - re-measure before '
                             'anyone ships or retires this tier'))
    trees.clear()
    return failures


def check_shapes():
    """TIER 4: the truth table, asserted against the seal this file is standing under.

    Every shape is parsed first: an unparseable module yields no findings, which would read as
    "quiet" and let a broken builder fake a PASS on the shipped seal.
    """
    failures = []
    for label, source, when_abstained, when_shipped in SHAPES:
        try:
            ast.parse(source)
        except SyntaxError as exc:
            print(f'  {label:26s} UNPARSEABLE {exc}')
            failures.append((label, 'shape syntax', 'parses', str(exc)))
            continue
        expected = when_abstained if CWE208_SEAL == 'abstained' else when_shipped
        found = scan_source(source)
        status = 'loud' if found else 'quiet'
        note = '; '.join(f'L{n}:{m.replace("CWE-208: ", "")}' for n, m in found)[:60]
        marker = 'ok' if status == expected else 'MISMATCH'
        print(f'  {label:26s} want={expected:5s} got={status:5s} {marker:8s} {note}')
        if status != expected:
            failures.append((label, 'seal', expected, status,
                             'the answer moved without the seal, or the seal moved without the answer'))
    return failures


def check_pairs():
    """TIER 4b: the same counter with and without a credential in the comparison."""
    failures = []
    for label, clean, with_secret in PAIRS:
        a = bool(scan_source(clean))
        b = bool(scan_source(with_secret))
        want_clean = CWE208_SEAL == 'abstained'
        agree = (a == want_clean) and b
        print(f'  {label:52s} clean_loud={a} (want {want_clean})  credential_loud={b} '
              f'(want True)  {"agree" if agree else "DISAGREE"}')
        if not agree:
            failures.append((label, 'credential provenance', (want_clean, True), (a, b)))
    return failures


def check_vocabulary():
    """TIER 5: the three tables and the name-shape unit row, pinned against edits."""
    failures = []
    prefixes = getattr(ast_scanner, 'CWE208_LLM_METRIC_PREFIXES', None)
    tails = getattr(ast_scanner, 'CWE208_LLM_METRIC_TAILS', None)
    counts = getattr(ast_scanner, 'CWE208_LLM_METRIC_COUNT_WORDS', None)
    creds = getattr(ast_scanner, 'CWE208_CREDENTIAL_NAME_WORDS', None)
    if prefixes is None or tails is None or counts is None or creds is None:
        return [('table missing', 'CWE208_LLM_METRIC_* / CWE208_CREDENTIAL_NAME_WORDS')]
    if frozenset(prefixes) != PREFIXES_REQUIRED:
        failures.append(('prefix table', sorted(prefixes), sorted(PREFIXES_REQUIRED)))
    if frozenset(tails) != TAILS_REQUIRED:
        failures.append(('tail table', sorted(tails), sorted(TAILS_REQUIRED)))
    for word in CREDENTIAL_WORDS_REQUIRED:
        if word not in creds:
            failures.append(('credential word required', word))
    moved = 0
    for name, want in NAME_SHAPE_ROWS:
        got = is_metric(name)
        if got is not want:
            failures.append(('name shape', name, want, got))
            moved += 1
    print(f'  prefixes={sorted(prefixes)}  tails={sorted(tails)}  count_words={sorted(counts)}')
    print(f'  credential words={len(creds)}  name-shape rows={len(NAME_SHAPE_ROWS)} '
          f'mismatched={moved}')
    return failures


def main() -> int:
    if CWE208_SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {CWE208_SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-208 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the parity corpus behind those keys, scanned live:')
    failures += check_corpus()
    print('TIER 3 - the 30 blessed Big-8 timing lines, read from the hash-verified corpus:')
    failures += check_big8_lines()
    print('TIER 3b - the sentinel pitch, scored on the emitting compare of every blessed line:')
    failures += check_sentinels()
    print(f'TIER 4 - truth table under seal={CWE208_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4b - same counter, with and without a credential:')
    failures += check_pairs()
    print('TIER 5 - prefix, tail, count-word and credential tables:')
    failures += check_vocabulary()
    print(f'\nseal={CWE208_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'pairs={len(PAIRS)} name_rows={len(NAME_SHAPE_ROWS)} '
          f'sentinel_rows={len(SENTINEL_SHAPES)} sentinel_reach={SENTINEL_REACH["big8"]} '
          f'locked_cwe208={sum(CWE208_LOCKED.values())} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-208 metric predicate no longer matches its measured evidence. '
              'Restore the answer or update the seal with a re-measured truth table; never re-bless a '
              'baseline -- the 30 blessed Big-8 timing keys are tensor and tokenizer comparisons whose '
              'names merely contain "token", and a substring reading of this rule deletes them.')
        return 1
    print(f'VERDICT: PASS - all {sum(CWE208_LOCKED.values())} blessed CWE-208 keys still reported '
          f'(6 parity exact-set, 30 Big-8 lines unreachable by the metric rule), '
          f'{len(FP_ROWS)} counter shapes silent, {len(MUST_REPORT_ROWS)} secret/blessed/residual '
          f'shapes reported, {len(NAME_SHAPE_ROWS)} name-shape rows agreeing.')
    return 0


def _substring_metric(name: str) -> bool:
    """The rule as the mandate drafted it: a substring search for a role word before `_tokens?`."""
    return bool(re.search(r'(prompt|completion|total|max|chunk|usage|generated|num|input|output|'
                          r'special|new|next|valid|selected)_tokens?', name, re.IGNORECASE))


def _apply_dimension_pitch():
    """Ship the refused pitch inside the engine, in memory: mute dimension/integer compares.

    Wired on the emitter's own secret-vs-secret gate, which is the only place a CWE-208 finding can be
    lost, so the mutation cannot be dodged by a second emitter.
    """
    original = ast_scanner.TaintTracker._compares_two_secrets

    def muted(self, node):
        if isinstance(node, ast.Compare) and _pitch_reaches(node)[0]:
            return False
        return original(self, node)

    ast_scanner.TaintTracker._compares_two_secrets = muted


def _apply_sentinel_pitch():
    """Ship the sentinel pitch inside the engine, in memory, on the last veto the emitter consults.

    The mandate's own words, not a caricature: mute when *any* operand is a sentinel under the literal,
    bound or named reading, with its credential veto honoured. The domain guard is the hook because it
    is the only shipped exemption that already receives the comparison, the module and the names, so the
    bound reading can resolve a module-level sentinel exactly as a shipped guard would.
    """
    original = ast_scanner.TaintTracker._c208_timing_is_llm_domain_compare

    def pitched(self, node, mod_name, all_names, evidence_names, sensitive_markers):
        if original(self, node, mod_name, all_names, evidence_names, sensitive_markers):
            return True
        return _sentinel_pitch(node, _sentinel_bindings(self.modules.get(mod_name)))

    ast_scanner.TaintTracker._c208_timing_is_llm_domain_compare = pitched


def _any_operand_metric(self, operand_names, evidence_names, sensitive_markers):
    """The `all(...)` requirement replaced by `any(...)` -- one clean operand silences the whole
    comparison, secrets included."""
    triggering = [name for name in operand_names
                  if any(marker in name for marker in sensitive_markers)]
    if not triggering:
        return False
    return any(self._c208_name_is_llm_token_metric(name) for name in triggering)


MUTATIONS = {
    'delete_metric_guard': {
        'what': 'make the metric test always answer "not a counter" (the 6 counter rows come back)',
        'rows': [row[0] for row in FP_ROWS],
        'requires': '_c208_timing_is_llm_token_metric',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c208_timing_is_llm_token_metric',
                                 lambda self, *args: False),
    },
    'dimension_pitch_shipped': {
        'what': 'ship the refused shape pitch: mute a compare whose operands are all `.shape` / '
                '`len()` / integer constants and whose names hold none of the eight rescue words -- '
                'this is the mandate, not a caricature of it',
        'rows': ['dim_shape_compare', 'len_over_mask_compare_int', 'shape_zero_vs_batch_size'],
        'requires': '_compares_two_secrets',
        'apply': _apply_dimension_pitch,
    },
    'sentinel_pitch_shipped': {
        'what': 'ship the sentinel pitch: mute a compare when any operand is 0/-1/-100/None, a name '
                'bound once to one of those, or a pad/eos/bos/sep-style special-token id, with no '
                'credential word on the line -- measured to reach 12 of the 30 blessed Big-8 timing '
                'lines and 0 false positives anywhere on this machine',
        'rows': ['sentinel_literal_negative', 'sentinel_bound_pad', 'sentinel_bound_none',
                 'sentinel_batch_vs_pad'],
        'keeps_loud': ['dim_shape_compare', 'sentinel_slice_contains', 'sentinel_vs_credential',
                       'blessed_request_token', 'blessed_secret'],
        'requires': '_c208_timing_is_llm_domain_compare',
        'apply': _apply_sentinel_pitch,
    },
    'metric_guard_always_true': {
        'what': 'make the metric test answer "counter" for everything -- the widest version of the '
                'rule, and the reason the credential veto and the all-operands test exist',
        'rows': ['blessed_request_token', 'metric_vs_credential', 'generated_tokens_count',
                 'old_num_tokens', 'input_output_residual'],
        'requires': '_c208_timing_is_llm_token_metric',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c208_timing_is_llm_token_metric',
                                 lambda self, *args: True),
    },
    'metric_rule_to_substring': {
        'what': 'replace the structural segment rule with the substring rule the mandate drafted -- '
                'measured to reach the blessed Big-8 names generated_tokens / old_num_tokens / '
                'special_tokens_mask / next_tokens',
        'rows': ['generated_tokens_count', 'special_tokens_mask', 'old_num_tokens', 'pad_token_id'],
        'requires': '_c208_name_is_llm_token_metric',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c208_name_is_llm_token_metric',
                                 staticmethod(_substring_metric)),
    },
    'drop_credential_veto': {
        'what': 'read only the triggering operand names, so a credential hidden in an attribute tail '
                'of the same comparison stops counting as evidence',
        'rows': ['metric_with_api_attr'],
        'requires': '_c208_timing_is_llm_token_metric',
        'apply': lambda: setattr(
            ast_scanner.TaintTracker, '_c208_timing_is_llm_token_metric',
            lambda self, operand_names, evidence_names, sensitive_markers: all(
                self._c208_name_is_llm_token_metric(name)
                for name in operand_names
                if any(marker in name for marker in sensitive_markers)
            )),
    },
    'one_operand_is_enough': {
        'what': 'require only one metric-shaped operand instead of every triggering one',
        'rows': ['metric_vs_credential', 'session_token_count'],
        'requires': '_c208_timing_is_llm_token_metric',
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c208_timing_is_llm_token_metric',
                                 _any_operand_metric),
    },
}


def run_mutation(name: str) -> int:
    """Apply one in-memory mutation and run the real gate over it. Exit 1 = the mutation was caught."""
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print(f"  rows that must move: {', '.join(spec['rows'])}")
    if spec['requires'] and not hasattr(ast_scanner.TaintTracker, spec['requires']):
        print(f"  SKIP - not shipped in this step: the guard symbol {spec['requires']} does "
              f"not exist, so there is nothing to delete or widen. NOT counted as a falsification.")
        return 2
    spec['apply']()
    # TIER 1 and 2 read the frozen baselines and re-scan the whole `benchmark/` tree; an in-memory
    # patch of a guard cannot move a blessed key the corpus does not hold, and running them here would
    # make each mutation cost a full tree scan. TIER 3 (the corpus lines), the truth table and the
    # tables are what a guard is falsified on.
    print('TIER 3 - the 30 blessed Big-8 timing lines under the mutation:')
    failures = check_big8_lines()
    print(f'TIER 4 - truth table under seal={CWE208_SEAL!r}:')
    failures += check_shapes()
    sources = {row[0]: row[1] for row in SHAPES}
    for label in spec.get('keeps_loud', ()):
        loud = bool(scan_source(sources[label]))
        print(f'  {"ok         " if loud else "SILENCED ! "} keeps-loud {label:26s} loud={loud}')
        if not loud:
            failures.append((label, 'loud while this pitch is installed', 'loud', 'quiet',
                             'the pitch silenced a row the mandate named as protected'))
    print('TIER 4b - same counter, with and without a credential:')
    failures += check_pairs()
    print('TIER 5 - prefix, tail, count-word and credential tables:')
    failures += check_vocabulary()
    for item in failures[:12]:
        print(f'  !! {item}')
    caught = bool(failures)
    print(f"\nFALSIFICATION VERDICT ({name}): "
          + (f'CAUGHT on {len(failures)} row(s) -- '
             + ', '.join(sorted({str(f[0]) for f in failures})[:6])
             if caught else 'MISSED - the guard is decorative, the engine still answers its own truth '
                            'table'))
    # 1 = the gate fails under the mutation (the guard is load-bearing); 0 = the mutation slipped
    # through and that is the alarm condition; 2 = this mutation tests a guard that is not shipped.
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
