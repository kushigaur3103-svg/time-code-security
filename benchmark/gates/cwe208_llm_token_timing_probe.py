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
  fixtures                   : 20 shapes, each pair verified against HEAD's bytes before this file
                               claimed them (scratch/_abstained_check.py -- all 20 are LOUD on HEAD):
                               6 counter shapes go LOUD->QUIET and 14 stay LOUD, which includes the 6
                               blessed parity spellings, the 5 Big-8 name shapes TIER 3 re-reads from
                               the corpus, and the honest `input_tokens == output_tokens` residual.

Seal semantics - `CWE208_SEAL`
------------------------------
  'shipped'   : the 5 counter shapes MUST be silent and every tripwire MUST stay loud.
  'abstained' : the engine before the metric test landed -- all 16 shapes MUST be loud. A counter shape
                that goes quiet while the seal says abstained means a narrowing landed without a
                contract.
Either way a mismatch is exit 1.
"""
from __future__ import annotations

import ast
import contextlib
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
]

FP_ROWS = [row for row in SHAPES if row[2] == 'loud' and row[3] == 'quiet']
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == 'loud']
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == 'quiet']

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
    print(f'TIER 4 - truth table under seal={CWE208_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4b - same counter, with and without a credential:')
    failures += check_pairs()
    print('TIER 5 - prefix, tail, count-word and credential tables:')
    failures += check_vocabulary()
    print(f'\nseal={CWE208_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'pairs={len(PAIRS)} name_rows={len(NAME_SHAPE_ROWS)} '
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
