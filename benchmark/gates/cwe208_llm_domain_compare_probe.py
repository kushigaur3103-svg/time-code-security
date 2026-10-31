"""CWE-208 truth table: which token-worded comparison is a codec or a config string, and which is a secret.

Why this gate exists
--------------------
On the pinned LiteLLM tree 2,780 CWE-208 rows exist. The prompt's target shape -- a comparison against
a model, provider or config *literal* (`model == "gpt-4"`) -- measures 0 of them, because
`_compares_two_secrets` (ast_scanner.py:6861) refuses any comparison with a `ast.Constant` operand: a
literal on either side makes the compared value a fact of the source text, so no timing branch depends
on a secret. That rule is older than this change and is not touched here. What does reach those rows is
the same shape one step further out -- a name bound at module level to a config string, or a literal
inside a subscript -- plus comparisons whose only token-worded participant is a *codec object*.
Measured: 12 codec rows and 49 domain rows retire, and 1,336 of the 2,780 carry a credential word that
the mandate itself requires to stay loud, so they are not reachable at all.

The emitter
-----------
`_collect_batch4_structural_findings` (ast_scanner.py:18880) is the only CWE-208 emitter. It fires on an
`ast.Compare` with Eq/NotEq, no `compare_digest` in the subtree, at least one `ast.Name` id carrying a
marker of `token`/`secret`/`signature`/`hmac`/`api_key`/`auth_token`, and `_compares_two_secrets`. Two
guards sit between that and the record, and this gate owns the second one:

  * `_c208_timing_is_llm_token_metric` -- the usage-counter rule, locked by
    `cwe208_llm_token_timing_probe.py`;
  * `_c208_timing_is_llm_domain_compare` (ast_scanner.py:18839) -- this gate.

The narrowing this gate locks
-----------------------------
Three vetoes run before anything can be exempted, and the mandate's "the secret veto table MUST run
first" is why they are in that order:

  1. any name or attribute tail carrying a word of `CWE208_CREDENTIAL_NAME_WORDS` (18 words) refuses;
  2. any sensitive marker other than `token` -- `secret`, `signature`, `hmac`, `api_key`, `auth_token`
     -- refuses;
  3. no name on the comparison containing `token` at all refuses (the rule could not have fired).

Vetoes 2 and 3 are measured individually redundant: every emitter marker except `token` is also a word
of the credential table, and the bare-token rule already refuses the rows veto 3 would. They stay
because they are what survives a table edit -- `drop_credential_word_password` is CAUGHT only while
veto 1 holds the word, and `drop_all_three_vetoes` is CAUGHT on five secret rows. A guard that only
one path needs is not decoration if removing two paths at once loses the finding.

Then two disjoint structural answers:

  * codec -- no name names a *bare* token (`_c208_name_has_bare_token` cuts every
    `CWE208_CODEC_WORDS` entry out first, so `tokenizer` and `detokenize` come out clean while
    `pad_token_id` and `generated_tokens` do not) and no codec is invoked in the comparison;
  * domain -- an operand is a literal, or a name bound exactly once at module level to a plain string
    (`_c208_domain_constants`; a name written twice is dropped), whose value matches
    `CWE208_DOMAIN_VALUE_RE` and carries no credential fingerprint (`_c798_fingerprinted`).

Measured evidence behind the numbers
------------------------------------
  blessed overlap     : CWE-208 keys -- 6 in parity, 30 in Big-8 (TIER 1). TIER 5 runs the real emitter
                        over every blessed file, one at a time, and asserts both halves: each blessed
                        line still gets its CWE-208 sink record, and the predicate never answered True
                        on it. 36 of 36.
  fixtures            : 20 shapes -- 6 loud->quiet rows the guard itself earns, 12 must-report rows and
                        2 quiet at both seals. Both quiet rows are named rather than hidden:
                        `literal_model_compare` is the prompt's own target shape, and it is silent on
                        HEAD's bytes too, because `_compares_two_secrets` never lets a literal compare
                        reach a record. The abstained column was measured by answering False from the
                        predicate, which is exactly what HEAD does with no predicate at all.
  LiteLLM A/B         : whole-file re-scan of every file holding a CWE-78 or CWE-208 row, HEAD's engine
                        beside this one, keys compared exactly (scratch/_c78_c208_ab.py); RETIRED and
                        ADDED are both measured. ADDED must be 0.

Seal semantics - `CWE208_SEAL`
------------------------------
  'shipped'   : the six codec/domain rows MUST be silent and every secret row MUST stay loud.
  'abstained' : the engine before this predicate landed -- every row that is not already quiet MUST be
                loud. Run it with TCS_CWE208_ENGINE pointed at HEAD's ast_scanner.py; a seal is only
                honest beside the engine it describes.
Override with TCS_CWE208_SEAL=abstained and TCS_CWE208_ENGINE=<path to another ast_scanner.py>.
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

if os.environ.get('TCS_CWE208_ENGINE'):
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

SEAL_TARGETS = ('abstained', 'shipped')
CWE208_SEAL = os.environ.get('TCS_CWE208_SEAL', 'shipped')

# The blessed CWE-208 population, counted from the frozen baselines themselves.
CWE208_LOCKED = {'parity': 6, 'big8': 30}

DOMAIN_PREDICATE = '_c208_timing_is_llm_domain_compare'

# (label, source, expect_when_abstained, expect_when_shipped)
# 'loud' = a CWE-208 finding is required in that module, 'quiet' = none is allowed.
SHAPES = [
    # ---- the two structural answers, each proven to be the reason the row went silent ----
    ('codec_object_compare', '''
def check(tokenizer, alt_tokenizer):
    if tokenizer == alt_tokenizer:
        return 1
''', 'loud', 'quiet'),
    ('codec_word_attribute_tail', '''
def check(tokenizer_ref, detokenizer_ref):
    if tokenizer_ref == detokenizer_ref:
        return 1
''', 'loud', 'quiet'),
    ('domain_constant_model', '''
DEFAULT = "gpt-4"
def pick(token_kind):
    if token_kind == DEFAULT:
        return 1
''', 'loud', 'quiet'),
    ('domain_subscript_literal', '''
def check(tokens_by_model, chosen_tokens):
    if tokens_by_model["claude"] == chosen_tokens:
        return 1
''', 'loud', 'quiet'),
    ('domain_provider_constant', '''
PROVIDER = "anthropic"
def route(token_provider):
    if token_provider == PROVIDER:
        return 1
''', 'loud', 'quiet'),
    ('domain_wire_format', '''
WIRE = "json"
def encode(token_encoding):
    if token_encoding == WIRE:
        return 1
''', 'loud', 'quiet'),
    # ---- the secret side of the rule: everything the mandate names loud ----
    ('secret_compare', '''
def check(provided_secret, expected_secret):
    if provided_secret == expected_secret:
        return 1
''', 'loud', 'loud'),
    ('bearer_token_attribute', '''
def check(token, cfg):
    if token != cfg.bearer_token:
        return 1
''', 'loud', 'loud'),
    ('hmac_compare', '''
def check(received_hmac, expected_hmac):
    if received_hmac != expected_hmac:
        return 1
''', 'loud', 'loud'),
    ('session_token_compare', '''
def check(session_token, stored_token):
    if session_token == stored_token:
        return 1
''', 'loud', 'loud'),
    ('api_key_compare', '''
def check(api_key, stored_api_key):
    if api_key == stored_api_key:
        return 1
''', 'loud', 'loud'),
    ('signature_marker_not_token', '''
def check(token_signature, alt_signature):
    if token_signature == alt_signature:
        return 1
''', 'loud', 'loud'),
    ('password_vs_tokenizer', '''
def check(password_hash, tokenizer):
    if password_hash == tokenizer:
        return 1
''', 'loud', 'loud'),
    # ---- token-worded names that name a token: the blessed Big-8 shapes ----
    ('generated_tokens_compare', '''
def check(generated_tokens, expected_tokens):
    if generated_tokens == expected_tokens:
        return 1
''', 'loud', 'loud'),
    ('special_tokens_mask_compare', '''
def check(special_tokens_mask, padded_special_tokens_mask):
    if special_tokens_mask == padded_special_tokens_mask:
        return 1
''', 'loud', 'loud'),
    ('codec_invoked_result', '''
def check(first_token_id, tokenizer, text, other_tokens):
    if first_token_id == tokenizer.encode(text)[0] and other_tokens:
        return 1
''', 'loud', 'loud'),
    # ---- a domain value is not a licence to mute a secret, and a fingerprint is not a model name ----
    ('auth_token_vs_model_constant', '''
DEFAULT = "gpt-4"
def check(auth_token):
    if auth_token == DEFAULT:
        return 1
''', 'loud', 'loud'),
    ('fingerprinted_model_constant', '''
DEFAULT = "gpt-4-4242424242"
def check(token_kind):
    if token_kind == DEFAULT:
        return 1
''', 'loud', 'loud'),
    ('codec_invoked_object', '''
def check(tok_a, tokenizer, text):
    if tok_a == tokenizer.encode(text):
        return 1
''', 'loud', 'loud'),
    ('domain_constant_reassigned', '''
import os
DEFAULT = "gpt-4"
DEFAULT = os.environ.get("TOKEN")
def check(token_kind):
    if token_kind == DEFAULT:
        return 1
''', 'loud', 'loud'),
    # ---- quiet at both seals: reachable by no emitter, so they are not wins ----
    ('literal_model_compare', '''
def check(model):
    if model == "gpt-4":
        return 1
''', 'quiet', 'quiet'),
    ('token_vs_none', '''
def check(token):
    if token == None:
        return 1
''', 'quiet', 'quiet'),
]

FP_ROWS = [row for row in SHAPES if row[2] == 'loud' and row[3] == 'quiet']
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == 'loud']
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == 'quiet']
_BY_LABEL = {row[0]: row[1] for row in SHAPES}

# One veto per row, both arms on opposite sides of it, and every clean arm a row this guard itself
# silences (FP_ROWS: loud on HEAD's bytes, quiet on these). A pair that agrees only because both arms
# are silent for some other reason cannot pass this tier.
PAIRS = [
    ('codec object vs a token the codec produced', 'codec_object_compare', 'codec_invoked_result'),
    ('config string vs the secret that string names', 'domain_constant_model',
     'auth_token_vs_model_constant'),
    ('clean model id vs one carrying a secret fingerprint', 'domain_wire_format',
     'fingerprinted_model_constant'),
    ('tokenizer the source wrote vs a token it emitted', 'codec_word_attribute_tail',
     'generated_tokens_compare'),
    ('provider name vs a session credential', 'domain_provider_constant', 'session_token_compare'),
]

# Names that must never be read as a codec, or the exemption is really "any token word" in disguise.
CODEC_WORDS_REQUIRED = ('untokenize', 'detokenize', 'tokenization', 'tokenisation', 'tokenizers',
                        'tokenizer', 'tokeniser', 'tokenize', 'tokenise', 'tokenized', 'tokenised')
# Token-worded names that name a token, not a codec. Every one of these appears on a blessed Big-8
# line, so a table that swallowed them is an FN in one edit.
BARE_TOKEN_NAMES = ('pad_token_id', 'special_tokens_mask', 'generated_tokens', 'next_tokens',
                    'old_num_tokens', 'auth_token', 'bearer_token', 'session_token', 'api_token',
                    'token_kind', 'tokens_used')
CODEC_NAMES = ('tokenizer', 'tokeniser', 'detokenizer', 'untokenize', 'tokenization', 'tokenize')
# Config values the domain table is allowed to name.
DOMAIN_VALUES_REQUIRED = ('gpt-4', 'gpt-4o-mini', 'o3', 'claude-3-5-sonnet', 'text-embedding-3-small',
                          'anthropic', 'azure', 'openai', 'gemini-1.5-pro', 'mistral-large',
                          'cohere', 'vertex_ai', 'bedrock', 'json', 'sse', 'base64', 'utf-8',
                          'chat', 'completion', 'embedding', 'rerank')
# Values that must stay out: each is a credential, a shape the prompt never named, or a word long
# enough to be a real identifier rather than a config alphabet.
DOMAIN_VALUES_REFUSED = ('sk-ant-api03-abc', 'hunter2secret', 'admin', 'tokenizer',
                         'token', 'pad_token_id', 'x-api-key', 'AWS_ACCESS_KEY_ID', 'password',
                         'session-token', 'sig', 'embedding_size')
# The id alternatives are prefix-greedy (`gpt[\w.\-]*` swallows a suffix), so these DO match. Asserted
# rather than wished away: the protection on a value like `gpt-4-admin` is not the alphabet, it is the
# credential veto and `_c798_fingerprinted`, and both are pinned behaviourally above. Shrinking the
# alphabet is a decision with a re-measure behind it, never a regex edit that this table would not see.
DOMAIN_VALUES_OVERBLOCKED = ('gpt-4-admin', 'gptwhatever', 'o3x')


def scan_source(source):
    """One in-memory module through the real record path, as both baselines were built."""
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-208'})


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


def _emitter_pass(sources):
    """Run only the CWE-208 emitter over each module, and record what the predicate answered.

    The collector is `PURE_STRUCTURAL`: it appends its sink and its `SinkRecord` in the same statement
    as the emit test, so "a record exists on this line" is exactly "the emitter decided to report it".
    Running the collector instead of the whole pipeline keeps this tier to one parse and one walk per
    file -- which is also the only way to ask a blessed Big-8 line a question without re-scanning 2 MB
    of corpus through the taint graph.
    """
    answers = []
    original = getattr(ast_scanner.TaintTracker, DOMAIN_PREDICATE)

    def recorder(self, node, mod_name, all_names, evidence_names, sensitive_markers):
        verdict = original(self, node, mod_name, all_names, evidence_names, sensitive_markers)
        answers.append((mod_name, getattr(node, 'lineno', 0), verdict))
        return verdict

    setattr(ast_scanner.TaintTracker, DOMAIN_PREDICATE, recorder)
    reported = {}
    try:
        for name, source in sorted(sources.items()):
            with contextlib.redirect_stderr(_io.StringIO()):
                tracker = ast_scanner.TaintTracker(files={name: source}, audit_all=True)
                tracker._collect_batch4_structural_findings()
            lines = {r.lineno for r in tracker.sink_records
                     if r.security_node.metadata.get('cwe') == 'CWE-208'}
            reported[name] = lines
    finally:
        setattr(ast_scanner.TaintTracker, DOMAIN_PREDICATE, original)
    return reported, answers


def _corpus_sources(keys, kind):
    """The files behind a set of blessed keys, read once, keyed the way the emitter keys them."""
    # A parity fixture leaf can repeat across directories, so the emitter is keyed by the blessed path
    # itself; the Big-8 keys are already collapsed to `<corpus_marker>/<leaf>` by `canon_key`, and each
    # of those is re-joined under the hash-verified corpus directory, so no blessed string ever names
    # a directory.
    corpus = corpus_dir('big8') if kind == 'big8' else ''
    if kind == 'big8':
        verify_corpus('big8', corpus)
    sources, absent = {}, []
    for row in keys:
        if kind == 'big8':
            name = os.path.basename(row[0].rsplit('/', 1)[-1])
            path = os.path.abspath(os.path.join(corpus, os.path.basename(name)))
        else:
            name = row[0]
            path = os.path.abspath(os.path.join(ROOT, name))
        if not os.path.exists(path):
            absent.append(name)
            continue
        with open(path, encoding='utf-8', errors='replace') as handle:
            sources[name] = handle.read()
    return sources, absent


def _without_any_veto(self, node, mod_name, all_names, evidence_names, sensitive_markers):
    """The shipped predicate with vetoes 1, 2 and 3 deleted: codec and domain answers only."""
    if (not any(self._c208_name_has_bare_token(n) for n in evidence_names)
            and not self._c208_codec_is_invoked(node)):
        return True
    constants = self._c208_domain_constants(mod_name)
    for operand in [node.left] + list(node.comparators):
        for child in ast.walk(operand):
            value = None
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                value = child.value
            elif isinstance(child, ast.Name) and child.id in constants:
                value = constants[child.id]
            if (value and ast_scanner.CWE208_DOMAIN_VALUE_RE.fullmatch(value.strip())
                    and not self._c798_fingerprinted(value)):
                return True
    return False


def check_blessed_lines():
    """TIER 5: all 36 blessed lines, asked through the real emitter, in both baselines.

    Two assertions per line, because one of them alone can be satisfied by accident: the emitter must
    still put a CWE-208 record on that exact line (the key is alive), and the predicate must never
    have answered True on it (the guard is what is keeping it alive, not luck).
    """
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = sorted((row for row in rows if row[2] == 'CWE-208'), key=lambda r: (r[0], r[1]))
        sources, missing_files = _corpus_sources(keys, kind)
        if missing_files:
            failures.append((kind, 'blessed files not in the tree', missing_files))
            continue
        reported, answers = _emitter_pass(sources)
        silent = {}
        for mod_name, line, verdict in answers:
            silent.setdefault(mod_name, set()).add((line, verdict))
        lost, reached = [], []
        for row in keys:
            leaf = row[0] if kind == 'parity' else os.path.basename(row[0].rsplit('/', 1)[-1])
            if row[1] not in reported.get(leaf, set()):
                lost.append((leaf, row[1]))
            if (leaf, row[1], True) in silent.get(leaf, set()):
                reached.append((leaf, row[1]))
        trues = sum(1 for _, _, verdict in answers if verdict)
        print(f'  {kind:7s} blessed={len(keys)}  emitter_reports={len(keys) - len(lost)}  '
              f'predicate_calls={len(answers)}  answered_domain={trues}  '
              f'reaches_blessed={len(reached)}')
        for leaf, line in lost:
            print(f'  LOST     {leaf[-44:]}:{line}')
        for leaf, line in reached:
            print(f'  REACHES  {leaf[-44:]}:{line}')
        if lost:
            failures.append((kind, len(lost), 'a blessed CWE-208 line no longer gets its record'))
        if reached:
            failures.append((kind, len(reached), 'the domain predicate reaches blessed CWE-208 lines'))
    return failures


def check_shapes():
    """TIER 3: the truth table, asserted against the seal this file is standing under."""
    failures = []
    for label, source, when_abstained, when_shipped in SHAPES:
        try:
            ast.parse(source)
        except SyntaxError as exc:
            print(f'  {label:34s} UNPARSEABLE {exc}')
            failures.append((label, 'shape syntax', 'parses', str(exc)))
            continue
        expected = when_abstained if CWE208_SEAL == 'abstained' else when_shipped
        found = scan_source(source)
        status = 'loud' if found else 'quiet'
        note = '; '.join(f'L{n}:{m.replace("CWE-208: ", "")}' for n, m in found)[:56]
        marker = 'ok' if status == expected else 'MISMATCH'
        print(f'  {label:34s} want={expected:5s} got={status:5s} {marker:8s} {note}')
        if status != expected:
            failures.append((label, 'seal', expected, status,
                             'the answer moved without the seal, or the seal moved without the answer'))
    return failures


def check_pairs():
    """TIER 4: one veto, two arms, both moved by this guard."""
    failures = []
    fp_labels = {row[0] for row in FP_ROWS}
    loud_labels = {row[0] for row in MUST_REPORT_ROWS}
    for label, clean, dirty in PAIRS:
        if clean not in fp_labels:
            failures.append((label, 'clean arm is a loud->quiet row (the guard moves it)', clean))
        if dirty not in loud_labels:
            failures.append((label, 'tripwire arm is a must-report row', dirty))
        a = bool(scan_source(_BY_LABEL[clean]))
        b = bool(scan_source(_BY_LABEL[dirty]))
        want_clean = CWE208_SEAL == 'abstained'
        agree = (a == want_clean) and b
        print(f'  {label:44s} clean_loud={a} (want {want_clean})  tripwire_loud={b} '
              f'(want True)  {"agree" if agree else "DISAGREE"}')
        if not agree:
            failures.append((label, 'pair provenance', (want_clean, True), (a, b)))
    return failures


def check_vocabulary():
    """TIER 6: the two tables, the three vetoes and the wiring, pinned so an edit is a decision."""
    failures = []
    words = getattr(ast_scanner, 'CWE208_CODEC_WORDS', None)
    if not words:
        failures.append(('CWE208_CODEC_WORDS', 'exists'))
    else:
        for word in CODEC_WORDS_REQUIRED:
            if word not in words:
                failures.append(('codec word required', word))
    if not hasattr(ast_scanner.TaintTracker, '_c208_name_has_bare_token'):
        return [('_c208_name_has_bare_token', 'exists')]
    bare = ast_scanner.TaintTracker._c208_name_has_bare_token
    for name in BARE_TOKEN_NAMES:
        if not bare(name):
            failures.append(('token-worded name must stay a token (blessed Big-8 shapes)', name))
    for name in CODEC_NAMES:
        if bare(name):
            failures.append(('codec name must read as a codec, not a token', name))
    regex = getattr(ast_scanner, 'CWE208_DOMAIN_VALUE_RE', None)
    if not isinstance(regex, re.Pattern):
        failures.append(('CWE208_DOMAIN_VALUE_RE', 'exists', 'compiled pattern', regex))
    else:
        for value in DOMAIN_VALUES_REQUIRED:
            if not regex.fullmatch(value):
                failures.append(('config value must match', value))
        for value in DOMAIN_VALUES_REFUSED:
            if regex.fullmatch(value):
                failures.append(('value must not be in the config alphabet', value))
        for value in DOMAIN_VALUES_OVERBLOCKED:
            if not regex.fullmatch(value):
                failures.append(('greedy-prefix over-block is gone -- widening/shrinking the alphabet '
                                 'has to be a decision, and this table is what makes it visible', value))
    cred = getattr(ast_scanner, 'CWE208_CREDENTIAL_NAME_WORDS', None) or ()
    for word in ('auth', 'access', 'session', 'bearer', 'api', 'signature', 'secret', 'hmac',
                 'password', 'jwt', 'oauth', 'private', 'digest', 'verify', 'credential', 'csrf'):
        if word not in cred:
            failures.append(('credential veto word required', word))
    # The three vetoes must run before either structural answer, in the order the mandate names. The
    # source is read on the shipped module, so a reorder that puts a veto after a `return True` fails.
    try:
        body = inspect.getsource(ast_scanner.TaintTracker._c208_timing_is_llm_domain_compare)
    except (OSError, TypeError) as exc:
        failures.append(('predicate source readable', type(exc).__name__))
        return failures
    order = [body.find('CWE208_CREDENTIAL_NAME_WORDS'), body.find('marker != "token"'),
             body.find('"token" in name'), body.find('_c208_name_has_bare_token'),
             body.find('CWE208_DOMAIN_VALUE_RE'), body.find('_c798_fingerprinted')]
    if -1 in order or order != sorted(order):
        failures.append(('veto order: credentials, then non-token markers, then token presence, '
                         'then codec/domain, then fingerprint', order))
    # Wiring: exactly one call, in the emitter, after the metric guard so the two never overlap.
    try:
        emitter = inspect.getsource(ast_scanner.TaintTracker._collect_batch4_structural_findings)
    except (OSError, TypeError) as exc:
        failures.append(('emitter source readable', type(exc).__name__))
        return failures
    calls = emitter.count('_c208_timing_is_llm_domain_compare(')
    after_metric = (emitter.find('_c208_timing_is_llm_token_metric(')
                    < emitter.find('_c208_timing_is_llm_domain_compare('))
    print(f'  veto order ok={order == sorted(order)}  emitter calls={calls}  '
          f'after_metric_guard={after_metric}')
    if calls != 1 or not after_metric:
        failures.append(('predicate must be wired once in the emitter, after the metric guard',
                         (calls, after_metric)))
    if '_compares_two_secrets' not in emitter:
        failures.append(('the literal-operand veto must stay in the emitter'))
    print(f'  codec words={len(words or ())}  credential words={len(cred)}  '
          f'domain must-match={len(DOMAIN_VALUES_REQUIRED)} refused={len(DOMAIN_VALUES_REFUSED)} '
          f'over-blocked={len(DOMAIN_VALUES_OVERBLOCKED)}')
    return failures


def main() -> int:
    if CWE208_SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {CWE208_SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-208 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the parity corpus behind those keys, scanned live:')
    failures += check_corpus()
    print(f'TIER 3 - truth table under seal={CWE208_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4 - one veto, two arms, both moved by this guard:')
    failures += check_pairs()
    print('TIER 5 - all 36 blessed lines, through the real emitter:')
    failures += check_blessed_lines()
    print('TIER 6 - codec words, config alphabet, credential vetoes and wiring:')
    failures += check_vocabulary()
    print(f'\nseal={CWE208_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'pairs={len(PAIRS)} locked_cwe208={sum(CWE208_LOCKED.values())} '
          f'failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-208 domain predicate no longer matches its measured evidence. '
              'Restore the answer or move the seal with a re-measured truth table; never re-bless a '
              'baseline -- the 6 parity and 30 Big-8 timing keys are secret comparisons and the guard '
              'must stay blind to every one of them.')
        return 1
    print(f'VERDICT: PASS - all {sum(CWE208_LOCKED.values())} blessed CWE-208 keys still reported '
          f'through the emitter, parity corpus exact-set, {len(FP_ROWS)} codec/domain shapes silent, '
          f'{len(MUST_REPORT_ROWS)} secret/token/fingerprint shapes reported, {len(PAIRS)} pairs '
          f'agreeing.')
    return 0


MUTATIONS = {
    'delete_domain_guard': {
        'what': 'the predicate never exempts -- every retired codec and config row comes back',
        'rows': [row[0] for row in FP_ROWS],
        'apply': lambda: setattr(ast_scanner.TaintTracker, DOMAIN_PREDICATE,
                                 lambda self, *args: False),
    },
    'domain_guard_always_true': {
        'what': 'the predicate exempts every token-worded comparison -- the widest reading of the '
                'prompt, and the reason the three vetoes exist',
        'rows': [row[0] for row in MUST_REPORT_ROWS],
        'apply': lambda: setattr(ast_scanner.TaintTracker, DOMAIN_PREDICATE,
                                 lambda self, *args: True),
    },
    'drop_credential_veto': {
        'what': 'stop looking at CWE208_CREDENTIAL_NAME_WORDS. Measured: one row moves '
                '(auth_token_vs_model_constant) and the rest survive on the bare-token rule and on '
                'veto 2, which is what the 16 membership assertions in TIER 6 are for',
        'rows': ['auth_token_vs_model_constant'],
        'apply': lambda: setattr(ast_scanner, 'CWE208_CREDENTIAL_NAME_WORDS', ()),
    },
    'drop_credential_word_password': {
        'what': 'lose one word of the credential table. Measured: `password_hash == tokenizer` does '
                'NOT come back, because the same value is also held by the word `hash` and the row is '
                'held again by veto 2 -- the table is over-determined on purpose, and TIER 6 is the '
                'lock that makes deleting a word a decision',
        'rows': [],
        'apply': lambda: setattr(ast_scanner, 'CWE208_CREDENTIAL_NAME_WORDS',
                                 tuple(w for w in ast_scanner.CWE208_CREDENTIAL_NAME_WORDS
                                       if w != 'password')),
    },
    'drop_all_three_vetoes': {
        'what': 'the two structural answers alone, with no name reading in front of them -- what the '
                'rule would be if the mandate sentence "the secret veto table MUST run first" were '
                'dropped',
        'rows': ['secret_compare', 'hmac_compare', 'api_key_compare', 'password_vs_tokenizer',
                 'auth_token_vs_model_constant'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, DOMAIN_PREDICATE, _without_any_veto),
    },
    'blank_codec_words': {
        'what': 'empty the codec table, so `tokenizer` names a token and a codec compare stays loud',
        'rows': ['codec_object_compare', 'codec_word_attribute_tail'],
        'apply': lambda: setattr(ast_scanner, 'CWE208_CODEC_WORDS', ()),
    },
    'allow_codec_invoked': {
        'what': 'ignore whether a codec is called, so `a == tokenizer.encode(t)[0]` reads as two '
                'codec objects being compared',
        'rows': ['codec_invoked_object'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c208_codec_is_invoked',
                                 staticmethod(lambda node: False)),
    },
    'domain_constants_accept_reassigned': {
        'what': 'keep the first module-level binding of a name even after the file writes it again, '
                'so a value the source no longer guarantees buys silence',
        'rows': ['domain_constant_reassigned'],
        'apply': lambda: setattr(
            ast_scanner.TaintTracker, '_c208_domain_constants',
            lambda self, mod_name: {
                target.id: stmt.value.value
                for stmt in getattr(self.modules.get(mod_name), 'body', [])
                if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
                for target in stmt.targets if isinstance(target, ast.Name)}),
    },
    'drop_fingerprint_veto': {
        'what': 'trust the alphabet over the shape of the value, so `gpt-4-4242424242` -- a real '
                'secret-shaped string -- is read as a model id',
        'rows': ['fingerprinted_model_constant'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c798_fingerprinted',
                                 staticmethod(lambda value: False)),
    },
}


def _value_in_domain(tracker, child, mod_name):
    """Helper for the marker-veto mutation only: the domain half of the shipped predicate."""
    value = None
    if isinstance(child, ast.Constant) and isinstance(child.value, str):
        value = child.value
    elif isinstance(child, ast.Name):
        value = tracker._c208_domain_constants(mod_name).get(child.id)
    return bool(value and ast_scanner.CWE208_DOMAIN_VALUE_RE.fullmatch(value.strip())
                and not tracker._c798_fingerprinted(value))


def run_mutation(name: str) -> int:
    """Apply one in-memory mutation and run the real gate over it. Exit 1 = the mutation was caught."""
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print(f"  rows that must move: {', '.join(spec['rows']) or '(tables and blessed lines only)'}")
    spec['apply']()
    # TIER 1 and 2 read the frozen baselines and re-scan the whole `benchmark/` tree; an in-memory
    # patch of one predicate cannot move a blessed key the corpus does not hold, and running them here
    # would make each mutation cost a full tree scan. The truth table, the pairs, the blessed lines
    # and the tables are what a guard is falsified on.
    tiers = []
    try:
        print(f'TIER 3 - truth table under seal={CWE208_SEAL!r}:')
        tiers.append(('T3', check_shapes()))
        print('TIER 4 - one veto, two arms, both moved by this guard:')
        tiers.append(('T4', check_pairs()))
        print('TIER 5 - all 36 blessed lines, through the real emitter:')
        tiers.append(('T5', check_blessed_lines()))
        print('TIER 6 - codec words, config alphabet, credential vetoes and wiring:')
        tiers.append(('T6', check_vocabulary()))
    except Exception as exc:  # a mutation that cannot even run is not a falsification
        print(f'MUTATION ERROR: {type(exc).__name__}: {exc}')
        print(f'\nFALSIFICATION VERDICT ({name}): ERROR - the mutation is broken, '
              'so it proves nothing either way (exit 2, not a pass)')
        return 2
    failures = [item for _label, rows in tiers for item in rows]
    for item in failures[:12]:
        print(f'  !! {item}')
    counts = ' '.join(f'{label}={len(rows)}' for label, rows in tiers if rows)
    caught = bool(failures)
    print(f'\nFALSIFICATION VERDICT ({name}): '
          + (f'CAUGHT on {len(failures)} row(s) [{counts}] -- '
             + ', '.join(sorted({str(f[0]) for f in failures})[:6])
             if caught else 'MISSED - the guard is decorative, the engine still answers its own '
                            'truth table'))
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

