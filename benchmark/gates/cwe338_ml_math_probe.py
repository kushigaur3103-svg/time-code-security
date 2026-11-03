"""Truth table for the CWE-338 ML-math exemption: the check that fails loudly if it is weakened.

    python benchmark/gates/cwe338_ml_math_probe.py

The two frozen baselines can only prove what the engine said about corpora that already exist.
They cannot prove that a *credential drawn from a numeric library* stays reported, because nobody
hand-writes `session_key = torch.randint(...)` into a benchmark, so a later refactor that widens
the exemption to "any torch call" would pass both gates and ship a false negative. This table pins
the exact boundary instead: every shape is asserted against the same classmethod the engine calls
at `ast_scanner.py` inside the CWE-338 branch.

Sources are carried as strings and parsed in memory, so this directory -- which the parity gate
scans -- never finds a sink inside its own harness. Verdict `REPORT` means the finding survives;
`EXEMPT` means the rule drops it.

The table is a list of *canonical module roots*, never a list of two-letter conventions
------------------------------------------------------------------------------------------------
`ML_MATH_RANDOM_PREFIXES` shipped as `("torch", "numpy.random")` and now carries four more entries:
`tensorflow`, `jax`, `ray.tune`, `nn.initializers`. Measured on the frozen Transformers artifact
(`benchmark_results/tcs.sarif`, 194 CWE-338 rows over 86 files, callee root read out of the finding
message): those four roots are **39 rows** -- `tensorflow.random` 29, `ray.tune` 5, `jax.random` 3,
`nn.initializers` 2 -- and `torch` 7 + `numpy.random` 1 = 8 rows were already covered by the
original two. The 16 blessed CWE-338 keys (9 parity + 7 Big-8) are **all** stdlib `random` or
`random.Random`, so the new roots have an empty blessed population by construction, and the drift
lock below is what keeps it empty: `FORBIDDEN_ROOTS` refuses `random`, `secrets`, `os`,
`SystemRandom` *and the four bare aliases* `tf`, `np`, `nn`, `ray` on the table.

Two properties make a canonical root safe where an alias cannot be, and both are asserted per row:

  * `resolve_canonical_name` folds `import tensorflow as tf` to `tensorflow.random` **before** the
    table is consulted, so `tf.random.uniform(...)` qualifies while a local variable that happens
    to be called `tf` does not -- `v = tf.randint(0, 9)` with an unresolved receiver is REPORT.
  * the match is `root == prefix or root.startswith(prefix + ".")`, a dot boundary. `torchvision`
    does not inherit `torch` and `numpy.random_state` does not inherit `numpy.random`; both are
    asserted, and the mutation `prefix_matches_without_a_dot_boundary` turns the boundary into a
    plain `startswith` and is CAUGHT on 4 rows.

Refused, and named so the next round does not re-litigate it: the object-name family is **25 rows in
12 distinct symbols** -- `distributions.Bernoulli` 2, `distributions.Categorical` 2,
`distributions.Gumbel` 1, `distributions.RelaxedBernoulli` 1, `distributions.RelaxedOneHotCategorical`
1 (= 7), `self.sample` 4 + `self.prior.sample` 1 (= 5), `distribution.sample` 4, `distr.sample` 3,
`model.sample` 3, `bart_model.sample` 2, `prior.sample` 1 -- and 0 rows carry a `scipy` receiver.
They stay loud because a variable *called* `distributions` is not a module identity: `sample =
multivariate_normal.MultivariateNormal(...).sample()` is the same shape and is only exempt once
canonicalisation *proves* the torch family behind it, which is the `EXEMPT` half of that duplicated
pair in the table. Proving those 25 would need the arena's import table, which is not in this
repository, so the mandate's own conditional decides it -- not provable, stays reported. Every one of
the 12 symbols is now a `REPORT` row here, all seven roots sit in `FORBIDDEN_ROOTS`, and the
`object_receiver_alias_shipped` mutation ships them on the table in memory and is CAUGHT.

Falsification
-------------
    python benchmark/gates/cwe338_ml_math_probe.py                     # clean -> exit 0
    python benchmark/gates/cwe338_ml_math_probe.py --mutate=NAME       # exit 1 = CAUGHT

    prefix_matches_without_a_dot_boundary  7 rows  (the dot boundary is load-bearing)
    bare_alias_prefix_shipped              5 rows  (`tf`/`np` on the table exempts an unresolved name)
    drop_the_new_library_prefixes          8 rows  (the four new roots must each have a proof case)
    credential_veto_blanked               23 rows  (a security-named destination re-arms every library)
    derived_matcher_drops_the_dot          6 rows  (the engine's derived matcher, not the reference loop)
    object_receiver_alias_shipped         13 rows  (the 25-row arena family, exempted by name)

Each patch is applied in memory, never to the file, and restored in a `finally`; exit 0 under a
mutation would mean the guard is decorative. The first four and the sixth replace
`ast_scanner.TaintTracker._is_ml_math_random_draw` with a reference implementation over a widened
table; the fifth leaves the predicate alone and rebinds
`ast_scanner._ML_MATH_MATCHER_CACHE` to a dotless pair -- the seam the predicate actually reads,
carrying the live table object in slot 0 so the engine's own identity test does not heal the patch --
so a derivation bug in the fast path is caught by the same table rather than only by a row count. The
equivalence tier scores all 26 `MATCHER_ROOTS` spellings against the reference test on every clean run,
and the wiring tier asserts the predicate reads that cache, keeps the dot boundary, has exactly one
writer, and that no second matcher survives beside it.
"""
import ast
import inspect
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

import ast_scanner  # noqa: E402

REPORT, EXEMPT = 'REPORT', 'EXEMPT'

# (source, verdict, canon override or None, why-this-case note)
CASES = [
    # --- a credential destination re-arms the finding, whatever the library says -------------
    ('session_key = torch.randint(0, 256, (32,))', REPORT, None, 'key'),
    ('apiKey = torch.randint(0, 9, (1,))', REPORT, None, 'camelCase key'),
    ('otp = torch.randint(100000, 999999, (1,))', REPORT, None, 'otp'),
    ('iv = torch.randint(0, 256, (16,))', REPORT, None, 'initialisation vector'),
    ('seed = torch.randint(0, 2**31, (1,))', REPORT, None, 'seed'),
    ('nonce = torch.randint(0, 2**64, (1,))', REPORT, None, 'nonce'),
    ('code = torch.randint(0, 1000, (6,))', REPORT, None, 'one-time code'),
    ('reset_code = numpy.random.randint(0, 9999, size=6)', REPORT, None, 'reset code'),
    ('pin = numpy.random.randint(0, 9999, (4,))', REPORT, None, 'pin'),
    ('code_verifier = torch.randint(0, 9, (43,))', REPORT, None, 'PKCE verifier'),
    ('cache_key = torch.randint(0, 9, (1,))', REPORT, None, 'key beside another word'),
    ('label_token_ids = torch.randint(0, 9, (3,))', REPORT, None,
     'token without a vocab qualifier beside it stays guarded'),
    ('session_tokens = torch.randint(0, 9, (1,))', REPORT, None, 'session wins over token'),
    ('payload = {"session": torch.randint(0, 9, (1,))}', REPORT, None, 'dict key destination'),
    ('key = torch.randint(0, 9, (32,)).tolist()', REPORT, None, 'hop through tolist()'),
    # --- the library is not provably numeric math, so nothing is exempt ----------------------
    ('n = random.randint(1, 9)', REPORT, None, 'stdlib random'),
    ('c = random.choice(alphabet)', REPORT, None, 'stdlib choice'),
    ('r = random.random()', REPORT, None, 'stdlib random'),
    ('s = random.Random(0).randint(1, 9)', REPORT, None, 'stdlib Random instance'),
    ('randint = torch.randint\nv = randint(0, 9)', REPORT, None,
     'bare aliased callee never reaches the exemption'),
    ('from random import choice\npick = choice(alphabet)', REPORT, None,
     'imported stdlib leaf'),
    ('random_gen = numpy.random\nq = random_gen.uniform(0, 1)', REPORT, None,
     'alias receiver is not a proven module path'),
    ('sample = multivariate_normal.MultivariateNormal(loc, scale).sample()', REPORT, None,
     'unresolved receiver is never treated as safe'),
    ('sample = multivariate_normal.MultivariateNormal(loc, scale).sample()', EXEMPT,
     'torch.distributions.multivariate_normal',
     'canonicalisation proving the torch family is what retires this key in big8'),
    # --- the 25 object receivers left loud in the arena, spelled exactly as the artifact shows --
    # Measured on the frozen 194-row CWE-338 artifact: `distributions` 7, `self` 5, `distribution` 4,
    # `distr` 3, `model` 3, `bart_model` 2, `prior` 1 = 25 rows, and 0 rows carry a `scipy` receiver.
    # None of these seven words is a module identity -- each is a name a local can be bound to, so
    # the only door is canonicalisation, which needs the source tree's import table. That table is
    # not in this repository, so the mandate's own conditional applies: not provable -> stays loud.
    ('x = distributions.Bernoulli(logits).sample()', REPORT, None,
     'a local named distributions is not torch.distributions'),
    ('x = distributions.Categorical(probs).sample()', REPORT, None, 'the arena spelling, verbatim'),
    ('x = distributions.RelaxedBernoulli(logits).sample()', REPORT, None, 'same root, other class'),
    ('x = distribution.sample()', REPORT, None, 'an object built on some earlier line'),
    ('x = distr.sample(8)', REPORT, None, 'a shorter alias of the same idea'),
    ('x = self.prior.sample()', REPORT, None, 'an attribute of the instance'),
    ('x = self.sample()', REPORT, None, 'the receiver that names nothing but the object'),
    ('x = model.sample()', REPORT, None, 'model is a variable, not a library'),
    ('x = bart_model.sample()', REPORT, None, 'a model instance named after an architecture'),
    ('x = prior.sample()', REPORT, None, 'a distribution instance held in a local'),
    ('x = distributions.Bernoulli(logits).sample()', EXEMPT, 'torch.distributions',
     'the very same row retires once the receiver resolves to the torch family'),
    ('x = scipy.stats.norm.sample(size=8)', REPORT, None,
     'no scipy entry ships: measured 0 arena rows carry that receiver, so nothing proves it'),
    # --- proven torch / numpy.random index arithmetic with no credential name ----------------
    ('idx = torch.randint(0, 50257, (8,))', EXEMPT, None, 'vocabulary index'),
    ('input_ids = torch.randint(1, config.vocab_size, (1, 8))', EXEMPT, None, 'input ids'),
    ('self.input_ids = torch.randint(1, 10, (1, 9))', EXEMPT, None, 'attribute destination'),
    ('attention_mask = torch.randint(0, 2, (8,))', EXEMPT, None, 'mask is not a secret'),
    ('max_new_tokens = torch.randint(low=10, high=50, size=(1,))', EXEMPT, None,
     'vocab demotion: token beside max/new'),
    ('token_type_ids = numpy.random.randint(0, 9, (2,))', EXEMPT, None, 'vocab demotion: type'),
    ('eos_token = torch.randint(0, 9, (3,))', EXEMPT, None, 'vocab demotion: eos'),
    ('noise = numpy.random.uniform(0, 1, size=(8,))', EXEMPT, None, 'numpy random float'),
    ('perm = numpy.random.choice(indices)', EXEMPT, None, 'numpy batch reorder'),
    ('npn = np.random.uniform(0, 1, size=(4,))', EXEMPT, 'numpy.random',
     'np folds to numpy.random through canonicalisation'),
    ('x = torch.distributions.Normal(m, s).sample()', EXEMPT, None, 'torch distribution draw'),
    ('values = torch.randint(0, 9, (1,)).tolist()', EXEMPT, None, 'tolist hop, unnamed sink'),
    ('rows = {"labels": torch.randint(0, 9, (2,))}', EXEMPT, None, 'dict key labels'),
    ('def draw():\n    return torch.randint(2, target_shape, generator=generator)', EXEMPT,
     None, 'returned, not stored in a named slot'),
    ('data = numpy.random.uniform(0, 1, (4,))', EXEMPT, None, 'data is a tensor name, not a secret'),
    # --- the numeric libraries added for the Transformers arena, and their boundaries --------
    # Measured on the frozen artifact: `tensorflow.*` 29 CWE-338 rows, `ray.tune.*` 5,
    # `jax.random.*` 3, `nn.initializers.*` 2. Each EXEMPT row below is one of those spellings; each
    # REPORT row is the credential destination that must re-arm it.
    ('t = tf.random.uniform(shape=[8, 12])', EXEMPT, 'tensorflow.random',
     'import tensorflow as tf folds through canonicalisation'),
    ('t = tensorflow.random.uniform(shape=[8, 12])', EXEMPT, None, 'written canonical root'),
    ('session_key = tf.random.uniform(shape=[32])', REPORT, 'tensorflow.random',
     'a credential destination re-arms a tf draw'),
    ('otp = tensorflow.random.shuffle(values)', REPORT, None, 'otp beside tensorflow'),
    ('x = jax.random.uniform(rng_key, shape=(2, 8))', EXEMPT, None, 'jax tensor draw'),
    ('token = jax.random.randint(rng_key, (16,), 0, 256)', REPORT, None, 'token wins over jax'),
    ('lr = ray.tune.uniform(1e-5, 1e-3)', EXEMPT, None, 'a search space, not a PRNG draw'),
    ('api_key = ray.tune.choice(candidates)', REPORT, None, 'api_key re-arms ray.tune'),
    ('init = nn.initializers.uniform(scale)', EXEMPT, None, 'an initializer, not a secret'),
    ('salt = nn.initializers.uniform(scale)', REPORT, None, 'salt re-arms the initializer path'),
    # --- a bare convention alias must never qualify on its own spelling ----------------------
    ('tf = random\nv = tf.randint(0, 9)', REPORT, None,
     'a local named tf is not tensorflow: only the folded root qualifies'),
    ('np = random\nv = np.randint(0, 9)', REPORT, None, 'a local named np is not numpy.random'),
    # --- a prefix must match at a dot boundary, not as a string prefix -----------------------
    ('imgs = torchvision.randint(0, 9, (2,))', REPORT, None, 'a sibling of torch is not torch'),
    ('q = numpy.random_state.randint(0, 9, (2,))', REPORT, None,
     'numpy.random as a string prefix would swallow random_state'),
]

# The name test on its own, so a change to the word lists cannot pass unnoticed.
NAME_TEST = [
    ('session_key', True), ('apiKey', True), ('reset_code', True), ('iv', True),
    ('code_verifier', True), ('session_token_vocab', True), ('label_token_ids', True),
    ('max_new_tokens', False), ('token_type_ids', False), ('eos_token', False),
    ('num_tokens', False), ('input_tokens', True), ('attention_mask', False),
    ('input_ids', False), ('labels', False), ('data', False), ('value', False),
    ('vocab_size', False), ('permutation', False),
]


def dfs_calls(tree):
    out = []

    def visit(node):
        if isinstance(node, ast.Call):
            out.append(node)
        for child in ast.iter_child_nodes(node):
            visit(child)
    visit(tree)
    return out


def sink_of(tree):
    """The last randomness-named call in reading order -- the one the finding is reported on."""
    hits = []
    for call in dfs_calls(tree):
        leaf = (call.func.attr if isinstance(call.func, ast.Attribute)
                else (call.func.id if isinstance(call.func, ast.Name) else None))
        if leaf and leaf in ast_scanner.CWE338_RANDOM_NAMES:
            hits.append(call)
    if not hits:
        raise AssertionError('no randomness-named call in this case')
    return hits[-1]


def receiver_of(node):
    """The same receiver the engine reads at the CWE-338 branch, call-base fallback included."""
    receiver = ast_scanner.dotted_name(node.func.value) or ''
    if not receiver and isinstance(node.func.value, ast.Call):
        receiver = ast_scanner.dotted_name(node.func.value.func) or ''
    return receiver


def evaluate(source, canon_override):
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent
    node = sink_of(tree)
    if not isinstance(node.func, ast.Attribute):
        return REPORT, 'callee is not dotted - engine never enters the exemption branch'
    receiver = receiver_of(node)
    canon = canon_override if canon_override is not None else receiver
    if ast_scanner.TaintTracker._is_ml_math_random_draw(node, receiver, canon):
        return EXEMPT, 'proven numeric draw with no credential destination'
    return REPORT, 'receiver not proven, or a credential destination re-armed it'


# Roots that must never appear in `ML_MATH_RANDOM_PREFIXES`. The first four are the rule's own
# vocabulary and the CSPRNGs; the next four are two-letter convention aliases (`tf`, `np`, `nn`,
# `ray`) that any local can be re-bound to -- those qualify only through canonicalisation, never
# as a written root, which is what `tf = random` above pins. The last seven are the arena's object
# receivers: each is a name for *an instance*, so matching it would exempt `self.sample()` on any
# object in any file, which is the rule being deleted rather than narrowed.
OBJECT_RECEIVER_ROOTS = ('distributions', 'distribution', 'distr', 'prior', 'self', 'model',
                         'bart_model')
FORBIDDEN_ROOTS = ('random', 'secrets', 'os', 'SystemRandom', 'tf', 'np', 'nn', 'ray') \
    + OBJECT_RECEIVER_ROOTS

# Every shape the derived prefix matcher can be handed, scored against the reference test. The
# near-misses matter more than the hits: `torchvision` and `numpy.randomstate` inherit nothing,
# `nn` and `ray` are aliases rather than families, and the empty string is the unresolved receiver
# the engine must never treat as safe.
MATCHER_ROOTS = ('torch', 'TORCH', 'torchvision', 'torch.nn', 'numpy', 'numpy.random',
                 'numpy.randomstate', 'tensorflow', 'tensorflow.random', 'jax', 'jax.random',
                 'ray', 'ray.tune', 'nn', 'nn.initializers', 'random', 'secrets', 'os.urandom',
                 'tf.random', 'np.random', '', 'softmax',
                 'distributions', 'self.prior', 'bart_model', 'scipy.stats')


def run_cases(verbose=True):
    """Every tier except the baselines: the predicate table, the name test and the table drift lock."""
    failures = []
    for source, want, canon, note in CASES:
        got, reason = evaluate(source, canon)
        ok = got == want
        failures += [] if ok else [(source, want, got, reason)]
        if verbose:
            first_line = source.splitlines()[-1].strip()
            print(f'  {"ok  " if ok else "FAIL"} want={want:6s} got={got:6s} '
                  f'{first_line[:56]:56s} {reason if not ok else note}')

    for name, want in NAME_TEST:
        got = ast_scanner.TaintTracker._cwe338_name_is_security_named(name)
        ok = got == want
        failures += [] if ok else [(name, want, got, 'name test')]
        if verbose:
            print(f'  {"ok  " if ok else "FAIL"} name={name:22s} want={want} got={got}')

    prefixes = ast_scanner.ML_MATH_RANDOM_PREFIXES
    # A stdlib root, or a bare convention alias, on this table is a false negative waiting to happen:
    # `random` is the rule's own vocabulary, and `tf`/`np`/`nn`/`ray` are names a local can hold.
    for forbidden in FORBIDDEN_ROOTS:
        ok = not any(forbidden == p or forbidden.startswith(p + '.') for p in prefixes)
        if verbose:
            print(f'  {"ok  " if ok else "FAIL"} root {forbidden!r} absent from '
                  f'ML_MATH_RANDOM_PREFIXES')
        failures += [] if ok else [(forbidden, 'absent', 'present', 'prefix table')]

    # Every prefix must be load-bearing in the table above, so an entry cannot be added without a
    # case that proves it, and cannot be dropped without one that fails.
    for prefix in prefixes:
        proved = [source for source, want, _, _ in CASES if want == EXEMPT and prefix in source]
        ok = bool(proved)
        if verbose:
            print(f'  {"ok  " if ok else "FAIL"} prefix {prefix!r} has {len(proved)} '
                  f'EXEMPT case(s) written against it')
        failures += [] if ok else [(prefix, 'a case', 'none', 'prefix proof')]

    # Boundary: the match must be at a dot, so a sibling library or a longer name cannot inherit it.
    for sibling, parent in (('torchvision', 'torch'), ('numpy.random_state', 'numpy.random')):
        got, _ = evaluate(f'v = {sibling}.randint(0, 9, (2,))', None)
        ok = got == REPORT
        if verbose:
            print(f'  {"ok  " if ok else "FAIL"} {sibling} does not inherit the {parent} prefix')
        failures += [] if ok else [(sibling, REPORT, got, 'dot boundary')]

    # The engine answers the table through one derived pair (`_ml_math_matcher()` -> a `frozenset`
    # plus a tuple of `prefix + "."` spellings) instead of a loop per entry. That rewrite must mean
    # exactly the reference test, so every root shape is scored both ways here -- a derived-pair
    # build bug is invisible to a row count and is not invisible to this loop.
    reference = tuple(ast_scanner.ML_MATH_RANDOM_PREFIXES)
    exact, dotted = ast_scanner._ml_math_matcher()
    for root in MATCHER_ROOTS:
        # The engine hands this pair a lower-cased candidate, so `TORCH` is a hit, not a miss; the
        # reference test has to make the same promise or the tier would fail on correct code.
        lowered = root.lower()
        want = any(lowered == prefix or lowered.startswith(prefix + '.') for prefix in reference)
        got = bool(lowered) and (lowered in exact or lowered.startswith(dotted))
        ok = got == want
        if verbose:
            print(f'  {"ok  " if ok else "FAIL"} derived matcher agrees with the table on {root!r}')
        failures += [] if ok else [(root, want, got, 'derived matcher drift')]

    # And the pair is rebuilt, not remembered: the cache is keyed on the table's identity, so a
    # test (or a future config hook) that rebinds ML_MATH_RANDOM_PREFIXES must be answered by the
    # new table. A stale cache would silently keep the old exemption set.
    original_table = ast_scanner.ML_MATH_RANDOM_PREFIXES
    try:
        ast_scanner.ML_MATH_RANDOM_PREFIXES = tuple(original_table) + ('zoo.family',)
        widened = evaluate('v = zoo.family.randint(0, 9)', None)[0]
        stale_kept = 'zoo.family' not in ast_scanner._ml_math_matcher()[0]
    finally:
        ast_scanner.ML_MATH_RANDOM_PREFIXES = original_table
    restored = evaluate('v = zoo.family.randint(0, 9)', None)[0]
    for label, got, want in (('rebind exempts', widened, EXEMPT),
                             ('pair rebuilt', 'rebuilt' if not stale_kept else 'stale', 'rebuilt'),
                             ('restore reports', restored, REPORT)):
        ok = got == want
        if verbose:
            print(f'  {"ok  " if ok else "FAIL"} table cache: {label} -> {got}')
        failures += [] if ok else [(label, want, got, 'derived pair cache')]

    # One answer, in one place. The predicate reads the cache inline (no call frame on the hot path),
    # so the risk is a later refactor leaving two matchers that can disagree about the same receiver.
    # These four assertions are what make "the engine consults the pair this tier just scored" true by
    # construction rather than by inspection.
    module = inspect.getsource(ast_scanner)
    predicate = inspect.getsource(ast_scanner.TaintTracker._is_ml_math_random_draw)
    rebuild = inspect.getsource(ast_scanner._rebuild_ml_math_matcher)
    for label, ok in (
        ('predicate reads the derived pair', '_ML_MATH_MATCHER_CACHE' in predicate),
        ('predicate keeps the dot boundary', 'lowered.startswith(dotted)' in predicate),
        ('the cache has exactly one writer',
         module.count('_ML_MATH_MATCHER_CACHE = ') == 1 and '_ML_MATH_MATCHER_CACHE = ' in rebuild),
        ('no second matcher survives',
         not hasattr(ast_scanner, '_ml_math_root_is_numeric_family')),
    ):
        if verbose:
            print(f'  {"ok  " if ok else "FAIL"} wiring: {label}')
        failures += [] if ok else [(label, True, ok, 'wiring')]
    return failures


def main() -> int:
    print('cwe338 ml-math truth table')
    failures = run_cases()
    total = (len(CASES) + len(NAME_TEST) + len(FORBIDDEN_ROOTS)
             + len(ast_scanner.ML_MATH_RANDOM_PREFIXES) + 2 + len(MATCHER_ROOTS) + 3 + 4)
    print(f'\ncases={total} failures={len(failures)}')
    for item in failures:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL -- the CWE-338 exemption no longer matches its spec')
        return 1
    print('VERDICT: PASS')
    return 0


# Each mutation re-expresses one way this table could be widened by accident, and must be CAUGHT.
MUTATIONS = {
    'prefix_matches_without_a_dot_boundary': {
        'what': 'match the prefix as a plain string prefix, so torchvision inherits torch',
        'patch': ('startswith', True)},
    'bare_alias_prefix_shipped': {
        'what': 'put the convention aliases tf/np/nn/ray on the table as bare roots',
        'patch': ('aliases', True)},
    'drop_the_new_library_prefixes': {
        'what': 'roll the arena widening back to torch/numpy.random only',
        'patch': ('rollback', True)},
    'credential_veto_blanked': {
        'what': 'stop asking the destination name, so session_key = tf.random.uniform goes quiet',
        'patch': ('veto', True)},
    # The 25 arena object receivers are the population this step was asked to consider and refused.
    # Adding them with the boundary law intact is exactly the widening the mandate named, so this
    # mutation ships it in memory and the truth table must answer it on its own rows.
    'object_receiver_alias_shipped': {
        'what': 'put distributions / distribution / distr / prior / self / model / bart_model on '
                'the table, so any object with a .sample() method is exempt',
        'patch': ('objects', True)},
    # The engine answers the table through a derived matcher rather than a per-entry loop, so the
    # boundary can also be lost inside that derivation. This mutation patches the matcher and leaves
    # the predicate alone, which is the only way to prove the tier tests the code that runs.
    'derived_matcher_drops_the_dot': {
        'what': 'build the derived matcher from the bare prefixes, so torchvision inherits torch',
        'patch': ('startswith', True), 'target': 'helper'},
}


def _mutated(prefixes, boundary=None, veto=None):
    def patched(node, receiver_name, receiver_canon):
        qualified = False
        for candidate in (receiver_name, receiver_canon):
            lowered = (candidate or '').lower()
            if not lowered:
                continue
            for prefix in prefixes:
                if lowered == prefix or (lowered.startswith(prefix) if boundary
                                         else lowered.startswith(prefix + '.')):
                    qualified = True
                    break
            if qualified:
                break
        if not qualified:
            return False
        if veto is not None:
            return not veto(node)
        return not any(ast_scanner.TaintTracker._cwe338_name_is_security_named(name)
                       for name in ast_scanner.TaintTracker._cwe338_assignment_targets(node))
    return staticmethod(patched)


def _run_helper_mutation(name: str, spec) -> int:
    """Patch the derived pair itself and let the shipped predicate answer the table.

    The cache *is* the seam the predicate reads, so the patch has to carry the live table object in
    slot 0 -- otherwise the engine's own identity test rebuilds the pair and the mutation heals
    itself, which would prove nothing about the code that runs.
    """
    if not hasattr(ast_scanner, '_ML_MATH_MATCHER_CACHE'):
        print('  SKIP - the engine answers this table with a per-entry loop, so there is no '
              'derived pair to break')
        return 2
    table = ast_scanner.ML_MATH_RANDOM_PREFIXES
    lowered = [str(prefix).lower() for prefix in table]

    original = ast_scanner._ML_MATH_MATCHER_CACHE
    ast_scanner._ML_MATH_MATCHER_CACHE = (table, frozenset(lowered), tuple(lowered))
    try:
        caught = run_cases(verbose=False)
    finally:
        ast_scanner._ML_MATH_MATCHER_CACHE = original
    return report(name, caught)


def report(name: str, caught: list) -> int:
    print(f'  rows that changed verdict / broke a lock: {len(caught)}')
    for item in caught[:6]:
        print(f'    - {str(item[0])[:88]} want={item[1]} got={item[2]} ({item[3]})')
    print(f'\nFALSIFICATION VERDICT ({name}): {"CAUGHT" if caught else "NOT CAUGHT"}'
          f' on {len(caught)} row(s)')
    return 1 if caught else 0


def run_mutation(name: str) -> int:
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    if spec.get('target') == 'helper':
        return _run_helper_mutation(name, spec)
    base = ast_scanner.ML_MATH_RANDOM_PREFIXES
    kind, flag = spec['patch']
    prefixes, boundary, veto = tuple(base), None, None
    if kind == 'aliases':
        prefixes = base + ('tf', 'np', 'nn', 'ray')
    elif kind == 'rollback':
        prefixes = ('torch', 'numpy.random')
        if set(base) == set(prefixes):
            print('  SKIP - the widening this mutation tests is not shipped')
            return 2
    elif kind == 'startswith':
        boundary = True
    elif kind == 'veto':
        veto = lambda node: False  # noqa: E731
    elif kind == 'objects':
        prefixes = base + OBJECT_RECEIVER_ROOTS
    original = ast_scanner.TaintTracker._is_ml_math_random_draw
    ast_scanner.TaintTracker._is_ml_math_random_draw = _mutated(prefixes, boundary, veto)
    try:
        caught = run_cases(verbose=False)
    finally:
        ast_scanner.TaintTracker._is_ml_math_random_draw = original
    return report(name, caught)


if __name__ == '__main__':
    for arg in sys.argv[1:]:
        if arg.startswith('--mutate='):
            key = arg.split('=', 1)[1]
            if key not in MUTATIONS:
                print(f'unknown mutation {key!r}; known: {", ".join(sorted(MUTATIONS))}')
                sys.exit(64)
            sys.exit(run_mutation(key))
    sys.exit(main())
