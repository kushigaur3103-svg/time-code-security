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
"""
import ast
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


failures = []
print('cwe338 ml-math truth table')
for source, want, canon, note in CASES:
    got, reason = evaluate(source, canon)
    ok = got == want
    failures += [] if ok else [(source, want, got, reason)]
    first_line = source.splitlines()[-1].strip()
    print(f'  {"ok  " if ok else "FAIL"} want={want:6s} got={got:6s} {first_line[:56]:56s} '
          f'{reason if not ok else note}')

for name, want in NAME_TEST:
    got = ast_scanner.TaintTracker._cwe338_name_is_security_named(name)
    ok = got == want
    failures += [] if ok else [(name, want, got, 'name test')]
    print(f'  {"ok  " if ok else "FAIL"} name={name:22s} want={want} got={got}')

prefixes = ast_scanner.ML_MATH_RANDOM_PREFIXES
for forbidden in ('random', 'secrets', 'os', 'SystemRandom'):
    ok = not any(forbidden == p or forbidden.startswith(p + '.') for p in prefixes)
    print(f'  {"ok  " if ok else "FAIL"} stdlib-root {forbidden!r} absent from '
          f'ML_MATH_RANDOM_PREFIXES')
    failures += [] if ok else [(forbidden, 'absent', 'present', 'prefix table')]

print(f'\ncases={len(CASES) + len(NAME_TEST) + 4} failures={len(failures)}')
for item in failures:
    print(f'  !! {item}')
if failures:
    print('VERDICT: FAIL -- the CWE-338 exemption no longer matches its spec')
    sys.exit(1)
print('VERDICT: PASS')
