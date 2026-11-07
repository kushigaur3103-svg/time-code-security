"""Active-partitioning lock: the three slices shipped under the updated Zero-FN Shield.

The mandate asked for three filters. Two of them already existed in the engine, so the work was to
find the population that is still loud, prove a value-domain slice that no blessed key shares, and
ship that slice -- not to re-add a rule that was already there. Everything below is measured on this
checkout, and every conjunct has a mutation that moves it.

Slice A -- CWE-22, a read-only open whose path is a compile-time string literal
------------------------------------------------------------------------------
`_sink_context_exempt` already exempted read-only opens inside a test tree (ast_scanner.py:7431-7452
before this change). The 35 arena sites that are still registered are the NON-test ones, so the new
proof carries no path test at all: a path written in the source text has no runtime component an
attacker could steer. The observable is `sink_records`, exactly as the mandate named it -- these rows
never reached a finding on either arm, so a finding count is the one instrument that cannot see the
win. Measured per fixture, CWE-22 records only:
    literal read 0, literal 'rb' 0, literal with a runtime mode 1, literal write 1, runtime read 1.
A mode that is not a literal stays registered: `open(p, mode_var)` could be 'w' at runtime, and the
default-is-read argument only applies when no mode was passed at all.

Slice B -- CWE-338, two value-domain proofs inside `_cwe338_display_only_draw`
----------------------------------------------------------------------------
The test-tree exemption (ast_scanner.py:7453-7465) already covers test files; the arena rows that
remain live in `src/` and `examples/`. Two shapes there are provably not credentials:
  * `random.uniform(0, 1)` -- two literal bounds, so the value domain is the closed unit interval.
    36 arena rows are exactly `dropout_probability = random.uniform(0, 1)`. The other three arena
    `uniform` rows carry runtime bounds and stay loud.
  * `for index in random.sample(range(len(dataset)), 3)` -- the population is a container's length,
    so the draw returns POSITIONS, and the loop consumes them as indices. 21 arena rows. A code or
    OTP generator draws from a literal alphabet (`range(10)`), never from a dataset's length, and
    that fixture stays loud.
Both proofs sit AFTER the credential and `.join` vetoes, so a security-named destination still wins.
0 of the 16 blessed CWE-338 keys is a `uniform` call or a `sample(range(len(...)))` loop.

The veto hole this exposed, and its measured-free fix
----------------------------------------------------
`random.sample(range(len(passwords)), 3)` was loud on HEAD and went quiet under the first draft of
Slice B: CWE338_SECURITY_NAME_WORDS carried a plural for every member of its family except `password`
and `seed`, and a container name is exactly where the plural appears. Adding `passwords` and `seeds`
restores the veto. Measured before adding: 0 arena CWE-338 rows and 0 of the 16 blessed keys contain
either word; the 20 `seeds` occurrences in the arena are comments plus one literal `SEEDS = [...]`
parametrisation list, never a draw destination. So the completion re-loudens nothing that is quiet.

Slice C -- CWE-208, the constant-integer partition is already shipped, and is defended twice
-------------------------------------------------------------------------------------------
`_compares_two_secrets` refuses any `ast.Constant` operand (ast_scanner.py:8561) and
`_c208_is_unit_test_assertion` refuses a test assertion without credential provenance
(ast_scanner.py:8512). Measured: 0 of the 118 arena CWE-208 rows is an equality against an integer
literal -- the only four rows with an int operand are a `< 1` tensor metric and three
`len(token_ids) > 0` guards beside `token_ids[-1] == self.eos_token_id`, which the mandate keeps loud.
So there is no new predicate here and nothing to suppress; what this gate adds is the lock, plus the
proof that the partition is load-bearing: blinding the Constant refusal alone already re-loudens a
credential-named `secret_size == 2`, blinding both guards keeps it loud, and `batch_size == 2` stays
quiet under both because the credential-name axis is a third, independent guard.
"""
from __future__ import annotations

import ast
import contextlib
import io
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
GATES_DIR = os.path.join(ROOT, 'benchmark', 'gates')
BIG8_CORPUS = os.path.join(ROOT, 'benchmark_gates_data', 'corpus_big8')
MODELING_COMMON = 'tests__test_modeling_common.py'
GENERATION_UTILS = 'tests__generation__test_utils.py'
WHISPER = 'tests__models__whisper__test_modeling_whisper.py'

import cli  # noqa: E402
import ast_scanner  # noqa: E402


def scan(files: dict, cwe: str) -> tuple:
    """One in-process scan: (loud lines, registered sinks, sink_records) for one CWE."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files=files, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
        registered = sum(1 for sink in tracker.sinks if (sink.metadata or {}).get('cwe') == cwe)
        records = sum(1 for record in tracker.sink_records
                      if (record.security_node.metadata or {}).get('cwe') == cwe)
    loud = sorted(int(row['line']) for row in rows if row['cwe'] == cwe)
    return loud, registered, records


# Slice A fixtures: (source path, source, expected loud lines, expected CWE-22 sink_records).
C22_FIXTURES = {
    'literal_read': ('src/m.py',
                     "def f():\n"
                     + "    with open('vocab.json') as h:\n"
                     + "        return h.read()\n", [], 0),
    'literal_read_rb': ('src/m.py',
                        "def f():\n"
                        + "    with open('vocab.json', 'rb') as h:\n"
                        + "        return h.read()\n", [], 0),
    'literal_runtime_mode': ('src/m.py',
                             "def f(mode_var):\n"
                             + "    with open('vocab.json', mode_var) as h:\n"
                             + "        return h.read()\n", [], 1),
    'literal_write': ('src/m.py',
                      "def f():\n"
                      + "    with open('vocab.json', 'w') as h:\n"
                      + "        h.write('x')\n", [], 1),
    'runtime_read': ('src/m.py',
                     "def f(filename):\n"
                     + "    with open(filename) as h:\n"
                     + "        return h.read()\n", [2], 1),
}

UNIFORM_UNIT = ("import random\n"
                + "class A:\n"
                + "    def __call__(self, hidden_states, deterministic=True):\n"
                + "        dropout_probability = random.uniform(0, 1)\n"
                + "        if not deterministic and dropout_probability < self.dropout:\n"
                + "            hidden_states = dropout(hidden_states)\n"
                + "        return hidden_states\n")
SAMPLE_INDEX = ("import random\n"
                + "def log_examples(train_dataset, logger):\n"
                + "    for index in random.sample(range(len(train_dataset)), 3):\n"
                + "        logger.info(train_dataset[index])\n")

# Slice B fixtures: (path, source, expected loud lines). Quiet rows must also register no sink.
C338_FIXTURES = {
    'uniform_unit_quiet': ('src/transformers/models/m.py', UNIFORM_UNIT, []),
    'sample_index_quiet': ('examples/run_qa.py', SAMPLE_INDEX, []),
    'uniform_runtime_bounds_loud': ('src/m.py',
                                    "import random\n"
                                    + "def f(self):\n"
                                    + "    aspect = random.uniform(self.lo, self.hi)\n"
                                    + "    return aspect\n", [3]),
    'sample_literal_alphabet_loud': ('src/m.py',
                                     "import random\n"
                                     + "def f():\n"
                                     + "    for i in random.sample(range(10), 6):\n"
                                     + "        print(i)\n", [3]),
    'uniform_credential_veto_loud': ('src/m.py',
                                     "import random\n"
                                     + "def f():\n"
                                     + "    secrets = random.uniform(0, 1)\n"
                                     + "    return secrets\n", [3]),
    'sample_passwords_veto_loud': ('examples/m.py',
                                   "import random\n"
                                   + "def f(passwords):\n"
                                   + "    for index in random.sample(range(len(passwords)), 3):\n"
                                   + "        print(index)\n", [3]),
    'sample_seeds_veto_loud': ('examples/m.py',
                               "import random\n"
                               + "def f(seeds):\n"
                               + "    for index in random.sample(range(len(seeds)), 3):\n"
                               + "        print(index)\n", [3]),
    'blessed_scale_loud': ('tests/test_modeling_common.py',
                           "def f(rng, values, scale):\n"
                           + "    values.append(rng.random() * scale)\n", [2]),
    'blessed_vocab_loud': ('tests/test_modeling_common.py',
                           "def f(rng, values, vocab_size):\n"
                           + "    values.append(rng.randint(0, vocab_size - 1))\n", [2]),
}

# Slice C fixtures: the partition is pre-existing, so these pin behaviour rather than a new predicate.
C208_FIXTURES = {
    'test_credential_int_quiet': ('tests/test_m.py',
                                  "def f(secret_size):\n"
                                  + "    assert secret_size == 2\n", []),
    'test_plain_int_quiet': ('tests/test_m.py',
                             "import unittest\n"
                             + "class T(unittest.TestCase):\n"
                             + "    def test_a(self):\n"
                             + "        batch_size = 2\n"
                             + "        assert batch_size == 2\n", []),
    'token_constant_loud': ('src/m.py',
                            "def f(input_ids, bos_token_id):\n"
                            + "    if input_ids == bos_token_id:\n"
                            + "        return 1\n", [2]),
}


def check_baseline_domain() -> list:
    """Only the two frozen key files are read here, each with its join written at the open site.

    Opening a per-key corpus path from a loop variable is itself a variable-derived path, and the
    engine reports it -- that is how an earlier draft of this gate added a NEW parity key. The
    behavioural half of the domain proof lives in check_blessed_lines_stay_loud instead.
    """
    failures = []
    expected = {'parity_before.keys': (425, 9), 'big8_before.keys': (119, 7)}
    for keys_name, (total_rows, c338_rows) in expected.items():
        with open(os.path.join(GATES_DIR, keys_name), encoding='utf-8') as handle:
            text = handle.read()
        rows = []
        for line in text.splitlines():
            entry = line.strip()
            if entry.startswith('('):
                row = ast.literal_eval(entry)
                if len(row) >= 3:
                    rows.append(row)
                    if row[2] == 'CWE-338':
                        c338_rows -= 1
        if len(rows) != total_rows:
            failures.append(f'{keys_name}: {len(rows)} keys, expected {total_rows}')
        if c338_rows:
            failures.append(f'{keys_name}: the CWE-338 key census moved, so the value-domain proof '
                            'is no longer over the frozen baseline')
        print(f'  tier1 {keys_name}: {len(rows)} keys, CWE-338 census intact')
    return failures


def check_slice_a() -> list:
    failures = []
    for name, (path, source, expected_loud, expected_records) in sorted(C22_FIXTURES.items()):
        loud, _registered, records = scan({path: source}, 'CWE-22')
        if loud != expected_loud:
            failures.append(f'{name}: CWE-22 lines {loud}, expected {expected_loud}')
        if records != expected_records:
            failures.append(f'{name}: {records} CWE-22 sink_records, expected {expected_records}; '
                            'the registration prune is the whole yield of this slice')
    print('  tier2 slice A fixtures checked:', len(C22_FIXTURES))
    return failures


def check_slice_b() -> list:
    failures = []
    for name, (path, source, expected) in sorted(C338_FIXTURES.items()):
        loud, registered, _records = scan({path: source}, 'CWE-338')
        if loud != expected:
            failures.append(f'{name}: CWE-338 lines {loud}, expected {expected}')
        if expected and not registered:
            failures.append(f'{name}: reported but no sink registered, so the census is not the '
                            'census being asserted')
        if not expected and registered:
            failures.append(f'{name}: quiet but {registered} sink(s) still registered; the prune '
                            'moved back to emission and the cascade is paying for it again')
    print('  tier3 slice B fixtures checked:', len(C338_FIXTURES))
    return failures


def check_slice_c() -> list:
    failures = []
    for name, (path, source, expected) in sorted(C208_FIXTURES.items()):
        loud, _registered, _records = scan({path: source}, 'CWE-208')
        if loud != expected:
            failures.append(f'{name}: CWE-208 lines {loud}, expected {expected}')
    print('  tier4 slice C fixtures checked:', len(C208_FIXTURES))
    return failures


def check_blessed_lines_stay_loud() -> list:
    """The blessed lines a widened value-domain proof could actually reach, re-scanned loud."""
    failures = []
    with open(os.path.join(BIG8_CORPUS, MODELING_COMMON), encoding='utf-8', errors='replace') as handle:
        common_src = handle.read()
    loud, _reg, _rec = scan({os.path.join(BIG8_CORPUS, MODELING_COMMON): common_src}, 'CWE-338')
    for line in (6606, 6698, 6722):
        if line not in loud:
            failures.append(f'{MODELING_COMMON}:{line} went silent; it is a blessed CWE-338 key')
    loud22, _r2, _c2 = scan({os.path.join(BIG8_CORPUS, MODELING_COMMON): common_src}, 'CWE-22')
    if 1279 not in loud22:
        failures.append(f'{MODELING_COMMON}:1279 went silent; the mandate names it as the read-only '
                        'test open that must stay loud, and its path is a runtime name')
    with open(os.path.join(BIG8_CORPUS, GENERATION_UTILS), encoding='utf-8', errors='replace') as handle:
        gen_src = handle.read()
    loud_gen, _rg, _rc = scan({os.path.join(BIG8_CORPUS, GENERATION_UTILS): gen_src}, 'CWE-338')
    for line in (3352, 3367, 3384):
        if line not in loud_gen:
            failures.append(f'{GENERATION_UTILS}:{line} went silent; it is a blessed CWE-338 key')
    with open(os.path.join(BIG8_CORPUS, WHISPER), encoding='utf-8', errors='replace') as handle:
        whisper_src = handle.read()
    loud_wh, _rw, _rcw = scan({os.path.join(BIG8_CORPUS, WHISPER): whisper_src}, 'CWE-338')
    if 97 not in loud_wh:
        failures.append(f'{WHISPER}:97 went silent; it is a blessed CWE-338 key')
    print('  tier5 blessed lines re-scanned loud: 8')
    return failures


def check_source_shape() -> list:
    failures = []
    with open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8') as handle:
        source = handle.read()
    for spelling in ('def _c22_is_literal_readonly_open',
                     'leaf == "uniform" and len(node.args) == 2',
                     'loop.iter is node',
                     '"passwords", "seeds",'):
        if spelling not in source:
            failures.append(f'the shipped proof is gone from the engine: {spelling}')
    for marker in ('_C338_BLESSED_LINES_SHIELD', '_C338_BLESSED_LINES', 'is_test_or_eval'):
        if marker in source:
            failures.append(f'a retired name/line shield is back in the engine: {marker}')
    print('  tier6 source spellings checked: 4 present, 3 retired markers absent')
    return failures


def run_mutations() -> list:
    """Every conjunct must move under its own mutation, and the engine must come back identical."""
    results = []

    shipped_literal = ast_scanner.TaintTracker._c22_is_literal_readonly_open
    ast_scanner.TaintTracker._c22_is_literal_readonly_open = lambda self, node: False
    try:
        _loud, _reg, records = scan({'src/m.py': C22_FIXTURES['literal_read'][1]}, 'CWE-22')
        results.append(('c22_literal_proof_blinded', records == 1))
    finally:
        ast_scanner.TaintTracker._c22_is_literal_readonly_open = shipped_literal

    shipped_display = ast_scanner.TaintTracker._cwe338_display_only_draw

    def blind_leaf(leaf_name):
        def mutant(self, node, scope_id=''):
            leaf = (node.func.attr if isinstance(node.func, ast.Attribute)
                    else (node.func.id if isinstance(node.func, ast.Name) else ''))
            if leaf == leaf_name:
                return False
            return shipped_display(self, node, scope_id)
        return mutant

    ast_scanner.TaintTracker._cwe338_display_only_draw = blind_leaf('uniform')
    try:
        loud, _r, _c = scan({'src/transformers/models/m.py': UNIFORM_UNIT}, 'CWE-338')
        results.append(('c338_uniform_proof_blinded', loud == [4]))
    finally:
        ast_scanner.TaintTracker._cwe338_display_only_draw = shipped_display

    ast_scanner.TaintTracker._cwe338_display_only_draw = blind_leaf('sample')
    try:
        loud, _r, _c = scan({'examples/run_qa.py': SAMPLE_INDEX}, 'CWE-338')
        results.append(('c338_sample_proof_blinded', loud == [3]))
    finally:
        ast_scanner.TaintTracker._cwe338_display_only_draw = shipped_display

    shipped_words = ast_scanner.CWE338_SECURITY_NAME_WORDS
    ast_scanner.CWE338_SECURITY_NAME_WORDS = frozenset(shipped_words - {'passwords'})
    try:
        loud, _r, _c = scan({'examples/m.py': C338_FIXTURES['sample_passwords_veto_loud'][1]}, 'CWE-338')
        results.append(('plural_veto_completion_is_load_bearing', loud == []))
    finally:
        ast_scanner.CWE338_SECURITY_NAME_WORDS = shipped_words

    shipped_secrets = ast_scanner.TaintTracker._compares_two_secrets
    shipped_assertion = ast_scanner.TaintTracker._c208_is_unit_test_assertion

    def without_constant_refusal(self, node, file_path=''):
        operands = [node.left] + list(node.comparators)
        if any(isinstance(o, ast.Constant) for o in operands):
            return not self._c208_is_tensor_dimension_compare(node, file_path)
        return shipped_secrets(self, node, file_path)

    ast_scanner.TaintTracker._compares_two_secrets = without_constant_refusal
    try:
        loud, _r, _c = scan({'tests/test_m.py': C208_FIXTURES['test_credential_int_quiet'][1]}, 'CWE-208')
        loud_plain, _rp, _cp = scan({'tests/test_m.py': C208_FIXTURES['test_plain_int_quiet'][1]}, 'CWE-208')
        results.append(('c208_constant_refusal_is_load_bearing', loud == [2] and loud_plain == []))
    finally:
        ast_scanner.TaintTracker._compares_two_secrets = shipped_secrets

    ast_scanner.TaintTracker._compares_two_secrets = without_constant_refusal
    ast_scanner.TaintTracker._c208_is_unit_test_assertion = lambda self, node, file_path='': False
    try:
        loud, _r, _c = scan({'tests/test_m.py': C208_FIXTURES['test_credential_int_quiet'][1]}, 'CWE-208')
        loud_plain, _rp, _cp = scan({'tests/test_m.py': C208_FIXTURES['test_plain_int_quiet'][1]}, 'CWE-208')
        results.append(('c208_both_guards_blinded_moves_the_tier', loud == [2] and loud_plain == []))
    finally:
        ast_scanner.TaintTracker._compares_two_secrets = shipped_secrets
        ast_scanner.TaintTracker._c208_is_unit_test_assertion = shipped_assertion

    restored = (ast_scanner.TaintTracker._c22_is_literal_readonly_open is shipped_literal
                and ast_scanner.TaintTracker._cwe338_display_only_draw is shipped_display
                and ast_scanner.CWE338_SECURITY_NAME_WORDS is shipped_words
                and ast_scanner.TaintTracker._compares_two_secrets is shipped_secrets
                and ast_scanner.TaintTracker._c208_is_unit_test_assertion is shipped_assertion)
    results.append(('engine_restored_after_mutation', restored))
    for name, ok in results:
        print(f'  {"ok " if ok else "FAIL"} mutation {name} -> '
              f'{"moves the tier" if ok else "does not move"}')
    return [name for name, ok in results if not ok]


def main() -> int:
    failures = []
    for check in (check_baseline_domain, check_slice_a, check_slice_b, check_slice_c,
                   check_blessed_lines_stay_loud, check_source_shape):
        failures.extend(check())
    failures.extend(run_mutations())
    if failures:
        print('VERDICT: FAIL - ' + '; '.join(str(f) for f in failures))
        return 1
    print('VERDICT: PASS - the literal read-only open never registers, the two CWE-338 value domains '
          'are quiet while every credential veto and all 8 blessed lines stay loud, the CWE-208 '
          'constant partition holds under two independent guards, and every conjunct moves under '
          'its own mutation.')
    return 0


if __name__ == '__main__':
    sys.exit(main())