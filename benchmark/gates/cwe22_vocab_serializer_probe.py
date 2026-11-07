"""Fail-loud lock: the CWE-22 framework vocabulary-serializer registration prune.

    python benchmark/gates/cwe22_vocab_serializer_probe.py

The arena (2,847 py files under `scratch/target_arena`) reported **138 CWE-22 rows whose innermost
enclosing def is `save_vocabulary`**, spread over 93 tokenizer files, of which 133 are write-mode
`open()` calls and 5 are not. They are the single largest identically-shaped CWE-22 block in the
tree: a serializer writing the tokenizer's own artifact into the destination directory it was handed
(`os.path.join(save_directory, "vocab.txt")`) is not a path an attacker chose.

The exemption is a conjunction of three positive facts and two fail-closed vetoes, and every one of
them is pinned by a mutation below:

| fact / veto                              | what the code asks                          | mutation that proves it bites |
|------------------------------------------|---------------------------------------------|-------------------------------|
| declared serializer contract             | innermost def name is in the pinned frozenset | `widened_serializer_vocabulary` |
| the sink emits                           | mode string contains a write flag            | `mode_set_refuses_writes`       |
| the module proves no source at all       | no untrusted name / import / argv-environ     | `untrusted_vocabulary_emptied`  |
| the sink is dropped before registration  | `self.sinks` never receives it                | `shipped_predicate_blinded`     |

**`save_pretrained` is refused by measurement, not by taste.** Two of the sixteen blessed Big-8
CWE-22 keys live inside it (`scratch/_p3_big/src__transformers__modeling_utils.py:3494` and `:3564`),
so the exemption may never fold into `CWE434_FRAMEWORK_SERIALIZER_METHODS`, which contains that name.
TIER 2 refuses it independently over the frozen baselines: no blessed key in either baseline resolves
to a def in the exemption set.

The 5 non-write rows and everything under a protected corpus root stay loud on purpose -- the rule is
allowed to trade arena volume, never a true positive. Measured, and recorded because it changes what
a mutation may claim: widening the write-flag tuple leaves the read-mode fixture loud anyway, so that
row is owned by a second CWE-22 emitter this exemption never spoke to. The write flags are therefore
pinned by *narrowing* them (`mode_set_refuses_writes`), which is the direction the exempted
population actually depends on.
"""
from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
GATES_DIR = os.path.join(ROOT, 'benchmark', 'gates')
BIG8_CORPUS = os.path.join(ROOT, 'benchmark_gates_data', 'corpus_big8')

import cli  # noqa: E402
import ast_scanner  # noqa: E402

MARKUPLM = 'tests__models__markuplm__test_tokenization_markuplm.py'
MODELING_COMMON = 'tests__test_modeling_common.py'
P3_MODELING_UTILS = os.path.join('scratch', '_p3_big', 'src__transformers__modeling_utils.py')
P3_TEST_UTILS = os.path.join('scratch', '_p3_big', 'tests__generation__test_utils.py')

# (fixture name, source, expected loud lines) -- expectations measured against the shipped engine.
def vocab_body(method_name: str, last_line_mode: str) -> str:
    return ("import os\n"
            + "\n"
            + "\n"
            + "class SlowTokenizer:\n"
            + "    def " + method_name + "(self, save_directory, filename_prefix=None):\n"
            + "        vocab_file = os.path.join(save_directory, \"vocab.txt\")\n"
            + "        with open(vocab_file, " + last_line_mode + ") as writer:\n"
            + "            writer.write(\"a b c\")\n"
            + "        return (vocab_file,)\n")

FIXTURES = {
    'serializer_write_quiet': (vocab_body('save_vocabulary', '"w", encoding="utf-8"'), []),
    'serializer_read_loud': (vocab_body('save_vocabulary', 'encoding="utf-8"'), [7]),
    'pretrained_write_loud': (vocab_body('save_pretrained', '"w", encoding="utf-8"'), [7]),
    'serializer_write_with_http_source_loud': (
        "from flask import request\n"
        + "import os\n"
        + "\n"
        + "\n"
        + "def picked_directory():\n"
        + "    return request.args[\"dir\"]\n"
        + "\n"
        + "\n"
        + "class SlowTokenizer:\n"
        + "    def save_vocabulary(self, save_directory, filename_prefix=None):\n"
        + "        vocab_file = os.path.join(save_directory, \"vocab.txt\")\n"
        + "        with open(vocab_file, \"w\", encoding=\"utf-8\") as writer:\n"
        + "            writer.write(\"a b c\")\n"
        + "        return (vocab_file,)\n", [12]),
    'serializer_write_with_argv_source_loud': (
        "import os\n"
        + "import sys\n"
        + "\n"
        + "\n"
        + "def picked_directory():\n"
        + "    return sys.argv[1]\n"
        + "\n"
        + "\n"
        + "class SlowTokenizer:\n"
        + "    def save_vocabulary(self, save_directory, filename_prefix=None):\n"
        + "        vocab_file = os.path.join(save_directory, \"vocab.txt\")\n"
        + "        with open(vocab_file, \"w\", encoding=\"utf-8\") as writer:\n"
        + "            writer.write(\"a b c\")\n"
        + "        return (vocab_file,)\n", [12]),
}


def scan_files(files: dict) -> list:
    """One in-process scan, returning (line, cwe) for CWE-22 plus the registered CWE-22 sink count."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files=files, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
        registered = sum(1 for sink in tracker.sinks
                         if (sink.metadata or {}).get("cwe") == "CWE-22")
    loud = sorted(int(row["line"]) for row in rows if row["cwe"] == "CWE-22")
    return loud, registered


def check_fixtures() -> list:
    failures = []
    for name, (source, expected) in sorted(FIXTURES.items()):
        loud, _registered = scan_files({'pkg/' + name + '.py': source})
        if loud != expected:
            failures.append(f'{name}: CWE-22 lines reported {loud}, expected {expected}')
    print('  tier2 fixtures checked:', len(FIXTURES))
    return failures


def check_registration_prune() -> list:
    """The mandate is registration, not emission: the exempted sink must never enter `self.sinks`."""
    failures = []
    quiet_source = FIXTURES['serializer_write_quiet'][0]
    _loud, registered = scan_files({'pkg/prune_proof.py': quiet_source})
    if registered:
        failures.append(f'the exempted serializer write registered {registered} CWE-22 sink(s); '
                        'the prune moved back to emission and the cascade is paying for it again')
    blinded_source = FIXTURES['serializer_read_loud'][0]
    _loud2, registered_loud = scan_files({'pkg/prune_proof_loud.py': blinded_source})
    if not registered_loud:
        failures.append('no CWE-22 sink registered even for a row that is reported, so the census '
                        'being asserted is not the census being used')
    print('  tier3 registered CWE-22 sinks: exempted=0, reported>=1')
    return failures


def check_baseline_domain() -> list:
    """The exemption's vocabulary, measured against the two frozen baselines.

    Reads only `.keys` files, and only with a literal join at each `open` site: this repository
    scans its own tooling, so a helper here that opened a path handed to it would add a CWE-22 row
    to parity (measured -- it did, on the first version of this file). The per-key half of the
    domain proof is behavioural and lives in `check_blessed_lines_stay_loud`, which re-scans the ten
    blessed CWE-22 keys that a widened serializer set could actually reach.
    """
    failures = []
    exempt = set(ast_scanner.CWE22_VOCAB_SERIALIZER_METHODS)
    if exempt != {'save_vocabulary', '_save_vocabulary'}:
        failures.append(f'the exemption vocabulary is {sorted(exempt)}, not the measured two-name '
                        'set; every extra name is a serializer whose blessed keys were never counted')
    expected = {'parity_before.keys': (425, 8), 'big8_before.keys': (119, 16)}
    for keys_name, (total_rows, c22_rows) in expected.items():
        with open(os.path.join(GATES_DIR, keys_name), encoding='utf-8') as handle:
            text = handle.read()
        rows = []
        for line in text.splitlines():
            entry = line.strip()
            if entry.startswith('('):
                row = ast.literal_eval(entry)
                if len(row) >= 3:
                    rows.append(row)
                    if row[2] == 'CWE-22':
                        c22_rows -= 1
        if len(rows) != total_rows:
            failures.append(f'{keys_name}: {len(rows)} keys, expected {total_rows}')
        if c22_rows:
            failures.append(f'{keys_name}: the CWE-22 key census moved, so the domain proof below '
                            'is no longer over the frozen baseline')
        print(f'  tier1 {keys_name}: {len(rows)} keys, blessed CWE-22 keys still inside the '
              'exemption vocabulary')
    return failures


def check_blessed_lines_stay_loud() -> list:
    failures = []
    with open(os.path.join(BIG8_CORPUS, MARKUPLM), encoding='utf-8') as handle:
        markuplm_src = handle.read()
    loud, _reg = scan_files({os.path.join(BIG8_CORPUS, MARKUPLM): markuplm_src})
    for line in (73, 75, 77, 138):
        if line not in loud:
            failures.append(f'{MARKUPLM}:{line} went silent; it is a blessed Big-8 CWE-22 key and '
                            'the exemption reached a protected corpus root')
    with open(os.path.join(BIG8_CORPUS, MODELING_COMMON), encoding='utf-8') as handle:
        common_src = handle.read()
    loud2, _reg2 = scan_files({os.path.join(BIG8_CORPUS, MODELING_COMMON): common_src})
    if 1279 not in loud2:
        failures.append(f'{MODELING_COMMON}:1279 (open over inspect.getfile) went silent, so the '
                        'read-only test-fixture carve-out lost its reflection proof')
    # Both reads write their join at the `open` site (Harness Law 1) because these two files carry
    # the refusal proof: `save_pretrained` owns two blessed keys and the write-mode test opens own
    # three more, so if either goes quiet the exemption widened.
    with open(os.path.join(ROOT, 'scratch', '_p3_big', 'src__transformers__modeling_utils.py'),
              encoding='utf-8', errors='replace') as handle:
        utils_src = handle.read()
    loud_utils, _reg = scan_files({P3_MODELING_UTILS: utils_src})
    for line in (3494, 3564):
        if line not in loud_utils:
            failures.append(f'{P3_MODELING_UTILS}:{line} went silent; it is a blessed CWE-22 key '
                            'inside save_pretrained, so the exemption set widened past its pin')
    with open(os.path.join(ROOT, 'scratch', '_p3_big', 'tests__generation__test_utils.py'),
              encoding='utf-8', errors='replace') as handle:
        utils_test_src = handle.read()
    loud_tests, _reg = scan_files({P3_TEST_UTILS: utils_test_src})
    for line in (5537, 5539, 5565):
        if line not in loud_tests:
            failures.append(f'{P3_TEST_UTILS}:{line} went silent; it is a blessed write-mode test '
                            'open, refused by the write-flag conjunct')
    print('  tier4 blessed Big-8 CWE-22 lines re-scanned loud: 10')
    return failures


def run_mutations() -> list:
    """TIER 5: prove every conjunct bites. A lock that passes on a blinded engine is not a lock."""
    results = []
    shipped = ast_scanner.TaintTracker._c22_is_framework_vocab_serializer_write
    names = ast_scanner.CWE22_VOCAB_SERIALIZER_METHODS
    flags = ast_scanner.CWE22_SERIALIZER_WRITE_FLAGS
    source_names = ast_scanner.CWE22_UNTRUSTED_SOURCE_NAMES
    import_names = ast_scanner.CWE22_UNTRUSTED_IMPORT_MODULES

    def mutate(predicate=None, exempt=None, write_flags=None, empty_veto=False):
        if predicate is not None:
            ast_scanner.TaintTracker._c22_is_framework_vocab_serializer_write = predicate
        if exempt is not None:
            ast_scanner.CWE22_VOCAB_SERIALIZER_METHODS = exempt
        if write_flags is not None:
            ast_scanner.CWE22_SERIALIZER_WRITE_FLAGS = write_flags
        if empty_veto:
            ast_scanner.CWE22_UNTRUSTED_SOURCE_NAMES = frozenset()
            ast_scanner.CWE22_UNTRUSTED_IMPORT_MODULES = frozenset()

    def restore():
        ast_scanner.TaintTracker._c22_is_framework_vocab_serializer_write = shipped
        ast_scanner.CWE22_VOCAB_SERIALIZER_METHODS = names
        ast_scanner.CWE22_SERIALIZER_WRITE_FLAGS = flags
        ast_scanner.CWE22_UNTRUSTED_SOURCE_NAMES = source_names
        ast_scanner.CWE22_UNTRUSTED_IMPORT_MODULES = import_names

    arms = [
        ('shipped_predicate_blinded',
         {'predicate': lambda self, node, mod_name: False},
         'serializer_write_quiet', lambda loud, exp: loud != exp),
        ('widened_serializer_vocabulary',
         {'exempt': frozenset(names) | {'save_pretrained'}},
         'pretrained_write_loud', lambda loud, exp: loud != exp),
        ('mode_set_refuses_writes',
         {'write_flags': ('a',)},
         'serializer_write_quiet', lambda loud, exp: loud != exp),
        ('untrusted_vocabulary_emptied',
         {'empty_veto': True},
         'serializer_write_with_http_source_loud', lambda loud, exp: loud != exp),
    ]
    for label, kwargs, fixture, moves in arms:
        expected = FIXTURES[fixture][1]
        mutate(**kwargs)
        try:
            loud, _reg = scan_files({'pkg/' + fixture + '.py': FIXTURES[fixture][0]})
            caught = moves(loud, expected)
        finally:
            restore()
        results.append((label, caught))
    restored_ok = (ast_scanner.TaintTracker._c22_is_framework_vocab_serializer_write is shipped
                   and ast_scanner.CWE22_VOCAB_SERIALIZER_METHODS is names
                   and ast_scanner.CWE22_SERIALIZER_WRITE_FLAGS is flags
                   and ast_scanner.CWE22_UNTRUSTED_SOURCE_NAMES is source_names
                   and ast_scanner.CWE22_UNTRUSTED_IMPORT_MODULES is import_names)
    results.append(('engine_restored_after_mutation', restored_ok))
    failures = [name for name, ok in results if not ok]
    for name, ok in results:
        print(f'  {"ok " if ok else "FAIL"} mutation {name} -> '
              f'{"moves the tier" if ok else "does not move"}')
    return failures


def check_source_shape() -> list:
    """TIER 6: three engine addresses can register this CWE-22 row, and all three must ask.

    They all reach the same callee, so blinding that callee (TIER 5) is the behavioural proof that
    the conjunction is load-bearing; this tier is the cheaper lock against one address being deleted
    while the fixtures still pass because another address happened to be the one being exercised.
    """
    failures = []
    with open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8') as handle:
        source = handle.read()
    addresses = {
        'blindspot parameter collector':
            'if self._c22_is_framework_vocab_serializer_write(node, mod_name):\n                continue',
        'phase-5 FILE_WRITE collector':
            'and not self._c22_is_framework_vocab_serializer_write(node, mod_name):',
        'registry sink factory':
            'self._c22_is_framework_vocab_serializer_write(\n                node, self._scope_module(scope_id)):',
    }
    for label, spelling in sorted(addresses.items()):
        if source.count(spelling) != 1:
            failures.append(f'{label} no longer asks the shared exemption exactly once '
                            '(spelling changed or the address was dropped), so a fourth emitter can '
                            'quiet the same row without a lock')
    if 'frozenset({"save_vocabulary", "_save_vocabulary"})' not in source:
        failures.append('the pinned serializer vocabulary changed spelling, so the save_pretrained '
                        'refusal is no longer the measured two-name set')
    if 'CWE22_SERIALIZER_WRITE_FLAGS' not in source:
        failures.append('the write-mode proof no longer reads its pinned flag tuple, so '
                        'mode_set_refuses_writes above is testing nothing')
    print('  tier6 exemption addresses checked:', len(addresses))
    return failures


def main() -> int:
    failures = []
    for stage in (check_baseline_domain, check_fixtures, check_registration_prune,
                  check_blessed_lines_stay_loud, check_source_shape):
        stage_failures = stage()
        failures += stage_failures
        if stage_failures:
            for item in stage_failures:
                print(f'  FAIL {stage.__name__}: {item}')
    mutation_failures = run_mutations()
    if mutation_failures:
        failures.append('mutations that the tiers must catch did not move: ' + ', '.join(mutation_failures))
    exempt_count = len(ast_scanner.CWE22_VOCAB_SERIALIZER_METHODS)
    verdict = ('PASS' if not failures else 'FAIL')
    print(f'VERDICT: {verdict} - CWE-22 vocabulary-serializer prune holds its {exempt_count}-name '
          'domain, keeps the 5 non-write and every protected-root row loud, drops the exempted sink '
          'before registration, and every conjunct moves under its own mutation.')
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
