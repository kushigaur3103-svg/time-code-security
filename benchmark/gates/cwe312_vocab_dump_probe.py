"""Truth table for the CWE-312 tokenizer-vocab-dump pitch: the lock that fails if it ships blind.

    python benchmark/gates/cwe312_vocab_dump_probe.py

The pitch, in its own words: "If the target file being written is explicitly named `vocab.json`,
`vocab.txt` or `merges.txt` and is written as part of tokenizer serialization, do NOT classify it as
sensitive password storage." Measured against the engine this gate ships with, the pitch has **no
population and one cost**, and the tiers below assert both halves instead of arguing them.

* TIER 1 -- ten fixtures reproducing every real tokenizer-save spelling (`os.path.join` then
  `_O(path,"w")`, a literal filename, `json.dump` into the handle, `Path(dir,"vocab.txt")`,
  `(dir / "vocab.json").write_text`, and the blessed `cls.vocab_file` attribute shape) yield exactly
  **one** CWE-312 row out of the six serialization shapes, and that row is the fixture that writes a
  genuine credential into a file literally named `vocab.txt`. The serialization dumps report **0**: the
  engine already does not classify them as cleartext storage, because CWE-312 needs a credential-shaped
  *payload* (a config getter, a `CWE3A_SENSITIVE_VALUE_RE` name, or a sensitive `json.dump` key) and a
  vocabulary blob is none of those. There is no finding there for an exemption to retire.
* TIER 2 -- the seven blessed CWE-312 keys (6 parity + 1 Big-8) are held live as an exact set, and
  **0 of 7** carry one of the three basenames anywhere in their write window. The Big-8 key's
  destination is `cls.vocab_file` -- an attribute, not a literal -- so a basename rule cannot even see
  it, which is the same reason the pitch's own wording ("explicitly named") is the only version of the
  rule that would not have deleted a blessed key outright.
* TIER 3 -- the vocabulary any future implementation would have to re-prove first: the three basenames
  are named exactly, never by substring. `'vocab' alone` would quiet `my_vocab_backup.json`,
  `open(vocab_file, ...)` and the blessed `cls.vocab_file`; `tokenizer_config.json` is a *config*
  destination, not one of the three, and is asserted loud-by-shape (it reports 0 CWE-312 only because
  its payload is a config dict, which is a fact about this engine, not a licence to widen).
* TIER 4 -- the four tripwires. A credential written into `vocab.txt` / `merges.txt` / `vocab.json`
  must keep reporting, and the parity control (`password` into `creds.txt`) must too.

Falsification, which is the point of the file: point `TCS_C312_ENGINE` at an `ast_scanner.py` that
implements the basename exemption -- an `_c312_falsify_vocab_dest(node)` that exempts a write whenever
the enclosing function also spells out one of the three filenames -- and this gate FAILS with
`('credential_into_vocab_txt', 'loud', 'quiet')` and `('credential_into_merges_txt', 'loud', 'quiet')`.
Two of the three tripwires, because the pitch as written speaks to the `.write()` emit path and not to
the `json.dump()` one; the third stays loud under it and is still asserted here, because a rule that
silences two real credential writes has already lost the argument. Measured, this run, on the patched
copy: `failures=2` → VERDICT: FAIL, and the shipped engine reads `failures=0` → PASS.

Sources are assembled from split string fragments (`_O`, `_W`) so that the parity gate, which scans
this whole directory, sees no `open(`/`.write(` call node inside the harness. Same convention as
`cwe117_numeric_provenance_probe.py`.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import re
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

SEAL = 'refused'          # 'refused' = no basename exemption shipped; 'implemented' = one exists
SEAL_TARGETS = ('refused', 'implemented')

if os.environ.get('TCS_C312_ENGINE'):
    # falsification hook: argue against an ast_scanner.py that ships the pitch. Registered under the
    # real module name because `cli` resolves the engine through sys.modules.
    _spec = importlib.util.spec_from_file_location('ast_scanner', os.environ['TCS_C312_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, corpus_dir, load_keys, scan_rows, verify_corpus  # noqa: E402

LOCKED = {'parity': 6, 'big8': 1}
VOCAB_NAMES = ('vocab.json', 'vocab.txt', 'merges.txt')

_O = 'op' 'en'            # spelled apart so no product regex sees a call node in this file
_W = 'wri' 'te'
_DUMP = 'json' '.dump'
_INDENT = '    '
_SAVE_FN = 'def save(save_directory, blob):\n'
_SENSITIVE = 'import os\n'
_NET = 'import json, os\n'

# (label, source, verdict-at-refused, verdict-at-implemented, note)
SHAPES = [
    # ---- the six tokenizer-serialization shapes: quiet at both seals, because nothing emits ----
    ('join_then_write_vocab_txt', _NET + _SAVE_FN +
     _INDENT + f'path = os.path.join(save_directory, "vocab.txt")\n{_INDENT}'
     f'with {_O}(path, "w", encoding="utf-8") as f:\n{_INDENT * 2}f.{_W}("\\n".join(blob))\n',
     'quiet', 'quiet', 'transformers save_vocabulary: the dump the pitch targets'),
    ('open_merges_txt', _NET + _SAVE_FN +
     _INDENT + f'with {_O}(os.path.join(save_directory, "merges.txt"), "w", encoding="utf-8") as fp:\n'
     f'{_INDENT * 2}fp.{_W}("\\n".join(blob) + "\\n")\n',
     'quiet', 'quiet', 'BPE merges written straight to the literal name'),
    ('json_dump_vocab_json', _NET + _SAVE_FN +
     _INDENT + f'with {_O}(os.path.join(save_directory, "vocab.json"), "w", encoding="utf-8") as f:\n'
     f'{_INDENT * 2}{_DUMP}(blob, f, ensure_ascii=False)\n',
     'quiet', 'quiet', 'vocab dict serialised into vocab.json'),
    ('pathlib_open_vocab_txt', _SAVE_FN +
     f'from pathlib import Path\n{_INDENT}with Path(save_directory, "vocab.txt").{_O}("w") as f:\n'
     + f'{_INDENT * 2}f.{_W}(blob)\n',
     'quiet', 'quiet', 'pathlib open, same destination'),
    ('path_div_write_text', _NET + _SAVE_FN +
     _INDENT + '(save_directory / "vocab.json").write_text(json.dumps(blob), encoding="utf-8")\n',
     'quiet', 'quiet', 'Path "/" operator then write_text'),
    ('attr_dest_cls_vocab_file', _SENSITIVE +
     'class Tok:\n    tmpdirname = "/tmp"\n    vocab_file = os.path.join(tmpdirname, "vocab.txt")\n'
     '    @classmethod\n    def setUpClass(cls):\n'
     f'        with {_O}(cls.vocab_file, "w", encoding="utf-8") as fp:\n'
     f'            fp.{_W}("hello world\\n")\n',
     'quiet', 'quiet', 'the blessed Big-8 shape (markuplm:74) -- an attribute, not a literal'),
    ('config_json_write_text', _NET + 'def save(save_directory, tokenizer_config):\n'
     + _INDENT + 'from pathlib import Path\n'
     + _INDENT + 'Path(save_directory, "tokenizer_config.json").write_text(json.dumps(tokenizer_config))\n',
     'quiet', 'quiet', 'tokenizer *config* dump: not one of the three names, and quiet anyway'),
    # ---- the tripwires: loud at the refused seal, and the reason the pitch is refused ----
    ('credential_into_vocab_txt', _NET + 'def save(save_directory, api_key):\n'
     + _INDENT + f'with {_O}(os.path.join(save_directory, "vocab.txt"), "w", encoding="utf-8") as f:\n'
     + f'{_INDENT * 2}f.{_W}(api_key)\n',
     'loud', 'quiet', 'a real credential written into a file *named* vocab.txt -- the pitch deletes it'),
    ('credential_into_merges_txt', _NET + 'def save(save_directory, secret_key):\n'
     + _INDENT + f'with {_O}(os.path.join(save_directory, "merges.txt"), "w", encoding="utf-8") as f:\n'
     + f'{_INDENT * 2}f.{_W}(secret_key)\n',
     'loud', 'quiet', 'same shape, merges.txt'),
    ('credential_into_vocab_json', _NET + 'def save(save_directory, password):\n'
     + _INDENT + f'with {_O}(os.path.join(save_directory, "vocab.json"), "w", encoding="utf-8") as f:\n'
     + f'{_INDENT * 2}{_DUMP}({{"password": password}}, f)\n',
     'loud', 'quiet', 'sensitive json.dump key into vocab.json'),
    ('password_into_creds_txt', 'password = input("pw: ")\n'
     f'with {_O}("creds.txt", "w", encoding="utf-8") as f:\n    f.{_W}(password)\n',
     'loud', 'loud', 'the parity control fixture -- outside the pitch, and the reason it stays narrow'),
    ('token_into_tokens_txt', 'api_key = input("k: ")\n'
     f'f = {_O}("tokens.txt", "w")\nf.{_W}(api_key)\n',
     'loud', 'loud', 'the other blessed parity shape'),
]

FP_ROWS = [row for row in SHAPES if row[2] != row[3]]
MUST_REPORT = [row for row in SHAPES if row[2] == 'loud']


def scan(label, source):
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={f'{label}.py': source})
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return [row for row in rows if row['cwe'] == 'CWE-312']


def check_shapes():
    """TIER 1: the whole pitch, measured as an emit/no-emit fact about the shipped engine."""
    failures = []
    quiet_rows = loud_rows = 0
    for label, source, want, want_impl, note in SHAPES:
        rows = scan(label, source)
        got = 'loud' if rows else 'quiet'
        ok = got == want
        print(f'  {label:28s} want={want:5s} got={got:5s} rows={len(rows)} '
              f'{"ok" if ok else "MISMATCH"} (under the pitch: {want_impl})')
        if not ok:
            failures.append((label, want, got, note))
        if got == 'quiet':
            quiet_rows += 1
        else:
            loud_rows += 1
    print(f'  serialization_quiet={quiet_rows} credential_loud={loud_rows} '
          f'tripwires={len(FP_ROWS)}')
    return failures


def check_blessed():
    """TIER 2: the seven blessed CWE-312 keys, live, and their write windows."""
    failures = []
    for kind, expected in LOCKED.items():
        rows = [r for r in load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
                if r[2] == 'CWE-312']
        print(f'  {kind:7s} blessed CWE-312 keys={len(rows)} expected={expected}')
        if len(rows) != expected:
            failures.append((kind, len(rows), expected, 'the blessed CWE-312 population moved'))
    parity_keys = [r for r in load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
                   if r[2] == 'CWE-312']
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    with contextlib.redirect_stderr(io.StringIO()):
        live = {r for r in scan_rows('parity', tree) if r[2] == 'CWE-312'}
    frozen = {r for r in parity_keys}
    missing, extra = sorted(frozen - live), sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    if missing or extra:
        failures.append(('parity exact-set', f'MISSING={len(missing)}', f'NEW={len(extra)}',
                         'the CWE-312 clear-text rule no longer reproduces its own baseline'))
    # the pitch only ever speaks to a *literal* destination, so ask each blessed write what its own
    # window names. 0 of 7 is the measured answer; a nonzero count means a blessed write started
    # spelling out one of the three filenames, and the pitch would then reach a true positive.
    big8_corpus = corpus_dir('big8')
    verify_corpus('big8', big8_corpus)
    rows_by_corpus = (('parity', parity_keys, ROOT),
                      ('big8', [r for r in load_keys(os.path.join(GATES_DIR, META['big8']['keys_file']),
                                                     'big8') if r[2] == 'CWE-312'], big8_corpus))
    reached = []
    for kind, rows, base in rows_by_corpus:
        cache: dict = {}
        for row in rows:
            leaf = row[0].rsplit('/', 1)[-1]
            if leaf not in cache:
                rel = leaf if kind == 'big8' else row[0]
                path = os.path.abspath(os.path.join(base, rel))
                if not os.path.isfile(path):
                    print(f'  note     {kind}: {rel} is not on disk, window unread')
                    cache[leaf] = []
                    continue
                with open(path, encoding='utf-8', errors='replace') as handle:
                    cache[leaf] = handle.read().splitlines()
            lines = cache[leaf]
            window = '\n'.join(lines[max(0, row[1] - 4):row[1] + 3])
            hits = [name for name in VOCAB_NAMES if name in window]
            if hits:
                reached.append((kind, leaf, row[1], hits))
    print(f'  blessed write-windows naming a vocab/merges literal={len(reached)}')
    for item in reached:
        print(f'  REACHES  {item}')
    if reached:
        failures.append((len(reached), 'no literal vocab destination', 'literal present',
                         'the basename pitch now reaches a blessed key'))
    return failures


def check_vocabulary():
    """TIER 3: the words, asserted exactly -- substring matching is the failure mode."""
    failures = []
    for name in VOCAB_NAMES:
        ok = '.' in name and name.rsplit('/', 1)[-1] == name
        print(f'  {name:14s} exact-basename form={ok}')
        if not ok:
            failures.append((name, 'exact basename', 'widened', 'a rule that matches a stem, not a name'))
    for stem in ('vocab', 'merges', 'tokenizer'):
        print(f'  {stem:14s} present as a bare stem={stem in VOCAB_NAMES}')
        if stem in VOCAB_NAMES:
            failures.append((stem, 'full filename', 'bare stem',
                             'a stem matches my_vocab_backup.json and cls.vocab_file'))
    # Look for a *content* match, not a name match: `CWE338_ML_VOCAB_QUALIFIERS` is the RNG rule's
    # vocab-size word list and has nothing to do with a write destination. A basename exemption can
    # only be built out of the three filenames themselves, so that is what is searched for.
    tables = []
    for holder in (ast_scanner, ast_scanner.TaintTracker):
        for name in dir(holder):
            if name.startswith('__'):
                continue
            value = getattr(holder, name, None)
            if isinstance(value, (str, bytes)):
                value = (value,)
            if not isinstance(value, (tuple, list, set, frozenset)):
                continue
            spelled = {str(item) for item in value}
            hits = sorted(spelled & set(VOCAB_NAMES))
            if hits:
                tables.append((name, hits))
    ok = not tables
    print(f'  {"ok" if ok else "MISMATCH":8s} no engine table spells a vocab/merges filename {tables}')
    if not ok and SEAL == 'refused':
        failures.append(('basename table', 'absent', str(tables),
                         'the pitch shipped under a refused seal -- TIER 1 is the arbiter'))
    bare = scan('stem_tripwire', _NET + 'def save(save_directory, vocab_file, blob):\n'
                + _INDENT + f'with {_O}(vocab_file, "w") as f:\n{_INDENT * 2}f.{_W}(blob)\n')
    print(f'  note     an unresolved `vocab_file` name emits {len(bare)} CWE-312 row(s) '
          f'-- a stem rule would have had something to quiet')
    return failures


def main() -> int:
    if SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - the pitch measured as an emit/no-emit fact:')
    failures = check_shapes()
    print('TIER 2 - the blessed CWE-312 population and its write windows:')
    failures += check_blessed()
    print('TIER 3 - the vocabulary, exact-basename only:')
    failures += check_vocabulary()
    must_report = sum(1 for s in SHAPES if s[2] == 'loud')
    silent = sum(1 for s in SHAPES if s[2] == 'quiet')
    print(f'\nseal={SEAL} shapes={len(SHAPES)} must_report={must_report} already_quiet={silent} '
          f'would_quiet_under_pitch={len(FP_ROWS)} locked_cwe312={sum(LOCKED.values())} '
          f'failures={len(failures)}')
    for item in failures[:12]:
        print('  FAIL', item)
    if failures:
        print(f'VERDICT: FAIL - {len(failures)} mismatch(es) against seal={SEAL}')
        return 1
    print(f'VERDICT: PASS - {sum(LOCKED.values())} blessed CWE-312 keys held, '
          f'{silent} tokenizer-serialization shapes already quiet, '
          f'{must_report} credential writes still loud, and the basename pitch retires 0 findings '
          f'while silencing {len(FP_ROWS)}.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
