"""Shared plumbing for the tracked verification gates.

Why this exists: the baseline key files were blessed on one machine and spell the same file two
different ways -- 416 rows relative (`benchmark/corpus/...`) and 9 rows absolute
(`C:/Users/<user>/<repo>/benchmark/fixtures/...`). Diffing those strings verbatim makes a gate
pass only on the machine that recorded it. Every key is therefore reduced to one repo-relative
spelling before it is compared, which lets the baseline bytes stay exactly as they were while the
gate runs anywhere.

Nothing here touches detection logic: it is path arithmetic over findings the engine already made.
The scan itself runs in `scan_child.py`, so no code in this directory assembles Python source.

Run `python benchmark/gates/gate_common.py` for the portability self-test.
"""
from __future__ import annotations

import ast
import hashlib
import json
import ntpath
import os
import posixpath
import re
import subprocess
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))


class GatePathError(RuntimeError):
    """A key file or corpus is not in the shape this gate can verify. Loud beats silently wrong."""


def find_root(start: str) -> str:
    """Repository root: the first ancestor holding both `cli.py` and `benchmark/`."""
    current = os.path.dirname(os.path.abspath(start))
    while True:
        if (os.path.isfile(os.path.join(current, 'cli.py'))
                and os.path.isdir(os.path.join(current, 'benchmark'))):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            raise GatePathError(f'no repository root found above {start}')
        current = parent


ROOT = find_root(__file__)
with open(os.path.join(GATES_DIR, 'gate_meta.json'), encoding='utf-8') as _handle:
    META = json.load(_handle)
ROOT_POSIX = ROOT.replace('\\', '/')


def _posix(path) -> str:
    return str(path).replace('\\', '/')


def _root_spellings(recorded_root):
    """Both separators of both roots, longest first.

    Longest-first matters when one root contains the other: a checkout nested inside the blessing
    path would otherwise keep the inner segment as machine-specific text.
    """
    spellings = set()
    for base in (ROOT_POSIX, _posix(recorded_root or '')):
        base = str(base).rstrip('/')
        if base:
            spellings.add(base)
            spellings.add(base.replace('/', '\\'))
    return sorted(spellings, key=len, reverse=True)


_ROOT_TOKEN = '<root>'
_ROOT_RE: dict = {}


def _root_re(recorded_root):
    """`root` + the path run that follows it, as one alternation over both roots and separators.

    Compiled once per root spelling and cached: `canon_key` runs this over every key on both sides.
    """
    key = str(recorded_root)
    if key not in _ROOT_RE:
        spellings = _root_spellings(recorded_root)
        if not spellings:
            _ROOT_RE[key] = None
        else:
            _ROOT_RE[key] = re.compile(
                r'(?P<root>(?:{}))(?P<tail>[^\s,]*)'.format('|'.join(re.escape(s) for s in spellings))
            )
    return _ROOT_RE[key]


def scrub_message(message, recorded_root):
    """Rewrite a checkout's absolute path inside a message to `<root>/relative/path`, so one finding
    reads identically on the blessing machine, on any other clone, and across separators.

    The root *and only the path run hanging off it* are folded: separators become `/` and the tail --
    file, line, sink symbol -- survives byte-for-byte inside the canonical form. So a finding that
    moves to another file or line still yields a different key, and text that never started with a
    known root is left exactly as the engine wrote it. Nine parity messages embed the blessing
    machine's absolute path (`... flows into ... at C:\\...\\repo01.py:7`), which made
    `aa_parity.py` unmatchable on any other checkout: MISSING=9 NEW=9 while every true positive was
    still reported.
    """
    if not isinstance(message, str):
        return message
    pattern = _root_re(recorded_root)
    if pattern is None:
        return message

    def canonical(match) -> str:
        return f'{_ROOT_TOKEN}/{_posix(match.group("tail")).lstrip("/")}'

    return pattern.sub(canonical, message)


def relativise(raw_path, recorded_root):
    """Repo-relative spelling of a path, from the blessing machine or from any other checkout.

    The live root is tried first: a checkout nested inside the blessing path (a worktree under the
    recorded root) must rebase against the tree it actually lives in, or its keys come out labelled
    with the outer path. The recorded root is data in `gate_meta.json`, never a guess, so rebasing
    is exact. A path absolute under neither root raises, because a key this gate cannot place is a
    key it cannot honestly compare.
    """
    path = _posix(raw_path)
    for prefix in (ROOT_POSIX, recorded_root):
        if not prefix:
            continue
        prefix = _posix(prefix).rstrip('/')
        if path == prefix or path.startswith(prefix + '/'):
            return path[len(prefix) + 1:]
    if ntpath.isabs(path) or posixpath.isabs(path):
        raise GatePathError(f'cannot rebase absolute path {raw_path!r}')
    return path


def canon_key(row, kind: str):
    """One finding key, rebased so the same finding hashes identically in every checkout.

    Three rebases, all driven by `gate_meta.json` and none touching the stored bytes:

    - `scan_root` -- the gate scans a tree from inside it, so the engine spells its files relative
      to that tree (`corpus/x/bad.py`) while the baseline spells them from the repo root
      (`benchmark/corpus/x/bad.py`). The recorded prefix is put back.
    - `corpus_files` -- the Big-8 corpus has lived in two directories, so its keys collapse to the
      pinned `<corpus_marker>/<leaf>` form and a stray file in the corpus is an error, not a finding.
    - message -- an absolute root embedded in a finding's message is this machine's address, not a
      property of the finding, so it collapses to `<root>` (see `scrub_message`).
    """
    meta = META[kind]
    file_field = relativise(row[0], meta.get('recorded_root'))
    root = meta.get('scan_root')
    if root and not (file_field == root or file_field.startswith(root + '/')):
        file_field = f'{root}/{file_field}'
    names = meta.get('corpus_files') or {}
    if names:
        leaf = file_field.rsplit('/', 1)[-1]
        if leaf not in names:
            raise GatePathError(f'{file_field!r} is not a {kind} corpus file')
        file_field = f'{meta["corpus_marker"]}/{leaf}'
    rest = list(row[1:])
    if len(rest) > 3:
        rest[3] = scrub_message(rest[3], meta.get('recorded_root'))
    return (file_field,) + tuple(rest)


def load_keys(path: str, kind: str):
    """Canonical key tuples from a frozen baseline file.

    A header line that is a dict (the parity file's run metadata) is skipped: only tuples are
    findings. This is the only reader of the baselines; no gate ever writes to them.
    """
    out = []
    with open(path, encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if line.startswith('('):
                out.append(canon_key(ast.literal_eval(line), kind))
    return out


def scan_rows(kind: str, cwd: str):
    """Canonical keys from scanning one tree with the working copy of the engine.

    `cwd` is the tree under test and the only variable in the call: `scan_child.py` scans `.`, so
    the command line holds nothing but constants. That is deliberate -- this directory sits inside
    the parity scan, and an argument-derived element in an argv list is the pattern the product
    reports as CWE-78. The keys arrive over stdout, so a run writes no file anywhere.
    """
    proc = subprocess.run([sys.executable, os.path.join(GATES_DIR, 'scan_child.py')],
                          cwd=cwd, capture_output=True, encoding='utf-8', errors='replace')
    if proc.returncode != 0:
        raise GatePathError(f'scan in {cwd!r} failed (exit {proc.returncode}):\n'
                            f'{proc.stdout[-400:]}{proc.stderr[-800:]}')
    rows = []
    for line in proc.stdout.splitlines():
        if line.startswith('('):
            rows.append(canon_key(ast.literal_eval(line), kind))
    return rows


def corpus_dir(kind: str, override=None) -> str:
    """Locate the corpus: explicit argument, tracked home, then the legacy untracked copy."""
    if override:
        path = os.path.abspath(override)
        if not os.path.isdir(path):
            raise GatePathError(f'corpus directory not found: {path}')
        return path
    looked = []
    for candidate in META[kind].get('corpus_search_paths') or ():
        path = os.path.join(ROOT, _posix(candidate))
        looked.append(path)
        if os.path.isdir(path):
            return path
    raise GatePathError(
        f'{kind} corpus not found. Put it in '
        f'{META[kind]["corpus_marker"]}/ (or the legacy scratch copy) and retry. Looked in: '
        + ' -> '.join(looked))


def verify_corpus(kind: str, directory: str) -> None:
    """Fail if the corpus is not byte-identical to the one the frozen baseline came from.

    This is what replaces re-running the pinned engine every time: the frozen keys can only still be
    an authority if the input is still the same eight files. Each name is reduced to its basename
    before joining, so a tampered `gate_meta.json` cannot walk out of the corpus directory.
    """
    for name, digest in META[kind]['corpus_sha256'].items():
        path = os.path.join(directory, os.path.basename(name))
        if not os.path.isfile(path):
            raise GatePathError(f'corpus file missing: {path}')
        with open(path, 'rb') as handle:
            actual = hashlib.sha256(handle.read()).hexdigest()
        if actual != digest:
            raise GatePathError(f'corpus drift in {name}:\n  got    {actual}\n  expect {digest}')


def diff(before, after):
    return sorted(set(before) - set(after)), sorted(set(after) - set(before))


def report(kind: str, before_n: int, after_n: int, missing, new, expected: int) -> int:
    print(f'baseline={before_n} now={after_n} MISSING={len(missing)} NEW={len(new)}')
    for item in missing[:8]:
        print('  MISSING:', item)
    for item in new[:8]:
        print('  NEW    :', item)
    if missing or new:
        print(f'VERDICT: FAIL - {kind} keys moved, and a true positive may be among them.')
        return 1
    if after_n != expected or before_n != expected:
        print(f'VERDICT: FAIL - {kind} expected {expected} keys on each side, '
              f'got {before_n}/{after_n}.')
        return 1
    print(f'VERDICT: PASS - {kind} {expected}/{expected}, exact-set match.')
    return 0


def _selftest() -> int:
    """A key must canonicalise the same on the blessing machine as on any other checkout."""
    meta = META['parity']
    leaf = 'benchmark/corpus/cwe_338_random/bad.py'
    cases = [
        ('relative', leaf),
        ('absolute-at-live-root', f'{ROOT_POSIX}/{leaf}'),
        ('absolute-at-recorded-root', f"{_posix(meta['recorded_root'])}/{leaf}"),
    ]
    ok = True
    print('portability self-test (parity key spelling):')
    for label, value in cases:
        got = relativise(value, meta['recorded_root'])
        ok = ok and got == leaf
        print(f'  {label:26s} -> {got}')
    foreign = f'/home/runner/work/x/y/{leaf}'
    try:
        relativise(foreign, meta['recorded_root'])
        print('  absolute-at-unknown-root   -> accepted (WRONG: must refuse to guess)')
        ok = False
    except GatePathError:
        print('  absolute-at-unknown-root   -> GatePathError, refuses to guess')
    big8 = META['big8']
    for label, value in (('scratch/_p3_big/trainer.py', 'scratch/_p3_big/src__transformers__trainer.py'),
                         ('corpus_big8/trainer.py', f"{big8['corpus_marker']}/src__transformers__trainer.py"),
                         ('abs trainer.py', f"{ROOT_POSIX}/scratch/_p3_big/src__transformers__trainer.py")):
        got = canon_key((value, 1, 'CWE-117', 'Injection', 'm', 'MEDIUM'), 'big8')[0]
        print(f'  big8 corpus rebase {label:26s} -> {got}')
    scanned_from_inside = 'corpus/cwe_338_random/bad.py'
    got = canon_key((scanned_from_inside, 1, 'CWE-338', 'Crypto', 'm', 'LOW'), 'parity')[0]
    ok = ok and got == leaf
    print(f'  parity scan-root rebase {scanned_from_inside:26s} -> {got}')

    nested = f'{ROOT_POSIX}/scratch/_wt'
    saved = ROOT_POSIX
    try:
        globals()['ROOT_POSIX'] = nested
        nested_key = relativise(f'{nested}/{leaf}', meta['recorded_root'])
    finally:
        globals()['ROOT_POSIX'] = saved
        _ROOT_RE.clear()
    ok = ok and nested_key == leaf
    print(f'  nested-checkout rebase        -> {nested_key}')

    recorded = _posix(meta['recorded_root'])
    rel_tail = 'benchmark/fixtures/cross_file/case_01/repo01.py:7'
    want = f'leak at {_ROOT_TOKEN}/{rel_tail}'
    win = scrub_message('leak at ' + recorded.replace('/', '\\') + '\\'
                        + rel_tail.replace('/', '\\'), meta['recorded_root'])
    fwd = scrub_message(f'leak at {recorded}/{rel_tail}', meta['recorded_root'])
    ok = ok and win == want and fwd == want
    print(f'  message scrub both separators -> {fwd}')
    foreign = '/home/runner/work/other/benchmark/x.py'
    untouched = scrub_message(f'leak at {foreign}', meta['recorded_root']) == f'leak at {foreign}'
    moved = scrub_message(f'leak at {recorded}/benchmark/fixtures/cross_file/case_01/repo02.py:7',
                          meta['recorded_root'])
    ok = ok and untouched and moved != fwd
    print(f'  foreign root untouched={untouched}, moved sink still distinct={moved != fwd}')
    print(f'  ROOT={ROOT}')
    print(f'  recorded_root={meta["recorded_root"]}')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(_selftest())
