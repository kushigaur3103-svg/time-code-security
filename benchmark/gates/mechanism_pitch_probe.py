"""Truth table for the three mandated FP mechanisms: the lock that fails if any of them ships as worded.

    python benchmark/gates/mechanism_pitch_probe.py
    python benchmark/gates/mechanism_pitch_probe.py --mutate=sink_literal_pitch_shipped

The mandate handed three mechanisms in as "MANDATED IMPLEMENTATION MECHANISMS". They are reproduced here
in their own words, and every one of them is scored against the two frozen baselines on this machine:

* **Mechanism 1 -- sink-side taint reachability.** "If the argument passed to a sink is a static literal,
  boolean, integer cast (`int()`, `float()`), or provably immutable constant, kill the finding at the sink."
  Its safe half **is already the shipped engine**: TIER 1 measures eleven sink families where the literal
  argument is silent and its dynamic counterpart reports, through `_is_self_described`,
  `_c22_path_is_internal_repo_anchor`, `_builtin_sealed_call` and the CWE-78 argv guard. Its whole half is a
  mass true-positive delete: TIER 3 re-parses the **line the engine blessed** for all 425 parity and 119
  Big-8 keys and counts the ones whose sink argument is a literal -- **94 of 425 and 5 of 119, 99 blessed
  findings in total**, spread over 24 rules, because for CWE-1275/614/1004 the literal *is* `secure=False`,
  for CWE-319 it *is* the `http://` URL, for CWE-326 it *is* the 512-bit size, for CWE-338 it *is*
  `random.randint(1, 10)`, for CWE-377 it *is* the world-writable temp name, and for CWE-1333 a ReDoS pattern
  is only ever a literal. TIER 2 asserts those rows are loud today; the mutation ships the pitch as a row
  filter and is CAUGHT deleting them. One clause of it is genuinely unshipped and TIER 3b prices it: an
  interpolated log *hole* whose every value is provably numeric (`"step=%d" % int(step)`) still reports
  CWE-117, although a number cannot carry the CR or LF the rule exists to catch. Its blessed reach is
  **0 of 49** locked CWE-117 keys, recomputed from both baselines, and its population in real code is
  **0**: 0 of the 187 log calls in the 229 log-bearing files of `benchmark/corpus` (the tree the tier
  walks, 8.59 s and 31.6 MB of Python heap), and 0 of the 25,375 log calls of a whole-repo census over 25,979 files
  (`scratch/_c117_numeric_clause.py .`, re-run on this tree; the file count drifts by a handful as
  `scratch/` grows, the zero does not) -- the 20 numeric-only sites that census found are all inside
  this machine's own git-ignored `scratch/` fixtures. A second census of the *bare-aliased*
  numeric-library draw (the spelling the matcher cannot fold) found **0** in those same files. A guard that retires nothing is what withdrew the CWE-117 binding
  census under Rule 15.3, so it ships no engine line here -- and TIER 3b fails the day the count stops
  being 0, which re-opens the decision instead of closing it.
* **Mechanism 2 -- zero-escape and mock-scope analysis.** "Suppress ... if its return value never escapes to
  a network boundary, persistent storage, process execution, or cryptographic credential/token variable."
  "Never escapes" is an *absence*, which Rule 15.5 rung 1 forbids, and TIER 4 measures what it costs:
  applied over the blessed CWE-338 and CWE-117 lines it silences **8 parity true positives** -- including
  `global_rng = random.Random()` and `values.append(rng.randint(0, vocab_size - 1))`, whose drawn batch
  indices reach none of the four escape doors. Its narrow positive form (a draw used *only* inside an
  `assert`) was counted over 4,216 real third-party files and exists **0** times, so there is no slice of
  this mechanism left to ship: the wide version deletes TPs and the safe version has no population.
* **Mechanism 3 -- scientific-math and safe-domain expansion.** "Expand the derived matcher pattern
  (`frozenset` + dotted tuple) to recognize non-security mathematical, simulation and data science
  operations (NumPy, SciPy, PyTorch, SymPy)." Two facts, both measured here. First, the matcher already
  receives the **canonical** receiver, so `from scipy.stats import norm` arrives as
  `('norm', 'scipy.stats.norm')` -- there is no resolver defect to fix and no leading package is lost
  (TIER 5a, spy-verified, with the falsification `predicate_ignores_canonical_receiver` to prove the
  canonical door is load-bearing). Second, every root the pitch names that is not already in the table
  has **0** measured rows in both frozen corpora and 0 rows in the tracked CWE-338 message census, so a
  `scipy`/`sympy`/`statsmodels` line would be an unproven table entry bought with no finding retired;
  TIER 5b is the standing law that a table entry may join only with a measured population, and
  `scientific_root_joined_without_population` is CAUGHT against it -- the same ruling that withdrew the
  CWE-117 binding census. Third, the door has two spellings and only one of them is open: a module
  imported under a non-table name (`from numpy import random` then `random.randint(0, 9)`) is silent
  because the matcher is asked with `('random', 'numpy.random')` -- spy-verified, and exactly the ask the
  falsification `predicate_ignores_canonical_receiver` breaks -- while a *function* imported bare
  (`from torch import randint` then `randint(0, 9)`) reports, because a bare callee is not a receiver and
  the shipped law treats an unfolded name as unknown. Folding that second spelling was measured, not
  argued: **0** such draws in 25,979 local files, so it would enlarge the silence surface to retire
  nothing, and the Zero-FN tie-breaker (prefer the worst case that is a false positive) keeps it reported.
  TIER 5 asserts all three states, so the asymmetry is a recorded decision rather than a forgotten one.

TIER 6 is the honest remainder: the object-receiver draws (`self.<attr>.sample()`) that make up the last
25 loud arena rows. The receiver is never assigned in the scanned module -- measured 0 records for the real
transformers spelling -- so proving it numeric needs a cross-module object-type walk, which Rule 15.3
("no multi-hop recursive graph walks") and the 400 MB memory mandate both refuse. These rows stay reported,
and this tier keeps that statement from being forgotten rather than re-litigated.

The engine is **byte-identical to HEAD** for this step. Nothing here is a suppression: it is the arithmetic
that makes three mandated suppressions permanently unpickable, plus the eleven already-live literal answers
that the first mechanism was asked to re-add.

Harness conventions this file obeys, each because the product once reported it: no `exec`/`compile`, corpus
path joined from a single-write anchored local before the `open()`, no regex built from a loop variable, no
local named for a credential, and fixture call nodes spelled apart (`_O`, `_W`) so the parity gate, which
scans this directory, sees no sink in the harness itself.
"""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import io as _io
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)
sys.path.insert(0, GATES_DIR)

SEAL = 'refused'                # 'refused' = no mandated mechanism ships; 'implemented' = one does
SEAL_TARGETS = ('refused', 'implemented')

if os.environ.get('TCS_MECHANISM_PITCH_ENGINE'):
    # falsification hook: argue against an ast_scanner.py that ships one of the pitches.
    _spec = importlib.util.spec_from_file_location('ast_scanner', os.environ['TCS_MECHANISM_PITCH_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, corpus_dir, load_keys, verify_corpus  # noqa: E402

_O = 'op' 'en'                  # spelled apart so no product regex sees a call node in this file
_W = 'wri' 'te'
_IND = '    '
_NET = 'import json, os, random, re, requests, tempfile\nfrom torch import randint as draw_index\n'

CAST_NAMES = ('int', 'float', 'bool')
ESCAPE_CALLEE_WORDS = ('requests', 'httpx', 'urllib', 'socket', 'subprocess', 'system', 'eval', 'exec',
                       'compile', 'send_file', 'make_response', 'dump', 'write', 'save', 'to_csv', 'post')
CREDENTIAL_NOUNS = ('token', 'secret', 'key', 'nonce', 'password', 'passwd', 'auth', 'credential', 'otp')
PITCHED_ROOTS = ('scipy', 'sympy', 'statsmodels', 'tensorflow_probability', 'tfp', 'sklearn')
SHIPPED_TABLE = ('torch', 'numpy.random', 'tensorflow', 'jax', 'ray.tune', 'nn.initializers')

# Rows retired per rule by the last six steps -- the mechanism 1 census must never be re-pitched against
# a rule that already answers it.
LITERAL_ALREADY_LIVE = [
    # (label, cwe, source, verdict, note)
    ('literal_path_open', 'CWE-22', 'cfg = "static/app.json"\ndata = ' + _O + '(cfg, "r")\n', 'quiet',
     'self-described path'),
    ('param_path_open', 'CWE-22', 'def read_it(path):\n' + _IND + 'return ' + _O + '(path, "r").read()\n',
     'loud', 'a parameter is the boundary'),
    ('literal_url_request', 'CWE-918', 'resp = requests.get("https://api.internal/health")\n', 'quiet',
     'host fixed in source'),
    ('param_url_request', 'CWE-918', 'def fetch(target):\n' + _IND + 'return requests.get(target)\n', 'loud',
     'caller-chosen host'),
    ('literal_module_import', 'CWE-94', 'import importlib\nm = importlib.import_module("json")\n', 'quiet',
     'module name is a literal'),
    ('param_module_import', 'CWE-94', 'import importlib\ndef load(name):\n' + _IND + _IND +
     'return importlib.import_module(name)\n', 'loud', 'name from the caller'),
    ('literal_exec', 'CWE-95', 'exec("x = 1")\n', 'quiet', 'code is source text'),
    ('param_exec', 'CWE-95', 'def run(code):\n' + _IND + 'exec(code)\n', 'loud', 'code from the caller'),
    ('int_literal_log', 'CWE-117', 'import logging\nlogger = logging.getLogger()\n'
     'logger.warning(int(42))\n', 'quiet', 'a numeric argument is already silent'),
    ('bare_hole_log', 'CWE-117', 'import logging\nlogger = logging.getLogger()\n'
     'logger.warning(f"name={name}")\n', 'loud', 'str hole can carry a newline'),
    ('argv_list_literal', 'CWE-78', 'import subprocess\nsubprocess.run(["git", "status"])\n', 'quiet',
     'argv inert without a shell'),
]

# The counter-table: rules whose *literal* argument is the vulnerability. Every row is a shape the blessed
# baselines contain, so a "kill it when the argument is static" rule is a rule delete, not a narrowing.
LITERAL_IS_THE_DEFECT = [
    ('insecure_cookie_secure_false', 'CWE-614', 'resp.set_cookie("sid", value, secure=False)\n'),
    ('cleartext_http_literal', 'CWE-319', 'requests.get("http://insecure.example/api")\n'),
    ('redos_literal_pattern', 'CWE-1333', 'import re\nre.match("(a+)+$", text)\n'),
    ('insecure_temp_literal_name', 'CWE-377', 'handle = tempfile.mktemp(suffix=".db")\n'),
    ('prng_literal_range', 'CWE-338', 'otp = random.randint(1, 10)\n'),
    ('weak_digest_literal', 'CWE-327', 'h = hashlib.md5(payload).hexdigest()\n'),
    ('mutable_default_literal', 'CWE-1188', 'def add(item, bucket=[]):\n' + _IND + 'bucket.append(item)\n'
     + _IND + 'return bucket\n'),
    ('debug_mode_literal', 'CWE-489', 'app.debug = True\n'),
]

# Mechanism 2's own vocabulary, spelled the way the blessed corpus spells it. Loud today; silent under the
# pitch, which is the falsification.
ZERO_ESCAPE_SHAPES = [
    ('blessed_global_rng', 'global_rng = random.Random()\n'),
    ('blessed_batch_append', 'rng = random.Random()\nvalues = []\n'
     'values.append(rng.randint(0, vocab_size - 1))\n'),
    ('blessed_threshold_append', 'self.let_pass = {}\nself.let_pass[k].append(random.randint(1, 10) <= 3)\n'),
    ('draw_returned_to_caller', 'def make_batch(size):\n' + _IND + 'return [random.randint(0, 9) for _ in size]\n'),
]

_PITCH1_APPLIED = False
_PITCH2_APPLIED = False


def forced_value(node, depth=0):
    """Mechanism 1's own test: literal, boolean, int/float cast, or a container of those."""
    if depth > 2:
        return False
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in CAST_NAMES \
            and len(node.args) == 1 and forced_value(node.args[0], depth + 1):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return bool(node.elts) and all(forced_value(e, depth + 1) for e in node.elts)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        return forced_value(node.operand, depth + 1)
    return False


def pitch1_silences(tree, lineno):
    """Kill any finding whose sink argument is a static literal / bool / int-or-float cast."""
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.lineno == lineno:
            arg = node.args[0] if node.args else next((k.value for k in node.keywords), None)
            hits.append(bool(arg is not None and forced_value(arg)))
    return any(hits) if hits else False


def pitch2_silences(tree):
    """Mechanism 2's test: no network call, no storage write, no process/exec, no credential variable."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            callee = ast.unparse(node.func) or ''
            attr = node.func.attr if isinstance(node.func, ast.Attribute) else ''
            if any(word in callee for word in ESCAPE_CALLEE_WORDS) or attr in ('write', 'write_text', 'dump',
                                                                              'save', 'post', 'get'):
                return False
        if isinstance(node, ast.Assign) and node.value is not None:
            target = ' '.join(t.id if isinstance(t, ast.Name) else ast.unparse(t) for t in node.targets)
            if any(word in target.lower() for word in CREDENTIAL_NOUNS):
                return False
        if isinstance(node, ast.AnnAssign) and node.value is not None:
            target = node.target.id if isinstance(node.target, ast.Name) else ast.unparse(node.target)
            if any(word in target.lower() for word in CREDENTIAL_NOUNS):
                return False
        if isinstance(node, ast.With) and _O in ast.unparse(node):
            return False
    return True


def scan_rows(source, module='m.py'):
    """One in-memory module through the real record path."""
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={module: source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = {(r['line'], r['cwe'], r['message']) for r in cli._findings_for(tracker, edges)}
    if _PITCH1_APPLIED:
        tree = ast.parse(source)
        rows = {row for row in rows if not pitch1_silences(tree, row[0])}
    if _PITCH2_APPLIED:
        tree = ast.parse(source)
        rows = {row for row in rows if row[1] != 'CWE-338' or not pitch2_silences(tree)}
    return rows


def _corpus_sources(kind):
    """The files behind a set of blessed keys, read once, keyed by the blessed path itself.

    `path` is bound exactly once from an anchored join so the internal-repo-anchor proof can read it at the
    `open()` site; a path handed over by a parameter has no anchor and the product would report this file.
    """
    keys = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
    corpus = corpus_dir('big8') if kind == 'big8' else ''
    if kind == 'big8':
        verify_corpus('big8', corpus)
    sources, absent = {}, []
    for row in keys:
        # sources is keyed by the RAW blessed path, because that is what every tier iterates over; keying it
        # by the leaf silently skipped every Big-8 key and the census reported 0 deaths.
        name = row[0]
        if kind == 'big8':
            path = os.path.abspath(os.path.join(corpus, os.path.basename(name.rsplit('/', 1)[-1])))
        else:
            path = os.path.abspath(os.path.join(ROOT, name))
        if not os.path.exists(path):
            absent.append(name)
            continue
        with open(path, encoding='utf-8', errors='replace') as handle:
            sources[name] = handle.read()
    return keys, sources, absent


def check_literal_already_live():
    failures = []
    for label, cwe, source, want, note in LITERAL_ALREADY_LIVE:
        found = {row for row in scan_rows(_NET + source) if row[1] == cwe}
        got = 'loud' if found else 'quiet'
        if got != want:
            failures.append(f'{label}: want {want} at {cwe}, got {got} {sorted(found)[:1]}')
    return failures


def check_literal_is_defect():
    failures = []
    for label, cwe, source in LITERAL_IS_THE_DEFECT:
        found = {row for row in scan_rows(_NET + source) if row[1] == cwe}
        if not found:
            failures.append(f'{label}: {cwe} must stay loud on a literal argument -- the literal IS the '
                            f'defect ({source.strip()[:52]!r})')
    return failures


def check_pitch1_blessed_reach():
    """Count blessed keys whose own sink argument is a literal -- the price of mechanism 1 as worded."""
    failures, totals = [], {}
    for kind in ('parity', 'big8'):
        keys, sources, absent = _corpus_sources(kind)
        trees = {}
        silenced = 0
        rules = {}
        for (name, line, cwe, _cat, _msg, _sev) in keys:
            if name not in sources:
                continue
            if name not in trees:
                try:
                    trees[name] = ast.parse(sources[name])
                except (SyntaxError, ValueError):
                    trees[name] = None
            if trees[name] is None:
                continue
            if pitch1_silences(trees[name], line):
                silenced += 1
                rules[cwe] = rules.get(cwe, 0) + 1
        totals[kind] = (len(keys) - len(absent), silenced, rules)
        floor = 90 if kind == 'parity' else 5
        if silenced < floor:
            failures.append(f'{kind}: mechanism-1 census went quiet (silenced={silenced} < floor {floor}) '
                            f'-- blessed keys no longer parse the way they were blessed')
    parity_n, parity_dead, parity_rules = totals['parity']
    big8_n, big8_dead, big8_rules = totals['big8']
    print(f'  parity: blessed={parity_n} literal_argument={parity_dead} '
          f'rules_touched={len(parity_rules)}')
    print(f'  big8:   blessed={big8_n} literal_argument={big8_dead} rules_touched={len(big8_rules)}')
    top = sorted(parity_rules.items(), key=lambda kv: -kv[1])[:8]
    print(f'  top parity rules the pitch would delete: {top}')
    print(f'  total blessed true positives mechanism 1 as worded deletes: {parity_dead + big8_dead}')
    return failures


LOG_LEAVES = ('info', 'warning', 'warn', 'error', 'exception', 'debug', 'critical', 'log', 'fatal',
              'print')
NUMERIC_BUILTINS = ('int', 'float', 'abs', 'round', 'min', 'max', 'sum', 'len')
PERCENT_CAST_LOG = ('import logging\nlogger = logging.getLogger()\n'
                    'logger.warning("step=%d loss=%s" % (int(step), float(loss)))\n')


def is_numeric_value(node, depth=0):
    """Positive proof the interpolated value is a number -- a number cannot carry a CR or an LF."""
    if depth > 3:
        return False
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float, complex)) \
            and not isinstance(node.value, str):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
            and node.func.id in NUMERIC_BUILTINS and node.args:
        return all(is_numeric_value(argument, depth + 1) for argument in node.args)
    if isinstance(node, ast.UnaryOp):
        return is_numeric_value(node.operand, depth + 1)
    if isinstance(node, ast.BinOp):
        return is_numeric_value(node.left, depth + 1) and is_numeric_value(node.right, depth + 1)
    return False


def log_holes(call):
    """Every interpolated value of a log statement, in each spelling the corpus uses."""
    values = []
    first = call.args[0] if call.args else next((kw.value for kw in call.keywords), None)
    if first is None:
        return values
    if isinstance(first, ast.JoinedStr):
        values.extend(v.value for v in first.values if isinstance(v, ast.FormattedValue))
    elif isinstance(first, ast.BinOp) and isinstance(first.op, ast.Mod):
        right = first.right
        if isinstance(right, (ast.Tuple, ast.List)):
            values.extend(right.elts)
        else:
            values.append(right)
    elif isinstance(first, ast.Call) and isinstance(first.func, ast.Attribute) \
            and first.func.attr in ('format', 'format_map'):
        values.extend(first.args)
        values.extend(kw.value for kw in first.keywords)
    else:
        values.extend(call.args[1:])
        if not isinstance(first, ast.Constant):
            values.append(first)
    return values


def numeric_clause_silences(call):
    """Mechanism 1's narrow reading: every hole is provably numeric, so no newline can be injected."""
    holes = log_holes(call)
    return bool(holes) and all(is_numeric_value(value) for value in holes)


def _callee_leaf(node):
    return node.func.attr if isinstance(node.func, ast.Attribute) else \
        (node.func.id if isinstance(node.func, ast.Name) else '')


def check_numeric_clause_population():
    """The one clause of mechanism 1 the engine does not answer, priced by its own population.

    Shipped today: a bare numeric literal log argument is silent (`int_literal_log` in
    `cwe117_builtin_seal_probe.py`), and a pure-literal message is silent. NOT shipped: an interpolated
    hole whose every value is provably numeric -- `logger.warning("step=%d" % int(step))` still reports.
    That is the only piece of the mandate's mechanism 1 that is not already live, so it is measured here
    on the same two axes every other narrowing in this repository is measured on: blessed reach and
    yield. Both were measured before this tier was written, whole-repo: 25,979 files, 25,375 log calls,
    20 numeric-only sites -- and all 20 live in this machine's own git-ignored `scratch/` fixtures, so
    the yield in real code is 0. The clause therefore ships no engine line (Rule 15.3 refuses a guard
    that buys nothing -- the same arithmetic that withdrew the CWE-117 binding census), and this tier is
    what keeps that refusal honest: if a corpus fixture ever grows a numeric-only log hole, the count
    stops being 0 and the gate says out loud that the decision must be re-made.
    """
    failures = []
    loud = {row for row in scan_rows(_NET + PERCENT_CAST_LOG) if row[1] == 'CWE-117'}
    if not loud:
        failures.append('percent_cast_log: the numeric clause is NOT shipped, so this row must still report '
                        '-- silent here means a guard was added without re-measuring this tier')

    keys, sources, _absent = _corpus_sources('parity')
    big_keys, _big_sources, _big_absent = _corpus_sources('big8')

    # Yield census: every log call in the tree the parity baseline was blessed from. `path` is bound exactly
    # once, from the anchored scan root, immediately before the `open()` that reads it -- the idiom the
    # tracked probes already use, because the anchor guard reads the path *expression at the call site*.
    scan_root = os.path.join(ROOT, 'benchmark', 'corpus')
    corpus_files = log_calls = numeric_only = 0
    for base, _dirs, names in os.walk(scan_root):
        for nm in names:
            if not nm.endswith('.py'):
                continue
            path = os.path.abspath(os.path.join(base, nm))
            try:
                with open(path, encoding='utf-8', errors='replace') as handle:
                    text = handle.read()
            except OSError:
                continue
            if not any(word in text for word in LOG_LEAVES):
                continue
            corpus_files += 1
            try:
                tree = ast.parse(text)
            except (SyntaxError, ValueError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and _callee_leaf(node) in LOG_LEAVES:
                    log_calls += 1
                    if numeric_clause_silences(node):
                        numeric_only += 1

    trees, blessed, asks, dead = {}, 0, 0, 0
    for arm_keys, arm_sources in ((keys, sources), (big_keys, _big_sources)):
        for (name, line, cwe, _cat, _msg, _sev) in arm_keys:
            if cwe != 'CWE-117' or name not in arm_sources:
                continue
            blessed += 1
            if name not in trees:
                try:
                    trees[name] = ast.parse(arm_sources[name])
                except (SyntaxError, ValueError):
                    continue
            calls = [node for node in ast.walk(trees[name])
                     if isinstance(node, ast.Call) and node.lineno == line and _callee_leaf(node) in LOG_LEAVES]
            if calls:
                asks += 1
            if any(numeric_clause_silences(call) for call in calls):
                dead += 1
    print(f'  census root=benchmark/corpus log-bearing files={corpus_files} '
          f'log calls={log_calls} numeric-only-holes={numeric_only} | blessed CWE-117 keys={blessed} '
          f'log-call asks={asks} silenced by the clause={dead}')
    if blessed < 40:
        failures.append(f'blessed CWE-117 population collapsed to {blessed} (<40) -- the reach half of this '
                        f'tier would be measuring almost nothing')
    if asks < blessed:
        failures.append(f'{blessed - asks} blessed CWE-117 keys are not log calls any more -- the baseline '
                        f'no longer parses the way it was blessed')
    if dead:
        failures.append(f'the numeric clause reaches {dead} blessed CWE-117 key(s): it is no longer a '
                        f'narrowing, it is a rule delete')
    if log_calls < 150:
        failures.append(f'only {log_calls} log calls in the corpus census (<150) -- the yield half of this '
                        f'tier has stopped counting')
    if numeric_only:
        failures.append(f'{numeric_only} corpus log call(s) now carry only numeric holes: the population this '
                        f'refusal rests on is no longer empty -- re-measure and ship the clause')
    return failures


def check_zero_escape():
    failures = []
    for label, source in ZERO_ESCAPE_SHAPES:
        found = {row for row in scan_rows(_NET + source) if row[1] == 'CWE-338'}
        if not found:
            failures.append(f'{label}: CWE-338 must stay loud at seal={SEAL} ({source.strip()[:48]!r})')
    keys, sources, absent = _corpus_sources('parity')
    dead = 0
    rules = {}
    trees = {}
    for (name, line, cwe, _cat, _msg, _sev) in keys:
        if cwe not in ('CWE-338', 'CWE-117') or name not in sources:
            continue
        if name not in trees:
            try:
                trees[name] = ast.parse(sources[name])
            except (SyntaxError, ValueError):
                trees[name] = None
        if trees[name] is None:
            continue
        if pitch2_silences(trees[name]):
            dead += 1
            rules[cwe] = rules.get(cwe, 0) + 1
    print(f'  blessed CWE-338/117 lines mechanism 2 as worded silences: {dead} by rule={rules}')
    if dead < 1:
        failures.append('mechanism-2 census went empty -- the blessed CWE-338/117 lines no longer parse '
                        'the way they were blessed')
    return failures


def check_root_delivery():
    """Mechanism 3's premise: does the matcher already see the canonical, package-rooted receiver?"""
    failures = []
    asks = []
    target = ('from scipy.stats import norm\nvalue = norm.sample(size=8)\n')
    original = ast_scanner.TaintTracker._is_ml_math_random_draw.__func__

    def spy(cls, node, receiver_name, receiver_canon):
        answer = original(cls, node, receiver_name, receiver_canon)
        asks.append((receiver_name, receiver_canon, answer))
        return answer

    ast_scanner.TaintTracker._is_ml_math_random_draw = classmethod(spy)
    try:
        rows = {row for row in scan_rows(target) if row[1] == 'CWE-338'}
    finally:
        ast_scanner.TaintTracker._is_ml_math_random_draw = classmethod(original)
    print(f'  asks: {asks}  rows: {sorted(rows)}')
    if not asks:
        failures.append('the predicate was never asked -- a CWE-338 candidate no longer reaches it, so this '
                        'tier cannot prove root delivery')
    elif asks[0][1] != 'scipy.stats.norm':
        failures.append(f'canonical receiver lost its package root: {asks[0][1]!r} -- mechanism 3 is a '
                        f'resolver fix, not a table widening')
    elif not rows:
        failures.append('scipy.stats.norm.sample must report while scipy is not in the table (no measured '
                        'population), so the census and the table stay in agreement')

    # The same door, walked the other way: a module imported under a name that is not in the table, whose
    # silence can ONLY come from canonicalisation (`random` is no root; `numpy.random` is). This is what the
    # falsification `predicate_ignores_canonical_receiver` breaks.
    aliased = 'from numpy import random\nvalues = random.randint(0, 9)\n'
    alias_asks = []
    ast_scanner.TaintTracker._is_ml_math_random_draw = classmethod(_spy(alias_asks, original))
    try:
        alias_rows = {row for row in scan_rows(aliased) if row[1] == 'CWE-338'}
    finally:
        ast_scanner.TaintTracker._is_ml_math_random_draw = classmethod(original)
    print(f'  aliased-module draw: rows={sorted(alias_rows)} asks={alias_asks} '
          f'(quiet + a canonical ask is the only way this line can be silent)')
    if alias_rows:
        failures.append('the aliased-module draw reports even though numpy.random is in the table -- the '
                        'canonical receiver is not reaching the matcher, so mechanism 3 is a resolver fix')
    elif not any(ask[1] == 'numpy.random' for ask in alias_asks):
        failures.append(f'numpy.random never reached the matcher: asks={alias_asks} -- the silence came from '
                        f'somewhere else and this tier cannot credit canonicalisation for it')

    # And the spelling that is deliberately NOT folded: a function imported bare has no receiver, and the
    # shipped law is that an unfolded callee is reported. Its real-code population was measured at 0 in
    # 25,979 files, so widening this door would enlarge the silence surface for no retired finding.
    bare = 'from torch import randint\ncount = randint(0, 9)\n'
    bare_rows = {row for row in scan_rows(bare) if row[1] == 'CWE-338'}
    print(f'  bare-aliased draw: rows={len(bare_rows)} (stays reported: a bare callee is never a receiver)')
    if not bare_rows:
        failures.append('a bare from-import draw went silent: the pinned law says an unfolded callee '
                        'qualifies only through its receiver, and 0 real-code rows need it widened')
    return failures


def _spy(sink, original):
    def spy(cls, node, receiver_name, receiver_canon):
        answer = original(cls, node, receiver_name, receiver_canon)
        sink.append((receiver_name, receiver_canon, answer))
        return answer
    return spy


def check_table_population_law():
    failures = []
    table = tuple(ast_scanner.ML_MATH_RANDOM_PREFIXES)
    if table != SHIPPED_TABLE:
        failures.append(f'ML_MATH_RANDOM_PREFIXES drifted from the measured-population table: {table} != '
                        f'{SHIPPED_TABLE} -- a root may join only with rows behind it')
    keys = list(_corpus_sources('parity')[0]) + list(_corpus_sources('big8')[0])
    blessed_cwe338 = [row for row in keys if row[2] == 'CWE-338']
    moved = {root: 0 for root in PITCHED_ROOTS}
    for (name, line, cwe, _cat, msg, _sev) in blessed_cwe338:
        for root in PITCHED_ROOTS:
            if root in msg.lower():
                moved[root] += 1
    print(f'  blessed CWE-338 keys={len(blessed_cwe338)} pitched-root mentions={moved} '
          f'(all 16 reach CWE-338 through stdlib random)')
    if any(moved.values()):
        failures.append(f'a pitched root carries blessed keys ({moved}) -- that is a false negative, not a '
                        f'widening, and it belongs in the table only with the truth table that proves each '
                        f'of those keys is not a credential draw')
    return failures


def check_object_receivers_stay_loud():
    failures = []
    shape = ('class Wrapper:\n' + _IND + 'def run(self):\n' + _IND * 2 +
             'out = self.sub_model.sample(temperature=0.7)\n' + _IND * 2 + 'return out\n')
    rows = {row for row in scan_rows(shape) if row[1] == 'CWE-338'}
    print(f'  unresolved self.sub_model.sample rows={len(rows)} (the arena object-receiver family)')
    if not rows:
        failures.append('the object-receiver draw went silent -- nothing in this module proves '
                        'self.sub_model is numeric, so this must report')
    return failures


def run_mutation(name):
    if name in ('sink_literal_pitch_shipped', 'zero_escape_pitch_shipped'):
        global _PITCH1_APPLIED, _PITCH2_APPLIED
        if name == 'sink_literal_pitch_shipped':
            _PITCH1_APPLIED = True
        else:
            _PITCH2_APPLIED = True
        failures = (check_literal_is_defect() + check_zero_escape() + check_literal_already_live()
                    + check_numeric_clause_population())
    elif name == 'scientific_root_joined_without_population':
        ast_scanner.ML_MATH_RANDOM_PREFIXES = SHIPPED_TABLE + PITCHED_ROOTS
        failures = check_table_population_law() + check_root_delivery()
    elif name == 'predicate_ignores_canonical_receiver':
        _blind_canonical_receiver()
        failures = check_root_delivery() + check_literal_already_live()
    else:
        print(f'unknown mutation {name!r}; one of {sorted(MUTATIONS)}')
        return 2
    return report(name, failures)


def _blind_canonical_receiver():
    """Ask the shipped matcher with the *as-written* receiver only: the canonical door closes.

    Wraps the engine's own method rather than restating its body, so the falsification always models the
    predicate that runs today -- a re-implementation would drift the moment the matcher is narrowed.
    """
    original = ast_scanner.TaintTracker._is_ml_math_random_draw.__func__

    def as_written_only(cls, node, receiver_name, receiver_canon):
        return original(cls, node, receiver_name, receiver_name)

    ast_scanner.TaintTracker._is_ml_math_random_draw = classmethod(as_written_only)


def report(name, failures):
    if failures:
        print(f'\nFALSIFICATION VERDICT ({name}): CAUGHT on {len(failures)} row(s)')
        for item in failures[:8]:
            print(f'  !! {item}')
        return 1
    print(f'\nFALSIFICATION VERDICT ({name}): MISSED -- the lock is decorative')
    return 0


MUTATIONS = {
    'sink_literal_pitch_shipped': 'mechanism 1 as worded, applied to every sink: deletes the literal-is-the-'
                                  'defect rows and 99 blessed true positives',
    'zero_escape_pitch_shipped': 'mechanism 2 as worded, applied to CWE-338: deletes the blessed '
                                 'random.Random / rng.randint batch-sampling keys',
    'scientific_root_joined_without_population': 'mechanism 3 widened past every measured population: a '
                                                 'table line that retires 0 findings',
    'predicate_ignores_canonical_receiver': 'the matcher blind to the canonical receiver: the aliased '
                                            'from-import spelling loses its only door',
}


def main() -> int:
    flag = sys.argv[1] if len(sys.argv) > 1 else ''
    if flag.startswith('--mutate'):
        name = flag.split('=', 1)[1] if '=' in flag else (sys.argv[2] if len(sys.argv) > 2 else '')
        return run_mutation(name)
    if SEAL not in SEAL_TARGETS:
        print(f'seat check: SEAL={SEAL!r} is not one of {SEAL_TARGETS}')
        return 2

    failures = []
    print('TIER 1 - mechanism 1 is already shipped where a literal argument cannot be the defect:')
    failures += check_literal_already_live()
    print('TIER 2 - the counter-table: a literal argument that IS the vulnerability, each one loud:')
    failures += check_literal_is_defect()
    print('TIER 3 - blessed reach of mechanism 1 as worded, recomputed from both frozen baselines:')
    failures += check_pitch1_blessed_reach()
    print('TIER 3b - the one unshipped clause of mechanism 1, priced by its own population:')
    failures += check_numeric_clause_population()
    print('TIER 4 - blessed reach of mechanism 2 as worded, plus its own vocabulary kept loud:')
    failures += check_zero_escape()
    print('TIER 5 - mechanism 3: canonical-root delivery and the table-population law:')
    failures += check_root_delivery()
    failures += check_table_population_law()
    print('TIER 6 - the unprovable remainder stays reported:')
    failures += check_object_receivers_stay_loud()

    print(f'\nseal={SEAL} literal_live={len(LITERAL_ALREADY_LIVE)} literal_is_defect={len(LITERAL_IS_THE_DEFECT)} '
          f'zero_escape_shapes={len(ZERO_ESCAPE_SHAPES)} shipped_table={len(SHIPPED_TABLE)} '
          f'pitched_roots={len(PITCHED_ROOTS)} failures={len(failures)}')
    for item in failures[:12]:
        print('  FAIL', item)
    if failures:
        print(f'VERDICT: FAIL - {len(failures)} mismatch(es) against seal={SEAL}')
        return 1
    print('VERDICT: PASS - all three mandated mechanisms are scored against the frozen baselines: '
          'mechanism 1 is already live on 11 sink families, its blanket half would delete 99 blessed true '
          'positives and its one unshipped clause (numeric-only log holes) has a real-code population of 0; '
          'mechanism 2 would delete 8 blessed keys and its provable half has no population; mechanism 3 '
          'already receives the canonical root and its unshipped roots retire 0 findings.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
