"""CWE-89 truth table: which interpolated string constructions are URL/endpoint paths, and what a
path-only proof may cover.

Why this gate exists
--------------------
`SQL_INJECTION` / `SQL_QUERY_EXECUTION` on a `.join(...)`-shaped builder sink is reported for HTTP
routes. On the pinned LiteLLM tree, 3 of the rows in the 53 files that carry CWE-89 are exactly that
shape (scratch/_c89_pilot.py), e.g.

    url=str(URL(self.guardrails_ai_api_base).join(f"guards/{name}/validate"))   # guardrails_ai.py:78
    facet_sql = f" WHERE {' AND '.join(where_parts)}" ...                        # spend_logs.py:137

The second one is a genuine injection and is the reason this rule is hard: it is *also* a `.join`
whose parts are path-free, and the only difference between it and a route is the words around it.

The emitter
-----------
  ast_scanner.py `_collect_cwe89_driver_querybuilder_findings` (:20352) walks every call whose
  attribute is a driver, builder or Django name (`execute`, `run`, `fetch*`, `where`, `join`,
  `order_by`, `filter`, `raw`, `extra`, ...) and hands it to `_vulnerable_call` (:20687). That guard
  chain ends in a fork:

      if require_shape_or_db:      # execute/run/raw sinks: needs a SQL verb or a DB-looking receiver
          if not (_has_sql_shape(resolved) or _db_like_receiver(...)): return False
      elif _c89_template_is_endpoint_path_only(call, resolved): return False   # <- this change
      return True

  The `builder_attrs` / `django_attrs` branches pass `require_shape_or_db=False`, so they will judge
  *any* dynamically built string as a query. That is the only branch this exemption touches, and it is
  the honest one: a sink that already saw a SQL verb never asks the question.

The narrowing this gate locks
-----------------------------
`_c89_template_is_endpoint_path_only` (ast_scanner.py:1127) answers two independent questions in two
deliberately different scopes, and every branch errs toward reporting:

  * positive proof (this text is a route), read from the construction only -- the call and its
    resolved value: at least one string literal carries a path separator, and every non-empty literal
    of it is path-shaped or a scheme. A template that also holds plain text (`"id="`, `' AND '`,
    `" and reload"`) is not a route. Reading the positive only from the construction is what keeps a
    request statement's header strings out of the evidence;
  * negative veto (this text belongs to a query), read from the whole enclosing function or module:
    no SQL verb (`CWE89_SQL_VERB_RE`, word-boundary) may appear in any string of that scope, and no
    DB-flavoured identifier (`CWE89_DB_STATEMENT_WORDS`, matched on `_CWE89_SEGMENT_SPLIT` segments)
    may appear as a name or attribute tail anywhere in it;
  * a scope that cannot be read -- no parent links, no literals, or more than
    `_CWE89_SCOPE_NODE_LIMIT` nodes -- proves nothing, and nothing is not silence.

The scope matters and is measured: with the veto reading only the enclosing *statement*, the fixture
`verb_in_function` (a SELECT assembled one statement above the route) went LOUD->QUIET in
scratch/_c89_fix2.py. The function-wide sweep is what closes that, and `giant_function_cap` (400
assignments, over the node limit) pins the fail-closed side of the same rule.

Why the veto has to read identifiers, not just verbs: 5 of the 25 blessed parity CWE-89 keys carry no
SQL verb near the sink at all and are kept loud by their receiver (`connection.cursor().execute`,
cross_file cases 03/04/06/07 and `benchmark/corpus/cwe_1004_cookies/test_v01_bad.py`). An exemption
that looked only at literals could reach them.

Measured evidence behind the numbers
-----------------------------------
  blessed overlap            : CWE-89 keys -- 25 in parity, 0 in Big-8 (counted from the frozen key
                               files, TIER 1). All 20 CWE-89 records reproduced from the 31 files that
                               hold those keys come off `execute`, and none is a `.join` route, so none
                               is reachable by this branch (scratch/_c89_mem.py).
  LiteLLM A/B, measured      : see the module footer of the shipping commit -- 53 files that carry
                               CWE-89 rows, whole-tree and chunked re-scan with HEAD's engine beside
                               this one; ADDED must be 0 on both sides of the fork.
  fixtures                   : 13 shapes, all verified against HEAD's bytes before this file claimed
                               them (scratch/_abstained_check.py -- every one of the 13 is LOUD on
                               HEAD): 6 route shapes go LOUD->QUIET and 7 tripwires stay LOUD, and the
                               pair arms are 3 more loud-on-HEAD modules.

Seal semantics - `CWE89_SEAL`
-----------------------------
  'shipped'   : the 6 route shapes MUST be silent and every tripwire MUST stay loud.
  'abstained' : the engine before this branch landed -- all 12 shapes MUST be loud. A route shape that
                goes quiet while the seal says abstained means a narrowing landed without a contract.
Either way a mismatch is exit 1.
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

if os.environ.get('TCS_CWE89_ENGINE'):
    # falsification hook: load an alternative ast_scanner.py and let the gate argue against it. The
    # module is registered under its real name because `dataclass(slots=True)` and `cli` both resolve
    # the engine through sys.modules.
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        'ast_scanner', os.environ['TCS_CWE89_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys, scan_rows  # noqa: E402

CWE89_SEAL = 'shipped'   # 'abstained' = the engine before the path-only branch landed
SEAL_TARGETS = ('abstained', 'shipped')

# The blessed CWE-89 population, counted from the frozen baselines themselves.
CWE89_LOCKED = {'parity': 25, 'big8': 0}

URL = 'from yarl import URL\n'

# (label, source, expect_when_abstained, expect_when_shipped)
# 'loud' = a CWE-89 finding is required on that module, 'quiet' = none is allowed.
SHAPES = [
    # ---- routes: path template, no verb, no DB-flavoured identifier in scope ----
    ('guards_validate_join', URL + '''
class Guardrail:
    async def run(self, request_data):
        return await self.aclient.post(
            url=str(URL(self.api_base).join(f"guards/{self.guard_name}/validate")),
            headers={"Content-Type": "application/json"},
        )
''', 'loud', 'quiet'),
    ('api_v1_repos_join', URL + '''
def fetch(org, repo):
    return str(URL(base).join(f"api/v1/{org}/repos/{repo}"))
''', 'loud', 'quiet'),
    ('http_scheme_join', URL + '''
def events_url(tenant):
    return str(URL(host).join(f"http://events/{tenant}/stream"))
''', 'loud', 'quiet'),
    ('dict_value_path', URL + '''
def payload(name):
    return {"url": str(URL(base).join(f"v1/items/{name}/details"))}
''', 'loud', 'quiet'),
    ('module_level_path', URL + '''
ENDPOINT = str(URL(BASE).join(f"api/v1/{NAME}/run"))
''', 'loud', 'quiet'),
    ('path_prefix_binop', URL + '''
def leaf(name):
    return str(URL(base).join("api/v1/" + f"{name}" + "/details"))
''', 'loud', 'quiet'),
    # ---- the real injection, and the four ways a route claim can be wrong ----
    ('no_slash_template', '''
def filter_on(col, value):
    return table.filter(f"id={col} eq {value}")
''', 'loud', 'loud'),
    ('plain_text_chunk', URL + '''
def leaf(name):
    return str(URL(base).join("api/v1/" + f"{name}" + " and reload"))
''', 'loud', 'loud'),
    ('verb_in_function', URL + '''
def run_lookup(parts, base):
    text = "SELECT name FROM people WHERE id = "
    return str(URL(base).join(f"guards/{parts}/validate")) + text
''', 'loud', 'loud'),
    ('db_word_in_function', URL + '''
def run_lookup(parts, conn):
    rows = conn.fetchall()
    return str(URL(base).join(f"guards/{parts}/validate")) + str(rows)
''', 'loud', 'loud'),
    ('cursor_receiver_shape', '''
def look(up):
    cur.execute("SELECT x FROM t WHERE y = " + up)
''', 'loud', 'loud'),
    # the measured over-block, spelled as a route: `update` is a verb to this rule wherever it turns
    # up, so this row keeps its finding even though it is only a path.
    ('hyphen_verb_route', URL + '''
def leaf(name):
    return str(URL(base).join(f"api/v1/update-policy/{name}"))
''', 'loud', 'loud'),
    # ---- a scope the predicate refuses to read is a scope that stays reported ----
    ('giant_function_cap', URL + '''
def big(parts, base):
''' + '\n'.join(f'    junk_{i} = {i}' for i in range(400)) + '''
    return str(URL(base).join(f"guards/{parts}/validate"))
''', 'loud', 'loud'),
]

FP_ROWS = [row for row in SHAPES if row[2] == 'loud' and row[3] == 'quiet']
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == 'loud']
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == 'quiet']

_BY_LABEL = {row[0]: row[1] for row in SHAPES}

# The same route, with and without the one piece of evidence that says "query". A narrowing keyed on
# the path separator alone would answer both arms alike -- and would exempt a route sitting under a
# SELECT.
PAIRS = [
    ('route alone vs route + SQL text', _BY_LABEL['api_v1_repos_join'],
     _BY_LABEL['verb_in_function']),
    ('route alone vs route + cursor call', _BY_LABEL['guards_validate_join'],
     _BY_LABEL['db_word_in_function']),
    ('route alone vs template + plain text', _BY_LABEL['path_prefix_binop'],
     _BY_LABEL['plain_text_chunk']),
]

# The verb vocabulary, pinned from the mandate: these must all be read as SQL.
VERB_MUST_MATCH = ('SELECT', 'insert into', 'UPDATE x', 'DELETE', 'DROP TABLE', 'ALTER TABLE',
                   'CREATE INDEX', 'REPLACE INTO', 'TRUNCATE', 'MERGE', 'WHERE id', 'FROM t',
                   'UNION SELECT', 'ORDER BY', 'GROUP BY', 'HAVING', 'SET x', 'VALUES', 'INTO',
                   'TABLE t', 'select', 'Where', 'from')
# And these are route words that must never be mistaken for verbs: the exemption is only safe while
# the verb test stays this narrow.
VERB_MUST_NOT_MATCH = ('guards/validate', 'api/v1/repos', 'http://events/stream', 'selection',
                       'ordering', 'setting', 'tableaux', '/v1/items/details', 'token_count',
                       'my-form', 'former', 'from_value')
# Measured over-blocks, asserted rather than excused: a word boundary is a hyphen too, so a route
# segment that spells a verb keeps its finding. That costs false positives and buys no false
# negative, which is the side the shield chooses. A future edit that loosens the verb test to make
# these silent has to re-measure this table first.
VERB_OVERBLOCKS_ARE_HYPHENATED = ('update-policy', 'select-box', 'insert-order',
                                  'api/v1/set-value')

# Receiver names that keep the 5 verb-free blessed keys loud. Every one of these must stay in the
# table, whole-word, as a segment of a longer name.
DB_WORDS_REQUIRED = ('cursor', 'execute', 'connection', 'db', 'sql', 'query', 'session',
                     'statement', 'objects', 'tablename', 'engine', 'orm')


def scan_source(source):
    """One in-memory module through the real record path, as both baselines were built."""
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-89'})


def check_floors():
    """TIER 1: the blessed CWE-89 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-89'}
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-89={len(keys)} (want {CWE89_LOCKED[kind]})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != CWE89_LOCKED[kind]:
            failures.append((kind, 'CWE-89', CWE89_LOCKED[kind], len(keys),
                             'the blessed CWE-89 population moved'))
    return failures


def check_corpus():
    """TIER 2: the CWE-89 keys re-produced by a real tree scan, as an exact key set.

    The frozen keys come from a whole-tree scan of `benchmark/`, so the only honest comparison is the
    same whole-tree scan filtered to CWE-89. Big-8 holds 0 CWE-89 keys, which is exactly what deleting
    this rule would produce there -- so for that baseline the only lock that exists is TIER 3, and the
    corpus is not re-scanned here (big8_ab.py does that, with the other 118 keys).
    """
    failures = []
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    live = {row for row in scan_rows('parity', tree) if row[2] == 'CWE-89'}
    frozen = {row for row in load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
              if row[2] == 'CWE-89'}
    missing = sorted(frozen - live)
    extra = sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    for row in missing:
        print(f'  MISSING  {row[0]}:{row[1]} {row[4]}')
    for row in extra:
        print(f'  NEW      {row[0]}:{row[1]} {row[4]}')
    if missing:
        failures.append((len(missing), 'frozen CWE-89 keys no longer reported'))
    if extra:
        failures.append((len(extra), 'CWE-89 keys appeared that the baseline never held'))
    return failures


def check_shapes():
    """TIER 3: the truth table, asserted against the seal this file is standing under.

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
        expected = when_abstained if CWE89_SEAL == 'abstained' else when_shipped
        found = scan_source(source)
        status = 'loud' if found else 'quiet'
        note = '; '.join(f'L{n}:{m.replace("CWE-89: ", "")}' for n, m in found)[:60]
        marker = 'ok' if status == expected else 'MISMATCH'
        print(f'  {label:26s} want={expected:5s} got={status:5s} {marker:8s} {note}')
        if status != expected:
            failures.append((label, 'seal', expected, status,
                             'the answer moved without the seal, or the seal moved without the answer'))
    return failures


def check_pairs():
    """TIER 4: the same route with and without the evidence that says query.

    The clean arm follows the seal; the query-flavoured arm is loud at both seals.
    """
    failures = []
    for label, clean, query_flavoured in PAIRS:
        a = bool(scan_source(clean))
        b = bool(scan_source(query_flavoured))
        want_clean = CWE89_SEAL == 'abstained'
        agree = (a == want_clean) and b
        print(f'  {label:34s} route_loud={a} (want {want_clean})  query_flavoured_loud={b} '
              f'(want True)  {"agree" if agree else "DISAGREE"}')
        if not agree:
            failures.append((label, 'evidence provenance', (want_clean, True), (a, b)))
    return failures


def check_vocabulary():
    """TIER 5: the two tables and the wiring, pinned so a later edit cannot widen them by accident."""
    failures = []
    verb_re = getattr(ast_scanner, 'CWE89_SQL_VERB_RE', None)
    if not isinstance(verb_re, re.Pattern):
        print('  CWE89_SQL_VERB_RE missing')
        return [('CWE89_SQL_VERB_RE', 'exists', 'compiled pattern', verb_re)]
    for text in VERB_MUST_MATCH:
        if not verb_re.search(text):
            failures.append(('verb must match', text))
    for text in VERB_MUST_NOT_MATCH:
        if verb_re.search(text):
            failures.append(('route word must not match', text))
    for text in VERB_OVERBLOCKS_ARE_HYPHENATED:
        if not verb_re.search(text):
            failures.append(('hyphenated verb over-block is gone -- this table is asserted so the '
                             'widening has to be a decision', text))
    words = getattr(ast_scanner, 'CWE89_DB_STATEMENT_WORDS', None)
    if words is None:
        failures.append(('CWE89_DB_STATEMENT_WORDS', 'exists'))
    else:
        for name in DB_WORDS_REQUIRED:
            if name == 'fetchall_placeholder':
                continue   # not a receiver word, it is the segmentation test below
            if name not in words:
                failures.append(('db word required', name))
        split = getattr(ast_scanner, '_CWE89_SEGMENT_SPLIT', None)
        check = getattr(ast_scanner, '_c89_identifier_is_db_flavoured', None)
        if split is None or check is None:
            failures.append(('segmentation helpers', 'exist'))
        else:
            for identifier, want in (('cursor_execute', True), ('connection', True),
                                     ('sqlalchemy_query', True), ('db', True),
                                     ('modified_path', False), ('guard_name', False),
                                     ('api_base', False), ('aclient', False)):
                got = bool(check(identifier))
                if got is not want:
                    failures.append(('identifier segment test', identifier, want, got))
    limit = getattr(ast_scanner, '_CWE89_SCOPE_NODE_LIMIT', None)
    if not isinstance(limit, int) or limit <= 0:
        failures.append(('_CWE89_SCOPE_NODE_LIMIT', 'positive int', limit))
    # The branch the guard may touch: it must sit on the `require_shape_or_db=False` side only. A
    # wiring edit that moved it under the shape-required branch would silence rows this table cannot
    # reach, so the placement is asserted on the shipped source, not assumed.
    try:
        body = inspect.getsource(ast_scanner.TaintTracker._collect_cwe89_driver_querybuilder_findings)
    except (OSError, TypeError) as exc:
        failures.append(('collector source readable', str(exc)))
        wiring_ok = False
    else:
        wiring_ok = (body.count('_c89_template_is_endpoint_path_only(') == 1
                     and 'if require_shape_or_db:' in body
                         .split('_c89_template_is_endpoint_path_only(')[0]
                     and 'elif _c89_template_is_endpoint_path_only' in body)
        if not wiring_ok:
            failures.append(('guard is the elif of the require_shape_or_db fork, wired once',
                             body.count('_c89_template_is_endpoint_path_only(')))
    print(f'  verb vocabulary: {len(VERB_MUST_MATCH)} must-match, {len(VERB_MUST_NOT_MATCH)} '
          f'must-not-match  db words={len(words or ())}  scope_node_limit={limit}')
    print(f'  wiring: guard on the no-shape fork only -> {"ok" if wiring_ok else "WRONG"}')
    return failures


def main() -> int:
    if CWE89_SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {CWE89_SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-89 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the corpus behind those keys, scanned live:')
    failures += check_corpus()
    print(f'TIER 3 - truth table under seal={CWE89_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4 - same route, with and without query evidence:')
    failures += check_pairs()
    print('TIER 5 - verb table, db-word table, scope cap and wiring:')
    failures += check_vocabulary()
    print(f'\nseal={CWE89_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'pairs={len(PAIRS)} locked_cwe89={sum(CWE89_LOCKED.values())} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-89 path-only predicate no longer matches its measured evidence. '
              'Restore the answer or update the seal with a re-measured truth table; never re-bless a '
              'baseline -- 25 blessed parity CWE-89 keys are hand-written true positives and the '
              'literal-only version of this rule reaches the 5 of them that carry no verb near the sink.')
        return 1
    print(f'VERDICT: PASS - all {sum(CWE89_LOCKED.values())} blessed CWE-89 keys still reported, '
          f'parity corpus exact-set, {len(FP_ROWS)} route shapes silent, '
          f'{len(MUST_REPORT_ROWS)} query/blessed/unreadable shapes reported, '
          f'{len(PAIRS)} provenance pairs agreeing.')
    return 0


MUTATIONS = {
    'delete_path_guard': {
        'what': 'make the path-only proof always answer "not a route" (the 6 route rows come back)',
        'rows': [row[0] for row in FP_ROWS],
        'requires': '_c89_template_is_endpoint_path_only',
        'apply': lambda: setattr(ast_scanner, '_c89_template_is_endpoint_path_only',
                                 lambda *args: False),
    },
    'path_guard_always_true': {
        'what': 'make the path-only proof answer "route" for everything -- the widest version of the '
                'rule the prompt asked for, and the reason the vetoes exist',
        'rows': ['verb_in_function', 'db_word_in_function', 'plain_text_chunk', 'no_slash_template',
                 'giant_function_cap'],
        'requires': '_c89_template_is_endpoint_path_only',
        'apply': lambda: setattr(ast_scanner, '_c89_template_is_endpoint_path_only',
                                 lambda *args: True),
    },
    'blank_verb_regex': {
        'what': 'empty the SQL verb table, so a SELECT sitting one statement above the route is '
                'evidence of nothing',
        'rows': ['verb_in_function'],
        'requires': 'CWE89_SQL_VERB_RE',
        'apply': lambda: setattr(ast_scanner, 'CWE89_SQL_VERB_RE',
                                 re.compile(r'(?!x)x', re.IGNORECASE)),
    },
    'blank_db_words': {
        'what': 'empty the DB identifier table, so a cursor-named scope stops counting as evidence',
        'rows': ['db_word_in_function'],
        'requires': 'CWE89_DB_STATEMENT_WORDS',
        'apply': lambda: setattr(ast_scanner, 'CWE89_DB_STATEMENT_WORDS', frozenset()),
    },
    'veto_reads_statement_only': {
        'what': 'narrow the negative veto back to the enclosing statement -- the exact defect found '
                'by the first fixture round',
        'rows': ['verb_in_function'],
        'requires': '_c89_enclosing_scope',
        'apply': lambda: setattr(ast_scanner, '_c89_enclosing_scope',
                                 lambda node: next((c for c in _stmt_chain(node)), None)),
    },
    'no_scope_node_limit': {
        'what': 'raise the scope cap so a 400-assignment function is read as provable',
        'rows': ['giant_function_cap'],
        'requires': '_CWE89_SCOPE_NODE_LIMIT',
        'apply': lambda: setattr(ast_scanner, '_CWE89_SCOPE_NODE_LIMIT', 10 ** 9),
    },
}


def _stmt_chain(node):
    current = getattr(node, 'parent', None)
    while current is not None:
        if isinstance(current, ast.stmt):
            yield current
            return
        current = getattr(current, 'parent', None)


def run_mutation(name: str) -> int:
    """Apply one in-memory mutation and run the real gate over it. Exit 1 = the mutation was caught."""
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print(f"  rows that must move: {', '.join(spec['rows'])}")
    if spec['requires'] and not hasattr(ast_scanner, spec['requires']):
        print(f"  SKIP - not shipped in this step: the guard symbol ast_scanner.{spec['requires']} does "
              f"not exist, so there is nothing to delete or widen. NOT counted as a falsification.")
        return 2
    spec['apply']()
    # TIER 1 and 2 read the frozen baselines and re-scan the whole `benchmark/` tree; an in-memory
    # patch of a guard cannot move a blessed key the corpus does not hold, and running them here would
    # make each mutation cost a full tree scan. The truth table, the pairs and the tables are what a
    # guard is falsified on.
    print(f'TIER 3 - truth table under seal={CWE89_SEAL!r}:')
    failures = check_shapes()
    print('TIER 4 - same route, with and without query evidence:')
    failures += check_pairs()
    print('TIER 5 - verb table, db-word table, scope cap and wiring:')
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
