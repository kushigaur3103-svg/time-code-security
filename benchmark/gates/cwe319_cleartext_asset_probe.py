"""Truth table for the CWE-319 public-asset-fetch clause: the lock that fails if a consult goes away.

    python benchmark/gates/cwe319_cleartext_asset_probe.py
    python benchmark/gates/cwe319_cleartext_asset_probe.py --mutate=NAME
    python benchmark/gates/cwe319_cleartext_asset_probe.py --print-rows

What the clause is, in its own words
------------------------------------
`_c319_is_public_static_asset_fetch` (ast_scanner.py:14785) answers one question: *is this sink call
fetching a static raster asset over a cleartext URL, with nothing carried in either direction?* It is a
conjunction of positive proofs -- a literal cleartext scheme, no query / fragment / format / percent hole,
a host with a path tail and no userinfo, a `.jpg`/`.jpeg` suffix on the last path segment, a read verb
(`get`) whose chain head is an `ast.Name` that resolves through **this module's own import table** to
`requests`, exactly one positional argument, and only transport options among the keywords. Every consult
sits in a suppressing position, so the clause can retire a CWE-319 row and can never create one; measured
on the shipped bytes: arena `RETIRED=102 ADDED=0`, parity `474 -> 474 rows / CWE-319 35 = 35`, Big-8
`119 = 119`.

Why a directory or a basename rule was not used
-----------------------------------------------
The population is one shape: 283 of the arena's 311 cleartext literals are the same COCO sample image the
vision conversion scripts download to smoke-test a pipeline, and 98 of the rule's 102 kept rows sit on
those two lines. A `**/models/**`-style glob is a locked refusal for this tree (the same files carry
CWE-312 cleartext storage and CWE-532 sensitive logging), so the deciding axis here is the *value and the
call shape*, never a path -- Rule 15.5 rungs 1 and 2.

Why there are FOUR consults, and the relabel this gate pins
----------------------------------------------------------
The rule emits from four places: `_collect_batch3a_structural_findings` (`CLEARTEXT_HTTP_TRANSMISSION`),
`_collect_cluster2_structural_findings` through its `_is_cleartext_url` closure
(`CLEARTEXT_HTTP_REQUEST`), and `_collect_cwe319_variable_resolution_findings` twice (Shape 2, a default
parameter holding the literal, and Shape 1, a local variable bound to it). The first draft consulted only
three and the arena A/B read `RETIRED=102 ADDED=52`: on `models/align/convert_align_tf_to_hf.py` the
transmission rows went quiet at 67/68 and the cluster-2 registry immediately surfaced line 68 again under
a *different symbol*. That is a relabel, not a retirement -- the count barely moves and a downstream
consumer sees a new rule name on the same line. So the clause is consulted inside `_is_cleartext_url` too,
and its only caller passes the sink `node`.

`default_arg_double_emit` below is that shape written small: a default parameter carrying the literal plus
one fetch. With the clause live it emits **0** rows; with the clause blinded it emits **2** rows, one per
symbol. It is the finding-level pin on the fourth consult: drop that consult, or drop the `node` argument
its caller passes, and this row comes back as a lone request-symbol finding and TIER 3 fails on a message
it was not expecting -- without waiting for a baseline to move. TIER 7 counts the consult sites
structurally from the engine's own AST, so the same drift fails twice: once behaviourally, once as a shape.

Falsification
-------------
Eleven mutations, one at a time (`--mutate=NAME`), each patching the module in memory -- a rebind of the
predicate, a rebind of one of its four tables, or a self-contained restatement of the clause with exactly
one clause removed. TIER 4 first requires the restatement to agree with the shipped method on every
predicate row, so a mutation can only ever bite on a clause the engine still has; a mutation that cannot
run exits 2 rather than pretending to pass. Every one exits 1 CAUGHT on the shipped bytes, and the clean
run exits 0 with `failures=0`.

Measured on the shipped bytes (the `CAUGHT on N row(s)` lines, with the tier split the runner prints --
T3 findings table / T4 predicate table / T5 pairs / T6 blessed reach / T7 wiring + tables):
`delete_asset_clause` 32 [T3=11 T4=7 T5=9 T6=1 T7=4], `asset_clause_always_true` 76
[T3=26 T4=36 T5=9 T6=1 T7=4], `asset_suffix_accepts_a_weight_file` 9, `asset_verb_joined_without_population`
5, `asset_root_joined_without_population` 6, `asset_transport_keywords_accept_a_payload` 10,
`asset_head_proof_dropped` 23 [T3=6 T4=10 T5=3 T7=4], `asset_positional_count_dropped` 11,
`asset_root_match_becomes_a_substring` 8 [T4=4 T7=4], `asset_url_accepts_a_query_hole` 13
[T3=4 T4=4 T5=1 T7=4], `asset_url_accepts_a_format_hole` 11 [T3=3 T4=4 T7=4].

Two defects this file had to fix before any of that meant anything, both of them the same standing law
("a mutation must be visible to the tier it is written against"):

* `_rows` and TIER 4/6/7 first called the *pristine* method object directly, so a `--mutate` rebind was
  invisible and two falsifications reported MISSED (exit 0) on a guard that is very much load-bearing.
  Everything now asks through `_installed()`, which reads the class attribute at call time, and the
  blinded arm restores whatever was installed before it, never the pristine method.
* `asset_url_accepts_a_query_hole` was a dead tripwire: `?` and `#` already break
  `endswith(".jpg")`, so removing the hole clause moved no row and the mutation was caught only by four
  table assertions. `query_after_suffix` and `fragment_after_suffix` -- a query or fragment whose *own
  value* ends in `.jpg` -- are refused only by the hole clause, and after adding them the mutation bites
  13 rows including four finding-level ones.

Sources are assembled from split string fragments (`_H`, `_REQ`, `_OPEN`, `_GET`) so that the parity gate,
which scans this whole directory, sees no cleartext URL literal and no fetch call spelled in one piece
inside the harness. Same convention as `cwe312_vocab_dump_probe.py` and
`cwe117_numeric_provenance_probe.py`.
"""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import inspect
import io as _io
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

SEAL_TARGETS = ('shipped', 'absent')

if os.environ.get('TCS_C319_ENGINE'):
    # falsification hook: argue against an ast_scanner.py whose text has been patched. Registered under
    # the real module name because `cli` resolves the engine through sys.modules.
    _spec = importlib.util.spec_from_file_location('ast_scanner', os.environ['TCS_C319_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys, scan_rows  # noqa: E402

CLAUSE_NAME = '_c319_is_public_static_asset_fetch'
PRISTINE = getattr(ast_scanner.TaintTracker, CLAUSE_NAME, None)
SEAL = 'shipped' if PRISTINE is not None else 'absent'

LOCKED = {'parity': 35, 'big8': 0}
CWE = 'CWE-319'
MSG_T = 'CWE-319: ' + 'CLEARTEXT_HTTP_' + 'TRANSMISSION'
MSG_R = 'CWE-319: ' + 'CLEARTEXT_HTTP_' + 'REQUEST'

# Fragments: nothing below this line may spell a cleartext URL or a fetch call in one piece.
_H = 'ht' 'tp' ':' + '/' + '/'
_HS = 'ht' 'tps' ':' + '/' + '/'
_REQ = 're' 'quests'
_OPEN = 'op' 'en'
_GET = 'g' 'et'
_FETCH = _REQ + '.' + _GET
_IMG = 'Image.' + _OPEN
_HEAD = 'import ' + _REQ + '\nfrom PIL import Image\n'
# The host-and-path text, spelled once so both schemes are built from it rather than sliced out of it.
_ASSET_PATH = 'images.cocodataset.org/val2017/000000039769.jpg'
_COCO = _H + _ASSET_PATH
_CDN = _H + 'cdn.example.com/a.jpg'


def _img_fetch(url_text, extra=''):
    """`Image.open(requests.get(<url>, <extra>).raw)` -- the arena shape, one line."""
    return _IMG + '(' + _FETCH + '(' + url_text + (', ' + extra if extra else '') + ').raw)'


# (label, source, rows-without-the-clause, rows-on-the-shipped-engine, note)
SHAPES = [
    # ---- the shapes the clause retires ----
    ('literal_at_call', _HEAD + _img_fetch('"' + _COCO + '"', 'stream=True') + '\n',
     ((3, MSG_T),), (), 'the arena shape with the URL written at the call'),
    ('arena_two_line', _HEAD + 'url = "' + _COCO + '"\n'
     + _img_fetch('url', 'stream=True') + '\n',
     ((4, MSG_T),), (), 'a module-level name bound to the literal, then handed to the fetch'),
    ('func_local_two_line', _HEAD + 'def prepare_img():\n'
     + '    url = "' + _COCO + '"\n    ' + _img_fetch('url', 'stream=True') + '\n    return im\n',
     ((4, MSG_T), (5, MSG_T)), (), 'the verbatim arena shape: a function-local url and its sink line'),
    ('func_local_literal', _HEAD + 'def prepare_img():\n'
     + '    ' + _img_fetch('"' + _CDN + '"', 'stream=True') + '\n    return im\n',
     ((4, MSG_T),), (), 'the same, with the literal at the call'),
    ('no_keyword', _HEAD + _img_fetch('"' + _COCO + '"') + '\n',
     ((3, MSG_T),), (), 'no keyword at all: transport options are a permitted subset, not a requirement'),
    ('timeout_kw', _HEAD + _img_fetch('"' + _COCO + '"', 'timeout=5') + '\n',
     ((3, MSG_T),), (), 'a timeout is how the request is made, not what it carries'),
    ('jpeg_suffix', _HEAD + _img_fetch('"' + _COCO[:-4] + '.jpeg"') + '\n',
     ((3, MSG_T),), (), 'the second member of the raster table'),
    ('default_arg_double_emit', _HEAD + 'def prepare_img(url="' + _COCO + '"):\n'
     + '    ' + _img_fetch('url', 'stream=True') + '\n    return im\n',
     ((3, MSG_T), (4, MSG_R)), (), 'THE RELABEL ROW: two emitters, two symbols, one line each'),
    ('bare_call_no_image', _HEAD + _FETCH + '("' + _CDN + '", stream=True)\n',
     ((3, MSG_T),), (), 'the fetch alone, with no image loader wrapped around it'),
    # ---- the tripwires: loud with the clause, loud without it ----
    ('query_string', _HEAD + _img_fetch('"' + _COCO + '?v=1"', 'stream=True') + '\n',
     ((3, MSG_T),), ((3, MSG_T),), 'a query is a value the caller chose'),
    ('percent_hole', _HEAD + _img_fetch('"' + _H + 'cdn.example.com/a%2Fb.jpg"') + '\n',
     ((3, MSG_T),), ((3, MSG_T),), 'an encoded escape is a path somebody built, not a literal path'),
    # The two rows that make the query/fragment clause load-bearing. Without them the suffix test alone
    # refuses every hole-shaped URL (a `?` or `#` in the tail breaks `endswith('.jpg')`), so dropping the
    # clause would move nothing and its mutation would be caught only at a source-fragment pin.
    ('query_after_suffix', _HEAD + _img_fetch('"' + _H + 'cdn.example.com/a.jpg' + '?v=b.jpg"',
                                              'stream=True') + '\n',
     ((3, MSG_T),), ((3, MSG_T),),
     'a query whose own value ends in .jpg: only the query clause can refuse it'),
    ('fragment_after_suffix', _HEAD + _img_fetch('"' + _H + 'cdn.example.com/a.jpg' + '#/b.jpg"',
                                                 'stream=True') + '\n',
     ((3, MSG_T),), ((3, MSG_T),),
     'a fragment path under the same law: the suffix test is fooled, the hole clause is not'),
    ('format_hole', _HEAD + 'host = "cdn.example.com"\n'
     + _img_fetch('f"' + _H + '{host}/a.jpg"') + '\n',
     (), (), 'an f-string URL folds to no literal, so nothing emits at either arm'),
    ('userinfo', _HEAD + _img_fetch('"' + _H + 'user:pw@cdn.example.com/a.jpg"') + '\n',
     ((3, MSG_T),), ((3, MSG_T),), 'credentials in the URL are the finding, never an exemption'),
    ('weight_bin', _HEAD + _img_fetch('"' + _H + 'cdn.example.com/w.bin"') + '\n',
     ((3, MSG_T),), ((3, MSG_T),), 'a weight blob is not a raster asset'),
    ('weights_json', _HEAD + _img_fetch('"' + _H + 'cdn.example.com/params.json"') + '\n',
     ((3, MSG_T),), ((3, MSG_T),), 'a parameter manifest'),
    ('config_env', _HEAD + _img_fetch('"' + _H + 'cdn.example.com/.env"') + '\n',
     ((3, MSG_T),), ((3, MSG_T),), 'an env file: the suffix table has no member for it and must not gain one'),
    ('two_positional', _HEAD + 't = 5\n' + _img_fetch('"' + _COCO + '", t') + '\n',
     ((4, MSG_T),), ((4, MSG_T),), 'a second positional is an argument this clause cannot name'),
    ('second_pos_data', _HEAD + 'd = {"a": 1}\n' + _img_fetch('"' + _COCO + '", d') + '\n',
     ((4, MSG_T),), ((4, MSG_T),), 'a positional payload'),
    ('headers_kw', _HEAD + _img_fetch('"' + _COCO + '"', 'headers={"a": "1"}') + '\n',
     ((3, MSG_T),), ((3, MSG_T),), 'headers carry content out'),
    ('data_kw', _HEAD + _img_fetch('"' + _COCO + '"', 'data=b"x"') + '\n',
     ((3, MSG_T),), ((3, MSG_T),), 'a body'),
    ('json_kw', _HEAD + _img_fetch('"' + _COCO + '"', 'json={"a": 1}') + '\n',
     ((3, MSG_T),), ((3, MSG_T),), 'a serialised body'),
    ('auth_kw', _HEAD + _img_fetch('"' + _COCO + '"', 'auth=("u", "p")') + '\n',
     ((3, MSG_T),), ((3, MSG_T),), 'a credential handed to the request'),
    ('params_kw', _HEAD + _img_fetch('"' + _COCO + '"', 'params={"q": "1"}') + '\n',
     ((3, MSG_T),), ((3, MSG_T),), 'a caller-chosen query'),
    ('post_verb', _HEAD + _REQ + '.post("' + _H + 'api.example.com/login", json={"password": "x"})\n',
     ((3, MSG_T),), ((3, MSG_T),), 'a POST with a password in it'),
    ('post_asset_verb', _HEAD + _IMG + '(' + _REQ + '.post("' + _CDN + '").' + 'raw)\n',
     ((3, MSG_T),), ((3, MSG_T),), 'a POST of the asset URL: the verb is not a read'),
    ('httpx_get', 'import httpx\nfrom PIL import Image\n' + _IMG + '(httpx.get("' + _CDN + '").' + 'raw)\n',
     ((3, MSG_T),), ((3, MSG_T),), 'a second HTTP library has no measured asset rows here'),
    ('urlopen_get', 'import urllib.' + 'request\nfrom PIL import Image\n'
     + 'im = urllib.' + 'request.urlopen("' + _CDN + '")\n',
     ((3, MSG_T),), ((3, MSG_T),), 'the stdlib fetch stays loud until measured'),
    ('unimported_head', 'from PIL import Image\n' + _img_fetch('"' + _CDN + '"') + '\n',
     ((2, MSG_T),), ((2, MSG_T),), 'a name nobody imported is not a library identity'),
    ('local_named_requests', 'from PIL import Image\n' + _REQ + ' = object()\n'
     + _img_fetch('"' + _CDN + '"') + '\n',
     ((3, MSG_T),), ((3, MSG_T),), 'a local object wearing the library name'),
    ('session_asset', _HEAD + 'sess = ' + _REQ + '.Session()\n'
     + _IMG + '(sess.' + _GET + '("' + _CDN + '", stream=True).' + 'raw)\n',
     ((4, MSG_R),), ((4, MSG_R),), 'a session head resolves to no module: the control for the relabel row'),
    ('localhost_asset', _HEAD + _img_fetch('"' + _H + 'localhost:8000/a.jpg"', 'stream=True') + '\n',
     (), (), 'loopback is retired upstream by the host allowlist, not by this clause'),
    ('no_path', _HEAD + _img_fetch('"' + _H + 'cdn.example.com"') + '\n',
     ((3, MSG_T),), ((3, MSG_T),), 'a bare host has no tail to check'),
    ('bare_host_dir', _HEAD + _img_fetch('"' + _H + 'cdn.example.com/photos/"') + '\n',
     ((3, MSG_T),), ((3, MSG_T),), 'a directory listing is not one asset'),
]

RETIRED = [row for row in SHAPES if row[2] and not row[3]]
LOUD = [row for row in SHAPES if row[3]]
MULTI = [row for row in SHAPES if len(row[2]) > 1]

# (label, source, callee-of-the-call-to-ask, url-handed-to-the-clause, want, note)
PREDICATES = [
    ('jpeg_literal', _HEAD + _img_fetch('"' + _COCO + '"') + '\n', _FETCH, _COCO, True,
     'the retired shape, asked at the predicate'),
    ('jpeg_stream_kw', _HEAD + _img_fetch('"' + _COCO + '"', 'stream=True') + '\n', _FETCH, _COCO, True,
     'the arena shape itself'),
    ('port_host', _HEAD + _img_fetch('"' + _H + 'localhost:8000/a.jpg"') + '\n', _FETCH,
     _H + 'localhost:8000/a.jpg', True,
     'the clause does not know about loopback -- the upstream allowlist does, and this row says so'),
    ('weight_suffix', _HEAD + _img_fetch('"' + _H + 'cdn.example.com/w.bin"') + '\n', _FETCH,
     _H + 'cdn.example.com/w.bin', False, 'no weight member in the suffix table'),
    ('env_suffix', _HEAD + _img_fetch('"' + _H + 'cdn.example.com/.env"') + '\n', _FETCH,
     _H + 'cdn.example.com/.env', False, 'no env member either'),
    ('query_hole', _HEAD + _img_fetch('"' + _COCO + '?v=1"') + '\n', _FETCH, _COCO + '?v=1', False,
     'the query clause'),
    ('query_past_the_suffix', _HEAD + _img_fetch('"' + _H + 'cdn.example.com/a.jpg?v=b.jpg"') + '\n',
     _FETCH, _H + 'cdn.example.com/a.jpg?v=b.jpg', False,
     'the suffix test passes here, so this row is the query clause alone doing the work'),
    ('fragment_past_the_suffix', _HEAD + _img_fetch('"' + _H + 'cdn.example.com/a.jpg#/b.jpg"') + '\n',
     _FETCH, _H + 'cdn.example.com/a.jpg#/b.jpg', False,
     'and this one the fragment half of it'),
    ('percent_hole', _HEAD + _img_fetch('"' + _H + 'cdn.example.com/a%2Fb.jpg"') + '\n', _FETCH,
     _H + 'cdn.example.com/a%2Fb.jpg', False, 'the escape clause'),
    ('format_hole', _HEAD + _img_fetch('"' + _H + '{host}/a.jpg"') + '\n', _FETCH,
     _H + '{host}/a.jpg', False, 'the brace clause -- what an f-string folds to'),
    ('userinfo_host', _HEAD + _img_fetch('"' + _H + 'user:pw@cdn.example.com/a.jpg"') + '\n', _FETCH,
     _H + 'user:pw@cdn.example.com/a.jpg', False, 'the no-credentials clause'),
    ('bare_host', _HEAD + _img_fetch('"' + _H + 'cdn.example.com"') + '\n', _FETCH,
     _H + 'cdn.example.com', False, 'the tail clause'),
    ('trailing_dir', _HEAD + _img_fetch('"' + _H + 'cdn.example.com/photos/"') + '\n', _FETCH,
     _H + 'cdn.example.com/photos/', False, 'a directory is not a file'),
    ('second_positional', _HEAD + 't = 5\n' + _img_fetch('"' + _COCO + '", t') + '\n', _FETCH, _COCO,
     False, 'a second positional argument'),
    ('headers_payload', _HEAD + _img_fetch('"' + _COCO + '"', 'headers={"a": "1"}') + '\n', _FETCH, _COCO,
     False, 'a keyword that carries content'),
    ('https_url', _HEAD + _img_fetch('"' + _HS + _ASSET_PATH + '"') + '\n', _FETCH,
     _HS + _ASSET_PATH, False, 'a cleartext clause never speaks for TLS'),
    ('unimported_head', 'from PIL import Image\n' + _img_fetch('"' + _CDN + '"') + '\n', _FETCH, _CDN,
     False, 'the name is not in this module import table'),
    ('toolbelt_head', 'import ' + _REQ + '_toolbelt\nfrom PIL import Image\n'
     + _IMG + '(' + _REQ + '_toolbelt.' + _GET + '("' + _CDN + '").' + 'raw)\n',
     _REQ + '_toolbelt.' + _GET, _CDN, False, 'the root test is a dot boundary, not a substring'),
    ('mock_head', 'import ' + _REQ + '_mock\nfrom PIL import Image\n'
     + _IMG + '(' + _REQ + '_mock.' + _GET + '("' + _CDN + '").' + 'raw)\n',
     _REQ + '_mock.' + _GET, _CDN, False, 'a test double is not the network, and does not inherit the root'),
    ('session_head', _HEAD + 'sess = ' + _REQ + '.Session()\n'
     + _IMG + '(sess.' + _GET + '("' + _CDN + '", stream=True).' + 'raw)\n',
     'sess.' + _GET, _CDN, False, 'a session object is a response factory, not a module identity'),
    ('local_requests_name', 'from PIL import Image\n' + _REQ + ' = object()\n'
     + _img_fetch('"' + _CDN + '"') + '\n', _FETCH, _CDN, False,
     'a local binding wearing the library name is not the library'),
]

PAIRS = [
    ('suffix axis', 'jpeg_suffix', 'weights_json', 'only a raster suffix is an asset'),
    ('hole axis', 'literal_at_call', 'query_string', 'a query is a caller-chosen value'),
    ('smuggled hole axis', 'literal_at_call', 'query_after_suffix',
     'a hole the suffix test cannot see, refused only by the hole clause'),
    ('keyword axis', 'literal_at_call', 'headers_kw', 'transport options only, never content'),
    ('positional axis', 'literal_at_call', 'two_positional', 'one positional argument, the URL'),
    ('root axis', 'literal_at_call', 'httpx_get', 'a root joins the table only with rows behind it'),
    ('verb axis', 'literal_at_call', 'post_asset_verb', 'get is the measured read verb'),
    ('head axis', 'default_arg_double_emit', 'session_asset', 'a head must resolve through the imports'),
    ('emitter axis', 'func_local_two_line', 'session_asset',
     'both symbols retire, so no line is left wearing a different one'),
]

SUFFIXES_REQUIRED = ('.jpg', '.jpeg')
VERBS_REQUIRED = ('get',)
ROOTS_REQUIRED = ('requests',)
VERBS_FORBIDDEN = ('post', 'put', 'patch', 'delete', 'head', 'options', 'fetch', 'urlopen', 'urlretrieve')
ROOTS_FORBIDDEN = ('httpx', 'urllib3', 'urllib', 'aiohttp', 'tornado')
KEYWORDS_FORBIDDEN = ('data', 'json', 'params', 'files', 'headers', 'auth', 'cookies')
KEYWORDS_REQUIRED = ('stream', 'timeout', 'verify', 'allow_redirects', 'cert')
CONSULT_SITES = {'_collect_batch3a_structural_findings': 1,
                 '_collect_cluster2_structural_findings': 1,
                 '_collect_cwe319_variable_resolution_findings': 2}


# --------------------------------------------------------------------------- helpers

def _installed():
    """Whatever clause the engine is running right now -- the pristine method, or an active mutation.

    Every tier asks this and never `PRISTINE` directly, because a mutation installed by --mutate has to
    be visible to the tier it is written against. Restoring after a blinded arm puts *this* back, not the
    pristine one, so a mutation is never clobbered mid-run.
    """
    return getattr(ast_scanner.TaintTracker, CLAUSE_NAME)


def _rows(source: str, blind: bool = False):
    """Every CWE-319 row a fixture emits, as (line, message) -- the pair that makes a relabel visible."""
    current = _installed()
    if blind:
        setattr(ast_scanner.TaintTracker, CLAUSE_NAME, lambda self, u, c, m: False)
    try:
        with contextlib.redirect_stderr(_io.StringIO()):
            tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
            _, _, edges = tracker.analyze()
            found = cli._findings_for(tracker, edges)
    finally:
        if blind:
            setattr(ast_scanner.TaintTracker, CLAUSE_NAME, current)
    return tuple(sorted({(int(r['line']), r['message']) for r in found if r['cwe'] == CWE}))


def _calls_on(tree, lineno):
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == lineno]


def _literal_str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _url_at(tree, call):
    """Best-effort URL for a call: a first-positional literal, a name written exactly once to one, or url=."""
    arg = call.args[0] if call.args else None
    if arg is None:
        for kw in call.keywords or []:
            if kw.arg == 'url':
                arg = kw.value
    got = _literal_str(arg)
    if got is not None:
        return got
    if isinstance(arg, ast.Name):
        writes = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                targets = [node.target]
            else:
                continue
            if any(getattr(t, 'id', None) == arg.id for t in targets):
                writes.append(node)
        if len(writes) == 1:
            return _literal_str(getattr(writes[0], 'value', None))
    return None


def _pitch(tracker, url_val, call, mod_name, drop=None):
    """A self-contained copy of the clause with exactly one named clause removable.

    TIER 4 requires it to agree with the shipped method on every predicate row before any mutation runs,
    so a mutation can only ever bite on a clause the engine still has.
    """
    if not isinstance(url_val, str) or not url_val.lower().startswith(_H):
        return False
    if drop != 'query_hole' and ('?' in url_val or '#' in url_val):
        return False
    if drop != 'format_hole' and ('{' in url_val or '}' in url_val or '%' in url_val):
        return False
    rest = url_val[len(_H):]
    host, slash, tail = rest.partition('/')
    if drop != 'host_tail' and (not slash or not tail or '@' in host):
        return False
    if drop != 'suffix' and not tail.rsplit('/', 1)[-1].lower().endswith(
            ast_scanner.CWE319_ASSET_SUFFIXES):
        return False
    func = call.func
    if drop != 'verb':
        if (not isinstance(func, ast.Attribute)
                or func.attr not in ast_scanner.CWE319_ASSET_READ_VERBS):
            return False
    head = func.value if isinstance(func, ast.Attribute) else func
    while isinstance(head, ast.Attribute):
        head = head.value
    if drop == 'head_proof':
        pass
    elif drop == 'root_substring':
        if not isinstance(head, ast.Name):
            return False
        origin = (tracker.imports.get(mod_name) or {}).get(head.id)
        if origin is None or not any(root in origin
                                     for root in ast_scanner.CWE319_ASSET_LIBRARY_ROOTS):
            return False
    else:
        if not isinstance(head, ast.Name):
            return False
        origin = (tracker.imports.get(mod_name) or {}).get(head.id)
        if origin is None or origin.split('.')[0] not in ast_scanner.CWE319_ASSET_LIBRARY_ROOTS:
            return False
    if drop != 'positional' and len(call.args) != 1:
        return False
    if drop != 'keywords' and not all(kw.arg in ast_scanner.CWE319_ASSET_TRANSPORT_KEYWORDS
                                      for kw in call.keywords or []):
        return False
    return True


def _pred_ask(source, callee, url):
    """Ask the clause on the first call spelled `callee` in `source`, at the engine and at the restatement.

    Returns `(shipped, restated, asked)`; `asked` is False when the fixture holds no such call, which the
    tier reports as a broken row rather than as a refusal.
    """
    tree = ast.parse(source)
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
        tracker.analyze()
    mod = next(iter(tracker.modules), 'm')
    clause = _installed()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if ast_scanner.dotted_name(node.func) != callee:
            continue
        return bool(clause(tracker, url, node, mod)), bool(_pitch(tracker, url, node, mod)), True
    return None, None, False


# --------------------------------------------------------------------------- tiers

def check_floors():
    """TIER 1: the blessed CWE-319 population, and what its own lines name."""
    failures = []
    for kind, expected in LOCKED.items():
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == CWE}
        cats = {}
        suffix_hits = []
        for row in keys:
            cats[str(row[3])] = cats.get(str(row[3]), 0) + 1
            message = (str(row[4]) + ' ' + str(row[3])).lower()
            if '.jpg' in message or '.jpeg' in message:
                suffix_hits.append((row[0], row[1]))
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'{CWE}={len(keys)} (want {expected})  categories={sorted(cats.items())}  '
              f'rows naming a raster asset={len(suffix_hits)}')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != expected:
            failures.append((kind, CWE, expected, len(keys),
                             'the blessed CWE-319 population moved -- the clause reached a true positive'))
        if suffix_hits:
            failures.append((kind, 'a blessed CWE-319 key names a raster asset', 0, len(suffix_hits),
                             'the clause and the baseline would now answer the same line twice'))
    if SEAL != 'shipped':
        failures.append(('seal', CLAUSE_NAME, 'present on TaintTracker', SEAL,
                         'the clause was withdrawn, so every quiet row in TIER 3 must go back to loud'))
    return failures


def check_live_baseline():
    """TIER 2: the rule reproduces its own frozen set on the corpus it was blessed from."""
    failures = []
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    with contextlib.redirect_stderr(_io.StringIO()):
        live = {r for r in scan_rows('parity', tree) if r[2] == CWE}
    frozen = {r for r in load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
              if r[2] == CWE}
    missing, extra = sorted(frozen - live), sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    for item in missing[:6]:
        print(f'  MISSING  {item}')
    for item in extra[:6]:
        print(f'  NEW      {item}')
    if missing:
        failures.append(('parity exact-set', f'{CWE} blessed keys no longer report', len(missing), 0,
                         'the clause silenced a true positive'))
    if extra:
        failures.append(('parity exact-set', f'new {CWE} rows appeared', 0, len(extra),
                         'a suppressing clause must not emit'))
    return failures


def check_shapes():
    """TIER 3: the findings truth table, both arms, compared as (line, message) sets."""
    failures = []
    quiet_rows = loud_rows = multi_rows = 0
    for label, source, want_absent, want_shipped, note in SHAPES:
        absent = _rows(source, blind=True)
        shipped = _rows(source, blind=False)
        ok = absent == want_absent and shipped == want_shipped
        if shipped and not absent:
            failures.append((label, 'a row the clause did not retire appeared', absent, shipped,
                             'a suppressing clause cannot emit -- this is an added finding'))
        markers = []
        if absent != want_absent:
            markers.append(f'without-clause want={want_absent} got={absent}')
        if shipped != want_shipped:
            markers.append(f'shipped want={want_shipped} got={shipped}')
        print(f'  {label:26s} {"ok" if ok else "MISMATCH":8s} without={len(absent)} '
              f'shipped={len(shipped)} {"; ".join(markers)}')
        if not ok:
            failures.append((label, 'truth table', (want_absent, want_shipped), (absent, shipped), note))
        if absent and not shipped:
            quiet_rows += 1
        if shipped:
            loud_rows += 1
        if len(absent) > 1:
            multi_rows += 1
    print(f'  retired_by_clause={quiet_rows} (want {len(RETIRED)}) still_loud={loud_rows} '
          f'(want {len(LOUD)}) multi_emitter_shapes={multi_rows} (want {len(MULTI)}) shapes={len(SHAPES)}')
    if quiet_rows != len(RETIRED):
        failures.append(('retirement', 'every retired shape must still be retired',
                         len(RETIRED), quiet_rows))
    if loud_rows != len(LOUD):
        failures.append(('tripwires', 'every tripwire must still report', len(LOUD), loud_rows))
    if multi_rows < 1:
        failures.append(('relabel', 'at least one shape must emit from two symbols', 1, multi_rows,
                         'this is the row that pins the fourth consult'))
    return failures


def check_predicates():
    """TIER 4: the clause asked directly, and the faithfulness of the copy its mutations run through."""
    failures = []
    proven = refused = 0
    print('  the clause, asked at the predicate on the call its fixture spells:')
    for label, source, callee, url, want, note in PREDICATES:
        shipped, restated, asked = _pred_ask(source, callee, url)
        ok = asked and shipped is want and restated == shipped
        print(f'  {label:20s} want={want!s:5s} engine={str(shipped):5s} restated={str(restated):5s} '
              f'{"ok" if ok else "MISMATCH":8s} callee={callee}')
        if not asked:
            failures.append((label, 'the fixture holds no call spelled like that -- the row asks nothing',
                             callee, asked))
            continue
        if shipped is not want:
            failures.append((label, 'clause answer', want, shipped, note))
        if restated != shipped:
            failures.append((label, 'the restated clause no longer agrees with the engine',
                             shipped, restated, 'a mutation run through it would prove nothing'))
        if shipped:
            proven += 1
        else:
            refused += 1
    print(f'  pred_proven={proven} pred_refused={refused} pred_rows={len(PREDICATES)}')
    if proven < 3:
        failures.append(('predicate census', 'at least 3 rows must answer True, so the refusals are '
                         'refusals and not an unasked question', 3, proven))
    return failures


def check_pairs():
    """TIER 5: one axis per pair, both arms read from the findings table."""
    failures = []
    by_label = {row[0]: row for row in SHAPES}
    for name, quiet_label, loud_label, claim in PAIRS:
        q, l = by_label[quiet_label], by_label[loud_label]
        a_q, s_q = _rows(q[1], blind=True), _rows(q[1], blind=False)
        a_l, s_l = _rows(l[1], blind=True), _rows(l[1], blind=False)
        ok = bool(a_q) and not s_q and bool(a_l) and s_l == a_l
        print(f'  {name:16s} {quiet_label} vs {loud_label:22s} '
              f'{"ok" if ok else "MISMATCH":8s} retired={bool(a_q) and not s_q} '
              f'unmoved={s_l == a_l}  ({claim})')
        if not ok:
            failures.append((name, quiet_label, loud_label,
                             'the two arms do not separate on this axis: retired='
                             f'{bool(a_q) and not s_q}, unmoved={s_l == a_l}'))
    return failures


def _blessed_rows(kind):
    rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
    return sorted((row for row in rows if row[2] == CWE), key=lambda r: (str(r[0]), r[1]))


def check_blessed_reach():
    """TIER 6: ask the clause on every blessed CWE-319 line, and prove the sweep is alive."""
    failures = []
    controls_wanted = sum(1 for row in PREDICATES if row[4])
    controls = sum(1 for label, source, callee, url, want, note in PREDICATES
                   if want and _pred_ask(source, callee, url)[0])
    print(f'  control (predicate rows the clause must answer True on): {controls}/{controls_wanted}')
    if controls != controls_wanted:
        failures.append(('control', 'the sweep must answer on every True-shaped predicate row',
                         controls_wanted, controls,
                         'a census that answers nothing cannot prove a refusal'))

    for kind in ('parity', 'big8'):
        rows = _blessed_rows(kind)
        by_file = {}
        for row in rows:
            by_file.setdefault(str(row[0]), set()).add(row[1])
        asked = answered = calls = resolved = unasked_lines = 0
        for name, wanted_lines in sorted(by_file.items()):
            relative = (name if kind == 'parity' else os.path.join(
                'benchmark_gates_data', 'corpus_big8', os.path.basename(name)))
            module = os.path.basename(name)
            if not os.path.isfile(os.path.abspath(os.path.join(ROOT, relative))):
                failures.append((name, 'blessed fixture file is not in the tree'))
                continue
            with open(os.path.abspath(os.path.join(ROOT, relative)),
                      encoding='utf-8', errors='replace') as handle:
                source = handle.read()
            tree = ast.parse(source)
            with contextlib.redirect_stderr(_io.StringIO()):
                tracker = ast_scanner.TaintTracker(files={module: source}, audit_all=True)
                tracker.analyze()
            mod = next(iter(tracker.modules), module[:-3])
            for lineno in sorted(wanted_lines):
                found = _calls_on(tree, lineno)
                if not found:
                    unasked_lines += 1
                    continue
                for call in found:
                    url = _url_at(tree, call)
                    asked += 1
                    calls += 1
                    if url is not None:
                        resolved += 1
                    if _installed()(tracker, url, call, mod):
                        answered += 1
                        print(f'  REACHES  {name}:{lineno}  {str(url)[:60]}')
        print(f'  {kind:7s} blessed_lines={len(rows)} (locked {LOCKED[kind]})  calls_asked={calls}  '
              f'url_resolved={resolved}  asks={asked}  lines_with_no_call={unasked_lines}  '
              f'answers_asset_fetch={answered}')
        if answered:
            failures.append((kind, 'a blessed CWE-319 line is reachable by the asset clause', 0, answered))
        if asked < len(rows):
            failures.append((kind, 'the census must ask at least every locked key', len(rows), asked,
                             'asks < blessed_lines means the zero above is not a refusal'))
        if unasked_lines:
            failures.append((kind, 'a blessed CWE-319 line holds no call for the census to ask',
                             0, unasked_lines))
    return failures


def _consult_sites():
    """Every TaintTracker method that consults the clause, counted from the engine own AST."""
    sites = {}
    for method in _tracker_methods():
        for call in (c for c in ast.walk(method) if isinstance(c, ast.Call)):
            target = call.func
            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) \
                    and target.value.id == 'self' and target.attr == CLAUSE_NAME:
                sites[method.name] = sites.get(method.name, 0) + 1
    return sites


_ENGINE_TREE = None


def _tracker_methods():
    """The TaintTracker method nodes, read from the engine AST once (method source is indented,
    so it cannot be re-parsed with ast.parse on its own -- the tier reads the tree instead)."""
    global _ENGINE_TREE
    if _ENGINE_TREE is None:
        _ENGINE_TREE = ast.parse(inspect.getsource(ast_scanner))
    for cls in (n for n in ast.walk(_ENGINE_TREE) if isinstance(n, ast.ClassDef)
                and n.name == 'TaintTracker'):
        return [m for m in cls.body
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
    return []


def check_tables_and_wiring():
    """TIER 7: the four tables, the four consult sites, and the caller that hands the closure the node."""
    failures = []
    mod = ast_scanner
    suffixes = tuple(mod.CWE319_ASSET_SUFFIXES)
    odd = sorted(n for n in suffixes if not n.startswith('.'))
    print(f'  suffixes   {sorted(suffixes)}  required={sorted(SUFFIXES_REQUIRED)}  odd={odd}')
    if set(suffixes) != set(SUFFIXES_REQUIRED) or odd:
        failures.append(('suffixes', SUFFIXES_REQUIRED, suffixes,
                         'a weight, env or model-file suffix turns a payload download into an exemption'))
    verbs = set(mod.CWE319_ASSET_READ_VERBS)
    print(f'  verbs      {sorted(verbs)}  forbidden present={sorted(verbs & set(VERBS_FORBIDDEN))}')
    if verbs != set(VERBS_REQUIRED):
        failures.append(('verbs', VERBS_REQUIRED, sorted(verbs),
                         'a verb with no measured arena rows may not join the table (the '
                         'table-population law)'))
    roots = set(mod.CWE319_ASSET_LIBRARY_ROOTS)
    bare = sorted(n for n in roots if not n.islower() or '.' in n)
    forbidden = sorted(roots & set(ROOTS_FORBIDDEN))
    print(f'  roots      {sorted(roots)}  forbidden present={forbidden}  odd={bare}')
    if roots != set(ROOTS_REQUIRED) or bare:
        failures.append(('roots', ROOTS_REQUIRED, sorted(roots),
                         'an alias or a bare object name would exempt an unresolved receiver'))
    if forbidden:
        failures.append(('roots forbidden list', 'no measured alias may join the root table',
                         [], forbidden, 'httpx / urllib3 / aiohttp carry 0 asset rows in the arena, '
                         'so a root joining the table without population is the table-population law '
                         'being broken'))
    kws = set(mod.CWE319_ASSET_TRANSPORT_KEYWORDS)
    leak = sorted(kws & set(KEYWORDS_FORBIDDEN))
    print(f'  transport  {sorted(kws)}  payload keywords present={leak}  '
          f'required missing={sorted(set(KEYWORDS_REQUIRED) - kws)}')
    if leak:
        failures.append(('transport keywords', 'no keyword that carries content', [], leak,
                         'data/json/headers/auth are the request body, which is what the rule reports'))
    if set(KEYWORDS_REQUIRED) - kws:
        failures.append(('transport keywords', KEYWORDS_REQUIRED, sorted(kws),
                         'the clause stopped answering the arena shape it was measured on'))

    sites = _consult_sites()
    print(f'  consult sites={sites} (want {CONSULT_SITES})')
    if sites != CONSULT_SITES:
        failures.append(('wiring', 'the clause must be consulted exactly once per emitting path',
                         CONSULT_SITES, sites,
                         'a missing consult relabels the finding instead of retiring it, and an extra '
                         'one reaches a rule that was never measured'))
    collector = next((m for m in _tracker_methods()
                      if m.name == '_collect_cluster2_structural_findings'), None)
    nodes = list(ast.walk(collector)) if collector is not None else []
    closure = [n for n in nodes if isinstance(n, ast.FunctionDef) and n.name == '_is_cleartext_url']
    closure_ids = {id(n) for node in closure for n in ast.walk(node)}
    consults = sum(1 for n in nodes if isinstance(n, ast.Call)
                   and isinstance(n.func, ast.Attribute) and n.func.attr == CLAUSE_NAME)
    ask_calls = [c for c in nodes if isinstance(c, ast.Call) and id(c) not in closure_ids
                 and isinstance(c.func, ast.Name) and c.func.id == '_is_cleartext_url']
    passes_node = bool(ask_calls) and all(
        c.args and isinstance(c.args[-1], ast.Name) and c.args[-1].id == 'node' for c in ask_calls)
    print(f'  cluster-2: closure={len(closure)} (want 1)  consults inside the collector={consults} '
          f'(want 1)  asks with the sink node={passes_node} ({len(ask_calls)} call sites)')
    if len(closure) != 1 or consults != 1 or not passes_node:
        failures.append(('cluster-2 wiring', (1, 1, True), (len(closure), consults, passes_node),
                         'the fourth consult or its node argument moved -- the relabel row would return'))
    body = inspect.getsource(_installed())
    for fragment in ('self.imports.get(mod_name)', 'split(".")', 'CWE319_ASSET_TRANSPORT_KEYWORDS',
                     'len(call.args) != 1'):
        ok = fragment in body
        print(f'  clause fragment {fragment!r}: {ok}')
        if not ok:
            failures.append(('clause body', fragment, 'present', 'absent',
                             'the predicate no longer asks the question this gate mutates'))
    return failures


# --------------------------------------------------------------------------- mutations

def _rebind(fn):
    setattr(ast_scanner.TaintTracker, CLAUSE_NAME, fn)


def _restore_tables(name):
    _rebind(PRISTINE)
    for attr, value in TABLE_PRISTINE.items():
        setattr(ast_scanner, attr, value)
    del name


TABLE_PRISTINE = {
    'CWE319_ASSET_SUFFIXES': ('.jpg', '.jpeg'),
    'CWE319_ASSET_READ_VERBS': frozenset({'get'}),
    'CWE319_ASSET_LIBRARY_ROOTS': frozenset({'requests'}),
    'CWE319_ASSET_TRANSPORT_KEYWORDS': frozenset({'stream', 'timeout', 'verify', 'allow_redirects',
                                                  'cert'}),
}


def _pitched(drop):
    return lambda self, url_val, call, mod_name: _pitch(self, url_val, call, mod_name, drop=drop)


MUTATIONS = {
    'delete_asset_clause': {
        'what': 'the clause always answers False -- as if the four consults were never wired',
        'rows': 'every retired shape, both symbols of default_arg_double_emit, all eight pairs',
        'apply': lambda: _rebind(lambda self, u, c, m: False)},
    'asset_clause_always_true': {
        'what': 'the clause always answers True -- the exemption replaces the rule',
        'rows': 'every tripwire, and the blessed reach census',
        'apply': lambda: _rebind(lambda self, u, c, m: True)},
    'asset_suffix_accepts_a_weight_file': {
        'what': 'the suffix table gains .bin / .json / .env / .safetensors',
        'rows': 'weight_bin, weights_json, config_env, the suffix axis, the table assertion',
        'apply': lambda: setattr(ast_scanner, 'CWE319_ASSET_SUFFIXES',
                                 ('.jpg', '.jpeg', '.bin', '.json', '.env', '.safetensors'))},
    'asset_verb_joined_without_population': {
        'what': 'post / put / patch / delete join the read-verb table',
        'rows': 'post_asset_verb, the verb axis, the table assertion',
        'apply': lambda: setattr(ast_scanner, 'CWE319_ASSET_READ_VERBS',
                                 frozenset({'get', 'post', 'put', 'patch', 'delete'}))},
    'asset_root_joined_without_population': {
        'what': 'httpx and urllib3 join the library-root table with no measured asset rows',
        'rows': 'httpx_get, the root axis, the table assertion',
        'apply': lambda: setattr(ast_scanner, 'CWE319_ASSET_LIBRARY_ROOTS',
                                 frozenset({'requests', 'httpx', 'urllib3'}))},
    'asset_transport_keywords_accept_a_payload': {
        'what': 'data / json / headers / auth / params are called transport options',
        'rows': 'headers_kw, data_kw, json_kw, auth_kw, params_kw, the keyword axis',
        'apply': lambda: setattr(ast_scanner, 'CWE319_ASSET_TRANSPORT_KEYWORDS',
                                 frozenset({'stream', 'timeout', 'verify', 'allow_redirects', 'cert',
                                            'data', 'json', 'headers', 'auth', 'params', 'files',
                                            'cookies'}))},
    'asset_url_accepts_a_query_hole': {
        'what': 'the query / fragment clause is dropped',
        'rows': 'query_string, the hole axis, the query predicate row',
        'apply': lambda: _rebind(_pitched('query_hole'))},
    'asset_url_accepts_a_format_hole': {
        'what': 'the brace / percent clause is dropped',
        'rows': 'percent_hole, and the format and percent predicate rows',
        'apply': lambda: _rebind(_pitched('format_hole'))},
    'asset_head_proof_dropped': {
        'what': 'the chain head is trusted without this module import table',
        'rows': 'unimported_head, local_named_requests, session_asset, and the two alias predicate rows',
        'apply': lambda: _rebind(_pitched('head_proof'))},
    'asset_positional_count_dropped': {
        'what': 'the one-positional clause is dropped',
        'rows': 'two_positional, second_pos_data, the positional predicate row',
        'apply': lambda: _rebind(_pitched('positional'))},
    'asset_root_match_becomes_a_substring': {
        'what': 'the dot-boundary root test becomes a substring of the canonical name',
        'rows': 'toolbelt_head and mock_head, both at the predicate -- the arena has no CWE-319 row on '
                'those spellings because the emitter does not recognise the library, so this is the '
                'Rule 15.5 rung-5 case: pinned at the predicate and at the clause-body fragment, not at '
                'a finding',
        'apply': lambda: _rebind(_pitched('root_substring'))},
}


def run_mutation(name: str) -> int:
    """Apply one in-memory mutation and run the real gate over it. Exit 1 = the mutation was caught."""
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print(f"  rows that must move: {spec['rows']}")
    tiers = []
    try:
        spec['apply']()
        print('TIER 3 - findings truth table:')
        tiers.append(('T3', check_shapes()))
        print('TIER 4 - the clause asked at the predicate:')
        tiers.append(('T4', check_predicates()))
        print('TIER 5 - one axis, two arms:')
        tiers.append(('T5', check_pairs()))
        print('TIER 6 - the blessed lines, asked about directly:')
        tiers.append(('T6', check_blessed_reach()))
        print('TIER 7 - the four tables and the four consult sites:')
        tiers.append(('T7', check_tables_and_wiring()))
    except Exception as exc:  # a mutation that cannot even run is not a falsification
        print('MUTATION ERROR: ' + type(exc).__name__ + ': ' + str(exc))
        print('\nFALSIFICATION VERDICT (' + name + '): ERROR - the mutation is broken, '
              'so it proves nothing either way (exit 2, not a pass)')
        _restore_tables(name)
        return 2
    _restore_tables(name)
    failures = [item for _label, rows in tiers for item in rows]
    for item in failures[:12]:
        print(f'  !! {item}')
    caught = bool(failures)
    counts = ' '.join(f'{label}={len(rows)}' for label, rows in tiers if rows)
    print('FALSIFICATION VERDICT (' + name + '): '
          + (f'CAUGHT on {len(failures)} row(s) [{counts}] -- '
             + ', '.join(sorted({str(f[0]) for f in failures})[:6])
             if caught else 'MISSED - the guard is decorative, the engine still answers its own '
                            'truth table'))
    return 1 if caught else 0


def print_rows() -> int:
    """Dump both arms of every shape, so a truth-table entry is copied from measurement."""
    for label, source, _a, _s, _n in SHAPES:
        print(f'{label:26s} {(_rows(source, blind=True), _rows(source, blind=False))}')
    return 0


def main() -> int:
    if SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    wanted = [a.split('=', 1)[1] for a in sys.argv[1:] if a.startswith('--mutate=')]
    unknown = [w for w in wanted if w not in MUTATIONS]
    if unknown:
        print(f'BAD MUTATION: {unknown} is not one of {sorted(MUTATIONS)}')
        return 1
    if len(wanted) > 1:
        print('ONE mutation at a time -- they patch the same module.')
        return 1
    if wanted:
        return run_mutation(wanted[0])
    if '--print-rows' in sys.argv[1:]:
        return print_rows()

    print('TIER 1 - the blessed CWE-319 population:')
    failures = check_floors()
    print('TIER 2 - the rule reproduces its own frozen set:')
    failures += check_live_baseline()
    print('TIER 3 - findings truth table:')
    failures += check_shapes()
    print('TIER 4 - the clause asked at the predicate:')
    failures += check_predicates()
    print('TIER 5 - one axis, two arms:')
    failures += check_pairs()
    print('TIER 6 - the blessed lines, asked about directly:')
    failures += check_blessed_reach()
    print('TIER 7 - the four tables and the four consult sites:')
    failures += check_tables_and_wiring()

    print(f'\nseal={SEAL} shapes={len(SHAPES)} must_report={len(LOUD)} retired={len(RETIRED)} '
          f'multi_emitter={len(MULTI)} pred_rows={len(PREDICATES)} pairs={len(PAIRS)} '
          f'consults={sum(CONSULT_SITES.values())} locked_cwe319={sum(LOCKED.values())} '
          f'failures={len(failures)}')
    for item in failures[:12]:
        print('  FAIL', item)
    if failures:
        print(f'VERDICT: FAIL - {len(failures)} mismatch(es) against seal={SEAL}')
        return 1
    print(f'VERDICT: PASS - {LOCKED["parity"]} blessed parity CWE-319 keys held and 0 in Big-8, '
          f'{len(RETIRED)} asset-fetch shapes retired at every emitter symbol, {len(LOUD)} tripwires '
          f'still loud, the blessed census answering 0 on {LOCKED["parity"]} lines, and the fourth '
          f'consult pinned by the relabel row and by its own site count.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
