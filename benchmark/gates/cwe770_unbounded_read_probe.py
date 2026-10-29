"""CWE-770 truth table: which no-argument `read()`/`recv()` calls the engine answers, and what a
proven-bounded receiver may cover.

Why this gate exists
--------------------
CWE-770 `UNBOUNDED_RESOURCE_ALLOCATION` is 91 of 2,128 findings on odoo/odoo@17.0 at sha
dca5cd22 (scratch/_770_601_fetch.py + _770_final.py over the 85 source files behind those rows).
The audit asked, for every row, what the receiver object actually is:

     34  `file_open(variable_path)` / not import-proven   -> a path a caller chooses, stays loud
     19  `file_open("<literal>")` as odoo's accessor      -> in-tree data file, fixed path
     12  `io.BytesIO()` / `io.StringIO()`                 -> an in-memory buffer, no I/O at all
     12  websocket client `recv()`                        -> a test client's own socket
      3  unbound receiver name                            -> cannot be proven, stays loud
      2  builtin `open()` (one literal path, one `file =`) -> the blessed shape, stays loud
      2  producer is not a call                           -> stays loud
      1  producer `= _get_image_stream_from(...)`          -> a helper's return, stays loud
      6  two producers, one bounded one not (MIXED)        -> stays loud (fail-closed)

The emitter
-----------
  ast_scanner.py:17593-17599 (collector `_collect_batch3b_structural_findings`, :17433) fires on a
  *name*,
  never on a size: `read`/`recv` with no argument and no keyword, whose receiver dotted name is in
  `("f", "file", "stream", "self.f", "s", "sock")`, or contains `stream`, or whose attribute is
  `recv`. Measured: 0 of the 91 rows carry a limit argument (a `read(4096)`/`recv(1024)` is silent
  today), and none of them is a database pagination/limit constant -- the rule cannot see size at
  all, so "internal limit constant vs unconstrained input" is not a dimension this population has.

That is the whole defect: the engine asks "what is the receiver called?", never "what is the
receiver?". `io.BytesIO().read()` allocates from bytes that already exist in RAM;
`file_open("l10n_es_edi_facturae/data/x.xml").read()` reads a path written in the same source file,
which no attacker controls.

The narrowing this gate locks
-----------------------------
One fail-closed predicate on receiver provenance the engine can already resolve. Emit unless every
binding of the receiver name is proven bounded:

  (a) buffer    every producer is `BytesIO()`/`StringIO()` with no argument and no keyword, and the
                name is import-backed (`imports['io'] == 'io'`, or `imports['BytesIO'] ==
                'io.BytesIO'`) -> `io.BytesIO(request.data)` keeps its finding, because the buffer
                is built from client data.
  (b) websocket the attribute is `recv` and every producer is `websocket_connect(...)` (import-backed
                as `odoo.tests.common.websocket_connect`) or `<websocket module>.create_connection`;
                `socket.socket()` and `socket.create_connection()` are not a websocket client and
                keep their finding.
  (c) file_open every producer's callee leaf is `file_open` -- never `open` -- with the same
                spelling-and-import backing the shipped CWE-116 ORM narrowing uses (`file_open` /
                alias with imports[name] in ('odoo.tools.file_open', 'odoo.tools.misc.file_open'),
                `tools.file_open` with imports['tools'] in ('odoo.tools', 'odoo.tools.misc'),
                `misc.file_open`, `odoo.tools.file_open`), and its first argument is an
                `ast.Constant` `str` written in that very call.

Why the literal test is not `_eval_static_constant`: that folder's cross-scope fallback answers for a
bare *parameter* name whenever one unrelated assignment elsewhere in the repo holds a single literal.
`def _read_file(cls, path, *args): file_open(path, *args)` plus an unrelated `path = "a/b.xml"` in the
same module is exactly that shape, and it is row `file_open_param_path` below -- loud on the shipped
engine, quiet on the folding one (proved with scratch/_770_loose_check.py, so re-widening this
predicate turns the gate red). The approved rule says "compile-time string literal"; the folder is a
different question, and the shield does not let a cheaper-looking proof stand in for the one asked for.

The leading segment of a proven callee must still mean the module it was imported as: a name bound
to a call on itself (`websocket = websocket.create_connection(...)`, the `websocket` library's own
tutorial spelling and row `websocket_module_recv`) keeps
`websocket.<attr>` intact and is allowed, while a name bound to anything else (`file_open = open`,
`websocket = get_evil()`, `websocket = socket.socket()`) cancels it and the read keeps its finding.
An unresolved `io.BytesIO` in a module that imports no `io` keeps its finding, because the origin is
read from `self.imports[mod]` and builtin `open` is never in it. A receiver bound twice -- once to a
buffer and once to `open(...)` -- keeps its finding: every producer must qualify. `self.f.read()` and
`self.ws.recv()` stay reported, because an attribute receiver's object is chosen by whoever
constructs the class.

Measured evidence behind the numbers
------------------------------------
  arena rows                 : 91, all through the single emitter above (91/91 reproduced by
                               scratch/_770_probe.py; the trigger is name-based, not size-based)
  eligible for exemption    : 43 = 12 (a) + 12 (b) + 19 (c) in the read-only census; the 6 MIXED rows
                               and the 34 variable or unproven `file_open` paths stay reported
  arena A/B, measured       : 91 CWE-770 keys at HEAD -> 60 with this narrowing (scratch/_770_601_ab.py,
                               alternating rounds, both arms deterministic). Removed = 12 (a) + 19 (c)
                               = 31, ADDED = 0, and no CWE other than 770/601 moved. The 12 (b) rows do
                               not fire in this arena because every one of them is
                               `websocket = self.websocket_connect(...)` -- a method on an unresolvable
                               `self`, which has no entry in `self.imports`, so the origin test cannot
                               prove it. Class (b) is still live and locked for the import-backed
                               spellings (`odoo.tests.common.websocket_connect(...)`, rows
                               `websocket_connect_recv` / `websocket_guest_var`, and
                               `websocket.create_connection(...)`, row `websocket_module_recv`);
                               widening it to `self.<method>` would need a base-class name heuristic,
                               which is a weaker proof than the import table and is not shipped here.
  blessed overlap            : 0 -- the 9 parity + 2 Big-8 CWE-770 keys are builtin `open()` (6
                               shapes, literal *and* variable path), `socket.socket()` + `recv()`,
                               `sock.makefile()`, `request.stream.read()` (2 shapes), a parameter
                               named `stream`, `self.f.read()`, `open(self.path)` under traversal
                               and unbound `*_stream` receivers. None is a buffer, a websocket
                               client or a literal `file_open`.
  refused, with evidence     : (i) "literal path means safe" for builtin `open` -- `test_v01_bad.py`
                               and `test_v06_bad.py` are blessed true positives whose paths are
                               literals, so the accessor identity, not the path, is the proof;
                               (ii) a test-file path exemption -- it deletes 8 of the 9 parity
                               CWE-770 keys (scratch/_770_601/matrix.json); (iii) `self.<attr>`
                               receivers, whose producer is outside the module (1 arena row,
                               `websocket = self.ws`, and the blessed `self.f.read()`);
                               (iv) any receiver with two producers where one is unproven;
                               (v) folding the `file_open` path through `_eval_static_constant` -- it
                               would have exempted 5 more arena rows (4 in
                               `account_edi_ubl_cii/tests/test_ubl_cii.py`, 1 in
                               `l10n_es_edi_verifactu/tests/common.py:84`, where the argument is the
                               parameter `path` of `def _read_file(cls, path, *args)`) by answering from
                               an unrelated scope's literal. The shipped rule reads only the literal
                               written in the call, and row `file_open_param_path` fails the gate if
                               that is ever widened.
  known gap                  : `file_open` imported through `odoo/tools/__init__.py` folds to
                               `odoo.misc.file_open` in the engine's import table (measured,
                               scratch/_imp_probe.py) -- one segment short of the true origin. The
                               allowlist requires the full `odoo.tools[.misc].file_open` spelling, so
                               that row stays reported. Fail-closed by construction.

Seal semantics - `CWE770_SEAL`
------------------------------
  'shipped'   : the proven-bounded shapes MUST be silent and every must-report row MUST stay loud --
                narrow AND still catching the bad input.
  'abstained' : the proven-bounded shapes MUST still be loud. If they go quiet while the seal says
                abstained, a narrowing landed without updating this contract.
Either way a mismatch is exit 1.
"""
from __future__ import annotations

import ast
import contextlib
import io
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

if os.environ.get('TCS_CWE770_ENGINE'):
    # falsification hook: load an alternative ast_scanner.py and let the gate argue against it. With
    # `CWE770_SEAL = 'shipped'` and the pre-narrowing engine, 0/N proven-bounded targets go silent
    # and the gate exits 1, so deleting the predicate from ast_scanner.py cannot pass unnoticed. The
    # module is registered under its real name because `dataclass(slots=True)` and `cli` both resolve
    # the engine through sys.modules, so an override that is not registered cannot even be imported.
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        'ast_scanner', os.environ['TCS_CWE770_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys, scan_rows  # noqa: E402

CWE770_SEAL = 'shipped'   # 'abstained' = the engine before the receiver predicate landed
SEAL_TARGETS = ('abstained', 'shipped')

# The blessed CWE-770 population, counted from the frozen baselines themselves.
CWE770_LOCKED = {'parity': 9, 'big8': 2}

IO = 'import io\n'
IO_BARE = 'from io import BytesIO\n'
WS_ODOO = 'from odoo.tests.common import websocket_connect\n'
WS_MODULE = 'import websocket\n'
SOCKET = 'import socket\n'
FLASK = 'from flask import request\n'
FO_TOOLS = 'from odoo.tools import file_open\n'
FO_MISC = 'from odoo.tools.misc import file_open\n'
FO_ALIAS = 'from odoo.tools.misc import file_open as fo\n'
FO_DOTTED = 'from odoo import tools\n'
FO_RELATIVE = 'from .misc import file_open\n'


def body(*lines: str) -> str:
    """A module holding one function whose body is `*lines` -- the shape the arena rows have."""
    return '\n\ndef handler():\n    ' + '\n    '.join(lines) + '\n'


def two(*lines: str) -> str:
    """A module-level statement sequence, for shapes the corpus files write at top level."""
    return '\n' + '\n'.join(lines) + '\n'


# (label, source, expect_when_abstained, expect_when_shipped)
# 'loud' = a CWE-770 finding is required on that module, 'quiet' = none is allowed.
SHAPES = [
    # ---- class (a): an in-memory buffer that is not built from anything ----
    ('bytesio_import_io', IO + body('f = io.BytesIO()', 'return f.read()'), 'loud', 'quiet'),
    ('stringio_import_io', IO + body('f = io.StringIO()', 'return f.read()'), 'loud', 'quiet'),
    ('bytesio_bare_import', IO_BARE + body('f = BytesIO()', 'return f.read()'), 'loud', 'quiet'),
    ('bytesio_as_context', IO + body('with io.BytesIO() as f:', '    return f.read()'),
     'loud', 'quiet'),
    ('bytesio_stream_name', IO + body('stream = io.BytesIO()', 'return stream.read()'),
     'loud', 'quiet'),
    # ---- class (b): a websocket test client's own socket ----
    ('websocket_connect_recv', WS_ODOO + body('websocket = websocket_connect(None)',
                                              'return websocket.recv()'), 'loud', 'quiet'),
    ('websocket_guest_var', WS_ODOO + body('guest_websocket = websocket_connect(None)',
                                           'return guest_websocket.recv()'), 'loud', 'quiet'),
    ('websocket_module_recv', WS_MODULE + body('websocket = websocket.create_connection'
                                               '("ws://localhost:8072")',
                                               'return websocket.recv()'), 'loud', 'quiet'),
    # ---- class (c): odoo's file accessor on a path written in the same file ----
    ('file_open_from_tools', FO_TOOLS + body('with file_open("l10n_x/data/a.xml", "rb") as f:',
                                             '    return f.read()'), 'loud', 'quiet'),
    ('file_open_from_misc', FO_MISC + body('with file_open("a/b.xml", "rb") as f:',
                                           '    return f.read()'), 'loud', 'quiet'),
    ('file_open_aliased', FO_ALIAS + body('with fo("a/b.xml", "rb") as f:', '    return f.read()'),
     'loud', 'quiet'),
    ('file_open_dotted_tools', FO_DOTTED + body('with tools.file_open("web/static/x.ico", "rb") as f:',
                                                '    return f.read()'), 'loud', 'quiet'),
    ('file_open_bound_to_var', FO_TOOLS + body('stream = file_open("a/b.xml", "rb")',
                                               'return stream.read()'), 'loud', 'quiet'),
    ('file_open_relative_import', FO_RELATIVE + body('with file_open("data/a.xml", "rb") as f:',
                                                     '    return f.read()'), 'loud', 'quiet'),
    # ---- builtin open(): a blessed true positive under EVERY spelling, literal path included ----
    ('builtin_open_literal', two('with open("huge_data.bin", "rb") as f:',
                                 '    payload = f.read()'), 'loud', 'loud'),
    ('builtin_open_var_name', two('file = open("input.dat", "r")', 'content = file.read()',
                                  'file.close()'), 'loud', 'loud'),
    ('builtin_open_rebound_file_open', FO_TOOLS + '\nfile_open = open\n'
     + body('with file_open("a/b.xml", "rb") as f:', '    return f.read()'), 'loud', 'loud'),
    ('builtin_open_after_buffer', IO + body('f = io.BytesIO()', 'f = open("a.bin", "rb")',
                                            'return f.read()'), 'loud', 'loud'),
    ('open_self_path_traversal', '\nclass FileReader:\n'
     '    def __init__(self, filename):\n        self.path = f"/var/app/uploads/{filename}"\n\n'
     '    def read(self):\n        with open(self.path) as f:\n            return f.read()\n'
     '\nfilename = input("filename: ")\nprint(FileReader(filename).read())\n', 'loud', 'loud'),
    # ---- sockets: a websocket client is not a TCP socket ----
    ('socket_socket_recv', SOCKET + two('s = socket.socket()', 's.connect(("example.com", 80))',
                                        'data = s.recv()'), 'loud', 'loud'),
    ('socket_create_connection_recv', SOCKET + body('s = socket.create_connection(("host", 80))',
                                                    'return s.recv()'), 'loud', 'loud'),
    ('sock_makefile_read', '\nimport socket\n\n\ndef receive_all(sock):\n    f = sock.makefile()\n'
     '    return f.read()\n', 'loud', 'loud'),
    # ---- streams that are handed in, not built here ----
    ('param_stream_read', two('def read_stream(stream):', '    return stream.read()'),
     'loud', 'loud'),
    ('request_stream_read', FLASK + '\n\ndef get_upload_content():\n    return request.stream.read()\n',
     'loud', 'loud'),
    ('request_stream_via_var', FLASK + '\n\ndef receive_stream():\n    stream = request.stream\n'
     '    payload = stream.read()\n    return payload\n', 'loud', 'loud'),
    ('upload_file_stream', FLASK + '\n\ndef h():\n'
     '    stream = request.httprequest.files.getlist("ufile")[0]\n    return stream.read()\n',
     'loud', 'loud'),
    ('self_f_read', '\nclass StreamReader:\n    def __init__(self, f):\n        self.f = f\n\n'
     '    def ingest(self):\n        data = self.f.read()\n        return len(data)\n',
     'loud', 'loud'),
    ('self_ws_recv', '\nclass Bus:\n    def h(self):\n        return self.ws.recv()\n',
     'loud', 'loud'),
    ('unbound_stream_read', '\ndef h():\n    return binary_stream.read()\n', 'loud', 'loud'),
    # ---- the bad inputs inside each exempt class, which must stay reported ----
    ('bytesio_from_client_data', IO + FLASK + body('f = io.BytesIO(request.data)',
                                                   'return f.read()'), 'loud', 'loud'),
    ('file_open_variable_path', FO_TOOLS + '\n\ndef handler(user_path):\n'
     '    with file_open(user_path, "rb") as f:\n        return f.read()\n', 'loud', 'loud'),
    # The fold-shaped false positive this row exists to catch: `_eval_static_constant` would answer
    # `"a/b.xml"` for the parameter `path`, because one unrelated scope in the same module assigns
    # that literal to a name called `path`. The shipped predicate reads the call itself, so the row
    # stays reported; re-widening it turns this row quiet while the seal says 'shipped' and the gate
    # exits 1. scratch/_770_loose_check.py measures both answers on this exact source.
    ('file_open_param_path', FO_TOOLS + '\n\ndef _read_file(cls, path, *args):\n'
     '    with file_open(path, *args) as f:\n        return f.read()\n\n\n'
     'def unrelated():\n    path = "a/b.xml"\n    return path\n', 'loud', 'loud'),
    ('file_open_no_import', body('with file_open("a/b.xml", "rb") as f:', '    return f.read()'),
     'loud', 'loud'),
    ('websocket_no_import', body('websocket = websocket_connect(None)', 'return websocket.recv()'),
     'loud', 'loud'),
    ('websocket_rebound_socket', WS_ODOO + SOCKET
     + body('websocket = websocket_connect(None)', 'websocket = socket.socket()',
            'return websocket.recv()'), 'loud', 'loud'),
    # The module name itself shadowed by something that is not a call on it: `websocket` no longer
    # means the `websocket` module, so `websocket.create_connection(...)` proves nothing. Deleting
    # that check from `_c770_callee_origin` turns this row quiet and fails the gate.
    ('websocket_root_shadowed', WS_MODULE + '\n\ndef get_evil():\n    return websocket\n'
     + body('websocket = get_evil()', 'conn = websocket.create_connection("ws://x")',
            'return conn.recv()'), 'loud', 'loud'),
    # ---- already silent, and required to stay silent at both seals ----
    ('read_with_size', '\ndef h(f):\n    return f.read(4096)\n', 'quiet', 'quiet'),
    ('recv_with_size', SOCKET + '\n\ndef h(s):\n    return s.recv(1024)\n', 'quiet', 'quiet'),
    ('read_kwarg', '\ndef h(f):\n    return f.read(size=-1)\n', 'quiet', 'quiet'),
    ('readline_not_read', FO_TOOLS + body('with file_open("a/b.xml", "rb") as f:',
                                          '    return f.readline()'), 'quiet', 'quiet'),
]

FP_ROWS = [row for row in SHAPES if row[2] == 'loud' and row[3] == 'quiet']
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == 'loud']
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == 'quiet']

# The same call text with and without the import that proves what the producer is. The proven arm
# must go quiet under the shipped seal; the stripped arm must stay loud, or the narrowing keyed on
# the callee spelling instead of the binding.
PAIRS = [
    ('io buffer', IO + body('f = io.BytesIO()', 'return f.read()'),
     body('f = io.BytesIO()', 'return f.read()')),
    ('file_open bare', FO_TOOLS + body('with file_open("a/b.xml", "rb") as f:', '    return f.read()'),
     body('with file_open("a/b.xml", "rb") as f:', '    return f.read()')),
    ('file_open dotted', FO_DOTTED
     + body('with tools.file_open("web/x.ico", "rb") as f:', '    return f.read()'),
     body('with tools.file_open("web/x.ico", "rb") as f:', '    return f.read()')),
    ('websocket_connect', WS_ODOO + body('websocket = websocket_connect(None)',
                                         'return websocket.recv()'),
     body('websocket = websocket_connect(None)', 'return websocket.recv()')),
]

# The package-relative spelling resolves only when the module name carries its package, so it is
# scanned at its arena path instead of m.py (the CWE-116 gate's TIER-2 lesson, applied to a shape).
RELATIVE_SHAPE = ('file_open_relative_import',
                  FO_RELATIVE + body('with file_open("data/a.xml", "rb") as f:',
                                     '    return f.read()'),
                  'odoo/tools/convert.py')


def scan_source(source, path='m.py'):
    """One in-memory module through the real record path, as both baselines were built."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={path: source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-770'})


def check_floors():
    """TIER 1: the blessed CWE-770 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-770'}
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-770={len(keys)} (want {CWE770_LOCKED[kind]})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != CWE770_LOCKED[kind]:
            failures.append((kind, 'CWE-770', CWE770_LOCKED[kind], len(keys),
                             'the blessed CWE-770 population moved'))
    return failures


def check_corpus():
    """TIER 2: the CWE-770 keys re-produced by a real tree scan, as an exact key set.

    In-memory single-module scanning is not how the baselines were made: the odoo spelling needs its
    package, and the corpus files need their whole tree. The only honest comparison is the same
    whole-tree scan `aa_parity` uses, filtered to CWE-770.
    """
    failures = []
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    live = {row for row in scan_rows('parity', tree) if row[2] == 'CWE-770'}
    frozen = {row for row in load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
              if row[2] == 'CWE-770'}
    missing = sorted(frozen - live)
    extra = sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    for row in extra:
        print(f'  NEW      {row[0]}:{row[1]} {row[4]}')
    for row in missing:
        print(f'  MISSING  {row[0]}:{row[1]} {row[4]}')
    if missing:
        failures.append((len(missing), 'frozen CWE-770 keys no longer reported'))
    if extra:
        failures.append((len(extra), 'CWE-770 keys appeared that the baseline never held'))
    return failures


def check_shapes():
    """TIER 3: the truth table, asserted against the seal the file is standing under.

    Every shape is parsed first: an unparseable module yields no findings, which would read as
    "quiet" and let a broken builder fake a PASS on the shipped seal.
    """
    failures = []
    for label, source, when_abstained, when_shipped in SHAPES:
        try:
            ast.parse(source)
        except SyntaxError as exc:
            print(f'  {label:32s} UNPARSEABLE {exc}')
            failures.append((label, 'shape syntax', 'parses', str(exc)))
            continue
        path = RELATIVE_SHAPE[2] if label == RELATIVE_SHAPE[0] else 'm.py'
        expected = when_abstained if CWE770_SEAL == 'abstained' else when_shipped
        found = scan_source(source, path)
        status = 'loud' if found else 'quiet'
        note = '; '.join(f'L{n}:{m.replace("CWE-770: ", "")}' for n, m in found)[:60]
        marker = 'ok' if status == expected else 'MISMATCH'
        print(f'  {label:32s} want={expected:5s} got={status:5s} {marker:8s} {note}')
        if status != expected:
            failures.append((label, 'seal', expected, status,
                             'the answer moved without the seal, or the seal moved without the answer'))
    return failures


def check_pairs():
    """TIER 4: the same call text with and without the import that proves what it is.

    A narrowing that keyed on the callee spelling would answer both arms alike -- and would exempt
    `io.BytesIO()` in a module that never imports io, or a local `file_open` that is builtin open.
    The stripped arm must stay loud at both seals; the proven arm follows the seal.
    """
    failures = []
    for label, proven, stripped in PAIRS:
        a = bool(scan_source(proven))
        b = bool(scan_source(stripped))
        want_proven = CWE770_SEAL == 'abstained'
        agree = (a == want_proven) and b
        print(f'  {label:22s} proven_loud={a} (want {want_proven})  stripped_loud={b} '
              f'(want True)  {"agree" if agree else "DISAGREE"}')
        if not agree:
            failures.append((label, 'provenance arm', (want_proven, True), (a, b)))
    return failures


def main() -> int:
    if CWE770_SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {CWE770_SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-770 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the corpus behind those keys, scanned live:')
    failures += check_corpus()
    print(f'TIER 3 - truth table under seal={CWE770_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4 - proven vs stripped provenance, same call text:')
    failures += check_pairs()
    print(f'\nseal={CWE770_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'pairs={len(PAIRS)} locked_cwe770={sum(CWE770_LOCKED.values())} '
          f'failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-770 receiver predicate no longer matches its measured '
              'evidence. Restore the answer or update the seal with a re-measured truth table; '
              'never re-bless a baseline.')
        return 1
    print(f'VERDICT: PASS - all {sum(CWE770_LOCKED.values())} blessed CWE-770 keys still reported '
          f'(0 lost), corpus exact-set, '
          f'{len(FP_ROWS)} proven-bounded shapes silent, {len(MUST_REPORT_ROWS)} open/socket/stream/'
          f'unproven shapes reported, {len(ALREADY_QUIET_ROWS)} sized reads silent, '
          f'all provenance pairs agreeing.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
