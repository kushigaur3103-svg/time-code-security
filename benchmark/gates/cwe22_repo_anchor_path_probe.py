"""CWE-22 truth table: which path expressions were chosen by the file that reads them, and which by
somebody else.

Why this gate exists
--------------------
On the recorded LiteLLM baseline 967 CWE-22 rows exist, and the prompt asked for them to be suppressed
"when the file path is constructed strictly from internal module anchors" -- `ast.Name(__file__)`,
`os.path.dirname(__file__)`, `Path(__file__)`, static package-resource lookups -- with zero tainted
parameters in the expression. Measured against the engine, that axis reaches 28 of the 967 rows (2.9%),
not 967: `_is_self_described` (ast_scanner.py:6848, `__file__` accepted at :6881) already accepts `__file__` through
`_SELF_DESCRIBED_NAMES` and every `os.path` spelling, and the other 939 rows have a name, a parameter,
a subscript or a call in them. The 28 are one grammar gap: the pathlib / importlib-resources spellings
of the same idea -- `Path(__file__).with_name("x.json")`, `Path(litellm.__file__).parent / "x.json"`,
`importlib.resources.files(__package__).joinpath("x.json")` -- because `Path` is not in
`_INERT_CALLEES` and no chain grammar exists. 20 of the 28 are answered by the predicate below on the
real record path (`scratch/_c22_anchored_text.py`); 2 further rows carry a synthetic `p4_source_id` and
never reach this prune at all, so they stay reported and are left alone deliberately.

What the guard proves, and only that
-----------------------------------
`_c22_path_is_internal_repo_anchor` (ast_scanner.py:6942) answers True for a chain that *starts* at a
module anchor (`__file__`, `__cached__`, `__package__`, `<imported module>.__file__`) and continues
only through literal segments and path algebra. Every branch fails closed:

  * a bare literal path is not an anchor (`Path("config/app.json")` is relative to whatever the
    process was started in), so `allow_literal` is False at the top of the chain and True inside it;
  * a name is an anchor only through *all* of its writes (`_assignment_records`), so a root rebound to
    `request.args.get(...)` later is refused -- `twice_written_root` is the row that proves it;
  * `..` as a whole segment of any literal is refused whatever the anchor says (`_C22_ESCAPE_SEGMENT`);
  * a subscript is only `parents[<int literal>]`; a `["name"]` slot is a value somebody filled in;
  * a constructor call needs every slot anchored-or-literal, and for the resource functions
    (`files`, `resource_filename`, `resource_string`, `resource_path`, `module_path`) that matters:
    `resource_filename('pkg', request.args['f'])` names a package the source chose and a *member the
    caller* chose, so it is refused -- `resource_filename_tainted_member`. The first draft accepted it
    on `any()` of the slots, and TIER 6's `resource_func_accepts_any_member` mutation re-introduces
    exactly that and is CAUGHT here;
  * a path *method* needs a module-qualified or anchored receiver, then anchored-or-literal parts,
    then at the top level one of those parts (or the receiver) to actually carry the anchor -- so
    `obj.joinpath("x.json")` on an unexplained object stays reported.

Wiring is one disjunct of one prune (`is_cwe22 and (...)`, ast_scanner.py:25913), next to the two
checks the engine already ran there, ahead of taint resolution. It can only ever remove a CWE-22 sink,
never add one: measured ADDED=0 on every fixture row and on the whole parity corpus.

Measured evidence behind the numbers
------------------------------------
  blessed overlap   : CWE-22 keys -- 8 in parity, 16 in Big-8 (TIER 1). TIER 5 rebuilds each blessed
                      line through the real record path and asks the guard: it answers anchored on 0
                      of the 24, and the same sweep answers True on the anchored control rows, so the
                      zero is a refusal and not an unasked question.
  fixtures          : 42 shapes -- 6 loud->quiet rows the guard itself earns, 24 must-report rows,
                      and 12 quiet at both seals (`pathlib_parent_div_literal`,
                      `str_anchor_plus_literal`, `abs_escape_literal`, `subscript_index_from_request`,
                      `bare_literal_relative`, `parent_chain_literal`, `ospath_dirname_literal` plus
                      the five all-literal rows `lit_join_two_literals`, `lit_path_two_slot_literals`,
                      `lit_dir_constant_join`, `lit_fstring_no_hole`, `lit_concat_literals` -- those
                      are already silent on HEAD's bytes and are listed as ALREADY_QUIET, never as
                      wins). ADDED (quiet->loud) is 0 and is asserted as 0.
  root-operand pitch: TIER 5b scores the second reading of this mandate -- "suppress when the ROOT
                      operand is `__file__`-derived or a hardcoded relative directory literal,
                      whatever the leaf holds" -- against every shape here. Item (a) is the shipped
                      guard verbatim; item (b) is disjunct 1 of the same prune (`_is_self_described`,
                      ast_scanner.py:6848), so all 12 all-literal shapes are already quiet and the
                      pitch buys them nothing. What it costs: 8 of the 11 pitch-reachable reported
                      rows go silent under `--mutate=root_operand_pitch_shipped` and the run is
                      `CAUGHT on 33 row(s) [T3=8 T4=1 T5b=16 T6=8]` with exit 1; the other 3 stay loud,
                      so the pitch does not even silence its own whole shape set. Applied to the 24
                      blessed lines the same mutation answers `pitch_reach=0` on parity and
                      `pitch_reach=0` on Big-8 -- so it silences 0 real findings and its only measured
                      effect is a false negative. A traversal lives in the leaf: `os.path.join('models', name)`
                      where `name` comes from the caller is exactly the bug CWE-22 names, and a
                      root-only test cannot see it.
  LiteLLM census    : 967 CWE-22 rows, 798 of them under a tests/-fixture-looking path -- which is
                      why the guard reads the *expression* and never the directory: a directory rule
                      would have deleted 798 rows of which the engine cannot prove a single one, and
                      6 of the 8 parity blessed keys and 11 of the 16 Big-8 ones live in exactly such
                      a path.

Seal semantics - `CWE22_ANCHOR_SEAL`
------------------------------------
  'shipped'   : the anchored rows MUST be silent and every tripwire MUST stay loud.
  'abstained' : the engine before this guard landed -- every row that is not already quiet MUST be
                loud. A row that goes quiet while the seal says abstained means a narrowing landed
                without a contract.
Override with TCS_CWE22_ANCHOR_SEAL=abstained and point TCS_CWE22_ANCHOR_ENGINE at an alternative
ast_scanner.py.
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

if os.environ.get('TCS_CWE22_ANCHOR_ENGINE'):
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        'ast_scanner', os.environ['TCS_CWE22_ANCHOR_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys, scan_rows  # noqa: E402

SEAL_TARGETS = ('abstained', 'shipped')
CWE22_ANCHOR_SEAL = os.environ.get('TCS_CWE22_ANCHOR_SEAL', 'shipped')

# The blessed CWE-22 population, counted from the frozen baselines themselves.
CWE22_LOCKED = {'parity': 8, 'big8': 16}

REQ = 'from flask import request\n'
HEAD = 'import os\nfrom pathlib import Path\nimport importlib.resources\n'

# (label, source, expect_when_abstained, expect_when_shipped)
# 'loud' = a CWE-22 finding is required in that module, 'quiet' = none is allowed.
SHAPES = [
    # ---- chains that start at the file's own anchor and carry nothing else ----
    ('pathlib_with_name', HEAD + 'open(Path(__file__).with_name("config.json"))\n',
     'loud', 'quiet'),
    ('pathlib_parent_div_literal', HEAD + 'open(Path(__file__).parent / "config.json")\n',
     'quiet', 'quiet'),
    ('resources_package_joinpath', HEAD + 'open(importlib.resources.files(__package__)'
                                         '.joinpath("data.json"))\n', 'loud', 'quiet'),
    ('read_text_on_anchored', HEAD + 'Path(__file__).with_name("c.json").read_text()\n',
     'loud', 'quiet'),
    ('module_dunder_file_parent_literal', HEAD + 'import litellm\n'
                                                'open(Path(litellm.__file__).parent / "backup.json")\n',
     'loud', 'quiet'),
    ('resources_files_dotted_literal', HEAD + 'import importlib.resources\n'
                                             'open(importlib.resources.files("pkg.sub")'
                                             '.joinpath("tok.json"))\n', 'loud', 'quiet'),
    ('resource_filename_literal_member', HEAD + 'import importlib.resources\n'
                                               'open(importlib.resources.resource_filename('
                                               '"pkg", "data/x.json"))\n', 'loud', 'quiet'),
    ('str_anchor_plus_literal', REQ + HEAD + 'name = request.args.get("f")\n'
                                            'open(str(Path(__file__).parent) + "/x.json")\n',
     'quiet', 'quiet'),
    ('parent_chain_literal', HEAD + 'open(Path(__file__).parent.parent / "shared" / "x.json")\n',
     'quiet', 'quiet'),
    ('ospath_dirname_literal', HEAD + 'open(os.path.join(os.path.dirname(__file__), "x.json"))\n',
     'quiet', 'quiet'),
    ('abs_escape_literal', REQ + 'from pathlib import Path\n'
                                'open(Path(__file__).parent / "../secret.txt")\n',
     'quiet', 'quiet'),
    ('subscript_index_from_request', REQ + 'from pathlib import Path\nidx = request.args.get("i")\n'
                                          'open(Path(__file__).parents[idx] / "x.json")\n',
     'quiet', 'quiet'),
    ('bare_literal_relative', 'from pathlib import Path\nopen(Path("config/app.json"))\n',
     'quiet', 'quiet'),
    # ---- tripwires: an attacker, a caller or the process cwd still decides something ----
    ('pathlib_parent_div_name', REQ + HEAD + 'name = request.args.get("f")\n'
                                            'open(Path(__file__).parent / name)\n', 'loud', 'loud'),
    ('pathlib_parents_index', REQ + HEAD + 'name = request.args.get("f")\n'
                                          'open(Path(__file__).parents[2] / "shared" / name)\n',
     'loud', 'loud'),
    ('module_dunder_file_parent', REQ + HEAD + 'import litellm\nname = request.args.get("f")\n'
                                              'open(Path(litellm.__file__).parent / name)\n',
     'loud', 'loud'),
    ('ospath_dirname_join', REQ + HEAD + 'name = request.args.get("f")\n'
                                        'open(os.path.join(os.path.dirname(__file__), '
                                        '"templates", name))\n', 'loud', 'loud'),
    ('fstring_anchor_root', REQ + HEAD + 'root = Path(__file__).parent\nname = request.args.get("f")\n'
                                        'open(f"{root}/{name}.json")\n', 'loud', 'loud'),
    ('concat_of_anchored_and_tainted', REQ + 'from pathlib import Path\nname = request.args.get("f")\n'
                                            'open(str(Path(__file__).parent) + name)\n', 'loud', 'loud'),
    ('starlette_path_anchored', REQ + 'from pathlib import Path\nname = request.args.get("f")\n'
                                     'p = Path(__file__).parent\nopen(p / name)\n', 'loud', 'loud'),
    ('tainted_member_of_anchored_package', REQ + 'import importlib.resources\n'
                                                 'name = request.args.get("f")\n'
                                                 'open(importlib.resources.files(__package__)'
                                                 '.joinpath(name))\n', 'loud', 'loud'),
    ('resource_filename_tainted_member', REQ + 'import importlib.resources\n'
                                               'open(importlib.resources.resource_filename('
                                               '"pkg", request.args.get("f")))\n', 'loud', 'loud'),
    ('escape_after_anchor', REQ + 'from pathlib import Path\nname = request.args.get("f")\n'
                                 'open(Path(__file__).parent / ".." / "etc" / name)\n',
     'loud', 'loud'),
    ('twice_written_root', REQ + 'from pathlib import Path\nroot = Path(__file__).parent\n'
                                'root = Path(request.args.get("d"))\nopen(root / "x.json")\n',
     'loud', 'loud'),
    ('parameter_root', REQ + 'from pathlib import Path\n\n\ndef load(root):\n'
                            '    return open(root / "x.json")\n\n'
                            'load(Path(request.args.get("d")))\n', 'loud', 'loud'),
    ('kwargs_slot', REQ + 'from pathlib import Path\n\n\ndef load(**kwargs):\n'
                         '    return open(Path(kwargs["f"]))\n', 'loud', 'loud'),
    ('method_on_foreign_object', REQ + 'from pathlib import Path\nobj = request.args.get("f")\n'
                                      'open(obj.joinpath("x.json"))\n', 'loud', 'loud'),
    ('upload_stream_handle', REQ + 'from pathlib import Path\nstream = request.files["f"].stream\n'
                                  'open(stream)\n', 'loud', 'loud'),
    ('tainted_constructor', REQ + 'from pathlib import Path\n'
                                 'open(Path(request.args.get("f")))\n', 'loud', 'loud'),
    ('tainted_join_arg', REQ + 'import os\nopen(os.path.join("templates", request.args.get("f")))\n',
     'loud', 'loud'),
    ('resolve_of_tainted', REQ + 'from pathlib import Path\n'
                                'open(Path(request.args.get("f")).resolve())\n', 'loud', 'loud'),
    ('fstring_no_anchor', REQ + 'from pathlib import Path\nname = request.args.get("f")\n'
                               'open(f"/srv/app/{name}.json")\n', 'loud', 'loud'),
    # ---- the "root operand is a hardcoded relative directory literal" pitch, spelled five ways ----
    # Every one of these is a real traversal: the root is fixed, the LEAF is the caller's, and a
    # fixed root does not constrain it. They are loud at both seals, so a rule that decides on the
    # root alone cannot land without failing this table.
    ('lit_root_join_name', REQ + 'import os\nname = request.args.get("f")\n'
                                'open(os.path.join("models", name))\n', 'loud', 'loud'),
    ('lit_root_dir_constant_name', REQ + 'import os\nASSET_DIR = "./models"\n'
                                         'name = request.args.get("f")\n'
                                         'open(os.path.join(ASSET_DIR, name))\n', 'loud', 'loud'),
    ('lit_root_div_name', REQ + 'from pathlib import Path\nname = request.args.get("f")\n'
                               'open(Path("./assets") / name)\n', 'loud', 'loud'),
    ('lit_root_plus_name', REQ + 'name = request.args.get("f")\nopen("./models/" + name)\n',
     'loud', 'loud'),
    ('lit_root_fstring_name', REQ + 'name = request.args.get("f")\nopen(f"models/{name}")\n',
     'loud', 'loud'),
    # ---- and the same pitch with no dynamic part anywhere: silent today, bought by nobody ----
    ('lit_join_two_literals', 'import os\nopen(os.path.join("models", "app.json"))\n',
     'quiet', 'quiet'),
    ('lit_path_two_slot_literals', 'from pathlib import Path\nopen(Path("models", "app.json"))\n',
     'quiet', 'quiet'),
    ('lit_dir_constant_join', 'import os\nASSET_DIR = "./models"\n'
                              'open(os.path.join(ASSET_DIR, "a.png"))\n', 'quiet', 'quiet'),
    ('lit_fstring_no_hole', 'open(f"models/app.json")\n', 'quiet', 'quiet'),
    ('lit_concat_literals', 'open("./models/" "app.json")\n', 'quiet', 'quiet'),
]

FP_ROWS = [row for row in SHAPES if row[2] == 'loud' and row[3] == 'quiet']
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == 'loud']
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == 'quiet']
_BY_LABEL = {row[0]: row[1] for row in SHAPES}

# One axis per row, with the two arms on opposite sides of it. Every clean arm is a row the guard
# itself silences (FP_ROWS: measured loud on 697a58e's bytes, quiet on these), so a pair that starts
# agreeing only because both arms went quiet for some other reason cannot pass this tier.
PAIRS = [
    ('fixed file name vs attacker-chosen file name', 'pathlib_with_name', 'pathlib_parent_div_name'),
    ('package member the source wrote vs member the caller wrote', 'resources_package_joinpath',
     'tainted_member_of_anchored_package'),
    ('resource function: package only vs package plus caller member',
     'resource_filename_literal_member', 'resource_filename_tainted_member'),
    ('anchored root vs root rebound to a request value', 'module_dunder_file_parent_literal',
     'twice_written_root'),
    ('path the file named vs path an unexplained object was handed', 'resources_files_dotted_literal',
     'method_on_foreign_object'),
]

# The literal segment table, asserted so a rename or a widen is a decision with a re-measure behind
# it and never a one-character edit.
ANCHOR_NAMES_REQUIRED = ('__file__', '__cached__', '__package__')
ANCHOR_NAMES_FORBIDDEN = ('__name__', '__doc__', 'cwd', 'getcwd', 'tmp', 'temp', 'home', 'argv',
                          'request', 'kwargs', 'path', 'root')
CONSTRUCTORS_REQUIRED = ('Path', 'files', 'resource_filename', 'PurePath')
CONSTRUCTORS_FORBIDDEN = ('open', 'normpath', 'join', 'split', 'abspath', 'relpath')
ESCAPE_SEGMENTS = ('..', '../', '/..', '..\\')

# The mandate's own vocabulary, spelled out so the tier measures the rule that was asked for and not
# a rule of this file's invention. Clause (a) is a `__file__`-derived root; clause (b) is a relative
# directory literal (bare, or a module-level name bound once to one).
PITCH_DUNDER_ROOTS = ('__file__', '__cached__', '__package__')
PITCH_REACH = ('dunder_anchor', 'module_dunder_anchor', 'relative_literal')# The six spellings the pitch names that the engine reports today -- all of them carry the caller's
# value in the leaf, which is the part a root test cannot see.
PITCH_REACHABLE_ROWS = ('tainted_join_arg', 'lit_root_join_name', 'lit_root_dir_constant_name',
                        'lit_root_div_name', 'lit_root_plus_name', 'lit_root_fstring_name')
# The same six with nothing dynamic anywhere: silent before the pitch, silent after it.
PITCH_SILENT_ROWS = ('bare_literal_relative', 'lit_join_two_literals', 'lit_path_two_slot_literals',
                     'lit_dir_constant_join', 'lit_fstring_no_hole', 'lit_concat_literals')


def scan_source(source):
    """One in-memory module through the real record path, as both baselines were built."""
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-22'})


def is_cwe22_record(meta):
    return (meta.get('cwe') == 'CWE-22'
            or meta.get('sink_type') in ('PATH_TRAVERSAL', 'FILE_ACCESS')
            or meta.get('operation') == 'FILE_ACCESS')


KEYWORDS = ('source', 'template', 's', 'filename_or_fp', 'filename', 'path_or_file',
            'path', 'code', 'line', 'url')


def target_of(record, tracker):
    """The cascade's own `target_expr` extraction, mirrored for the shapes the prune reads."""
    node = record.node
    if isinstance(node, ast.Return):
        return node.value
    if not isinstance(node, ast.Call):
        return None
    if isinstance(node.func, ast.Attribute) and (
            node.func.attr in {'read_text', 'read_bytes', 'write_text', 'write_bytes',
                               'extractall', 'extract'}
            or (node.func.attr == 'open'
                and tracker._is_path_expr(node.func.value, record.scope_id))):
        return node.func.value
    if node.args:
        idx = record.security_node.metadata.get('target_arg', 0)
        return node.args[idx] if len(node.args) > idx else node.args[0]
    for kw in node.keywords:
        if kw.arg in KEYWORDS:
            return kw.value
    return None


def check_floors():
    """TIER 1: the blessed CWE-22 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-22'}
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-22={len(keys)} (want {CWE22_LOCKED[kind]})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != CWE22_LOCKED[kind]:
            failures.append((kind, 'CWE-22', CWE22_LOCKED[kind], len(keys),
                             'the blessed CWE-22 population moved'))
    return failures


def check_corpus():
    """TIER 2: the CWE-22 keys re-produced by a real tree scan, as an exact key set."""
    failures = []
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    live = {row for row in scan_rows('parity', tree) if row[2] == 'CWE-22'}
    frozen = {row for row in load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
              if row[2] == 'CWE-22'}
    missing = sorted(frozen - live)
    extra = sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    for row in missing:
        print(f'  MISSING  {row[0]}:{row[1]} {row[4]}')
    for row in extra:
        print(f'  NEW      {row[0]}:{row[1]} {row[4]}')
    if missing:
        failures.append((len(missing), 'frozen CWE-22 keys no longer reported'))
    if extra:
        failures.append((len(extra), 'CWE-22 keys appeared that the baseline never held'))
    return failures


def check_shapes():
    """TIER 3: the truth table, asserted against the seal this file is standing under."""
    failures = []
    for label, source, when_abstained, when_shipped in SHAPES:
        try:
            ast.parse(source)
        except SyntaxError as exc:
            print(f'  {label:38} UNPARSEABLE {type(exc).__name__}')
            failures.append((label, 'shape syntax', 'parses', type(exc).__name__))
            continue
        expected = when_abstained if CWE22_ANCHOR_SEAL == 'abstained' else when_shipped
        found = scan_source(source)
        status = 'loud' if found else 'quiet'
        note = '; '.join(f'L{n}' for n, _m in found)[:60]
        marker = 'ok' if status == expected else 'MISMATCH'
        print(f'  {label:38} want={expected:5s} got={status:5s} {marker:8s} {note}')
        if status != expected:
            failures.append((label, 'seal', expected, status,
                             'the answer moved without the seal, or the seal moved without the answer'))
    return failures


def check_pairs():
    """TIER 4: one axis, two arms, and both arms proven to be moved by this guard."""
    failures = []
    fp_labels = {row[0] for row in FP_ROWS}
    loud_labels = {row[0] for row in MUST_REPORT_ROWS}
    for label, clean, dirty in PAIRS:
        if clean not in fp_labels:
            failures.append((label, 'clean arm is a loud->quiet row (the guard moves it)', clean))
        if dirty not in loud_labels:
            failures.append((label, 'tripwire arm is a must-report row', dirty))
        a = bool(scan_source(_BY_LABEL[clean]))
        b = bool(scan_source(_BY_LABEL[dirty]))
        want_clean = CWE22_ANCHOR_SEAL == 'abstained'
        agree = (a == want_clean) and b
        print(f'  {label:52} clean_loud={a} (want {want_clean})  tripwire_loud={b} (want True)  '
              f'{"agree" if agree else "DISAGREE"}')
        if not agree:
            failures.append((label, 'pair provenance', (want_clean, True), (a, b)))
    return failures


def pitch_root_operand(expr, tracker):
    """Descend to the base operand a "root derives from..." rule reads.

    Deliberately shallow and deliberately naive: this is the mandate's own wording, not the engine's
    proof. It follows the receiver of a path *method* (`Path(x).with_name("y")` is rooted at `x`),
    the first slot of a module-qualified function or a constructor (`os.path.join(root, leaf)` is
    rooted at `root`), the left side of `+` / `/` / `%`, the value of a subscript, the tail of an
    attribute chain and the opening text of an f-string, and stops at the first Name or Constant.
    """
    cur = expr
    for _ in range(12):
        if cur is None:
            return None
        if isinstance(cur, ast.Call):
            func = cur.func
            if isinstance(func, ast.Attribute) and not tracker._is_module_qualified(func.value):
                cur = func.value
            else:
                cur = cur.args[0] if cur.args else None
        elif isinstance(cur, ast.BinOp):
            cur = cur.left
        elif isinstance(cur, ast.Subscript):
            cur = cur.value
        elif isinstance(cur, ast.Attribute):
            if cur.attr in PITCH_DUNDER_ROOTS:
                return cur
            cur = cur.value
        elif isinstance(cur, ast.JoinedStr):
            cur = cur.values[0] if cur.values else None
        else:
            return cur
    return cur


def pitch_root_kind(tracker, expr, scope_id, lineno):
    root = pitch_root_operand(expr, tracker)
    if root is None:
        return 'none'
    if isinstance(root, ast.Constant):
        if not isinstance(root.value, str) or isinstance(root.value, bool):
            return 'other'
        return 'abs_literal' if root.value.replace('\\', '/').startswith('/') else 'relative_literal'
    if isinstance(root, ast.Name):
        if root.id in PITCH_DUNDER_ROOTS:
            return 'dunder_anchor'
        records = ast_scanner._assignment_records(tracker.assignments_by_scope, root.id,
                                                 scope_id, lineno)
        if len(records) == 1 and isinstance(records[0].value_node, ast.Constant) \
                and isinstance(records[0].value_node.value, str):
            return 'relative_literal'
        return 'other'
    return 'other'


PRUNE_DISJUNCTS = ('_is_self_described', '_is_upload_handle', '_c22_path_is_internal_repo_anchor',
                   '_c22_cleanup_is_temp_teardown')


def _silent_where(source):
    """For a pitch-reachable row that reports nothing, ask *why* it reports nothing.

    Neuter all four disjuncts of the `is_cwe22` prune for one scan and restore exactly whatever was
    installed beforehand, so a mutation run keeps its own patch afterwards. If the finding comes
    back, this prune is what retired it; if it stays away, no collector ever emits that sink and the
    prune never gets to speak.
    """
    tracker = ast_scanner.TaintTracker
    saved = {name: getattr(tracker, name) for name in PRUNE_DISJUNCTS}
    try:
        for name in PRUNE_DISJUNCTS:
            setattr(tracker, name, lambda self, *args, **kwargs: False)
        return scan_source(source)
    finally:
        for name, value in saved.items():
            setattr(tracker, name, value)


def check_root_operand_pitch():
    """TIER 5b: what the "root operand is `__file__` or a relative directory literal" pitch can
    actually reach, and what reaching it would cost.

    The pitch decides on the ROOT. A traversal never lives in the root -- it lives in the leaf the
    caller chose -- so this tier separates three populations and asserts each:

      * rows the pitch reaches that are reported today. Each one must be a must-report row: if a row
        the pitch reaches is loud and is *not* on the must-report list, the refusal is wrong and a
        real false positive is being left on the table;
      * rows the pitch reaches that are already silent. These are the all-literal spellings, and they
        are silent because `_is_self_described` (disjunct 1 of the same prune) answers on them today,
        which is why the pitch buys 0 findings. If one of them ever starts reporting, the pitch has a
        real yield and this tier is the thing that says so out loud;
      * the shipped predicate's own refusal: a relative literal must not root an anchored chain.

    The blessed half of the census is printed here and gathered by TIER 5, because rebuilding the 24
    frozen lines through the record path is the expensive part and doing it twice would only make
    the gate slower, not stronger.
    """
    failures = []
    loud_labels = {row[0] for row in MUST_REPORT_ROWS}
    fp_labels = {row[0] for row in FP_ROWS}
    quiet_labels = {row[0] for row in ALREADY_QUIET_ROWS}
    reached_loud = bought_by_self_described = bought_by_anchor = bought_by_other = 0
    silent_prune_retired = silent_never_a_finding = 0
    for label, source in _BY_LABEL.items():
        with contextlib.redirect_stderr(_io.StringIO()):
            tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
            _, _, edges = tracker.analyze()
            rows = cli._findings_for(tracker, edges)
        reported_lines = {row['line'] for row in rows if row['cwe'] == 'CWE-22'}
        seen = set()
        for record in tracker.sink_records:
            if not is_cwe22_record(record.security_node.metadata):
                continue
            expr = target_of(record, tracker)
            if expr is None or record.lineno in seen:
                continue
            seen.add(record.lineno)
            kind = pitch_root_kind(tracker, expr, record.scope_id, record.lineno)
            if kind not in PITCH_REACH:
                continue
            text = ast.unparse(expr)[:46]
            if record.lineno in reported_lines:
                reached_loud += 1
                marker = 'ok (must-report)' if label in loud_labels else 'UNLISTED'
                print(f'  REACHES A REPORTED ROW  {label:30} root={kind:15} {text:46} {marker}')
                if label not in loud_labels:
                    failures.append((label, 'the pitch reaches a reported row that is not a '
                                 'must-report row -- a real false positive the refusal is hiding',
                                 'loud', kind))
                continue
            self_described = tracker._is_self_described(expr, record.scope_id, record.lineno)
            anchored = tracker._c22_path_is_internal_repo_anchor(
                expr, record.scope_id, record.lineno)
            upload = tracker._is_upload_handle(expr, record.scope_id, record.lineno)
            temp = tracker._c22_cleanup_is_temp_teardown(
                record.node, expr, record.scope_id, record.lineno)
            if anchored:
                bought_by_anchor += 1
                who = 'bought by the anchor guard'
                listed = label in fp_labels or label in quiet_labels
            elif self_described:
                bought_by_self_described += 1
                who = 'bought by _is_self_described'
                listed = label in quiet_labels or label in fp_labels
            elif upload or temp:
                bought_by_other += 1
                who = 'bought by ' + ('the upload-handle test' if upload else 'the temp-teardown guard')
                listed = True
            else:
                comes_back = bool(_silent_where(source))
                if comes_back:
                    silent_prune_retired += 1
                    who = 'retired by this prune -- a disjunct answers on the cascade own expression'
                else:
                    silent_never_a_finding += 1
                    who = 'never a CWE-22 finding -- no collector emits this sink at all'
                listed = label in quiet_labels or label in fp_labels
            print(f'  reaches a silent row    {label:30} root={kind:15} {text:46} {who}')
            if not listed and label not in quiet_labels and label not in fp_labels:
                failures.append((label, 'a pitch-reachable silent row is on neither the fp, the '
                             'must-report nor the already-quiet list', 'quiet', kind))
    silent_total = (bought_by_self_described + bought_by_anchor + bought_by_other
                    + silent_prune_retired + silent_never_a_finding)
    print(f'\n  pitch reach over the shapes: reported={reached_loud}  silent={silent_total} '
          f'(self-described {bought_by_self_described}, anchor guard {bought_by_anchor}, '
          f'upload/temp {bought_by_other}, retired by this prune {silent_prune_retired}, '
          f'never emitted {silent_never_a_finding})')
    if silent_total < len(PITCH_SILENT_ROWS):
        failures.append(('pitch yield', 'the all-static spellings the pitch names must be shown '
                         'silent and accounted for', len(PITCH_SILENT_ROWS), silent_total))
    if reached_loud < len(PITCH_REACHABLE_ROWS):
        failures.append(('pitch reach', 'the pitch must be shown to reach every row the mandate '
                         'names', len(PITCH_REACHABLE_ROWS), reached_loud))
    with contextlib.redirect_stderr(_io.StringIO()):
        probe = ast_scanner.TaintTracker(files={'m.py': 'x = 1\n'}, audit_all=True)
    for text, want in [
            # the pitch's clause (b): a relative literal root. The shipped guard refuses every one of
            # these whatever the leaf is, because the leaf is where a traversal lives.
            ('os.path.join("models", name)', False),
            ('os.path.join("./assets", request.args["f"])', False),
            ('Path("./assets") / name', False),
            ('"./models/" + name', False),
            ('ASSET_DIR', False),
            ('f"models/{name}"', False),
            # and clause (a) -- which the shipped guard already grants when the rest of the chain is
            # literal too, and still refuses when a caller chose a segment.
            ('Path(__file__).parent / "cfg.json"', True),
            ('os.path.join(os.path.dirname(__file__), "cfg.json")', True),
            ('Path(__file__).parent / name', False),
            ('os.path.join(os.path.dirname(__file__), name)', False)]:
        expr = ast.parse(text, mode='eval').body
        got = probe._c22_path_is_internal_repo_anchor(expr, 'm:global', 1)
        marker = 'ok' if got == want else 'MISMATCH'
        print(f'  shipped guard on the pitch shape: {text:46} want={want!s:5} got={got!s:5} {marker}')
        if got != want:
            failures.append(('pitch shape predicate', text, want, got))
    return failures


def _blessed_rows(kind):
    rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
    return sorted((row for row in rows if row[2] == 'CWE-22'), key=lambda r: (str(r[0]), r[1]))


def check_blessed_lines():
    """TIER 5: the 24 blessed CWE-22 lines, rebuilt through the record path and asked about directly.

    A corpus re-scan shows a lost key after the fact. This asks the one question the exemption can
    answer -- does the guard call itself True on a blessed line -- so a widening that reaches a true
    positive fails here before a baseline moves. The ask uses the exact triple the cascade passes --
    the reconstructed `target_expr` of every CWE-22 record sitting on that blessed line -- so a guard
    that reaches a true positive is caught on the same expression that would silence it, and every
    blessed line is required to carry such a record (`predicate_asks` equals the blessed count).
    A control run over the anchored fixtures proves the ask answers True when it should, so the
    zero below is a refusal and not an unasked question.
    """
    failures = []
    controls = ('pathlib_with_name', 'resources_package_joinpath',
                'module_dunder_file_parent_literal')
    control_hits = sum(1 for label in controls if _ask_fixtures(_BY_LABEL[label]))
    if control_hits != len(controls):
        failures.append(('control', 'the sweep must answer anchored on the 3 anchored fixtures',
                         len(controls), control_hits))
    print(f'  control (anchored fixtures the sweep must answer True on): '
          f'{control_hits}/{len(controls)}')
    for kind in ('parity', 'big8'):
        rows = _blessed_rows(kind)
        sources = {}
        for row in rows:
            # One binding for `path`, hanging off this repository's own anchor, with literal segments
            # only -- the same shape the other probes use, because a twice-written name or a helper's
            # return value makes the harness itself a CWE-22 key when parity scans `benchmark/gates/`.
            relative = (row[0] if kind == 'parity' else os.path.join(
                'benchmark_gates_data', 'corpus_big8', os.path.basename(str(row[0]))))
            path = os.path.abspath(os.path.join(ROOT, relative))
            if not os.path.exists(path):
                failures.append((row[0], 'blessed fixture file is not in the tree'))
                continue
            with open(path, encoding='utf-8', errors='replace') as handle:
                sources[str(row[0])] = handle.read()
        asked = answered = 0
        pitch_hits = 0
        covered = set()
        for name, source in sources.items():
            with contextlib.redirect_stderr(_io.StringIO()):
                tracker = ast_scanner.TaintTracker(files={name: source}, audit_all=True)
                tracker.analyze()
            wanted = {row[1] for row in rows if str(row[0]) == name}
            for record in tracker.sink_records:
                if record.lineno not in wanted or not is_cwe22_record(record.security_node.metadata):
                    continue
                expr = target_of(record, tracker)
                if expr is None:
                    continue
                covered.add((name, record.lineno))
                asked += 1
                if tracker._c22_path_is_internal_repo_anchor(
                        expr, record.scope_id, record.lineno):
                    answered += 1
                    print(f'  REACHABLE  {name}:{record.lineno}  {ast.unparse(expr)[:70]}')
                root_kind = pitch_root_kind(tracker, expr, record.scope_id, record.lineno)
                if root_kind in PITCH_REACH:
                    pitch_hits += 1
                    print(f'  THE PITCH REACHES A BLESSED KEY  {name}:{record.lineno} '
                          f'root={root_kind}  {ast.unparse(expr)[:60]}')
        blessed_lines = len({(name, row[1]) for name in sources for row in rows
                             if str(row[0]) == name})
        print(f'  {kind:7s} blessed_lines={blessed_lines}  predicate_asks={asked}  '
              f'answers_anchor={answered}  pitch_reach={pitch_hits}  '
              f'lines_with_no_cwe22_record={blessed_lines - len(covered)}')
        if answered:
            failures.append((kind, 'a blessed CWE-22 line is reachable by the anchor guard',
                             0, answered))
        if asked == 0:
            failures.append((kind, 'no blessed CWE-22 record could be rebuilt to ask about', 1, 0))
    return failures


def _ask_fixtures(source):
    """Does the guard answer True on the real target of this fixture module's CWE-22 sink?"""
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
        _, _, edges = tracker.analyze()
        cli._findings_for(tracker, edges)
        for record in tracker.sink_records:
            if not is_cwe22_record(record.security_node.metadata):
                continue
            expr = target_of(record, tracker)
            if expr is not None and tracker._c22_path_is_internal_repo_anchor(
                    expr, record.scope_id, record.lineno):
                return True
    return False


_PRISTINE_SOURCE = {name: inspect.getsource(getattr(ast_scanner.TaintTracker, name))
                    for name in ('_c22_anchor_literal_ok', '_c22_path_is_internal_repo_anchor')}


def _method_source(name):
    """The shipped text of one predicate method, read at import.

    `inspect.getsource` cannot see a callable that a mutation re-in-memory with `exec`, so reading
    the live attribute would turn a behavioural falsification into an OSError instead of a verdict.
    TIER 6's text checks are about the file, so the import-time copy is the honest target; the truth
    table, the pairs and the blessed lines run against whatever callable is installed right now.
    """
    if name not in _PRISTINE_SOURCE:
        _PRISTINE_SOURCE[name] = inspect.getsource(getattr(ast_scanner.TaintTracker, name))
    return _PRISTINE_SOURCE[name]


def check_vocabulary():
    """TIER 6: the anchor tables, the escape rule and the single wiring site."""
    failures = []
    tracker = ast_scanner.TaintTracker
    for table, required, forbidden, label in (
            ('_C22_ANCHOR_NAMES', ANCHOR_NAMES_REQUIRED, ANCHOR_NAMES_FORBIDDEN, 'anchor names'),
            ('_C22_PATH_CONSTRUCTORS', CONSTRUCTORS_REQUIRED, CONSTRUCTORS_FORBIDDEN,
             'path constructors')):
        values = set(getattr(tracker, table))
        absent = [name for name in required if name not in values]
        present = [name for name in forbidden if name in values]
        print(f'  {label:20} n={len(values):2}  absent_required={absent}  '
              f'present_forbidden={present}')
        if absent:
            failures.append((label, 'required member missing', required, absent))
        if present:
            failures.append((label, 'forbidden member present -- it is not a path anchor',
                             forbidden, present))
    if tracker._C22_ESCAPE_SEGMENT != '..':
        failures.append(('escape segment', '..', tracker._C22_ESCAPE_SEGMENT))
    with contextlib.redirect_stderr(_io.StringIO()):
        probe = ast_scanner.TaintTracker(files={'m.py': 'x = 1\n'}, audit_all=True)
    for text, want in [('Path(__file__)', True), ('Path("app.json")', False),
                       ('os.path.dirname(__file__)', True), ('"x/../y"', False),
                       ('Path(__file__).parent / ".."', False), ('__file__', True),
                       ('files(__package__)', True), ('files(pkg, name)', False),
                       # The last line of the path-function branch: a `join`-shaped call whose
                       # receiver is module-qualified and whose slots are all literals carries no
                       # anchor at all, so it is not this proof. `drop_final_anchor_requirement`
                       # returns True here, and this row is where that is observable -- no engine
                       # finding can show it, because an all-literal path holds no taint to report.
                       ('os.path.join("templates", "app.json")', False),
                       ('Path(__file__).joinpath("app.json")', True)]:
        expr = ast.parse(text, mode='eval').body
        got = probe._c22_path_is_internal_repo_anchor(expr, '', 1)
        marker = 'ok' if got == want else 'MISMATCH'
        print(f'  {text:34} want={want!s:5} got={got!s:5} {marker}')
        if got != want:
            failures.append(('literal anchor probe', text, want, got))
    for payload in ESCAPE_SEGMENTS:
        text = f'Path(__file__).parent / {payload!r}'
        expr = ast.parse(text, mode='eval').body
        if probe._c22_path_is_internal_repo_anchor(expr, '', 1):
            failures.append(('escape payload accepted', payload))
    print(f'  escape payloads refused: {len(ESCAPE_SEGMENTS)}')
    body = _method_source('_c22_path_is_internal_repo_anchor')
    for fragment, why in (
            ('depth > 12', 'the chain walk must fail closed on depth'),
            ('allow_literal', 'a bare literal must not root a chain'),
            ('_assignment_records', 'a name must be resolved through every one of its writes'),
            ('if not all(a or l for a, l in zip(anchored_slots, literal_slots))',
             'every slot of a resource call must be anchored or literal, not just one of them'),
            ('return receiver_anchored or any(self._c22_path_is_internal_repo_anchor(',
             'a path-function call must still carry one real anchor, not only literals'),
    ):
        if fragment not in body:
            failures.append(('predicate body', fragment, 'present', 'absent', why))
    literal_body = _method_source('_c22_anchor_literal_ok')
    for fragment, why in (
            ('_C22_ESCAPE_SEGMENT', 'the escape segment must be read from the table'),
            ('not allow_literal', 'the top of a chain may not be a bare literal'),
    ):
        if fragment not in literal_body:
            failures.append(('literal slot body', fragment, 'present', 'absent', why))
    source = inspect.getsource(tracker)
    tail = source.split('Graph evaluation cascade', 1)[-1]
    calls = len(re.findall(r'self\._c22_path_is_internal_repo_anchor\(', tail))
    prune = tail.find('if is_cwe22 and (')
    call = tail.find('self._c22_path_is_internal_repo_anchor(', prune + 1) if prune >= 0 else -1
    between = tail[prune:call] if prune >= 0 and call > prune else ''
    inside_prune = (prune >= 0 and call > prune
                    and 'self._is_self_described(' in between
                    and 'self._is_upload_handle(' in between
                    and '\n            if ' not in between)
    provenance = tail.find('self.resolve_path_provenance(')
    print(f'  wiring: calls in the cascade tail={calls} (want 1)  inside the is_cwe22 prune='
          f'{inside_prune} (want True)  ahead of the CWE-22 provenance walk='
          f'{call >= 0 and call < provenance}')
    if calls != 1 or not inside_prune:
        failures.append(('wiring', 'exactly one call, as one disjunct of the is_cwe22 prune',
                         (1, True), (calls, inside_prune)))
    if inside_prune and not (0 <= call < provenance):
        failures.append(('wiring', 'the prune must run before the CWE-22 provenance walk',
                         provenance, call))
    return failures


def _call_segment(expr):
    func = expr.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ''


def _anchor_accepting_any_resource_member(self, expr, scope_id='', lineno=0, depth=0,
                                          allow_literal=False):
    """Mutation: the constructor branch with the all-slots test removed, written out as code.

    This is the first draft of the shipped branch -- one package-name literal anywhere in the call was
    enough, because the two `any()` tests were independent instead of one test over every slot pair --
    so `resource_filename('pkg', request.args['f'])` answers anchored on the strength of slot 0 alone.
    The semantics are the shipped draft's exactly: `any(anchored) or any(literal)` is the same question
    as `any(anchored or literal)` over the same list. It is written by hand rather than `exec`-ed from
    patched source because a probe that compiles a string into code is itself a CWE-95/89/79 finding in
    the tree the parity gate scans, and harness noise is fixed in the harness, never excused. The drift
    lock for the hand-written copy is TIER 6: it asserts that the shipped predicate body still carries
    the exact branch this function widens, so if that branch is renamed or removed the copy stops
    describing the engine and the gate fails instead of quietly testing a stale shape.
    """
    if isinstance(expr, ast.Call):
        seg = _call_segment(expr)
        if seg in self._C22_PATH_CONSTRUCTORS and seg not in self._C22_PATH_FUNCS:
            parts = list(expr.args) + [kw.value for kw in expr.keywords]
            if not parts:
                return False
            return any(_ORIG_ANCHOR(self, p, scope_id, lineno, depth + 1)
                       or self._c22_anchor_literal_ok(p, True) for p in parts)
    return _ORIG_ANCHOR(self, expr, scope_id, lineno, depth, allow_literal)


def _anchor_without_final_requirement(self, expr, scope_id='', lineno=0, depth=0,
                                      allow_literal=False):
    """Mutation: the shipped `return receiver_anchored or any(...)` of the path-function branch
    replaced by `return True`, written out as code for the same reason as above.

    It widens at the top of the chain, which is where the prune asks its question; nested calls
    answer with the shipped verdict, so the mutation cannot cost more than the guard it removes.
    """
    result = _ORIG_ANCHOR(self, expr, scope_id, lineno, depth, allow_literal)
    if result or allow_literal or depth or not isinstance(expr, ast.Call):
        return result
    seg = _call_segment(expr)
    parts = list(expr.args) + [kw.value for kw in expr.keywords]
    if not parts or seg not in self._C22_PATH_FUNCS:
        return result
    if not all(_ORIG_ANCHOR(self, p, scope_id, lineno, depth + 1,
                            allow_literal=(seg != 'resolve')) for p in parts):
        return result
    receiver = expr.func.value if isinstance(expr.func, ast.Attribute) else None
    if receiver is not None and not (self._is_module_qualified(receiver)
                                     or _ORIG_ANCHOR(self, receiver, scope_id, lineno, depth + 1)):
        return result
    return True


MUTATIONS = {
    'delete_anchor_guard': {
        'what': 'the guard always answers "not anchored" -- every retired anchored row comes back',
        'rows': [row[0] for row in FP_ROWS],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_path_is_internal_repo_anchor',
                                 lambda self, *args, **kwargs: False),
    },
    'anchor_guard_always_true': {
        'what': 'the guard answers "anchored" for every path -- the widest version of the rule the '
                'prompt asked for, and the reason every veto exists',
        'rows': ['pathlib_parent_div_name', 'ospath_dirname_join', 'twice_written_root',
                 'parameter_root', 'kwargs_slot', 'method_on_foreign_object',
                 'resource_filename_tainted_member', 'escape_after_anchor', 'tainted_constructor'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_path_is_internal_repo_anchor',
                                 lambda self, *args, **kwargs: True),
    },
    'blank_escape_segment': {
        'what': 'retire the `..` test -- `Path(__file__).parent / ".." / "etc" / name` becomes a '
                'safe internal path, which is the traversal this rule is supposed to report',
        'rows': ['escape_after_anchor'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_C22_ESCAPE_SEGMENT', '~!~never~!~'),
    },
    'any_name_is_anchor': {
        'what': 'let any bare name root a chain, so `root`, `kwargs` and a request-bound name all '
                'read as `__file__`',
        'rows': ['pathlib_parent_div_name', 'ospath_dirname_join', 'twice_written_root',
                 'parameter_root', 'kwargs_slot', 'starlette_path_anchored',
                 'concat_of_anchored_and_tainted'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_path_is_internal_repo_anchor',
                                 lambda self, expr, scope_id='', lineno=0, depth=0,
                                 allow_literal=False:
                                 True if isinstance(expr, (ast.Name, ast.Attribute))
                                 else _ORIG_ANCHOR(self, expr, scope_id, lineno, depth,
                                                   allow_literal)),
    },
    'literal_slot_always_ok': {
        'what': 'accept any expression in a literal slot -- `os.path.join(dirname(__file__), '
                'request.args["f"])` is then a constant path',
        'rows': ['ospath_dirname_join', 'pathlib_parent_div_name', 'fstring_anchor_root',
                 'resource_filename_tainted_member', 'tainted_member_of_anchored_package',
                 'concat_of_anchored_and_tainted', 'escape_after_anchor'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_anchor_literal_ok',
                                 lambda self, expr, allow_literal: True),
    },
    'resource_func_accepts_any_member': {
        'what': 'the first draft of the constructor branch: one package-name literal was enough, so '
                '`resource_filename("pkg", request.args["f"])` -- a member the caller chose -- went '
                'silent. The all()-over-slots test is what this mutation removes',
        'rows': ['resource_filename_tainted_member'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_path_is_internal_repo_anchor',
                                 _anchor_accepting_any_resource_member),
    },
    'drop_final_anchor_requirement': {
        'what': 'a path method whose slots are all literals is enough, even when neither the '
                'receiver nor any slot carries an anchor -- `os.path.join("templates", "x.json")` '
                'becomes internally-anchored. This one is pinned at the predicate, not through a '
                'finding: an all-literal path holds no taint, so no engine row exists to move, and '
                'the shipped refusal is the reason the proof cannot be reused on somebody else\'s '
                'directory',
        'rows': ['literal anchor probe: os.path.join("templates", "app.json")'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_path_is_internal_repo_anchor',
                                 _anchor_without_final_requirement),
    },
    'accept_anchored_receiver_past_escape': {
        'what': 'stop resolving the receiver of an anchored chain and trust the call: the '
                '`allow_literal` walk through a name is what refuses `root = request...`',
        'rows': ['twice_written_root'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_C22_ANCHOR_NAMES',
                                 frozenset(set(ast_scanner.TaintTracker._C22_ANCHOR_NAMES)
                                           | {'root', 'p', 'obj', 'stream'})),
    },
    'root_operand_pitch_shipped': {
        'what': 'the mandate as written: a path whose ROOT operand is `__file__`-derived or a '
                'relative directory literal counts as internally anchored, whatever the leaf holds. '
                'A traversal lives in the leaf, so a root test is a rule delete wearing a narrowing',
        'rows': list(PITCH_REACHABLE_ROWS),
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_path_is_internal_repo_anchor',
                                 _anchor_accepting_literal_root),
    },
}


def _anchor_accepting_literal_root(self, expr, scope_id='', lineno=0, depth=0,
                                   allow_literal=False):
    """The pitch installed in memory: decide on the root operand, ignore everything below it."""
    if depth == 0 and not allow_literal and expr is not None:
        if pitch_root_kind(self, expr, scope_id, lineno) in PITCH_REACH:
            return True
    return _ORIG_ANCHOR(self, expr, scope_id, lineno, depth, allow_literal)

_ORIG_ANCHOR = ast_scanner.TaintTracker._c22_path_is_internal_repo_anchor


def run_mutation(name: str) -> int:
    """Apply one in-memory mutation and run the real gate over it. Exit 1 = the mutation was caught."""
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print(f"  rows that must move: {', '.join(spec['rows'])}")
    tiers = []
    # TIER 1 and 2 read the frozen baselines and re-scan the whole `benchmark/` tree; an in-memory
    # patch of a guard cannot move a blessed key the corpus does not hold, and running them here
    # would make each mutation cost a full tree scan. The truth table, the pairs, the blessed lines
    # and the tables are what a guard is falsified on.
    try:
        # Applying the patch is inside the try: an anchor that no longer matches the shipped method
        # would otherwise leave a traceback whose exit code 1 reads exactly like a real falsification.
        spec['apply']()
        print(f'TIER 3 - truth table under seal={CWE22_ANCHOR_SEAL!r}:')
        tiers.append(('T3', check_shapes()))
        print('TIER 4 - one axis, two arms, both moved by this guard:')
        tiers.append(('T4', check_pairs()))
        print('TIER 5 - the 24 blessed lines, asked about directly:')
        tiers.append(('T5', check_blessed_lines()))
        print('TIER 5b - the root-operand pitch: what it reaches, what it buys, what it costs:')
        tiers.append(('T5b', check_root_operand_pitch()))
        print('TIER 6 - anchor tables, escape rule, literal probes and wiring:')
        tiers.append(('T6', check_vocabulary()))
    except Exception as exc:  # a mutation that cannot even run is not a falsification
        print('MUTATION ERROR: ' + type(exc).__name__ + ': ' + str(exc))
        print('\nFALSIFICATION VERDICT (' + name + '): ERROR - the mutation is broken, '
              'so it proves nothing either way (exit 2, not a pass)')
        return 2
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


def main() -> int:
    if CWE22_ANCHOR_SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {CWE22_ANCHOR_SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-22 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the corpus behind those keys, scanned live:')
    failures += check_corpus()
    print(f'TIER 3 - truth table under seal={CWE22_ANCHOR_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4 - one axis, two arms, both moved by this guard:')
    failures += check_pairs()
    print('TIER 5 - the 24 blessed lines, asked about directly:')
    failures += check_blessed_lines()
    print('TIER 5b - the root-operand pitch: what it reaches, what it buys, what it costs:')
    failures += check_root_operand_pitch()
    print('TIER 6 - anchor tables, escape rule, literal probes and wiring:')
    failures += check_vocabulary()
    print(f'\nseal={CWE22_ANCHOR_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'pairs={len(PAIRS)} locked_cwe22={sum(CWE22_LOCKED.values())} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-22 repo-anchor predicate no longer matches its measured '
              'evidence. Restore the answer or update the seal with a re-measured truth table; '
              'never re-bless a baseline -- 24 blessed CWE-22 keys are caller- or parameter-chosen '
              'paths and the guard must stay blind to every one of them.')
        return 1
    print(f'VERDICT: PASS - all {sum(CWE22_LOCKED.values())} blessed CWE-22 keys still reported, '
          f'parity corpus exact-set, {len(FP_ROWS)} anchored shapes silent, '
          f'{len(MUST_REPORT_ROWS)} tainted/parameter/escape shapes reported, '
          f'{len(PAIRS)} pairs agreeing.')
    return 0


if __name__ == '__main__':
    wanted = [a.split('=', 1)[1] for a in sys.argv[1:] if a.startswith('--mutate=')]
    if wanted:
        unknown = [w for w in wanted if w not in MUTATIONS]
        if unknown:
            print(f'BAD MUTATION: {unknown} is not one of {sorted(MUTATIONS)}')
            sys.exit(1)
        sys.exit(run_mutation(wanted[0]))
    sys.exit(main())
