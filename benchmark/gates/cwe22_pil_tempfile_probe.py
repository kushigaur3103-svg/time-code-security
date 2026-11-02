"""CWE-22 truth table: which delete paths the program made in a temp root, and which somebody else chose.

Why this gate exists
--------------------
The mandate asked for two AST guards: (1) silence `PIL.Image.open` CWE-22 rows unless the target has
"confirmed tainted provenance", on the premise that the blessed ground truth holds zero PIL keys and so
the guard drops zero TPs; (2) silence `shutil.rmtree` / `os.remove` / `os.unlink` when the path is built
from `tempfile`, `mkdtemp`, `tmp_dir` or "local test fixture teardown contexts".

Item 1 is REFUSED, and this file is where the refusal stays loud. Measured before any edit: the blessed
CWE-22 population is 8 parity + 16 Big-8 keys and `Image.open` appears in **none** of them, so the
mandate's invariant check is literally true -- and useless, because a rule with no blessed row gets no
protection from `MISSING=0`: re-blessing after a PIL exemption would show an empty diff. So the question
was asked of the engine instead. Over the audited LiteLLM subset the engine scans (14 files, 555,583
bytes) there is exactly **one** PIL CWE-22 row, `validators.py:39 Image.open(gif_path)`, and its target is
a *function parameter* rebound to `Path(gif_path)` -- the same class as blessed
`modeling_utils.py:336 open(checkpoint_path, "rb")`, `trainer.py:4301 open(model_card_filepath, "w")` and
`test_utils.py:5537 open(custom_generate_dir / "generate.py", "w")`. So the pitch's FP yield is 0 rows and
its cost is the one PIL row that is a true traversal: an image loader reading a file the caller named. The
fixture rows `pil_image_open_param_path` and `pil_image_open_upload_handle` are asserted LOUD at both
seals, and `pil_pitch_shipped` re-applies the pitch as a row filter and is CAUGHT deleting the first one.

Item 2 ships, but only as a positive proof, because the mandate's three named keys are three different
things. Measured clause by clause against the 24 blessed CWE-22 keys and the 117 CWE-22 rows of the
audited subset: a `tmp_dir`/**name**-match reaches 26 rows with no tempfile behind them (`temp_migrations_dir
= schema_path.parent / "migrations"`, a pytest `tmp_path`), a *teardown scope name* reaches 6, a `tests/`
**path** reaches 71 of 117 rows and 11 of the 16 blessed Big-8 CWE-22 keys -- all three are rule deletes
dressed as narrowings, since the blessed delete keys `modeling_utils.py:3494 os.remove(full_filename)` and
`trainer.py:2008 shutil.rmtree(checkpoint, ignore_errors=True)` are exactly a directory listing and a
checkpoint loop variable. What survives measurement is the one clause that can be *proved*: the path reads
back a value the `tempfile` module returned.

What the guard proves, and only that
------------------------------------
`_c22_cleanup_is_temp_teardown` (ast_scanner.py:7176) asks the callee first -- `dotted_name(node.func)`
must be in `CWE22_CLEANUP_DELETE_SINKS` (`os.remove`, `os.unlink`, `shutil.rmtree`, exactly three names),
because a path handed to `open` or `send_file` can still be read or shipped, which is a different question
from the teardown retiring. Then `_c22_path_is_proven_temp_root` (ast_scanner.py:7066) must resolve the
path expression to a `tempfile` entry point:

  * only the fully-qualified stdlib spelling counts (`tempfile.mkdtemp`, `tempfile.mkstemp`,
    `tempfile.NamedTemporaryFile`, `tempfile.TemporaryDirectory`, `tempfile.SpooledTemporaryFile`,
    `tempfile.gettempdir`) -- `from tempfile import mkdtemp` then `mkdtemp()` is refused, since a bare
    leaf could be anybody's function (`bare_import_mkdtemp`);
  * one attribute hop is part of the proof, restricted to `name`/`filename`, because a context manager or
    an open file object exposes the path there (`fh.name` of a `NamedTemporaryFile` is proven, `fh.name`
    of a plain `open("out.txt", "w")` is not -- `plain_open_handle_name`);
  * a name resolves through **every** write `_assignment_records` shows for it, so a root later pointed at
    `request.args.get(...)` fails closed (`root_rebound_to_request`) -- `drop_every_write_check` takes the
    first write only and is CAUGHT on that row;
  * inside a join, `+` or an f-string every non-literal part must prove itself, so a temp root is only a
    root and the segment a caller chose still rides inside it (`caller_segment_inside_root`,
    `name_bound_rmtree_taint_inside`);
  * a literal may never start a chain and `..` voids it (`escape_literal_in_root`, `allow_escape_literal`);
  * a subscript is a value somebody put in a container, not a root this program made
    (`subscript_of_temp_list`); a `Subscript` answer is False by branch, not by accident;
  * a path *method* needs a module-qualified or proven receiver, so `holder.join(tempfile.mkdtemp())` on a
    request-bound object stays loud (`foreign_join_receiver`, `allow_arbitrary_join_receiver`);
  * `depth > 8` caps the walk.

The rule never reads a file name, a directory name or a function name. That is the difference between this
guard and the mandate, and it is machine-checked: TIER 7 asserts no `PIL`/`Image` token appears inside
either guard method and that the sink table holds exactly the three deletes.

Measured evidence behind the numbers
------------------------------------
  blessed overlap   : 24 CWE-22 keys (8 parity + 16 Big-8), of which exactly 2 are delete sinks. TIER 6
                      rebuilds both through the record path and asks the guard with the cascade's own
                      triple: `parity asks=8 answers_temp_root=0`, `big8 asks=13 answers_temp_root=0`, and
                      the same sweep answers True on the three proven-temp controls, so the zero is a
                      refusal and not an unasked question.
  findings          : 30 fixture shapes -- 3 loud->quiet rows the guard itself earns, 11 must-report rows,
                      16 already quiet at both seals (never claimed as wins). ADDED (quiet->loud) is 0 and
                      is asserted as 0.
  predicate         : 29 shapes -- 12 proven, 17 refused, asserted at the expression the wiring would pass.
  real tree         : 19 -> 15 CWE-22 rows on the audited 14-file subset, RETIRED=4 ADDED=0; blessed delta
                      0/24. The 4 are all `Path(tempfile.mkdtemp(...))`-shaped: the constructor is what made
                      the path look dynamic to the engine, which is why the yield is small and exact.
  what a widen costs: `accept_tests_path_teardown` (a tests/-shaped module is teardown code) answers True
                      on **6 parity and 8 Big-8 blessed CWE-22 lines** -- 14 of the 24 keys -- which is the
                      arithmetic behind "the rule never reads a file name, a directory name or a function
                      name". `accept_nondelete_sink` (widen the sink table past the three deletes) reaches 3
                      more blessed lines, and `pil_pitch_shipped` deletes the one PIL row that is real.

Seal semantics - `CWE22_TEMP_SEAL`
------------------------------------
  'shipped'   : the proven-temp rows MUST be silent and every tripwire MUST stay loud.
  'abstained' : the engine before this guard landed -- every row that is not already quiet MUST be loud.
                A row that goes quiet while the seal says abstained means a narrowing landed without a
                contract. The 'abstained' column below was measured by neutering the guard on HEAD's bytes,
                not guessed.
Override with TCS_CWE22_TEMP_SEAL=abstained and point TCS_CWE22_TEMP_ENGINE at an alternative ast_scanner.py.
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

if os.environ.get('TCS_CWE22_TEMP_ENGINE'):
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        'ast_scanner', os.environ['TCS_CWE22_TEMP_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys, scan_rows  # noqa: E402

SEAL_TARGETS = ('abstained', 'shipped')
CWE22_TEMP_SEAL = os.environ.get('TCS_CWE22_TEMP_SEAL', 'shipped')

CWE22_LOCKED = {'parity': 8, 'big8': 16}
# The blessed CWE-22 lines that are delete sinks -- the only two keys this guard could ever reach.
BLESSED_DELETE_LINES = {
    'src__transformers__modeling_utils.py': 3494,
    'src__transformers__trainer.py': 2008,
}

REQ = 'from flask import request\n'
HEAD = 'import os\nimport shutil\nimport tempfile\nfrom pathlib import Path\n'

# (label, source, expect_when_abstained, expect_when_shipped)
# 'loud' = a CWE-22 finding is required in that module, 'quiet' = none is allowed.
SHAPES = [
    # ---- proven temp roots: retired by this guard, or already silent before it ----
    ('name_bound_to_path_mkdtemp', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'runtime_dir = Path(tempfile.mkdtemp(prefix="gate-"))\n'
     'shutil.rmtree(runtime_dir, ignore_errors=True)\n', 'loud', 'quiet'),
    ('name_bound_mkdtemp_no_prefix', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'runtime_dir = Path(tempfile.mkdtemp())\nshutil.rmtree(runtime_dir)\n', 'loud', 'quiet'),
    ('pathlib_div_under_mkdtemp', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'os.remove(Path(tempfile.mkdtemp()) / "sub" / "f.txt")\n', 'loud', 'quiet'),
    ('rmtree_mkdtemp_direct', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'shutil.rmtree(tempfile.mkdtemp())\n', 'quiet', 'quiet'),
    ('mkstemp_tuple_unlink', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'fd, tmp_file = tempfile.mkstemp(suffix=".json")\nos.close(fd)\nos.unlink(tmp_file)\n',
     'quiet', 'quiet'),
    ('with_temporary_dir_remove', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'with tempfile.TemporaryDirectory() as scratch:\n    os.remove(scratch)\n', 'quiet', 'quiet'),
    ('named_temp_file_name_attr', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'fh = tempfile.NamedTemporaryFile(delete=False)\nfh.write(b"x")\nfh.close()\n'
     'os.remove(fh.name)\n', 'quiet', 'quiet'),
    ('join_over_proven_root', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'root = tempfile.mkdtemp()\nos.remove(os.path.join(root, "app.json"))\n', 'quiet', 'quiet'),
    ('fstring_proven_root', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'root = tempfile.mkdtemp()\nshutil.rmtree(f"{root}/sub")\n', 'quiet', 'quiet'),
    ('gettempdir_join_literal', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'base = tempfile.gettempdir()\nos.remove(os.path.join(base, "run.log"))\n', 'quiet', 'quiet'),
    ('td_name_attribute', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'td = tempfile.TemporaryDirectory()\nshutil.rmtree(td.name)\n', 'quiet', 'quiet'),
    ('loop_variable_delete', HEAD + 'checkpoints = sorted(["a"])\nfor checkpoint in checkpoints:\n'
     '    os.remove(checkpoint)\n', 'quiet', 'quiet'),
    ('escape_literal_inside_temp_root', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'root = tempfile.mkdtemp()\nshutil.rmtree(os.path.join(root, "../etc"))\n', 'quiet', 'quiet'),
    ('subscript_of_temp_list', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'paths = [tempfile.mkdtemp()]\nos.remove(paths[0])\n', 'quiet', 'quiet'),
    ('plain_file_handle_name', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'fh = open("out.txt", "w")\nfh.write("x")\nfh.close()\nos.remove(fh.name)\n', 'quiet', 'quiet'),
    ('str_of_mkstemp_subscript', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'd = str(tempfile.mkstemp()[1])\nos.remove(d)\n', 'quiet', 'quiet'),
    # ---- a read sink is not a teardown: the callee bound keeps it out of this rule ----
    ('open_name_bound_temp_read', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'runtime_dir = Path(tempfile.mkdtemp(prefix="gate-"))\nopen(runtime_dir / "x.json")\n',
     'quiet', 'quiet'),
    ('read_sink_on_temp_path_stays_loud', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'p = os.path.join(tempfile.mkdtemp(), "x.json")\nopen(p)\n', 'quiet', 'quiet'),
    # ---- tripwires: a caller, a name, a rebind or an unproven leaf still decides something ----
    ('caller_segment_inside_temp_root', REQ + HEAD + 'root = tempfile.mkdtemp()\n'
     'shutil.rmtree(os.path.join(root, request.args["sub"]))\n', 'loud', 'loud'),
    ('name_bound_rmtree_taint_inside', REQ + HEAD + 'runtime_dir = Path(tempfile.mkdtemp())\n'
     'shutil.rmtree(os.path.join(runtime_dir, request.args["s"]))\n', 'loud', 'loud'),
    ('twice_written_root_in_join', REQ + HEAD + 'root = tempfile.mkdtemp()\n'
     'root = request.args.get("d")\nshutil.rmtree(os.path.join(root, "x.json"))\n', 'loud', 'loud'),
    ('pytest_tmp_path_param', REQ + HEAD + '\n\ndef test_teardown(tmp_path):\n'
     '    os.remove(tmp_path / "x.json")\n', 'loud', 'loud'),
    ('name_says_temp_but_is_repo_relative', REQ + HEAD + 'schema_path = Path(request.args["s"])\n'
     'temp_migrations_dir = schema_path.parent / "migrations"\nshutil.rmtree(temp_migrations_dir)\n',
     'loud', 'loud'),
    ('teardown_scope_name_cannot_decide', REQ + HEAD + '\n\ndef tearDown(target):\n'
     '    shutil.rmtree(target)\n\ntearDown(request.args.get("d"))\n', 'loud', 'loud'),
    ('function_parameter_path', REQ + HEAD + '\n\ndef cleanup(p):\n    shutil.rmtree(p)\n\n'
     'cleanup(request.args.get("d"))\n', 'loud', 'loud'),
    ('env_var_tmpdir', REQ + HEAD + 'tmp = os.environ.get("TMPDIR")\nshutil.rmtree(tmp)\n',
     'loud', 'loud'),
    ('bare_import_mkdtemp', REQ + 'from tempfile import mkdtemp\nimport os, shutil\n'
     'd = mkdtemp()\nshutil.rmtree(d)\n', 'loud', 'loud'),
    # ---- mandate item 1, asserted loud at both seals ----
    ('pil_image_open_param_path', REQ + 'from PIL import Image\n\n\ndef check(gif_path):\n'
     '    return Image.open(gif_path)\n\n\ncheck(request.args.get("p"))\n', 'loud', 'loud'),
    ('pil_image_open_upload_handle', REQ + 'from PIL import Image\n'
     'img = Image.open(request.files["f"].stream)\nprint(img)\n', 'loud', 'loud'),
    ('pil_image_open_bytesio', REQ + 'import io\nfrom PIL import Image\ndata = bytes(4)\n'
     'img = Image.open(io.BytesIO(data))\nprint(img)\n', 'quiet', 'quiet'),
]

FP_ROWS = [row for row in SHAPES if row[2] == 'loud' and row[3] == 'quiet']
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == 'loud']
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == 'quiet']
_BY_LABEL = {row[0]: row[1] for row in SHAPES}

# One axis per row, with the two arms on opposite sides of it. Every clean arm is a row the guard itself
# silences, so a pair that agrees only because both arms went quiet for some other reason cannot pass.
PAIRS = [
    ('temp root vs a segment the caller chose inside it', 'name_bound_to_path_mkdtemp',
     'name_bound_rmtree_taint_inside'),
    ('proven tempfile root vs a name that merely says temp', 'name_bound_mkdtemp_no_prefix',
     'name_says_temp_but_is_repo_relative'),
    ('tempfile module spelling vs the same function imported bare', 'pathlib_div_under_mkdtemp',
     'bare_import_mkdtemp'),
    ('proven root vs the same root rebound to a request value', 'name_bound_mkdtemp_no_prefix',
     'twice_written_root_in_join'),
    ('delete of a proven root vs delete of a parameter somebody passed in',
     'name_bound_to_path_mkdtemp', 'function_parameter_path'),
]

# The guard's own truth table, asked at the expression the wiring passes it. Rows quiet at finding level
# (an escape, a subscript, a foreign receiver) are only observable here, so they are asserted here.
# (label, sink callee, source, want)
PREDICATES = [
    ('direct_mkdtemp', 'shutil.rmtree', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'shutil.rmtree(tempfile.mkdtemp())\n', True),
    ('name_bound_to_path_mkdtemp', 'shutil.rmtree', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'runtime_dir = Path(tempfile.mkdtemp(prefix="gate-"))\nshutil.rmtree(runtime_dir)\n', True),
    ('mkstemp_tuple_unlink', 'os.unlink', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'fd, tmp_file = tempfile.mkstemp(suffix=".json")\nos.close(fd)\nos.unlink(tmp_file)\n', True),
    ('with_temporary_dir_as', 'os.remove', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'with tempfile.TemporaryDirectory() as scratch:\n    os.remove(scratch)\n', True),
    ('named_temp_file_name_attr', 'os.remove', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'fh = tempfile.NamedTemporaryFile(delete=False)\nfh.close()\nos.remove(fh.name)\n', True),
    ('join_proven_root_and_literal', 'os.remove', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'root = tempfile.mkdtemp()\nos.remove(os.path.join(root, "app.json"))\n', True),
    ('fstring_proven_root', 'shutil.rmtree', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'root = tempfile.mkdtemp()\nshutil.rmtree(f"{root}/sub")\n', True),
    ('gettempdir_join_literal', 'os.remove', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'base = tempfile.gettempdir()\nos.remove(os.path.join(base, "run.log"))\n', True),
    ('pathlib_div_under_mkdtemp', 'os.remove', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'os.remove(Path(tempfile.mkdtemp()) / "sub" / "f.txt")\n', True),
    ('temporary_dir_name_attr', 'shutil.rmtree', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'td = tempfile.TemporaryDirectory()\nshutil.rmtree(td.name)\n', True),
    ('keyword_path_slot', 'shutil.rmtree', REQ + HEAD + 'q = request.args.get("q")\nprint(q)\n'
     'root = tempfile.mkdtemp()\nshutil.rmtree(path=root)\n', True),
    ('teardown_function_scope', 'shutil.rmtree', REQ + HEAD + '\n\ndef tearDown():\n'
     '    d = tempfile.mkdtemp()\n    shutil.rmtree(d)\n', True),
    ('caller_segment_inside_root', 'shutil.rmtree', REQ + HEAD + 'root = tempfile.mkdtemp()\n'
     'shutil.rmtree(os.path.join(root, request.args["sub"]))\n', False),
    ('loop_variable', 'os.remove', HEAD + 'checkpoints = sorted(["a"])\nfor checkpoint in checkpoints:\n'
     '    os.remove(checkpoint)\n', False),
    ('pytest_tmp_path_param', 'os.remove', REQ + HEAD + '\n\ndef test_teardown(tmp_path):\n'
     '    os.remove(tmp_path / "x.json")\n', False),
    ('name_says_temp_repo_relative', 'shutil.rmtree', REQ + HEAD + 'schema_path = Path(request.args["s"])\n'
     'temp_migrations_dir = schema_path.parent / "migrations"\nshutil.rmtree(temp_migrations_dir)\n',
     False),
    ('function_parameter', 'shutil.rmtree', REQ + HEAD + '\n\ndef cleanup(p):\n    shutil.rmtree(p)\n\n'
     'cleanup(request.args.get("d"))\n', False),
    ('teardown_scope_param', 'shutil.rmtree', REQ + HEAD + '\n\ndef tearDown(target):\n'
     '    shutil.rmtree(target)\n', False),
    ('root_rebound_to_request', 'shutil.rmtree', REQ + HEAD + 'root = tempfile.mkdtemp()\n'
     'root = request.args.get("d")\nshutil.rmtree(root)\n', False),
    ('escape_literal_in_root', 'shutil.rmtree', REQ + HEAD + 'root = tempfile.mkdtemp()\n'
     'shutil.rmtree(os.path.join(root, "../etc"))\n', False),
    ('subscript_of_temp_list', 'os.remove', REQ + HEAD + 'paths = [tempfile.mkdtemp()]\n'
     'os.remove(paths[0])\n', False),
    ('env_var_tmpdir', 'shutil.rmtree', REQ + HEAD + 'tmp = os.environ.get("TMPDIR")\n'
     'shutil.rmtree(tmp)\n', False),
    ('bare_import_mkdtemp', 'shutil.rmtree', REQ + 'from tempfile import mkdtemp\nimport os, shutil\n'
     'd = mkdtemp()\nshutil.rmtree(d)\n', False),
    ('plain_open_handle_name', 'os.remove', REQ + HEAD + 'fh = open("out.txt", "w")\nfh.close()\n'
     'os.remove(fh.name)\n', False),
    ('cwd_root', 'shutil.rmtree', REQ + HEAD + 'd = os.getcwd()\nshutil.rmtree(d)\n', False),
    ('direct_request_delete', 'shutil.rmtree', REQ + HEAD + 'shutil.rmtree(request.args.get("d"))\n',
     False),
    ('foreign_join_receiver', 'os.remove', REQ + HEAD + 'holder = request.args.get("h")\n'
     'os.remove(holder.join(tempfile.mkdtemp()))\n', False),
    ('read_sink_on_temp_path', 'open', REQ + HEAD + 'open(Path(tempfile.mkdtemp()) / "x.json")\n', False),
    ('image_open_on_temp_path', 'Image.open', REQ + 'from PIL import Image\nimport tempfile\n'
     'from pathlib import Path\nImage.open(Path(tempfile.mkdtemp()) / "x.gif")\n', False),
]

PRED_PROVEN = [row for row in PREDICATES if row[3]]
PRED_REFUSED = [row for row in PREDICATES if not row[3]]

DELETE_SINKS_REQUIRED = ('os.remove', 'os.unlink', 'shutil.rmtree')
DELETE_SINKS_FORBIDDEN = ('open', 'Image.open', 'PIL.Image.open', 'os.rmdir', 'send_file',
                         'shutil.move', 'os.makedirs', 'Path.mkdir')
TEMPFILE_REQUIRED = ('tempfile.mkdtemp', 'tempfile.mkstemp', 'tempfile.NamedTemporaryFile',
                     'tempfile.TemporaryDirectory', 'tempfile.gettempdir')
TEMPFILE_FORBIDDEN = ('mkdtemp', 'gettempdir', 'NamedTemporaryFile', 'tmpdir', 'TMPDIR',
                      'tempfile.TemporaryFileWrapper', 'tempfile.mktemp')
NAME_ATTRS_REQUIRED = ('name', 'filename')
NAME_ATTRS_FORBIDDEN = ('path', 'parent', 'suffix', 'dir', 'file', 'decode')


def scan_source(source, module='m.py'):
    """One in-memory module through the real record path, as both baselines were built.

    The PIL pitch mutation is a row filter, applied here and nowhere else, because the pitch is a
    row-level rule and the shipped engine has no PIL exemption to delete.
    """
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={module: source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    found = sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-22'})
    if _PIL_PITCH_APPLIED:
        lines = source.splitlines()
        found = [row for row in found
                 if not (row[1].endswith('PIL.Image.open')
                         and 'request' not in (lines[row[0] - 1] if row[0] - 1 < len(lines) else '')
                         and 'files[' not in (lines[row[0] - 1] if row[0] - 1 < len(lines) else ''))]
    return found


_PIL_PITCH_APPLIED = False


def is_cwe22_record(meta):
    return (meta.get('cwe') == 'CWE-22'
            or meta.get('sink_type') in ('PATH_TRAVERSAL', 'FILE_ACCESS')
            or meta.get('operation') == 'FILE_ACCESS')


KEYWORDS = ('source', 'template', 's', 'filename_or_fp', 'filename', 'path_or_file',
            'path', 'code', 'line', 'url')


def path_expr_of_call(node):
    """The path expression the shipped wirings hand the guard for a delete sink."""
    if not isinstance(node, ast.Call):
        return None
    for arg in node.args:
        return arg
    for kw in node.keywords:
        if kw.arg in KEYWORDS:
            return kw.value
    return None


def delete_target_of(record):
    return path_expr_of_call(record.node)


def _ask_guard(tracker, record, expr):
    """The guard, asked with the cascade's own triple."""
    return tracker._c22_cleanup_is_temp_teardown(
        record.node, expr, record.scope_id, record.lineno)


def callee_of(node):
    if isinstance(node, ast.Call):
        return ast_scanner.dotted_name(node.func) or ''
    return ''


def enclosing_scope_id(tree, module, lineno):
    """The tracker's own scope spelling for the frame containing `lineno` (`m:function:C.tearDown`)."""
    answer = [f'{module}:global']

    def walk(node, qual):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f'{qual}.{child.name}' if qual else child.name
                low = child.lineno
                high = max([n.lineno for n in ast.walk(child) if hasattr(n, 'lineno')] or [low])
                if low <= lineno <= high:
                    answer[0] = f'{module}:function:{q}'
                walk(child, q)
            elif isinstance(child, ast.ClassDef):
                walk(child, f'{qual}.{child.name}' if qual else child.name)
            else:
                walk(child, qual)

    walk(tree, '')
    return answer[0]


def predicate_ask(source, sink, module='m.py'):
    """Ask the guard on the first call to `sink` in `source`, with the triple the wiring would pass."""
    tree = ast.parse(source)
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={module: source}, audit_all=True)
        _, _, edges = tracker.analyze()
        cli._findings_for(tracker, edges)
    for node in ast.walk(tree):
        if callee_of(node) != sink:
            continue
        expr = path_expr_of_call(node)
        if expr is None:
            continue
        return bool(tracker._c22_cleanup_is_temp_teardown(
            node, expr, enclosing_scope_id(tree, module[:-3], node.lineno), node.lineno))
    return None


# --------------------------------------------------------------------------- tiers

def check_floors():
    """TIER 1: the blessed CWE-22 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-22'}
        pil = {row for row in rows if 'Image.open' in str(row[4])}
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-22={len(keys)} (want {CWE22_LOCKED[kind]})  PIL_CWE22={len(pil)} (want 0)')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != CWE22_LOCKED[kind]:
            failures.append((kind, 'CWE-22', CWE22_LOCKED[kind], len(keys),
                             'the blessed CWE-22 population moved'))
        if pil:
            failures.append((kind, 'a blessed CWE-22 key names PIL.Image.open -- the PIL refusal must '
                             'be re-measured before any PIL rule ships', 0, len(pil)))
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
    """TIER 3: the findings truth table, asserted against the seal this file stands under."""
    failures = []
    for label, source, when_abstained, when_shipped in SHAPES:
        try:
            ast.parse(source)
        except SyntaxError as exc:
            print(f'  {label:38} UNPARSEABLE {type(exc).__name__}')
            failures.append((label, 'shape syntax', 'parses', type(exc).__name__))
            continue
        expected = when_abstained if CWE22_TEMP_SEAL == 'abstained' else when_shipped
        found = scan_source(source)
        status = 'loud' if found else 'quiet'
        note = '; '.join(f'L{n}' for n, _m in found)[:60]
        marker = 'ok' if status == expected else 'MISMATCH'
        print(f'  {label:38} want={expected:5s} got={status:5s} {marker:8s} {note}')
        if status != expected:
            failures.append((label, 'seal', expected, status,
                             'the answer moved without the seal, or the seal moved without the answer'))
    added = [row[0] for row in SHAPES if row[2] == 'quiet' and row[3] == 'loud']
    if added:
        failures.append(('ADDED', 'a quiet shape went loud -- this guard may only retire rows', added))
    return failures


def check_predicates():
    """TIER 4: the guard's own answers, at the expression each wiring hands it."""
    failures = []
    for label, sink, source, want in PREDICATES:
        got = predicate_ask(source, sink)
        marker = 'ok' if got == want else 'MISMATCH'
        print(f'  {label:34} want={want!s:5} got={str(got):5} {marker:8s} sink={sink}')
        if got is None:
            failures.append((label, 'no call to the named sink in the fixture -- the row asks nothing',
                             sink))
        elif got != want:
            failures.append((label, 'predicate answer', want, got,
                             'the guard no longer answers its own contract'))
    return failures


def check_pairs():
    """TIER 5: one axis, two arms, and both arms proven to be moved by this guard."""
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
        want_clean = CWE22_TEMP_SEAL == 'abstained'
        agree = (a == want_clean) and b
        print(f'  {label:52} clean_loud={a} (want {want_clean})  tripwire_loud={b} (want True)  '
              f'{"agree" if agree else "DISAGREE"}')
        if not agree:
            failures.append((label, 'pair provenance', (want_clean, True), (a, b)))
    return failures


def _blessed_rows(kind):
    rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
    return sorted((row for row in rows if row[2] == 'CWE-22'), key=lambda r: (str(r[0]), r[1]))


def _ask_records_on(source, module, wanted_lines, predicate):
    """Ask `predicate` on every CWE-22 record that sits on one of `wanted_lines`."""
    hits = asked = 0
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={module: source}, audit_all=True)
        tracker.analyze()
    for record in tracker.sink_records:
        if record.lineno not in wanted_lines or not is_cwe22_record(record.security_node.metadata):
            continue
        expr = delete_target_of(record)
        if expr is None:
            continue
        asked += 1
        if predicate(tracker, record, expr):
            hits += 1
    return asked, hits


def check_blessed_lines():
    """TIER 6: the 24 blessed CWE-22 lines, asked about directly. Zero answers, twice proved alive.

    A corpus re-scan shows a lost key only after the fact. This asks the one question the exemption can
    answer -- does the guard call itself True on a blessed line -- so a widening that reaches a true
    positive fails here before a baseline moves. The ask uses the cascade's own triple (the record's node,
    target expression, scope id and line), and the same sweep is required to answer True on the temp
    controls, so the zero is a refusal and not an unasked question.
    """
    failures = []
    controls = ('name_bound_to_path_mkdtemp', 'pathlib_div_under_mkdtemp', 'direct_mkdtemp')
    control_hits = 0
    for label in controls:
        row = next(r for r in PREDICATES if r[0] == label)
        if predicate_ask(row[2], row[1]):
            control_hits += 1
    if control_hits != len(controls):
        failures.append(('control', 'the sweep must answer temp-root on the 3 proven fixtures',
                         len(controls), control_hits))
    print(f'  control (proven-temp fixtures the sweep must answer True on): '
          f'{control_hits}/{len(controls)}')

    for kind in ('parity', 'big8'):
        rows = _blessed_rows(kind)
        by_file = {}
        for row in rows:
            by_file.setdefault(str(row[0]), set()).add(row[1])
        asked = answered = delete_lines_asked = 0
        for name, lines in sorted(by_file.items()):
            relative = (name if kind == 'parity' else os.path.join(
                'benchmark_gates_data', 'corpus_big8', os.path.basename(name)))
            path = os.path.abspath(os.path.join(ROOT, relative))
            if not os.path.exists(path):
                failures.append((name, 'blessed fixture file is not in the tree'))
                continue
            with open(path, encoding='utf-8', errors='replace') as handle:
                source = handle.read()
            module = os.path.basename(name)
            a, h = _ask_records_on(source, module, lines, _ask_guard)
            asked += a
            answered += h
            for row in rows:
                if str(row[0]) != name:
                    continue
                if 'os.remove' in str(row[4]) or 'shutil.rmtree' in str(row[4]):
                    delete_lines_asked += 1
                    if h:
                        print(f'  REACHABLE  {name}:{row[1]}  {str(row[4])[:40]}')
        print(f'  {kind:7s} blessed_lines={len(rows)}  predicate_asks={asked}  '
              f'answers_temp_root={answered}  delete_sink_blessed_lines={delete_lines_asked}')
        if answered:
            failures.append((kind, 'a blessed CWE-22 line is reachable by the temp guard', 0, answered))
        if asked == 0:
            failures.append((kind, 'no blessed CWE-22 record could be rebuilt to ask about', 1, 0))
        if kind == 'big8' and delete_lines_asked != len(BLESSED_DELETE_LINES):
            failures.append((kind, 'the two blessed delete keys must still be in the baseline',
                             len(BLESSED_DELETE_LINES), delete_lines_asked))
    return failures


_PRISTINE_SOURCE = {name: inspect.getsource(getattr(ast_scanner.TaintTracker, name))
                    for name in ('_c22_cleanup_is_temp_teardown',
                                 '_c22_path_is_proven_temp_root', '_c22_anchor_literal_ok')}


def _method_source(name):
    """The shipped text of one guard method, read at import.

    `inspect.getsource` cannot see a callable a mutation re-installed, so reading the live attribute would
    turn a behavioural falsification into an OSError instead of a verdict. TIER 7's text checks are about
    the file, so the import-time copy is the honest target; every behavioural tier runs against whatever
    callable is installed right now.
    """
    if name not in _PRISTINE_SOURCE:
        _PRISTINE_SOURCE[name] = inspect.getsource(getattr(ast_scanner.TaintTracker, name))
    return _PRISTINE_SOURCE[name]


def check_tables_and_wiring():
    """TIER 7: the three tables, the PIL refusal, and the exactly-three wiring sites."""
    failures = []
    mod = ast_scanner
    sinks = set(mod.CWE22_CLEANUP_DELETE_SINKS)
    absent = [n for n in DELETE_SINKS_REQUIRED if n not in sinks]
    present = [n for n in DELETE_SINKS_FORBIDDEN if n in sinks]
    print(f'  delete sinks     n={len(sinks)}  {sorted(sinks)}  absent={absent} forbidden={present}')
    if absent or present or len(sinks) != len(DELETE_SINKS_REQUIRED):
        failures.append(('delete sinks', DELETE_SINKS_REQUIRED, sorted(sinks),
                         'the guard is about exactly the three teardown deletes'))
    roots = set(mod.CWE22_TEMPFILE_ROOT_CALLS)
    absent = [n for n in TEMPFILE_REQUIRED if n not in roots]
    present = [n for n in TEMPFILE_FORBIDDEN if n in roots]
    bare = sorted(n for n in roots if '.' not in n)
    print(f'  tempfile roots   n={len(roots)}  absent={absent} forbidden={present} '
          f'bare_leaves={bare}')
    if absent or present or bare:
        failures.append(('tempfile roots', 'all fully qualified, no bare leaf',
                         sorted(roots), (absent, present, bare),
                         'a bare name could be anybody\'s function'))
    attrs = set(mod.CWE22_TEMPFILE_NAME_ATTRS)
    absent = [n for n in NAME_ATTRS_REQUIRED if n not in attrs]
    present = [n for n in NAME_ATTRS_FORBIDDEN if n in attrs]
    print(f'  name attrs         n={len(attrs)}  {sorted(attrs)}  absent={absent} forbidden={present}')
    if absent or present:
        failures.append(('name attrs', NAME_ATTRS_REQUIRED, sorted(attrs),
                         'only the path an object exposes as its name counts'))

    guard_text = _method_source('_c22_cleanup_is_temp_teardown') + \
        _method_source('_c22_path_is_proven_temp_root')
    # Identifier split, not a regex: `re.search` with a pattern built in a loop is itself a CWE-400 row,
    # and a harness that trips the product on itself shows up as a parity NEW -- measured here, fixed here.
    guard_names = set(''.join(c if (c.isalnum() or c == '_') else ' '
                              for c in guard_text).split())
    pil_names = [name for name in ('PIL', 'Image', 'image') if name in guard_names]
    print(f'  PIL names inside the guard: {pil_names} (want [])')
    if pil_names:
        failures.append(('PIL refusal', 'no PIL/Image identifier may appear in the temp guard -- '
                         'the mandate\'s item 1 was refused and a name-based PIL rule would delete '
                         'the one reported PIL traversal', [], pil_names))
    for fragment, why in (
            ('depth > 8', 'the walk must fail closed on depth'),
            ('records = _assignment_records(self.assignments_by_scope, expr.id, scope_id, lineno)',
             'a name must be resolved through every one of its writes'),
            ('if not records:', 'an unresolved name is not a proven temp root'),
            ('self._is_module_qualified(receiver) or receiver_proven',
             'a path method on somebody else\'s value is not os.path.join'),
            ('CWE22_TEMPFILE_ROOT_CALLS', 'the root must be a tempfile entry point'),
            ('allow_literal=(seg != "resolve")', 'a resolve() call must not launder a bare literal'),
    ):
        if fragment not in _method_source('_c22_path_is_proven_temp_root'):
            failures.append(('predicate body', fragment, 'present', 'absent', why))
    if 'CWE22_CLEANUP_DELETE_SINKS' not in guard_text or 'dotted_name(call_node.func)' \
            not in _method_source('_c22_cleanup_is_temp_teardown'):
        failures.append(('guard body', 'the callee test must run before any path walk',
                         'present', 'absent'))

    source = inspect.getsource(mod.TaintTracker)
    calls = len(re.findall(r'self\._c22_cleanup_is_temp_teardown\(', source))
    defs = len(re.findall(r'def _c22_cleanup_is_temp_teardown\(', source))
    tails = {
        'phase-11 collector (continue)': 'if self._c22_cleanup_is_temp_teardown(node, path_arg, '
                                         'scope_id, lineno):\n                    continue' in source,
        'phase-5 FILE_DELETE (not)': 'and not self._c22_cleanup_is_temp_teardown(node, path_expr, '
                                     'scope_id, lineno)' in source,
        'registry prune (disjunct)': 'or self._c22_cleanup_is_temp_teardown(' in source,
    }
    print(f'  wiring: calls={calls} (want 3)  defs={defs} (want 1)  sites='
          + ', '.join(f'{k}={v}' for k, v in tails.items()))
    if calls != 3 or defs != 1 or not all(tails.values()):
        failures.append(('wiring', 'exactly one def and three call sites, each in a suppressing '
                         'position (the guard can only ever remove a CWE-22 sink, never add one)',
                         (3, 1, True), (calls, defs, all(tails.values()))))
    return failures


# --------------------------------------------------------------------------- mutations

def _accept_name_word(self, call_node, path_expr, scope_id='', lineno=0):
    """Mutation: the mandate's `tmp_dir` reading -- a name that says temp is a temp root."""
    text = ast.unparse(path_expr).lower() if path_expr is not None else ''
    if 'tmp' in text or 'temp' in text:
        return True
    return _ORIG_GUARD(self, call_node, path_expr, scope_id, lineno)


def _accept_teardown_scope(self, call_node, path_expr, scope_id='', lineno=0):
    """Mutation: the mandate's "test fixture teardown context" reading -- the frame name decides."""
    low = (scope_id or '').lower()
    if any(word in low for word in ('teardown', 'cleanup', 'fixture', 'destroy', 'close')):
        return True
    return _ORIG_GUARD(self, call_node, path_expr, scope_id, lineno)


def _accept_tests_path(self, call_node, path_expr, scope_id='', lineno=0):
    """Mutation: the mandate's third reading -- a tests/-shaped module is teardown code."""
    low = (scope_id or '').lower()
    if 'test' in low:
        return True
    return _ORIG_GUARD(self, call_node, path_expr, scope_id, lineno)


def _proven_first_write_only(self, expr, scope_id='', lineno=0, depth=0, allow_literal=False):
    """Mutation: trust the first write of a name instead of all of them."""
    if isinstance(expr, ast.Name):
        records = ast_scanner._assignment_records(self.assignments_by_scope, expr.id,
                                                  scope_id, lineno)
        if records:
            return _ORIG_PROVEN(self, records[0].value_node, records[0].scope_id,
                                records[0].lineno, depth + 1)
    return _ORIG_PROVEN(self, expr, scope_id, lineno, depth, allow_literal)


def _literal_ok_ignoring_escape(self, expr, allow_literal):
    """Mutation: any string constant is a safe literal segment, `..` included."""
    return isinstance(expr, ast.Constant) and isinstance(expr.value, str) and expr.value != ''


_ORIG_GUARD = ast_scanner.TaintTracker._c22_cleanup_is_temp_teardown
_ORIG_PROVEN = ast_scanner.TaintTracker._c22_path_is_proven_temp_root
_ORIG_LITERAL = ast_scanner.TaintTracker._c22_anchor_literal_ok
_ORIG_QUALIFIED = ast_scanner.TaintTracker._is_module_qualified

MUTATIONS = {
    'delete_temp_guard': {
        'what': 'the guard always answers "not a temp teardown" -- every retired row comes back',
        'rows': [row[0] for row in FP_ROWS],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_cleanup_is_temp_teardown',
                                 lambda self, *a, **k: False),
    },
    'temp_guard_always_true': {
        'what': 'the guard answers "teardown" for every path -- the widest version of the rule the '
                'mandate asked for, and the reason every veto exists',
        'rows': ['caller_segment_inside_temp_root', 'name_says_temp_but_is_repo_relative',
                 'function_parameter_path', 'pytest_tmp_path_param', 'env_var_tmpdir',
                 'bare_import_mkdtemp', 'twice_written_root_in_join', 'name_bound_rmtree_taint_inside',
                 'teardown_scope_name_cannot_decide'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_cleanup_is_temp_teardown',
                                 lambda self, *a, **k: True),
    },
    'accept_tmp_word_without_proof': {
        'what': 'the mandate\'s own `tmp_dir` clause: match the word tmp/temp in the expression and '
                'skip the tempfile proof -- `temp_migrations_dir = schema_path.parent / "migrations"` '
                'and an `os.environ.get("TMPDIR")` root then read as temp teardowns',
        'rows': ['name_says_temp_but_is_repo_relative', 'env_var_tmpdir', 'bare_import_mkdtemp',
                 'pytest_tmp_path_param', 'subscript_of_temp_list', 'loop_variable'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_cleanup_is_temp_teardown',
                                 _accept_name_word),
    },
    'accept_scope_name_teardown': {
        'what': 'the mandate\'s "local test fixture teardown contexts" clause: the enclosing frame name '
                'buys silence, so `def tearDown(target): shutil.rmtree(target)` -- a parameter -- is a '
                'temp root',
        'rows': ['teardown_scope_param', 'function_parameter', 'pytest_tmp_path_param',
                 'teardown_scope_name_cannot_decide', 'function_parameter_path'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_cleanup_is_temp_teardown',
                                 _accept_teardown_scope),
    },
    'accept_tests_path_teardown': {
        'what': 'a tests/-shaped module is teardown code. 11 of the 16 blessed Big-8 CWE-22 keys live in '
                'a tests__ module, and the blessed `tests__generation__test_utils.py` open() rows are '
                'why no directory name may ever decide anything here',
        'rows': ['blessed reach: the 16 Big-8 CWE-22 keys'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_cleanup_is_temp_teardown',
                                 _accept_tests_path),
    },
    'drop_every_write_check': {
        'what': 'trust the first write of a name: `root = tempfile.mkdtemp()` then '
                '`root = request.args.get("d")` stays exempt, which is the rebind this guard refuses',
        'rows': ['root_rebound_to_request', 'twice_written_root_in_join', 'root_rebound_to_request'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_path_is_proven_temp_root',
                                 _proven_first_write_only),
    },
    'allow_escape_literal': {
        'what': 'any string constant is a safe literal segment -- `os.path.join(root, "../etc")` is then '
                'a proven temp root and the escape that walks out of it is silenced',
        'rows': ['escape_literal_in_root', 'escape_literal_inside_temp_root'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_anchor_literal_ok',
                                 _literal_ok_ignoring_escape),
    },
    'allow_arbitrary_join_receiver': {
        'what': 'treat any receiver as `os.path.`: `holder.join(tempfile.mkdtemp())` on a request-bound '
                'object becomes a proven root, so the module-qualification test is load-bearing',
        'rows': ['foreign_join_receiver'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_is_module_qualified',
                                 lambda self, node: True),
    },
    'accept_nondelete_sink': {
        'what': 'widen the sink table past the three deletes, so a read of a temp path is answered by a '
                'teardown proof -- the callee test is what bounds this rule to what it was asked about',
        'rows': ['read_sink_on_temp_path', 'image_open_on_temp_path'],
        'apply': lambda: setattr(ast_scanner, 'CWE22_CLEANUP_DELETE_SINKS',
                                 frozenset(set(ast_scanner.CWE22_CLEANUP_DELETE_SINKS)
                                           | {'open', 'Image.open'})),
    },
    'pil_pitch_shipped': {
        'what': 'the mandate\'s item 1 applied as a row filter over the real record path (the shipped '
                'engine has no PIL exemption to delete, which is the refusal): silence '
                '`CWE-22: PIL.Image.open` unless the sink line itself spells the request -- the pitch\'s '
                '"confirmed tainted provenance" as an AST-local test. It keeps the upload stream loud and '
                'deletes `Image.open(gif_path)`, the one PIL row that is a real traversal',
        'rows': ['pil_image_open_param_path'],
        'apply': lambda: globals().update({'_PIL_PITCH_APPLIED': True}),
    },
}


def run_mutation(name: str) -> int:
    """Apply one in-memory mutation and run the real gate over it. Exit 1 = the mutation was caught."""
    global _PIL_PITCH_APPLIED
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print(f"  rows that must move: {', '.join(spec['rows'])}")
    tiers = []
    try:
        spec['apply']()
        if name == 'pil_pitch_shipped':
            _PIL_PITCH_APPLIED = True
        print(f'TIER 3 - findings truth table under seal={CWE22_TEMP_SEAL!r}:')
        tiers.append(('T3', check_shapes()))
        print('TIER 4 - the guard\'s own predicate table:')
        tiers.append(('T4', check_predicates()))
        print('TIER 5 - one axis, two arms, both moved by this guard:')
        tiers.append(('T5', check_pairs()))
        print('TIER 6 - the 24 blessed lines, asked about directly:')
        tiers.append(('T6', check_blessed_lines()))
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
    if CWE22_TEMP_SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {CWE22_TEMP_SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-22 floors in both frozen baselines (and the PIL zero):')
    failures = check_floors()
    print('TIER 2 - the corpus behind those keys, scanned live:')
    failures += check_corpus()
    print(f'TIER 3 - findings truth table under seal={CWE22_TEMP_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4 - the guard\'s own predicate table:')
    failures += check_predicates()
    print('TIER 5 - one axis, two arms, both moved by this guard:')
    failures += check_pairs()
    print('TIER 6 - the 24 blessed lines, asked about directly:')
    failures += check_blessed_lines()
    print('TIER 7 - three tables, the PIL refusal and the wiring sites:')
    failures += check_tables_and_wiring()
    print(f'\nseal={CWE22_TEMP_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'pred_rows={len(PREDICATES)} pred_proven={len(PRED_PROVEN)} '
          f'pred_refused={len(PRED_REFUSED)} pairs={len(PAIRS)} '
          f'locked_cwe22={sum(CWE22_LOCKED.values())} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-22 temp-teardown predicate no longer matches its measured '
              'evidence. Restore the answer or update the seal with a re-measured truth table; never '
              're-bless a baseline -- the 2 blessed delete keys (`modeling_utils.py:3494`, '
              '`trainer.py:2008`) are a directory listing and a checkpoint loop variable and the guard '
              'must stay blind to both, and the PIL row stays refused.')
        return 1
    print(f'VERDICT: PASS - all {sum(CWE22_LOCKED.values())} blessed CWE-22 keys still reported, '
          f'parity corpus exact-set, {len(FP_ROWS)} proven-temp shapes silent, '
          f'{len(MUST_REPORT_ROWS)} caller/name/scope/path shapes reported, '
          f'{len(PRED_REFUSED)} predicate refusals held, {len(PAIRS)} pairs agreeing.')
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
