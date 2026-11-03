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
`_c22_cleanup_is_temp_teardown` (ast_scanner.py:7237) asks the callee first -- `dotted_name(node.func)`
must be in `CWE22_CLEANUP_DELETE_SINKS` (`os.remove`, `os.unlink`, `shutil.rmtree`, exactly three names),
because a path handed to `open` or `send_file` can still be read or shipped, which is a different question
from the teardown retiring. Then `_c22_path_is_proven_temp_root` (ast_scanner.py:7114) must resolve the
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

A second mandate came back to the same two names with a new shape -- "silence `PIL.Image.open` unless the
argument traces to an external tainted HTTP source" (this file's item 1, verbatim) and "silence `shutil.move`
/ `os.makedirs` when the target destination resolves within a newly created temporary or target model
template directory". The first is already refused and re-locked here, unchanged. The second was measured
against the shipped collector before it was trusted, and it is a rule rewrite, not a narrowing: the collector
audits `path_arg = node.args[0]` -- the **source** of a move -- and never reads `node.args[1]`, while
`os.makedirs` and `mkdir` do not appear in the CWE-22 collector at all (0 rows at either seal). So a
destination test can only ever silence a caller-chosen source: the two fixtures
`move_source_chosen_by_caller_to_temp_dest` and `move_source_param_to_template_dir` are exactly the pitch's
own shape, both asserted LOUD at both seals, and `move_dest_pitch_shipped` -- the pitch applied as a row
filter, since there is no destination exemption in the engine to delete -- is CAUGHT deleting those two.
TIER 7 reads the three shape facts off the shipped collector text so a destination exemption cannot land
without failing this gate: `shutil.move` appears exactly once (the sink table), the first-slot fragment is
present, and `node.args[1]` is never read.

Measured evidence behind the numbers
------------------------------------
  blessed overlap   : 24 CWE-22 keys (8 parity + 16 Big-8), of which exactly 2 are delete sinks. TIER 6
                      rebuilds both through the record path and asks the guard with the cascade's own
                      triple: `parity asks=8 answers_temp_root=0`, `big8 asks=13 answers_temp_root=0`, and
                      the same sweep answers True on the three proven-temp controls, so the zero is a
                      refusal and not an unasked question.
  findings          : 34 fixture shapes -- 3 loud->quiet rows the guard itself earns, 13 must-report rows
                      (the last two are the move pitch's own shapes), 18 already quiet at both seals (never
                      claimed as wins; two of them are the proof that a move destination is never inspected
                      and that `os.makedirs` is not a path sink). ADDED (quiet->loud) is 0 and is asserted
                      as 0.
  predicate         : 29 shapes -- 12 proven, 17 refused, asserted at the expression the wiring would pass.
  real tree         : 19 -> 15 CWE-22 rows on the audited 14-file subset, RETIRED=4 ADDED=0; blessed delta
                      0/24. The 4 are all `Path(tempfile.mkdtemp(...))`-shaped: the constructor is what made
                      the path look dynamic to the engine, which is why the yield is small and exact.
  what a widen costs: `accept_tests_path_teardown` (a tests/-shaped module is teardown code) answers True
                      on **6 parity and 8 Big-8 blessed CWE-22 lines** -- 14 of the 24 keys -- which is the
                      arithmetic behind "the rule never reads a file name, a directory name or a function
                      name". `accept_nondelete_sink` (widen the sink table past the three deletes) reaches 3
                      more blessed lines, and `pil_pitch_shipped` deletes the one PIL row that is real.
                      `move_dest_pitch_shipped` deletes 2 must-report rows and buys 0: the destination it
                      tests is not the argument the rule reads, and the `os.makedirs` half of that pitch
                      has no population to quiet.

The HTTP response body stream: a stream object is not a path
-------------------------------------------------------------
A third shape reached this rule from the arena census rather than from a mandate: 117 kept CWE-22 rows are
`Image.open(requests.get(url, stream=True).raw)`-shaped. The argument is the urllib3 body stream the server
filled; nothing in it names a file, so the traversal sink the *callee name* suggests has no path to
traverse. That is the same reasoning `io.BytesIO` already gets -- `_is_in_memory_buffer_path`
(ast_scanner.py:7433) exempts a buffer construction in the path slot -- so the clause ships **inside that
one shared predicate** (ast_scanner.py:7440), not as a fourth CWE-22 exemption: all three CWE-22 consult
sites inherit one answer, and TIER 7 proves by walking the collector ASTs that no other rule consults it.

Two tables keep it a positive proof, and both are narrower than the shape that pays:
  * the attribute must be the stream slot itself -- `_HTTP_STREAM_ATTRS = {"raw"}` -- so `.text` and
    `.content`, which a path-named sink really can be handed *as a filename*, stay loud
    (`stream_text_attr_is_not_a_stream`, `stream_content_attr_is_not_a_stream`);
  * the receiver must be a **call** whose head resolves through this module's import table to
    `_HTTP_STREAM_ROOTS = {"requests"}` -- so `resp.raw` after `resp = requests.get(url)` is refused
    (a name is not the library: `assignments_by_scope` would have to be trusted for the value, and the
    arena has 0 rows of that shape -- `stream_name_bound_response_is_not_proven`), a `requests` object the
    module made itself is refused (`stream_local_object_named_requests`), an unimported `requests` is
    refused (`stream_unimported_requests_name`), and `urllib3`/`httpx`/`torch` are refused because a table
    entry needs rows behind it (`stream_httpx_root_is_not_requests`, `stream_urllib3_root_is_not_requests`,
    `stream_requests_mock_is_not_requests`), and a chain whose head is a constructor is refused before the
    root table is read (`stream_constructor_chain_is_refused` -- a named over-block, not an axis).
The sink wrapper's own three clauses are re-pinned beside the new ones, because the clause widens *what
counts as a stream*, not what counts as a sink: a stream buried inside a path expression still joins a
path (`stream_raw_inside_join_still_joins`), a caller-controlled second argument still rides past the first
slot (`stream_raw_second_arg_dynamic`), a non-literal keyword likewise (`stream_non_literal_keyword`), and a
`*args` unpacking is not an argument the guard can read (`stream_starred_argument`).

Yield and cost, measured: 117 arena CWE-22 rows retired, **ADDED=0**, over 86 files, and blessed reach 0
asked on all 24 frozen lines by name (TIER 6). The three retired spellings that are *not* the arena's shape
(`io.open(...raw)`, `import requests as rq`, a literal second argument) are asserted anyway, because a
clause that only answers one spelling is a fixture, not a rule.

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
# The stream fixtures need a library that answers with a stream, an image loader that reads a path *or* a
# stream, and one tainted value in the module so the sink it sits behind is the same shape the arena has.
RLIB = 'import requests\n'
PIL = 'from PIL import Image\n'
URL = 'url = request.args.get("u")\nprint(url)\n'

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
    # ---- the move/destination pitch (this mandate's item 2), measured before any edit ----
    # Both loud rows are the pitch's own shape: a source a caller chose, moved *into* a directory the
    # pitch calls safe. `move_dest_pitch_shipped` silences exactly these two.
    ('move_source_chosen_by_caller_to_temp_dest', REQ + HEAD +
     'shutil.move(os.path.join("exports", request.args["f"]), tempfile.mkdtemp())\n',
     'loud', 'loud'),
    ('move_source_param_to_template_dir', REQ + HEAD + '\n\ndef stage(name):\n'
     '    shutil.move(os.path.join("exports", name), "models/staging")\n\n\n'
     'stage(request.args.get("f"))\n', 'loud', 'loud'),
    # The destination is never the audited argument, so the reverse -- a temp source moved to a caller's
    # path -- already reads quiet at HEAD. The pitch therefore buys nothing here and costs the two rows
    # above, which is why item 2 is a rewrite of *which argument* is inspected, not a narrowing.
    ('move_dest_is_never_the_audited_argument', REQ + HEAD +
     'shutil.move(os.path.join(tempfile.mkdtemp(), "x.json"), request.args.get("d"))\n',
     'quiet', 'quiet'),
    # `os.makedirs` is not a CWE-22 sink at all: 0 rows exist to suppress, so the only way to honour
    # this half of the pitch is to ADD a sink -- a finding that was never reported, in a rule whose
    # shipped wirings all sit in a suppressing position.
    ('makedirs_is_not_a_cwe22_sink', REQ + HEAD +
     'os.makedirs(os.path.join("models", request.args["f"]), exist_ok=True)\n', 'quiet', 'quiet'),
    # ---- the instance-attribute hop: the assignment table's blind spot, not a new exemption ----
    # `self.<attr>` writes are recorded in `class_field_assignments`, never in `assignments_by_scope`,
    # so a root the class itself created in `setUp` was invisible to the proof at `tearDown`.
    ('self_attr_written_to_mkdtemp', REQ + HEAD + '\n\nclass GateCase:\n'
     '    def setUp(self):\n        self.tmpdirname = tempfile.mkdtemp()\n\n'
     '    def tearDown(self):\n        shutil.rmtree(self.tmpdirname)\n', 'loud', 'quiet'),
    ('self_attr_written_to_path_mkdtemp', REQ + HEAD + '\n\nclass GateCase:\n'
     '    def setUp(self):\n        self.out = Path(tempfile.mkdtemp(prefix="gate-"))\n\n'
     '    def clean(self):\n        os.remove(self.out / "f.json")\n', 'loud', 'quiet'),
    # The tripwire is the whole point of the hop: a second write to the same attribute makes the proof
    # false, so the row that says temp in `setUp` and takes the directory from `request` in `go` stays
    # reported. Deleting the `all(...)` fold (mutation `attribute_hop_takes_first_write`) lights this up.
    ('self_attr_rebound_to_request', REQ + HEAD + '\n\nclass GateCase:\n'
     '    def setUp(self):\n        self.tmpdirname = tempfile.mkdtemp()\n\n'
     '    def go(self):\n        self.tmpdirname = request.args["dir"]\n'
     '        shutil.rmtree(self.tmpdirname)\n', 'loud', 'loud'),
    ('self_attr_from_constructor_param', REQ + HEAD + '\n\nclass GateCase:\n'
     '    def __init__(self, where):\n        self.outdir = where\n\n'
     '    def clean(self):\n        shutil.rmtree(self.outdir)\n\n\n'
     'GateCase(request.args.get("d")).clean()\n', 'loud', 'loud'),
    # ---- the HTTP response body stream: an object in the path slot, so no path is ever reached ----
    # Every row here is loud at HEAD, because the clause that reads it is new. The retired spellings are
    # one per clause the proof depends on: the keyword that makes it a stream, the two sink names, the
    # import alias, a literal companion argument and an attribute-chain head.
    ('stream_raw_image_open', RLIB + PIL + URL + 'img = Image.open(requests.get(url, stream=True).raw)\n'
     'print(img)\n', 'loud', 'quiet'),
    ('stream_raw_image_open_plain', RLIB + PIL + URL + 'img = Image.open(requests.get(url).raw)\n'
     'print(img)\n', 'loud', 'quiet'),
    ('stream_raw_builtin_open', RLIB + URL + HEAD + 'data = open(requests.get(url).raw)\nprint(data)\n',
     'loud', 'quiet'),
    ('stream_raw_io_open', 'import io\n' + RLIB + URL + 'data = io.open(requests.get(url).raw)\n'
     'print(data)\n', 'loud', 'quiet'),
    ('stream_raw_import_alias', 'import requests as rq\n' + PIL + URL
     + 'img = Image.open(rq.get(url).raw)\nprint(img)\n', 'loud', 'quiet'),
    ('stream_raw_literal_companion_arg', RLIB + PIL + URL
     + 'img = Image.open(requests.get(url).raw, "PNG")\nprint(img)\n', 'loud', 'quiet'),
    ('stream_raw_attribute_chain_head', RLIB + URL + PIL
     + 'img = Image.open(requests.adapters.CaseInsensitiveDict(url).raw)\nprint(img)\n', 'loud', 'quiet'),
    # Tripwires: each is one axis from a retired row, and each is a case where a real path *can* reach the
    # sink -- so the proof is a refusal here, not a gap in coverage.
    ('stream_text_attr_is_not_a_stream', RLIB + PIL + URL + 'img = Image.open(requests.get(url).text)\n'
     'print(img)\n', 'loud', 'loud'),
    ('stream_content_attr_is_not_a_stream', RLIB + PIL + URL
     + 'img = Image.open(requests.get(url).content)\nprint(img)\n', 'loud', 'loud'),
    ('stream_json_call_is_not_a_stream', RLIB + PIL + URL + 'img = Image.open(requests.get(url).json())\n'
     'print(img)\n', 'loud', 'loud'),
    ('stream_name_bound_response_is_not_proven', RLIB + PIL + URL
     + 'resp = requests.get(url)\nimg = Image.open(resp.raw)\nprint(img)\n', 'loud', 'loud'),
    ('stream_session_bound_response_is_not_proven', RLIB + PIL + URL
     + 'sess = requests.Session()\nimg = Image.open(sess.get(url).raw)\nprint(img)\n', 'loud', 'loud'),
    ('stream_unimported_requests_name', PIL + URL
     + 'img = Image.open(requests.get(url).raw)\nprint(img)\n', 'loud', 'loud'),
    ('stream_local_object_named_requests', PIL + URL
     + 'class Requests:\n    def get(self, u):\n        return self\n\n\nrequests = Requests()\n'
     'img = Image.open(requests.get(url).raw)\nprint(img)\n', 'loud', 'loud'),
    ('stream_raw_inside_join_still_joins', RLIB + URL + HEAD
     + 'open(os.path.join(requests.get(url).raw, "x.json"))\n', 'loud', 'loud'),
    ('stream_raw_second_arg_dynamic', RLIB + URL + HEAD
     + 'mode = request.args.get("m")\nprint(mode)\nopen(requests.get(url).raw, mode)\n', 'loud', 'loud'),
    ('stream_non_literal_keyword', RLIB + PIL + URL
     + 'img = Image.open(requests.get(url).raw, formats=["PNG"])\nprint(img)\n', 'loud', 'loud'),
    ('stream_starred_argument', RLIB + URL + HEAD
     + 'paths = [requests.get(url).raw]\nopen(*paths)\n', 'loud', 'loud'),
    ('stream_httpx_root_is_not_requests', 'import httpx\n' + PIL + URL
     + 'img = Image.open(httpx.get(url).raw)\nprint(img)\n', 'loud', 'loud'),
    ('stream_urllib3_root_is_not_requests', 'import urllib3\n' + PIL + URL
     + 'img = Image.open(urllib3.request("GET", url).raw)\nprint(img)\n', 'loud', 'loud'),
    ('stream_requests_mock_is_not_requests', 'import requests_mock\n' + PIL + URL
     + 'img = Image.open(requests_mock.get(url).raw)\nprint(img)\n', 'loud', 'loud'),
    # A named over-block, not an axis: the chain head here is a constructor call, so the clause refuses it
    # before the root table is ever read -- widening either table cannot move this row.
    ('stream_constructor_chain_is_refused', 'import requests_toolbelt\n' + PIL + URL
     + 'img = Image.open(requests_toolbelt.Session().get(url).raw)\nprint(img)\n', 'loud', 'loud'),
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
    ('an instance attribute written once to a temp root vs the same attribute rebound to a request '
     'value later in the class', 'self_attr_written_to_mkdtemp', 'self_attr_rebound_to_request'),
    # One axis per stream pair, and the dirty arm is a case where a real path can still reach the sink.
    ('the stream slot of a response vs the same response read as text', 'stream_raw_image_open_plain',
     'stream_text_attr_is_not_a_stream'),
    ('a call whose head this module imported from requests vs the same call on an unimported name',
     'stream_raw_image_open_plain', 'stream_unimported_requests_name'),
    ('a stream in the path slot vs the same stream buried inside a join', 'stream_raw_builtin_open',
     'stream_raw_inside_join_still_joins'),
    ('a stream with a literal companion argument vs the same call with a caller-controlled mode',
     'stream_raw_literal_companion_arg', 'stream_raw_second_arg_dynamic'),
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
    # ---- the instance-attribute hop, one axis per row ----
    ('self_attr_mkdtemp_root', 'shutil.rmtree', REQ + HEAD + '\n\nclass C:\n'
     '    def setUp(self):\n        self.tmpdirname = tempfile.mkdtemp()\n\n'
     '    def tearDown(self):\n        shutil.rmtree(self.tmpdirname)\n', True),
    ('self_attr_path_div', 'os.remove', REQ + HEAD + '\n\nclass C:\n'
     '    def setUp(self):\n        self.out = Path(tempfile.mkdtemp())\n\n'
     '    def clean(self):\n        os.remove(self.out / "f.json")\n', True),
    ('self_attr_both_writes_temp', 'shutil.rmtree', REQ + HEAD + '\n\nclass C:\n'
     '    def setUp(self):\n        self.tmpdirname = tempfile.mkdtemp()\n\n'
     '    def redo(self):\n        self.tmpdirname = tempfile.mkdtemp()\n'
     '        shutil.rmtree(self.tmpdirname)\n', True),
    ('self_attr_second_write_request', 'shutil.rmtree', REQ + HEAD + '\n\nclass C:\n'
     '    def setUp(self):\n        self.tmpdirname = tempfile.mkdtemp()\n\n'
     '    def go(self):\n        self.tmpdirname = request.args["dir"]\n'
     '        shutil.rmtree(self.tmpdirname)\n', False),
    ('self_attr_constructor_param', 'shutil.rmtree', REQ + HEAD + '\n\nclass C:\n'
     '    def __init__(self, where):\n        self.outdir = where\n\n'
     '    def clean(self):\n        shutil.rmtree(self.outdir)\n', False),
    # The table is keyed by class, so a sibling class that writes the same attribute name from a
    # request value must not lend its proof to this one -- and must not lose its own finding either.
    ('self_attr_sibling_class_writes_same_name', 'shutil.rmtree', REQ + HEAD + '\n\nclass A:\n'
     '    def go(self):\n        self.d = request.args["d"]\n        shutil.rmtree(self.d)\n\n\n'
     'class B:\n    def go(self):\n        self.d = tempfile.mkdtemp()\n        shutil.rmtree(self.d)\n',
     False),
    ('self_attr_nested_attribute', 'shutil.rmtree', REQ + HEAD + '\n\nclass C:\n'
     '    def go(self, holder):\n        shutil.rmtree(self.root.tmpdirname)\n', False),
]

PRED_PROVEN = [row for row in PREDICATES if row[3]]
PRED_REFUSED = [row for row in PREDICATES if not row[3]]

# The stream proof's own truth table, at two levels, because the clause and the wrapper that consults it
# answer different questions. `want_sink` is what the CWE-22 wiring sees -- `_is_in_memory_buffer_sink`
# on the whole call, which also demands a positional first argument and literal companions. `want_expr`
# is the new clause alone -- `_is_http_response_stream` on that first argument. A row where the two
# disagree is the interesting one: it proves a wrapper clause is load-bearing on the new shape, so the
# stream table could never be accused of having widened the *sink* test along with the *path* test.
# (label, sink callee, source, want_sink, want_expr)
STREAMS = [
    ('raw_stream_direct', 'Image.open', RLIB + PIL + URL
     + 'img = Image.open(requests.get(url).raw)\nprint(img)\n', True, True),
    ('stream_true_keyword', 'Image.open', RLIB + PIL + URL
     + 'img = Image.open(requests.get(url, stream=True).raw)\nprint(img)\n', True, True),
    ('builtin_open_stream', 'open', RLIB + URL + HEAD
     + 'data = open(requests.get(url).raw)\nprint(data)\n', True, True),
    ('io_open_stream', 'io.open', 'import io\n' + RLIB + URL
     + 'data = io.open(requests.get(url).raw)\nprint(data)\n', True, True),
    ('head_imported_by_alias', 'Image.open', 'import requests as rq\n' + PIL + URL
     + 'img = Image.open(rq.get(url).raw)\nprint(img)\n', True, True),
    ('function_imported_directly', 'Image.open', 'from requests import get\n' + PIL + URL
     + 'img = Image.open(get(url).raw)\nprint(img)\n', True, True),
    ('receiver_attribute_chain', 'Image.open', RLIB + URL + PIL
     + 'img = Image.open(requests.adapters.CaseInsensitiveDict(url).raw)\nprint(img)\n', True, True),
    ('text_slot_is_a_string', 'Image.open', RLIB + PIL + URL
     + 'img = Image.open(requests.get(url).text)\nprint(img)\n', False, False),
    ('content_slot_is_bytes', 'Image.open', RLIB + PIL + URL
     + 'img = Image.open(requests.get(url).content)\nprint(img)\n', False, False),
    ('json_call_is_not_a_slot', 'Image.open', RLIB + PIL + URL
     + 'img = Image.open(requests.get(url).json())\nprint(img)\n', False, False),
    ('name_bound_response', 'Image.open', RLIB + PIL + URL
     + 'resp = requests.get(url)\nimg = Image.open(resp.raw)\nprint(img)\n', False, False),
    ('session_bound_response', 'Image.open', RLIB + PIL + URL
     + 'sess = requests.Session()\nimg = Image.open(sess.get(url).raw)\nprint(img)\n', False, False),
    ('attribute_of_a_non_call', 'Image.open', RLIB + PIL + URL
     + 'img = Image.open(requests.holder.raw)\nprint(img)\n', False, False),
    ('unimported_head', 'Image.open', PIL + URL
     + 'img = Image.open(requests.get(url).raw)\nprint(img)\n', False, False),
    ('locally_defined_head', 'Image.open', PIL + URL
     + 'class Requests:\n    def get(self, u):\n        return self\n\n\nrequests = Requests()\n'
     + 'img = Image.open(requests.get(url).raw)\nprint(img)\n', False, False),
    ('other_library_root', 'Image.open', 'import httpx\n' + PIL + URL
     + 'img = Image.open(httpx.get(url).raw)\nprint(img)\n', False, False),
    ('second_other_library_root', 'Image.open', 'import urllib3\n' + PIL + URL
     + 'img = Image.open(urllib3.request("GET", url).raw)\nprint(img)\n', False, False),
    ('mock_head_is_not_the_root', 'Image.open', 'import requests_mock\n' + PIL + URL
     + 'img = Image.open(requests_mock.get(url).raw)\nprint(img)\n', False, False),
    ('constructor_head_chain', 'Image.open', 'import requests_toolbelt\n' + PIL + URL
     + 'img = Image.open(requests_toolbelt.Session().get(url).raw)\nprint(img)\n', False, False),
    ('stream_inside_join', 'open', RLIB + URL + HEAD
     + 'open(os.path.join(requests.get(url).raw, "x.json"))\n', False, False),
    ('starred_slot', 'open', RLIB + URL + HEAD
     + 'paths = [requests.get(url).raw]\nopen(*paths)\n', False, False),
    ('non_literal_keyword_blocks', 'Image.open', RLIB + PIL + URL
     + 'img = Image.open(requests.get(url).raw, formats=["PNG"])\nprint(img)\n', False, True),
    ('dynamic_second_arg_blocks', 'open', RLIB + URL + HEAD
     + 'mode = request.args.get("m")\nprint(mode)\nopen(requests.get(url).raw, mode)\n', False, True),
]

STREAM_PROVEN = [row for row in STREAMS if row[3]]
STREAM_REFUSED = [row for row in STREAMS if not row[3]]
# Both tables are asked with the same triple the wiring builds, so a blessed line the stream proof would
# silence is counted by name rather than inferred from a baseline diff. These are the sink segments the 24
# frozen CWE-22 keys actually carry, so `asks` can be required to equal the locked count exactly.
BLESSED_SINK_SEGMENTS = ('open', 'remove', 'rmtree', 'extract', 'read_bytes')

STREAM_ATTRS_REQUIRED = ('raw',)
STREAM_ATTRS_FORBIDDEN = ('content', 'text', 'json', 'data', 'stream', 'body', 'headers',
                          'reason', 'raw_data', 'file')
STREAM_ROOTS_REQUIRED = ('requests',)
STREAM_ROOTS_FORBIDDEN = ('httpx', 'urllib3', 'urllib', 'aiohttp', 'torch', 'numpy', 'random',
                         'secrets', 'self', 'session', 'resp', 'requests_toolbelt', 'requests_mock')

DELETE_SINKS_REQUIRED = ('os.remove', 'os.unlink', 'shutil.rmtree')
DELETE_SINKS_FORBIDDEN = ('open', 'Image.open', 'PIL.Image.open', 'os.rmdir', 'send_file',
                         'shutil.move', 'os.makedirs', 'Path.mkdir')
TEMPFILE_REQUIRED = ('tempfile.mkdtemp', 'tempfile.mkstemp', 'tempfile.NamedTemporaryFile',
                     'tempfile.TemporaryDirectory', 'tempfile.gettempdir')
TEMPFILE_FORBIDDEN = ('mkdtemp', 'gettempdir', 'NamedTemporaryFile', 'tmpdir', 'TMPDIR',
                      'tempfile.TemporaryFileWrapper', 'tempfile.mktemp')
NAME_ATTRS_REQUIRED = ('name', 'filename')
NAME_ATTRS_FORBIDDEN = ('path', 'parent', 'suffix', 'dir', 'file', 'decode')
# The one line of the collector that decides what a move alert is *about*. Everything else in this
# rule is downstream of it, so a destination exemption has to change this text -- which TIER 7 reads.
SLOT_FRAGMENT = 'path_arg = node.args[0] if node.args else None'


def scan_source(source, module='m.py'):
    """One in-memory module through the real record path, as both baselines were built.

    The PIL and move pitch mutations are row filters, applied here and nowhere else, because both
    pitches are row-level rules and the shipped engine has neither a PIL exemption nor a destination
    exemption to delete.
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
    if _MOVE_PITCH_APPLIED:
        found = [row for row in found
                 if not (row[1].endswith('shutil.move') and _move_pitch_silences(source, row[0]))]
    return found


_PIL_PITCH_APPLIED = False
_MOVE_PITCH_APPLIED = False


def _move_pitch_silences(source, lineno):
    """The pitch as written, on the sink line it would be asked about.

    "Suppress the traversal alert if the target destination expression resolves within a newly created
    temporary or target model template directory" -- so the test is on `args[1]`: a fresh
    `tempfile.mkdtemp()` root, or a literal directory the file names itself. Both are what the two loud
    move fixtures pass.
    """
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call) or getattr(node, 'lineno', 0) != lineno:
            continue
        if ast_scanner.dotted_name(node.func) != 'shutil.move' or len(node.args) < 2:
            continue
        destination = node.args[1]
        if isinstance(destination, ast.Constant) and isinstance(destination.value, str):
            return True
        if (isinstance(destination, ast.Call)
                and ast_scanner.dotted_name(destination.func) == 'tempfile.mkdtemp'):
            return True
    return False


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


def stream_ask_both(source, sink, module='m.py'):
    """Ask the stream proof on the first call to `sink`, at both levels, with the wiring's own triple.

    `(sink-level answer, clause-level answer)`, or `(None, None)` when the fixture holds no readable call.
    The clause is asked on `args[0]` because that is the only slot the shipped wrapper consults, and the
    wrapper is asked on the whole node because its three companion clauses are part of its contract.
    """
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
        scope_id = enclosing_scope_id(tree, module[:-3], node.lineno)
        return (bool(tracker._is_in_memory_buffer_sink(node, module[:-3], scope_id, node.lineno)),
                bool(tracker._is_http_response_stream(expr, module[:-3])))
    return (None, None)


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


def _stream_ask_on_lines(source, module, wanted_lines):
    """Ask the sink-level stream proof on every path-named sink call on `wanted_lines`.

    The record route cannot see a retired row -- the collector `continue`s before it registers the sink --
    so this walks the parsed file instead and asks with the triple the wiring builds. `BLESSED_SINK_SEGMENTS`
    is what makes `asked` equal the locked key count exactly: a census that asked nothing would look just
    like a safe zero.
    """
    tree = ast.parse(source)
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={module: source}, audit_all=True)
        tracker.analyze()
    mod = module[:-3] if module.endswith('.py') else module
    asked = hits = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node.lineno not in wanted_lines:
            continue
        if (ast_scanner.dotted_name(node.func) or '').split('.')[-1] not in BLESSED_SINK_SEGMENTS:
            continue
        asked += 1
        if tracker._is_in_memory_buffer_sink(
                node, mod, enclosing_scope_id(tree, mod, node.lineno), node.lineno):
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

    # The same discipline for the stream proof: three fixtures it must answer True on, so the 0 below is a
    # refusal and not a route that asked nothing.
    stream_controls = ('raw_stream_direct', 'builtin_open_stream', 'head_imported_by_alias')
    stream_control_hits = 0
    for label in stream_controls:
        row = next(r for r in STREAMS if r[0] == label)
        if stream_ask_both(row[2], row[1])[0]:
            stream_control_hits += 1
    if stream_control_hits != len(stream_controls):
        failures.append(('stream control',
                         'the sweep must answer buffer-sink on the 3 proven stream fixtures',
                         len(stream_controls), stream_control_hits))
    print(f'  stream control (proven-stream fixtures the sweep must answer True on): '
          f'{stream_control_hits}/{len(stream_controls)}')

    for kind in ('parity', 'big8'):
        rows = _blessed_rows(kind)
        by_file = {}
        for row in rows:
            by_file.setdefault(str(row[0]), set()).add(row[1])
        asked = answered = delete_lines_asked = 0
        stream_asked = stream_answered = 0
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
            sa, sh = _stream_ask_on_lines(source, module, lines)
            stream_asked += sa
            stream_answered += sh
            for row in rows:
                if str(row[0]) != name:
                    continue
                if 'os.remove' in str(row[4]) or 'shutil.rmtree' in str(row[4]):
                    delete_lines_asked += 1
                    if h:
                        print(f'  REACHABLE  {name}:{row[1]}  {str(row[4])[:40]}')
                    if sh:
                        print(f'  STREAM REACHABLE  {name}:{row[1]}  {str(row[4])[:40]}')
        print(f'  {kind:7s} blessed_lines={len(rows)}  predicate_asks={asked}  '
              f'answers_temp_root={answered}  delete_sink_blessed_lines={delete_lines_asked}')
        print(f'  {kind:7s} stream_asks={stream_asked}  answers_buffer_sink={stream_answered}  '
              f'(every blessed line must be asked, so asks must equal blessed_lines)')
        if answered:
            failures.append((kind, 'a blessed CWE-22 line is reachable by the temp guard', 0, answered))
        if stream_answered:
            failures.append((kind, 'a blessed CWE-22 line is reachable by the stream proof',
                             0, stream_answered))
        if stream_asked != len(rows):
            failures.append((kind, 'the stream census must ask every blessed line by name',
                             len(rows), stream_asked))
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
    """TIER 7: the three tables, the PIL and move refusals, and the exactly-three wiring sites."""
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
            ('cls_scope = self._get_enclosing_class_scope(scope_id)',
             'the instance-attribute hop resolves the *class*, so a sibling class writing the same '
             'attribute name cannot lend its proof'),
            ('self.class_field_assignments.get((cls_scope, expr.attr), [])',
             'and reads the table collect_statements already builds for `self.<attr>` writes -- the '
             'assignment map keys plain-name targets only, so this is a blind spot, not an exemption'),
            ('return all(self._c22_path_is_proven_temp_root(\n'
             '                        r.value_node, r.scope_id, r.lineno, depth + 1) for r in writes)',
             'every write the class shows must prove itself -- `any` would let a later '
             '`self.tmpdirname = request.args[...]` ride the first write'),
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

    # The two shape facts behind this mandate's item 2, read off the shipped collector rather than
    # asserted: `os.makedirs` is not a path sink (so there is nothing to suppress), and the rule audits
    # the first positional argument only (so a *destination* test is not a narrowing of this rule -- it
    # is a rewrite of which argument is inspected, and the only thing it can silence is a source).
    collector = inspect.getsource(mod.TaintTracker._collect_cwe22_path_traversal_findings)
    make_dir_words = [word for word in ('makedirs', 'mkdir') if word in collector]
    print(f'  item-2 shape census: makedirs/mkdir in the CWE-22 collector={make_dir_words} (want []), '
          f'`shutil.move`={collector.count("shutil.move")} (want 1), '
          f'first-slot audit={SLOT_FRAGMENT in collector} (want True), '
          f'second-slot reads={collector.count("node.args[1]")} (want 0)')
    if make_dir_words:
        failures.append(('makedirs refusal', 'no makedirs or mkdir sink in the CWE-22 collector',
                         [], make_dir_words,
                         'the mandate named a call that is not a path traversal sink: it has 0 rows to '
                         'suppress, and adding it would ADD findings in a rule whose every wiring sits '
                         'in a suppressing position'))
    if collector.count('shutil.move') != 1:
        failures.append(('move pitch refusal', 'exactly one `shutil.move`: the sink table',
                         1, collector.count('shutil.move'),
                         'a second mention means a destination exemption has landed, and the only rows '
                         'it can move are caller-chosen sources'))
    if SLOT_FRAGMENT not in collector or collector.count('node.args[1]'):
        failures.append(('move pitch refusal', SLOT_FRAGMENT + ' and no read of node.args[1]',
                         'present', 'absent',
                         'CWE-22 inspects the SOURCE of a move; silencing on the destination would hide '
                         'an attacker-named file being carried into a directory the pitch calls safe'))
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


def _proven_without_attribute_hop(self, expr, scope_id='', lineno=0, depth=0, allow_literal=False):
    """Mutation: delete the instance-attribute hop and nothing else.

    The class-field table is blinded for this predicate only, so `self.tmpdirname` becomes an
    unresolved name again while every other arm of the guard keeps its shipped answer. A mutation
    that restored the pre-hop method text instead would also drop the `..`, subscript and receiver
    vetoes and prove nothing about the one line under test.
    """
    table = self.class_field_assignments
    self.class_field_assignments = {}
    try:
        return _ORIG_PROVEN(self, expr, scope_id, lineno, depth, allow_literal)
    finally:
        self.class_field_assignments = table


def _proven_attribute_first_write(self, expr, scope_id='', lineno=0, depth=0, allow_literal=False):
    """Mutation: `any` write of the attribute proves the root instead of *every* write.

    One axis from the shipped hop: the fold. A class that writes `self.tmpdirname` to `mkdtemp()`
    in `setUp` and to `request.args["dir"]` later then reads as proven again.
    """
    if _ORIG_PROVEN(self, expr, scope_id, lineno, depth, allow_literal):
        return True
    if (expr is not None and depth <= 8 and isinstance(expr, ast.Attribute)
            and isinstance(expr.value, ast.Name) and expr.value.id in ('self', 'cls')):
        cls_scope = self._get_enclosing_class_scope(scope_id)
        writes = (self.class_field_assignments.get((cls_scope, expr.attr), [])
                  if cls_scope else [])
        if writes:
            return any(_proven_attribute_first_write(
                self, record.value_node, record.scope_id, record.lineno, depth + 1)
                for record in writes)
    return False


def _literal_ok_ignoring_escape(self, expr, allow_literal):
    """Mutation: any string constant is a safe literal segment, `..` included."""
    return isinstance(expr, ast.Constant) and isinstance(expr.value, str) and expr.value != ''


_ORIG_GUARD = ast_scanner.TaintTracker._c22_cleanup_is_temp_teardown
_ORIG_PROVEN = ast_scanner.TaintTracker._c22_path_is_proven_temp_root
_ORIG_LITERAL = ast_scanner.TaintTracker._c22_anchor_literal_ok
_ORIG_QUALIFIED = ast_scanner.TaintTracker._is_module_qualified
_ORIG_STREAM = ast_scanner.TaintTracker._is_http_response_stream


def _stream_accepts_any_head(self, expr, mod_name):
    """Mutation: a head this module never imported is the library anyway.

    One axis from the shipped clause -- the import lookup. A module that defines `requests = Requests()`
    or simply uses the name without importing it then reads as an HTTP stream, which is the CWE-338
    "a bare alias exempts an unresolved receiver" defect in this rule's own vocabulary.
    """
    if not (isinstance(expr, ast.Attribute) and expr.attr in self._HTTP_STREAM_ATTRS):
        return False
    call = expr.value
    if not isinstance(call, ast.Call):
        return False
    imports = self.imports.get(mod_name) or {}
    func = call.func
    if isinstance(func, ast.Attribute):
        head = func.value
        while isinstance(head, ast.Attribute):
            head = head.value
        if not isinstance(head, ast.Name):
            return False
        origin = imports.get(head.id) or head.id
    elif isinstance(func, ast.Name):
        origin = imports.get(func.id) or func.id
    else:
        return False
    return origin.split('.')[0] in self._HTTP_STREAM_ROOTS


def _stream_root_match_becomes_a_substring(self, expr, mod_name):
    """Mutation: `requests` *inside* the resolved origin exempts, so the dot boundary is gone.

    One axis from the shipped clause -- how the origin is matched. `requests_mock` and
    `requests_toolbelt` are different libraries whose `.raw` slot is whatever that library puts there, and
    under a substring law they inherit the `requests` proof without ever being measured.
    """
    if not (isinstance(expr, ast.Attribute) and expr.attr in self._HTTP_STREAM_ATTRS):
        return False
    call = expr.value
    if not isinstance(call, ast.Call):
        return False
    imports = self.imports.get(mod_name) or {}
    func = call.func
    if isinstance(func, ast.Attribute):
        head = func.value
        while isinstance(head, ast.Attribute):
            head = head.value
        if not isinstance(head, ast.Name):
            return False
        origin = imports.get(head.id)
    elif isinstance(func, ast.Name):
        origin = imports.get(func.id)
    else:
        return False
    return origin is not None and any(p in origin for p in self._HTTP_STREAM_ROOTS)

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
    'attribute_hop_dropped': {
        'what': 'delete the instance-attribute hop and nothing else: the assignment table keys plain '
                '`ast.Name` targets only, so `self.tmpdirname = tempfile.mkdtemp()` written in `setUp` '
                'and deleted in `tearDown` is an unresolved name again and every one of those rows '
                'comes back. This is the blind spot the hop fixes, priced as a regression rather than '
                'as an exemption -- the guard still refuses a name, a parameter and a loop variable',
        'rows': ['self_attr_written_to_mkdtemp', 'self_attr_written_to_path_mkdtemp',
                 'self_attr_mkdtemp_root', 'self_attr_path_div', 'self_attr_both_writes_temp'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_path_is_proven_temp_root',
                                 _proven_without_attribute_hop),
    },
    'attribute_hop_takes_first_write': {
        'what': 'the hop folds `any` class write instead of `all`: a test class that sets '
                '`self.tmpdirname` from `tempfile.mkdtemp()` and later points the same attribute at '
                '`request.args["dir"]` is silenced on the strength of the first write, which is the '
                'rebinding every other arm of this rule refuses',
        'rows': ['self_attr_rebound_to_request', 'self_attr_second_write_request'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_c22_path_is_proven_temp_root',
                                 _proven_attribute_first_write),
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
    'move_dest_pitch_shipped': {
        'what': 'the mandate\'s item 2 applied as a row filter over the real record path (there is no '
                'destination exemption in the engine to delete, which is the refusal): silence a '
                '`CWE-22: shutil.move` row when the *destination* is a fresh `tempfile.mkdtemp()` root or '
                'a literal template directory. The rule audits `node.args[0]`, so both rows this buys '
                'silence for are a caller-chosen SOURCE being carried into a directory the pitch calls '
                'safe -- `os.path.join("exports", request.args["f"])` and `os.path.join("exports", name)` '
                'with `name` from `request.args`. Item 2\'s other name, `os.makedirs`, has 0 rows at any '
                'seal because it is not a path sink, so that half of the pitch cannot be applied at all '
                'without adding findings',
        'rows': ['move_source_chosen_by_caller_to_temp_dest', 'move_source_param_to_template_dir'],
        'apply': lambda: globals().update({'_MOVE_PITCH_APPLIED': True}),
    },
}


# ---------------------------------------------------------------- the cache-anchor refusal, measured
#
# The mandate after the attribute hop asked to resolve "safe provenance for arguments deriving from
# standard HuggingFace cache anchors (`pretrained_model_name_or_path`, `cache_dir`, `subfolder`,
# `resolved_archive_file`)" over the file sinks in `src/transformers/models/`, and to widen this guard
# from the three cleanup deletes to `open()`. Both were measured on the shipped predicates before any
# engine line was trusted, and both are refused. The numbers they produced are frozen here.

ANCHOR_FIXTURES = [
    # (label, source, callee) -- every one is the mandate's own shape, and none may be provable.
    ('anchor_cache_dir_param', '''
def load(cache_dir):
    return open(os.path.join(cache_dir, "config.json"))
''', 'open'),
    ('anchor_model_path_param', '''
def load(pretrained_model_name_or_path):
    return open(pretrained_model_name_or_path)
''', 'open'),
    ('anchor_subfolder_param', '''
def save(subfolder, filename):
    return open(os.path.join(subfolder, filename), "w")
''', 'open'),
    ('anchor_resolved_archive_file_download', '''
def load(resolved_archive_file):
    resolved_archive_file = http_get(url).name
    return open(resolved_archive_file)
''', 'open'),
    ('anchor_pretrained_path_from_request', '''
def load(request):
    pretrained_model_name_or_path = request.args["model"]
    return open(os.path.join(pretrained_model_name_or_path, "weights.bin"))
''', 'open'),
    # the alive control: a value the `tempfile` module returned, on a FILE sink. The raw proof accepts
    # it, which is exactly why the widening is a false-negative machine and not an inert rule.
    ('temp_root_file_sink_control', '''
import tempfile


def write_vocab():
    with tempfile.TemporaryDirectory() as tmp:
        return open(os.path.join(tmp, "vocab.json"), "w")
''', 'open'),
]
ANCHOR_REFUSED = ANCHOR_FIXTURES[:-1]
ANCHOR_CONTROL = ANCHOR_FIXTURES[-1]
WIDEN_BLESSED_DEATHS = 3          # big8 tests__generation__test_utils.py 5537 / 5539 / 5565
WIDEN_BLESSED_LINES = {5537, 5539, 5565}


def _ask_proofs(source, module, sink):
    """The two shipped CWE-22 provenance proofs, asked raw (no callee test) on the first `sink` call."""
    tree = ast.parse(source)
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={module: source}, audit_all=True)
        tracker.analyze()
        for node in ast.walk(tree):
            if callee_of(node) != sink:
                continue
            expr = path_expr_of_call(node)
            if expr is None:
                continue
            scope = enclosing_scope_id(tree, module[:-3], node.lineno)
            return (bool(tracker._c22_path_is_proven_temp_root(expr, scope, node.lineno)),
                    bool(tracker._c22_path_is_internal_repo_anchor(expr, scope, node.lineno)))
    return (None, None)


def _sweep_blessed(ask):
    """Ask `ask` on all 24 blessed CWE-22 records; return (asks, hits, the lines that answered True)."""
    asked = hits = 0
    lines_hit = set()
    for kind in ('parity', 'big8'):
        rows = _blessed_rows(kind)
        by_file = {}
        for row in rows:
            by_file.setdefault(str(row[0]), set()).add(row[1])
        for name, wanted in sorted(by_file.items()):
            relative = (name if kind == 'parity' else os.path.join(
                'benchmark_gates_data', 'corpus_big8', os.path.basename(name)))
            path = os.path.abspath(os.path.join(ROOT, relative))
            if not os.path.exists(path):
                return asked, hits, lines_hit
            with open(path, encoding='utf-8', errors='replace') as handle:
                source = handle.read()
            module = os.path.basename(name)
            with contextlib.redirect_stderr(_io.StringIO()):
                tracker = ast_scanner.TaintTracker(files={module: source}, audit_all=True)
                tracker.analyze()
            for record in tracker.sink_records:
                if record.lineno not in wanted or not is_cwe22_record(record.security_node.metadata):
                    continue
                expr = delete_target_of(record)
                if expr is None:
                    continue
                asked += 1
                if ask(tracker, record, expr):
                    hits += 1
                    lines_hit.add(record.lineno)
    return asked, hits, lines_hit


def check_cache_anchor_refusal():
    """TIER 8: the mandated HF cache anchors, the file-sink widening, and the 3 blessed keys it costs."""
    failures = []
    print('  the four mandated anchors, asked of the shipped proofs (both must refuse):')
    for label, source, sink in ANCHOR_REFUSED:
        temp, anchor = _ask_proofs(source, 'm.py', sink)
        ok = temp is False and anchor is False
        print(f'  {"ok" if ok else "REACHES":8s} {label:42s} temp_root={temp} repo_anchor={anchor}')
        if not ok:
            failures.append((label, 'a mandated HF cache anchor name is provable as a safe root',
                             (False, False), (temp, anchor),
                             'a parameter or a downloaded archive is not an internal anchor'))
    temp, anchor = _ask_proofs(ANCHOR_CONTROL[1], 'm.py', ANCHOR_CONTROL[2])
    print(f'  {"ok" if temp else "DEAD":8s} {ANCHOR_CONTROL[0]:42s} temp_root={temp} '
          f'(the proof is alive on a file sink)')
    if not temp:
        failures.append((ANCHOR_CONTROL[0], 'the raw temp proof must answer on a proven tempfile root',
                         True, temp, 'a sweep that answers nothing cannot prove a refusal'))

    shipped_ask, shipped_hits, shipped_lines = _sweep_blessed(_ask_guard)
    widen_ask, widen_hits, widen_lines = _sweep_blessed(_ask_raw_temp_root)
    print(f'  blessed CWE-22 asks: shipped callee-first wrapper asks={shipped_ask} '
          f'silenced={shipped_hits}')
    print(f'  blessed CWE-22 asks: widened to file sinks  asks={widen_ask} '
          f'silenced={widen_hits} lines={sorted(widen_lines)}')
    if shipped_hits:
        failures.append(('blessed', 'the shipped guard silences a blessed CWE-22 key', 0, shipped_hits))
    if widen_hits != WIDEN_BLESSED_DEATHS or set(widen_lines) != WIDEN_BLESSED_LINES:
        failures.append(('blessed', 'the frozen cost of widening the temp proof to file sinks',
                         (WIDEN_BLESSED_DEATHS, sorted(WIDEN_BLESSED_LINES)),
                         (widen_hits, sorted(widen_lines)),
                         'the reach of the refused widening moved - re-measure before anyone ships it'))
    table = inspect.getsource(ast_scanner.TaintTracker._c22_cleanup_is_temp_teardown)
    callee_first = 'CWE22_CLEANUP_DELETE_SINKS' in table
    print(f'  wiring: the wrapper is still callee-first over the delete table={callee_first} '
          f'delete sinks={sorted(ast_scanner.CWE22_CLEANUP_DELETE_SINKS)}')
    if not callee_first:
        failures.append(('wiring', '_c22_cleanup_is_temp_teardown must test the callee before anything'))
    return failures


def _consult_sites():
    """Every TaintTracker method that consults the buffer/stream proof, counted from the engine's AST.

    Read structurally, not as a text count: the law is *which rule may inherit this answer*, and a method
    rename must not turn the lock into a string match.
    """
    module_tree = ast.parse(inspect.getsource(ast_scanner))
    sites = {'_is_in_memory_buffer_sink': {}, '_is_http_response_stream': {}}
    for cls in (n for n in ast.walk(module_tree) if isinstance(n, ast.ClassDef)
                and n.name == 'TaintTracker'):
        for method in (m for m in cls.body
                       if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))):
            for call in (c for c in ast.walk(method) if isinstance(c, ast.Call)
                         and isinstance(c.func, ast.Attribute)
                         and isinstance(c.func.value, ast.Name) and c.func.value.id == 'self'):
                if call.func.attr in sites:
                    sites[call.func.attr][method.name] = sites[call.func.attr].get(method.name, 0) + 1
    return sites


def check_stream_proof():
    """TIER 9: the stream clause -- its two-level table, its two tables and who may consult it."""
    failures = []
    print('  the stream predicate table, asked at both levels (sink wrapper / new clause):')
    for label, sink, source, want_sink, want_expr in STREAMS:
        got_sink, got_expr = stream_ask_both(source, sink)
        marker = 'ok' if (got_sink, got_expr) == (want_sink, want_expr) else 'MISMATCH'
        print(f'  {label:34} want=({want_sink!s:5},{want_expr!s:5}) '
              f'got=({str(got_sink):5},{str(got_expr):5}) {marker:8s} sink={sink}')
        if got_sink is None:
            failures.append((label, 'no call to the named sink in the fixture -- the row asks nothing',
                             sink))
        elif (got_sink, got_expr) != (want_sink, want_expr):
            failures.append((label, 'stream predicate answers', (want_sink, want_expr),
                             (got_sink, got_expr), 'the clause no longer answers its own contract'))
    disagree = [row[0] for row in STREAMS if row[3] != row[4]]
    print(f'  rows where the wrapper and the clause disagree (each one proves a companion clause is '
          f'load-bearing on the new shape): {disagree}')
    if len(disagree) < 2:
        failures.append(('wrapper clauses', 'at least 2 rows must separate the clause from the wrapper',
                         2, len(disagree)))

    mod = ast_scanner
    attrs = set(mod.TaintTracker._HTTP_STREAM_ATTRS)
    absent = [n for n in STREAM_ATTRS_REQUIRED if n not in attrs]
    present = [n for n in STREAM_ATTRS_FORBIDDEN if n in attrs]
    print(f'  stream attrs       n={len(attrs)}  {sorted(attrs)}  absent={absent} forbidden={present}')
    if absent or present or attrs != set(STREAM_ATTRS_REQUIRED):
        failures.append(('stream attrs', STREAM_ATTRS_REQUIRED, sorted(attrs),
                         '`.text` and `.content` are bytes a path-named sink can be handed as a filename, '
                         'so only the stream slot itself may be exempt'))
    roots = set(mod.TaintTracker._HTTP_STREAM_ROOTS)
    absent = [n for n in STREAM_ROOTS_REQUIRED if n not in roots]
    present = [n for n in STREAM_ROOTS_FORBIDDEN if n in roots]
    bare = sorted(n for n in roots if not n.islower())
    print(f'  stream roots       n={len(roots)}  {sorted(roots)}  absent={absent} forbidden={present} '
          f'odd={bare}')
    if absent or present or bare:
        failures.append(('stream roots', STREAM_ROOTS_REQUIRED, sorted(roots),
                         'a root joins the table only with measured arena rows behind it (the '
                         'table-population law), and an alias or a bare object name would exempt an '
                         'unresolved receiver'))

    try:
        clause = inspect.getsource(mod.TaintTracker._is_http_response_stream)
    except (OSError, TypeError):
        clause = ''
        failures.append(('clause body', 'the shipped clause is unreadable -- the method that answers '
                         'now is not the method this table measures', 'readable', 'gone'))
    for fragment, why in (
            ('expr.attr in self._HTTP_STREAM_ATTRS', 'the attribute is the table, not a literal compare'),
            ('if not isinstance(call, ast.Call):', 'a name or an attribute is not a call the library made'),
            ('imports = self.imports.get(mod_name) or {}',
             'the receiver is resolved through this module\'s import table, so a locally defined object '
             'named `requests` does not qualify'),
            ('if not isinstance(head, ast.Name):', 'the chain head must be a name somebody imported'),
            ('origin is not None', 'an unresolved head fails closed -- no taint-free guess'),
            ('origin.split(".")[0] in self._HTTP_STREAM_ROOTS',
             'the match is on the top-level package, so `requests_mock` does not inherit `requests`'),
    ):
        if fragment not in clause:
            failures.append(('clause body', fragment, 'present', 'absent', why))
    for fragment, why in (
            ('if self._is_http_response_stream(expr, mod_name):',
             'the clause ships inside the one shared path predicate, so every CWE-22 consult site '
             'inherits the same answer instead of growing a third exemption'),
            ('if self._is_buffer_construction(expr, mod_name):',
             'and it sits beside the BytesIO proof it generalises, not behind a new table of sinks'),
    ):
        if fragment not in inspect.getsource(mod.TaintTracker._is_in_memory_buffer_path):
            failures.append(('shared predicate body', fragment, 'present', 'absent', why))

    sites = _consult_sites()
    buffer_sites = sites['_is_in_memory_buffer_sink']
    clause_sites = sites['_is_http_response_stream']
    non_cwe22 = sorted(m for m in buffer_sites if 'cwe22' not in m.lower())
    print(f'  consult sites: buffer sink=' + str(dict(sorted(buffer_sites.items()))) +
          f' (total={sum(buffer_sites.values())}, want 3, non-cwe22={non_cwe22})')
    print(f'  consult sites: stream clause=' + str(dict(sorted(clause_sites.items()))) +
          f' (total={sum(clause_sites.values())}, want 1, inside _is_in_memory_buffer_path)')
    if sum(buffer_sites.values()) != 3 or non_cwe22 or sum(clause_sites.values()) != 1 \
            or list(clause_sites) != ['_is_in_memory_buffer_path']:
        failures.append(('consult sites',
                         'the stream/buffer proof is consulted by the three CWE-22 sites only, through '
                         'one shared predicate', (3, [], 1),
                         (sum(buffer_sites.values()), non_cwe22, sum(clause_sites.values())),
                         'a rule outside CWE-22 that inherits this answer would silence findings this '
                         'gate has never measured -- widening it is a decision, not a refactor'))
    return failures



def _ask_raw_temp_root(tracker, record, expr):
    """The refused reading: the temp proof asked without the callee-first test, so `open` counts too."""
    return tracker._c22_path_is_proven_temp_root(expr, record.scope_id, record.lineno)


def _apply_widen_to_file_sinks():
    """Install the widening in memory: the wrapper stops asking which callee it is guarding."""
    ast_scanner.TaintTracker._c22_cleanup_is_temp_teardown = (
        lambda self, call_node, path_expr, scope_id='', lineno=0:
        self._c22_path_is_proven_temp_root(path_expr, scope_id, lineno))


MUTATIONS['widen_temp_root_to_file_sinks'] = {
    'what': 'widen the proven-temp-root proof from the three cleanup deletes to every CWE-22 sink, '
            'which is the mandate\'s "open() and file sinks load local cached weights" reading - it '
            'must die on the 3 blessed test_utils.py file sinks it silences',
    'rows': ['blessed:test_utils.py:5537', 'blessed:test_utils.py:5539', 'blessed:test_utils.py:5565'],
    'keeps_loud': ['temp_root_file_sink_control is the proof that this widening is alive, not inert'],
    'apply': _apply_widen_to_file_sinks,
}


MUTATIONS['delete_stream_clause'] = {
    'what': 'the stream clause always answers "not a stream" -- every retired row comes back, which is '
            'the 117-row arena population this clause exists for',
    'rows': [row[0] for row in SHAPES if row[0].startswith('stream_') and row[3] == 'quiet'],
    'apply': lambda: setattr(ast_scanner.TaintTracker, '_is_http_response_stream',
                             lambda self, *a, **k: False),
}

MUTATIONS['stream_clause_always_true'] = {
    'what': 'the clause answers "stream" for any expression -- the widest reading of "it is an object, '
            'not a path", and the reason the attribute table and the import lookup both exist',
    'rows': ['text_slot_is_a_string', 'content_slot_is_bytes', 'unimported_head',
             'locally_defined_head', 'other_library_root', 'second_other_library_root',
             'mock_head_is_not_the_root', 'constructor_head_chain', 'blessed parity/big8 lines'],
    'apply': lambda: setattr(ast_scanner.TaintTracker, '_is_http_response_stream',
                             lambda self, *a, **k: True),
}

MUTATIONS['stream_attrs_accept_response_payload'] = {
    'what': 'add text/content/json to `_HTTP_STREAM_ATTRS` -- the response *payload* joins the stream '
            'slot, and `open(requests.get(url).text)` (a path the server chose) reads as a file-like '
            'object',
    'rows': ['stream_text_attr_is_not_a_stream', 'stream_content_attr_is_not_a_stream',
             'stream_json_call_is_not_a_stream', 'text_slot_is_a_string', 'content_slot_is_bytes'],
    'apply': lambda: setattr(ast_scanner.TaintTracker, '_HTTP_STREAM_ATTRS',
                             frozenset({'raw', 'text', 'content', 'json'})),
}

MUTATIONS['stream_roots_accept_other_libraries'] = {
    'what': 'put urllib3/httpx/urllib in `_HTTP_STREAM_ROOTS` with no arena rows behind them -- the '
            'table-population law is what this breaks, and `.raw` means something different in each '
            'of those libraries',
    'rows': ['stream_httpx_root_is_not_requests', 'stream_urllib3_root_is_not_requests',
             'other_library_root', 'second_other_library_root', 'stream roots table'],
    'apply': lambda: setattr(ast_scanner.TaintTracker, '_HTTP_STREAM_ROOTS',
                             frozenset({'requests', 'urllib3', 'httpx', 'urllib'})),
}

MUTATIONS['stream_accepts_unimported_head'] = {
    'what': 'the receiver lookup falls back to the name as written, so a module-local object called '
            '`requests` -- or no `requests` at all -- is proven to be the library',
    'rows': ['stream_unimported_requests_name', 'stream_local_object_named_requests',
             'unimported_head', 'locally_defined_head'],
    'apply': lambda: setattr(ast_scanner.TaintTracker, '_is_http_response_stream',
                             _stream_accepts_any_head),
}

MUTATIONS['stream_root_match_becomes_a_substring'] = {
    'what': 'match the resolved origin with a substring test instead of the top-level package, so '
            '`requests_mock` inherits the `requests` proof it was never measured for',
    'rows': ['stream_requests_mock_is_not_requests', 'mock_head_is_not_the_root'],
    'apply': lambda: setattr(ast_scanner.TaintTracker, '_is_http_response_stream',
                             _stream_root_match_becomes_a_substring),
}


def run_mutation(name: str) -> int:
    """Apply one in-memory mutation and run the real gate over it. Exit 1 = the mutation was caught."""
    global _PIL_PITCH_APPLIED, _MOVE_PITCH_APPLIED
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print(f"  rows that must move: {', '.join(spec['rows'])}")
    tiers = []
    try:
        spec['apply']()
        if name == 'pil_pitch_shipped':
            _PIL_PITCH_APPLIED = True
        if name == 'move_dest_pitch_shipped':
            _MOVE_PITCH_APPLIED = True
        print(f'TIER 3 - findings truth table under seal={CWE22_TEMP_SEAL!r}:')
        tiers.append(('T3', check_shapes()))
        print('TIER 4 - the guard\'s own predicate table:')
        tiers.append(('T4', check_predicates()))
        print('TIER 5 - one axis, two arms, both moved by this guard:')
        tiers.append(('T5', check_pairs()))
        print('TIER 6 - the 24 blessed lines, asked about directly:')
        tiers.append(('T6', check_blessed_lines()))
        print('TIER 8 - the mandated HF cache anchors and the file-sink widening:')
        tiers.append(('T8', check_cache_anchor_refusal()))
        print('TIER 9 - the HTTP response body stream table, its two clause tables and its sites:')
        tiers.append(('T9', check_stream_proof()))
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
    print('TIER 7 - three tables, the PIL and move refusals, and the wiring sites:')
    failures += check_tables_and_wiring()
    print('TIER 8 - the mandated HF cache anchors and the file-sink widening, scored on the blessed 24:')
    failures += check_cache_anchor_refusal()
    print('TIER 9 - the HTTP response body stream: its table, its two clause tables, its consult sites:')
    failures += check_stream_proof()
    print(f'\nseal={CWE22_TEMP_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'pred_rows={len(PREDICATES)} pred_proven={len(PRED_PROVEN)} '
          f'pred_refused={len(PRED_REFUSED)} stream_rows={len(STREAMS)} '
          f'stream_proven={len(STREAM_PROVEN)} stream_refused={len(STREAM_REFUSED)} '
          f'pairs={len(PAIRS)} '
          f'locked_cwe22={sum(CWE22_LOCKED.values())} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-22 temp-teardown and stream predicates no longer match their '
              'measured evidence. Restore the answer or update the seal with a re-measured truth table; never '
              're-bless a baseline -- the 2 blessed delete keys (`modeling_utils.py:3494`, '
              '`trainer.py:2008`) are a directory listing and a checkpoint loop variable and the guard '
              'must stay blind to both, the PIL row stays refused, and the stream clause may only ever '
              'answer for the attribute and the imported root it names.')
        return 1
    print(f'VERDICT: PASS - all {sum(CWE22_LOCKED.values())} blessed CWE-22 keys still reported, '
          f'parity corpus exact-set, {len(FP_ROWS)} proven-temp and stream shapes silent, '
          f'{len(MUST_REPORT_ROWS)} caller/name/scope/path shapes reported, '
          f'{len(PRED_REFUSED)} predicate refusals and {len(STREAM_REFUSED)} stream refusals held, '
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
