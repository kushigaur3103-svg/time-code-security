"""CWE-78 truth table: which subprocess argv can inject a command, and what an execve proof covers.

Why this gate exists
--------------------
On the pinned LiteLLM tree 208 CWE-78 rows exist and every one of them is an argv call: 147 pass a
List/Tuple with at least one non-literal element, 30 pass a name bound to such a sequence, and 0 pass
a string command. Not one of them is `os.system`, `os.popen` or `shell=True`. The prompt's eligible
set -- "explicit list/tuple literal, every element a constant" -- measures 0 rows, because
`rule_engine._cwe78_safety_filter` (rule_engine.py:416) has exempted that shape for a long time. So
the whole population sits on the one question nobody had answered: with no shell, can an argv element
become a *command*?

The emitter
-----------
  Every CWE-78 sink -- registry path, `is_sink_call`, blindspot (`_add_blindspot_sink`,
  ast_scanner.py:12365), phase-11 (:19735) and phase-12 (:19781+) -- lands in `sink_records`, and the
  graph-evaluation cascade is the only place a sink becomes a finding. The guard is wired there, once,
  ahead of the synthetic-source shortcuts (`p11_source_id`, `p3_source_id`, `p4_source_id`), because
  a LiteLLM row registered with `p4_source_id: OS_COMMAND_EXECUTION` used to reach its edge before
  the argv question could be asked.

The narrowing this gate locks
-----------------------------
`_cwe78_argv_execve_inert` (ast_scanner.py:7213) answers True only for a call shape where no parser
exists between the bytes and `execve`. Four vetoes, each a named method so each can be falsified:

  * `_cwe78_shell_is_off` -- `shell=` absent or statically False. `shell=flag` is unknown and unknown
    keeps the finding;
  * `_cwe78_resolve_argv_sequence` -- the argv is one List/Tuple the source wrote, optionally behind
    a name bound exactly once. `shlex.split(...)`, an attribute slot and a twice-written name resolve
    to nothing;
  * `_cwe78_argv_program_is_internal` -- the first slot is not an interpreter (`sh`, `bash`,
    `python3.11`, `cmd.exe`), not `sys.executable`, not attacker-chosen, not a leading splat, and no
    untrusted `executable=`;
  * `_cwe78_argv_has_script_payload` -- no `-c` / `-m` / `/c` / `-Command` carries a payload the
    source did not write, and no element is splatted.

Measured evidence behind the numbers
------------------------------------
  blessed overlap     : CWE-78 keys -- 15 in parity, 0 in Big-8 (TIER 1). TIER 5 reads each blessed
                        line back and asks the guard about it: 11 of the 15 are sink lines (all
                        `shell=True` or `os.system`) and 4 are the source half of a cross-file pair,
                        where no CWE-78 record exists at all. The guard answers inert on 0 of them.
  fixtures            : 26 shapes -- 5 loud->quiet rows the guard itself earns, 17 must-report rows,
                        and 4 quiet at both seals (`argv_keyword_args`, `argv_literal_payload_after_dash_c`,
                        `shell=<unknown>`, `executable=<request>`). Those 4 are listed as ALREADY_QUIET,
                        not as wins: they are silent on HEAD's bytes too, and the two `=` keyword rows
                        come from the lineage prune at ast_scanner.py:25303 reading argv only.
                        `argv_keyword_args` is why TIER 6 asks the `args=` spelling directly.
  the quoting bug this gate found: `ast.unparse` renders a literal with its quotes, so `["python3.11",
                        script]` read as a program named `'python3.11'`, matched no interpreter, and
                        went silent. TIER 3 caught it as two MISMATCH rows on the first run and
                        TIER 6 now pins `_cwe78_expr_text` on the shipped helper.
  LiteLLM A/B         : whole-file re-scan of every file holding a CWE-78 or CWE-208 row, HEAD's
                        engine beside this one, keys compared exactly (scratch/_c78_c208_ab.py);
                        RETIRED and ADDED are both measured. ADDED must be 0.

Seal semantics - `CWE78_SEAL`
-----------------------------
  'shipped'   : the argv rows MUST be silent and every tripwire MUST stay loud.
  'abstained' : the engine before this guard landed -- every row that is not already quiet MUST be
                loud. A row that goes quiet while the seal says abstained means a narrowing landed
                without a contract.
Override with TCS_CWE78_SEAL=abstained and point TCS_CWE78_ENGINE at an alternative ast_scanner.py.
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

if os.environ.get('TCS_CWE78_ENGINE'):
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        'ast_scanner', os.environ['TCS_CWE78_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys, scan_rows  # noqa: E402

SEAL_TARGETS = ('abstained', 'shipped')
CWE78_SEAL = os.environ.get('TCS_CWE78_SEAL', 'shipped')

# The blessed CWE-78 population, counted from the frozen baselines themselves.
CWE78_LOCKED = {'parity': 15, 'big8': 0}

REQ = 'from flask import request\n'

# (label, source, expect_when_abstained, expect_when_shipped)
# 'loud' = a CWE-78 finding is required in that module, 'quiet' = none is allowed.
SHAPES = [
    # ---- argv sequences with no shell: execve takes each element verbatim ----
    ('argv_request_value', REQ + '''
import subprocess
host = request.args.get("h")
subprocess.run(["ping", "-c", "1", host])
''', 'loud', 'quiet'),
    ('argv_popen_tuple', REQ + '''
import subprocess
name = request.args.get("n")
subprocess.Popen(("docker", "logs", name))
''', 'loud', 'quiet'),
    ('argv_name_bound_once', REQ + '''
import subprocess
arg = request.args.get("a")
cmd = ["tool", "run", arg]
subprocess.run(cmd)
''', 'loud', 'quiet'),
    ('argv_keyword_args', REQ + '''
import subprocess
term = request.args.get("t")
subprocess.check_output(args=["grep", term, "/var/log/app.log"])
''', 'quiet', 'quiet'),
    ('argv_fstring_element', REQ + '''
import subprocess
name = request.args.get("n")
subprocess.run(["convert", f"-density {name}", "in.png", "out.png"])
''', 'loud', 'quiet'),
    ('argv_aliased_import', REQ + '''
from subprocess import run
from flask import request
path = request.args.get("p")
run(["stat", path])
''', 'loud', 'quiet'),
    ('argv_literal_payload_after_dash_c', REQ + '''
import sys, subprocess
subprocess.run([sys.executable, "-c", "print(1)"])
''', 'quiet', 'quiet'),
    # ---- the four shapes where a parser does exist, and the call is not argv at all ----
    ('shell_true_fstring', REQ + '''
import subprocess
host = request.args.get("h")
subprocess.run(f"ping -c 1 {host}", shell=True)
''', 'loud', 'loud'),
    ('shell_true_list', REQ + '''
import subprocess
host = request.args.get("h")
subprocess.run(["ping", host], shell=True)
''', 'loud', 'loud'),
    ('os_system_concat', REQ + '''
import os
from flask import request
os.system("grep " + request.args.get("q") + " app.log")
''', 'loud', 'loud'),
    ('os_popen_read', REQ + '''
import os
from flask import request
os.popen("cat " + request.args.get("f")).read()
''', 'loud', 'loud'),
    # ---- a whole command built as one string: the mandate names these loud, and the guard cannot
    # ---- reach them (no List/Tuple to resolve), which is what 'loud at both seals' proves ----
    ('command_is_fstring', REQ + '''
import subprocess
host = request.args.get("h")
subprocess.run(f"ping -c 1 {host}")
''', 'loud', 'loud'),
    ('command_is_percent_format', REQ + '''
import subprocess
host = request.args.get("h")
subprocess.run("ping -c 1 %s" % host)
''', 'loud', 'loud'),
    ('command_is_dot_format', REQ + '''
import subprocess
host = request.args.get("h")
subprocess.run("ping -c 1 {}".format(host))
''', 'loud', 'loud'),
    ('argv_from_shlex_split', REQ + '''
import subprocess, shlex
from flask import request
subprocess.run(shlex.split(request.args.get("c")))
''', 'loud', 'loud'),
    ('argv_program_is_request_value', REQ + '''
import subprocess
from flask import request
prog = request.args.get("p")
subprocess.run([prog, "status"])
''', 'loud', 'loud'),
    ('argv_bash_dash_c_payload', REQ + '''
import subprocess
from flask import request
code = request.args.get("c")
subprocess.run(["bash", "-c", code])
''', 'loud', 'loud'),
    ('argv_python_interpreter_program', REQ + '''
import subprocess
from flask import request
script = request.args.get("s")
subprocess.run(["python3.11", script])
''', 'loud', 'loud'),
    ('argv_sys_executable_dash_c_code', REQ + '''
import sys, subprocess
from flask import request
code = request.args.get("c")
subprocess.run([sys.executable, "-c", code])
''', 'loud', 'loud'),
    ('argv_tool_dash_c_payload', REQ + '''
import subprocess
from flask import request
code = request.args.get("c")
subprocess.run(["lua", "-e", code])
''', 'loud', 'loud'),
    ('argv_tool_with_interpreter_prefix', REQ + '''
import subprocess
from flask import request
path = request.args.get("p")
subprocess.run(["shellcheck", path])
''', 'loud', 'loud'),
    ('argv_splat_tail', REQ + '''
import subprocess
from flask import request
extra = request.args.getlist("e")
subprocess.run(["docker", "ps", *extra])
''', 'loud', 'loud'),
    ('argv_name_written_twice', REQ + '''
import subprocess
from flask import request
arg = request.args.get("a")
cmd = ["tool", "run"]
cmd = [arg, "run"]
subprocess.run(cmd)
''', 'loud', 'loud'),
    ('argv_attribute_slot', REQ + '''
import subprocess
from flask import request
request.args.argv = ["tool", "run"]
subprocess.run(request.args.argv)
''', 'loud', 'loud'),
    # ---- quiet before this guard existed: the lineage prune answers for them, argv only ----
    ('shell_keyword_unknown', REQ + '''
import subprocess
flag = request.args.get("s")
subprocess.run(["ping", "x"], shell=flag)
''', 'quiet', 'quiet'),
    ('executable_keyword_from_request', REQ + '''
import subprocess
from flask import request
bin_ = request.args.get("b")
subprocess.run(["x", "y"], executable=bin_)
''', 'quiet', 'quiet'),
]

FP_ROWS = [row for row in SHAPES if row[2] == 'loud' and row[3] == 'quiet']
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == 'loud']
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == 'quiet']
_BY_LABEL = {row[0]: row[1] for row in SHAPES}

# One axis per row, with the two arms on opposite sides of it. Every clean arm is a row the guard
# itself silences (FP_ROWS: measured loud on HEAD's bytes, quiet on these), so a pair that starts
# agreeing only because both arms went quiet for some other reason cannot pass this tier.
PAIRS = [
    ('no shell vs shell=True on the same argv', 'argv_request_value', 'shell_true_list'),
    ('fixed argv vs an interpreter running attacker bytes', 'argv_popen_tuple',
     'argv_bash_dash_c_payload'),
    ('name bound once vs name written twice', 'argv_name_bound_once', 'argv_name_written_twice'),
    ('attacker bytes in a slot vs attacker bytes choosing the program', 'argv_fstring_element',
     'argv_program_is_request_value'),
    ('tool program vs interpreter program', 'argv_aliased_import',
     'argv_python_interpreter_program'),
]

# Programs that must always be read as an interpreter, because naming one is naming a parser.
INTERPRETERS_REQUIRED = ('sh', 'bash', 'zsh', 'dash', 'cmd', 'cmd.exe', 'powershell', 'pwsh',
                         'python', 'python3', 'python3.11', 'pypy3', 'node', 'ruby', 'perl', 'php',
                         'lua')
# Programs that must never match, or the exemption is really a shell check in disguise.
NON_INTERPRETERS = ('docker', 'git', 'grep', 'convert', 'ping', 'tool', 'stat', 'kubectl',
                    'ffmpeg', 'ls', 'bash-completion', 'python-venv-wrapper')
# Tools whose *name* starts with an interpreter word. The prefix regex reads them as interpreters, so
# they stay reported -- the loud direction, and asserted here so that widening the table to exempt them
# has to be a decision with a re-measure behind it, never a regex typo.
INTERPRETER_OVERBLOCKS = ('shlint', 'shellcheck', 'shfmt', 'bashunit', 'pythonrunner', 'nodeapp')
# Switches whose next element is parsed as a command or script.
FLAGS_REQUIRED = ('-c', '-m', '/c', '-Command')
FLAGS_MUST_NOT_MATCH = ('--check', '--name', '-f', '--config', '-y', '--format')


def scan_source(source):
    """One in-memory module through the real record path, as both baselines were built."""
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-78'})


def check_floors():
    """TIER 1: the blessed CWE-78 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-78'}
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-78={len(keys)} (want {CWE78_LOCKED[kind]})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != CWE78_LOCKED[kind]:
            failures.append((kind, 'CWE-78', CWE78_LOCKED[kind], len(keys),
                             'the blessed CWE-78 population moved'))
    return failures


def check_corpus():
    """TIER 2: the CWE-78 keys re-produced by a real tree scan, as an exact key set."""
    failures = []
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    live = {row for row in scan_rows('parity', tree) if row[2] == 'CWE-78'}
    frozen = {row for row in load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
              if row[2] == 'CWE-78'}
    missing = sorted(frozen - live)
    extra = sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    for row in missing:
        print(f'  MISSING  {row[0]}:{row[1]} {row[4]}')
    for row in extra:
        print(f'  NEW      {row[0]}:{row[1]} {row[4]}')
    if missing:
        failures.append((len(missing), 'frozen CWE-78 keys no longer reported'))
    if extra:
        failures.append((len(extra), 'CWE-78 keys appeared that the baseline never held'))
    return failures


def check_shapes():
    """TIER 3: the truth table, asserted against the seal this file is standing under."""
    failures = []
    for label, source, when_abstained, when_shipped in SHAPES:
        try:
            ast.parse(source)
        except SyntaxError as exc:
            print(f'  {label:32s} UNPARSEABLE {exc}')
            failures.append((label, 'shape syntax', 'parses', str(exc)))
            continue
        expected = when_abstained if CWE78_SEAL == 'abstained' else when_shipped
        found = scan_source(source)
        status = 'loud' if found else 'quiet'
        note = '; '.join(f'L{n}:{m.replace("CWE-78: ", "")}' for n, m in found)[:60]
        marker = 'ok' if status == expected else 'MISMATCH'
        print(f'  {label:32s} want={expected:5s} got={status:5s} {marker:8s} {note}')
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
        want_clean = CWE78_SEAL == 'abstained'
        agree = (a == want_clean) and b
        print(f'  {label:38s} clean_loud={a} (want {want_clean})  tripwire_loud={b} (want True)  '
              f'{"agree" if agree else "DISAGREE"}')
        if not agree:
            failures.append((label, 'pair provenance', (want_clean, True), (a, b)))
    return failures


def _call_from_source(source, cwe='CWE-78'):
    """The single subprocess call a fixture holds, as the engine sees it."""
    tree = ast.parse(source)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    return tree, calls


def _analyze(source, name):
    """The real record path for one module, returning the tracker with its sink records attached."""
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={name: source}, audit_all=True)
        tracker.analyze()
    return tracker


def check_blessed_lines():
    """TIER 5: the 15 blessed parity CWE-78 lines, read back and asked about directly.

    A corpus re-scan shows a lost key after the fact. This asks the one question the exemption can
    answer -- does the guard call itself True on a blessed line -- so a widening that reaches a true
    positive fails here before a baseline moves.

    Two kinds of blessed line exist and both are asked, in the engine's own terms:
      * the 11 sink-side rows, reached through `sink_records`, so node, scope id and line are the exact
        triple the cascade passes to the guard, not a hand-built stand-in;
      * the 4 `Cross-file leak:` rows, whose blessed line is the *source* half of a pair (an argument
        being handed to a helper, not a subprocess call). No CWE-78 record lives there, so every call
        node spanning the line is swept, under every scope id the tracker actually uses for that file.
    """
    failures = []
    rows = load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
    keys = sorted((row for row in rows if row[2] == 'CWE-78'), key=lambda r: (r[0], r[1]))
    reached, record_asks, sweep_asks, unswept = [], 0, 0, []
    for row in keys:
        path = os.path.abspath(os.path.join(ROOT, row[0]))
        if not os.path.exists(path):
            failures.append((row[0], 'blessed fixture file is not in the tree'))
            continue
        with open(path, encoding='utf-8', errors='replace') as handle:
            source = handle.read()
        lines = source.splitlines()
        index = row[1] - 1
        if not 0 <= index < len(lines):
            failures.append((row[0], row[1], 'blessed line is not in the fixture'))
            continue
        tracker = _analyze(source, row[0])
        cwe78 = lambda md: (md.get('cwe') == 'CWE-78'
                            or md.get('sink_type') in ('COMMAND_INJECTION', 'OS_COMMAND_EXECUTION')
                            or md.get('operation') in ('OS_COMMAND_EXECUTION', 'COMMAND_EXECUTION'))
        records = [r for r in tracker.sink_records if r.lineno == row[1] and cwe78(r.security_node.metadata)]
        scopes = {r.scope_id for r in tracker.sink_records} | {key[1] for key in tracker.assignments_by_scope}
        scopes |= {row[0], ''}
        asked_here = 0
        for record in records:
            asked_here += 1
            if tracker._cwe78_argv_execve_inert(record.node, record.scope_id, record.lineno):
                reached.append((row[0], row[1], 'record', lines[index].strip()[:60]))
        record_asks += len(records)
        if not records:
            tree = ast.parse(source)
            for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
                if call.lineno <= row[1] <= (getattr(call, 'end_lineno', None) or call.lineno):
                    for scope in scopes:
                        asked_here += 1
                        if tracker._cwe78_argv_execve_inert(call, scope, row[1]):
                            reached.append((row[0], row[1], 'sweep', lines[index].strip()[:60]))
                    sweep_asks += 1
        if not asked_here:
            unswept.append((row[0], row[1]))
    print(f'  blessed CWE-78 keys={len(keys)}  asks_on_sink_records={record_asks}  '
          f'asks_on_cross_file_source_lines={sweep_asks}  answers_inert={len(reached)}')
    for leaf, line, kind, text in reached:
        print(f'  REACHES[{kind}]  {leaf[-46:]}:{line} :: {text}')
    for leaf, line in unswept:
        print(f'  NO CALL AT BLESSED LINE  {leaf[-46:]}:{line}')
    if reached:
        failures.append((len(reached), 'the execve guard reaches blessed parity CWE-78 lines'))
    if unswept:
        failures.append((len(unswept), 'a blessed CWE-78 line could not be asked about at all'))
    if record_asks < 11:
        failures.append((record_asks, 11, 'fewer blessed sink lines hold a CWE-78 record than measured'))
    if sweep_asks < 4:
        failures.append((sweep_asks, 4, 'every cross-file source row must be swept at least once'))
    return failures


def check_vocabulary():
    """TIER 6: the three tables, the call set and the wiring, pinned so an edit is a decision."""
    failures = []
    regex = getattr(ast_scanner, '_CWE78_INTERPRETER_NAME_RE', None)
    if not isinstance(regex, re.Pattern):
        return [('_CWE78_INTERPRETER_NAME_RE', 'exists', 'compiled pattern', regex)]
    for name in INTERPRETERS_REQUIRED:
        if not regex.match(name):
            failures.append(('interpreter must match', name))
    for name in NON_INTERPRETERS:
        if regex.match(name):
            failures.append(('tool name must not match', name))
    for name in INTERPRETER_OVERBLOCKS:
        if not regex.match(name):
            failures.append(('interpreter-prefix over-block is gone -- the safe direction was '
                             'pinned here so opening it is a decision', name))
    flags = getattr(ast_scanner, 'CWE78_SHELL_PARSING_FLAGS', None)
    if flags is None:
        failures.append(('CWE78_SHELL_PARSING_FLAGS', 'exists'))
    else:
        for flag in FLAGS_REQUIRED:
            if flag not in flags:
                failures.append(('flag required', flag))
        for flag in FLAGS_MUST_NOT_MATCH:
            if flag in flags:
                failures.append(('flag must not be a script switch', flag))
    calls = getattr(ast_scanner, 'CWE78_ARGV_EXEC_CALLS', None)
    if calls is None:
        failures.append(('CWE78_ARGV_EXEC_CALLS', 'exists'))
    else:
        for entry in ('subprocess.run', 'subprocess.Popen', 'subprocess.check_output'):
            if entry not in calls:
                failures.append(('argv call required in table', entry))
        for entry in ('os.system', 'os.popen', 'os.execlp', 'asyncio.create_subprocess_shell'):
            if entry in calls:
                failures.append(('shell-taking call must stay out of the argv table', entry))
    programs = getattr(ast_scanner, 'CWE78_INTERPRETER_PROGRAM_EXPRS', None)
    if not programs or 'sys.executable' not in programs:
        failures.append(('sys.executable must count as an interpreter program', programs))
    # `ast.unparse` renders a literal with its quotes, and `"python3.11"` is the commonest way to spell
    # an interpreter. If the program slot is read as source text the interpreter table is dead and the
    # exemption silently widens -- so the lowering itself is pinned, on the shipped helper.
    text = ast_scanner.TaintTracker._cwe78_expr_text(ast.parse('"Python3.11"').body[0].value)
    print(f'  program slot lowering: "Python3.11" -> {text!r}')
    if text != 'python3.11':
        failures.append(('_cwe78_expr_text must lower a string literal to its own value', text))
    # The `args=` spelling never reaches TIER 3 as a loud->quiet row (the engine does not emit it), so
    # the keyword path is exercised directly here rather than left untested.
    kw_source = _BY_LABEL['argv_keyword_args']
    kw_tracker = _analyze(kw_source, 'm.py')
    kw_scope = next(iter({key[1] for key in kw_tracker.assignments_by_scope}), 'm.py')
    kw_calls = [n for n in ast.walk(ast.parse(kw_source)) if isinstance(n, ast.Call)]
    kw_inert = [kw_tracker._cwe78_argv_execve_inert(c, kw_scope, c.lineno) for c in kw_calls]
    print(f'  argv behind the `args=` keyword answered inert: {any(kw_inert)}')
    if not any(kw_inert):
        failures.append(('subprocess.check_output(args=[...]) must be answered by the guard', kw_inert))
    # Wiring: the guard is asked once, in the cascade, ahead of every synthetic-source shortcut, so
    # no emitter can register a CWE-78 finding that never meets the question.
    try:
        body = inspect.getsource(ast_scanner.TaintTracker)
    except (OSError, TypeError) as exc:
        failures.append(('engine source readable', type(exc).__name__))
        return failures
    cascade = body.split('Graph evaluation cascade')[-1].split('def ')[0]
    hits = cascade.count('_cwe78_argv_execve_inert(')
    order_ok = hits == 1 and cascade.find('_cwe78_argv_execve_inert(') < cascade.find('p4_source_id')
    print(f'  guard calls in the cascade={hits}  ahead_of_p4_shortcut={order_ok}')
    if not order_ok:
        failures.append(('guard must be called once in the cascade, before p4_source_id', hits))
    print(f'  interpreters={len(INTERPRETERS_REQUIRED)} must-match, '
          f'{len(NON_INTERPRETERS)} must-not-match  flags={len(flags or ())}  argv calls={len(calls or ())}')
    return failures


def main() -> int:
    if CWE78_SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {CWE78_SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-78 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the corpus behind those keys, scanned live:')
    failures += check_corpus()
    print(f'TIER 3 - truth table under seal={CWE78_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4 - one axis, two arms, both moved by this guard:')
    failures += check_pairs()
    print('TIER 5 - the 15 blessed lines, asked about directly:')
    failures += check_blessed_lines()
    print('TIER 6 - interpreter table, flag table, argv-call table and wiring:')
    failures += check_vocabulary()
    print(f'\nseal={CWE78_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'pairs={len(PAIRS)} locked_cwe78={sum(CWE78_LOCKED.values())} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-78 execve predicate no longer matches its measured evidence. '
              'Restore the answer or update the seal with a re-measured truth table; never re-bless a '
              'baseline -- 15 blessed parity CWE-78 keys are shell=True or os.system and the guard '
              'must stay blind to every one of them.')
        return 1
    print(f'VERDICT: PASS - all {sum(CWE78_LOCKED.values())} blessed CWE-78 keys still reported, '
          f'parity corpus exact-set, {len(FP_ROWS)} argv shapes silent, '
          f'{len(MUST_REPORT_ROWS)} shell/os.system/interpreter shapes reported, '
          f'{len(PAIRS)} pairs agreeing.')
    return 0


MUTATIONS = {
    'delete_argv_guard': {
        'what': 'the guard always answers "not inert" -- every retired argv row comes back',
        'rows': [row[0] for row in FP_ROWS],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_cwe78_argv_execve_inert',
                                 lambda self, *args: False),
    },
    'argv_guard_always_true': {
        'what': 'the guard answers "inert" for every call -- the widest version of the rule the '
                'prompt asked for, and the reason the four vetoes exist',
        'rows': ['shell_true_list', 'shell_true_fstring', 'os_system_concat', 'os_popen_read',
                 'command_is_fstring', 'command_is_percent_format', 'command_is_dot_format',
                 'argv_bash_dash_c_payload', 'argv_splat_tail', 'argv_program_is_request_value',
                 'argv_from_shlex_split', 'argv_python_interpreter_program'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_cwe78_argv_execve_inert',
                                 lambda self, *args: True),
    },
    'ignore_shell_keyword': {
        'what': 'drop the shell= veto, so `subprocess.run([...], shell=True)` reads as argv execution',
        'rows': ['shell_true_list'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_cwe78_shell_is_off',
                                 lambda self, node, scope_id, lineno: True),
    },
    'no_sequence_resolution': {
        'what': 'refuse to follow a name to its list -- the 30 name-bound argv rows come back',
        'rows': ['argv_name_bound_once'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_cwe78_resolve_argv_sequence',
                                 lambda self, expr, scope_id, lineno, depth=0:
                                 expr if isinstance(expr, (ast.List, ast.Tuple)) else None),
    },
    'sequence_resolution_accepts_anything': {
        'what': 'treat every expression as its own argv sequence, so `shlex.split(...)` and an '
                'attribute slot are silently exempt',
        'rows': ['argv_from_shlex_split', 'argv_name_written_twice', 'argv_attribute_slot'],
        'apply': lambda: setattr(
            ast_scanner.TaintTracker, '_cwe78_resolve_argv_sequence',
            lambda self, expr, scope_id, lineno, depth=0: expr if getattr(expr, 'elts', None)
            else (ast.parse('["a", "b"]').body[0].value if not isinstance(
                expr, (ast.List, ast.Tuple)) else expr)),
    },
    'ignore_program_provenance': {
        'what': 'stop asking who chose the program -- `[request_value, "status"]` becomes inert',
        'rows': ['argv_program_is_request_value', 'argv_bash_dash_c_payload',
                 'argv_python_interpreter_program', 'argv_sys_executable_dash_c_code',
                 'argv_tool_with_interpreter_prefix', 'argv_splat_tail'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_cwe78_argv_program_is_internal',
                                 lambda self, elements, scope_id, lineno: True),
    },
    'ignore_script_payload_flag': {
        'what': 'stop reading `-c` / `-m` as a parser switch, so an attacker-chosen script is argv',
        'rows': ['argv_tool_dash_c_payload'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_cwe78_argv_has_script_payload',
                                 staticmethod(lambda elements: False)),
    },
    'read_program_slot_as_source_text': {
        'what': 'go back to ast.unparse for the program slot, so a literal argv element arrives with '
                'its quotes and no interpreter name ever matches -- the exact defect TIER 3 found',
        'rows': ['argv_python_interpreter_program', 'argv_tool_dash_c_payload',
                 'argv_bash_dash_c_payload', 'argv_tool_with_interpreter_prefix'],
        'apply': lambda: setattr(ast_scanner.TaintTracker, '_cwe78_expr_text',
                                 staticmethod(lambda expr: (ast.unparse(expr) or '').strip().casefold()))},
    'blank_interpreter_regex': {
        'what': 'empty the interpreter table -- `python3.11 script` is just a program name again',
        'rows': ['argv_python_interpreter_program', 'argv_bash_dash_c_payload',
                 'argv_tool_dash_c_payload', 'argv_tool_with_interpreter_prefix'],
        'apply': lambda: setattr(ast_scanner, '_CWE78_INTERPRETER_NAME_RE',
                                 re.compile(r'(?!x)x')),
    },
}


def run_mutation(name: str) -> int:
    """Apply one in-memory mutation and run the real gate over it. Exit 1 = the mutation was caught."""
    spec = MUTATIONS[name]
    print(f"MUTATION {name}: {spec['what']}")
    print(f"  rows that must move: {', '.join(spec['rows'])}")
    spec['apply']()
    tiers = []
    # TIER 1 and 2 read the frozen baselines and re-scan the whole `benchmark/` tree; an in-memory
    # patch of a guard cannot move a blessed key the corpus does not hold, and running them here
    # would make each mutation cost a full tree scan. The truth table, the pairs and the tables are
    # what a guard is falsified on.
    try:
        print(f'TIER 3 - truth table under seal={CWE78_SEAL!r}:')
        tiers.append(('T3', check_shapes()))
        print('TIER 4 - one axis, two arms, both moved by this guard:')
        tiers.append(('T4', check_pairs()))
        print('TIER 5 - the 15 blessed lines, asked about directly:')
        tiers.append(('T5', check_blessed_lines()))
        print('TIER 6 - interpreter table, flag table, argv-call table and wiring:')
        tiers.append(('T6', check_vocabulary()))
    except Exception as exc:  # a mutation that cannot even run is not a falsification
        print('MUTATION ERROR: ' + type(exc).__name__ + ': ' + str(exc))
        print(
            '\n' + 'FALSIFICATION VERDICT (' + name + '): ERROR - the mutation is broken, '
            'so it proves nothing either way (exit 2, not a pass)')
        return 2
    failures = [item for _label, rows in tiers for item in rows]
    for item in failures[:12]:
        print(f'  !! {item}')
    caught = bool(failures)
    counts = ' '.join(f'{label}={len(rows)}' for label, rows in tiers if rows)
    print(f'{" + BSN + "}FALSIFICATION VERDICT ({name}): '
          + (f'CAUGHT on {len(failures)} row(s) [{counts}] -- '
             + ', '.join(sorted({str(f[0]) for f in failures})[:6])
             if caught else 'MISSED - the guard is decorative, the engine still answers its own '
                            'truth table'))
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

