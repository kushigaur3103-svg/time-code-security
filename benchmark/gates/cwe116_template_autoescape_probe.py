"""CWE-116 truth table: which `Environment` calls the engine answers, and what a safe narrowing may cover.

Why this gate exists
--------------------
CWE-116 `TEMPLATE_AUTOESCAPE_DISABLED` is 135 of 2,128 findings on odoo/odoo@17.0 at engine
f7d144f2, and the audit behind this file (scratch/_c116_fetch.py + _c116_provenance.py over the 93
source files behind those rows, pinned at sha dca5cd22) split them by asking the modules themselves
what the name `Environment` resolves to:

    134  Odoo ORM  `api.Environment(cr, uid, {})`           -> not a template engine at all
      1  `jinja2.Environment()`  odoo/cli/scaffold.py:88    -> real jinja2, stays loud

The 134 are a name collision, not a template-loader decision: `odoo.api.Environment` is the ORM
record environment, it takes a cursor/uid/context, and it has never rendered a template. The one
real jinja2 environment is a module scaffolder whose render whitelist includes `.html`
(odoo/cli/scaffold.py:136), so it may render web templates and must keep its finding.

The emitter
-----------
  path A  ast_scanner.py:14636-14643   any call whose *last* callee name is `Environment` and that has
                                       no `autoescape` kwarg (`CLUSTER1_AUTOESCAPE_KEYS`, :1634), or a
                                       kwarg whose value `_c116_autoescape_is_dynamic` (:14496) reads
                                       out of caller options or evaluates to a falsy constant
  path B  ast_scanner.py:14667-14672   any dict literal with `"autoescape": False/None`
  (a third site, ast_scanner.py:20512-20517, emits the same label under CWE-79; it is 0 rows in the
   arena and is not this file's contract)

Path A fires on a *spelling*, not on a template. That is the whole defect: the engine asks "is the
callee called Environment?", never "is the callee jinja2's Environment?".

The narrowing this gate locks
-----------------------------
One positive allowlist on provenance the engine already resolves - `_c1_call_names` (:14383) asks
`resolve_canonical_name` (:4447), and the import table `self.imports[mod]` holds the binding. Emit
unless the callee is *proven* not to be jinja2:

  1. the binding chain is import-backed and lands on `odoo.api.Environment`:
       `api.Environment`  with imports['api'] == 'odoo.api'          (covers `from odoo import api`
                                                                      and `from .. import api`)
       `odoo.api.Environment` with imports['odoo'] == 'odoo'
       bare `Environment` (or an alias) with imports[name] == 'odoo.api.Environment'
     -> 133 of the 134 measured rows
  2. bare unresolved `Environment` in a module that defines its own top-level `class Environment`
     and imports no `jinja2` -> 1 row (odoo/api.py:586, the ORM class calling its own constructor)

Everything else - unknown bare names, unproven `api.Environment`, jinja2 under any spelling,
`autoescape=...` handling, path B - keeps its current answer. A name that does not resolve stays
loud: the allowlist can only *remove* a finding when the import table proves which class it is.

Measured evidence behind the numbers
------------------------------------
  arena rows                 : 135, all path A, all with zero `autoescape` kwargs
                               (100 `api.` + 32 `odoo.api.` + 2 bare + 1 `jinja2` receiver spelling;
                               101 production / 34 tests; 0 of the 93 files is .html)
  provenance                 : 133 canonical `odoo.api.Environment` + 1 own-class = 134 ORM,
                               1 `jinja2.Environment` (scaffold.py:88, whitelist with .html at :136)
  overlap with blessed keys  : 0 - 0 CWE-116 keys in parity (425) and Big-8 (119)
  refused, with evidence     : the whole extension class named in the task (`.txt`/`.xml`/`.csv`/
                               `.sql` loaders, text/plain email) is 0 of these 135 rows, and
                               exempting a live jinja2 environment because its *visible* template
                               loads are non-HTML cannot be bounded here - the env object can be
                               handed to another module that renders .html. Those shapes stay loud
                               below so the refusal is recorded in the truth table, not just in prose.
  gap closed in this revision   : `Environment(autoescape=lambda n: False)` used to be silent - the
                                  lambda is neither a literal nor a mapping read, so path A had no
                                  question left to ask. It is now reported: a lambda whose body folds
                                  to a falsy literal is `autoescape=False` written as a callable. Four
                                  falsy-callable shapes are asserted loud (`False`, `0`, `None`, `{}`)
                                  and five that must not be swept up are asserted silent (`True`,
                                  `n.endswith('.html')`, a truthy string, a free name, a module-level
                                  function reference). 0 of the 135 arena rows are any of these, and
                                  `autoescape=lambda` appears in no corpus or fixture file (grep over
                                  the repo: only this gate and the engine), so the flip cannot move a
                                  blessed key in either direction.
  still not claimed             : `autoescape=escapes` where `escapes` is a module function returning
                                  False is silent, and stays silent - deciding it needs inter-
                                  procedural analysis, and guessing would print a finding on every
                                  selective-autoescape environment in the world. Recorded as a row so
                                  the limit is measured rather than invisible.

Seal semantics - `CWE116_SEAL`
------------------------------
  'shipped' (today) : the five proven-ORM shapes MUST be silent, every must-report row MUST stay
            loud, and a falsy-body lambda MUST now be reported.
  'abstained'       : the five proven-ORM shapes MUST still be loud. If they go quiet while the seal
            says abstained, a narrowing landed without updating this contract.
Either way a mismatch is exit 1.
"""
from __future__ import annotations

import contextlib
import io
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

if os.environ.get('TCS_CWE116_ENGINE'):
    # falsification hook: load an alternative ast_scanner.py and let the gate argue against it. With
    # `CWE116_SEAL = 'shipped'` and the pre-narrowing engine, 0/N proven-ORM targets go silent and
    # the gate exits 1, so deleting the allowlist from ast_scanner.py cannot pass unnoticed. The
    # module is registered under its real name because `dataclass(slots=True)` and `cli` both resolve
    # the engine through sys.modules, so an override that is not registered cannot even be imported.
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        'ast_scanner', os.environ['TCS_CWE116_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys, scan_rows  # noqa: E402

CWE116_SEAL = 'shipped'   # 'abstained' = the engine before the provenance allowlist landed
SEAL_TARGETS = ('abstained', 'shipped')

# The blessed CWE-116 population, counted from the frozen baselines themselves.
CWE116_LOCKED = {'parity': 0, 'big8': 0}

ODOO_API = 'from odoo import api\n'
ODOO = 'import odoo\n'
ODOO_IMPORT = 'from odoo.api import Environment\n'
ODOO_ALIAS = 'from odoo.api import Environment as OrmEnvironment\n'
JINJA = 'import jinja2\nfrom jinja2 import FileSystemLoader\n'
JINJA_BARE = 'from jinja2 import Environment\nfrom jinja2 import FileSystemLoader\n'
JINJA_ALIAS = 'from jinja2 import Environment as JEnv\n'
EMAIL = 'from email.mime.text import MIMEText\n'


def wrap(header: str, body: str) -> str:
    return header + '\n\ndef handler(cr, uid, name):\n    ' + body.replace('\n', '\n    ') + '\n'


# (label, source, expect_when_abstained, expect_when_shipped)
# 'loud' = a CWE-116 finding is required on that module, 'quiet' = none is allowed.
SHAPES = [
    # ---- proven ORM: the import table says which class this is, and it is not jinja2 ----
    ('orm_api_receiver', wrap(ODOO_API, 'env = api.Environment(cr, uid, {})'), 'loud', 'quiet'),
    ('orm_dotted_receiver', wrap(ODOO, 'env = odoo.api.Environment(cr, uid, {}, True)'),
     'loud', 'quiet'),
    ('orm_imported_bare', wrap(ODOO_IMPORT, 'env = Environment(cr, uid, {})'), 'loud', 'quiet'),
    ('orm_imported_alias', wrap(ODOO_ALIAS, 'env = OrmEnvironment(cr, uid, {})'),
     'loud', 'quiet'),
    # module-level class, exactly like odoo/api.py:584-587 - the method calls its own constructor
    ('orm_own_class_constructor',
     ('class Environment:\n'
      '    def __init__(self, cr, uid, context):\n'
      '        self.cr = cr\n'
      '\n'
      '    def copy(self, cr):\n'
      '        return Environment(cr, self.uid, {})\n'),
     'loud', 'quiet'),
    # ---- the bad input: a real jinja2 environment building a web page stays loud ----
    ('jinja_html_no_arg', wrap(JINJA, "jinja2.Environment().get_template('page.html')"),
     'loud', 'loud'),
    ('jinja_html_bare_import', wrap(JINJA_BARE, "Environment().get_template('page.html')"),
     'loud', 'loud'),
    ('jinja_html_from_string',
     wrap(JINJA, "env = jinja2.Environment()\nenv.from_string('<b>{{ x }}</b>')"),
     'loud', 'loud'),
    ('jinja_htm_loader', wrap(JINJA, (
        "env = jinja2.Environment(loader=FileSystemLoader('templates'))\n"
        "env.get_template('index.htm').render()")), 'loud', 'loud'),
    ('mixed_imports_jinja2_call', wrap('from odoo.api import Environment as OrmEnvironment\n'
                                      + JINJA, (
        "env = jinja2.Environment(loader=FileSystemLoader('t'))\n"
        "env.get_template('page.html')")), 'loud', 'loud'),
    # ---- a name that is not proven stays loud, however familiar it looks ----
    ('unknown_bare_environment', wrap('', "env = Environment().get_template('page.html')"),
     'loud', 'loud'),
    ('unproven_api_receiver', wrap('', 'env = api.Environment(cr, uid, {})'), 'loud', 'loud'),
    ('unproven_dotted_receiver', wrap('', 'env = odoo.api.Environment(cr, uid, {})'),
     'loud', 'loud'),
    ('local_class_but_jinja_imported', wrap(JINJA_ALIAS + (
        'class Environment:\n'
        '    pass'), 'env = Environment(cr, uid, {})'), 'loud', 'loud'),
    # ---- path B is untouched by the narrowing ----
    ('dict_autoescape_false', wrap('', "TEMPLATES = [{'OPTIONS': {'autoescape': False}}]"),
     'loud', 'loud'),
    # ---- refused: 0 of the 135 arena rows are these shapes, and the exemption cannot be bounded
    #      (the environment object can leave the module), so they keep their finding ----
    ('jinja_txt_loader',
     wrap(JINJA, "jinja2.Environment().get_template('mail_body.txt').render(name=name)"),
     'loud', 'loud'),
    ('jinja_xml_loader', wrap(JINJA, (
        "env = jinja2.Environment(loader=FileSystemLoader('t'))\n"
        "env.get_template('report.xml')")), 'loud', 'loud'),
    ('jinja_csv_loader', wrap(JINJA, "jinja2.Environment().get_template('export.csv')"),
     'loud', 'loud'),
    ('jinja_plain_email', wrap(JINJA + EMAIL, (
        "body = jinja2.Environment().from_string('Hi {{ n }}').render(n=name)\n"
        "msg = MIMEText(body, 'plain')")), 'loud', 'loud'),
    # ---- already silent, and required to stay silent at both seals ----
    ('jinja_autoescape_true', wrap(JINJA,
                                   "jinja2.Environment(autoescape=True).get_template('a.html')"),
     'quiet', 'quiet'),
    ('jinja_autoescape_false_explicit', wrap(JINJA,
                                             "jinja2.Environment(autoescape=False)"
                                             ".get_template('a.html')"), 'quiet', 'quiet'),
    ('jinja_select_autoescape_html', wrap(JINJA, (
        "flag = jinja2.select_autoescape(['html'])\n"
        "env = jinja2.Environment(autoescape=flag)")), 'quiet', 'quiet'),
    ('jinja_sql_loader_autoescape_false', wrap(
        JINJA, "jinja2.Environment(autoescape=False).get_template('query.sql')"),
     'quiet', 'quiet'),
    # ---- callable autoescape: the gap this file used to record, now closed ----
    # `autoescape=lambda n: False` is `autoescape=False` with a callable around it: jinja2 calls it
    # with the template name and gets a falsy value back for every name, so nothing is escaped. The
    # engine used to read a lambda as "not a literal, not a mapping read" and stay silent.
    ('jinja_autoescape_lambda_false', wrap(JINJA, (
        "env = jinja2.Environment(autoescape=lambda n: False)\n"
        "env.get_template('page.html')")), 'quiet', 'loud'),
    ('jinja_autoescape_lambda_zero', wrap(JINJA, (
        "env = jinja2.Environment(autoescape=lambda name, template_name=None: 0)\n"
        "env.get_template('page.html')")), 'quiet', 'loud'),
    ('jinja_autoescape_lambda_bare_none', wrap(JINJA, (
        "env = jinja2.Environment(autoescape=lambda: None)\n"
        "env.get_template('page.html')")), 'quiet', 'loud'),
    ('jinja_autoescape_lambda_empty_dict', wrap(JINJA, (
        "env = jinja2.Environment(autoescape=lambda n: {})\n"
        "env.get_template('page.html')")), 'quiet', 'loud'),
    # ---- and the callables that DO escape, which must not be swept up by the new branch ----
    # A lambda whose body is a real decision is `select_autoescape` written inline. Reporting those
    # would turn a safe configuration into a finding, which is the false-positive half of this rule.
    ('jinja_autoescape_lambda_true', wrap(JINJA, (
        "env = jinja2.Environment(autoescape=lambda n: True)\n"
        "env.get_template('page.html')")), 'quiet', 'quiet'),
    ('jinja_autoescape_lambda_endswith', wrap(JINJA, (
        "env = jinja2.Environment(autoescape=lambda n: n.endswith('.html'))\n"
        "env.get_template('page.html')")), 'quiet', 'quiet'),
    ('jinja_autoescape_lambda_truthy_str', wrap(JINJA, (
        "env = jinja2.Environment(autoescape=lambda n: 'yes')\n"
        "env.get_template('page.html')")), 'quiet', 'quiet'),
    ('jinja_autoescape_lambda_name', wrap(JINJA, (
        "flag = True\nenv = jinja2.Environment(autoescape=lambda n: flag)\n"
        "env.get_template('page.html')")), 'quiet', 'quiet'),
    ('jinja_autoescape_func_ref', wrap(JINJA + 'def escapes(name):\n    return False\n',
                                       "env = jinja2.Environment(autoescape=escapes)\n"
                                       "env.get_template('page.html')"), 'quiet', 'quiet'),
]

FP_ROWS = [row for row in SHAPES if row[2] == 'loud' and row[3] == 'quiet']
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == 'loud']
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == 'quiet']

# The same call text with and without the proof that it is the odoo ORM. The proven arm must go
# quiet under the shipped seal; the stripped arm must stay loud, or the narrowing keyed on the
# spelling instead of the binding.
PAIRS = [
    ('api receiver', wrap(ODOO_API, 'env = api.Environment(cr, uid, {})'),
     wrap('', 'env = api.Environment(cr, uid, {})')),
    ('dotted receiver', wrap(ODOO, 'env = odoo.api.Environment(cr, uid, {})'),
     wrap('', 'env = odoo.api.Environment(cr, uid, {})')),
    ('bare imported', wrap(ODOO_IMPORT, 'env = Environment(cr, uid, {})'),
     wrap('', 'env = Environment(cr, uid, {})')),
    ('own class', ('class Environment:\n    pass\n\n\ndef handler(cr, uid):\n'
                   '    env = Environment(cr, uid, {})\n'),
     wrap('', 'env = Environment(cr, uid, {})')),
]


def scan_source(source):
    """One in-memory module through the real record path, as both baselines were built."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-116'})


def check_floors():
    """TIER 1: the blessed CWE-116 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-116'}
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-116={len(keys)} (want {CWE116_LOCKED[kind]})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != CWE116_LOCKED[kind]:
            failures.append((kind, 'CWE-116', CWE116_LOCKED[kind], len(keys),
                             'the blessed CWE-116 population moved'))
    return failures


def check_corpus():
    """TIER 2: the CWE-116 keys re-produced by a real tree scan, as an exact key set.

    In-memory single-module scanning is not how the baselines were made - it loses every row that
    depends on package context (the two `from .. import api` rows prove it: the relative binding
    resolves only when the module name carries its package). The only honest comparison is the same
    whole-tree scan `aa_parity` uses, filtered to CWE-116.
    """
    failures = []
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    live = {row for row in scan_rows('parity', tree) if row[2] == 'CWE-116'}
    frozen = {row for row in load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
              if row[2] == 'CWE-116'}
    missing = sorted(frozen - live)
    extra = sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    for row in sorted(frozen):
        print(f'  held     {row[0]}:{row[1]} {row[4]}')
    for row in extra:
        print(f'  NEW      {row[0]}:{row[1]} {row[4]}')
    if missing:
        failures.append((len(missing), 'frozen CWE-116 keys no longer reported'))
    if extra:
        failures.append((len(extra), 'CWE-116 keys appeared that the baseline never held'))
    return failures


def check_shapes():
    """TIER 3: the truth table, asserted against the seal the file is standing under."""
    failures = []
    for label, source, when_abstained, when_shipped in SHAPES:
        expected = when_abstained if CWE116_SEAL == 'abstained' else when_shipped
        found = scan_source(source)
        status = 'loud' if found else 'quiet'
        note = '; '.join(f'L{n}:{m.replace("CWE-116: ", "")}' for n, m in found)[:60]
        marker = 'ok' if status == expected else 'MISMATCH'
        print(f'  {label:34s} want={expected:5s} got={status:5s} {marker:8s} {note}')
        if status != expected:
            failures.append((label, 'seal', expected, status,
                             'the answer moved without the seal, or the seal moved without the answer'))
    return failures


def check_pairs():
    """TIER 4: the same call text with and without the import that proves what it is.

    A narrowing that keyed on the callee spelling would answer both arms alike - and would exempt
    `odoo.api.Environment(...)` in a module that never imports odoo. The stripped arm must stay loud
    at both seals; the proven arm follows the seal.
    """
    failures = []
    for label, proven, stripped in PAIRS:
        a = bool(scan_source(proven))
        b = bool(scan_source(stripped))
        want_proven = CWE116_SEAL == 'abstained'
        agree = (a == want_proven) and b
        print(f'  {label:22s} proven_loud={a} (want {want_proven})  stripped_loud={b} '
              f'(want True)  {"agree" if agree else "DISAGREE"}')
        if not agree:
            failures.append((label, 'provenance arm', (want_proven, True), (a, b)))
    return failures


def main() -> int:
    if CWE116_SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {CWE116_SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-116 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the corpus behind those keys, scanned live:')
    failures += check_corpus()
    print(f'TIER 3 - truth table under seal={CWE116_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4 - proven vs stripped provenance, same call text:')
    failures += check_pairs()
    print(f'\nseal={CWE116_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'pairs={len(PAIRS)} locked_cwe116={sum(CWE116_LOCKED.values())} '
          f'failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-116 Environment predicate no longer matches its measured '
              'evidence. Restore the answer or update the seal with a re-measured truth table; '
              'never re-bless a baseline.')
        return 1
    print(f'VERDICT: PASS - no blessed CWE-116 key exists ({CWE116_LOCKED["parity"]} in parity, '
          f'{CWE116_LOCKED["big8"]} in Big-8), corpus exact-set, '
          f'{len(FP_ROWS)} proven-ORM shapes silent, {len(MUST_REPORT_ROWS)} jinja2/unproven shapes '
          f'reported, {len(ALREADY_QUIET_ROWS)} safe shapes silent, all provenance pairs agreeing.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
