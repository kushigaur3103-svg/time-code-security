"""CWE-601 truth table: which `%`-formatted redirect targets are same-origin, and what a safe
relative-anchor proof may cover.

Why this gate exists
--------------------
CWE-601 `URL_REDIRECTION` on the `request.redirect` / `redirect` sink is 86 of 2,128 findings on
odoo/odoo@17.0 at sha dca5cd22 (scratch/_770_601_fetch.py, _601_rule.py, _601_strict.py over the
85 source files behind those rows). Classified by what the target value is built from
(scratch/_770_601/split.json):

     27  STATIC-relative  (`redirect('/web')`-shaped anchors)  -> already silent today
     22  a framework/helper-built URL passed to the sink
     12  REQUEST-derived target (`request.args`, `request.params`)
      9  RELATIVE f-string with non-request holes              -> already silent today
      7  `redirect(url, local=False)`
      6  other, read by hand
      3  STATIC-absolute / other                               -> already silent today

Then `_601_strict.py` re-ran the engine's *own* client-input predicate over every one of the 86 and
laddered them, which is the table this contract is built from:

     18  SAFE: same-origin relative head + no client-input hole -> the 18 this change removes
     32  target is not a literal-headed template (a Name, a Call, a dict read) -> unreachable
     20  a hole reads client input under `_expr_reads_client_input`            -> stays loud
      7  `local=False`                                                         -> stays loud
      5  the head is not a single-`/` relative anchor (`http://…`, `?x=…`)     -> stays loud
      3  a chained-redirect query key in the head (`?redirect=%s`)             -> stays loud
      1  the first hole could open a new authority (`"/%s%s"`)                 -> stays loud

All 18 SAFE rows are `%`-format: `"/forum/%s" % slug(forum)`,
`"/my/invoices/%s?access_token=%s" % (order.account_move.id, ...)`,
`"/web#id=%s&action=%s" % (lead_id, action_id)`.

The emitter
-----------
  ast_scanner.py:22836-22849 (redirect sweep inside `_collect_phase8_structural_findings`, :22414) --
  if the callee is a redirect sink, `target` is the
  `url`/`location`/`to` keyword or `args[0]`, and `_is_dynamic(target, ...)` (:22472) says the value
  is not a plain literal, the finding lands unless `_redirect_is_safe` (:22686) proves otherwise.
  The safety proof already contains a same-origin branch, `_same_origin_relative_target` (:22625):
  a Location that begins with exactly one `/`, whose interpolated parts carry no client input, cannot
  change the host -- the browser resolves it against the current origin.

The defect is a spelling gap, not a missing rule: that helper parses `ast.JoinedStr` (f-string) and
`ast.BinOp` with `ast.Add` (concatenation) and returns False for everything else. Odoo's dominant
spelling is `%`-formatting, so 18 rows that are the *same* value shape as an already-exempted f-string
keep their finding.

The narrowing this gate locks
-----------------------------
One new branch in `_same_origin_relative_target`, for `ast.BinOp` with `ast.Mod` only. The f-string
and concatenation branches are untouched, so nothing that is silent today can become loud and
nothing that is loud on those paths changes answer here. Inside the new branch:

  * the left operand must be an `ast.Constant` `str` (a `%`-format on a non-literal left side proves
    nothing about the anchor);
  * that literal must start with `/`, must not start with `//`, must not contain `://` or NUL, must
    be at least 2 characters, and its **second character must be a literal** -- so `"/%s%s"` is
    refused: the first hole can open a new authority (`"//" + "evil.com"` is protocol-relative);
  * the right operand contributes the holes: a `Tuple` contributes its elements and anything else is
    one hole. No extra rejection is needed for a `%(name)s` map or a starred element -- the
    fail-closed predicate below already refuses a `Dict` and a `Starred`, and the truth table locks
    both of those rows so the reuse cannot be quietly widened later;
  * the head may not contain a chained-redirect query key (`redirect=`, `next=`, `url=`, `return=`,
    `to=`) -- a same-origin page that bounces onward is not a same-origin destination. 3 arena rows
    and the 2 `mod_chained_*` rows below hold that line;
  * every hole then runs through the engine's *existing* `_expr_reads_client_input` (:22578), which
    is fail-closed: a `request`-rooted chain, an unresolved name that is not a parameter of the
    scope, a subscript, a ternary, a comprehension or anything past depth 3 counts as client input.

This branch adds a value shape, not a new route to a target: `redirect(url)` where `url` is a local
`Name` already inherits the same-origin proof today, because `_redirect_is_safe` (:22686) resolves a
Name target through the assignment chain before asking this helper. Measured on the same two spellings
(scratch/_601_namehop.py): at HEAD `name -> concat` is silent while `name -> %-format` is reported, and
with the narrowing both are silent. So `mod_name_target` is this gate's one loud->quiet row reached
through a Name, and it is reached only because the *value* became provable -- the hop itself is
pre-existing and is not widened here. `concat_name_target` holds that symmetry: it is quiet on both
seals, so a future change that makes Name targets loud again cannot be mistaken for this branch.

Measured evidence behind the numbers
------------------------------------
  arena rows                 : 86 on the redirect sink (the SARIF CWE-601 total is 123; the other 37
                               are `UNTRUSTED_REDIRECT_SOURCE` rows from ast_scanner.py:15087)
  eligible for exemption    : 18, all `%`-format with a clean hole (scratch/_770_601/strict601.json)
  arena A/B, measured       : 112 CWE-601 keys at HEAD -> 94 with this branch (scratch/_770_601_ab.py,
                               alternating rounds, both arms deterministic). Removed = 18, exactly the
                               census set; ADDED = 0; no CWE other than 601/770 moved in either arm.
  refused, with numbers      : 6 more rows were reachable by loosening the hole rule (a hole that is
                               a `Subscript`, an `IfExp` or an unresolved module global) -- refused,
                               because `_expr_reads_client_input` is the only proof this branch has
                               and loosening it is the FN the shield forbids;
                               the 6 `local=False` rows all carry a Name or Call target
                               (`redirect_url`, `url`, `account_link`, `updated_redirect.to_url()`)
                               and are unreachable from this branch -- measured, not assumed.
  blessed overlap            : 0 of 6 -- the parity keys are `flask.redirect` on a Name/Attribute/
                               subscript/ternary target and one `UNTRUSTED_REDIRECT_SOURCE`; Big-8
                               holds 0 CWE-601 keys.
  inherited, and proved      : a `self.`-rooted hole is clean under `_expr_reads_client_input`, so
                               `"/x/%s" % self.owner` goes quiet with the rest. That is not new reach:
                               `concat_self_attr_hole` (`"/x/" + self.owner`) is already silent at
                               both seals, measured. It is safe because the second-character guard
                               means the anchor cannot be swallowed -- a value of `//evil.com`
                               produces `/x//evil.com`, which the browser resolves on the same host.
                               The blessed `redirect(self.redirect_url)` has no literal anchor at all
                               and stays reported.

Seal semantics - `CWE601_SEAL`
------------------------------
  'shipped'   : the 8 same-origin `%`-format shapes (18 arena rows) MUST be silent and every
                must-report row MUST stay loud -- narrow AND still catching the bad input.
  'abstained' : those shapes MUST still be loud. If they go quiet while the seal says abstained, a
                narrowing landed without updating this contract.
Either way a mismatch is exit 1.
"""
from __future__ import annotations

import ast
import contextlib
import io as _io
import os
import sys

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, os.pardir, os.pardir))
sys.path.insert(0, ROOT)

if os.environ.get('TCS_CWE601_ENGINE'):
    # falsification hook: load an alternative ast_scanner.py and let the gate argue against it. With
    # `CWE601_SEAL = 'shipped'` and the pre-narrowing engine, 0/8 shapes go silent and the gate
    # exits 1, so deleting the Mod branch from ast_scanner.py cannot pass unnoticed. The module is
    # registered under its real name because `dataclass(slots=True)` and `cli` both resolve the
    # engine through sys.modules, so an override that is not registered cannot even be imported.
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        'ast_scanner', os.environ['TCS_CWE601_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys, scan_rows  # noqa: E402

CWE601_SEAL = 'shipped'   # 'abstained' = the engine before the %-format branch landed
SEAL_TARGETS = ('abstained', 'shipped')

# The blessed CWE-601 population, counted from the frozen baselines themselves.
CWE601_LOCKED = {'parity': 6, 'big8': 0}

ODOO = 'from odoo import http\nfrom odoo.http import request\n'
SLUG = 'from odoo.addons.website.models.ir_http import slug\n'
FLASK = 'from flask import request, redirect\n'

# Every name the shapes below interpolate is a route parameter of this one method, so "the hole is a
# parameter" is a fact of the source and not a hope. `dbname`, `record_owner` and the `input()` reads
# in the blessed shapes are deliberately NOT parameters -- they are the unproven arms.
_PARAMS = ('forum, question, lead_id, action_id, lang_code, path, host, target, record, '
           'pos_order, v, a, b, c, owner')


def _indent(text: str, spaces: int) -> str:
    pad = ' ' * spaces
    return '\n'.join(pad + line if line else line for line in text.split('\n'))


def odoo_route(*lines: str) -> str:
    """An odoo controller method holding one `request.redirect(...)`, the arena's own shape."""
    return (ODOO + SLUG + '\n\nclass C(http.Controller):\n'
            '    @http.route("/forum")\n'
            f'    def h(self, {_PARAMS}):\n' + _indent('\n'.join(lines), 8) + '\n')


def flask_handler(*lines: str) -> str:
    return (FLASK + '\n\ndef h(next_url, project_id, post, is_internal, owner):\n'
            + _indent('\n'.join(lines), 4) + '\n')


# (label, source, expect_when_abstained, expect_when_shipped)
# 'loud' = a CWE-601 finding is required on that module, 'quiet' = none is allowed.
SHAPES = [
    # ---- %-format into a fixed relative anchor, holes that are route parameters ----
    ('mod_one_hole_accessor', odoo_route('return request.redirect("/forum/%s" % slug(forum))'),
     'loud', 'quiet'),
    ('mod_two_holes_code301', odoo_route(
        'return request.redirect("/forum/%s/%s" % (slug(forum), slug(question)), code=301)'),
     'loud', 'quiet'),
    ('mod_attr_chain_holes', odoo_route(
        'return request.redirect("/my/invoices/%s?access_token=%s" '
        '% (pos_order.account_move.id, pos_order.account_move._portal_ensure_token()))'),
     'loud', 'quiet'),
    ('mod_fragment_query', odoo_route(
        'return request.redirect("/web#id=%s&action=%s" % (lead_id, action_id))'),
     'loud', 'quiet'),
    ('mod_single_param', odoo_route('return request.redirect("/forum/%s" % forum)'),
     'loud', 'quiet'),
    ('mod_suffix_after_hole', odoo_route('return request.redirect("/forum/%s/ask" % slug(forum))'),
     'loud', 'quiet'),
    ('mod_three_holes', odoo_route('return request.redirect("/blog/%s/%s/%s" % (a, b, c))'),
     'loud', 'quiet'),
    ('mod_self_attr_hole', odoo_route('return request.redirect("/x/%s" % self.owner)'),
     'loud', 'quiet'),
    # ---- the authority bypass the second-character guard exists for ----
    ('mod_first_char_is_hole', odoo_route('return request.redirect("/%s%s" % (lang_code, path))'),
     'loud', 'loud'),
    ('mod_double_slash_head', odoo_route('return request.redirect("//%s/x" % host)'),
     'loud', 'loud'),
    ('mod_scheme_in_head', odoo_route('return request.redirect("https://x/%s" % v)'),
     'loud', 'loud'),
    ('mod_head_is_only_slash', odoo_route('return request.redirect("/%s" % v)'), 'loud', 'loud'),
    # ---- chained redirect: a same-origin page that bounces onward is not a destination ----
    ('mod_chained_redirect_key', odoo_route(
        'return request.redirect("/web/login?redirect=%s" % target)'), 'loud', 'loud'),
    ('mod_chained_next_key', odoo_route('return request.redirect("/web?next=%s" % target)'),
     'loud', 'loud'),
    # ---- holes the client-input predicate cannot explain ----
    ('mod_request_params_hole', odoo_route(
        'return request.redirect("/forum/%s" % request.params["next"])'), 'loud', 'loud'),
    ('mod_subscript_hole', odoo_route('return request.redirect("/x/%s" % record["url"])'),
     'loud', 'loud'),
    ('mod_dict_rhs', odoo_route('return request.redirect("/x/%(url)s" % {"url": v})'),
     'loud', 'loud'),
    ('mod_starred_tuple', odoo_route('return request.redirect("/x/%s" % (*v,))'),
     'quiet', 'quiet'),
    ('mod_unresolved_name', '\ndef h():\n    return request.redirect("/x/%s" % dbname)\n',
     'loud', 'loud'),
    ('mod_second_hole_is_request', odoo_route(
        'return request.redirect("/forum/%s/%s" % (slug(forum), request.params["q"]))'),
     'loud', 'loud'),
    # ---- a Name target inherits the same proof, and that hop is pre-existing, not new reach ----
    ('mod_name_target', odoo_route('url = "/web#id=%s" % lead_id\n'
                                   'return request.redirect(url)'), 'loud', 'quiet'),
    ('concat_name_target', odoo_route('url = "/web#" + lead_id\n'
                                      'return request.redirect(url)'), 'quiet', 'quiet'),
    # ---- the six blessed CWE-601 shapes, read from benchmark/corpus/cwe_601_redirect/ ----
    ('blessed_args_next', flask_handler('target = request.args.get("next")', 'return redirect(target)'),
     'loud', 'loud'),
    ('blessed_param_direct', FLASK + '\n\ndef login_redirect(next_url):\n    return redirect(next_url)\n'
     '\nnext_url = input("next: ")\nprint(login_redirect(next_url))\n', 'loud', 'loud'),
    ('blessed_helper_passthrough', FLASK + '\n\ndef resolve_target(next_url):\n    return next_url\n'
     '\n\ndef login_redirect(next_url):\n    target = resolve_target(next_url)\n'
     '    return redirect(target)\n\nnext_url = input("next: ")\n'
     'print(login_redirect(next_url))\n', 'loud', 'loud'),
    ('blessed_dict_subscript', FLASK + '\n\ndef login_redirect(next_url):\n'
     '    routes = {"target": next_url}\n    return redirect(routes["target"])\n'
     '\nnext_url = input("next: ")\nprint(login_redirect(next_url))\n', 'loud', 'loud'),
    ('blessed_self_attribute', FLASK + '\n\nclass AuthHandler:\n    def __init__(self, next_url):'
     '\n        self.redirect_url = next_url\n\n    def finish_login(self):\n'
     '        return redirect(self.redirect_url)\n\nnext_url = input("next: ")\n'
     'print(AuthHandler(next_url).finish_login())\n', 'loud', 'loud'),
    ('blessed_ternary_branch', FLASK + '\n\ndef login_redirect(next_url, is_internal):\n'
     '    if is_internal:\n        target = next_url\n    else:\n        target = next_url\n'
     '    return redirect(target)\n\nnext_url = input("next: ")\n'
     'print(login_redirect(next_url, False))\n', 'loud', 'loud'),
    # ---- already silent on the f-string / concat / literal paths, and required to stay silent ----
    ('concat_relative_param', flask_handler('return redirect("/taskManager/" + project_id + "/")'),
     'quiet', 'quiet'),
    # The symmetry proof: a `self.`-rooted hole on the path this branch extends is already accepted
    # today, so the new branch is no wider. If this row ever goes loud, %-format became stricter than
    # concatenation and the shipped `mod_self_attr_hole` expectation must be re-measured.
    ('concat_self_attr_hole', odoo_route('return request.redirect("/x/" + self.owner)'),
     'quiet', 'quiet'),
    ('fstring_relative_param', flask_handler('return redirect(f"/blog/{slug(post)}")'),
     'quiet', 'quiet'),
    ('pure_literal', flask_handler('return redirect("/web")'), 'quiet', 'quiet'),
    ('literal_with_query', flask_handler('return redirect("/web/login?redirect=/home")'),
     'quiet', 'quiet'),
]

FP_ROWS = [row for row in SHAPES if row[2] == 'loud' and row[3] == 'quiet']
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == 'loud']
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == 'quiet']

# The same format string with and without a binding that explains the hole. A narrowing that keyed
# on the anchor spelling alone would answer both arms alike -- and would exempt
# `"/x/%s" % request.params["next"]`. The client-input arm must stay loud at both seals.
PAIRS = [
    ('hole is a parameter', odoo_route('return request.redirect("/x/%s" % forum)'),
     '\ndef h():\n    return request.redirect("/x/%s" % forum)\n'),
    ('hole from request', odoo_route('return request.redirect("/x/%s" % record)'),
     odoo_route('record = request.params["next"]\nreturn request.redirect("/x/%s" % record)')),
    ('anchor is literal vs hole', odoo_route('return request.redirect("/forum/%s" % forum)'),
     odoo_route('return request.redirect("/%s" % forum)')),
]


def scan_source(source):
    """One in-memory module through the real record path, as both baselines were built."""
    with contextlib.redirect_stderr(_io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-601'})


def check_floors():
    """TIER 1: the blessed CWE-601 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-601'}
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-601={len(keys)} (want {CWE601_LOCKED[kind]})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != CWE601_LOCKED[kind]:
            failures.append((kind, 'CWE-601', CWE601_LOCKED[kind], len(keys),
                             'the blessed CWE-601 population moved'))
    return failures


def check_corpus():
    """TIER 2: the CWE-601 keys re-produced by a real tree scan, as an exact key set.

    The frozen keys come from a whole-tree scan of `benchmark/`, so the only honest comparison is
    the same whole-tree scan filtered to CWE-601 -- an in-memory module cannot reproduce a key whose
    message names another file.
    """
    failures = []
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    live = {row for row in scan_rows('parity', tree) if row[2] == 'CWE-601'}
    frozen = {row for row in load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
              if row[2] == 'CWE-601'}
    missing = sorted(frozen - live)
    extra = sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    for row in missing:
        print(f'  MISSING  {row[0]}:{row[1]} {row[4]}')
    for row in extra:
        print(f'  NEW      {row[0]}:{row[1]} {row[4]}')
    if missing:
        failures.append((len(missing), 'frozen CWE-601 keys no longer reported'))
    if extra:
        failures.append((len(extra), 'CWE-601 keys appeared that the baseline never held'))
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
            print(f'  {label:31s} UNPARSEABLE {exc}')
            failures.append((label, 'shape syntax', 'parses', str(exc)))
            continue
        expected = when_abstained if CWE601_SEAL == 'abstained' else when_shipped
        found = scan_source(source)
        status = 'loud' if found else 'quiet'
        note = '; '.join(f'L{n}:{m.replace("CWE-601: ", "")}' for n, m in found)[:60]
        marker = 'ok' if status == expected else 'MISMATCH'
        print(f'  {label:31s} want={expected:5s} got={status:5s} {marker:8s} {note}')
        if status != expected:
            failures.append((label, 'seal', expected, status,
                             'the answer moved without the seal, or the seal moved without the answer'))
    return failures


def check_pairs():
    """TIER 4: the same anchor with and without a binding that explains the hole.

    A narrowing that keyed on the format string alone would answer both arms alike, and would exempt
    a hole that reads `request.params`. The clean arm follows the seal; the client-input arm is loud
    at both.
    """
    failures = []
    for label, clean, tainted in PAIRS:
        a = bool(scan_source(clean))
        b = bool(scan_source(tainted))
        want_clean = CWE601_SEAL == 'abstained'
        agree = (a == want_clean) and b
        print(f'  {label:24s} clean_loud={a} (want {want_clean})  client_input_loud={b} '
              f'(want True)  {"agree" if agree else "DISAGREE"}')
        if not agree:
            failures.append((label, 'hole provenance', (want_clean, True), (a, b)))
    return failures


def main() -> int:
    if CWE601_SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {CWE601_SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-601 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the corpus behind those keys, scanned live:')
    failures += check_corpus()
    print(f'TIER 3 - truth table under seal={CWE601_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4 - clean vs client-input hole, same anchor:')
    failures += check_pairs()
    print(f'\nseal={CWE601_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'pairs={len(PAIRS)} locked_cwe601={sum(CWE601_LOCKED.values())} '
          f'failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-601 relative-target predicate no longer matches its measured '
              'evidence. Restore the answer or update the seal with a re-measured truth table; '
              'never re-bless a baseline.')
        return 1
    print(f'VERDICT: PASS - all {sum(CWE601_LOCKED.values())} blessed CWE-601 keys still reported '
          f'(0 lost), corpus exact-set, '
          f'{len(FP_ROWS)} same-origin %-format shapes silent, {len(MUST_REPORT_ROWS)} tainted/'
          f'authority/chained/blessed shapes reported, {len(ALREADY_QUIET_ROWS)} proven-safe '
          f'shapes silent, all provenance pairs agreeing.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
