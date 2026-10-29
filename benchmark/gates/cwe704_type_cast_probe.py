"""CWE-704 truth table: which conversions the NaN sink may answer, and what `bool` may be exempted for.

Why this gate exists
--------------------
CWE-704 `NAN_UNVALIDATED_CONVERSION` is 15 of 2,128 findings on odoo/odoo@17.0. The 32 source files
behind those rows and behind the 23 CWE-328 rows were fetched to `scratch/_328_704/src` (odoo/odoo@17.0)
and re-scanned with the working engine at `b450f0a`, file by file, which is where every number below
comes from. Splitting the 15 rows by the conversion actually written:

    12  bool(...)      <- the sink is named for NaN, and bool() cannot produce one
     3  float(...)     <- money math and a config-supplied threshold; all three are real

The emitter
-----------
  ast_scanner.py:15412-15440 (inside `_collect_cluster2_structural_findings`, def :14755)
    * `CLUSTER2_NAN_CONVERSIONS` (:1664) = {float, bool, complex}, exactly one positional argument,
      callee must be the bare builtin Name.
    * `tainted_arg` (:15422-15428): a bare Name must be in `taint_vars`/`route_params`, a
      Call/Subscript/Attribute must satisfy `_root_is_request` (:14822).
    * `guarded` (:15429-15431): `int()` wrapper (`CLUSTER2_NAN_SAFE_WRAPPERS` :1665), an `int()`
      argument, or the name compared to the literal `"nan"` earlier in scope (:15073-15081).
  Nothing about the operand's type is ever consulted. That is the whole defect: `bool(x)` returns
  True/False for every input, so it can never carry a NaN into arithmetic.

The narrowing this gate locks
-----------------------------
`bool` stays in the sink. It is exempted only when the operand is **provably not a string**, because
the one real risk `bool()` carries is the string coercion: a client- or config-supplied `"0"`,
`"False"` or `"no"` is non-empty, therefore truthy, therefore the flag is on when the operator meant
off. Provable not-a-string means one of:

  1. the operand is a Call whose callee's last name is in `CLUSTER2_BOOL_NONSTRING_CALLEES` -
     Odoo recordsets (`search`, `search_count`, `browse`, `exists`, `filtered`: `bool(records)` is
     `len(records) != 0`), numbers (`len`, `any`, `all`, `sum`, `count`, `index`), `re` objects
     (`match`, `fullmatch`, `finditer`), and `str` predicates (`startswith`, `endswith`, `isdigit`,
     ...), all of which return bool/int, never a str;
  2. the operand is structurally a bool, a container, or a comprehension (`Compare`, `not`, list /
     set / dict literals, comprehensions - truthiness there is emptiness, not string content);
  3. the operand is a bare Name whose *every* assignment to it in the *same* scope qualifies under
     1 or 2 - scope-exact lookup in `self.assignments_by_scope`, never the cross-scope fallback, and
     a conditional assignment disqualifies the name.

Anything undecidable stays loud, so the worst case this rule can produce is a false positive.

Measured evidence behind the numbers
------------------------------------
  rows                                  : 15 (12 bool + 3 float) over the 32 fetched files
  cleared by this rule                  : 6 - `base_setup/controllers/main.py:58`,
                                          `im_livechat/controllers/main.py:123` and `:129`
                                          (all `search_count`), `website_event_track_live/controllers
                                          /session.py:18` (`re.match`), `website_sale_product_
                                          configurator/controllers/main.py:23` and `website_hr_
                                          recruitment/controllers/main.py:295` (recordset through a
                                          same-scope name hop)
  arena A/B, measured                   : HEAD `b450f0a` vs this working copy, alternating fresh
                                          subprocesses, both fetched odoo arenas in one run (116
                                          files): 527 findings -> 520, removed = 7 and every removed
                                          key is CWE-704, ADDED = 0, `_collect_cluster1` untouched.
                                          7 not 6 because `website_hr_recruitment/controllers/main.py`
                                          is byte-identical in the two arenas, so its :295 row is
                                          counted under two tags. Full scan 34.81s -> 33.30s (0.957x),
                                          the patched collector 0.889s -> 0.770s (0.866x), peak RSS
                                          157.9 MB. Harness: `scratch/_704_116_ab.py`.
  refused, with evidence                : 6 bool rows stay loud because their operand is a string
                                          read - `portal/controllers/portal.py:238`,
                                          `web/models/ir_http.py:181` and `mass_mailing/controllers
                                          /main.py:317` all hash a `get_param(...)` value,
                                          `survey/controllers/main.py:226` a cookie, and
                                          `http_routing/models/ir_http.py:637` a `getattr(request,
                                          ...)`; exempting these is the false negative the rule
                                          exists to catch ("admin sets allow_api_keys=False, API
                                          keys stay enabled").
  float/complex                         : untouched by construction - `website_payment/controllers
                                          /portal.py:39` and `:40` (client `amount`) and
                                          `google_recaptcha/models/ir_http.py:94` (`float(min_score)`
                                          over a config string, where a NaN comparison fails the bot
                                          check open) are all still reported.
  overlap with blessed keys             : 0 - 0 CWE-704 keys in parity (425) and Big-8 (119), counted
                                          from the frozen files themselves. That is why this file,
                                          and not a baseline diff, is the only thing standing between
                                          a `bool` cut and a silent miss: a re-bless would show an
                                          empty diff while the string-coercion class disappeared.

Seal semantics - `CWE704_SEAL`
------------------------------
`bool` keeps its finding unless `_c704_bool_operand_is_nonstring` (ast_scanner.py:14714) says the
operand cannot be a string; its allowlist is `CLUSTER2_BOOL_NONSTRING_CALLEES` (:1673) and the call
site that consults it is :15436-15440.

  'shipped' (today) : the 13 provably-non-string `bool` shapes here MUST be silent, every string-shaped
                      `bool` and every float/complex shape MUST stay loud.
  'abstained'       : all of them MUST still be loud. If a shape goes quiet while the seal says
                      abstained, a `bool` cut landed without this contract being re-measured.
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

if os.environ.get('TCS_CWE704_ENGINE'):
    # falsification hook: load an alternative ast_scanner.py and let the gate argue against it. With
    # `CWE704_SEAL = 'shipped'` and the pre-narrowing engine the 13 non-string bool shapes stay loud
    # and the gate exits 1, so deleting the predicate from ast_scanner.py cannot pass unnoticed - and
    # a blanket `bool` removal fails the string-shaped bool rows for the same reason.
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        'ast_scanner', os.environ['TCS_CWE704_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys, scan_rows  # noqa: E402

CWE704_SEAL = 'shipped'   # 'abstained' = the engine before the non-string bool predicate landed
SEAL_TARGETS = ('abstained', 'shipped')

# The blessed CWE-704 population, counted from the frozen baselines themselves.
CWE704_LOCKED = {'parity': 0, 'big8': 0}

ODOO = 'import re\nfrom odoo import http\n'


def wrap(header: str, body: str) -> str:
    return header + '\n\ndef handler(cr, uid, name):\n    ' + body.replace('\n', '\n    ') + '\n'


# (label, source, expect_when_abstained, expect_when_shipped)
# 'loud' = a CWE-704 finding is required on that module, 'quiet' = none is allowed.
SHAPES = [
    # ---- must be exempted: bool() of an operand that provably cannot be a string ----
    ('bool_search_count', wrap(ODOO, "flag = bool(request.env['ir.module.module'].search_count("
                                     "[('demo', '=', True)]))\nreturn flag"), 'loud', 'quiet'),
    ('bool_search_count_sudo', wrap(ODOO, "flag = bool(request.env['im_livechat.channel'].sudo()"
                                          ".search_count([('x', '=', 1)]))\nreturn flag"),
     'loud', 'quiet'),
    ('bool_re_match', wrap(ODOO, "flag = bool(re.match(r'^/shop', request.httprequest.path))\n"
                                "return flag"), 'loud', 'quiet'),
    ('bool_re_search', wrap(ODOO, "flag = bool(re.search('a', request.httprequest.path))\n"
                                "return flag"), 'loud', 'quiet'),
    ('bool_browse_name_hop', wrap(ODOO, "combination = request.env"
                                        "['product.template.attribute.value'].browse(name)\n"
                                        "return bool(combination)"), 'loud', 'quiet'),
    ('bool_search_name_hop', wrap(ODOO, "recent = http.request.env['hr.applicant'].sudo()"
                                        ".search([])\nreturn bool(recent)"), 'loud', 'quiet'),
    ('bool_len_call', wrap(ODOO, "return bool(len(request.env['x'].search([])))"),
     'loud', 'quiet'),
    ('bool_exists_call', wrap(ODOO, "return bool(request.env['x'].search([]).exists())"),
     'loud', 'quiet'),
    ('bool_filtered_call', wrap(ODOO, "return bool(request.env['x'].search([])"
                                      ".filtered(lambda r: r.active))"), 'loud', 'quiet'),
    ('bool_compare_name_hop', wrap(ODOO, "ok = request.params.get('active') == 'true'\n"
                                        "return bool(ok)"), 'loud', 'quiet'),
    ('bool_istartswith_call', wrap(ODOO, "return bool(request.httprequest.path.startswith"
                                         "('/shop'))"), 'loud', 'quiet'),
    ('bool_list_comprehension', wrap(ODOO, "return bool([v.id for v in request.env['x'].search([])])"),
     'loud', 'quiet'),
    # ---- must stay reported: the string coercion is the real bug in this rule ----
    ('bool_get_param_api_keys', wrap(ODOO, "return bool(request.env['ir.config_parameter'].sudo()"
                                           ".get_param('portal.allow_api_keys'))"), 'loud', 'loud'),
    ('bool_get_param_show_effect', wrap(ODOO, "return bool(request.env['ir.config_parameter']"
                                              ".sudo().get_param('base_setup.show_effect'))"),
     'loud', 'loud'),
    ('bool_get_param_with_default', wrap(ODOO, "return bool(request.env['ir.config_parameter'].sudo()"
                                               ".get_param('mass_mailing.show_blacklist_buttons',"
                                               " True))"), 'loud', 'loud'),
    ('bool_cookie_name_hop', wrap(ODOO, "token = request.httprequest.cookies.get('survey_%s' % name)"
                                        "\nreturn bool(token)"), 'loud', 'loud'),
    ('bool_getattr_request', wrap(ODOO, "return bool(getattr(request, 'is_frontend', False))"),
     'loud', 'loud'),
    ('bool_record_field_attr', wrap(ODOO, "return bool(request.env['res.users'].browse(uid)"
                                          ".password)"), 'loud', 'loud'),
    ('bool_jsonrequest_get', wrap(ODOO, "return bool(request.jsonrequest.get('enable_editor',"
                                        " False))"), 'loud', 'loud'),
    ('bool_str_builtin', wrap(ODOO, "return bool(str(request.env['x'].browse(uid).website_message))"),
     'loud', 'loud'),
    # Pre-existing miss, recorded not fixed: `tainted_arg` tests a Call operand with `_root_is_request`
    # only, so an alias as local as `kw = request.jsonrequest` hides the read behind a plain name and the
    # conversion is never asked about. odoo `website/controllers/main.py:165` (`mode_edit =
    # bool(kw.pop('enable_editor', False))`) is that row in the arena. Closing it means ADDING findings
    # and needs its own truth table, so it is left loud-proof below instead of silently blessed quiet.
    ('bool_dict_pop_aliased_jsonrequest', wrap(ODOO, "kw = request.jsonrequest\nreturn bool(kw.pop("
                                           "'enable_editor', False))"), 'quiet', 'quiet'),
    # ---- must stay reported: float and complex are the NaN sinks and are untouched ----
    ('float_client_amount', wrap(ODOO, "if float(request.jsonrequest['amount']) < float(10):\n"
                                       "    raise ValueError('low')"), 'loud', 'loud'),
    ('float_config_min_score', wrap(ODOO, "score = 0.5\nif score < float(request.env"
                                          "['ir.config_parameter'].sudo()"
                                          ".get_param('google_recaptcha.min_score')):\n"
                                          "    raise ValueError('bot')"), 'loud', 'loud'),
    ('float_params_get', wrap(ODOO, "qty = float(request.params.get('qty', 0))\nreturn qty"),
     'loud', 'loud'),
    ('complex_params_get', wrap(ODOO, "z = complex(request.params.get('z'))\nreturn z"),
     'loud', 'loud'),
    ('float_search_count_operand', wrap(ODOO, "ratio = float(request.env['x'].search_count([])) / 3"
                                          "\nreturn ratio"), 'loud', 'loud'),
    # ---- already silent, and required to stay silent at both seals ----
    ('int_wrapped_float', wrap(ODOO, "n = int(float(request.params.get('n')))\nreturn n"),
     'quiet', 'quiet'),
    ('bool_of_int_call', wrap(ODOO, "return bool(int(request.params.get('x')))"), 'quiet', 'quiet'),
    ('bool_literal_string', wrap(ODOO, "return bool('False')"), 'quiet', 'quiet'),
    ('bool_recordset_not_request_tainted', wrap(ODOO, "count = self.model.search_count([])\n"
                                                     "return bool(count)"), 'quiet', 'quiet'),
    ('float_nan_guarded', wrap(ODOO, "v = request.params.get('v')\nif v == 'nan':\n    v = '0'"
                                    "\nreturn float(v)"), 'quiet', 'quiet'),
    # loud at abstained, exempt at shipped: `flag` is a Compare, so it is structurally a bool. It is
    # filed here rather than above because the shape only reaches the predicate through the name hop.
    ('bool_of_bool_result', wrap(ODOO, "flag = request.env['x'].search_count([]) > 0\n"
                                      "return bool(flag)"), 'loud', 'quiet'),
]

FP_ROWS = [row for row in SHAPES if row[2] == 'loud' and row[3] == 'quiet']
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == 'loud']
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == 'quiet']

# The same conversion with a provably non-string operand and with a string operand. The non-string
# arm follows the seal; the string arm must stay loud at both seals, or the cut keyed on `bool` as a
# name instead of on what the value can be. The third pair keeps `float()` loud over the *same*
# non-string operand the `bool()` arm exempts, so the predicate cannot be re-keyed onto the operand
# alone and quietly shrink the NaN sink.
PAIRS = [
    ('count read vs config read',
     wrap(ODOO, "return bool(request.env['x'].search_count([]))"),
     wrap(ODOO, "return bool(request.env['ir.config_parameter'].sudo()"
                ".get_param('portal.allow_api_keys'))")),
    ('recordset hop vs cookie hop',
     wrap(ODOO, "combination = request.env['product.template.attribute.value'].browse(name)\n"
                "return bool(combination)"),
     wrap(ODOO, "token = request.httprequest.cookies.get('survey_%s' % name)\nreturn bool(token)")),
    ('bool vs float over one operand',
     wrap(ODOO, "return bool(request.env['x'].search_count([]))"),
     wrap(ODOO, "return float(request.env['x'].search_count([]))")),
]


def scan_source(source):
    """One in-memory module through the real record path, as both baselines were built."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-704'})


def check_floors():
    """TIER 1: the blessed CWE-704 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-704'}
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-704={len(keys)} (want {CWE704_LOCKED[kind]})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != CWE704_LOCKED[kind]:
            failures.append((kind, 'CWE-704', CWE704_LOCKED[kind], len(keys),
                             'the blessed CWE-704 population moved'))
    return failures


def check_corpus():
    """TIER 2: the CWE-704 keys re-produced by a real tree scan, as an exact key set.

    In-memory scanning cannot see a package, and CWE-704 does not need one - but it does need the
    same honest comparison every other gate uses: the whole-tree scan `aa_parity` runs, filtered to
    this CWE. With 0 blessed keys on both sides this tier is the guard against a *new* NaN row
    appearing anywhere the frozen baseline already covers.
    """
    failures = []
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    live = {row for row in scan_rows('parity', tree) if row[2] == 'CWE-704'}
    frozen = {row for row in load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
              if row[2] == 'CWE-704'}
    missing = sorted(frozen - live)
    extra = sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    for row in extra:
        print(f'  NEW      {row[0]}:{row[1]} {row[4]}')
    if missing:
        failures.append((len(missing), 'frozen CWE-704 keys no longer reported'))
    if extra:
        failures.append((len(extra), 'CWE-704 keys appeared that the baseline never held'))
    return failures


def check_shapes():
    """TIER 3: the truth table, asserted against the seal the file is standing under."""
    failures = []
    for label, source, when_abstained, when_shipped in SHAPES:
        ast.parse(source)  # an unparseable shape would look "quiet" for the wrong reason
        expected = when_abstained if CWE704_SEAL == 'abstained' else when_shipped
        found = scan_source(source)
        status = 'loud' if found else 'quiet'
        note = '; '.join(f'L{n}:{m.replace("CWE-704: ", "")}' for n, m in found)[:60]
        marker = 'ok' if status == expected else 'MISMATCH'
        print(f'  {label:34s} want={expected:5s} got={status:5s} {marker:8s} {note}')
        if status != expected:
            failures.append((label, 'seal', expected, status,
                             'the answer moved without the seal, or the seal moved without the answer'))
    return failures


def check_pairs():
    """TIER 4: a provably non-string operand beside a string operand, same conversion.

    A narrowing that deleted `bool` from the sink set would answer both arms alike - and would take
    the config/cookie coercions with it. The string arm must stay loud at both seals; the non-string
    arm follows the seal.
    """
    failures = []
    for label, nonstring, stringy in PAIRS:
        a = bool(scan_source(nonstring))
        b = bool(scan_source(stringy))
        want_nonstring = CWE704_SEAL == 'abstained'
        agree = (a == want_nonstring) and b
        print(f'  {label:34s} nonstring_loud={a} (want {want_nonstring})  string_loud={b} '
              f'(want True)  {"agree" if agree else "DISAGREE"}')
        if not agree:
            failures.append((label, 'operand arm', (want_nonstring, True), (a, b)))
    return failures


def main() -> int:
    if CWE704_SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {CWE704_SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-704 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the corpus behind those keys, scanned live:')
    failures += check_corpus()
    print(f'TIER 3 - truth table under seal={CWE704_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4 - non-string operand vs string operand, same conversion:')
    failures += check_pairs()
    print(f'\nseal={CWE704_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'pairs={len(PAIRS)} locked_cwe704={sum(CWE704_LOCKED.values())} '
          f'failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-704 NaN sink no longer matches its measured evidence. Restore '
              'the answer or move the seal with a re-measured truth table; never re-bless a baseline, '
              'and never delete `bool` from the sink outright - the string-coercion rows are the real '
              'findings in this rule.')
        return 1
    print(f'VERDICT: PASS - no blessed CWE-704 key exists (0 in parity, 0 in Big-8, so this truth '
          f'table is the only lock on the rule), corpus exact-set held, '
          f'{len(FP_ROWS)} provably-non-string bool shapes silent, '
          f'{len(MUST_REPORT_ROWS)} string/float/complex shapes reported, '
          f'{len(ALREADY_QUIET_ROWS)} guarded shapes silent, all operand pairs agreeing.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
