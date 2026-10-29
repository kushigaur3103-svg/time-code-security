"""CWE-79 truth table: which dynamic-string shapes the engine answers, and what a safe exemption may cover.

Why this gate exists
--------------------
CWE-79 is the second-largest finding count in the tracked real-world artifact: 160 of 2,128 findings on
odoo/odoo@17.0 (7,191 python files, engine rev f7d144f2). 159 of those 160 rows come from `ast_scanner.py`
and one from `html_auditor.py`. The audit behind this file (git-ignored `scratch/_c79_final.py` over the
75 arena files behind those rows) split them into a provably-safe set of 51 and a kept set of 109, and
found the noise has one root cause shared by three rules: **the engine calls a string "HTML" because it
contains `<` and `>`, without asking whether anything between them is a tag a browser would parse.**

The four record paths that answer for one string
------------------------------------------------
  * the sink registry - `TCS_SINKS` at ast_scanner.py:735-739, `Markup`/`markupsafe.Markup`/`mark_safe`/
    `Response` fire on the *call name* with no content test;
  * the response sink - `_is_html_construction_expr` (ast_scanner.py:5852) feeding `html_response`
    (ast_scanner.py:7757) for any `return` that looks like markup;
  * the phase-10.3 prune - `_collect_cwe79_xss_recovery_findings` (ast_scanner.py:19694): the sanitizer
    guard at :19725 is the only place that can take a registry record away, and it does it by `sink.id`,
    so a different CWE on the same AST node survives;
  * the structural phase-11 layer - `tag_re` (ast_scanner.py:19897), DYNAMIC_HTML_CONSTRUCTION (:20031),
    DYNAMIC_HTML_ARGUMENT (:20086), UNESCAPED_TEMPLATE_EXTENSION (:20119), plus the second template
    collector's `render_template` rule (ast_scanner.py:23256) and the response MIME guard
    `_json_or_structured_body` (ast_scanner.py:2847, consulted at :21929 and :23184).

What the exemption is
---------------------
One markup test, `_MARKUP_SHAPE_RE`, replaces the loose `("<" in val and ">" in val)` clauses at
:5879/:5885/:5891 and `tag_re` at :19897, after folding every `%s`/`{}` substitution marker and every
dynamic hole to one sentinel character. A fragment is markup only when `<` or `</` is followed by an
element name and then a delimiter (`>`, `/`, whitespace), or by a hole and then a delimiter, or by one of
`svg:`/`xhtml:`/`math:`/`html:`/`body:`. That single change covers the email/placeholder family:

    f'"{name}" <{local}@{domain}>'            RFC 2822 address   -> QUIET
    fr"... -- Odoo Bot <info@odoo.com> ..."   Debian changelog   -> QUIET
    f"<cbc:DocumentTypeCode {a}>{v}</cbc:...>"  UBL XML element  -> QUIET
    f"<{tag}>{content}</{tag}>"               dynamic tag name   -> REPORTED
    f"<svg:script>{name}</svg:script>"        executable ns tag  -> REPORTED

Five context rules ride on top, each with the shape test still inside it:

  A  a dynamic string that is only an exception/assert/regex-pattern/dedent argument never becomes a
     response body -- but `raise UserError('<b>%s</b>' % x)` stays reported, because the same arena file
     (`addons/l10n_ar/models/l10n_latam_document_type.py:47`) writes `"<br/>"` into a `UserError` message,
     which proves that channel does render.
  B  `__repr__`/`__str__` returns: `<%s %s%s>` is an object identity, not markup -- but `def __str__`
     returning `<div>%s</div>` stays reported, and the blessed corpus's own Django `@html_safe` case
     (`tests/test_cwe79_xss.py:179`) depends on that.
  C  a response whose literal Content-Type is a type the browser will not parse as HTML
     (`text/xml`, `text/csv`, `application/octet-stream`, ...) -- extended to list-of-tuples `headers`
     and to a name resolving to one, which is how `web/controllers/database.py:138` declares a dump.
  D  `Markup(literal) % value` and `Markup(literal).format(value)`: markupsafe escapes everything
     substituted into a `Markup`, measured on markupsafe 3.0.3
     (`Markup('<b>%s</b>') % '<script>alert(1)</script>'` -> `<b>&lt;script&gt;...`). The danger is the
     *inner* value, so it is reported there: `Markup(x)` and `Markup(f"...{x}...")` stay loud.
  E  `render_template` that this very module reassigns and never imports is a local helper, not Flask's
     (`odoo/addons/base/models/ir_qweb.py:616`, `odoo/tools/profiler.py:324`). A `render_template` that is
     *only* called and never imported or assigned stays reported -- that is the shape
     `tests/test_cwe79_xss.py:128` and `:142` require.

Measured evidence behind the numbers
------------------------------------
  arena rows audited          : 160 CWE-79 (159 python + 1 html) at engine f7d144f2
  provably safe set           : 51 rows = A1 4, A2 20, A3 3, B1 6, B2 1, B3 5, B4 1, B5 3, C1 1, C2 2,
                                D1 3, D2 2 (scratch/_c79/buckets.txt)
  overlap with blessed keys   : 0 -- 15 parity CWE-79 keys, 0 big8 CWE-79 keys
  refused, with evidence      : 17 parser-argument rows (website_snippet_filter.py:78 re-emits the parse
                                result into a response), all 45 bare-Markup rows (blessed bad.py:6), all
                                57 test-path rows (would delete 13 of the 15 blessed keys)
  caveat                      : the SARIF was produced 10 engine commits before this file's HEAD, so the
                                live drop is measured by the arena A/B, not claimed from 51.

Seal semantics - `CWE79_SAFE_SEAL`
----------------------------------
  'shipped' (today) : the 51-row shapes MUST be silent and MUST_REPORT_ROWS must stay loud on every
            spelling - narrow AND still catching the bad input.
  'abstained'       : the 51-row shapes MUST still be loud. If one goes quiet while the seal says
            abstained, an exemption landed without updating this contract.
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

if os.environ.get('TCS_CWE79_ENGINE'):
    # falsification hook: load an alternative ast_scanner.py and let the gate argue against it. With
    # `CWE79_SAFE_SEAL = 'shipped'` and the pre-exemption engine, 0/N targets go silent and the gate
    # exits 1, so deleting one of these exemptions from ast_scanner.py cannot pass unnoticed. The
    # module is registered under its real name because `dataclass(slots=True)` and `cli` both resolve
    # the engine through sys.modules, so an override that is not registered cannot even be imported.
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        'ast_scanner', os.environ['TCS_CWE79_ENGINE'])
    ast_scanner = importlib.util.module_from_spec(_spec)
    sys.modules['ast_scanner'] = ast_scanner
    _spec.loader.exec_module(ast_scanner)
else:
    import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys, scan_rows  # noqa: E402

CWE79_SAFE_SEAL = 'shipped'   # 'abstained' = the engine before the five context rules landed
SEAL_TARGETS = ('abstained', 'shipped')

# The blessed CWE-79 population, counted from the frozen baselines themselves.
CWE79_LOCKED = {'parity': 15, 'big8': 0}

# A tainted value in every shape below: request text, so no row is quiet for want of a source.
PRE = ('from flask import Flask, Response, request\n'
       'from markupsafe import Markup, escape\n'
       'from django.http import HttpResponse\n'
       'from gettext import gettext as _\n'
       'from odoo.exceptions import UserError\n'
       'import re\n'
       'import textwrap\n'
       'import unittest\n'
       '\n\n'
       '@app.route("/x")\n'
       'def handler():\n'
       '    name = request.args.get("name")\n')

# (label, source, expect_when_abstained, expect_when_shipped)
# 'loud' = a CWE-79 finding is required on that source, 'quiet' = none is allowed.
SHAPES = [
    # ---- A: message-only arguments; never a response body ----
    ('a1_raise_placeholder',
     PRE + '    raise ValueError("<info@odoo.com> is not a valid sender for %s" % name)\n',
     'loud', 'quiet'),
    ('a2_assert_expected',
     PRE + ('    return None\n\n\nclass Case(unittest.TestCase):\n'
            '    def test_one(self, ext, html):\n'
            '        self.assertIn(\'<span data-q="1">%s</span>\' % ext, html)\n'),
     'loud', 'quiet'),
    ('a3_regex_pattern_argument',
     PRE + ('    return None\n\n\ndef pattern(base, old):\n'
            '    return re.compile(\'old <a href="{old}">x</a> new <a href="{base}">y</a>\''
            '.format(old=old, base=base))\n'),
     'loud', 'quiet'),
    ('a3_dedent_block',
     PRE + ('    return None\n\n\ndef build_email(body):\n'
            '    return textwrap.dedent(f"""\n        <div>Hello {body}</div>\n        """)\n'),
     'loud', 'quiet'),
    # ---- B: object identity and address syntax, not markup ----
    ('b1_repr_identity',
     PRE + ('    return None\n\n\nclass Session(dict):\n'
            '    def __repr__(self):\n'
            '        return "<%s %s%s>" % (self.__class__.__name__, dict.__repr__(self), "*")\n'),
     'loud', 'quiet'),
    ('b1_str_module_qualified',
     PRE + ('    return None\n\n\nclass Field:\n'
            '    def __str__(self):\n'
            '        return "<%s.%s>" % (__name__, type(self).__name__)\n'),
     'loud', 'quiet'),
    ('b2_rfc2822_address',
     PRE + ('    return None\n\n\ndef formataddr(name, local, domain):\n'
            '    return f\'"{name}" <{local}@{domain}>\'\n'),
     'loud', 'quiet'),
    # ---- C1/C2: text that carries angle brackets but no parsable tag ----
    ('c1_debian_changelog',
     PRE + ('    return None\n\n\ndef changelog(version, tstamp):\n'
            '    return fr"odoo ({version}.{tstamp}) stable; urgency=low  '
            '* {version}  -- Odoo Bot <info@odoo.com>  {tstamp}"\n'),
     'loud', 'quiet'),
    ('c2_ubl_namespaced_element',
     PRE + ('    return None\n\n\ndef doc_type_node(attrs, value):\n'
            '    return f"<cbc:DocumentTypeCode {attrs}>{value}</cbc:DocumentTypeCode>"\n'),
     'loud', 'quiet'),
    # ---- C: literal non-HTML media type ----
    ('c1_text_xml_mimetype',
     PRE + '    return Response(name, mimetype="text/xml")\n', 'loud', 'quiet'),
    ('c1_text_csv_headers_list',
     PRE + ('    return Response(name, headers=[("Content-Type", "text/csv"),\n'
            '        ("Content-Disposition", "attachment; filename=a.csv")])\n'),
     'loud', 'quiet'),
    ('c1_octet_stream_headers_name',
     PRE + ('    headers = [("Content-Type", "application/octet-stream; charset=binary")]\n'
            '    return Response(name, headers=headers, direct_passthrough=True)\n'),
     'loud', 'quiet'),
    # ---- D: markupsafe escapes what it substitutes ----
    ('d1_markup_percent',
     PRE + ('    return Markup(_("abc") + "<ul>%(t)s</ul>") % {"t": name}\n'),
     'loud', 'quiet'),
    ('d1_markup_format',
     PRE + ('    return Markup(_("abc") + "<ul>{t}</ul>").format(t=name)\n'),
     'loud', 'quiet'),
    ('d2_markup_fstring_escaped_holes',
     PRE + ('    return emit(Markup(f\'<a data-oe-model="{escape(name)}"\n'
            '        data-oe-id="{int(name)}">{escape(name)}</a>\'))\n'),
     'loud', 'quiet'),
    # ---- E: a locally rebound render helper is not Flask's ----
    ('e1_local_render_binding',
     PRE + ('    return None\n\n\ndef render_compiled(functions, def_name, env, values):\n'
            '    render_template = functions[def_name]\n'
            '    return render_template(env, values)\n'),
     'loud', 'quiet'),
    # ---- the bad input: loud at both seals, this is the proof each exemption stayed narrow ----
    ('raw_markup_fstring',
     PRE + '    return Markup(f"<b>Hello {name}</b>")\n', 'loud', 'loud'),
    ('markup_wraps_user_text',
     PRE + '    return Markup(name)\n', 'loud', 'loud'),
    ('markup_percent_of_markup',
     PRE + '    return Markup("<b>%s</b>") % Markup(name)\n', 'loud', 'loud'),
    ('dynamic_tag_name_fstring',
     PRE + '    return f"<{name}>{name}</{name}>"\n', 'loud', 'loud'),
    ('known_tag_return',
     PRE + '    return f"<h1>Hello, {name}!</h1>"\n', 'loud', 'loud'),
    ('text_html_response',
     PRE + '    return Response(name, content_type="text/html")\n', 'loud', 'loud'),
    ('bare_response',
     PRE + '    return Response(name)\n', 'loud', 'loud'),
    ('headers_without_content_type',
     PRE + '    return Response(name, headers=[("X-A", "1")])\n', 'loud', 'loud'),
    ('headers_media_type_is_dynamic',
     PRE + ('    media = request.headers.get("X-Media")\n'
            '    return Response(name, headers=[("Content-Type", media)])\n'),
     'loud', 'loud'),
    ('raise_carries_a_real_tag',
     PRE + '    raise UserError("<b>%s</b> is not valid" % name)\n', 'loud', 'loud'),
    ('str_returns_a_real_tag',
     PRE + ('    return None\n\n\nclass Html:\n    def __str__(self):\n'
            '        return "<div>%s</div>" % self.name\n'),
     'loud', 'loud'),
    ('assert_like_name_is_not_an_assert',
     PRE + '    emit(f"<div>{name}</div>")\n', 'loud', 'loud'),
    ('parser_reemits_the_document',
     PRE + '    return f"<body>{name}</body>"\n', 'loud', 'loud'),
    ('namespaced_executable_tag',
     PRE + '    return f"<svg:script>{name}</svg:script>"\n', 'loud', 'loud'),
    ('flask_render_template_still_a_sink',
     PRE + '    return render_template("unsafe.txt", name=name)\n', 'loud', 'loud'),
    ('jinja2_direct_use',
     ('from flask import request\nimport jinja2\n\n\ndef render_greeting():\n'
      '    name = request.args.get("name")\n'
      '    template = jinja2.Template("Hello {{ name }}!")\n'
      '    return template.render(name=name)\n'),
     'loud', 'loud'),
    # ---- already silent, and required to stay silent at both seals ----
    ('static_literal_response',
     PRE + '    return HttpResponse("<h1>Static Title</h1>")\n', 'quiet', 'quiet'),
    ('escaped_value_response',
     PRE + '    return HttpResponse(escape(name))\n', 'quiet', 'quiet'),
    ('angle_free_text',
     PRE + '    return f"{name}@{name}"\n', 'quiet', 'quiet'),
    ('json_response',
     PRE + '    return Response(name, content_type="application/json")\n', 'quiet', 'quiet'),
]

FP_ROWS = [row for row in SHAPES if row[2] == 'loud' and row[3] == 'quiet']
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == 'loud']
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == 'quiet']


def scan_source(source):
    """One in-memory module through the real record path, as both baselines were built."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source}, audit_all=True)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-79'})


def check_floors():
    """TIER 1: the blessed CWE-79 population, in both frozen baselines."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-79'}
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-79={len(keys)} (want {CWE79_LOCKED[kind]})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != CWE79_LOCKED[kind]:
            failures.append((kind, 'CWE-79', CWE79_LOCKED[kind], len(keys),
                             'the blessed CWE-79 population moved'))
    return failures


def check_corpus():
    """TIER 2: the 15 blessed keys re-produced by a real tree scan, as an exact key set.

    In-memory single-module scanning is not how the baselines were made - it loses every row that
    depends on package context, so it under-reports. The only honest comparison is the same whole-tree
    scan `aa_parity` uses, filtered to CWE-79.
    """
    failures = []
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    live = {row for row in scan_rows('parity', tree) if row[2] == 'CWE-79'}
    frozen = {row for row in load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
              if row[2] == 'CWE-79'}
    missing = sorted(frozen - live)
    extra = sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    for row in sorted(frozen):
        tag = 'held' if row in live else 'MISSING'
        print(f'  {tag:8s} {str(row[0])[str(row[0]).find("corpus"):][:50]}:{row[1]} {row[4]}')
    for row in extra:
        print(f'  NEW      {row[0]}:{row[1]} {row[4]}')
    if missing:
        failures.append((len(missing), 'frozen CWE-79 keys no longer reported'))
    if extra:
        failures.append((len(extra), 'CWE-79 keys appeared that the baseline never held'))
    return failures


def check_shapes():
    """TIER 3: the truth table, asserted against the seal the file is standing under."""
    failures = []
    for label, source, when_abstained, when_shipped in SHAPES:
        expected = when_abstained if CWE79_SAFE_SEAL == 'abstained' else when_shipped
        found = scan_source(source)
        status = 'loud' if found else 'quiet'
        note = '; '.join(f'L{n}:{m.replace("CWE-79: ", "")}' for n, m in found)[:60]
        marker = 'ok' if status == expected else 'MISMATCH'
        print(f'  {label:32s} want={expected:5s} got={status:5s} {marker:8s} {note}')
        if status != expected:
            failures.append((label, 'seal', expected, status,
                             'the answer moved without the seal, or the seal moved without the answer'))
    return failures


def check_path_agreement():
    """TIER 4: one string must not get two answers from two record paths.

    The response sink (`_is_html_construction_expr` over a `return`) and the structural layer
    (`tag_re`/`_const_tag` over an assignment or a call argument) read the same fragment. Any
    difference means one of them was tightened and the other was not - the exact defect CWE-611
    shipped against. Loudness is compared, not the message: the two paths name the same finding
    differently by design, and the line differs once the value is stored in a name first.
    """
    failures = []
    pairs = [
        ('markup-shaped return vs assignment',
         PRE + '    out = f"<{name}>{name}</{name}>"\n    return out\n',
         PRE + '    return f"<{name}>{name}</{name}>"\n'),
        ('non-tag angle text in return vs assignment',
         PRE + '    out = f\'"{name}" <{name}@{name}>\'\n    return out\n',
         PRE + '    return f\'"{name}" <{name}@{name}>\'\n'),
        ('namespaced element in return vs assignment',
         PRE + '    out = f"<cbc:Code {name}>{name}</cbc:Code>"\n    return out\n',
         PRE + '    return f"<cbc:Code {name}>{name}</cbc:Code>"\n'),
        ('Markup percent in return vs assignment',
         PRE + '    out = Markup("<b>%s</b>") % name\n    return out\n',
         PRE + '    return Markup("<b>%s</b>") % name\n'),
        ('non-HTML media in return vs assignment',
         PRE + '    out = Response(name, mimetype="text/xml")\n    return out\n',
         PRE + '    return Response(name, mimetype="text/xml")\n'),
    ]
    for label, left, right in pairs:
        a = bool(scan_source(left))
        b = bool(scan_source(right))
        agree = a == b
        print(f'  {label:42s} stored={a} direct={b} {"agree" if agree else "DISAGREE"}')
        if not agree:
            failures.append((label, 'the two record paths disagree about the same string', a, b))
    return failures


def main() -> int:
    if CWE79_SAFE_SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {CWE79_SAFE_SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-79 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the corpus behind those keys, scanned live:')
    failures += check_corpus()
    print(f'TIER 3 - truth table under seal={CWE79_SAFE_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4 - the two record paths, same string:')
    failures += check_path_agreement()
    print(f'\nseal={CWE79_SAFE_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'locked_cwe79={sum(CWE79_LOCKED.values())} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-79 markup layer no longer matches its measured evidence. Restore '
              'the answer or update the seal with a re-measured truth table; never re-bless a baseline.')
        return 1
    print('VERDICT: PASS - 15 blessed parity CWE-79 keys held, corpus exact-set, '
          f'{len(MUST_REPORT_ROWS)} untrusted-input shapes reported and '
          f'{len(ALREADY_QUIET_ROWS)} safe shapes silent, both record paths agreeing.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
