"""Contracts for the two CWE-79 Django XSS rules, the CWE-93 response-body write, and the
subprocess-lineage claim this round measured and did not implement.

Every positive shape is silent with its own collector switched off and is attributed by the
message this round added, so nothing here can be credited to an older phase. Synthetic snippets
never hard-code a line number: the statement or markup that should be reported carries either a
`<<T>>` marker or a needle looked up by `_line_of`.

Measured at this commit:

* `mark_safe` rule - Bandit's labelled corpus, `python cli.py scan` per file with the collector
  off then on: `examples/mark_safe_insecure.py` 15 -> 25 CWE-79 findings, gaining lines 10, 11,
  12, 13, 14, 30, 41, 54, 114 and 153; `examples/mark_safe_secure.py` 5 -> 5 with no line gained;
  `examples/mark_safe.py` 0 -> 0.
* `|safe` template rule - OWASP PyGoat `python cli.py scan external/pygoat/`: 160 -> 164
  findings, nothing lost. The four new rows are `introduction/templates/Lab/XSS/xss_lab.html:27`,
  `Lab/XSS/xss_lab_2.html:20`, `Lab/ssrf/ssrf_lab2.html:23` and
  `Lab_2021/A8_software_and_data_integrity_failure/lab2.html:11`. The other 44 template findings
  are unchanged (14 CWE-352 + 30 CWE-353 before and after), and `CWE-1336` at
  `introduction/views.py:990` plus the four CWE-94 rows are untouched.
* CWE-93 response body - `response.content = request.POST['body']` reported nothing at all before
  this round; it now reports the assignment. `response.write(request.GET['x'])` was already
  reported as CWE-79 *and* CWE-93 by pre-existing machinery, with the collector switched off, so
  no rule was added for it. PyGoat contains no `response.content =` / `response.body =` write, so
  the target's total is unaffected by this rule.
* CWE-78 lineage anchoring - not implemented, on purpose. `introduction/views.py:424`
  (`command="nslookup {}".format(domain)`) is the definition line the brief wanted, and the engine
  already reports the same defect at `views.py:430` (`subprocess.Popen(command, shell=True)`),
  measured with the blind-spot CWE-78 collector disabled. Emitting 424 as well would put two
  findings on one defect, and the alternative - widening the finding's line range - cannot be
  expressed: `_findings_for` emits a single `line` key and the SARIF primary region only a
  `startLine` (`sarif_adapter.py:321-324`). The project's own 3-way scorer already merges the two
  lines, because `scripts/pygoat_independent_showdown.py:281` uses `SITE_WINDOW = 20` and
  `:345` compares `abs(finding["line"] - cluster["line"]) <= SITE_WINDOW`.
"""

from __future__ import annotations

import textwrap
import unittest

import ast_scanner
from ast_scanner import TaintTracker
from cli import _findings_for
from html_auditor import audit_template

CWE78 = "CWE-78"
CWE79 = "CWE-79"
CWE93 = "CWE-93"
CWE352 = "CWE-352"
CWE353 = "CWE-353"

MSG79 = "CWE-79: Unescaped dynamic content marked safe or rendered directly in HTTP response"
MSG93_HEADER = "CWE-93: Improper Neutralization of CRLF Sequences in HTTP Headers"
MSG93_BODY = "CWE-93: Raw client input written directly into the HTTP response body"

BANDIT_INSECURE = "external/bandit_corpus/examples/mark_safe_insecure.py"
BANDIT_SECURE = "external/bandit_corpus/examples/mark_safe_secure.py"
BANDIT_PLAIN = "external/bandit_corpus/examples/mark_safe.py"
PYGOAT_VIEWS = "external/pygoat/introduction/views.py"
PYGOAT_ROOT = "external/pygoat"
PYGOAT_TEMPLATES = PYGOAT_ROOT + "/introduction/templates"
PYGOAT_CHALLENGE_TPL = "external/pygoat/challenge/templates/challenge.html"
PYGOAT_FORM_TPL = ("external/pygoat/dockerized_labs/sensitive_data_exposure/"
                   "templates/login.html")
PYGOAT_DOC_TPL = "external/pygoat/introduction/templates/Lab/XSS/xss.html"
PYGOAT_XSS_LAB = PYGOAT_TEMPLATES + "/Lab/XSS/xss_lab.html"
PYGOAT_XSS_LAB_2 = PYGOAT_TEMPLATES + "/Lab/XSS/xss_lab_2.html"
PYGOAT_SSRF_LAB_2 = PYGOAT_TEMPLATES + "/Lab/ssrf/ssrf_lab2.html"
PYGOAT_A8_LAB_2 = (PYGOAT_TEMPLATES + "/Lab_2021/A8_software_and_data_integrity_failure/"
                   "lab2.html")

MARK_SAFE_CALLS = "_collect_cwe79_django_xss"
RESPONSE_WRITES = "_collect_cwe93_header_injection"
SUBPROCESS_CALLS = "_collect_cwe78_subprocess_calls"


def _snippet(body: str) -> str:
    return textwrap.dedent(body).lstrip("\n")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _targets(code: str, marker: str = "<<T>>"):
    """1-indexed line numbers of the lines a test marks as the expected finding."""
    return {number for number, line in enumerate(code.splitlines(), 1) if marker in line}


def _line_of(markup: str, needle: str) -> int:
    """The single line carrying *needle*, so template tests never hard-code a number."""
    matches = [number for number, line in enumerate(markup.splitlines(), 1) if needle in line]
    assert len(matches) == 1, (needle, matches)
    return matches[0]


def _python_rows(path: str, code: str, collector: str, enabled: bool = True):
    """CLI-level rows for one Python file with *collector* optionally switched off."""
    original = getattr(ast_scanner.TaintTracker, collector)
    if not enabled:
        setattr(ast_scanner.TaintTracker, collector, lambda *a, **k: None)
    try:
        tracker = TaintTracker(files={path: code}, audit_all=False)
        _sources, _sinks, edges = tracker.analyze()
        return _findings_for(tracker, edges)
    finally:
        setattr(ast_scanner.TaintTracker, collector, original)


def _rule_lines(path: str, code: str, cwe: str, message: str, collector: str):
    """Lines reported under *cwe* with this round's own *message*."""
    return {row["line"] for row in _python_rows(path, code, collector)
            if row["cwe"] == cwe and row["message"] == message}


def _cwe_lines(path: str, code: str, cwe: str, collector: str, enabled: bool = True):
    return {row["line"] for row in _python_rows(path, code, collector, enabled)
            if row["cwe"] == cwe}


def _gained(path: str, code: str, cwe: str, collector: str):
    """Lines the collector adds: reported with it on, absent with it off."""
    return _cwe_lines(path, code, cwe, collector) - _cwe_lines(
        path, code, cwe, collector, enabled=False)


def _template_lines(markup: str, path: str = "sample.html", cwe: str = CWE79):
    return {finding["line"] for finding in audit_template(path, markup)
            if finding["cwe"] == cwe}


class TestDjangoMarkSafeCollector(unittest.TestCase):
    """`mark_safe(value)` / `SafeString(value)` where *value* is not spelled out in full."""

    def _lines(self, code: str):
        return _rule_lines("app/views.py", code, CWE79, MSG79, MARK_SAFE_CALLS)

    def test_wrapper_fed_a_function_parameter_is_flagged(self):
        code = _snippet('''
            from django.utils.safestring import mark_safe

            def view(user_input):
                return mark_safe(user_input)  # <<T>>
            ''')
        self.assertEqual(self._lines(code), _targets(code))

    def test_safestring_class_fed_a_parameter_is_flagged(self):
        code = _snippet('''
            from django.utils import safestring

            def render(body):
                return safestring.SafeString(body)  # <<T>>
            ''')
        self.assertEqual(self._lines(code), _targets(code))

    def test_wrapper_fed_a_module_level_build_is_flagged(self):
        code = _snippet('''
            from django.utils import safestring

            def wrap(text):
                return '<h1>{}</h1>'.format(text)

            my_str = wrap('x')
            safestring.mark_safe(my_str)  # <<T>>
            ''')
        self.assertEqual(self._lines(code), _targets(code))

    def test_fstring_payload_is_flagged(self):
        code = _snippet('''
            from django.utils.safestring import mark_safe

            def view(name):
                return mark_safe(f"<b>{name}</b>")  # <<T>>
            ''')
        self.assertEqual(self._lines(code), _targets(code))

    def test_hardcoded_literal_is_ignored(self):
        code = _snippet('''
            from django.utils.safestring import mark_safe

            def view():
                return mark_safe("<b>Static</b>")
            ''')
        self.assertEqual(self._lines(code), set())

    def test_literal_template_with_literal_format_arguments_is_ignored(self):
        code = _snippet('''
            from django.utils.safestring import mark_safe

            def view():
                return mark_safe("<b>{}</b>".format("secure"))
            ''')
        self.assertEqual(self._lines(code), set())

    def test_escaping_wrapper_is_not_flagged(self):
        code = _snippet('''
            from django.utils import safestring
            from django.utils.html import escape

            def render(x):
                return safestring.mark_safe(escape(x))
            ''')
        self.assertEqual(self._lines(code), set())

    def test_format_html_is_not_flagged(self):
        """`format_html` escapes every argument, so it is a mitigation, not a sink."""
        code = _snippet('''
            from django.utils.html import format_html

            def view(user_input):
                return format_html("<b>{}</b>", user_input)
            ''')
        self.assertEqual(self._lines(code), set())

    def test_unbound_module_constant_is_ignored(self):
        code = _snippet('''
            from django.utils import safestring

            def render():
                return safestring.mark_safe(CONFIG_HTML)
            ''')
        self.assertEqual(self._lines(code), set())

    def test_attribute_read_is_ignored(self):
        code = _snippet('''
            from django.utils import safestring

            def render(obj):
                return safestring.mark_safe(obj.constant)
            ''')
        self.assertEqual(self._lines(code), set())

    def test_value_reassigned_to_a_literal_is_ignored(self):
        code = _snippet('''
            from django.utils import safestring

            def render(cls):
                text = '<b>{}</b>'.format(cls)
                text = "<b>fixed</b>"
                return safestring.mark_safe(text)
            ''')
        self.assertEqual(self._lines(code), set())

    def test_reviewed_suppression_is_honoured(self):
        code = _snippet('''
            from django.utils.safestring import mark_safe

            def view(user_input):
                return mark_safe(user_input)  # nosec: reviewed, admin-only field
            ''')
        self.assertEqual(self._lines(code), set())

    def test_bandit_insecure_corpus_gains_ten_runtime_built_wrappers(self):
        self.assertEqual(_gained(BANDIT_INSECURE, _read(BANDIT_INSECURE), CWE79, MARK_SAFE_CALLS),
                         {10, 11, 12, 13, 14, 30, 41, 54, 114, 153})

    def test_bandit_secure_corpus_gains_nothing(self):
        code = _read(BANDIT_SECURE)
        self.assertEqual(_gained(BANDIT_SECURE, code, CWE79, MARK_SAFE_CALLS), set())
        self.assertEqual(_rule_lines(BANDIT_SECURE, code, CWE79, MSG79, MARK_SAFE_CALLS), set())

    def test_bandit_plain_corpus_stays_clean(self):
        code = _read(BANDIT_PLAIN)
        self.assertEqual(_cwe_lines(BANDIT_PLAIN, code, CWE79, MARK_SAFE_CALLS), set())

    def test_pygoat_python_files_gain_nothing(self):
        """The target spells none of these wrappers, so its CWE-79 rows come from templates."""
        code = _read(PYGOAT_VIEWS)
        self.assertEqual(_gained(PYGOAT_VIEWS, code, CWE79, MARK_SAFE_CALLS), set())


class TestTemplateSafeFilter(unittest.TestCase):
    """`{{ value|safe }}` switches off the auto-escaping that protects every other variable."""

    def test_reflected_input_marked_safe_is_flagged(self):
        markup = _snippet('''
            <h3> The company '{{query|safe}}' is not Part of FAANG</h3>
            ''')
        self.assertEqual(_template_lines(markup), {_line_of(markup, "query|safe")})

    def test_space_before_the_filter_is_still_matched(self):
        markup = _snippet('''
            <div>{{response | safe}}</div>
            ''')
        self.assertEqual(_template_lines(markup), {_line_of(markup, "| safe")})

    def test_expression_split_over_lines_anchors_at_its_opening_braces(self):
        markup = _snippet('''
            <p>Hello
               {{ username
                  |safe }}</p>
            ''')
        self.assertEqual(_template_lines(markup), {_line_of(markup, "{{ username")})

    def test_bound_field_value_marked_safe_is_flagged(self):
        markup = _snippet('''
            <p>{{ form.username.value|safe }}</p>
            ''')
        self.assertEqual(_template_lines(markup), {_line_of(markup, "form.username.value")})

    def test_plain_variable_is_not_flagged(self):
        markup = _snippet('''
            <h3>{{ username }}</h3>
            ''')
        self.assertEqual(_template_lines(markup), set())

    def test_csrf_token_is_not_flagged(self):
        markup = _snippet('''
            <script>const token = "{{ csrf_token|safe }}";</script>
            ''')
        self.assertEqual(_template_lines(markup), set())

    def test_widget_render_is_not_flagged(self):
        """Django builds `{{ form.field }}` markup itself and escapes its attributes."""
        markup = _snippet('''
            <div>{{ form.username|safe }}</div>
            ''')
        self.assertEqual(_template_lines(markup), set())

    def test_sample_code_inside_code_tag_is_not_flagged(self):
        markup = _snippet('''
            <code>{{ username|safe }}</code>
            ''')
        self.assertEqual(_template_lines(markup), set())

    def test_self_closing_code_tag_does_not_open_a_region(self):
        markup = _snippet('''
            <code/>
            <p>{{ username|safe }}</p>
            ''')
        self.assertEqual(_template_lines(markup), {_line_of(markup, "username|safe")})

    def test_stray_closing_tag_does_not_disable_the_next_code_region(self):
        markup = _snippet('''
            </code>
            <code>{{ username|safe }}</code>
            <p>{{ other|safe }}</p>
            ''')
        self.assertEqual(_template_lines(markup), {_line_of(markup, "other|safe")})

    def test_two_vulnerable_lines_report_two_findings(self):
        markup = _snippet('''
            <p>{{ first|safe }}</p>
            <p>{{ second|safe }}</p>
            ''')
        self.assertEqual(_template_lines(markup),
                         {_line_of(markup, "first|safe"), _line_of(markup, "second|safe")})

    def test_repeated_expression_on_one_line_reports_once(self):
        markup = _snippet('''
            <p>{{ first|safe }} {{ second|safe }}</p>
            ''')
        self.assertEqual(len(_template_lines(markup)), 1)

    def test_pygoat_xss_labs_are_reported(self):
        expected = {PYGOAT_XSS_LAB: 27, PYGOAT_XSS_LAB_2: 20, PYGOAT_SSRF_LAB_2: 23,
                    PYGOAT_A8_LAB_2: 11}
        for path, line in expected.items():
            with self.subTest(path=path):
                self.assertEqual(_template_lines(_read(path), path), {line})

    def test_pygoat_framework_and_doc_templates_stay_silent(self):
        for path in (PYGOAT_CHALLENGE_TPL, PYGOAT_FORM_TPL, PYGOAT_DOC_TPL):
            with self.subTest(path=path):
                self.assertEqual(_template_lines(_read(path), path), set())

    def test_existing_template_rules_are_unchanged(self):
        """The parser hooks added for CWE-79 must not disturb CSRF (352) or SRI (353)."""
        import glob
        import os

        counts = {}
        for path in sorted(glob.glob(os.path.join(PYGOAT_ROOT, "**", "*.html"),
                                     recursive=True)):
            for finding in audit_template(path, _read(path)):
                counts[finding["cwe"]] = counts.get(finding["cwe"], 0) + 1
        self.assertEqual(counts[CWE352], 14)
        self.assertEqual(counts[CWE353], 30)
        self.assertEqual(counts[CWE79], 4)


class TestResponseBodyWrite(unittest.TestCase):
    """`response.content = <client input>` replaces the bytes the browser reads."""

    def _lines(self, code: str):
        return _rule_lines("app/views.py", code, CWE93, MSG93_BODY, RESPONSE_WRITES)

    def test_content_assignment_is_flagged_at_the_statement(self):
        code = _snippet('''
            def view(request):
                response = HttpResponse()
                response.content = request.POST['body']  # <<T>>
                return response
            ''')
        self.assertEqual(self._lines(code), _targets(code))

    def test_encoded_content_assignment_is_flagged(self):
        code = _snippet('''
            def view(request):
                response = HttpResponse()
                response.content = request.POST['body'].encode()  # <<T>>
                return response
            ''')
        self.assertEqual(self._lines(code), _targets(code))

    def test_body_assignment_is_flagged(self):
        code = _snippet('''
            def view(request):
                resp = HttpResponse()
                resp.body = request.GET['page']  # <<T>>
                return resp
            ''')
        self.assertEqual(self._lines(code), _targets(code))

    def test_literal_payload_is_ignored(self):
        code = _snippet('''
            def view(request):
                response = HttpResponse()
                response.content = b'<h1>static</h1>'
                return response
            ''')
        self.assertEqual(self._lines(code), set())

    def test_ordinary_dictionary_is_not_a_response(self):
        code = _snippet('''
            def view(request):
                payload = {}
                payload['content'] = request.POST['body']
                return payload
            ''')
        self.assertEqual(self._lines(code), set())

    def test_unrelated_receiver_is_ignored(self):
        code = _snippet('''
            def view(request):
                widget.content = request.POST['body']
                return widget
            ''')
        self.assertEqual(self._lines(code), set())

    def test_reviewed_suppression_is_honoured(self):
        code = _snippet('''
            def view(request):
                response = HttpResponse()
                response.content = request.POST['body']  # ok: escaped by the template
                return response
            ''')
        self.assertEqual(self._lines(code), set())

    def test_header_rows_keep_their_own_message(self):
        code = _snippet('''
            def view(request):
                response = HttpResponse()
                response.set_header('X-Target', request.GET['url'])  # <<T>>
                return response
            ''')
        self.assertEqual(_rule_lines("app/views.py", code, CWE93, MSG93_HEADER, RESPONSE_WRITES),
                         _targets(code))
        self.assertEqual(self._lines(code), set())

    def test_pygoat_has_no_response_body_write(self):
        """The target writes no reply payload by attribute, so this rule adds no row there."""
        code = _read(PYGOAT_VIEWS)
        self.assertEqual(_rule_lines(PYGOAT_VIEWS, code, CWE93, MSG93_BODY, RESPONSE_WRITES),
                         set())


class TestSubprocessLineageAnchor(unittest.TestCase):
    """One CWE-78 finding per defect, anchored at the exec statement - see the module docstring."""

    def test_command_lab_is_reported_at_the_popen_statement(self):
        rows = _python_rows(PYGOAT_VIEWS, _read(PYGOAT_VIEWS), SUBPROCESS_CALLS)
        self.assertIn((430, CWE78), [(row["line"], row["cwe"]) for row in rows])

    def test_definition_line_is_not_reported_a_second_time(self):
        rows = _python_rows(PYGOAT_VIEWS, _read(PYGOAT_VIEWS), SUBPROCESS_CALLS)
        cwe78 = {row["line"] for row in rows if row["cwe"] == CWE78}
        self.assertNotIn(424, cwe78)

    def test_report_row_has_no_second_line_number(self):
        """The reason a widened range cannot be expressed: one `line` key per finding."""
        rows = _python_rows(PYGOAT_VIEWS, _read(PYGOAT_VIEWS), SUBPROCESS_CALLS)
        self.assertTrue(rows)
        self.assertNotIn("line_end", rows[0])
        self.assertNotIn("end_line", rows[0])


if __name__ == "__main__":
    unittest.main()
