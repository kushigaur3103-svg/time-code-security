"""Regression contracts for the PyGoat path-injection gap and its two neighbouring families.

Scope note, measured before writing anything: of the five reported PyGoat blind spots, only
`introduction/playground/ssrf/main.py:8` was a real gap. The other four were verified as
already-correct behaviour, and this file locks those measurements down so a future change has
to break a test rather than silently regress the target:

* `dockerized_labs/sensitive_data_exposure/templates/login.html:54` carries
  `{% csrf_token %}` on line 55 - protected, not a gap.
* `introduction/templates/Lab/ssrf/ssrf_discussion.html:125/135` are `<form>` tags written
  *inside* a `<textarea id="html">` code sample (opened at line 123) whose next line is the
  entity-escaped `{&#37; csrf_token &#37;}`; HTMLParser unescapes `&#37;` to `%` before
  `handle_data` sees it, so the auditor matches the token - protected, not a gap.
* A full census of the target's templates (117 `.html` files = every `.html` file in the repo,
  54 `<form>` tags) found 19 tokenless forms, and all 12 of them that are `method="post"` are
  already reported as CWE-352. The 7 silent ones are `method="get"` or method-less forms: the
  HTML default method is GET and Django's CSRF middleware only rejects unsafe methods, so
  reporting them would be a false positive. The task brief's "absent method defaults to POST"
  is the opposite of the spec, so `TestTemplateCsrfCoverage` pins the correct behaviour.
* `introduction/playground/A9/archive.py:49` is `f.write(f"INFO:{now}:{msg}\\n")`. Neither
  identifier names a credential, so the requested credential-name rule emits nothing there (that
  line is CWE-117 log injection, which the engine already reports for that file). A census of
  every write-family call in the target found no cleartext credential write at all, so no new
  CWE-312 collector was added; `TestCwe312ExistingCoverage` pins the rule that already exists.

Why the real gap was not a missing sink: `ssrf/main.py:8` already produced a CWE-22 `FILE_ACCESS`
sink, but with no edge it was never reported. `open(filename)` is not a `request` read, so phase
11's join+open recovery never matched it, and outside `audit_all` mode nothing propagates the
caller's value into an unreachable function. The new rule runs per module, requires the path to
carry a function parameter that no earlier line assigned, and defers to the existing sink by
adopting it (synthetic source id + message) instead of discarding it.

No line number in this file is hard-coded: each snippet marks its expected finding with `<<T>>`
and the assertion compares against that marker's own line.
"""

from __future__ import annotations

import textwrap
import unittest

from ast_scanner import TaintTracker
from cli import _findings_for
from html_auditor import audit_templates

CWE22 = "CWE-22"
CWE312 = "CWE-312"
CWE352 = "CWE-352"

MSG22 = "CWE-22: Unvalidated user input or dynamic variable used in file path operation"

# The verbatim body of external/pygoat/introduction/playground/ssrf/main.py, which is the
# finding the whole task exists for. The `<<T>>` marker sits on its `open()` line.
PYGOAT_SSRF_LAB = '''
    import os


    def ssrf_lab(file):
        try:
            dirname = os.path.dirname(__file__)
            filename = os.path.join(dirname, file)
            file = open(filename,"r")  # <<T>>
            data = file.read()
            return {"blog": data}
        except:
            return {"blog": "No blog found"}
    '''


def _snippet(body: str) -> str:
    return textwrap.dedent(body).lstrip("\n")


def _targets(code: str):
    """1-indexed line numbers of the lines a test marks as the expected finding."""
    return {number for number, line in enumerate(code.splitlines(), 1) if "<<T>>" in line}


def _edges(code: str, cwe: str, path: str = "sample.py", audit_all: bool = False,
           message: str = ""):
    """Sinks reachable by an edge, i.e. the ones a report actually shows.

    `audit_all=False` is the mode a real project scan uses, and it is the mode this rule exists
    for: with the collector disabled, none of the positive shapes below is reported at all, so a
    line that appears here can only have come from the new rule. `audit_all=True` additionally
    propagates parameters through unreachable functions, and that pre-existing path already
    reports some of the negative shapes (a `startswith` allowlist on a bare name, a module-level
    `open(os.path.join(dir, sys.argv[1]))`) with its own `CWE-22: open` message. Filtering by
    *message* keeps those from being mistaken for this rule's output.
    """
    tracker = TaintTracker(files={path: code}, audit_all=audit_all)
    _sources, sinks, edges = tracker.analyze()
    by_id = {sink.id: sink for sink in sinks}
    found = [by_id[edge.target_id] for edge in edges
             if edge.target_id in by_id and by_id[edge.target_id].metadata.get("cwe") == cwe]
    if message:
        found = [sink for sink in found if sink.metadata.get("message") == message]
    return found


def _lines(code: str, cwe: str, **kwargs):
    return {sink.location.line_start for sink in _edges(code, cwe, **kwargs)}


def _rule_lines(code: str, path: str = "sample.py"):
    """Lines this rule reported, attributed by its own message."""
    return _lines(code, CWE22, message=MSG22, path=path)


def _messages(code: str, cwe: str, **kwargs):
    return {sink.metadata.get("message") for sink in _edges(code, cwe, **kwargs)}


def _template_lines(html: str, path: str = "templates/Lab/x.html"):
    return {finding["line"] for finding in audit_templates({path: html})
            if finding["cwe"] == CWE352}


class TestCwe22CallerSuppliedPath(unittest.TestCase):
    def test_join_of_static_dir_and_parameter_into_open_is_flagged(self):
        code = _snippet('''
            import os

            def read_entry(name):
                base = os.path.dirname(__file__)
                path = os.path.join(base, name)
                return open(path).read()  # <<T>>
            ''')
        self.assertEqual(_rule_lines(code), _targets(code))

    def test_exact_message_is_reported(self):
        code = _snippet('''
            import os

            def read_entry(name):
                return open(os.path.join("/var/app", name))  # <<T>>
            ''')
        self.assertEqual(_messages(code, CWE22), {MSG22})

    def test_static_literal_path_stays_clean(self):
        code = _snippet('''
            def read_config():
                return open("config.json").read()
            ''')
        self.assertEqual(_rule_lines(code), set())

    def test_io_open_spelling_is_flagged(self):
        code = _snippet('''
            import io
            import os

            def read_entry(name):
                return io.open(os.path.join("/var/app", name))  # <<T>>
            ''')
        self.assertEqual(_rule_lines(code), _targets(code))

    def test_fstring_path_is_flagged(self):
        code = _snippet('''
            def read_entry(name):
                return open(f"/var/app/{name}")  # <<T>>
            ''')
        self.assertEqual(_rule_lines(code), _targets(code))

    def test_dict_subscript_derivation_is_flagged(self):
        code = _snippet('''
            import os

            def read_entry(name):
                paths = {"target": os.path.join("/var/app", name)}
                return open(paths["target"])  # <<T>>
            ''')
        self.assertEqual(_rule_lines(code), _targets(code))

    def test_secure_filename_wrapping_stays_clean(self):
        code = _snippet('''
            import os
            from werkzeug.utils import secure_filename

            def read_log(name):
                safe_name = secure_filename(name)
                path = os.path.join("/var/log", safe_name)
                with open(path) as handle:
                    return handle.read(1024)
            ''')
        self.assertEqual(_rule_lines(code), set())

    def test_basename_normpath_and_root_check_stay_clean(self):
        code = _snippet('''
            import os

            UPLOAD_DIR = "/var/app/uploads"

            def read_file(name):
                path = os.path.normpath(os.path.join(UPLOAD_DIR, os.path.basename(name)))
                if not path.startswith(UPLOAD_DIR):
                    raise ValueError("Path traversal detected")
                with open(path) as handle:
                    return handle.read()
            ''')
        self.assertEqual(_rule_lines(code), set())

    def test_sanitising_reassignment_of_the_parameter_stays_clean(self):
        code = _snippet('''
            import os

            def read_entry(name):
                name = os.path.basename(name)
                return open(os.path.join("/var/app", name))
            ''')
        self.assertEqual(_rule_lines(code), set())

    def test_startswith_guard_on_the_bound_name_stays_clean(self):
        code = _snippet('''
            import os

            BASE = "/var/app"

            def read_entry(name):
                path = os.path.join(BASE, name)
                if not path.startswith(BASE):
                    raise ValueError("Blocked")
                return open(path)
            ''')
        self.assertEqual(_rule_lines(code), set())

    def test_module_level_open_without_a_caller_stays_clean(self):
        code = _snippet('''
            import os
            import sys

            handle = open(os.path.join("/var/app", sys.argv[1]))
            ''')
        self.assertEqual(_rule_lines(code), set())

    def test_ok_marker_suppresses_the_finding(self):
        code = _snippet('''
            import os

            def read_entry(name):
                return open(os.path.join("/var/app", name))  # ok: name comes from a fixed menu
            ''')
        self.assertEqual(_rule_lines(code), set())

    def test_ok_marker_two_lines_above_still_suppresses(self):
        """The marker belongs to the statement, so the whole four-line window above counts.

        Regression: this is the `tests/test_cwe22_path_traversal.py` contract the new rule had to
        join, because it reports CWE-22 on an `open()` whose `# ok:` note sits above the
        assignment rather than above the call.
        """
        code = _snippet('''
            from django.http import HttpResponse

            def view(request):
                # ok: intentional test file access
                filename = request.GET.get('file')
                f = open(filename, 'r')
                return HttpResponse(f.read())
            ''')
        self.assertEqual(_rule_lines(code), set())

    def test_pygoat_ssrf_lab_is_flagged(self):
        code = _snippet(PYGOAT_SSRF_LAB)
        self.assertEqual(_rule_lines(code), _targets(code))

    def test_reports_one_finding_per_line(self):
        code = _snippet('''
            import os

            def read_entry(name):
                return open(os.path.join("/var/app", name))  # <<T>>
            ''')
        self.assertEqual(len(_edges(code, CWE22)), len(_targets(code)))


class TestCwe22AdoptsUnreachableSink(unittest.TestCase):
    """The bug that made this a blind spot: a sink with no edge is not a finding.

    `audit_all=False` is how a real project scan reaches a view helper whose caller lives in
    another module, and it is the mode the CLI uses. In that mode the `open()` in PyGoat's SSRF
    lab registers a CWE-22 sink and no edge, so only the adoption path reports it.
    """

    def test_finding_survives_without_audit_all(self):
        code = _snippet(PYGOAT_SSRF_LAB)
        self.assertEqual(_lines(code, CWE22, audit_all=False), _targets(code))

    def test_cli_shows_the_finding_for_the_real_target_file(self):
        with open("external/pygoat/introduction/playground/ssrf/main.py", encoding="utf-8") as handle:
            source = handle.read()
        tracker = TaintTracker(files={"introduction/playground/ssrf/main.py": source})
        _sources, _sinks, edges = tracker.analyze()
        findings = [f for f in _findings_for(tracker, edges) if f["cwe"] == CWE22]
        self.assertEqual([(f["line"], f["message"]) for f in findings], [(8, MSG22)])


class TestCwe312ExistingCoverage(unittest.TestCase):
    """No new CWE-312 rule: the engine already reports exactly the shapes the brief asked for."""

    def test_credential_written_to_a_file_is_flagged(self):
        code = _snippet('''
            def save(user_password):
                with open("out.txt", "w") as handle:
                    handle.write(user_password)  # <<T>>
            ''')
        self.assertEqual(_lines(code, CWE312), _targets(code))

    def test_plain_status_text_stays_clean(self):
        code = _snippet('''
            def save():
                with open("out.txt", "w") as handle:
                    handle.write("status_ok")
            ''')
        self.assertEqual(_lines(code, CWE312), set())

    def test_credential_in_a_dumped_dict_is_flagged(self):
        code = _snippet('''
            def save(auth_token):
                with open("out.json", "w") as handle:
                    json.dump({"token": auth_token}, handle)  # <<T>>
            ''')
        self.assertEqual(_lines(code, CWE312), _targets(code))

    def test_log_line_without_a_credential_name_stays_clean(self):
        """PyGoat's `archive.py:49` shape: `f.write(f"INFO:{now}:{msg}")` holds no credential."""
        code = _snippet('''
            import datetime

            class Log:
                def info(self, msg):
                    now = datetime.datetime.now()
                    handle = open("test.log", "a")
                    handle.write(f"INFO:{now}:{msg}\\n")
                    handle.close()
            ''')
        self.assertEqual(_lines(code, CWE312), set())


class TestTemplateCsrfCoverage(unittest.TestCase):
    """The auditor already handles multi-line tags, nested paths and both token spellings."""

    def test_post_form_without_a_token_is_flagged(self):
        html = _snippet('''
            <form method="post" action="/a">
                <input name="q">
            </form>
            ''')
        self.assertEqual(_template_lines(html), {1})

    def test_multi_line_form_attributes_are_flagged(self):
        html = _snippet('''
            <form
              method="post"
              action="/a">
                <input name="q">
            </form>
            ''')
        self.assertEqual(_template_lines(html), {1})

    def test_uppercase_form_and_method_are_flagged(self):
        html = _snippet('''
            <FORM METHOD="POST">
                <input name="q">
            </FORM>
            ''')
        self.assertEqual(_template_lines(html), {1})

    def test_csrf_block_tag_protects_the_form(self):
        html = _snippet('''
            <form method="post">
                {% csrf_token %}
                <input name="q">
            </form>
            ''')
        self.assertEqual(_template_lines(html), set())

    def test_entity_escaped_token_inside_a_textarea_protects_the_form(self):
        """The exact `ssrf_discussion.html` shape that was reported as a blind spot."""
        html = _snippet('''
            <textarea id="html">
                <form method="post" action="/ssrf_lab">
                    {&#37; csrf_token &#37;}
                    <button type="submit">Blog1</button>
                </form>
            </textarea>
            ''')
        self.assertEqual(_template_lines(html), set())

    def test_csrfmiddlewaretoken_input_protects_the_form(self):
        html = _snippet('''
            <form method="post">
                <input type="hidden" name="csrfmiddlewaretoken" value="{{ c }}">
            </form>
            ''')
        self.assertEqual(_template_lines(html), set())

    def test_get_form_without_a_token_stays_clean(self):
        """HTML's default method is GET and Django's CSRF middleware ignores safe methods."""
        html = _snippet('''
            <form method="get" action="/search">
                <input name="q">
            </form>
            ''')
        self.assertEqual(_template_lines(html), set())

    def test_method_less_form_without_a_token_stays_clean(self):
        html = _snippet('''
            <form action="/search">
                <input name="q">
            </form>
            ''')
        self.assertEqual(_template_lines(html), set())

    def test_deeply_nested_template_is_audited(self):
        html = _snippet('''
            <form method="post">
                <input name="q">
            </form>
            ''')
        path = "dockerized_labs/a/b/templates/deep/c/login.html"
        self.assertEqual(_template_lines(html, path=path), {1})


if __name__ == "__main__":
    unittest.main()
