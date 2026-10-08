"""Contracts for the CWE-94 generated-source write collector, and the measured state of the
three blind spots this round claimed but does not have.

Every positive shape below is silent with `_collect_cwe94_python_source_writes` disabled and is
attributed to this rule by its own message, so nothing here can be credited to an older phase.
Lines are never hard-coded for synthetic snippets: the statement that should be reported carries
a `<<T>>` marker and the assertion compares against that marker's own line number.

Measured against OWASP PyGoat at this commit (`python cli.py scan external/pygoat/`, 156 findings
before the collector, 160 after, nothing lost):

* Real gap that is now closed - four places take request- or runtime-built text and overwrite a
  Python module the project imports: `introduction/apis.py:70` (`playground/A9/main.py`),
  `introduction/apis.py:73` (`playground/A9/api.py`), `introduction/apis.py:134`
  (`playground/A6/utility.py`), `introduction/utility.py:36` (`playground/ssrf/main.py`). The next
  import runs attacker-written source, so these are code injection, not response injection.
* CWE-78 needs no new rule: `introduction/views.py:430` (`command = "nslookup {}".format(domain)`
  several lines above `subprocess.Popen(command, shell=True)`) is already reported CRITICAL by the
  existing dynamic-subprocess sink, with this collector switched off, and so is every `.format`,
  f-string and concatenation variant in `TestCwe78AlreadyCovered`. `challenge/views.py:50` is
  reported; `challenge/views.py:81` (`Popen(command.split(" "))`, no `shell=`, command built from
  the app's own `container_id`) stays silent on purpose.
* CWE-352 template discovery is already complete: 117 templates are parsed, and the nested
  `dockerized_labs/**` tree contributes 36 of them. `sensitive_data_exposure/templates/login.html:54`
  carries `{% csrf_token %}` on the next line - delete that token from the real file in memory and
  the auditor reports line 54. `ssrf_discussion.html:125/135` are `<form>` tags inside a
  `<textarea>` sample that each include the entity-encoded `{&#37; csrf_token &#37;}`.
* CWE-312 has no archive gap: PyGoat contains no `tarfile`, no `zipfile` and no `extractall`, and
  `playground/A9/archive.py:49` writes `f"INFO:{now}:{msg}"` into `test.log` - no credential
  reaches it. Credential writes to a file are already reported by the existing rule.
* CWE-93 has no response-write gap: there is no `response.write` in the target, `apis.py:65` is a
  `request.POST.get` read (a source, not a sink), and `views.py:981` (`blog = request.POST["blog"]`)
  feeds a template render the engine already reports as CWE-1336 at `views.py:990`.
"""

from __future__ import annotations

import textwrap
import unittest

import ast_scanner
from ast_scanner import TaintTracker
from cli import _findings_for
from html_auditor import audit_templates

CWE78 = "CWE-78"
CWE93 = "CWE-93"
CWE94 = "CWE-94"
CWE287 = "CWE-287"
CWE312 = "CWE-312"
CWE352 = "CWE-352"
CWE1336 = "CWE-1336"

MSG94 = ("CWE-94: Dynamically built content written into a Python source file the "
         "program imports")

PYGOAT_APIS = "external/pygoat/introduction/apis.py"
PYGOAT_UTILITY = "external/pygoat/introduction/utility.py"
PYGOAT_VIEWS = "external/pygoat/introduction/views.py"
PYGOAT_CHALLENGE = "external/pygoat/challenge/views.py"
PYGOAT_ARCHIVE = "external/pygoat/introduction/playground/A9/archive.py"
PYGOAT_NESTED_FORM = "external/pygoat/dockerized_labs/broken_auth_lab/templates/lab.html"
PYGOAT_LOGIN = ("external/pygoat/dockerized_labs/sensitive_data_exposure/"
                "templates/login.html")
PYGOAT_DISCUSSION = "external/pygoat/introduction/templates/Lab/ssrf/ssrf_discussion.html"


def _snippet(body: str) -> str:
    return textwrap.dedent(body).lstrip("\n")


def _targets(code: str, marker: str = "<<T>>"):
    """1-indexed line numbers of the lines a test marks as the expected finding."""
    return {number for number, line in enumerate(code.splitlines(), 1) if marker in line}


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _edges(code: str, cwe: str, path: str = "sample.py", collector: bool = True):
    """Sinks reachable by an edge, i.e. the ones a report actually shows.

    *collector* switches `_collect_cwe94_python_source_writes` off, which is how the negatives
    below are proven to be genuinely silent rather than reported by an older phase.
    """
    original = ast_scanner.TaintTracker._collect_cwe94_python_source_writes
    if not collector:
        ast_scanner.TaintTracker._collect_cwe94_python_source_writes = lambda *a, **k: None
    try:
        tracker = TaintTracker(files={path: code}, audit_all=False)
        _sources, sinks, edges = tracker.analyze()
    finally:
        ast_scanner.TaintTracker._collect_cwe94_python_source_writes = original
    by_id = {sink.id: sink for sink in sinks}
    found = [by_id[edge.target_id] for edge in edges
             if edge.target_id in by_id and by_id[edge.target_id].metadata.get("cwe") == cwe]
    return found


def _rule_lines(code: str, path: str = "sample.py"):
    """Lines this rule reported, attributed by its own message."""
    return {sink.location.line_start for sink in _edges(code, CWE94, path=path)
            if sink.metadata.get("message") == MSG94}


def _lines(code: str, cwe: str, **kwargs):
    return {sink.location.line_start for sink in _edges(code, cwe, **kwargs)}


def _real_file_rows(path: str, collector: bool = True):
    """Findings `_findings_for` would print for one real file, as (line, cwe, message) rows."""
    original = ast_scanner.TaintTracker._collect_cwe94_python_source_writes
    if not collector:
        ast_scanner.TaintTracker._collect_cwe94_python_source_writes = lambda *a, **k: None
    try:
        tracker = TaintTracker(files={path: _read(path)}, audit_all=False)
        _sources, _sinks, edges = tracker.analyze()
        rows = _findings_for(tracker, edges)
    finally:
        ast_scanner.TaintTracker._collect_cwe94_python_source_writes = original
    return [(row["line"], row["cwe"], row["message"]) for row in rows]


class TestCwe94GeneratedSourceWrites(unittest.TestCase):
    def test_request_payload_written_into_python_module_is_flagged(self):
        code = _snippet('''
            import os

            def save(request):
                log_code = request.POST.get('log_code')
                dirname = os.path.dirname(__file__)
                log_filename = os.path.join(dirname, "playground/A9/main.py")
                f = open(log_filename, "w")
                f.write(log_code)  # <<T>>
                f.close()
                return 1
            ''')
        self.assertEqual(_rule_lines(code), _targets(code))

    def test_exact_message_and_single_finding_per_line(self):
        code = _snippet('''
            def save(request):
                payload = request.POST.get('code')
                handle = open("generated/module.py", "w")
                handle.write(payload)  # <<T>>
            ''')
        reported = [sink for sink in _edges(code, CWE94)
                    if sink.metadata.get("message") == MSG94]
        self.assertEqual(len(reported), 1)
        self.assertEqual(reported[0].metadata.get("cwe"), CWE94)

    def test_with_statement_handle_is_flagged(self):
        code = _snippet('''
            import os

            def save(request):
                code = request.POST.get('code')
                with open(os.path.join(os.path.dirname(__file__), "mod.py"), "w") as fh:
                    fh.write(code)  # <<T>>
            ''')
        self.assertEqual(_rule_lines(code), _targets(code))

    def test_mode_keyword_is_flagged(self):
        code = _snippet('''
            def save(payload):
                fh = open("generated/module.py", mode="w")
                fh.write(payload)  # <<T>>
            ''')
        self.assertEqual(_rule_lines(code), _targets(code))

    def test_joined_generated_source_written_to_module_is_flagged(self):
        code = _snippet('''
            def convert(input_code):
                list_output = ["def f(x):", "    return " + input_code]
                output_Code = "\\n".join(list_output)
                filename = "playground/ssrf/main.py"
                f = open(filename, "w")
                f.write(output_Code)  # <<T>>
                f.close()
                return 1
            ''')
        self.assertEqual(_rule_lines(code), _targets(code))

    def test_writelines_of_generated_source_is_flagged(self):
        code = _snippet('''
            def emit(lines):
                handle = open("build/module.py", "w")
                handle.writelines(lines)  # <<T>>
            ''')
        self.assertEqual(_rule_lines(code), _targets(code))

    def test_literal_payload_stays_clean(self):
        code = _snippet('''
            def build():
                fh = open("generated/module.py", "w")
                fh.write("# generated\\n")  # <<T>>
            ''')
        self.assertEqual(_rule_lines(code), set())

    def test_non_python_target_stays_clean(self):
        code = _snippet('''
            def log(now, msg):
                fh = open('test.log', 'a')
                fh.write(f"INFO:{now}:{msg}\\n")  # <<T>>
            ''')
        self.assertEqual(_rule_lines(code), set())

    def test_read_mode_handle_stays_clean(self):
        code = _snippet('''
            def read(payload):
                fh = open("module.py")
                fh.write(payload)  # <<T>>
            ''')
        self.assertEqual(_rule_lines(code), set())

    def test_append_binary_mode_still_counts_as_a_write(self):
        code = _snippet('''
            def save(payload):
                fh = open("build/module.py", "ab")
                fh.write(payload)  # <<T>>
            ''')
        self.assertEqual(_rule_lines(code), _targets(code))

    def test_non_literal_mode_stays_clean(self):
        code = _snippet('''
            def save(payload, request):
                mode = request.POST.get('mode')
                fh = open("module.py", mode)
                fh.write(payload)  # <<T>>
            ''')
        self.assertEqual(_rule_lines(code), set())

    def test_handle_that_is_not_an_opened_file_stays_clean(self):
        code = _snippet('''
            import io

            def save(payload):
                buf = io.StringIO()
                buf.write(payload)  # <<T>>
            ''')
        self.assertEqual(_rule_lines(code), set())

    def test_attribute_receiver_stays_clean(self):
        code = _snippet('''
            def emit(response, payload):
                response.write(payload)  # <<T>>
                return response
            ''')
        self.assertEqual(_rule_lines(code), set())

    def test_ok_marker_suppresses(self):
        code = _snippet('''
            def save(payload):
                fh = open("module.py", "w")
                fh.write(payload)  # ok: template we ship ourselves  <<T>>
            ''')
        self.assertEqual(_rule_lines(code), set())

    def test_positives_are_silent_with_the_collector_disabled(self):
        code = _snippet('''
            def save(payload):
                fh = open("build/module.py", "w")
                fh.write(payload)  # <<T>>
            ''')
        self.assertEqual(_lines(code, CWE94, collector=False), set())
        self.assertEqual(_lines(code, CWE94), _targets(code))

    def test_pygoat_apis_module_reports_its_three_module_overwrites(self):
        rows = [(line, cwe) for line, cwe, message in _real_file_rows(PYGOAT_APIS)
                if message == MSG94]
        self.assertEqual(sorted(rows), [(70, CWE94), (73, CWE94), (134, CWE94)])

    def test_pygoat_apis_reports_nothing_extra_and_loses_nothing(self):
        without = [(line, cwe) for line, cwe, _ in _real_file_rows(PYGOAT_APIS, collector=False)]
        with_rule = [(line, cwe) for line, cwe, _ in _real_file_rows(PYGOAT_APIS)]
        self.assertEqual(sorted(set(without) - set(with_rule)), [])
        self.assertEqual(sorted(set(with_rule) - set(without)),
                         [(70, CWE94), (73, CWE94), (134, CWE94)])

    def test_pygoat_utility_module_reports_the_generated_ssrf_lab(self):
        rows = [(line, cwe) for line, cwe, message in _real_file_rows(PYGOAT_UTILITY)
                if message == MSG94]
        self.assertEqual(rows, [(36, CWE94)])


class TestCwe78AlreadyCovered(unittest.TestCase):
    """The claimed subprocess blind spot is a pre-existing rule's output, so no code was added.

    These shapes are reported even with the blind-spot CWE-78 collector switched off, which is
    why extending it to `.format` would have changed no finding anywhere.
    """

    def _cwe78_lines(self, code: str):
        original = ast_scanner.TaintTracker._collect_cwe78_subprocess_calls
        ast_scanner.TaintTracker._collect_cwe78_subprocess_calls = lambda *a, **k: None
        try:
            tracker = TaintTracker(files={"sample.py": code}, audit_all=False)
            _sources, sinks, edges = tracker.analyze()
        finally:
            ast_scanner.TaintTracker._collect_cwe78_subprocess_calls = original
        by_id = {sink.id: sink for sink in sinks}
        return {by_id[edge.target_id].location.line_start for edge in edges
                if edge.target_id in by_id
                and by_id[edge.target_id].metadata.get("cwe") == CWE78}

    def test_format_command_defined_lines_earlier_is_already_reported(self):
        code = _snippet('''
            import subprocess

            def build(domain):
                command = "nslookup {}".format(domain)
                return subprocess.Popen(command, shell=True)  # <<T>>
            ''')
        self.assertEqual(self._cwe78_lines(code) & _targets(code), _targets(code))

    def test_format_on_a_module_level_template_is_already_reported(self):
        code = _snippet('''
            import subprocess

            TEMPLATE = "dig {}"


            def build(host):
                return subprocess.run(TEMPLATE.format(host), shell=True)  # <<T>>
            ''')
        self.assertEqual(self._cwe78_lines(code) & _targets(code), _targets(code))

    def test_fstring_command_is_already_reported(self):
        code = _snippet('''
            import subprocess

            def build(host):
                return subprocess.run(f"ping -c 1 {host}", shell=True)  # <<T>>
            ''')
        self.assertEqual(self._cwe78_lines(code) & _targets(code), _targets(code))

    def test_pygoat_cmd_lab_is_reported_without_the_blindspot_collector(self):
        rows = _real_file_rows(PYGOAT_VIEWS, collector=False)
        self.assertIn((430, CWE78), [(line, cwe) for line, cwe, _ in rows])

    def test_challenge_argv_list_without_shell_stays_silent(self):
        rows = _real_file_rows(PYGOAT_CHALLENGE)
        self.assertEqual(sorted({line for line, cwe, _ in rows if cwe == CWE78}), [50])

    def test_literal_format_arguments_stay_clean(self):
        code = _snippet('''
            import subprocess

            def build():
                command = "nslookup {}".format("example.com")
                return subprocess.Popen(command, shell=True)  # <<T>>
            ''')
        self.assertEqual(self._cwe78_lines(code) & _targets(code), set())


class TestTemplateCsrfAlreadyCovered(unittest.TestCase):
    def test_nested_dockerized_lab_forms_are_discovered_and_reported(self):
        findings = audit_templates({PYGOAT_NESTED_FORM: _read(PYGOAT_NESTED_FORM)})
        self.assertEqual(sorted(f["line"] for f in findings if f["cwe"] == CWE352),
                         [13, 29, 40])

    def test_login_form_with_token_is_clean_but_reports_the_form_without_it(self):
        source = _read(PYGOAT_LOGIN)
        with_token = audit_templates({PYGOAT_LOGIN: source})
        self.assertEqual([f["line"] for f in with_token if f["cwe"] == CWE352], [])
        without_token = audit_templates({PYGOAT_LOGIN: source.replace("{% csrf_token %}", "", 1)})
        self.assertEqual([f["line"] for f in without_token if f["cwe"] == CWE352], [54])

    def test_discussion_page_forms_carry_the_entity_encoded_token(self):
        findings = audit_templates({PYGOAT_DISCUSSION: _read(PYGOAT_DISCUSSION)})
        self.assertEqual([f["line"] for f in findings if f["cwe"] == CWE352], [])
        self.assertIn("{&#37; csrf_token &#37;}", _read(PYGOAT_DISCUSSION))

    def test_entity_encoded_token_counts_on_a_nested_path(self):
        html = _snippet('''
            <form method="post" action="/ssrf_lab">
                {&#37; csrf_token &#37;}
                <button type="submit">Go</button>
            </form>
            ''')
        path = "dockerized_labs/lab_a/templates/nested/form.html"
        self.assertEqual([f["line"] for f in audit_templates({path: html})
                          if f["cwe"] == CWE352], [])

    def test_tokenless_nested_form_is_reported(self):
        html = _snippet('''
            <form method="post" action="/login">  # <<T>>
                <input type="text" name="user">
            </form>
            ''')
        path = "dockerized_labs/lab_a/templates/nested/login.html"
        findings = audit_templates({path: html})
        self.assertEqual([f["line"] for f in findings if f["cwe"] == CWE352],
                         sorted(_targets(html)))


class TestStorageAndResponseClaims(unittest.TestCase):
    def test_password_written_to_a_file_is_still_cleartext_storage(self):
        code = _snippet('''
            def dump(password):
                with open("backup.txt", "w") as handle:
                    handle.write(password)  # <<T>>
            ''')
        self.assertTrue(_lines(code, CWE312) & _targets(code))

    def test_pygoat_archive_has_no_cleartext_storage_finding(self):
        rows = _real_file_rows(PYGOAT_ARCHIVE)
        self.assertEqual(sorted({(line, cwe) for line, cwe, _message in rows}),
                         [(7, CWE352), (17, CWE287)])
        self.assertNotIn(CWE312, {cwe for _line, cwe, _message in rows})
        self.assertNotIn(49, {line for line, _cwe, _message in rows})

    def test_request_read_is_not_reported_as_header_injection(self):
        rows = _real_file_rows(PYGOAT_APIS)
        self.assertNotIn(CWE93, {cwe for _line, cwe, _ in rows})
        self.assertNotIn(65, [line for line, _cwe, _ in rows])

    def test_blog_write_flow_is_reported_as_template_injection(self):
        rows = _real_file_rows(PYGOAT_VIEWS)
        self.assertIn((990, CWE1336), [(line, cwe) for line, cwe, _ in rows])
        self.assertNotIn(981, [line for line, cwe, _ in rows if cwe in (CWE93, CWE94)])


if __name__ == "__main__":
    unittest.main()
