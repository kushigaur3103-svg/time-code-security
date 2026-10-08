"""Regression contracts for the four PyGoat blind-spot structural collectors.

Every positive case below is a shape measured in OWASP PyGoat (`external/pygoat/`) that
TimeCodeSecurity did not report before these collectors existed; every negative case is a
shape that must stay silent, taken from the repo's own ground-truth fixtures. Lines are
never hard-coded: each snippet marks the statement that should be reported with `<<T>>`, and
the assertions compare against the marker's own line number, so relocating a snippet cannot
silently change what the test proves.

Measured pre-fix baseline (`python cli.py scan external/pygoat/`): 147 findings, CWE-78 = 3,
CWE-93 = 0, CWE-532 = 0, CWE-668 = 0 - while the target really does contain
`print(user_name, passwd)` (introduction/views.py:314), `print(password)` (755, 861),
`app.run(host='0.0.0.0')` (dockerized_labs/insec_des_lab/main.py:51) and
`subprocess.Popen(command.split(" "))` over an f-string command (challenge/views.py:50, 81).

The collectors dedup against any sink an earlier phase already reported on the same
file+line+CWE, which is what the edge-count tests below pin: a rule that fires where the
taint engine already fires must add a finding nowhere.
"""

from __future__ import annotations

import textwrap
import unittest

from ast_scanner import TaintTracker

CWE78 = "CWE-78"
CWE93 = "CWE-93"
CWE532 = "CWE-532"
CWE668 = "CWE-668"

MSG532 = "CWE-532: Insertion of sensitive data into log entry"
MSG668 = "CWE-668: Insecure binding to all network interfaces (0.0.0.0)"
MSG93 = "CWE-93: Improper Neutralization of CRLF Sequences in HTTP Headers"


def _snippet(body: str) -> str:
    return textwrap.dedent(body).lstrip("\n")


def _targets(code: str):
    """1-indexed line numbers of the lines a test marks as the expected finding."""
    return {number for number, line in enumerate(code.splitlines(), 1) if "<<T>>" in line}


def _edges(tracker_code: str, cwe: str, path: str = "sample.py"):
    tracker = TaintTracker(files={path: tracker_code}, audit_all=True)
    _sources, sinks, edges = tracker.analyze()
    by_id = {sink.id: sink for sink in sinks}
    return [by_id[edge.target_id] for edge in edges
            if edge.target_id in by_id and by_id[edge.target_id].metadata.get("cwe") == cwe]


def _lines(code: str, cwe: str, path: str = "sample.py"):
    return {sink.location.line_start for sink in _edges(code, cwe, path)}


class TestCwe78ShellSubprocess(unittest.TestCase):
    def test_fstring_command_with_shell_true_is_flagged(self):
        code = _snippet('''
            import subprocess

            def ping(host):
                return subprocess.run(f"ping -c 1 {host}", shell=True)  # <<T>>
            ''')
        self.assertEqual(_lines(code, CWE78) & _targets(code), _targets(code))

    def test_concatenated_command_with_shell_true_is_flagged(self):
        code = _snippet('''
            import subprocess

            def status(job_name):
                return subprocess.run("systemctl status " + job_name, shell=True)  # <<T>>
            ''')
        self.assertEqual(_lines(code, CWE78) & _targets(code), _targets(code))

    def test_resolved_variable_and_split_argv_is_flagged(self):
        """challenge/views.py:50 - `command` is an f-string, then `.split(" ")` hides it."""
        code = _snippet('''
            import subprocess

            def launch(port, image):
                command = f"docker run -d -p {port}:{image}"
                process = subprocess.Popen(command.split(" "), stdout=subprocess.PIPE)  # <<T>>
                return process
            ''')
        self.assertEqual(_lines(code, CWE78) & _targets(code), _targets(code))

    def test_static_list_without_shell_is_clean(self):
        code = _snippet('''
            import subprocess

            def backup(filename):
                subprocess.run(["tar", "-czf", "backup.tar.gz", filename], shell=False)
            ''')
        self.assertEqual(_lines(code, CWE78), set())

    def test_static_literal_command_is_clean(self):
        code = _snippet('''
            import subprocess

            def whoami():
                subprocess.call("id", shell=True)
            ''')
        self.assertEqual(_lines(code, CWE78), set())

    def test_shell_false_is_clean_even_with_dynamic_command(self):
        code = _snippet('''
            import subprocess

            def ping(host):
                subprocess.run(["ping", "-c", "1", host], shell=False)
            ''')
        self.assertEqual(_lines(code, CWE78), set())

    def test_review_marker_suppresses_the_rule(self):
        code = _snippet('''
            import subprocess

            def ping(host):
                subprocess.run(f"ping -c 1 {host}", shell=True)  # ok: host is a uuid
            ''')
        self.assertEqual(_lines(code, CWE78), set())

    def test_does_not_duplicate_a_taint_reported_command_injection(self):
        """One finding per line+CWE, even when the taint engine already owns the line."""
        code = _snippet('''
            import subprocess
            from django.http import HttpResponse

            def view(request):
                cmd = f"grep {request.GET['q']} /var/log/app.log"
                return subprocess.run(cmd, shell=True)
            ''')
        self.assertGreaterEqual(len(_edges(code, CWE78)), 1)
        self.assertEqual(len({sink.location.line_start for sink in _edges(code, CWE78)}),
                         len(_edges(code, CWE78)))


class TestCwe532SensitiveLogging(unittest.TestCase):
    def test_logger_positional_credential_is_flagged(self):
        code = _snippet('''
            import logging

            logger = logging.getLogger(__name__)

            def store(user, password):
                logger.info("stored user %s", password)  # <<T>>
            ''')
        self.assertEqual(_lines(code, CWE532) & _targets(code), _targets(code))

    def test_print_of_credential_inside_function_is_flagged(self):
        """introduction/views.py:314 - `print(user_name, passwd)`."""
        code = _snippet('''
            def login(request, user_name, passwd):
                print(user_name, passwd)  # <<T>>
            ''')
        self.assertEqual(_lines(code, CWE532) & _targets(code), _targets(code))

    def test_fstring_interpolating_credential_is_flagged(self):
        code = _snippet('''
            def show(secret):
                print(f"value is {secret}")  # <<T>>
            ''')
        self.assertEqual(_lines(code, CWE532) & _targets(code), _targets(code))

    def test_subscript_key_is_flagged(self):
        code = _snippet('''
            def dump(data):
                print(data["api_key"])  # <<T>>
            ''')
        self.assertEqual(_lines(code, CWE532) & _targets(code), _targets(code))

    def test_attribute_credential_is_flagged(self):
        code = _snippet('''
            def audit(user):
                logger.warning("account", user.password)  # <<T>>
            ''')
        self.assertEqual(_lines(code, CWE532) & _targets(code), _targets(code))

    def test_plain_status_message_is_clean(self):
        code = _snippet('''
            import logging

            logger = logging.getLogger(__name__)

            def done():
                logger.info("Task completed successfully")
            ''')
        self.assertEqual(_lines(code, CWE532), set())

    def test_word_in_a_literal_alone_is_clean(self):
        code = _snippet('''
            def check():
                print("wrong password")
            ''')
        self.assertEqual(_lines(code, CWE532), set())

    def test_boolean_flag_names_are_clean(self):
        code = _snippet('''
            def state(has_password, password_reset_sent):
                logger.info("flags", has_password, password_reset_sent)
            ''')
        self.assertEqual(_lines(code, CWE532), set())

    def test_schema_and_field_names_are_clean(self):
        code = _snippet('''
            def schema(fields):
                print(fields["password_label"], fields["token_type"])
            ''')
        self.assertEqual(_lines(code, CWE532), set())

    def test_module_level_print_is_out_of_scope(self):
        """A print() that is not inside a function is stdout, not an application log."""
        code = _snippet('''
            import sys

            passwd = sys.argv[1]
            print(passwd)
        ''')
        self.assertEqual(_lines(code, CWE532), set())

    def test_message_text_is_exact(self):
        code = _snippet('''
            def show(secret):
                print(secret)  # <<T>>
            ''')
        messages = {sink.metadata.get("message") for sink in _edges(code, CWE532)}
        self.assertEqual(messages, {MSG532})


class TestCwe668InsecureHostBinding(unittest.TestCase):
    def test_wildcard_ipv4_bind_is_flagged(self):
        code = _snippet('''
            from flask import Flask

            app = Flask(__name__)

            def main():
                app.run(host="0.0.0.0", port=8080)  # <<T>>
            ''')
        self.assertEqual(_lines(code, CWE668) & _targets(code), _targets(code))

    def test_wildcard_ipv6_bind_is_flagged(self):
        code = _snippet('''
            def main(server):
                server.run(host="::")  # <<T>>
            ''')
        self.assertEqual(_lines(code, CWE668) & _targets(code), _targets(code))

    def test_loopback_bind_is_clean(self):
        code = _snippet('''
            from flask import Flask

            app = Flask(__name__)

            def main():
                app.run(host="127.0.0.1", port=5000)
            ''')
        self.assertEqual(_lines(code, CWE668), set())

    def test_bind_without_host_is_clean(self):
        code = _snippet('''
            def main(app):
                app.run(debug=True)
            ''')
        self.assertEqual(_lines(code, CWE668), set())

    def test_dynamic_host_is_left_to_the_taint_engine(self):
        code = _snippet('''
            def main(app, host):
                app.run(host=host)
            ''')
        self.assertEqual(_lines(code, CWE668), set())

    def test_message_text_is_exact_inside_a_container_lab(self):
        """dockerized_labs/* is suppressed by the older binding rule, so this collector owns it."""
        code = _snippet('''
            from flask import Flask

            app = Flask(__name__)

            def main():
                app.run(host="0.0.0.0", port=8080)  # <<T>>
            ''')
        sinks = _edges(code, CWE668, path="dockerized_labs/insec_des_lab/main.py")
        self.assertEqual({sink.metadata.get("message") for sink in sinks}, {MSG668})
        self.assertEqual({sink.location.line_start for sink in sinks} & _targets(code),
                         _targets(code))

    def test_does_not_duplicate_the_older_binding_rule(self):
        """Outside a container path the older rule already reports it: one finding, not two."""
        code = _snippet('''
            def main(app):
                app.run(host="0.0.0.0")
            ''')
        self.assertEqual(len(_edges(code, CWE668)), 1)


class TestCwe93HeaderInjection(unittest.TestCase):
    def test_subscript_assignment_from_get_is_flagged(self):
        code = _snippet('''
            def view(request, response):
                response["X-Custom"] = request.GET["data"]  # <<T>>
            ''')
        self.assertEqual(_lines(code, CWE93) & _targets(code), _targets(code))

    def test_set_cookie_with_assigned_post_value_is_flagged(self):
        """PyGoat shape: `email = request.POST['email']` then `html.set_cookie("email", email)`."""
        code = _snippet('''
            from django.http import HttpResponse

            def view(request):
                html = HttpResponse()
                email = request.POST["email"]
                html.set_cookie("email", email)  # <<T>>
                return html
            ''')
        self.assertEqual(_lines(code, CWE93) & _targets(code), _targets(code))

    def test_set_header_from_cookie_is_flagged(self):
        code = _snippet('''
            def view(request, response):
                response.set_header("Location", request.COOKIES["next"])  # <<T>>
            ''')
        self.assertEqual(_lines(code, CWE93) & _targets(code), _targets(code))

    def test_headers_keyword_is_flagged(self):
        code = _snippet('''
            from django.http import HttpResponse

            def view(request):
                return HttpResponse(headers={"X-Trace": request.META["HTTP_X_TRACE"]})  # <<T>>
            ''')
        self.assertEqual(_lines(code, CWE93) & _targets(code), _targets(code))

    def test_static_header_value_is_clean(self):
        code = _snippet('''
            def view(request, response):
                response["Content-Type"] = "text/plain"
            ''')
        self.assertEqual(_lines(code, CWE93), set())

    def test_static_header_keyword_is_clean(self):
        code = _snippet('''
            from django.http import HttpResponse

            def view(request):
                return HttpResponse(headers={"X-App": "pygoat"})
            ''')
        self.assertEqual(_lines(code, CWE93), set())

    def test_server_supplied_value_is_clean(self):
        code = _snippet('''
            from django.http import HttpResponse

            def view(request, user):
                return HttpResponse(headers={"X-Uid": user.userid})
            ''')
        self.assertEqual(_lines(code, CWE93), set())

    def test_non_response_object_assignment_is_clean(self):
        code = _snippet('''
            def view(request, context):
                context["q"] = request.GET["q"]
            ''')
        self.assertEqual(_lines(code, CWE93), set())

    def test_message_text_is_exact(self):
        code = _snippet('''
            def view(request, response):
                response["X"] = request.POST["y"]  # <<T>>
            ''')
        messages = {sink.metadata.get("message") for sink in _edges(code, CWE93)}
        self.assertEqual(messages, {MSG93})


if __name__ == "__main__":
    unittest.main()
