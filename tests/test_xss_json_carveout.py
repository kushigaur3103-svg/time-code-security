"""Locks the CWE-79 JSON carve-out in `_json_or_structured_body` (ast_scanner.py:1736).

The helper already honoured `content_type="application/json"` and structured literal bodies;
these tests pin the three shapes that were missing — `mimetype=`, an inline `headers` dict,
and a `headers` name that resolves to a dict literal — plus four controls proving the
carve-out is not a blanket `Response()` mute.

Blast radius, measured before shipping rather than assumed: the new branches can only run
for a call carrying a `mimetype=` or `headers=` keyword, so every file that could possibly
change behaviour is one containing those tokens. Running the committed engine (HEAD) and the
working-tree engine over exactly those 14 files in `benchmark/corpus` + `external`
(`scratch/_json_attrib.py`, same call path the gate uses) produced `REMOVED total=0`,
`ADDED total=0`, `position changes: new=0 lost=0`. So no true positive was lost, and the
carve-out's value is precision on targets shaped like VAmPI, not coverage of this corpus.

Deliberately NOT covered, and not claimed: a header written as a separate statement
(`resp = make_response(body)` then `resp.headers["Content-Type"] = "application/json"`).
That is a statement-level mutation rather than a call keyword, so it would need header
tracking across statements; such a response is still reported as CWE-79 today.
"""

from ast_scanner import TaintTracker

XSS_CWE = "CWE-79"

TEMPLATE = """
from flask import Flask, Response, request

app = Flask(__name__)


@app.route("/x")
def handler():
    name = request.args.get("name")
    %s
"""


def _sample(body_line):
    return TEMPLATE % body_line


def _response_line(code):
    for number, line in enumerate(code.splitlines(), 1):
        if "Response(" in line:
            return number
    raise AssertionError("no Response() call in sample")


def _xss_lines(code):
    tracker = TaintTracker(files={"sample.py": code}, audit_all=True)
    _sources, sinks, edges = tracker.analyze()
    by_id = {sink.id: sink for sink in sinks}
    return {by_id[edge.target_id].location.line_start
            for edge in edges
            if edge.target_id in by_id
            and by_id[edge.target_id].metadata.get("cwe") == XSS_CWE}


class TestJsonResponsesAreCarvedOut:
    def test_mimetype_application_json(self):
        code = _sample('return Response(name, mimetype="application/json")')
        assert _xss_lines(code) == set()

    def test_content_type_application_json(self):
        code = _sample('return Response(name, content_type="application/json")')
        assert _xss_lines(code) == set()

    def test_headers_dict_content_type_json(self):
        code = _sample('return Response(name, headers={"Content-Type": "application/json"})')
        assert _xss_lines(code) == set()

    def test_headers_name_resolving_to_json_dict(self):
        code = _sample('HEADERS = {"Content-Type": "application/json"}\n'
                       '    return Response(name, headers=HEADERS)')
        assert _xss_lines(code) == set()

    def test_headers_json_with_charset_parameter_is_still_json(self):
        code = _sample('return Response(name, headers={"content-type": '
                       '"application/json; charset=utf-8"})')
        assert _xss_lines(code) == set()


class TestMarkupResponsesStayFlagged:
    def test_bare_response_is_flagged(self):
        code = _sample("return Response(name)")
        assert _xss_lines(code) == {_response_line(code)}

    def test_content_type_html_is_flagged(self):
        code = _sample('return Response(name, content_type="text/html")')
        assert _xss_lines(code) == {_response_line(code)}

    def test_headers_dict_content_type_html_is_flagged(self):
        code = _sample('return Response(name, headers={"Content-Type": "text/html"})')
        assert _xss_lines(code) == {_response_line(code)}

    def test_headers_without_content_type_is_flagged(self):
        code = _sample('return Response(name, headers={"X-A": "1"})')
        assert _xss_lines(code) == {_response_line(code)}
