"""
Unit tests for CWE-918 (Server-Side Request Forgery / SSRF) taint analysis.

Verifies:
1. Route parameters and request inputs flowing into HTTP network sinks (requests, httpx, urllib, aiohttp).
2. URL formatting propagators (f-strings, %, .format(), +, +=) creating tainted URL host findings.
3. Fixed static host allowlist guards and static prefix checks suppressing SSRF findings.
4. Clean handling of unrecorded class attributes (e.g. self.base_url).
"""

from ast_scanner import TaintTracker


def test_route_param_to_requests_get_tainted():
    code = """
import flask
import requests

app = flask.Flask(__name__)

@app.route("/user/<username>")
def view_user(username):
    url = f"https://{username}/profile"
    requests.get(url)
    return True
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    cwe918_edges = [
        e for e in edges
        if e.target_id in by_id and by_id[e.target_id].metadata.get("cwe") == "CWE-918"
    ]
    assert len(cwe918_edges) >= 1


def test_percent_formatting_host_tainted():
    code = """
import flask
import requests

app = flask.Flask(__name__)

@app.route("/fetch")
def fetch():
    host = flask.request.args.get("host")
    url = "https://%s/data" % host
    requests.get(url)
    return url
"""
    # The sink is required, not decoration: building a URL is only SSRF once it is sent
    # (ast_scanner.py suppresses host-tainted URLs that never reach a network call).
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    assert any(
        by_id[e.target_id].metadata.get("cwe") == "CWE-918"
        for e in edges if e.target_id in by_id
    )


def test_format_call_host_tainted():
    code = """
import flask

app = flask.Flask(__name__)

@app.route("/goto/<domain>")
def goto(domain):
    return "<a href='https://{}/login'>Go</a>".format(domain)
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    assert any(
        by_id[e.target_id].metadata.get("cwe") == "CWE-918"
        for e in edges if e.target_id in by_id
    )


def test_concat_plus_host_tainted():
    code = """
import flask

app = flask.Flask(__name__)

@app.route("/proxy")
def proxy():
    target = flask.request.args.get("target")
    return "<a href='http://" + target + "'>Click</a>"
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    assert any(
        by_id[e.target_id].metadata.get("cwe") == "CWE-918"
        for e in edges if e.target_id in by_id
    )


def test_inplace_augassign_host_tainted():
    code = """
import flask
import requests

app = flask.Flask(__name__)

@app.route("/load")
def load():
    url = "https://"
    url += flask.request.args.get("target")
    requests.get(url)
    return True
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    assert any(
        by_id[e.target_id].metadata.get("cwe") == "CWE-918"
        for e in edges if e.target_id in by_id
    )


def test_httpx_async_client_tainted():
    code = """
import flask
import httpx

app = flask.Flask(__name__)

@app.route("/api/<endpoint>")
async def api_call(endpoint):
    client = httpx.AsyncClient()
    await client.get(f"https://{endpoint}/v1")
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    assert any(
        by_id[e.target_id].metadata.get("cwe") == "CWE-918"
        for e in edges if e.target_id in by_id
    )


def test_urllib_request_urlopen_tainted():
    code = """
import flask
import urllib.request

app = flask.Flask(__name__)

@app.route("/pull")
def pull():
    url = flask.request.args.get("url")
    urllib.request.urlopen(url)
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    assert any(
        by_id[e.target_id].metadata.get("cwe") == "CWE-918"
        for e in edges if e.target_id in by_id
    )


def test_aiohttp_client_session_tainted():
    code = """
import flask
import aiohttp

app = flask.Flask(__name__)

@app.route("/fetch_aio")
async def fetch_aio():
    url = flask.request.args.get("url")
    session = aiohttp.ClientSession()
    await session.get(url)
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    assert any(
        by_id[e.target_id].metadata.get("cwe") == "CWE-918"
        for e in edges if e.target_id in by_id
    )


def test_constant_url_safe():
    code = """
import requests

def safe_fetch():
    requests.get("https://api.github.com/zen")
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    cwe918_edges = [
        e for e in edges
        if e.target_id in by_id and by_id[e.target_id].metadata.get("cwe") == "CWE-918"
    ]
    assert len(cwe918_edges) == 0


def test_fixed_host_path_interpolation_safe():
    code = """
import flask
import requests

app = flask.Flask(__name__)

@app.route("/user/<uid>")
def profile(uid):
    requests.get(f"https://example.com/api/users/{uid}")
    return True
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    cwe918_edges = [
        e for e in edges
        if e.target_id in by_id and by_id[e.target_id].metadata.get("cwe") == "CWE-918"
    ]
    assert len(cwe918_edges) == 0


def test_static_prefix_startswith_guard_safe():
    code = """
import flask
import requests

app = flask.Flask(__name__)

@app.route("/forward")
def forward():
    url = flask.request.args.get("url")
    if url.startswith("https://trusted.corp.com/"):
        requests.get(url)
    return True
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    cwe918_edges = [
        e for e in edges
        if e.target_id in by_id and by_id[e.target_id].metadata.get("cwe") == "CWE-918"
    ]
    assert len(cwe918_edges) == 0


def test_unrecorded_class_attr_safe():
    code = """
import requests

class ScmClient:
    def get_file(self, path):
        requests.get(self.base_url + "/files/" + path)
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    cwe918_edges = [
        e for e in edges
        if e.target_id in by_id and by_id[e.target_id].metadata.get("cwe") == "CWE-918"
    ]
    assert len(cwe918_edges) == 0
