"""Pass 1 of the blind-spot elimination: the four Python core families, measured fixture by fixture.

Two of the four turned out to be open, and the other two were not - this file pins down which is which
so the next pass does not re-litigate it. Every case below was run before it was asserted:

* CWE-117 forwarded header -> log line: **already caught**. `headers` is a client-input container and
  `_blindspot_is_log_call` folds case, so `_LOGGER.info` is the same sink as `logger.info`.
* CWE-209 traceback in an HTTP body: **already caught**, for both `traceback.format_exc()` and the
  f-string `str(exc)` spelling.
* CWE-319 raw socket: **was open**. The transport rule reads URL strings, so
  `socket.create_connection(...)` and `socket.socket(AF_INET, SOCK_STREAM)` + `connect()` had nothing
  to match. Two collectors' worth of new signatures, no algorithm touched.
* CWE-605 `socket.INADDR_ANY`: **was open**. The interface set holds strings, and this spelling is a
  name that never resolves to one.

The negative controls are the contract: an SSL-wrapped socket, a `starttls()` socket, a bare
`socket.socket()`, `sqlite3.connect`, a loopback bind and a CRLF-sanitized header must all stay quiet.

Run it either way:
    python tests/test_blindspots_pass1.py
    python -m pytest tests/test_blindspots_pass1.py -q
"""
from __future__ import annotations

import ast
import contextlib
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ast_scanner  # noqa: E402
from ast_scanner import TaintTracker  # noqa: E402

# ─── fixtures ────────────────────────────────────────────────────────────────────────────────

# Positive: an untrusted proxy header reaching a log line. HA's own middleware rewrites `remote`
# from this header, so the value is attacker-chosen by the time it is formatted into the log.
F1_FORWARDED_LOG = '''import logging

from flask import request

_LOGGER = logging.getLogger(__name__)


def record_login():
    ip = request.headers.get("X-Forwarded-For")
    _LOGGER.info("Login attempt from %s", ip)
'''

# Positive: two spellings of a TCP socket that goes out in the clear.
F2_RAW_SOCKETS = '''import socket


def poll_device(host, port):
    sock = socket.create_connection((host, port))
    return sock.recv(1024)


def poll_raw(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s.recv(1024)
'''

# Negative control for F2: the same two sockets, each proven encrypted in its own scope.
F3_TLS_SOCKETS = '''import socket
import ssl


def secured(host, port):
    context = ssl.create_default_context()
    raw = socket.create_connection((host, port))
    return context.wrap_socket(raw, server_hostname=host)


def upgraded(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.starttls()
    return s.send(b"ping")
'''

# Positive plus negative control in one file: INADDR_ANY and "" are every-interface, 127.0.0.1 is not.
F4_BIND_VARIANTS = '''import socket


def serve_any(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((socket.INADDR_ANY, port))
    s.listen(1)


def serve_wildcard(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", port))
    s.listen(1)


def serve_loopback(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", port))
    s.listen(1)
'''

# Positive: exception detail handed to the client as the reply body.
F5_TRACEBACK_RESPONSE = '''import traceback

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/run")
def run():
    try:
        1 / 0
    except Exception:
        return jsonify({"error": traceback.format_exc()})


@app.route("/run2")
def run2():
    try:
        1 / 0
    except Exception as exc:
        return f"failed: {str(exc)}"
'''

# Negative controls: the same shapes, neutralised or belonging to a different socket API.
F6_SANITIZED_HEADER = '''import logging

from flask import request

_LOGGER = logging.getLogger(__name__)


def record_login():
    ip = request.headers.get("X-Forwarded-For", "")
    _LOGGER.info("Login attempt from %s", ip.replace("\\r", "").replace("\\n", ""))
'''

F7_NON_SOCKET_CONNECT = '''import socket
import sqlite3


def unspelled_socket(host, port):
    s = socket.socket()
    s.connect((host, port))
    return s.recv(1024)


def database(path):
    return sqlite3.connect(path)
'''

F8_LOGGER_ONLY_TRACEBACK = '''import logging
import traceback

LOGGER = logging.getLogger(__name__)


def run_quietly():
    try:
        1 / 0
    except Exception:
        LOGGER.error(traceback.format_exc())
        return None
'''

# (line, cwe, operation) for every fixture, read off a run of this exact source. Two of the four
# families were already covered (CWE-117's forwarded-header log line, CWE-209's traceback in the
# reply body); the two that were open are the raw-socket CWE-319 and the `INADDR_ANY` CWE-605.
EXPECTED = {
    "f1_forwarded_log.py": [(10, "CWE-117", "LOG_INJECTION")],
    "f2_raw_sockets.py": [(5, "CWE-319", "INSECURE_TRANSPORT"),
                          (11, "CWE-319", "INSECURE_TRANSPORT")],
    "f3_tls_sockets.py": [],
    "f4_bind_variants.py": [(6, "CWE-605", "INSECURE_SOCKET_BINDING"),
                            (12, "CWE-605", "INSECURE_SOCKET_BINDING")],
    "f5_traceback_response.py": [(13, "CWE-209", "SENSITIVE_ERROR_EXPOSURE"),
                                 (21, "CWE-209", "SENSITIVE_ERROR_EXPOSURE")],
    "f6_sanitized_header.py": [],
    "f7_non_socket_connect.py": [],
    "f8_logger_only_traceback.py": [],
}

FILES = {
    "f1_forwarded_log.py": F1_FORWARDED_LOG,
    "f2_raw_sockets.py": F2_RAW_SOCKETS,
    "f3_tls_sockets.py": F3_TLS_SOCKETS,
    "f4_bind_variants.py": F4_BIND_VARIANTS,
    "f5_traceback_response.py": F5_TRACEBACK_RESPONSE,
    "f6_sanitized_header.py": F6_SANITIZED_HEADER,
    "f7_non_socket_connect.py": F7_NON_SOCKET_CONNECT,
    "f8_logger_only_traceback.py": F8_LOGGER_ONLY_TRACEBACK,
}

TARGET_CWES = {"CWE-117", "CWE-209", "CWE-319", "CWE-605"}


def sinks_for(filename, source):
    """(line, cwe, operation) triples for one fixture, scoped to the four families under test."""
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        tracker = TaintTracker(files={filename: source}, audit_all=True)
        tracker.analyze()
    return sorted({
        (s.location.line_start, s.metadata.get("cwe"), s.operation)
        for s in tracker.sinks if s.metadata.get("cwe") in TARGET_CWES
    }), err.getvalue()


def test_positive_and_negative_fixtures():
    for filename, expected in EXPECTED.items():
        got, stderr = sinks_for(filename, FILES[filename])
        assert got == expected, f"{filename}: got {got}, expected {expected}\n{stderr[-300:]}"


def test_new_signatures_live_in_lookup_tables_not_in_algorithms():
    """The pass was an extension, not a rewrite: the tables grew, the collectors did not move."""
    src = (ROOT / "ast_scanner.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for name in ("RAW_SOCKET_ADDRESS_CALLS", "RAW_SOCKET_CONSTRUCTORS", "RAW_SOCKET_CONNECT_METHODS",
                 "RAW_SOCKET_TLS_WRAPPING_METHODS", "RAW_SOCKET_EXPLICIT_FAMILIES",
                 "INSECURE_BIND_ANY_ATTRIBUTES"):
        assert f"{name} = " in src, f"{name} must stay a module-level table"
    # `INADDR_ANY` is matched by attribute name in the existing bind branch; the value set itself is
    # untouched, so nothing that used to be silent because it was not one of the three strings can
    # become loud by accident.
    interfaces = next(node.value for node in ast.walk(tree)
                      if isinstance(node, ast.Assign)
                      and getattr(node.targets[0], "id", "") == "CWE3B_INSECURE_INTERFACES")
    assert {item.value for item in interfaces.elts} == {"0.0.0.0", "", "::"}


def test_raw_socket_collector_runs_last():
    """Sink ids are handed out in collector order, so a new collector must be appended, not inserted."""
    src = (ROOT / "ast_scanner.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    # Find the blindspot loop by the collector it calls first, then read its call order.
    loop = next(node for node in ast.walk(tree)
                if isinstance(node, ast.For)
                and any("_collect_cwe532_logging_leaks" in ast.dump(call)
                        for call in ast.walk(node) if isinstance(call, ast.Call)))
    calls = [call.func.attr for call in ast.walk(loop)
             if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
             and isinstance(call.func.value, ast.Name) and call.func.value.id == "self"
             and call.func.attr.startswith("_collect_")]
    assert calls[-1] == "_collect_cwe319_raw_socket_cleartext", calls
    assert len(calls) == len(set(calls)), calls


def test_collector_declines_test_scope_and_honours_review_markers():
    """The rule keeps the suppressions the transport family already had: no test dirs, `# nosec` ok."""
    inside_tests, _ = sinks_for("/repo/tests/hidden.py", F2_RAW_SOCKETS)
    assert inside_tests == [], inside_tests
    marked = F2_RAW_SOCKETS.replace(
        "    sock = socket.create_connection((host, port))",
        "    sock = socket.create_connection((host, port))  # nosec")
    got, _ = sinks_for("f2_raw_sockets.py", marked)
    assert got == [(11, "CWE-319", "INSECURE_TRANSPORT")], got


def test_cleartext_transport_rule_still_owns_dynamic_http_urls():
    """Non-regression: the URL rule that existed before this pass still fires, unmodified."""
    literal = 'import requests\n\n\ndef push(base):\n    return requests.post(f"http://{base}/api", json={})\n'
    got, _ = sinks_for("f9_dynamic_http.py", literal)
    assert got == [(5, "CWE-319", "INSECURE_TRANSPORT")], got
    # No `http://` spelled out means the URL rule has nothing to read, and the socket rule does not
    # guess on its behalf.
    unspelled = 'import requests\n\n\ndef push(base, path):\n    return requests.post(f"{base}{path}", json={})\n'
    got, _ = sinks_for("f9_dynamic_http.py", unspelled)
    assert got == [], got


def test_benchmark_corpus_sees_no_new_finding():
    """Parity guard in miniature, on the two corpus files whose socket spelling is the risk.

    Scanned under a non-`test_` name on purpose: the family declines test paths, so feeding these
    their real names would pass the assertion without ever reaching the socket gate.
    """
    corpus = ROOT / "benchmark" / "corpus"
    bare = (corpus / "cwe_770_unbounded_read" / "test_v05_bad.py").read_text(encoding="utf-8")
    got, _ = sinks_for("cwe_770_v05_bad.py", bare)
    assert got == [], f"bare socket.socket() must not become a CWE-319 finding: {got}"
    bad = (corpus / "cwe_605_socket_binding" / "test_v02_bad.py").read_text(encoding="utf-8")
    got, _ = sinks_for("cwe_605_v02_bad.py", bad)
    assert got == [(4, "CWE-605", "INSECURE_SOCKET_BINDING")], got
    good = (corpus / "cwe_605_socket_binding" / "test_v02_good.py").read_text(encoding="utf-8")
    got, _ = sinks_for("cwe_605_v02_good.py", good)
    assert got == [], got


def test_memory_stays_in_the_single_digit_range():
    """Eight fixtures per pass; the whole suite must not grow RSS the way a repo scan would."""
    try:
        import psutil
    except ImportError:
        return
    process = psutil.Process()
    before = process.memory_info().rss
    for _ in range(12):
        for filename, source in FILES.items():
            sinks_for(filename, source)
    growth = (process.memory_info().rss - before) / (1024 * 1024)
    assert growth < 12, f"RSS grew {growth:.1f} MB over 96 fixture scans"


if __name__ == "__main__":
    tests = [(name, obj) for name, obj in sorted(globals().items())
             if name.startswith("test_") and callable(obj)]
    failures = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL  {name}: {exc}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)
