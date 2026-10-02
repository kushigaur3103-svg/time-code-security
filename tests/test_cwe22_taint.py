"""Unit tests for Phase 7.2: CWE-22 Path Traversal Sinks & DRF Sources (Zero-FP Policy).

Verifies:
1. DRF request.data subscript and .get() taint flow to file sinks (open, send_file).
2. Flask route parameter seeding (<path:filename>, <filename>) into send_file sink.
3. Sanitizer suppression with os.path.basename and werkzeug.utils.secure_filename.
4. Non-route functions and constant arguments stay clean (zero FP).
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ast_scanner import TaintTracker
from cli import consolidate_findings, get_rule


def _scan_snippet(code: str) -> list[dict]:
    """Run TaintTracker on a code snippet and return consolidated findings."""
    tracker = TaintTracker(files={"test_app.py": code})
    sources, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    raw: list[dict] = []
    seen = set()

    for edge in edges:
        sink = by_id.get(edge.target_id)
        if sink is None:
            continue
        cwe = (sink.metadata or {}).get("cwe")
        if not cwe and edge.proof_graph is not None:
            cwe = edge.proof_graph.cwe
        cwe = cwe or "UNKNOWN_CWE"
        rule = get_rule(cwe)
        confidence_label = "CONFIRMED" if edge.kind == "CONFIRMED_DATA_FLOW" else "POTENTIAL"
        severity = rule.get_severity(confidence_label).upper() if rule else "HIGH"
        location = sink.location
        finding = {
            "file": location.file.replace("\\", "/"),
            "line": location.line_start,
            "cwe": cwe,
            "severity": severity,
            "category": (sink.metadata or {}).get("category") or (rule.category if rule else "Security"),
            "message": f"{cwe}: {(sink.metadata or {}).get('operation') or sink.symbol}",
        }
        identity = (finding["file"], finding["line"], finding["cwe"])
        if identity not in seen:
            seen.add(identity)
            raw.append(finding)
    return consolidate_findings(raw)


def test_drf_request_data_subscript_to_open_positive():
    """DRF request.data['path'] flowing to open() must trigger CWE-22."""
    code = """
def api_view(request):
    file_path = request.data['path']
    with open(file_path, 'r') as f:
        return f.read()
"""
    findings = _scan_snippet(code)
    cwe22_findings = [f for f in findings if f["cwe"] == "CWE-22"]
    assert len(cwe22_findings) == 1
    assert cwe22_findings[0]["line"] == 4


def test_drf_request_data_get_to_open_positive():
    """DRF request.data.get('path') flowing to open() must trigger CWE-22."""
    code = """
def api_view(request):
    file_path = request.data.get('path')
    f = open(file_path, 'w')
    f.write('data')
    f.close()
"""
    findings = _scan_snippet(code)
    cwe22_findings = [f for f in findings if f["cwe"] == "CWE-22"]
    assert len(cwe22_findings) == 1
    assert cwe22_findings[0]["line"] == 4


def test_flask_route_param_to_send_file_positive():
    """Flask route parameter <path:filename> flowing to send_file() must trigger CWE-22."""
    code = """
from flask import Flask, send_file

app = Flask(__name__)

@app.route("/<path:filename>")
def download_file(filename):
    return send_file(filename)
"""
    findings = _scan_snippet(code)
    cwe22_findings = [f for f in findings if f["cwe"] == "CWE-22"]
    assert len(cwe22_findings) == 1
    assert cwe22_findings[0]["line"] == 8


def test_flask_route_param_keyword_send_file_positive():
    """Flask route parameter flowing to send_file(filename_or_fp=...) must trigger CWE-22."""
    code = """
from flask import Flask, send_file

app = Flask(__name__)

@app.route("/files/<filename>")
def download_file(filename):
    return send_file(filename_or_fp=filename)
"""
    findings = _scan_snippet(code)
    cwe22_findings = [f for f in findings if f["cwe"] == "CWE-22"]
    assert len(cwe22_findings) == 1
    assert cwe22_findings[0]["line"] == 8


def test_sanitizer_os_path_basename_suppression_negative():
    """os.path.basename() sanitizer must suppress CWE-22 on send_file()."""
    code = """
import os
from flask import Flask, send_file

app = Flask(__name__)

@app.route("/<path:filename>")
def download_file(filename):
    safe_name = os.path.basename(filename)
    return send_file(safe_name)
"""
    findings = _scan_snippet(code)
    cwe22_findings = [f for f in findings if f["cwe"] == "CWE-22"]
    assert len(cwe22_findings) == 0


def test_sanitizer_secure_filename_suppression_negative():
    """werkzeug.utils.secure_filename() must suppress CWE-22 on open()."""
    code = """
from werkzeug.utils import secure_filename

def upload_view(request):
    raw_path = request.data['path']
    clean_path = secure_filename(raw_path)
    with open(clean_path, 'r') as f:
        return f.read()
"""
    findings = _scan_snippet(code)
    cwe22_findings = [f for f in findings if f["cwe"] == "CWE-22"]
    assert len(cwe22_findings) == 0


def test_non_route_function_send_file_zero_fp_negative():
    """Undecorated helper function calling send_file must NOT produce a false positive."""
    code = """
from flask import send_file

def download_not_flask_route(filename):
    return send_file(filename)
"""
    findings = _scan_snippet(code)
    cwe22_findings = [f for f in findings if f["cwe"] == "CWE-22"]
    assert len(cwe22_findings) == 0


def test_constant_filename_send_file_zero_fp_negative():
    """send_file with a constant path must NOT trigger CWE-22."""
    code = """
from flask import send_file

def serve_index():
    return send_file("static/index.html")
"""
    findings = _scan_snippet(code)
    cwe22_findings = [f for f in findings if f["cwe"] == "CWE-22"]
    assert len(cwe22_findings) == 0
