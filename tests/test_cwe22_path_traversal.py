"""Tests for CWE-22 Path Traversal detection."""

from ast_scanner import TaintTracker


def _scan(source: str) -> list[dict]:
    """Scan source code and return CWE-22 findings."""
    tracker = TaintTracker(files={"test.py": source})
    _s, sinks, edges = tracker.analyze()
    by_id = {x.id: x for x in sinks}
    findings = []
    for edge in edges:
        sink = by_id.get(edge.target_id)
        if sink is None:
            continue
        cwe = (sink.metadata or {}).get("cwe")
        if cwe == "CWE-22":
            findings.append({
                "line": sink.lineno,
                "operation": sink.operation,
                "cwe": cwe,
            })
    return findings


def test_open_with_request_get():
    """Positive: open(f"/data/{request.GET['file']}")."""
    source = '''
from django.http import HttpResponse

def view(request):
    filename = request.GET['file']
    f = open(f"/data/{filename}", 'r')
    return HttpResponse(f.read())
'''
    findings = _scan(source)
    assert len(findings) >= 1, f"Expected at least 1 CWE-22 finding, got {len(findings)}"
    assert any(f["line"] == 6 for f in findings), f"Expected finding on line 6 (open call), got {[f['line'] for f in findings]}"


def test_os_path_join_open():
    """Positive: os.path.join + open with request data."""
    source = '''
import os
from django.http import HttpResponse

def view(request):
    param = request.GET.get('param')
    file_path = os.path.join("/uploads", param)
    f = open(file_path, 'r')
    return HttpResponse(f.read())
'''
    findings = _scan(source)
    assert len(findings) >= 1, f"Expected at least 1 CWE-22 finding, got {len(findings)}"
    # Should detect either the join or the open (or both)
    assert any(f["line"] in (7, 8) for f in findings), f"Expected finding on line 7 or 8, got {[f['line'] for f in findings]}"


def test_static_literal_safe():
    """Negative: static literal path should not trigger."""
    source = '''
def safe():
    f = open("/tmp/data.txt", 'r')
    return f.read()
'''
    findings = _scan(source)
    assert len(findings) == 0, f"Expected 0 findings for static literal, got {len(findings)}: {findings}"


def test_secure_filename_sanitized():
    """Negative: secure_filename sanitized path should not trigger."""
    source = '''
from werkzeug.utils import secure_filename
from flask import request

def safe(request):
    filename = secure_filename(request.files['file'].filename)
    f = open(f"/uploads/{filename}", 'r')
    return f.read()
'''
    findings = _scan(source)
    assert len(findings) == 0, f"Expected 0 findings for secure_filename, got {len(findings)}: {findings}"


def test_suppressed_ok_marker():
    """Negative: # ok: suppression marker should silence finding."""
    source = '''
from django.http import HttpResponse

def view(request):
    # ok: intentional test file access
    filename = request.GET.get('file')
    f = open(filename, 'r')
    return HttpResponse(f.read())
'''
    findings = _scan(source)
    assert len(findings) == 0, f"Expected 0 findings with # ok: marker, got {len(findings)}: {findings}"
