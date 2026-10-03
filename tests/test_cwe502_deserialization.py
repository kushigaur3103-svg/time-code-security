"""Tests for CWE-502 Insecure Deserialization detection."""

from ast_scanner import TaintTracker


def _scan(source: str) -> list[dict]:
    """Scan source code and return CWE-502 findings."""
    tracker = TaintTracker(files={"test.py": source})
    _s, sinks, edges = tracker.analyze()
    by_id = {x.id: x for x in sinks}
    findings = []
    for edge in edges:
        sink = by_id.get(edge.target_id)
        if sink is None:
            continue
        cwe = (sink.metadata or {}).get("cwe")
        if cwe == "CWE-502":
            findings.append({
                "line": sink.lineno,
                "operation": sink.operation,
                "cwe": cwe,
            })
    return findings


def test_pickle_loads_with_user_data():
    """Positive: pickle.loads(user_data)."""
    source = '''
import pickle
from flask import request

def view():
    user_data = request.cookies.get('data')
    obj = pickle.loads(user_data)
    return str(obj)
'''
    findings = _scan(source)
    assert len(findings) >= 1, f"Expected at least 1 CWE-502 finding, got {len(findings)}"
    assert any(f["line"] == 7 for f in findings), f"Expected finding on line 7 (pickle.loads), got {[f['line'] for f in findings]}"


def test_yaml_load_with_unsafe_loader():
    """Positive: yaml.load(payload, Loader=yaml.Loader)."""
    source = '''
import yaml
from django.http import HttpResponse

def view(request):
    payload = request.POST.get('yaml_data')
    data = yaml.load(payload, Loader=yaml.Loader)
    return HttpResponse(str(data))
'''
    findings = _scan(source)
    assert len(findings) >= 1, f"Expected at least 1 CWE-502 finding, got {len(findings)}"
    assert any(f["line"] == 7 for f in findings), f"Expected finding on line 7 (yaml.load), got {[f['line'] for f in findings]}"


def test_shelve_open():
    """Positive: shelve.open(filename)."""
    source = '''
import shelve
from flask import request

def view():
    filename = request.args.get('file')
    db = shelve.open(filename)
    data = db['key']
    db.close()
    return str(data)
'''
    findings = _scan(source)
    assert len(findings) >= 1, f"Expected at least 1 CWE-502 finding, got {len(findings)}"
    assert any(f["line"] == 7 for f in findings), f"Expected finding on line 7 (shelve.open), got {[f['line'] for f in findings]}"


def test_yaml_safe_load_is_safe():
    """Negative: yaml.safe_load(payload) should NOT trigger."""
    source = '''
import yaml

def safe_view(payload):
    data = yaml.safe_load(payload)
    return str(data)
'''
    findings = _scan(source)
    assert len(findings) == 0, f"Expected 0 findings for yaml.safe_load, got {len(findings)}: {findings}"


def test_yaml_load_with_safe_loader_is_safe():
    """Negative: yaml.load(payload, Loader=yaml.SafeLoader) should NOT trigger."""
    source = '''
import yaml

def safe_view(payload):
    data = yaml.load(payload, Loader=yaml.SafeLoader)
    return str(data)
'''
    findings = _scan(source)
    assert len(findings) == 0, f"Expected 0 findings for SafeLoader, got {len(findings)}: {findings}"


def test_pickle_loads_static_bytes_is_safe():
    """Negative: pickle.loads(b"static") with pure bytes should NOT trigger (zero-FP guard)."""
    source = '''
import pickle

def view():
    obj = pickle.loads(b"\\x80\\x04\\x95\\x0b\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x8c\\x03foo\\x94.")
    return str(obj)
'''
    findings = _scan(source)
    assert len(findings) == 0, f"Expected 0 findings for static bytes, got {len(findings)}: {findings}"
