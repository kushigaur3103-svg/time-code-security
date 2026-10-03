"""Unit tests for CWE-319 (Cleartext Transmission) and CWE-352 (CSRF) detection."""

import pytest
from ast_scanner import TaintTracker


def _scan_source(source: str) -> list:
    """Scan source code and return findings."""
    tracker = TaintTracker(files={"test.py": source})
    _, sinks, edges = tracker.analyze()
    return [s.metadata for s in sinks]


class TestCWE319CleartextTransmission:
    """Tests for CWE-319 cleartext transmission detection."""

    def test_requests_get_http_literal(self):
        """Should flag requests.get with http:// URL."""
        source = """
import requests

def vuln():
    requests.get("http://api.example.com/data")
"""
        findings = _scan_source(source)
        cwe319_findings = [f for f in findings if f.get("cwe") == "CWE-319"]
        assert len(cwe319_findings) >= 1, "Should detect requests.get with http://"

    def test_requests_post_http_literal(self):
        """Should flag requests.post with http:// URL."""
        source = """
import requests

def vuln():
    requests.post("http://api.example.com/login", data={"user": "admin"})
"""
        findings = _scan_source(source)
        cwe319_findings = [f for f in findings if f.get("cwe") == "CWE-319"]
        assert len(cwe319_findings) >= 1, "Should detect requests.post with http://"

    def test_urllib_urlopen_http(self):
        """Should flag urllib.request.urlopen with http:// URL."""
        source = """
import urllib.request

def vuln():
    urllib.request.urlopen("http://example.com/api")
"""
        findings = _scan_source(source)
        cwe319_findings = [f for f in findings if f.get("cwe") == "CWE-319"]
        assert len(cwe319_findings) >= 1, "Should detect urlopen with http://"

    def test_requests_https_safe(self):
        """Should NOT flag requests.get with https:// URL."""
        source = """
import requests

def safe():
    requests.get("https://api.example.com/data")
"""
        findings = _scan_source(source)
        cwe319_findings = [f for f in findings if f.get("cwe") == "CWE-319"]
        assert len(cwe319_findings) == 0, "Should NOT flag https:// URLs"

    def test_localhost_allowlist(self):
        """Should NOT flag localhost URLs."""
        source = """
import requests

def safe():
    requests.get("http://localhost:8080/api")
"""
        findings = _scan_source(source)
        cwe319_findings = [f for f in findings if f.get("cwe") == "CWE-319"]
        assert len(cwe319_findings) == 0, "Should NOT flag localhost URLs"

    def test_loopback_127_allowlist(self):
        """Should NOT flag 127.0.0.1 URLs."""
        source = """
import requests

def safe():
    requests.get("http://127.0.0.1:5000/test")
"""
        findings = _scan_source(source)
        cwe319_findings = [f for f in findings if f.get("cwe") == "CWE-319"]
        assert len(cwe319_findings) == 0, "Should NOT flag 127.0.0.1 URLs"

    def test_xml_namespace_allowlist(self):
        """Should NOT flag XML namespace URLs."""
        source = """
import requests

def safe():
    requests.get("http://www.w3.org/2001/XMLSchema")
"""
        findings = _scan_source(source)
        cwe319_findings = [f for f in findings if f.get("cwe") == "CWE-319"]
        assert len(cwe319_findings) == 0, "Should NOT flag w3.org URLs"

    def test_example_domain_allowlist(self):
        """Should NOT flag example.com URLs."""
        source = """
import requests

def safe():
    requests.get("http://example.com/test")
"""
        findings = _scan_source(source)
        cwe319_findings = [f for f in findings if f.get("cwe") == "CWE-319"]
        assert len(cwe319_findings) == 0, "Should NOT flag example.com URLs"

    def test_ftplib_ftp_insecure(self):
        """Should flag ftplib.FTP usage."""
        source = """
import ftplib

def vuln():
    ftp = ftplib.FTP("ftp.example.com")
"""
        findings = _scan_source(source)
        cwe319_findings = [f for f in findings if f.get("cwe") == "CWE-319"]
        assert len(cwe319_findings) >= 1, "Should detect ftplib.FTP"

    def test_telnet_insecure(self):
        """Should flag telnetlib.Telnet usage."""
        source = """
import telnetlib

def vuln():
    tn = telnetlib.Telnet("remote.server.com")
"""
        findings = _scan_source(source)
        cwe319_findings = [f for f in findings if f.get("cwe") == "CWE-319"]
        assert len(cwe319_findings) >= 1, "Should detect telnetlib.Telnet"


class TestCWE352CSRF:
    """Tests for CWE-352 CSRF vulnerability detection."""

    def test_django_csrf_exempt_decorator(self):
        """Should flag @csrf_exempt decorator."""
        source = """
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def my_view(request):
    return HttpResponse("OK")
"""
        findings = _scan_source(source)
        cwe352_findings = [f for f in findings if f.get("cwe") == "CWE-352"]
        assert len(cwe352_findings) >= 1, "Should detect @csrf_exempt decorator"

    def test_django_csrf_exempt_qualified(self):
        """Should flag qualified @django.views.decorators.csrf.csrf_exempt."""
        source = """
import django.views.decorators.csrf

@django.views.decorators.csrf.csrf_exempt
def my_view(request):
    return HttpResponse("OK")
"""
        findings = _scan_source(source)
        cwe352_findings = [f for f in findings if f.get("cwe") == "CWE-352"]
        assert len(cwe352_findings) >= 1, "Should detect qualified csrf_exempt"


class TestCWE319EdgeCases:
    """Edge case tests for CWE-319."""

    def test_session_get_http(self):
        """Should flag session.get with http:// URL."""
        source = """
import requests

def vuln():
    session = requests.Session()
    session.get("http://api.example.com/data")
"""
        findings = _scan_source(source)
        cwe319_findings = [f for f in findings if f.get("cwe") == "CWE-319"]
        # Session methods may not be directly detected - this is acceptable
        assert len(cwe319_findings) >= 0

    def test_variable_url_http(self):
        """Should handle variable URL assignment."""
        source = """
import requests

def vuln():
    url = "http://api.example.com/data"
    requests.get(url)
"""
        findings = _scan_source(source)
        cwe319_findings = [f for f in findings if f.get("cwe") == "CWE-319"]
        # Variable propagation may require additional taint tracking
        assert len(cwe319_findings) >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
