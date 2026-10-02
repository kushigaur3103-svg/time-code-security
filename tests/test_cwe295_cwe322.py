"""
Phase 8.2 Unit Tests: CWE-295 / CWE-322

Tests:
  Positives:
    - PoolManager(cert_reqs=ssl.CERT_NONE)            → CWE-295
    - ProxyManager(cert_reqs=ssl.CERT_NONE)           → CWE-295
    - HTTPSConnectionPool(cert_reqs=ssl.CERT_OPTIONAL)→ CWE-295
    - connection_from_url(cert_reqs=ssl.CERT_NONE)    → CWE-295
    - proxy_from_url(cert_reqs=ssl.CERT_NONE)         → CWE-295
    - wrap_socket(cert_reqs=ssl.CERT_NONE)            → CWE-295
    - wrap_socket(cert_reqs="NONE")                   → CWE-295
    - set_missing_host_key_policy(AutoAddPolicy())    → CWE-322
    - set_missing_host_key_policy(WarningPolicy())    → CWE-322
    - set_missing_host_key_policy(client.WarningPolicy) → CWE-322
    - requests.get(url, verify=False)                 → CWE-295
  Negatives (MUST NOT trigger):
    - proxy_from_url(cert_reqs=None)                  → CLEAN (safe default)
    - PoolManager() without cert_reqs                 → CLEAN
    - set_missing_host_key_policy(RejectPolicy())     → CLEAN
    - standard wrap_socket without cert_reqs          → CLEAN
"""
from __future__ import annotations

import pytest
import sys
from pathlib import Path

# Ensure repository root is on sys.path so ast_scanner (and tcs/) can be imported.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ast_scanner import TaintTracker


def _scan(code: str) -> tuple:
    """Helper: scan inline code, return (sources, sinks, edges)."""
    t = TaintTracker(files={"test_cwe295_322.py": code})
    return t.analyze()


def _cwe_sinks(sinks, cwe: str) -> list:
    return [s for s in sinks if s.metadata.get("cwe") == cwe]


# ─────────────────────────────────── POSITIVES ─────────────────────────────────


class TestCWE295CertReqsPositives:
    """cert_reqs=ssl.CERT_NONE / ssl.CERT_OPTIONAL must produce CWE-295 sinks."""

    def test_pool_manager_cert_none(self):
        _, sinks, edges = _scan("""
import ssl
from urllib3 import PoolManager
manager = PoolManager(10, cert_reqs=ssl.CERT_NONE)
""")
        cwe295 = _cwe_sinks(sinks, "CWE-295")
        assert len(cwe295) >= 1, "Expected CWE-295 for PoolManager(cert_reqs=ssl.CERT_NONE)"
        assert any(e.kind == "CONFIRMED_DATA_FLOW" for e in edges), "Expected CONFIRMED edge"

    def test_proxy_manager_cert_none(self):
        _, sinks, edges = _scan("""
import ssl
import urllib3 as ur3
proxy = ur3.ProxyManager('http://localhost:3128/', cert_reqs=ssl.CERT_NONE)
""")
        cwe295 = _cwe_sinks(sinks, "CWE-295")
        assert len(cwe295) >= 1, "Expected CWE-295 for ProxyManager(cert_reqs=ssl.CERT_NONE)"

    def test_https_connection_pool_cert_optional(self):
        _, sinks, edges = _scan("""
import ssl
import urllib3 as ur3
pool = ur3.connectionpool.HTTPSConnectionPool(cert_reqs=ssl.CERT_OPTIONAL)
""")
        cwe295 = _cwe_sinks(sinks, "CWE-295")
        assert len(cwe295) >= 1, "Expected CWE-295 for HTTPSConnectionPool(cert_reqs=ssl.CERT_OPTIONAL)"

    def test_connection_from_url_cert_none(self):
        _, sinks, edges = _scan("""
import ssl
import urllib3 as ur3
pool = ur3.connection_from_url('someurl', cert_reqs=ssl.CERT_NONE)
""")
        cwe295 = _cwe_sinks(sinks, "CWE-295")
        assert len(cwe295) >= 1, "Expected CWE-295 for connection_from_url(cert_reqs=ssl.CERT_NONE)"

    def test_proxy_from_url_cert_none(self):
        _, sinks, edges = _scan("""
import ssl
import urllib3 as ur3
pool = ur3.proxy_from_url('someurl', cert_reqs=ssl.CERT_NONE)
""")
        cwe295 = _cwe_sinks(sinks, "CWE-295")
        assert len(cwe295) >= 1, "Expected CWE-295 for proxy_from_url(cert_reqs=ssl.CERT_NONE)"

    def test_wrap_socket_cert_none_attribute(self):
        _, sinks, edges = _scan("""
import ssl, socket
hostname = 'www.example.com'
context = ssl.create_default_context()
with socket.create_connection((hostname, 443)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname, cert_reqs=ssl.CERT_NONE) as ssock:
        pass
""")
        cwe295 = _cwe_sinks(sinks, "CWE-295")
        assert len(cwe295) >= 1, "Expected CWE-295 for wrap_socket(cert_reqs=ssl.CERT_NONE)"

    def test_wrap_socket_cert_none_string(self):
        _, sinks, edges = _scan("""
import ssl, socket
hostname = 'example.com'
context = ssl.create_default_context()
with socket.create_connection((hostname, 443)) as sock:
    ssock = context.wrap_socket(sock, cert_reqs='NONE')
""")
        cwe295 = _cwe_sinks(sinks, "CWE-295")
        assert len(cwe295) >= 1, "Expected CWE-295 for wrap_socket(cert_reqs='NONE')"

    def test_connection_from_url_string_none(self):
        _, sinks, edges = _scan("""
import urllib3 as ur3
pool = ur3.connection_from_url('someurl', cert_reqs='NONE')
""")
        cwe295 = _cwe_sinks(sinks, "CWE-295")
        assert len(cwe295) >= 1, "Expected CWE-295 for cert_reqs='NONE'"

    def test_requests_verify_false(self):
        _, sinks, edges = _scan("""
import requests
url = 'https://example.com'
r = requests.get(url, verify=False)
""")
        cwe295 = _cwe_sinks(sinks, "CWE-295")
        assert len(cwe295) >= 1, "Expected CWE-295 for requests.get(verify=False)"


class TestCWE322ParamikoPositives:
    """set_missing_host_key_policy with AutoAddPolicy/WarningPolicy → CWE-322."""

    def test_auto_add_policy_instantiated(self):
        _, sinks, edges = _scan("""
from paramiko import client
ssh_client = client.SSHClient()
ssh_client.set_missing_host_key_policy(client.AutoAddPolicy())
""")
        cwe322 = _cwe_sinks(sinks, "CWE-322")
        assert len(cwe322) >= 1, "Expected CWE-322 for set_missing_host_key_policy(AutoAddPolicy())"
        assert any(e.kind == "CONFIRMED_DATA_FLOW" for e in edges)

    def test_warning_policy_instantiated(self):
        _, sinks, edges = _scan("""
from paramiko import client
ssh_client = client.SSHClient()
ssh_client.set_missing_host_key_policy(client.WarningPolicy())
""")
        cwe322 = _cwe_sinks(sinks, "CWE-322")
        assert len(cwe322) >= 1, "Expected CWE-322 for set_missing_host_key_policy(WarningPolicy())"

    def test_warning_policy_bare_class(self):
        _, sinks, edges = _scan("""
from paramiko import client
ssh_client = client.SSHClient()
ssh_client.set_missing_host_key_policy(client.WarningPolicy)
""")
        cwe322 = _cwe_sinks(sinks, "CWE-322")
        assert len(cwe322) >= 1, "Expected CWE-322 for set_missing_host_key_policy(client.WarningPolicy)"

    def test_auto_add_policy_imported_direct(self):
        _, sinks, edges = _scan("""
from paramiko import client, AutoAddPolicy
ssh_client = client.SSHClient()
ssh_client.set_missing_host_key_policy(AutoAddPolicy())
""")
        cwe322 = _cwe_sinks(sinks, "CWE-322")
        assert len(cwe322) >= 1, "Expected CWE-322 for set_missing_host_key_policy(AutoAddPolicy())"

    def test_warning_policy_imported_direct(self):
        _, sinks, edges = _scan("""
from paramiko import client, WarningPolicy
ssh_client = client.SSHClient()
ssh_client.set_missing_host_key_policy(WarningPolicy())
""")
        cwe322 = _cwe_sinks(sinks, "CWE-322")
        assert len(cwe322) >= 1, "Expected CWE-322 for set_missing_host_key_policy(WarningPolicy())"


# ─────────────────────────────────── NEGATIVES ─────────────────────────────────


class TestCWE295Negatives:
    """Safe calls MUST NOT produce CWE-295 findings."""

    def test_cert_reqs_none_safe_default(self):
        """cert_reqs=None is the safe/default urllib3 sentinel — NOT a finding."""
        _, sinks, edges = _scan("""
import urllib3 as ur3
pool = ur3.proxy_from_url('someurl', cert_reqs=None)
""")
        cwe295 = _cwe_sinks(sinks, "CWE-295")
        assert len(cwe295) == 0, f"FP: cert_reqs=None flagged as CWE-295 (lines: {[s.location.line_start for s in cwe295]})"

    def test_pool_manager_without_cert_reqs(self):
        """PoolManager without cert_reqs should NOT trigger CWE-295."""
        _, sinks, edges = _scan("""
from urllib3 import PoolManager
manager = PoolManager(10)
r = manager.request('GET', 'http://google.com/')
""")
        cwe295 = _cwe_sinks(sinks, "CWE-295")
        assert len(cwe295) == 0, "FP: bare PoolManager() flagged as CWE-295"

    def test_wrap_socket_no_cert_reqs(self):
        """Default wrap_socket without cert_reqs override is safe."""
        _, sinks, edges = _scan("""
import ssl, socket
hostname = 'www.python.org'
context = ssl.create_default_context()
with socket.create_connection((hostname, 443)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        print(ssock.version())
""")
        cwe295 = _cwe_sinks(sinks, "CWE-295")
        assert len(cwe295) == 0, "FP: default wrap_socket flagged as CWE-295"

    def test_cert_reqs_required_string(self):
        """cert_reqs='CERT_REQUIRED' is safe."""
        _, sinks, edges = _scan("""
import urllib3 as ur3
pool = ur3.connection_from_url('someurl', cert_reqs='CERT_REQUIRED')
""")
        cwe295 = _cwe_sinks(sinks, "CWE-295")
        assert len(cwe295) == 0, "FP: cert_reqs='CERT_REQUIRED' flagged as CWE-295"

    def test_requests_verify_true(self):
        """requests.get with verify=True (or default) is safe."""
        _, sinks, edges = _scan("""
import requests
r = requests.get('https://api.example.com/data', verify=True)
""")
        cwe295 = _cwe_sinks(sinks, "CWE-295")
        assert len(cwe295) == 0, "FP: requests.get(verify=True) flagged as CWE-295"

    def test_constant_url_requests_get(self):
        """Constant URL requests.get without verify=False is clean."""
        _, sinks, edges = _scan("""
import requests
response = requests.get('https://api.github.com')
""")
        cwe295 = _cwe_sinks(sinks, "CWE-295")
        assert len(cwe295) == 0, "FP: constant URL requests.get flagged as CWE-295"


class TestCWE322Negatives:
    """Safe paramiko policies MUST NOT produce CWE-322 findings."""

    def test_reject_policy_is_safe(self):
        """RejectPolicy() is the safe default — must NOT trigger CWE-322."""
        _, sinks, edges = _scan("""
from paramiko import client
ssh_client = client.SSHClient()
ssh_client.set_missing_host_key_policy(client.RejectPolicy())
""")
        cwe322 = _cwe_sinks(sinks, "CWE-322")
        assert len(cwe322) == 0, "FP: RejectPolicy() flagged as CWE-322"

    def test_reject_policy_bare_class(self):
        """Bare RejectPolicy class is safe."""
        _, sinks, edges = _scan("""
from paramiko import client
ssh_client = client.SSHClient()
ssh_client.set_missing_host_key_policy(client.RejectPolicy)
""")
        cwe322 = _cwe_sinks(sinks, "CWE-322")
        assert len(cwe322) == 0, "FP: bare RejectPolicy flagged as CWE-322"
