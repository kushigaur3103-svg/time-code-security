"""
Phase 11 Step 2 Unit Tests: OSV API Client & Cache Layer (osv_client.py).
Tests are 100% offline with zero live network calls. Socket connections are blocked.
"""

import sys
import json
import socket
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List, Any
import urllib.error

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Import networking modules first before blocking connections
import urllib.request
import ssl

# Forbid all live socket connections
def _blocked_connect(*args, **kwargs):
    raise RuntimeError("Live network access is strictly forbidden in Phase 11 unit tests!")

socket.socket.connect = _blocked_connect
socket.create_connection = _blocked_connect

from osv_client import (
    OSVClient,
    OSVVulnerability,
    OSVAffectedRange,
    OSVQueryResult,
    DEFAULT_BATCH_CHUNK_SIZE,
    _parse_osv_vuln
)


class TestOSVClientOffline(unittest.TestCase):

    def setUp(self):
        self.sample_raw_vuln = {
            "id": "GHSA-j8r2-6x86-q33q",
            "summary": "Requests vulnerable to session fixation",
            "details": "Requests 2.3.0 through 2.31.0 leaks authorization headers...",
            "aliases": ["CVE-2023-32681"],
            "affected": [
                {
                    "package": {
                        "name": "requests",
                        "ecosystem": "PyPI"
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "2.3.0"},
                                {"fixed": "2.31.0"}
                            ]
                        }
                    ],
                    "versions": ["2.3.0", "2.4.0", "2.30.0"]
                }
            ],
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N"
                }
            ],
            "references": [
                {
                    "type": "ADVISORY",
                    "url": "https://github.com/advisories/GHSA-j8r2-6x86-q33q"
                }
            ]
        }

    def test_socket_is_blocked(self):
        """Verify that any attempt to open a socket connection raises RuntimeError."""
        with socket.socket() as s:
            with self.assertRaises(RuntimeError) as ctx:
                s.connect(("8.8.8.8", 80))
            self.assertIn("Live network access is strictly forbidden", str(ctx.exception))

    def test_batch_query_chunking(self):
        """Test that query_packages chunks queries exceeding batch_chunk_size (e.g. 1200 packages)."""
        calls = []

        def mock_requester(url: str, payload_bytes: bytes, timeout: float) -> bytes:
            payload = json.loads(payload_bytes.decode("utf-8"))
            queries = payload.get("queries", [])
            calls.append(len(queries))
            # Return empty vulns for each queried package
            results = [{"vulns": []} for _ in queries]
            return json.dumps({"results": results}).encode("utf-8")

        client = OSVClient(batch_chunk_size=500, http_requester=mock_requester)
        pkgs = [f"pkg-{i}" for i in range(1200)]
        results = client.query_packages(pkgs)

        self.assertEqual(len(results), 1200)
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls, [500, 500, 200])

    def test_local_cache_hit_prevents_secondary_request(self):
        """Test that a second query for the same package hits cache without calling requester."""
        call_count = 0

        def mock_requester(url: str, payload_bytes: bytes, timeout: float) -> bytes:
            nonlocal call_count
            call_count += 1
            payload = json.loads(payload_bytes.decode("utf-8"))
            queries = payload.get("queries", [])
            results = [{"vulns": [self.sample_raw_vuln]} for _ in queries]
            return json.dumps({"results": results}).encode("utf-8")

        client = OSVClient(http_requester=mock_requester)

        # First query: should call requester
        res1 = client.query_package("requests")
        self.assertEqual(call_count, 1)
        self.assertEqual(res1.source, "network")
        self.assertTrue(res1.has_vulnerabilities)
        self.assertEqual(res1.vulnerabilities[0].vuln_id, "GHSA-j8r2-6x86-q33q")

        # Second query: should hit cache directly, no new requester call
        res2 = client.query_package("requests")
        self.assertEqual(call_count, 1)
        self.assertEqual(res2.source, "cache")
        self.assertTrue(res2.has_vulnerabilities)
        self.assertEqual(res2.vulnerabilities[0].vuln_id, "GHSA-j8r2-6x86-q33q")

    def test_disk_cache_persistence(self):
        """Test that disk cache is saved and can be reloaded by a new OSVClient instance."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = str(Path(tmpdir) / "osv_cache.json")
            call_count = 0

            def mock_requester(url: str, payload_bytes: bytes, timeout: float) -> bytes:
                nonlocal call_count
                call_count += 1
                return json.dumps({"results": [{"vulns": [self.sample_raw_vuln]}]}).encode("utf-8")

            # Client 1 queries and persists
            client1 = OSVClient(cache_file=cache_file, http_requester=mock_requester)
            res1 = client1.query_package("requests")
            self.assertEqual(call_count, 1)
            self.assertTrue(Path(cache_file).exists())

            # Client 2 starts fresh with cache_file: should hit disk cache without network call
            client2 = OSVClient(cache_file=cache_file, http_requester=mock_requester)
            res2 = client2.query_package("requests")
            self.assertEqual(call_count, 1)  # No additional network call
            self.assertEqual(res2.source, "cache")
            self.assertEqual(len(res2.vulnerabilities), 1)

    def test_offline_mode_without_cache(self):
        """Test that offline_mode=True returns offline_fallback for uncached packages without calling requester."""
        requester_called = False

        def mock_requester(url: str, payload_bytes: bytes, timeout: float) -> bytes:
            nonlocal requester_called
            requester_called = True
            return b"{}"

        client = OSVClient(offline_mode=True, http_requester=mock_requester)
        res = client.query_package("flask")

        self.assertFalse(requester_called)
        self.assertEqual(res.source, "offline_fallback")
        self.assertEqual(res.vulnerabilities, [])
        self.assertIn("Offline mode active", str(res.error))

    def test_offline_fixtures(self):
        """Test that offline_fixtures pre-populates the cache and works offline."""
        fixtures = {
            "jinja2": [self.sample_raw_vuln]
        }
        client = OSVClient(offline_mode=True, offline_fixtures=fixtures)
        res = client.query_package("jinja2")

        self.assertEqual(res.source, "cache")
        self.assertTrue(res.has_vulnerabilities)
        self.assertEqual(res.vulnerabilities[0].vuln_id, "GHSA-j8r2-6x86-q33q")

    def test_http_500_server_error_retries_and_backs_off(self):
        """Test that HTTP 500 / 503 triggers retries up to max_retries before returning error."""
        attempts = 0

        def mock_failing_requester(url: str, payload_bytes: bytes, timeout: float) -> bytes:
            nonlocal attempts
            attempts += 1
            raise urllib.error.HTTPError(
                url=url,
                code=500,
                msg="Internal Server Error",
                hdrs={},
                fp=None
            )

        client = OSVClient(
            max_retries=3,
            backoff_factor=0.01,  # Short backoff for fast unit test
            http_requester=mock_failing_requester
        )
        res = client.query_package("cryptography")

        self.assertEqual(attempts, 3)
        self.assertEqual(res.source, "error")
        self.assertIn("HTTP 500", str(res.error))
        self.assertEqual(res.vulnerabilities, [])

    def test_http_400_client_error_fails_fast(self):
        """Test that HTTP 400 / 404 client error fails fast with 0 retries."""
        attempts = 0

        def mock_bad_request_requester(url: str, payload_bytes: bytes, timeout: float) -> bytes:
            nonlocal attempts
            attempts += 1
            raise urllib.error.HTTPError(
                url=url,
                code=400,
                msg="Bad Request",
                hdrs={},
                fp=None
            )

        client = OSVClient(
            max_retries=3,
            backoff_factor=0.01,
            http_requester=mock_bad_request_requester
        )
        res = client.query_package("badpkg")

        self.assertEqual(attempts, 1)  # Only 1 attempt, no retry
        self.assertEqual(res.source, "error")
        self.assertIn("HTTP 400", str(res.error))
        self.assertEqual(res.vulnerabilities, [])

    def test_network_timeout_retries_and_returns_offline_fallback(self):
        """Test that network timeout retries up to max_retries and returns offline_fallback."""
        attempts = 0

        def mock_timeout_requester(url: str, payload_bytes: bytes, timeout: float) -> bytes:
            nonlocal attempts
            attempts += 1
            raise TimeoutError("Connection timed out")

        client = OSVClient(
            max_retries=3,
            backoff_factor=0.01,
            http_requester=mock_timeout_requester
        )
        res = client.query_package("requests")

        self.assertEqual(attempts, 3)
        self.assertEqual(res.source, "offline_fallback")
        self.assertIn("Network error", str(res.error))

    def test_package_with_zero_vulnerabilities(self):
        """Test that a package with no advisories returns clean empty list."""
        def mock_clean_requester(url: str, payload_bytes: bytes, timeout: float) -> bytes:
            return json.dumps({"results": [{}]}).encode("utf-8")

        client = OSVClient(http_requester=mock_clean_requester)
        res = client.query_package("safe-package")

        self.assertEqual(res.source, "network")
        self.assertEqual(res.vulnerabilities, [])
        self.assertFalse(res.has_vulnerabilities)
        self.assertIsNone(res.error)

    def test_data_extraction_and_normalization(self):
        """Test accurate parsing of OSV vulnerability JSON into OSVVulnerability dataclass."""
        vuln = _parse_osv_vuln("requests", self.sample_raw_vuln)

        self.assertEqual(vuln.vuln_id, "GHSA-j8r2-6x86-q33q")
        self.assertEqual(vuln.package_name, "requests")
        self.assertEqual(vuln.ecosystem, "PyPI")
        self.assertEqual(vuln.summary, "Requests vulnerable to session fixation")
        self.assertEqual(vuln.aliases, ("CVE-2023-32681",))
        self.assertEqual(len(vuln.affected_ranges), 1)

        aff_range = vuln.affected_ranges[0]
        self.assertEqual(aff_range.type, "ECOSYSTEM")
        self.assertEqual(aff_range.events, ({"introduced": "2.3.0"}, {"fixed": "2.31.0"}))
        self.assertEqual(aff_range.versions, ("2.3.0", "2.4.0", "2.30.0"))

        self.assertEqual(len(vuln.severity), 1)
        self.assertEqual(vuln.severity[0]["type"], "CVSS_V3")
        self.assertEqual(vuln.severity[0]["score"], "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N")

        self.assertEqual(len(vuln.references), 1)
        self.assertEqual(vuln.references[0]["url"], "https://github.com/advisories/GHSA-j8r2-6x86-q33q")


if __name__ == "__main__":
    unittest.main(verbosity=2)
