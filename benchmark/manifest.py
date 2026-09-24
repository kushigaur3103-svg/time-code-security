"""TimeCodeSecurity (TCS) NIST Juliet-Style Ground-Truth Benchmark Manifest.

Defines the BenchmarkTestCase dataclass and the static registry of ground-truth
paired test cases across supported CWEs.
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class BenchmarkTestCase:
    test_id: str
    cwe: str
    file_path: str
    is_vulnerable: bool
    expected_sinks: List[str] = field(default_factory=list)
    description: str = ""

    def get_absolute_path(self, base_dir: Optional[str] = None) -> str:
        """Resolves file_path to an absolute filesystem path."""
        if os.path.isabs(self.file_path):
            return self.file_path
        if base_dir is None:
            # Default to repo root
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.normpath(os.path.join(base_dir, self.file_path))


BENCHMARK_TEST_CASES: List[BenchmarkTestCase] = [
    # CWE-89: SQL Injection
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE89-BAD",
        cwe="CWE-89",
        file_path="benchmark/corpus/cwe_89_sqli/bad.py",
        is_vulnerable=True,
        expected_sinks=["sqlite3.Cursor.execute"],
        description="SQL Injection via string interpolation in cursor.execute()"
    ),
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE89-GOOD",
        cwe="CWE-89",
        file_path="benchmark/corpus/cwe_89_sqli/good.py",
        is_vulnerable=False,
        expected_sinks=[],
        description="Remediated SQL query using parameterized placeholder tuple"
    ),

    # CWE-78: OS Command Injection
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE78-BAD",
        cwe="CWE-78",
        file_path="benchmark/corpus/cwe_78_cmdi/bad.py",
        is_vulnerable=True,
        expected_sinks=["subprocess.run"],
        description="OS Command Injection via string formatting with shell=True"
    ),
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE78-GOOD",
        cwe="CWE-78",
        file_path="benchmark/corpus/cwe_78_cmdi/good.py",
        is_vulnerable=False,
        expected_sinks=[],
        description="Safe command execution with argument list and shell=False"
    ),

    # CWE-22: Path Traversal
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE22-BAD",
        cwe="CWE-22",
        file_path="benchmark/corpus/cwe_22_traversal/bad.py",
        is_vulnerable=True,
        expected_sinks=["open"],
        description="Path Traversal via unvalidated user parameter in open()"
    ),
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE22-GOOD",
        cwe="CWE-22",
        file_path="benchmark/corpus/cwe_22_traversal/good.py",
        is_vulnerable=False,
        expected_sinks=[],
        description="Safe file access sanitized by werkzeug secure_filename()"
    ),

    # CWE-918: Server-Side Request Forgery (SSRF)
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE918-BAD",
        cwe="CWE-918",
        file_path="benchmark/corpus/cwe_918_ssrf/bad.py",
        is_vulnerable=True,
        expected_sinks=["requests.get"],
        description="Server-Side Request Forgery via unvalidated URL in requests.get()"
    ),
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE918-GOOD",
        cwe="CWE-918",
        file_path="benchmark/corpus/cwe_918_ssrf/good.py",
        is_vulnerable=False,
        expected_sinks=[],
        description="Safe HTTP request guarded by domain and scheme validator"
    ),

    # CWE-611: XML External Entity (XXE)
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE611-BAD",
        cwe="CWE-611",
        file_path="benchmark/corpus/cwe_611_xxe/bad.py",
        is_vulnerable=True,
        expected_sinks=["xml.etree.ElementTree.fromstring"],
        description="XML External Entity parsing via standard xml.etree"
    ),
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE611-GOOD",
        cwe="CWE-611",
        file_path="benchmark/corpus/cwe_611_xxe/good.py",
        is_vulnerable=False,
        expected_sinks=[],
        description="Safe XML parsing using defusedxml.ElementTree"
    ),

    # CWE-601: Open Redirect
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE601-BAD",
        cwe="CWE-601",
        file_path="benchmark/corpus/cwe_601_redirect/bad.py",
        is_vulnerable=True,
        expected_sinks=["flask.redirect"],
        description="Open URL Redirection via unvalidated user parameter"
    ),
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE601-GOOD",
        cwe="CWE-601",
        file_path="benchmark/corpus/cwe_601_redirect/good.py",
        is_vulnerable=False,
        expected_sinks=[],
        description="Safe URL redirection guarded by validator with relative fallback"
    ),

    # CWE-327: Broken Cryptography / Weak Hash
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE327-BAD",
        cwe="CWE-327",
        file_path="benchmark/corpus/cwe_327_crypto/bad.py",
        is_vulnerable=True,
        expected_sinks=["hashlib.md5"],
        description="Weak cryptographic hash MD5 used for password storage"
    ),
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE327-GOOD",
        cwe="CWE-327",
        file_path="benchmark/corpus/cwe_327_crypto/good.py",
        is_vulnerable=False,
        expected_sinks=[],
        description="Strong cryptographic hash SHA-256 for password storage"
    ),

    # CWE-338: Insecure Randomness
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE338-BAD",
        cwe="CWE-338",
        file_path="benchmark/corpus/cwe_338_random/bad.py",
        is_vulnerable=True,
        expected_sinks=["random.randint", "random.choice"],
        description="Cryptographically weak PRNG random used for security credentials"
    ),
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE338-GOOD",
        cwe="CWE-338",
        file_path="benchmark/corpus/cwe_338_random/good.py",
        is_vulnerable=False,
        expected_sinks=[],
        description="Cryptographically secure PRNG secrets used for security credentials"
    ),

    # CWE-400: Resource Exhaustion / Unbounded Read
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE400-BAD",
        cwe="CWE-400",
        file_path="benchmark/corpus/cwe_400_resource/bad.py",
        is_vulnerable=True,
        expected_sinks=["stream.read"],
        description="Unbounded stream read on untrusted network request stream"
    ),
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE400-GOOD",
        cwe="CWE-400",
        file_path="benchmark/corpus/cwe_400_resource/good.py",
        is_vulnerable=False,
        expected_sinks=[],
        description="Bounded stream read with explicit MAX_READ_SIZE buffer limit"
    ),

    # CWE-79: Cross-Site Scripting (XSS)
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE79-BAD",
        cwe="CWE-79",
        file_path="benchmark/corpus/cwe_79_xss/bad.py",
        is_vulnerable=True,
        expected_sinks=["markupsafe.Markup"],
        description="XSS via user input directly rendered via markupsafe.Markup without escaping"
    ),
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE79-GOOD",
        cwe="CWE-79",
        file_path="benchmark/corpus/cwe_79_xss/good.py",
        is_vulnerable=False,
        expected_sinks=[],
        description="Safe rendering with html.escape() sanitization before Markup"
    ),

    # CWE-95: Code Injection
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE95-BAD",
        cwe="CWE-95",
        file_path="benchmark/corpus/cwe_95_codei/bad.py",
        is_vulnerable=True,
        expected_sinks=["eval"],
        description="Code Injection via user input passed directly to eval()"
    ),
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE95-GOOD",
        cwe="CWE-95",
        file_path="benchmark/corpus/cwe_95_codei/good.py",
        is_vulnerable=False,
        expected_sinks=[],
        description="Safe expression parsing via ast.literal_eval()"
    ),

    # CWE-502: Insecure Deserialization
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE502-BAD",
        cwe="CWE-502",
        file_path="benchmark/corpus/cwe_502_deserial/bad.py",
        is_vulnerable=True,
        expected_sinks=["pickle.loads"],
        description="Insecure Deserialization of untrusted cookie payload via pickle.loads()"
    ),
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE502-GOOD",
        cwe="CWE-502",
        file_path="benchmark/corpus/cwe_502_deserial/good.py",
        is_vulnerable=False,
        expected_sinks=[],
        description="Safe deserialization using json.loads() on base64-decoded cookie"
    ),

    # CWE-295: Improper Certificate Validation (Disabled SSL)
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE295-BAD",
        cwe="CWE-295",
        file_path="benchmark/corpus/cwe_295_cert/bad.py",
        is_vulnerable=True,
        expected_sinks=["requests.get"],
        description="Disabled SSL certificate verification via verify=False in requests.get()"
    ),
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE295-GOOD",
        cwe="CWE-295",
        file_path="benchmark/corpus/cwe_295_cert/good.py",
        is_vulnerable=False,
        expected_sinks=[],
        description="SSL certificate verification enabled via verify=True"
    ),

    # CWE-1336: Server-Side Template Injection (SSTI)
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE1336-BAD",
        cwe="CWE-1336",
        file_path="benchmark/corpus/cwe_1336_ssti/bad.py",
        is_vulnerable=True,
        expected_sinks=["jinja2.Template"],
        description="SSTI via user input interpolated into jinja2.Template() constructor string"
    ),
    BenchmarkTestCase(
        test_id="TCS-BENCH-CWE1336-GOOD",
        cwe="CWE-1336",
        file_path="benchmark/corpus/cwe_1336_ssti/good.py",
        is_vulnerable=False,
        expected_sinks=[],
        description="Safe template rendering using static template string with context variable"
    ),
]


def get_benchmark_cases(cwe: Optional[str] = None) -> List[BenchmarkTestCase]:
    """Retrieve all benchmark test cases, optionally filtered by CWE."""
    if cwe is None:
        return list(BENCHMARK_TEST_CASES)
    cwe_norm = cwe.upper()
    if not cwe_norm.startswith("CWE-"):
        cwe_norm = f"CWE-{cwe_norm}"
    return [tc for tc in BENCHMARK_TEST_CASES if tc.cwe == cwe_norm]
