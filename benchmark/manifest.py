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

    # ─── Multi-Variant Stress Corpus (140 cases) ───
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE89-V01-BAD',
        cwe='CWE-89',
        file_path='benchmark/corpus/cwe_89_sqli/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['sqlite3.Cursor.execute'],
        description='Direct SQLi via f-string in cursor.execute()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE89-V01-GOOD',
        cwe='CWE-89',
        file_path='benchmark/corpus/cwe_89_sqli/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Parameterized query; no taint reaches execute()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE89-V02-BAD',
        cwe='CWE-89',
        file_path='benchmark/corpus/cwe_89_sqli/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['sqlite3.Cursor.execute'],
        description='Multi-hop SQLi: taint flows through build_query() helper'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE89-V02-GOOD',
        cwe='CWE-89',
        file_path='benchmark/corpus/cwe_89_sqli/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: int() cast sanitizes uid before execute()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE89-V03-BAD',
        cwe='CWE-89',
        file_path='benchmark/corpus/cwe_89_sqli/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['sqlite3.Cursor.execute'],
        description='Container SQLi: f-string stored in dict then executed'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE89-V03-GOOD',
        cwe='CWE-89',
        file_path='benchmark/corpus/cwe_89_sqli/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: parameterized query via dict, int cast'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE89-V04-BAD',
        cwe='CWE-89',
        file_path='benchmark/corpus/cwe_89_sqli/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['sqlite3.Cursor.execute'],
        description='OOP SQLi: tainted query stored as self.query in __init__'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE89-V04-GOOD',
        cwe='CWE-89',
        file_path='benchmark/corpus/cwe_89_sqli/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: parameterized query in OOP fetch method'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE89-V05-BAD',
        cwe='CWE-89',
        file_path='benchmark/corpus/cwe_89_sqli/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['sqlite3.Cursor.execute'],
        description='Branch SQLi: taint in both if/else arms fed to execute()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE89-V05-GOOD',
        cwe='CWE-89',
        file_path='benchmark/corpus/cwe_89_sqli/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: table name is literal; uid bound as parameter'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE78-V01-BAD',
        cwe='CWE-78',
        file_path='benchmark/corpus/cwe_78_cmdi/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['subprocess.run'],
        description='Direct CMDi: f-string in subprocess.run with shell=True'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE78-V01-GOOD',
        cwe='CWE-78',
        file_path='benchmark/corpus/cwe_78_cmdi/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: list args, shell=False'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE78-V02-BAD',
        cwe='CWE-78',
        file_path='benchmark/corpus/cwe_78_cmdi/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['subprocess.run'],
        description='Multi-hop CMDi: build_cmd() returns tainted shell string'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE78-V02-GOOD',
        cwe='CWE-78',
        file_path='benchmark/corpus/cwe_78_cmdi/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: regex whitelist + list args'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE78-V03-BAD',
        cwe='CWE-78',
        file_path='benchmark/corpus/cwe_78_cmdi/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['subprocess.run'],
        description='Container CMDi: cmd stored in dict, run with shell=True'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE78-V03-GOOD',
        cwe='CWE-78',
        file_path='benchmark/corpus/cwe_78_cmdi/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: list args in dict, shell=False'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE78-V04-BAD',
        cwe='CWE-78',
        file_path='benchmark/corpus/cwe_78_cmdi/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['subprocess.run'],
        description='OOP CMDi: tainted cmd as self.cmd, executed in method'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE78-V04-GOOD',
        cwe='CWE-78',
        file_path='benchmark/corpus/cwe_78_cmdi/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: host stored as attr, run with list args'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE78-V05-BAD',
        cwe='CWE-78',
        file_path='benchmark/corpus/cwe_78_cmdi/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['subprocess.run'],
        description='Branch CMDi: taint in both branches, shell=True'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE78-V05-GOOD',
        cwe='CWE-78',
        file_path='benchmark/corpus/cwe_78_cmdi/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: list args in both branches, shell=False'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE22-V01-BAD',
        cwe='CWE-22',
        file_path='benchmark/corpus/cwe_22_traversal/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['open'],
        description='Direct traversal: f-string path with user filename directly opened'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE22-V01-GOOD',
        cwe='CWE-22',
        file_path='benchmark/corpus/cwe_22_traversal/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: basename + normpath + startswith guard'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE22-V02-BAD',
        cwe='CWE-22',
        file_path='benchmark/corpus/cwe_22_traversal/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['open'],
        description='Multi-hop traversal: build_path() returns unsafe path, then opened'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE22-V02-GOOD',
        cwe='CWE-22',
        file_path='benchmark/corpus/cwe_22_traversal/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: basename + normpath in single function'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE22-V03-BAD',
        cwe='CWE-22',
        file_path='benchmark/corpus/cwe_22_traversal/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['open'],
        description='Container traversal: unsafe path stored in dict, then opened'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE22-V03-GOOD',
        cwe='CWE-22',
        file_path='benchmark/corpus/cwe_22_traversal/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: sanitized path stored in dict'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE22-V04-BAD',
        cwe='CWE-22',
        file_path='benchmark/corpus/cwe_22_traversal/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['open'],
        description='OOP traversal: unsafe path set as self.path in __init__, opened in method'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE22-V04-GOOD',
        cwe='CWE-22',
        file_path='benchmark/corpus/cwe_22_traversal/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: sanitized path in __init__, guard enforced'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE22-V05-BAD',
        cwe='CWE-22',
        file_path='benchmark/corpus/cwe_22_traversal/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['open'],
        description='Branch traversal: taint in both branches leads to open()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE22-V05-GOOD',
        cwe='CWE-22',
        file_path='benchmark/corpus/cwe_22_traversal/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: basename+normpath in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE79-V01-BAD',
        cwe='CWE-79',
        file_path='benchmark/corpus/cwe_79_xss/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['markupsafe.Markup'],
        description='Direct XSS: raw user input in f-string HTML output'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE79-V01-GOOD',
        cwe='CWE-79',
        file_path='benchmark/corpus/cwe_79_xss/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: html.escape() applied before rendering'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE79-V02-BAD',
        cwe='CWE-79',
        file_path='benchmark/corpus/cwe_79_xss/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['markupsafe.Markup'],
        description='Multi-hop XSS: wrap_tag() passes tainted name to HTML'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE79-V02-GOOD',
        cwe='CWE-79',
        file_path='benchmark/corpus/cwe_79_xss/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: html.escape() inside wrap_tag()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE79-V03-BAD',
        cwe='CWE-79',
        file_path='benchmark/corpus/cwe_79_xss/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['markupsafe.Markup'],
        description="Container XSS: raw name stored in dict 'header' key"
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE79-V03-GOOD',
        cwe='CWE-79',
        file_path='benchmark/corpus/cwe_79_xss/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: escaped name in dict'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE79-V04-BAD',
        cwe='CWE-79',
        file_path='benchmark/corpus/cwe_79_xss/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['markupsafe.Markup'],
        description='OOP XSS: raw name stored as self.snippet in __init__'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE79-V04-GOOD',
        cwe='CWE-79',
        file_path='benchmark/corpus/cwe_79_xss/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: escaped name stored in __init__'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE79-V05-BAD',
        cwe='CWE-79',
        file_path='benchmark/corpus/cwe_79_xss/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['markupsafe.Markup'],
        description='Branch XSS: tainted name in both admin/user branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE79-V05-GOOD',
        cwe='CWE-79',
        file_path='benchmark/corpus/cwe_79_xss/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: escaped before branching'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE95-V01-BAD',
        cwe='CWE-95',
        file_path='benchmark/corpus/cwe_95_codei/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['eval'],
        description='Direct code injection: user input passed to eval()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE95-V01-GOOD',
        cwe='CWE-95',
        file_path='benchmark/corpus/cwe_95_codei/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: ast.literal_eval() used instead'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE95-V02-BAD',
        cwe='CWE-95',
        file_path='benchmark/corpus/cwe_95_codei/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['eval'],
        description='Multi-hop: exec(code) called from run_code() helper'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE95-V02-GOOD',
        cwe='CWE-95',
        file_path='benchmark/corpus/cwe_95_codei/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: ast.literal_eval() in process_input()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE95-V03-BAD',
        cwe='CWE-95',
        file_path='benchmark/corpus/cwe_95_codei/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['eval'],
        description='Container: user input stored in dict, passed to eval()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE95-V03-GOOD',
        cwe='CWE-95',
        file_path='benchmark/corpus/cwe_95_codei/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: ast.literal_eval() on dict value'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE95-V04-BAD',
        cwe='CWE-95',
        file_path='benchmark/corpus/cwe_95_codei/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['eval'],
        description='OOP: code stored as self.code in __init__, exec() in run()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE95-V04-GOOD',
        cwe='CWE-95',
        file_path='benchmark/corpus/cwe_95_codei/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: ast.literal_eval() in SafeEvaluator'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE95-V05-BAD',
        cwe='CWE-95',
        file_path='benchmark/corpus/cwe_95_codei/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['eval'],
        description='Branch: eval() in both branches of is_trusted conditional'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE95-V05-GOOD',
        cwe='CWE-95',
        file_path='benchmark/corpus/cwe_95_codei/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: ast.literal_eval() in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE502-V01-BAD',
        cwe='CWE-502',
        file_path='benchmark/corpus/cwe_502_deserial/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['pickle.loads'],
        description='Direct deserialization: pickle.loads on base64-decoded cookie'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE502-V01-GOOD',
        cwe='CWE-502',
        file_path='benchmark/corpus/cwe_502_deserial/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: json.loads on base64-decoded cookie'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE502-V02-BAD',
        cwe='CWE-502',
        file_path='benchmark/corpus/cwe_502_deserial/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['pickle.loads'],
        description='Multi-hop: decode_payload() extracts bytes, pickle.loads consumes'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE502-V02-GOOD',
        cwe='CWE-502',
        file_path='benchmark/corpus/cwe_502_deserial/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: json.loads on decoded string'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE502-V03-BAD',
        cwe='CWE-502',
        file_path='benchmark/corpus/cwe_502_deserial/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['pickle.loads'],
        description='Container: decoded bytes in dict, pickle.loads on dict value'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE502-V03-GOOD',
        cwe='CWE-502',
        file_path='benchmark/corpus/cwe_502_deserial/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: json.loads on dict value'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE502-V04-BAD',
        cwe='CWE-502',
        file_path='benchmark/corpus/cwe_502_deserial/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['pickle.loads'],
        description='OOP: raw bytes in self.raw, pickle.loads in load()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE502-V04-GOOD',
        cwe='CWE-502',
        file_path='benchmark/corpus/cwe_502_deserial/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: json string in self.data, json.loads in load()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE502-V05-BAD',
        cwe='CWE-502',
        file_path='benchmark/corpus/cwe_502_deserial/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['pickle.loads'],
        description='Branch: pickle.loads in both legacy/non-legacy branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE502-V05-GOOD',
        cwe='CWE-502',
        file_path='benchmark/corpus/cwe_502_deserial/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: json.loads in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE601-V01-BAD',
        cwe='CWE-601',
        file_path='benchmark/corpus/cwe_601_redirect/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['redirect'],
        description='Direct open redirect: user next_url used in Location header'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE601-V01-GOOD',
        cwe='CWE-601',
        file_path='benchmark/corpus/cwe_601_redirect/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: urlparse check rejects absolute URLs'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE601-V02-BAD',
        cwe='CWE-601',
        file_path='benchmark/corpus/cwe_601_redirect/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['redirect'],
        description='Multi-hop: build_redirect_url() passes through unvalidated'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE601-V02-GOOD',
        cwe='CWE-601',
        file_path='benchmark/corpus/cwe_601_redirect/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: urlparse check rejects absolute URLs in-line'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE601-V03-BAD',
        cwe='CWE-601',
        file_path='benchmark/corpus/cwe_601_redirect/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['redirect'],
        description='Container: next_url in dict used as redirect target'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE601-V03-GOOD',
        cwe='CWE-601',
        file_path='benchmark/corpus/cwe_601_redirect/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: validated url stored in dict before redirect'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE601-V04-BAD',
        cwe='CWE-601',
        file_path='benchmark/corpus/cwe_601_redirect/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['redirect'],
        description='OOP: next_url stored as self.redirect_url, used in finish_login()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE601-V04-GOOD',
        cwe='CWE-601',
        file_path='benchmark/corpus/cwe_601_redirect/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: validated url stored in self.redirect_url'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE601-V05-BAD',
        cwe='CWE-601',
        file_path='benchmark/corpus/cwe_601_redirect/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['redirect'],
        description='Branch: unvalidated next_url in both is_internal branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE601-V05-GOOD',
        cwe='CWE-601',
        file_path='benchmark/corpus/cwe_601_redirect/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: absolute URLs rejected in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE611-V01-BAD',
        cwe='CWE-611',
        file_path='benchmark/corpus/cwe_611_xxe/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['lxml.etree.fromstring'],
        description='Direct XXE: lxml.etree.fromstring on user XML data'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE611-V01-GOOD',
        cwe='CWE-611',
        file_path='benchmark/corpus/cwe_611_xxe/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: defusedxml.ElementTree.fromstring()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE611-V02-BAD',
        cwe='CWE-611',
        file_path='benchmark/corpus/cwe_611_xxe/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['lxml.etree.fromstring'],
        description='Multi-hop: decode_xml() encodes data, etree.fromstring parses'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE611-V02-GOOD',
        cwe='CWE-611',
        file_path='benchmark/corpus/cwe_611_xxe/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: defusedxml used directly'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE611-V03-BAD',
        cwe='CWE-611',
        file_path='benchmark/corpus/cwe_611_xxe/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['lxml.etree.fromstring'],
        description='Container: encoded XML in dict, etree.fromstring on value'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE611-V03-GOOD',
        cwe='CWE-611',
        file_path='benchmark/corpus/cwe_611_xxe/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: defusedxml parses dict value'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE611-V04-BAD',
        cwe='CWE-611',
        file_path='benchmark/corpus/cwe_611_xxe/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['lxml.etree.fromstring'],
        description='OOP: encoded XML as self.payload, etree.fromstring in parse()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE611-V04-GOOD',
        cwe='CWE-611',
        file_path='benchmark/corpus/cwe_611_xxe/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: defusedxml parses self.payload'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE611-V05-BAD',
        cwe='CWE-611',
        file_path='benchmark/corpus/cwe_611_xxe/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['lxml.etree.fromstring'],
        description='Branch: etree.fromstring with resolve_entities=True in both paths'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE611-V05-GOOD',
        cwe='CWE-611',
        file_path='benchmark/corpus/cwe_611_xxe/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: defusedxml in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE918-V01-BAD',
        cwe='CWE-918',
        file_path='benchmark/corpus/cwe_918_ssrf/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get'],
        description='Direct SSRF: user-controlled URL passed to requests.get()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE918-V01-GOOD',
        cwe='CWE-918',
        file_path='benchmark/corpus/cwe_918_ssrf/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: host whitelist enforced before requests.get()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE918-V02-BAD',
        cwe='CWE-918',
        file_path='benchmark/corpus/cwe_918_ssrf/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get'],
        description='Multi-hop: build_request() calls requests.get() with user URL'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE918-V02-GOOD',
        cwe='CWE-918',
        file_path='benchmark/corpus/cwe_918_ssrf/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: whitelist check in fetch_url(), not in helper'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE918-V03-BAD',
        cwe='CWE-918',
        file_path='benchmark/corpus/cwe_918_ssrf/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get'],
        description="Container: URL stored in dict cfg, requests.get on cfg['endpoint']"
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE918-V03-GOOD',
        cwe='CWE-918',
        file_path='benchmark/corpus/cwe_918_ssrf/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description="Safe: whitelist check before requests.get(cfg['endpoint'])"
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE918-V04-BAD',
        cwe='CWE-918',
        file_path='benchmark/corpus/cwe_918_ssrf/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get'],
        description='OOP: user URL in self.url, requests.get(self.url) in fetch()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE918-V04-GOOD',
        cwe='CWE-918',
        file_path='benchmark/corpus/cwe_918_ssrf/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: whitelist in __init__ guards self.url'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE918-V05-BAD',
        cwe='CWE-918',
        file_path='benchmark/corpus/cwe_918_ssrf/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get'],
        description='Branch: requests.get(url) in both use_cache branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE918-V05-GOOD',
        cwe='CWE-918',
        file_path='benchmark/corpus/cwe_918_ssrf/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: whitelist check before branching; cached path returns early'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE327-V01-BAD',
        cwe='CWE-327',
        file_path='benchmark/corpus/cwe_327_crypto/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5'],
        description='Direct broken crypto: hashlib.md5 for password hashing'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE327-V01-GOOD',
        cwe='CWE-327',
        file_path='benchmark/corpus/cwe_327_crypto/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: hashlib.sha256 used instead'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE327-V02-BAD',
        cwe='CWE-327',
        file_path='benchmark/corpus/cwe_327_crypto/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5'],
        description='Multi-hop: compute_digest() wraps md5, called in store_password()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE327-V02-GOOD',
        cwe='CWE-327',
        file_path='benchmark/corpus/cwe_327_crypto/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: compute_digest() uses sha256'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE327-V03-BAD',
        cwe='CWE-327',
        file_path='benchmark/corpus/cwe_327_crypto/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5'],
        description='Container: md5 digest stored in dict as password_hash'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE327-V03-GOOD',
        cwe='CWE-327',
        file_path='benchmark/corpus/cwe_327_crypto/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: sha256 stored in dict'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE327-V04-BAD',
        cwe='CWE-327',
        file_path='benchmark/corpus/cwe_327_crypto/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5'],
        description='OOP: md5 digest in self.digest set in __init__'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE327-V04-GOOD',
        cwe='CWE-327',
        file_path='benchmark/corpus/cwe_327_crypto/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: sha256 digest in self.digest'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE327-V05-BAD',
        cwe='CWE-327',
        file_path='benchmark/corpus/cwe_327_crypto/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5'],
        description='Branch: md5 in legacy branch, sha1 in other — both weak'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE327-V05-GOOD',
        cwe='CWE-327',
        file_path='benchmark/corpus/cwe_327_crypto/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: sha256 in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE338-V01-BAD',
        cwe='CWE-338',
        file_path='benchmark/corpus/cwe_338_random/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['random.random'],
        description='Direct insecure random: random.random() for auth_token'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE338-V01-GOOD',
        cwe='CWE-338',
        file_path='benchmark/corpus/cwe_338_random/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: secrets.token_hex(32) for auth_token'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE338-V02-BAD',
        cwe='CWE-338',
        file_path='benchmark/corpus/cwe_338_random/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['random.random'],
        description='Multi-hop: make_secret() returns random.random(), used as session_key'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE338-V02-GOOD',
        cwe='CWE-338',
        file_path='benchmark/corpus/cwe_338_random/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: secrets.token_hex() directly for session_key'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE338-V03-BAD',
        cwe='CWE-338',
        file_path='benchmark/corpus/cwe_338_random/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['random.random'],
        description='Container: auth_secret and csrf_token from random.random() in dict'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE338-V03-GOOD',
        cwe='CWE-338',
        file_path='benchmark/corpus/cwe_338_random/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: secrets.token_hex() in dict'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE338-V04-BAD',
        cwe='CWE-338',
        file_path='benchmark/corpus/cwe_338_random/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['random.random'],
        description='OOP: self.session_secret = random.random() in __init__'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE338-V04-GOOD',
        cwe='CWE-338',
        file_path='benchmark/corpus/cwe_338_random/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: secrets.token_hex() in __init__'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE338-V05-BAD',
        cwe='CWE-338',
        file_path='benchmark/corpus/cwe_338_random/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['random.randint'],
        description='Branch: random.randint() for auth_token in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE338-V05-GOOD',
        cwe='CWE-338',
        file_path='benchmark/corpus/cwe_338_random/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: secrets.token_hex() in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE295-V01-BAD',
        cwe='CWE-295',
        file_path='benchmark/corpus/cwe_295_cert/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get'],
        description='Direct SSL bypass: requests.get(..., verify=False)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE295-V01-GOOD',
        cwe='CWE-295',
        file_path='benchmark/corpus/cwe_295_cert/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: requests.get(..., verify=True)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE295-V02-BAD',
        cwe='CWE-295',
        file_path='benchmark/corpus/cwe_295_cert/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get'],
        description='Multi-hop: session with s.verify=False, used in call_api()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE295-V02-GOOD',
        cwe='CWE-295',
        file_path='benchmark/corpus/cwe_295_cert/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: session with s.verify=True'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE295-V03-BAD',
        cwe='CWE-295',
        file_path='benchmark/corpus/cwe_295_cert/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get'],
        description='Container: options dict with verify=False passed to requests.get(**options)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE295-V03-GOOD',
        cwe='CWE-295',
        file_path='benchmark/corpus/cwe_295_cert/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: options dict with verify=True'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE295-V04-BAD',
        cwe='CWE-295',
        file_path='benchmark/corpus/cwe_295_cert/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get'],
        description='OOP: self.verify_ssl=False in __init__, requests.get(verify=self.verify_ssl)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE295-V04-GOOD',
        cwe='CWE-295',
        file_path='benchmark/corpus/cwe_295_cert/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: self.verify_ssl=True'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE295-V05-BAD',
        cwe='CWE-295',
        file_path='benchmark/corpus/cwe_295_cert/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get'],
        description='Branch: requests.get(verify=False) in both dev_mode branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE295-V05-GOOD',
        cwe='CWE-295',
        file_path='benchmark/corpus/cwe_295_cert/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: requests.get(verify=True) in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE400-V01-BAD',
        cwe='CWE-400',
        file_path='benchmark/corpus/cwe_400_resource/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['io.TextIOWrapper.read'],
        description='Direct resource exhaustion: sock.makefile().read() without limit'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE400-V01-GOOD',
        cwe='CWE-400',
        file_path='benchmark/corpus/cwe_400_resource/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: sock.makefile().read(MAX_READ) enforces 64 KB cap'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE400-V02-BAD',
        cwe='CWE-400',
        file_path='benchmark/corpus/cwe_400_resource/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['io.TextIOWrapper.read'],
        description='Multi-hop: receive_all() calls f.read() without limit'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE400-V02-GOOD',
        cwe='CWE-400',
        file_path='benchmark/corpus/cwe_400_resource/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: receive_all() calls f.read(MAX_READ)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE400-V03-BAD',
        cwe='CWE-400',
        file_path='benchmark/corpus/cwe_400_resource/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['io.TextIOWrapper.read'],
        description="Container: unbounded read stored in dict buf['data']"
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE400-V03-GOOD',
        cwe='CWE-400',
        file_path='benchmark/corpus/cwe_400_resource/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description="Safe: bounded read stored in dict buf['data']"
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE400-V04-BAD',
        cwe='CWE-400',
        file_path='benchmark/corpus/cwe_400_resource/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['io.TextIOWrapper.read'],
        description='OOP: ClientHandler.read_all() calls self.sock.makefile().read()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE400-V04-GOOD',
        cwe='CWE-400',
        file_path='benchmark/corpus/cwe_400_resource/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: ClientHandler.read_all() calls read(MAX_READ)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE400-V05-BAD',
        cwe='CWE-400',
        file_path='benchmark/corpus/cwe_400_resource/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['io.TextIOWrapper.read'],
        description='Branch: unbounded read in both binary/text branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE400-V05-GOOD',
        cwe='CWE-400',
        file_path='benchmark/corpus/cwe_400_resource/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: bounded read in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1336-V01-BAD',
        cwe='CWE-1336',
        file_path='benchmark/corpus/cwe_1336_ssti/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['jinja2.Template'],
        description='Direct SSTI: user name f-string in jinja2.Template() constructor'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1336-V01-GOOD',
        cwe='CWE-1336',
        file_path='benchmark/corpus/cwe_1336_ssti/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: static template string with .render(name=name)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1336-V02-BAD',
        cwe='CWE-1336',
        file_path='benchmark/corpus/cwe_1336_ssti/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['jinja2.Template'],
        description='Multi-hop: make_template(name) returns f-string, passed to Template()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1336-V02-GOOD',
        cwe='CWE-1336',
        file_path='benchmark/corpus/cwe_1336_ssti/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: static template string with render context'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1336-V03-BAD',
        cwe='CWE-1336',
        file_path='benchmark/corpus/cwe_1336_ssti/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['jinja2.Template'],
        description="Container: f-string template in dict parts['tmpl'], passed to Template()"
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1336-V03-GOOD',
        cwe='CWE-1336',
        file_path='benchmark/corpus/cwe_1336_ssti/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: static template in dict, rendered with context'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1336-V04-BAD',
        cwe='CWE-1336',
        file_path='benchmark/corpus/cwe_1336_ssti/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['jinja2.Template'],
        description='OOP: f-string in self.tmpl_str, jinja2.Template(self.tmpl_str) in render()'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1336-V04-GOOD',
        cwe='CWE-1336',
        file_path='benchmark/corpus/cwe_1336_ssti/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: static template, name in render context'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1336-V05-BAD',
        cwe='CWE-1336',
        file_path='benchmark/corpus/cwe_1336_ssti/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['jinja2.Template'],
        description='Branch: tainted f-string template in both formal/informal branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1336-V05-GOOD',
        cwe='CWE-1336',
        file_path='benchmark/corpus/cwe_1336_ssti/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: static template in both branches with render context'
    ),


    # ─── Batch 2 (data/cwe_blueprint_batch2.json) Multi-Variant Corpus (120 cases) ───
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE377-V01-BAD',
        cwe='CWE-377',
        file_path='benchmark/corpus/cwe_377_tempfile/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['tempfile.mktemp'],
        description='Direct insecure temp file via tempfile.mktemp() in helper'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE377-V01-GOOD',
        cwe='CWE-377',
        file_path='benchmark/corpus/cwe_377_tempfile/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: mkstemp fd/path pair'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE377-V02-BAD',
        cwe='CWE-377',
        file_path='benchmark/corpus/cwe_377_tempfile/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['tempfile.mktemp'],
        description='Insecure temp file via mktemp(suffix=...) kwargs'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE377-V02-GOOD',
        cwe='CWE-377',
        file_path='benchmark/corpus/cwe_377_tempfile/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: NamedTemporaryFile handle'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE377-V03-BAD',
        cwe='CWE-377',
        file_path='benchmark/corpus/cwe_377_tempfile/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['tempfile.mktemp'],
        description='mktemp result embedded in dict container'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE377-V03-GOOD',
        cwe='CWE-377',
        file_path='benchmark/corpus/cwe_377_tempfile/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: mkstemp with suffix kwarg'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE377-V04-BAD',
        cwe='CWE-377',
        file_path='benchmark/corpus/cwe_377_tempfile/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['tempfile.mktemp'],
        description='OOP: mktemp path stored as self.path in __init__'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE377-V04-GOOD',
        cwe='CWE-377',
        file_path='benchmark/corpus/cwe_377_tempfile/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: OOP NamedTemporaryFile(delete=False) handle'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE377-V05-BAD',
        cwe='CWE-377',
        file_path='benchmark/corpus/cwe_377_tempfile/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['tempfile.mktemp'],
        description='Branch: mktemp in both if/else arms'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE377-V05-GOOD',
        cwe='CWE-377',
        file_path='benchmark/corpus/cwe_377_tempfile/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: mkstemp in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE377-V06-BAD',
        cwe='CWE-377',
        file_path='benchmark/corpus/cwe_377_tempfile/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['tempfile.mktemp'],
        description='mktemp with dir/prefix kwargs at module level'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE377-V06-GOOD',
        cwe='CWE-377',
        file_path='benchmark/corpus/cwe_377_tempfile/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: mkstemp with prefix kwarg'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE732-V01-BAD',
        cwe='CWE-732',
        file_path='benchmark/corpus/cwe_732_permissions/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['os.chmod'],
        description='World-writable chmod 0o777 on config file'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE732-V01-GOOD',
        cwe='CWE-732',
        file_path='benchmark/corpus/cwe_732_permissions/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: owner-only 0o600'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE732-V02-BAD',
        cwe='CWE-732',
        file_path='benchmark/corpus/cwe_732_permissions/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['os.chmod'],
        description='Group/other-writable chmod 0o755'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE732-V02-GOOD',
        cwe='CWE-732',
        file_path='benchmark/corpus/cwe_732_permissions/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: owner-only 0o700'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE732-V03-BAD',
        cwe='CWE-732',
        file_path='benchmark/corpus/cwe_732_permissions/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['os.chmod'],
        description='Local mode var 0o666 resolved into chmod'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE732-V03-GOOD',
        cwe='CWE-732',
        file_path='benchmark/corpus/cwe_732_permissions/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: local mode var 0o600'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE732-V04-BAD',
        cwe='CWE-732',
        file_path='benchmark/corpus/cwe_732_permissions/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['os.chmod'],
        description='chmod mode=0o664 keyword argument'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE732-V04-GOOD',
        cwe='CWE-732',
        file_path='benchmark/corpus/cwe_732_permissions/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: mode=0o600 keyword argument'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE732-V05-BAD',
        cwe='CWE-732',
        file_path='benchmark/corpus/cwe_732_permissions/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['os.chmod'],
        description='Branch: 0o644/0o666 modes in both arms'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE732-V05-GOOD',
        cwe='CWE-732',
        file_path='benchmark/corpus/cwe_732_permissions/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: 0o600/0o700 in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE732-V06-BAD',
        cwe='CWE-732',
        file_path='benchmark/corpus/cwe_732_permissions/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['os.chmod'],
        description='Bitwise OR 0o600 | 0o004 leaks group bits'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE732-V06-GOOD',
        cwe='CWE-732',
        file_path='benchmark/corpus/cwe_732_permissions/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: 0o700 & 0o400 restricts to owner bits'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE326-V01-BAD',
        cwe='CWE-326',
        file_path='benchmark/corpus/cwe_326_crypto_key/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['RSA.generate', 'Crypto.PublicKey.RSA.generate', 'rsa.generate_private_key'],
        description='RSA.generate(1024) weak key via helper'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE326-V01-GOOD',
        cwe='CWE-326',
        file_path='benchmark/corpus/cwe_326_crypto_key/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: RSA.generate(2048)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE326-V02-BAD',
        cwe='CWE-326',
        file_path='benchmark/corpus/cwe_326_crypto_key/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['RSA.generate', 'Crypto.PublicKey.RSA.generate', 'rsa.generate_private_key'],
        description='Fully-qualified Crypto.PublicKey.RSA.generate(512)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE326-V02-GOOD',
        cwe='CWE-326',
        file_path='benchmark/corpus/cwe_326_crypto_key/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: bits=2048 keyword argument'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE326-V03-BAD',
        cwe='CWE-326',
        file_path='benchmark/corpus/cwe_326_crypto_key/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['RSA.generate', 'Crypto.PublicKey.RSA.generate', 'rsa.generate_private_key'],
        description='Local bits var 1024 resolved into generate'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE326-V03-GOOD',
        cwe='CWE-326',
        file_path='benchmark/corpus/cwe_326_crypto_key/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: local bits var 3072'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE326-V04-BAD',
        cwe='CWE-326',
        file_path='benchmark/corpus/cwe_326_crypto_key/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['RSA.generate', 'Crypto.PublicKey.RSA.generate', 'rsa.generate_private_key'],
        description='RSA.generate(bits=1024) keyword argument'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE326-V04-GOOD',
        cwe='CWE-326',
        file_path='benchmark/corpus/cwe_326_crypto_key/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: rsa.generate_private_key(2048, 65537)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE326-V05-BAD',
        cwe='CWE-326',
        file_path='benchmark/corpus/cwe_326_crypto_key/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['RSA.generate', 'Crypto.PublicKey.RSA.generate', 'rsa.generate_private_key'],
        description='Branch with legacy 1024-bit generate_private_key'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE326-V05-GOOD',
        cwe='CWE-326',
        file_path='benchmark/corpus/cwe_326_crypto_key/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: 4096/2048 in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE326-V06-BAD',
        cwe='CWE-326',
        file_path='benchmark/corpus/cwe_326_crypto_key/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['RSA.generate', 'Crypto.PublicKey.RSA.generate', 'rsa.generate_private_key'],
        description='Computed 2 * 512 evaluates to weak 1024 bits'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE326-V06-GOOD',
        cwe='CWE-326',
        file_path='benchmark/corpus/cwe_326_crypto_key/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: 1024 * 4 evaluates to 4096 bits'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE798-V01-BAD',
        cwe='CWE-798',
        file_path='benchmark/corpus/cwe_798_hardcoded/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='Hardcoded password literal assigned directly'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE798-V01-GOOD',
        cwe='CWE-798',
        file_path='benchmark/corpus/cwe_798_hardcoded/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: os.environ.get for password'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE798-V02-BAD',
        cwe='CWE-798',
        file_path='benchmark/corpus/cwe_798_hardcoded/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='Hardcoded api_key string literal'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE798-V02-GOOD',
        cwe='CWE-798',
        file_path='benchmark/corpus/cwe_798_hardcoded/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: os.getenv for api_key'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE798-V03-BAD',
        cwe='CWE-798',
        file_path='benchmark/corpus/cwe_798_hardcoded/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='Hardcoded secret on config attribute target'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE798-V03-GOOD',
        cwe='CWE-798',
        file_path='benchmark/corpus/cwe_798_hardcoded/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: config.get for secret_key'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE798-V04-BAD',
        cwe='CWE-798',
        file_path='benchmark/corpus/cwe_798_hardcoded/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='OOP: self.access_token hardcoded in __init__'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE798-V04-GOOD',
        cwe='CWE-798',
        file_path='benchmark/corpus/cwe_798_hardcoded/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: short literal below min_length threshold'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE798-V05-BAD',
        cwe='CWE-798',
        file_path='benchmark/corpus/cwe_798_hardcoded/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='Annotated assignment of hardcoded secret_key'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE798-V05-GOOD',
        cwe='CWE-798',
        file_path='benchmark/corpus/cwe_798_hardcoded/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: credential loaded via load_secret() call'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE798-V06-BAD',
        cwe='CWE-798',
        file_path='benchmark/corpus/cwe_798_hardcoded/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='Hardcoded passwd literal'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE798-V06-GOOD',
        cwe='CWE-798',
        file_path='benchmark/corpus/cwe_798_hardcoded/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: os.environ.get with fallback default'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1004-V01-BAD',
        cwe='CWE-1004',
        file_path='benchmark/corpus/cwe_1004_cookies/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['response.set_cookie', 'set_cookie'],
        description='set_cookie without httponly or secure flags'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1004-V01-GOOD',
        cwe='CWE-1004',
        file_path='benchmark/corpus/cwe_1004_cookies/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: httponly=True and secure=True'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1004-V02-BAD',
        cwe='CWE-1004',
        file_path='benchmark/corpus/cwe_1004_cookies/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['response.set_cookie', 'set_cookie'],
        description='Missing secure flag (httponly only)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1004-V02-GOOD',
        cwe='CWE-1004',
        file_path='benchmark/corpus/cwe_1004_cookies/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: secure=True and httponly=True (order swapped)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1004-V03-BAD',
        cwe='CWE-1004',
        file_path='benchmark/corpus/cwe_1004_cookies/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['response.set_cookie', 'set_cookie'],
        description='Missing httponly flag (secure only)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1004-V03-GOOD',
        cwe='CWE-1004',
        file_path='benchmark/corpus/cwe_1004_cookies/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: OOP response.set_cookie with both flags'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1004-V04-BAD',
        cwe='CWE-1004',
        file_path='benchmark/corpus/cwe_1004_cookies/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['response.set_cookie', 'set_cookie'],
        description='httponly=False disables protection'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1004-V04-GOOD',
        cwe='CWE-1004',
        file_path='benchmark/corpus/cwe_1004_cookies/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: both flags plus samesite kwarg'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1004-V05-BAD',
        cwe='CWE-1004',
        file_path='benchmark/corpus/cwe_1004_cookies/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['response.set_cookie', 'set_cookie'],
        description='Flags via **opts dict missing httponly'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1004-V05-GOOD',
        cwe='CWE-1004',
        file_path='benchmark/corpus/cwe_1004_cookies/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: both flags in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1004-V06-BAD',
        cwe='CWE-1004',
        file_path='benchmark/corpus/cwe_1004_cookies/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['response.set_cookie', 'set_cookie'],
        description='Bare set_cookie() without any flags'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE1004-V06-GOOD',
        cwe='CWE-1004',
        file_path='benchmark/corpus/cwe_1004_cookies/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: secure=True and httponly=True'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE209-V01-BAD',
        cwe='CWE-209',
        file_path='benchmark/corpus/cwe_209_error_exposure/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='Exception returned via str(e)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE209-V01-GOOD',
        cwe='CWE-209',
        file_path='benchmark/corpus/cwe_209_error_exposure/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: generic internal-server-error constant'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE209-V02-BAD',
        cwe='CWE-209',
        file_path='benchmark/corpus/cwe_209_error_exposure/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='Exception returned via repr(err)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE209-V02-GOOD',
        cwe='CWE-209',
        file_path='benchmark/corpus/cwe_209_error_exposure/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: generic invalid-input constant'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE209-V03-BAD',
        cwe='CWE-209',
        file_path='benchmark/corpus/cwe_209_error_exposure/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='Raw exception object returned directly'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE209-V03-GOOD',
        cwe='CWE-209',
        file_path='benchmark/corpus/cwe_209_error_exposure/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: logger.error with generic return constant'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE209-V04-BAD',
        cwe='CWE-209',
        file_path='benchmark/corpus/cwe_209_error_exposure/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='traceback.format_exc() returned to caller'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE209-V04-GOOD',
        cwe='CWE-209',
        file_path='benchmark/corpus/cwe_209_error_exposure/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: generic contact-support constant'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE209-V05-BAD',
        cwe='CWE-209',
        file_path='benchmark/corpus/cwe_209_error_exposure/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='Exception returned after logging'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE209-V05-GOOD',
        cwe='CWE-209',
        file_path='benchmark/corpus/cwe_209_error_exposure/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: handler without exception binding returns constant'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE209-V06-BAD',
        cwe='CWE-209',
        file_path='benchmark/corpus/cwe_209_error_exposure/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='str(e) returned inside nested if in handler'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE209-V06-GOOD',
        cwe='CWE-209',
        file_path='benchmark/corpus/cwe_209_error_exposure/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: type name printed, generic constant returned'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE117-V01-BAD',
        cwe='CWE-117',
        file_path='benchmark/corpus/cwe_117_logi/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['logging.info', 'logging.warning', 'logging.error', 'logger.info', 'logger.warning', 'logger.error'],
        description='Direct f-string user data into logging.info'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE117-V01-GOOD',
        cwe='CWE-117',
        file_path='benchmark/corpus/cwe_117_logi/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: replace_crlf sanitizer applied'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE117-V02-BAD',
        cwe='CWE-117',
        file_path='benchmark/corpus/cwe_117_logi/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['logging.info', 'logging.warning', 'logging.error', 'logger.info', 'logger.warning', 'logger.error'],
        description='Multi-hop: build_log_msg returns tainted f-string'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE117-V02-GOOD',
        cwe='CWE-117',
        file_path='benchmark/corpus/cwe_117_logi/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: re_sub_crlf regex sanitizer applied'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE117-V03-BAD',
        cwe='CWE-117',
        file_path='benchmark/corpus/cwe_117_logi/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['logging.info', 'logging.warning', 'logging.error', 'logger.info', 'logger.warning', 'logger.error'],
        description='Tainted message stored in dict then logged'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE117-V03-GOOD',
        cwe='CWE-117',
        file_path='benchmark/corpus/cwe_117_logi/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: sanitize_log_input inside dict literal'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE117-V04-BAD',
        cwe='CWE-117',
        file_path='benchmark/corpus/cwe_117_logi/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['logging.info', 'logging.warning', 'logging.error', 'logger.info', 'logger.warning', 'logger.error'],
        description='OOP: tainted self.msg logged via logger.warning'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE117-V04-GOOD',
        cwe='CWE-117',
        file_path='benchmark/corpus/cwe_117_logi/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: OOP sanitize_log_message in __init__'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE117-V05-BAD',
        cwe='CWE-117',
        file_path='benchmark/corpus/cwe_117_logi/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['logging.info', 'logging.warning', 'logging.error', 'logger.info', 'logger.warning', 'logger.error'],
        description='Branch: tainted user string logged when verbose'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE117-V05-GOOD',
        cwe='CWE-117',
        file_path='benchmark/corpus/cwe_117_logi/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: sanitized msg in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE117-V06-BAD',
        cwe='CWE-117',
        file_path='benchmark/corpus/cwe_117_logi/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['logging.info', 'logging.warning', 'logging.error', 'logger.info', 'logger.warning', 'logger.error'],
        description='logger.info with raw user input'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE117-V06-GOOD',
        cwe='CWE-117',
        file_path='benchmark/corpus/cwe_117_logi/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: sanitize_log_input in format args'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE94-V01-BAD',
        cwe='CWE-94',
        file_path='benchmark/corpus/cwe_94_codei_load/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['importlib.import_module', '__import__'],
        description='Direct importlib.import_module of user name'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE94-V01-GOOD',
        cwe='CWE-94',
        file_path='benchmark/corpus/cwe_94_codei_load/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: allowlist containment guard'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE94-V02-BAD',
        cwe='CWE-94',
        file_path='benchmark/corpus/cwe_94_codei_load/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['importlib.import_module', '__import__'],
        description='Multi-hop: module_path f-string helper'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE94-V02-GOOD',
        cwe='CWE-94',
        file_path='benchmark/corpus/cwe_94_codei_load/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: inverted not-in guard returns early'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE94-V03-BAD',
        cwe='CWE-94',
        file_path='benchmark/corpus/cwe_94_codei_load/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['importlib.import_module', '__import__'],
        description='Tainted module name stored in dict'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE94-V03-GOOD',
        cwe='CWE-94',
        file_path='benchmark/corpus/cwe_94_codei_load/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: set literal membership guard around __import__'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE94-V04-BAD',
        cwe='CWE-94',
        file_path='benchmark/corpus/cwe_94_codei_load/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['importlib.import_module', '__import__'],
        description='OOP: tainted self.module loaded'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE94-V04-GOOD',
        cwe='CWE-94',
        file_path='benchmark/corpus/cwe_94_codei_load/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: allowlist guard with raise fallback'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE94-V05-BAD',
        cwe='CWE-94',
        file_path='benchmark/corpus/cwe_94_codei_load/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['importlib.import_module', '__import__'],
        description='Branch: tainted f-string or raw name import'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE94-V05-GOOD',
        cwe='CWE-94',
        file_path='benchmark/corpus/cwe_94_codei_load/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: else arm imports default literal'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE94-V06-BAD',
        cwe='CWE-94',
        file_path='benchmark/corpus/cwe_94_codei_load/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['importlib.import_module', '__import__'],
        description='__import__ builtin with user name'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE94-V06-GOOD',
        cwe='CWE-94',
        file_path='benchmark/corpus/cwe_94_codei_load/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: inverted guard raises before import'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE643-V01-BAD',
        cwe='CWE-643',
        file_path='benchmark/corpus/cwe_643_xpath/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['lxml.etree.XPath', 'root.xpath', 'tree.xpath'],
        description='Direct f-string XPath with user name'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE643-V01-GOOD',
        cwe='CWE-643',
        file_path='benchmark/corpus/cwe_643_xpath/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: parameterized xpath with name= kwarg'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE643-V02-BAD',
        cwe='CWE-643',
        file_path='benchmark/corpus/cwe_643_xpath/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['lxml.etree.XPath', 'root.xpath', 'tree.xpath'],
        description='Multi-hop: build_xpath returns tainted f-string'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE643-V02-GOOD',
        cwe='CWE-643',
        file_path='benchmark/corpus/cwe_643_xpath/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: etree.XPath compiled with variables'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE643-V03-BAD',
        cwe='CWE-643',
        file_path='benchmark/corpus/cwe_643_xpath/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['lxml.etree.XPath', 'root.xpath', 'tree.xpath'],
        description='Tainted XPath stored in dict container'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE643-V03-GOOD',
        cwe='CWE-643',
        file_path='benchmark/corpus/cwe_643_xpath/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: parameterized query via dict container'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE643-V04-BAD',
        cwe='CWE-643',
        file_path='benchmark/corpus/cwe_643_xpath/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['lxml.etree.XPath', 'root.xpath', 'tree.xpath'],
        description='OOP: tainted self.query evaluated'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE643-V04-GOOD',
        cwe='CWE-643',
        file_path='benchmark/corpus/cwe_643_xpath/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: OOP parameterized query with name kwarg'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE643-V05-BAD',
        cwe='CWE-643',
        file_path='benchmark/corpus/cwe_643_xpath/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['lxml.etree.XPath', 'root.xpath', 'tree.xpath'],
        description='Branch: two tainted XPath forms'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE643-V05-GOOD',
        cwe='CWE-643',
        file_path='benchmark/corpus/cwe_643_xpath/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: parameterized xpath in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE643-V06-BAD',
        cwe='CWE-643',
        file_path='benchmark/corpus/cwe_643_xpath/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['lxml.etree.XPath', 'root.xpath', 'tree.xpath'],
        description='Fully-qualified lxml.etree.XPath with taint'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE643-V06-GOOD',
        cwe='CWE-643',
        file_path='benchmark/corpus/cwe_643_xpath/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: static lxml.etree.XPath without taint'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE943-V01-BAD',
        cwe='CWE-943',
        file_path='benchmark/corpus/cwe_943_nosql/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['collection.find', 'collection.find_one', 'collection.update_many'],
        description='Direct user value in collection.find dict'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE943-V01-GOOD',
        cwe='CWE-943',
        file_path='benchmark/corpus/cwe_943_nosql/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: sanitize_nosql_input applied'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE943-V02-BAD',
        cwe='CWE-943',
        file_path='benchmark/corpus/cwe_943_nosql/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['collection.find', 'collection.find_one', 'collection.update_many'],
        description='Multi-hop: build_query returns tainted dict'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE943-V02-GOOD',
        cwe='CWE-943',
        file_path='benchmark/corpus/cwe_943_nosql/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: sanitize_nosql_query wraps whole dict'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE943-V03-BAD',
        cwe='CWE-943',
        file_path='benchmark/corpus/cwe_943_nosql/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['collection.find', 'collection.find_one', 'collection.update_many'],
        description='$where operator with tainted f-string'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE943-V03-GOOD',
        cwe='CWE-943',
        file_path='benchmark/corpus/cwe_943_nosql/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: set membership guard on user value'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE943-V04-BAD',
        cwe='CWE-943',
        file_path='benchmark/corpus/cwe_943_nosql/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['collection.find', 'collection.find_one', 'collection.update_many'],
        description='OOP: tainted self.query passed to find'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE943-V04-GOOD',
        cwe='CWE-943',
        file_path='benchmark/corpus/cwe_943_nosql/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: OOP sanitize_nosql_query in __init__'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE943-V05-BAD',
        cwe='CWE-943',
        file_path='benchmark/corpus/cwe_943_nosql/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['collection.find', 'collection.find_one', 'collection.update_many'],
        description='Branch: tainted $where and find_one paths'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE943-V05-GOOD',
        cwe='CWE-943',
        file_path='benchmark/corpus/cwe_943_nosql/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: sanitized value in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE943-V06-BAD',
        cwe='CWE-943',
        file_path='benchmark/corpus/cwe_943_nosql/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['collection.find', 'collection.find_one', 'collection.update_many'],
        description='update_many filter with tainted user value'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE943-V06-GOOD',
        cwe='CWE-943',
        file_path='benchmark/corpus/cwe_943_nosql/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: sanitize_nosql_input inline in dict literal'
    ),

    # ─── Batch 3A (data/cwe_blueprint_batch3a.json) Multi-Variant Corpus (120 cases) ───
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE614-V01-BAD',
        cwe='CWE-614',
        file_path='benchmark/corpus/cwe_614_cookie_secure/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['response.set_cookie', 'set_cookie'],
        description='Cookie set with httponly but missing secure flag'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE614-V01-GOOD',
        cwe='CWE-614',
        file_path='benchmark/corpus/cwe_614_cookie_secure/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: secure=True with httponly=True'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE614-V02-BAD',
        cwe='CWE-614',
        file_path='benchmark/corpus/cwe_614_cookie_secure/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['response.set_cookie', 'set_cookie'],
        description='secure=False explicitly disables transport protection'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE614-V02-GOOD',
        cwe='CWE-614',
        file_path='benchmark/corpus/cwe_614_cookie_secure/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: both flags plus samesite=Lax'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE614-V03-BAD',
        cwe='CWE-614',
        file_path='benchmark/corpus/cwe_614_cookie_secure/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['response.set_cookie', 'set_cookie'],
        description='Multi-hop: helper issues cookie without secure'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE614-V03-GOOD',
        cwe='CWE-614',
        file_path='benchmark/corpus/cwe_614_cookie_secure/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: OOP cookie with secure and httponly'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE614-V04-BAD',
        cwe='CWE-614',
        file_path='benchmark/corpus/cwe_614_cookie_secure/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['response.set_cookie', 'set_cookie'],
        description='OOP: self.response.set_cookie missing secure'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE614-V04-GOOD',
        cwe='CWE-614',
        file_path='benchmark/corpus/cwe_614_cookie_secure/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: bare set_cookie with both flags'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE614-V05-BAD',
        cwe='CWE-614',
        file_path='benchmark/corpus/cwe_614_cookie_secure/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['response.set_cookie', 'set_cookie'],
        description='Branch: non-prod arm drops secure flag'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE614-V05-GOOD',
        cwe='CWE-614',
        file_path='benchmark/corpus/cwe_614_cookie_secure/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: both branches set secure and httponly'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE614-V06-BAD',
        cwe='CWE-614',
        file_path='benchmark/corpus/cwe_614_cookie_secure/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['response.set_cookie', 'set_cookie'],
        description='Bare set_cookie without secure flag'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE614-V06-GOOD',
        cwe='CWE-614',
        file_path='benchmark/corpus/cwe_614_cookie_secure/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: flags supplied via kwargs dict'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE916-V01-BAD',
        cwe='CWE-916',
        file_path='benchmark/corpus/cwe_916_weak_hash/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5', 'hashlib.sha1', 'hashlib.sha256', 'hashlib.sha512'],
        description='SHA-256 hash applied to password'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE916-V01-GOOD',
        cwe='CWE-916',
        file_path='benchmark/corpus/cwe_916_weak_hash/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: bcrypt.hashpw with gensalt'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE916-V02-BAD',
        cwe='CWE-916',
        file_path='benchmark/corpus/cwe_916_weak_hash/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5', 'hashlib.sha1', 'hashlib.sha256', 'hashlib.sha512'],
        description='Multi-hop: hash_password helper uses sha256'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE916-V02-GOOD',
        cwe='CWE-916',
        file_path='benchmark/corpus/cwe_916_weak_hash/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: argon2 PasswordHasher'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE916-V03-BAD',
        cwe='CWE-916',
        file_path='benchmark/corpus/cwe_916_weak_hash/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5', 'hashlib.sha1', 'hashlib.sha256', 'hashlib.sha512'],
        description='Weak hash stored in dict record'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE916-V03-GOOD',
        cwe='CWE-916',
        file_path='benchmark/corpus/cwe_916_weak_hash/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: passlib pbkdf2_sha256'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE916-V04-BAD',
        cwe='CWE-916',
        file_path='benchmark/corpus/cwe_916_weak_hash/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5', 'hashlib.sha1', 'hashlib.sha256', 'hashlib.sha512'],
        description='OOP: sha256 password hash in __init__'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE916-V04-GOOD',
        cwe='CWE-916',
        file_path='benchmark/corpus/cwe_916_weak_hash/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: hashlib.pbkdf2_hmac 200k iterations'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE916-V05-BAD',
        cwe='CWE-916',
        file_path='benchmark/corpus/cwe_916_weak_hash/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5', 'hashlib.sha1', 'hashlib.sha256', 'hashlib.sha512'],
        description='Branch: sha1/sha256 password hashes'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE916-V05-GOOD',
        cwe='CWE-916',
        file_path='benchmark/corpus/cwe_916_weak_hash/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: sha256 integrity checksum on non-password data'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE916-V06-BAD',
        cwe='CWE-916',
        file_path='benchmark/corpus/cwe_916_weak_hash/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5', 'hashlib.sha1', 'hashlib.sha256', 'hashlib.sha512'],
        description='Salted but weak sha256 (static salt)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE916-V06-GOOD',
        cwe='CWE-916',
        file_path='benchmark/corpus/cwe_916_weak_hash/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: django make_password'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE759-V01-BAD',
        cwe='CWE-759',
        file_path='benchmark/corpus/cwe_759_unsalted_hash/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5', 'hashlib.sha1', 'hashlib.sha256', 'hashlib.sha512'],
        description='Unsalted sha256 password hash'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE759-V01-GOOD',
        cwe='CWE-759',
        file_path='benchmark/corpus/cwe_759_unsalted_hash/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: PBKDF2 with os.urandom salt'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE759-V02-BAD',
        cwe='CWE-759',
        file_path='benchmark/corpus/cwe_759_unsalted_hash/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5', 'hashlib.sha1', 'hashlib.sha256', 'hashlib.sha512'],
        description='Unsalted sha1 password hash'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE759-V02-GOOD',
        cwe='CWE-759',
        file_path='benchmark/corpus/cwe_759_unsalted_hash/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: bcrypt with gensalt'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE759-V03-BAD',
        cwe='CWE-759',
        file_path='benchmark/corpus/cwe_759_unsalted_hash/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5', 'hashlib.sha1', 'hashlib.sha256', 'hashlib.sha512'],
        description='Unsalted md5 hash stored in dict'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE759-V03-GOOD',
        cwe='CWE-759',
        file_path='benchmark/corpus/cwe_759_unsalted_hash/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: argon2 internal salt'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE759-V04-BAD',
        cwe='CWE-759',
        file_path='benchmark/corpus/cwe_759_unsalted_hash/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5', 'hashlib.sha1', 'hashlib.sha256', 'hashlib.sha512'],
        description='OOP: unsalted sha256 in __init__'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE759-V04-GOOD',
        cwe='CWE-759',
        file_path='benchmark/corpus/cwe_759_unsalted_hash/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: passlib pbkdf2_sha256 (salted)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE759-V05-BAD',
        cwe='CWE-759',
        file_path='benchmark/corpus/cwe_759_unsalted_hash/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5', 'hashlib.sha1', 'hashlib.sha256', 'hashlib.sha512'],
        description='Branch: unsalted md5/sha256'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE759-V05-GOOD',
        cwe='CWE-759',
        file_path='benchmark/corpus/cwe_759_unsalted_hash/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: django make_password (salted PBKDF2)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE759-V06-BAD',
        cwe='CWE-759',
        file_path='benchmark/corpus/cwe_759_unsalted_hash/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['hashlib.md5', 'hashlib.sha1', 'hashlib.sha256', 'hashlib.sha512'],
        description='Multi-hop: unsalted digest via helper'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE759-V06-GOOD',
        cwe='CWE-759',
        file_path='benchmark/corpus/cwe_759_unsalted_hash/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: unsalted checksum on non-password data'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE434-V01-BAD',
        cwe='CWE-434',
        file_path='benchmark/corpus/cwe_434_upload/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['file.save'],
        description='User filename saved directly'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE434-V01-GOOD',
        cwe='CWE-434',
        file_path='benchmark/corpus/cwe_434_upload/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: secure_filename before save'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE434-V02-BAD',
        cwe='CWE-434',
        file_path='benchmark/corpus/cwe_434_upload/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['file.save'],
        description='Multi-hop: dest() joins raw filename'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE434-V02-GOOD',
        cwe='CWE-434',
        file_path='benchmark/corpus/cwe_434_upload/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: secure_filename on upload.filename'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE434-V03-BAD',
        cwe='CWE-434',
        file_path='benchmark/corpus/cwe_434_upload/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['file.save'],
        description='Raw filename via dict container'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE434-V03-GOOD',
        cwe='CWE-434',
        file_path='benchmark/corpus/cwe_434_upload/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: extension whitelist containment guard'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE434-V04-BAD',
        cwe='CWE-434',
        file_path='benchmark/corpus/cwe_434_upload/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['file.save'],
        description='OOP: self.filename saved directly'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE434-V04-GOOD',
        cwe='CWE-434',
        file_path='benchmark/corpus/cwe_434_upload/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: uuid4 rename with extension'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE434-V05-BAD',
        cwe='CWE-434',
        file_path='benchmark/corpus/cwe_434_upload/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['file.save'],
        description='Branch: both arms save raw filename'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE434-V05-GOOD',
        cwe='CWE-434',
        file_path='benchmark/corpus/cwe_434_upload/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: secure_filename with empty-name guard'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE434-V06-BAD',
        cwe='CWE-434',
        file_path='benchmark/corpus/cwe_434_upload/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['file.save'],
        description='Concatenated path from raw filename'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE434-V06-GOOD',
        cwe='CWE-434',
        file_path='benchmark/corpus/cwe_434_upload/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: secure_filename then join dest'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE352-V01-BAD',
        cwe='CWE-352',
        file_path='benchmark/corpus/cwe_352_csrf/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='csrf_exempt on POST transfer route'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE352-V01-GOOD',
        cwe='CWE-352',
        file_path='benchmark/corpus/cwe_352_csrf/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: csrf_protect on POST route'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE352-V02-BAD',
        cwe='CWE-352',
        file_path='benchmark/corpus/cwe_352_csrf/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='WTF_CSRF_ENABLED = False'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE352-V02-GOOD',
        cwe='CWE-352',
        file_path='benchmark/corpus/cwe_352_csrf/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: WTF_CSRF_ENABLED = True'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE352-V03-BAD',
        cwe='CWE-352',
        file_path='benchmark/corpus/cwe_352_csrf/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='PUT route without CSRF protection'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE352-V03-GOOD',
        cwe='CWE-352',
        file_path='benchmark/corpus/cwe_352_csrf/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: FlaskForm.validate_on_submit'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE352-V04-BAD',
        cwe='CWE-352',
        file_path='benchmark/corpus/cwe_352_csrf/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='csrf.exempt decorator form'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE352-V04-GOOD',
        cwe='CWE-352',
        file_path='benchmark/corpus/cwe_352_csrf/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: GET-only route (no state change)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE352-V05-BAD',
        cwe='CWE-352',
        file_path='benchmark/corpus/cwe_352_csrf/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='CSRF_ENABLED = False config'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE352-V05-GOOD',
        cwe='CWE-352',
        file_path='benchmark/corpus/cwe_352_csrf/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: CSRF_ENABLED = True'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE352-V06-BAD',
        cwe='CWE-352',
        file_path='benchmark/corpus/cwe_352_csrf/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='csrf.exempt() call form on handler'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE352-V06-GOOD',
        cwe='CWE-352',
        file_path='benchmark/corpus/cwe_352_csrf/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: csrf_protect on PUT route'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE287-V01-BAD',
        cwe='CWE-287',
        file_path='benchmark/corpus/cwe_287_auth/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='Hardcoded password equality in auth branch'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE287-V01-GOOD',
        cwe='CWE-287',
        file_path='benchmark/corpus/cwe_287_auth/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: @login_required decorator'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE287-V02-BAD',
        cwe='CWE-287',
        file_path='benchmark/corpus/cwe_287_auth/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='authenticated flag forced True'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE287-V02-GOOD',
        cwe='CWE-287',
        file_path='benchmark/corpus/cwe_287_auth/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: bcrypt.checkpw verification'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE287-V03-BAD',
        cwe='CWE-287',
        file_path='benchmark/corpus/cwe_287_auth/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='AUTH_ENABLED = False bypasses verification'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE287-V03-GOOD',
        cwe='CWE-287',
        file_path='benchmark/corpus/cwe_287_auth/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: session check with abort(401)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE287-V04-BAD',
        cwe='CWE-287',
        file_path='benchmark/corpus/cwe_287_auth/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='DEBUG_MODE bypass grants access'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE287-V04-GOOD',
        cwe='CWE-287',
        file_path='benchmark/corpus/cwe_287_auth/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: AUTH_ENABLED = True enforced'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE287-V05-BAD',
        cwe='CWE-287',
        file_path='benchmark/corpus/cwe_287_auth/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='Username-only admin grant without password'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE287-V05-GOOD',
        cwe='CWE-287',
        file_path='benchmark/corpus/cwe_287_auth/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: JWT signature verification'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE287-V06-BAD',
        cwe='CWE-287',
        file_path='benchmark/corpus/cwe_287_auth/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=[],
        description='Query-param auth bypass'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE287-V06-GOOD',
        cwe='CWE-287',
        file_path='benchmark/corpus/cwe_287_auth/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: auth backend credential check'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE862-V01-BAD',
        cwe='CWE-862',
        file_path='benchmark/corpus/cwe_862_idor/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['get_object_or_404', 'Model.objects.get', 'Query.get'],
        description='get_object_or_404 by raw id, no owner'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE862-V01-GOOD',
        cwe='CWE-862',
        file_path='benchmark/corpus/cwe_862_idor/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: owner=request.user filter'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE862-V02-BAD',
        cwe='CWE-862',
        file_path='benchmark/corpus/cwe_862_idor/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['get_object_or_404', 'Model.objects.get', 'Query.get'],
        description='Document.objects.get(pk) without owner'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE862-V02-GOOD',
        cwe='CWE-862',
        file_path='benchmark/corpus/cwe_862_idor/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: owner=user filter'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE862-V03-BAD',
        cwe='CWE-862',
        file_path='benchmark/corpus/cwe_862_idor/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['get_object_or_404', 'Model.objects.get', 'Query.get'],
        description='filter_by(id) without user scoping'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE862-V03-GOOD',
        cwe='CWE-862',
        file_path='benchmark/corpus/cwe_862_idor/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: ownership check with abort(403)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE862-V04-BAD',
        cwe='CWE-862',
        file_path='benchmark/corpus/cwe_862_idor/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['get_object_or_404', 'Model.objects.get', 'Query.get'],
        description='OOP: self.doc_id lookup without owner'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE862-V04-GOOD',
        cwe='CWE-862',
        file_path='benchmark/corpus/cwe_862_idor/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: user_id filter in query'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE862-V05-BAD',
        cwe='CWE-862',
        file_path='benchmark/corpus/cwe_862_idor/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['get_object_or_404', 'Model.objects.get', 'Query.get'],
        description='Branch: two unscoped order lookups'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE862-V05-GOOD',
        cwe='CWE-862',
        file_path='benchmark/corpus/cwe_862_idor/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: OOP owner-scoped lookup'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE862-V06-BAD',
        cwe='CWE-862',
        file_path='benchmark/corpus/cwe_862_idor/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['get_object_or_404', 'Model.objects.get', 'Query.get'],
        description='Order.query.get unscoped'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE862-V06-GOOD',
        cwe='CWE-862',
        file_path='benchmark/corpus/cwe_862_idor/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: current_user.id scoping'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE312-V01-BAD',
        cwe='CWE-312',
        file_path='benchmark/corpus/cwe_312_cleartext_store/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['open_write', 'json.dump', 'file.write'],
        description='Plaintext password written to file'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE312-V01-GOOD',
        cwe='CWE-312',
        file_path='benchmark/corpus/cwe_312_cleartext_store/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: Fernet encryption before write'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE312-V02-BAD',
        cwe='CWE-312',
        file_path='benchmark/corpus/cwe_312_cleartext_store/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['open_write', 'json.dump', 'file.write'],
        description='json.dump of plaintext password'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE312-V02-GOOD',
        cwe='CWE-312',
        file_path='benchmark/corpus/cwe_312_cleartext_store/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: bcrypt hash before DB insert'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE312-V03-BAD',
        cwe='CWE-312',
        file_path='benchmark/corpus/cwe_312_cleartext_store/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['open_write', 'json.dump', 'file.write'],
        description='Plaintext password INSERT into DB'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE312-V03-GOOD',
        cwe='CWE-312',
        file_path='benchmark/corpus/cwe_312_cleartext_store/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: vault write for secret'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE312-V04-BAD',
        cwe='CWE-312',
        file_path='benchmark/corpus/cwe_312_cleartext_store/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['open_write', 'json.dump', 'file.write'],
        description='Plaintext api_key written to file'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE312-V04-GOOD',
        cwe='CWE-312',
        file_path='benchmark/corpus/cwe_312_cleartext_store/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: mask_secret before write'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE312-V05-BAD',
        cwe='CWE-312',
        file_path='benchmark/corpus/cwe_312_cleartext_store/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['open_write', 'json.dump', 'file.write'],
        description='Access token appended to plaintext file'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE312-V05-GOOD',
        cwe='CWE-312',
        file_path='benchmark/corpus/cwe_312_cleartext_store/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: hash of token stored instead'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE312-V06-BAD',
        cwe='CWE-312',
        file_path='benchmark/corpus/cwe_312_cleartext_store/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['open_write', 'json.dump', 'file.write'],
        description='Secret key written to plaintext file'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE312-V06-GOOD',
        cwe='CWE-312',
        file_path='benchmark/corpus/cwe_312_cleartext_store/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: non-sensitive fields persisted'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE319-V01-BAD',
        cwe='CWE-319',
        file_path='benchmark/corpus/cwe_319_cleartext_transmit/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get', 'requests.post', 'urllib.request.urlopen', 'urlopen', 'httpx.get', 'httpx.post'],
        description='http:// login POST with credentials'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE319-V01-GOOD',
        cwe='CWE-319',
        file_path='benchmark/corpus/cwe_319_cleartext_transmit/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: https:// login POST'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE319-V02-BAD',
        cwe='CWE-319',
        file_path='benchmark/corpus/cwe_319_cleartext_transmit/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get', 'requests.post', 'urllib.request.urlopen', 'urlopen', 'httpx.get', 'httpx.post'],
        description='urlopen on http:// URL'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE319-V02-GOOD',
        cwe='CWE-319',
        file_path='benchmark/corpus/cwe_319_cleartext_transmit/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: urlopen on https://'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE319-V03-BAD',
        cwe='CWE-319',
        file_path='benchmark/corpus/cwe_319_cleartext_transmit/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get', 'requests.post', 'urllib.request.urlopen', 'urlopen', 'httpx.get', 'httpx.post'],
        description='Multi-hop: http URL via variable'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE319-V03-GOOD',
        cwe='CWE-319',
        file_path='benchmark/corpus/cwe_319_cleartext_transmit/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: runtime scheme validation'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE319-V04-BAD',
        cwe='CWE-319',
        file_path='benchmark/corpus/cwe_319_cleartext_transmit/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get', 'requests.post', 'urllib.request.urlopen', 'urlopen', 'httpx.get', 'httpx.post'],
        description='Branch: two http:// endpoints'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE319-V04-GOOD',
        cwe='CWE-319',
        file_path='benchmark/corpus/cwe_319_cleartext_transmit/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: https:// constant URL'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE319-V05-BAD',
        cwe='CWE-319',
        file_path='benchmark/corpus/cwe_319_cleartext_transmit/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get', 'requests.post', 'urllib.request.urlopen', 'urlopen', 'httpx.get', 'httpx.post'],
        description='http:// auth POST with creds data'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE319-V05-GOOD',
        cwe='CWE-319',
        file_path='benchmark/corpus/cwe_319_cleartext_transmit/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: https endpoints in both branches'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE319-V06-BAD',
        cwe='CWE-319',
        file_path='benchmark/corpus/cwe_319_cleartext_transmit/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['requests.get', 'requests.post', 'urllib.request.urlopen', 'urlopen', 'httpx.get', 'httpx.post'],
        description='httpx.post over http://'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE319-V06-GOOD',
        cwe='CWE-319',
        file_path='benchmark/corpus/cwe_319_cleartext_transmit/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: httpx.post over https://'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE489-V01-BAD',
        cwe='CWE-489',
        file_path='benchmark/corpus/cwe_489_debug/test_v01_bad.py',
        is_vulnerable=True,
        expected_sinks=['app.run', 'Flask.run', 'uvicorn.run'],
        description='app.run(debug=True)'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE489-V01-GOOD',
        cwe='CWE-489',
        file_path='benchmark/corpus/cwe_489_debug/test_v01_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: app.run() without debug'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE489-V02-BAD',
        cwe='CWE-489',
        file_path='benchmark/corpus/cwe_489_debug/test_v02_bad.py',
        is_vulnerable=True,
        expected_sinks=['app.run', 'Flask.run', 'uvicorn.run'],
        description='DEBUG = True module config'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE489-V02-GOOD',
        cwe='CWE-489',
        file_path='benchmark/corpus/cwe_489_debug/test_v02_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: DEBUG = False'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE489-V03-BAD',
        cwe='CWE-489',
        file_path='benchmark/corpus/cwe_489_debug/test_v03_bad.py',
        is_vulnerable=True,
        expected_sinks=['app.run', 'Flask.run', 'uvicorn.run'],
        description='app.config DEBUG = True'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE489-V03-GOOD',
        cwe='CWE-489',
        file_path='benchmark/corpus/cwe_489_debug/test_v03_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: env-driven debug flag'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE489-V04-BAD',
        cwe='CWE-489',
        file_path='benchmark/corpus/cwe_489_debug/test_v04_bad.py',
        is_vulnerable=True,
        expected_sinks=['app.run', 'Flask.run', 'uvicorn.run'],
        description='uvicorn.run debug=True'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE489-V04-GOOD',
        cwe='CWE-489',
        file_path='benchmark/corpus/cwe_489_debug/test_v04_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: run kwargs without debug'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE489-V05-BAD',
        cwe='CWE-489',
        file_path='benchmark/corpus/cwe_489_debug/test_v05_bad.py',
        is_vulnerable=True,
        expected_sinks=['app.run', 'Flask.run', 'uvicorn.run'],
        description='app.run kwargs with debug=True'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE489-V05-GOOD',
        cwe='CWE-489',
        file_path='benchmark/corpus/cwe_489_debug/test_v05_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: uvicorn.run without debug'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE489-V06-BAD',
        cwe='CWE-489',
        file_path='benchmark/corpus/cwe_489_debug/test_v06_bad.py',
        is_vulnerable=True,
        expected_sinks=['app.run', 'Flask.run', 'uvicorn.run'],
        description='app.debug = True attribute'
    ),
    BenchmarkTestCase(
        test_id='TCS-BENCH-CWE489-V06-GOOD',
        cwe='CWE-489',
        file_path='benchmark/corpus/cwe_489_debug/test_v06_good.py',
        is_vulnerable=False,
        expected_sinks=[],
        description='Safe: app.config DEBUG = False'
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
