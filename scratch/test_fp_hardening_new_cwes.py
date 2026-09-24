"""Test Suite for False Positive Elimination and Context-Aware Guards on 7 New CWEs.

Validates:
1. CWE-338 (Insecure Randomness):
   - Non-security usage (e.g. dice = random.randint(1, 6), math simulations) passes with 0 findings.
   - Security usage (e.g. token = random.randint(100000, 999999), reset_pin = random.randrange(...)) triggers CWE-338.
2. CWE-327 (Broken Crypto):
   - hashlib.md5(b"cache", usedforsecurity=False) passes with 0 findings.
   - Non-crypto checksum assignment (cache_key = hashlib.md5(...), etag = hashlib.sha1(...)) passes with 0 findings.
   - Security hash (hashlib.md5(pwd.encode()), pwd_hash = hashlib.md5(...)) correctly triggers CWE-327.
3. CWE-400 (Unbounded Read):
   - Small local file read (with open("config.json") as f: f.read()) passes with 0 findings.
   - open("config.json").read() passes with 0 findings.
   - Stream/upload read (request.stream.read(), request.files['file'].read()) correctly triggers CWE-400.
4. CWE-918 & CWE-601 (Semantic Sanitizer & Guard Verification):
   - Dummy validator (def is_safe_url(url): return True) does NOT clear taint (CWE-918 triggers).
   - Real validator clears taint inside safe branch of `if is_safe_url(url):`, but NOT outside the if block.
   - Dummy redirect validator does NOT clear taint (CWE-601 triggers).
"""

import unittest
from ast_scanner import TaintTracker


class TestCWE338ContextAwareRandomness(unittest.TestCase):
    """Verify CWE-338 flags only security-sensitive randomness and spares general numeric/utility use."""

    def test_non_security_random_randint_passes(self):
        code = """
import random

def roll_dice():
    dice = random.randint(1, 6)
    score = random.random() * 100
    item = random.choice(["apple", "banana", "cherry"])
    steps = random.randrange(1, 10)
    return dice, score, item, steps
"""
        tracker = TaintTracker(files={"test.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()
        cwe338_sinks = [s for s in sinks if s.metadata.get("cwe") == "CWE-338"]
        cwe338_edges = [e for e in edges if any(s.id == e.target_id and s.metadata.get("cwe") == "CWE-338" for s in sinks)]
        self.assertEqual(len(cwe338_sinks), 0, f"Expected 0 CWE-338 sinks for utility random, found: {cwe338_sinks}")
        self.assertEqual(len(cwe338_edges), 0, f"Expected 0 CWE-338 edges for utility random, found: {cwe338_edges}")

    def test_security_random_token_assignment_triggers(self):
        code = """
import random

def generate_credentials():
    token = random.randint(100000, 999999)
    session_key = random.choice("abcdef123456")
    auth_secret = random.randrange(1000, 9999)
    return token, session_key, auth_secret
"""
        tracker = TaintTracker(files={"test.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()
        cwe338_sinks = [s for s in sinks if s.metadata.get("cwe") == "CWE-338"]
        self.assertGreaterEqual(len(cwe338_sinks), 1, "Expected CWE-338 sinks for security token assignments")

    def test_security_random_passed_to_auth_function_triggers(self):
        code = """
import random

def authenticate_user(user_id, otp):
    pass

def login():
    authenticate_user(42, otp=random.randint(100000, 999999))
"""
        tracker = TaintTracker(files={"test.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()
        cwe338_sinks = [s for s in sinks if s.metadata.get("cwe") == "CWE-338"]
        self.assertGreaterEqual(len(cwe338_sinks), 1, "Expected CWE-338 sink when passed to auth function")


class TestCWE327BrokenCryptoGuards(unittest.TestCase):
    """Verify CWE-327 respects usedforsecurity=False and non-cryptographic checksum targets."""

    def test_usedforsecurity_false_keyword_passes(self):
        code = """
import hashlib

def compute_cache_tag(data):
    h = hashlib.md5(data, usedforsecurity=False)
    s = hashlib.sha1(data, usedforsecurity=False)
    return h.hexdigest(), s.hexdigest()
"""
        tracker = TaintTracker(files={"test.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()
        cwe327_sinks = [s for s in sinks if s.metadata.get("cwe") == "CWE-327"]
        self.assertEqual(len(cwe327_sinks), 0, f"Expected 0 CWE-327 sinks with usedforsecurity=False, got: {cwe327_sinks}")

    def test_non_crypto_checksum_assignment_passes(self):
        code = """
import hashlib

def get_metadata(content):
    cache_key = hashlib.md5(content).hexdigest()
    etag = hashlib.sha1(content).hexdigest()
    checksum = hashlib.md5(content).digest()
    return cache_key, etag, checksum
"""
        tracker = TaintTracker(files={"test.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()
        cwe327_sinks = [s for s in sinks if s.metadata.get("cwe") == "CWE-327"]
        self.assertEqual(len(cwe327_sinks), 0, f"Expected 0 CWE-327 sinks for cache_key/etag checksums, got: {cwe327_sinks}")

    def test_security_password_hash_triggers(self):
        code = """
import hashlib

def store_password(pwd):
    pwd_hash = hashlib.md5(pwd.encode()).hexdigest()
    auth_sig = hashlib.sha1(pwd.encode()).digest()
    return pwd_hash, auth_sig
"""
        tracker = TaintTracker(files={"test.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()
        cwe327_sinks = [s for s in sinks if s.metadata.get("cwe") == "CWE-327"]
        self.assertGreaterEqual(len(cwe327_sinks), 1, "Expected CWE-327 sink for password hash")

    def test_bare_hashlib_md5_call_triggers(self):
        code = """
import hashlib

def hash_secret(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()
"""
        tracker = TaintTracker(files={"test.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()
        cwe327_sinks = [s for s in sinks if s.metadata.get("cwe") == "CWE-327"]
        self.assertGreaterEqual(len(cwe327_sinks), 1, "Expected CWE-327 sink for bare md5 call")


class TestCWE400UnboundedReadRefinement(unittest.TestCase):
    """Verify CWE-400 only flags unbounded read when stream is tainted or from network/request input."""

    def test_local_config_file_read_passes(self):
        code = """
def load_app_config():
    with open("config.json", "r") as f:
        data = f.read()
    raw = open("settings.ini").read()
    return data, raw
"""
        tracker = TaintTracker(files={"test.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()
        cwe400_sinks = [s for s in sinks if s.metadata.get("cwe") == "CWE-400" and s.operation == "UNBOUNDED_READ"]
        cwe400_edges = [e for e in edges if any(s.id == e.target_id and s.metadata.get("cwe") == "CWE-400" for s in sinks)]
        self.assertEqual(len(cwe400_sinks), 0, f"Expected 0 CWE-400 unbounded read sinks for local config, got: {cwe400_sinks}")
        self.assertEqual(len(cwe400_edges), 0, f"Expected 0 CWE-400 edges for local config, got: {cwe400_edges}")

    def test_request_stream_read_triggers(self):
        code = """
from flask import request

def upload_handler():
    stream_data = request.stream.read()
    return stream_data
"""
        tracker = TaintTracker(files={"test.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()
        cwe400_edges = [e for e in edges if any(s.id == e.target_id and s.metadata.get("cwe") == "CWE-400" for s in sinks)]
        self.assertGreaterEqual(len(cwe400_edges), 1, "Expected CWE-400 edge for request.stream.read()")

    def test_request_uploaded_file_read_triggers(self):
        code = """
from flask import request

def handle_upload():
    uploaded_file = request.files['document']
    content = uploaded_file.read()
    return content
"""
        tracker = TaintTracker(files={"test.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()
        cwe400_edges = [e for e in edges if any(s.id == e.target_id and s.metadata.get("cwe") == "CWE-400" for s in sinks)]
        self.assertGreaterEqual(len(cwe400_edges), 1, "Expected CWE-400 edge for uploaded file read")


class TestSemanticSanitizerGuards(unittest.TestCase):
    """Verify CWE-918 and CWE-601 validators must be non-dummy and active conditional guards enclosing the sink."""

    def test_dummy_validator_does_not_clear_taint(self):
        code = """
from flask import request
import requests

def is_safe_url(url):
    return True

def proxy():
    url = request.args.get("url")
    if is_safe_url(url):
        requests.get(url)
"""
        tracker = TaintTracker(files={"test.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()
        cwe918_edges = [e for e in edges if any(s.id == e.target_id and s.metadata.get("cwe") == "CWE-918" for s in sinks)]
        self.assertGreaterEqual(len(cwe918_edges), 1, "Expected CWE-918 vulnerability when validator is a dummy return True")

    def test_real_validator_protects_inside_if_branch(self):
        code = """
from flask import request
import urllib.parse
import requests

def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc in ["example.com", "api.example.com"]

def proxy():
    url = request.args.get("url")
    if is_safe_url(url):
        requests.get(url)
"""
        tracker = TaintTracker(files={"test.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()
        cwe918_edges = [e for e in edges if any(s.id == e.target_id and s.metadata.get("cwe") == "CWE-918" for s in sinks)]
        self.assertEqual(len(cwe918_edges), 0, f"Expected 0 CWE-918 findings inside safe branch of real validator, got: {cwe918_edges}")

    def test_real_validator_does_not_protect_outside_if_branch(self):
        code = """
from flask import request
import urllib.parse
import requests

def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc in ["example.com", "api.example.com"]

def proxy():
    url = request.args.get("url")
    if is_safe_url(url):
        pass
    requests.get(url)
"""
        tracker = TaintTracker(files={"test.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()
        cwe918_edges = [e for e in edges if any(s.id == e.target_id and s.metadata.get("cwe") == "CWE-918" for s in sinks)]
        self.assertGreaterEqual(len(cwe918_edges), 1, "Expected CWE-918 vulnerability when sink is outside the if body")

    def test_dummy_redirect_validator_does_not_clear_taint(self):
        code = """
from flask import request, redirect

def is_safe_redirect_url(target):
    return True

def nav():
    nxt = request.args.get("next")
    if is_safe_redirect_url(nxt):
        return redirect(nxt)
"""
        tracker = TaintTracker(files={"test.py": code}, audit_all=True)
        sources, sinks, edges = tracker.analyze()
        cwe601_edges = [e for e in edges if any(s.id == e.target_id and s.metadata.get("cwe") == "CWE-601" for s in sinks)]
        self.assertGreaterEqual(len(cwe601_edges), 1, "Expected CWE-601 vulnerability when redirect validator is a dummy return True")


if __name__ == "__main__":
    unittest.main(verbosity=2)
