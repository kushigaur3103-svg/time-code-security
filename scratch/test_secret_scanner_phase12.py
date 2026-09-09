"""Unit and integration test suite for Phase 12 Step 1 - Core Secret Scanner.

Verifies:
- Network isolation (socket.connect blocked)
- Deterministic masking logic (mask_secret)
- Shannon entropy computation (shannon_entropy)
- Positive detector coverage across all 5 credential categories
- Negative / false-positive resistance
- Multi-line & CRLF (\r\n) handling (Technical Guard 1)
- ReDoS safety and negated character class enforcement (Technical Guard 2)
- Private key header anchoring without body buffering (Technical Guard 3)
- Multi-secret line redaction & context integrity
- Precedence-based span overlap resolution
- Zero cleartext leakage in SecretFinding structures, repr, str, dict, and context
- File scanning and exception handling
- 50-iteration determinism verification
"""

import dataclasses
import os
import socket
import sys
import tempfile
import unittest

# ---------------------------------------------------------------------------
# Network isolation guard
# ---------------------------------------------------------------------------
def _blocked_connect(*args, **kwargs):
    raise RuntimeError("NETWORK CALL ATTEMPTED: Offline invariant violated!")

socket.socket.connect = _blocked_connect

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Import secret scanner under test
from secret_scanner import (
    SecretFinding,
    mask_secret,
    shannon_entropy,
    scan_text,
    scan_file,
)


class TestMaskSecret(unittest.TestCase):
    """Test deterministic secret masking."""

    def test_empty_string(self):
        self.assertEqual(mask_secret(""), "")

    def test_short_secrets_up_to_4_chars(self):
        self.assertEqual(mask_secret("a"), "*")
        self.assertEqual(mask_secret("ab"), "**")
        self.assertEqual(mask_secret("abc"), "***")
        self.assertEqual(mask_secret("abcd"), "****")

    def test_medium_secrets_5_to_8_chars(self):
        self.assertEqual(mask_secret("abcde"), "a***e")
        self.assertEqual(mask_secret("abcdef"), "a****f")
        self.assertEqual(mask_secret("1234567"), "1*****7")
        self.assertEqual(mask_secret("12345678"), "1******8")

    def test_long_secrets_greater_than_8_chars(self):
        self.assertEqual(mask_secret("123456789"), "1234*6789")
        self.assertEqual(mask_secret("1234567890"), "1234**7890")
        masked = mask_secret("AKIA1234567890ABCD")
        self.assertEqual(masked, "AKIA**********ABCD")
        self.assertEqual(len(masked), 18)

    def test_unicode_handling(self):
        val = "ü123456ö"
        masked = mask_secret(val)
        self.assertEqual(len(masked), len(val))
        self.assertTrue(masked.startswith("ü"))
        self.assertTrue(masked.endswith("ö"))


class TestShannonEntropy(unittest.TestCase):
    """Test Shannon entropy calculation."""

    def test_empty_string(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_uniform_single_char(self):
        self.assertEqual(shannon_entropy("aaaaaaa"), 0.0)

    def test_two_equal_chars(self):
        # -2 * (0.5 * log2(0.5)) = 1.0
        self.assertAlmostEqual(shannon_entropy("ab"), 1.0, places=5)

    def test_four_equal_chars(self):
        # -4 * (0.25 * log2(0.25)) = 2.0
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0, places=5)

    def test_entropy_ordering(self):
        low_entropy = shannon_entropy("aaabbbccc")
        high_entropy = shannon_entropy("aBc9#xL!2@")
        self.assertGreater(high_entropy, low_entropy)


class TestPositiveDetections(unittest.TestCase):
    """Test detection of all 5 supported secret types."""

    def test_detect_private_keys(self):
        headers = [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY BLOCK-----",
        ]
        for header in headers:
            sample = f"line1\n{header}\nline3"
            findings = scan_text(sample, filename="test.pem")
            self.assertEqual(len(findings), 1, f"Failed on header: {header}")
            f = findings[0]
            self.assertEqual(f.secret_type, "private_key")
            self.assertEqual(f.detector, "private_key")
            self.assertEqual(f.line_number, 2)
            self.assertEqual(f.confidence, "HIGH")
            self.assertNotIn(header, f.context)

    def test_detect_github_tokens(self):
        prefixes = ["ghp", "gho", "ghu", "ghs", "ghr"]
        for pfx in prefixes:
            token = f"{pfx}_1234567890abcdefghijklmnopqrstuvwxyz"
            code = f'GITHUB_API_KEY = "{token}"'
            findings = scan_text(code, filename="config.py")
            self.assertEqual(len(findings), 1, f"Failed on prefix {pfx}")
            f = findings[0]
            self.assertEqual(f.secret_type, "github_token")
            self.assertEqual(f.detector, "github_token")
            self.assertEqual(f.confidence, "HIGH")
            self.assertNotIn(token, f.context)
            self.assertNotIn(token, repr(f))

    def test_detect_slack_tokens(self):
        prefixes = ["xoxb", "xoxp", "xoxa", "xoxr", "xoxs"]
        for pfx in prefixes:
            token = f"{pfx}-123456789012-abcdefghij"
            code = f'SLACK_TOKEN = "{token}"'
            findings = scan_text(code, filename="bot.py")
            self.assertEqual(len(findings), 1, f"Failed on slack prefix {pfx}")
            f = findings[0]
            self.assertEqual(f.secret_type, "slack_token")
            self.assertEqual(f.detector, "slack_token")
            self.assertEqual(f.confidence, "HIGH")
            self.assertNotIn(token, f.context)

    def test_detect_aws_access_keys(self):
        keys = [
            "AKIA1234567890ABCD",       # 18-char synthetic test value
            "ASIA1234567890ABCDEF",     # 20-char standard
            "ABIAABCDEFGHIJKLMNOP",     # 20-char standard
            "ACCA1234567890123456",     # 20-char standard
        ]
        for key in keys:
            code = f'aws_key = "{key}"'
            findings = scan_text(code, filename="aws.py")
            self.assertEqual(len(findings), 1, f"Failed on aws key {key}")
            f = findings[0]
            self.assertEqual(f.secret_type, "aws_access_key")
            self.assertEqual(f.detector, "aws_access_key")
            self.assertEqual(f.confidence, "HIGH")
            self.assertNotIn(key, f.context)

    def test_detect_database_connection_strings(self):
        uris = [
            ("postgres://app_user:s3cr3t_p@ss@db.internal:5432/production", "app_user", "s3cr3t_p@ss"),
            ("postgresql://admin:supersecret@localhost:5432/mydb", "admin", "supersecret"),
            ("mysql://root:toor123@10.0.0.1:3306/users", "root", "toor123"),
            ("mongodb://mongo_admin:pwd9988@cluster0.net:27017/analytics", "mongo_admin", "pwd9988"),
            ("redis://:auth_token_redis@cache.local:6379/0", None, "auth_token_redis"),
        ]
        for uri, user, pw in uris:
            code = f'DATABASE_URL = "{uri}"'
            findings = scan_text(code, filename="settings.py")
            self.assertEqual(len(findings), 1, f"Failed on URI: {uri}")
            f = findings[0]
            self.assertEqual(f.secret_type, "database_connection_string")
            self.assertEqual(f.detector, "database_connection_string")
            self.assertEqual(f.confidence, "HIGH")
            # Cleartext password must never appear anywhere
            self.assertNotIn(pw, f.masked_value)
            self.assertNotIn(pw, f.context)
            self.assertNotIn(pw, repr(f))


class TestNegativeDetections(unittest.TestCase):
    """Test non-detection of false positives, public keys, and normal code."""

    def test_clean_source_code(self):
        clean_code = """
        def compute_metrics(x, y):
            # Calculate total
            total = x + y
            return total
        """
        self.assertEqual(scan_text(clean_code), [])

    def test_public_key_and_certificate_ignored(self):
        text = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
        -----END PUBLIC KEY-----
        -----BEGIN CERTIFICATE-----
        MIICXTCCAcagAwIBAgIU...
        -----END CERTIFICATE-----
        """
        self.assertEqual(scan_text(text), [])

    def test_invalid_token_prefixes(self):
        text = """
        ghx_1234567890abcdefghijklmnopqrstuvwxyz
        xoxz-1234567890-abcdef
        BKIA1234567890ABCDEF
        """
        self.assertEqual(scan_text(text), [])

    def test_database_uris_without_password_ignored(self):
        no_pw_uris = """
        postgres://localhost:5432/mydb
        postgresql://app_user@db.internal:5432/mydb
        mysql://root@127.0.0.1:3306/db
        redis://localhost:6379/0
        mongodb://mongo.internal:27017/test
        http://user:password@example.com
        https://api.github.com
        """
        self.assertEqual(scan_text(no_pw_uris), [])


class TestTechnicalGuards(unittest.TestCase):
    """Verify CTO technical guards 1, 2, and 3."""

    def test_guard_1_crlf_handling(self):
        # Guard 1: Handle CRLF cleanly without \r in column positions or context
        token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        crlf_text = f"first_line = 1\r\ntoken = \"{token}\"\r\nlast_line = 3\r\n"
        findings = scan_text(crlf_text, filename="crlf.py")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.line_number, 2)
        self.assertNotIn("\r", f.context)
        self.assertNotIn("\n", f.context)
        # Column positions should index cleanly into stripped line
        clean_line = crlf_text.splitlines()[1]
        self.assertEqual(clean_line[f.column_start - 1 : f.column_end], token)

    def test_guard_2_db_uri_redos_immunity(self):
        # Guard 2: Negated character classes avoid catastrophic backtracking
        malicious = "postgres://" + ":" * 50 + "@" + "a" * 50
        # Must return quickly without hanging
        findings = scan_text(malicious, filename="redos_test.py")
        self.assertEqual(findings, [])

    def test_guard_3_private_key_header_anchored(self):
        # Guard 3: Anchored strictly to header line without buffering multi-line bodies
        pem_file = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1+r...fake_base64_body_line_1...
fake_base64_body_line_2...
-----END RSA PRIVATE KEY-----"""
        findings = scan_text(pem_file, filename="key.pem")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.line_number, 1)
        self.assertEqual(f.secret_type, "private_key")
        self.assertNotIn("fake_base64_body", f.context)


class TestMultiSecretAndRedaction(unittest.TestCase):
    """Test lines with multiple secrets, context redaction, and overlap."""

    def test_multiple_secrets_on_same_line_fully_redacted(self):
        tok1 = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        tok2 = "AKIA1234567890ABCD"
        line = f'key = "{tok2}", gh = "{tok1}"'
        findings = scan_text(line, filename="multi.py")
        self.assertEqual(len(findings), 2)
        # Context for BOTH findings must have BOTH secrets redacted
        for f in findings:
            self.assertNotIn(tok1, f.context)
            self.assertNotIn(tok2, f.context)
            self.assertNotIn(tok1, repr(f))
            self.assertNotIn(tok2, repr(f))

    def test_overlap_resolution_precedence(self):
        # Test precedence: private_key (1) beats all others
        # Suppose a line has private key header
        header = "-----BEGIN RSA PRIVATE KEY-----"
        line = f"# Key: {header}"
        findings = scan_text(line, filename="test.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].secret_type, "private_key")


class TestZeroCleartextLeakage(unittest.TestCase):
    """Strictly assert raw secrets never appear in finding objects or serializations."""

    def test_zero_leakage_in_structures(self):
        tok = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        findings = scan_text(f'token = "{tok}"', filename="secret.py")
        self.assertEqual(len(findings), 1)
        f = findings[0]

        # 1. No raw_secret or raw_value attribute
        self.assertFalse(hasattr(f, "raw_secret"))
        self.assertFalse(hasattr(f, "raw_value"))

        # 2. Not in __dict__
        for k, v in f.__dict__.items():
            self.assertNotIn(tok, str(k))
            self.assertNotIn(tok, str(v))

        # 3. Not in str or repr
        self.assertNotIn(tok, str(f))
        self.assertNotIn(tok, repr(f))

        # 4. Not in asdict
        as_dict = dataclasses.asdict(f)
        for k, v in as_dict.items():
            self.assertNotIn(tok, str(v))

        # 5. Not in context
        self.assertNotIn(tok, f.context)


class TestFileScannerAndDeterminism(unittest.TestCase):
    """Test file scanning, missing file handling, and reproducibility."""

    def test_scan_file_utf8(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as tf:
            tf.write('AWS_KEY = "AKIA1234567890ABCD"\n')
            temp_path = tf.name

        try:
            findings = scan_file(temp_path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].file, temp_path)
            self.assertEqual(findings[0].secret_type, "aws_access_key")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_scan_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            scan_file("non_existent_file_abc123.txt")

    def test_determinism_50_iterations(self):
        snippet = """
        # Config file
        GITHUB = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        AWS = "AKIA1234567890ABCD"
        DB = "postgres://usr:secretpw@10.0.0.1:5432/app"
        SLACK = "xoxb-123456789012-abcdefghij"
        """
        baseline = scan_text(snippet, filename="app.conf")
        self.assertEqual(len(baseline), 4)

        for _ in range(50):
            current = scan_text(snippet, filename="app.conf")
            self.assertEqual(baseline, current)


class TestEdgeCasesAndIsolation(unittest.TestCase):
    """Test architectural boundaries, query params, and column slicing."""

    def test_db_uri_with_query_params(self):
        uri = "postgres://app:s3cr3t@db.corp:5432/main?sslmode=verify-full&sslrootcert=ca.crt"
        code = f'DB_DSN = "{uri}"'
        findings = scan_text(code, filename="db.py")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertNotIn("s3cr3t", f.masked_value)
        self.assertNotIn("s3cr3t", f.context)
        self.assertTrue(f.masked_value.endswith("?sslmode=verify-full&sslrootcert=ca.crt"))

    def test_exact_column_slice_reconstruction(self):
        token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        lines = [
            token,                      # at start of line
            f"prefix {token}",          # in middle
            f"longer prefix token: {token} suffix",
        ]
        for idx, line in enumerate(lines, start=1):
            findings = scan_text(line, filename="test.py")
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f.line_number, 1)
            extracted = line[f.column_start - 1 : f.column_end]
            self.assertEqual(extracted, token)

    def test_module_isolation(self):
        # Verify secret_scanner does not import any forbidden modules
        forbidden = {
            "ast_scanner",
            "rule_engine",
            "suppression_resolver",
            "osv_client",
            "version_matcher",
            "app",
            "tcs_cli",
            "sarif_adapter",
        }
        loaded = set(sys.modules.keys())
        overlap = forbidden.intersection(loaded)
        self.assertEqual(overlap, set(), f"Forbidden modules loaded: {overlap}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
