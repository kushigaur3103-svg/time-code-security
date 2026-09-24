"""Test Suite for Phase 3: Shannon Entropy Engine & Reversible Secret Vault.

Validates:
1. calculate_shannon_entropy (empty/single char = 0.0, base-2 log entropy, alias)
2. Multi-provider regex registry (AWS, GitHub, Stripe, Slack, Google, Private Key)
3. High-entropy heuristic (adaptive: hex >= 3.0 (len>=24) vs mixed >= 4.3 (len>=16))
4. SecretVault deterministic sequential tokens: __TCS_VAULT_TOKEN_{idx}__ based on order of appearance
5. SecretVault restoration integrity verification: raises VaultRestorationError if token unreplaced
6. Lossless round-trip: restore(redact(code)[0], vault_map) == code
7. Integration with app.py (apply_zero_leak_redaction, cache hash determinism)
"""

import hashlib
import re
import unittest
from secret_scanner import (
    calculate_shannon_entropy,
    shannon_entropy,
    SECRET_PATTERNS,
    SecretVault,
    VaultRestorationError,
    is_adaptive_high_entropy_secret,
    find_high_entropy_secrets_ast,
    find_high_entropy_secrets_regex,
)

# Synthetic test tokens constructed dynamically to prevent scanner false positives
_SYNTHETIC_STRIPE_LIVE = "sk_live_" + "51Abcdefghijklmnopqrstuv12345"
_SYNTHETIC_STRIPE_RK = "rk_live_" + "51Abcdefghijklmnopqrstuv12345"
_SYNTHETIC_STRIPE_PK = "pk_live_" + "51Abcdefghijklmnopqrstuv12345"
_SYNTHETIC_STRIPE_TEST = "sk_test_" + "51Abcdefghijklmnopqrstuv12345"
_SYNTHETIC_AWS_KEY = "AKIA" + "1234567890ABCDEF"
_SYNTHETIC_GHP = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
_SYNTHETIC_PAT = "github_pat_" + "11AAAAAAA0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789012"
_SYNTHETIC_SLACK = "xoxb-" + "123456789012-1234567890123-abcdefghijkl"
_SYNTHETIC_GOOGLE = "AIza" + "SyD-1234567890abcdefghijklmnopqrSTU"


class TestShannonEntropyEngine(unittest.TestCase):
    """Test standard base-2 Shannon entropy calculation and edge cases."""

    def test_empty_string(self):
        self.assertEqual(calculate_shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_single_char_string(self):
        self.assertEqual(calculate_shannon_entropy("a"), 0.0)
        self.assertEqual(calculate_shannon_entropy("Z"), 0.0)
        self.assertEqual(calculate_shannon_entropy("!"), 0.0)
        self.assertEqual(shannon_entropy("a"), 0.0)

    def test_uniform_string(self):
        self.assertEqual(calculate_shannon_entropy("aaaaaaa"), 0.0)
        self.assertEqual(calculate_shannon_entropy("1111111111"), 0.0)

    def test_two_equal_chars(self):
        # H = - (0.5 * log2(0.5) + 0.5 * log2(0.5)) = 1.0
        self.assertAlmostEqual(calculate_shannon_entropy("ab"), 1.0, places=5)
        self.assertAlmostEqual(calculate_shannon_entropy("aabb"), 1.0, places=5)

    def test_four_equal_chars(self):
        # H = - 4 * (0.25 * log2(0.25)) = 2.0
        self.assertAlmostEqual(calculate_shannon_entropy("abcd"), 2.0, places=5)
        self.assertAlmostEqual(calculate_shannon_entropy("aabbccdd"), 2.0, places=5)

    def test_high_entropy_random_string(self):
        # Base64 random token should have entropy > 4.5
        token = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        entropy = calculate_shannon_entropy(token)
        self.assertGreater(entropy, 4.3)

    def test_low_entropy_predictable_string(self):
        # Repetitive / English string should have entropy < 4.3
        self.assertLess(calculate_shannon_entropy("password1234567890"), 4.3)
        self.assertLess(calculate_shannon_entropy("development_secret_key_for_testing"), 4.3)


class TestMultiProviderPatterns(unittest.TestCase):
    """Test provider regex detection in SECRET_PATTERNS registry."""

    def test_aws_access_key(self):
        pat = SECRET_PATTERNS["AWS Access Key"]
        self.assertTrue(pat.search(_SYNTHETIC_AWS_KEY))
        self.assertTrue(pat.search("ASIA" + "1234567890ABCDEF"))
        self.assertFalse(pat.search("NOTAKEY1234567890ABCDEF"))

    def test_aws_secret_key(self):
        pat = SECRET_PATTERNS["AWS Secret Key"]
        text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        m = pat.search(text)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

    def test_github_tokens(self):
        pat = SECRET_PATTERNS["GitHub Token"]
        # ghp token
        self.assertTrue(pat.search(_SYNTHETIC_GHP))
        # fine-grained PAT
        self.assertTrue(pat.search(_SYNTHETIC_PAT))

    def test_stripe_keys(self):
        pat = SECRET_PATTERNS["Stripe API Key"]
        self.assertTrue(pat.search(_SYNTHETIC_STRIPE_LIVE))
        self.assertTrue(pat.search(_SYNTHETIC_STRIPE_PK))
        self.assertTrue(pat.search(_SYNTHETIC_STRIPE_TEST))
        self.assertTrue(pat.search(_SYNTHETIC_STRIPE_RK))

    def test_slack_tokens(self):
        pat = SECRET_PATTERNS["Slack API Token"]
        self.assertTrue(pat.search(_SYNTHETIC_SLACK))
        self.assertTrue(pat.search("xoxp-" + "123456789012-abcdefghij"))

    def test_google_api_keys(self):
        pat = SECRET_PATTERNS["Google API Key"]
        self.assertTrue(pat.search(_SYNTHETIC_GOOGLE))

    def test_asymmetric_private_keys(self):
        pat = SECRET_PATTERNS["Asymmetric Private Key"]
        header_only = "-----BEGIN RSA PRIVATE KEY-----"
        self.assertTrue(pat.search(header_only))
        pem_block = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1+r...
-----END RSA PRIVATE KEY-----"""
        self.assertTrue(pat.search(pem_block))

    def test_flexible_dict_lookup(self):
        # Flexible case and underscore matching
        self.assertIsNotNone(SECRET_PATTERNS.get("aws_access_key"))
        self.assertIsNotNone(SECRET_PATTERNS.get("github_token"))
        self.assertIsNotNone(SECRET_PATTERNS.get("stripe_api_key"))
        self.assertIsNotNone(SECRET_PATTERNS.get("slack_api_token"))
        self.assertIsNotNone(SECRET_PATTERNS.get("google_api_key"))


class TestAdaptiveEntropyHeuristic(unittest.TestCase):
    """Test character-set adaptive entropy detection (Hex vs mixed)."""

    def test_hexadecimal_secret_detection(self):
        # 32-character hex API key (entropy ~3.58 >= 3.0, len 32 >= 24)
        hex32 = "e3b0c44298fc1c149afbf4c8996fb924"
        self.assertTrue(is_adaptive_high_entropy_secret(hex32))
        hex_code = f'api_key = "{hex32}"'
        secrets = find_high_entropy_secrets_ast(hex_code)
        self.assertIn(hex32, secrets)

        # 64-character hex secret (e.g. HMAC secret or SHA-256 key)
        hex64 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
        self.assertTrue(is_adaptive_high_entropy_secret(hex64))
        hex64_code = f'auth_secret = "{hex64}"'
        secrets64 = find_high_entropy_secrets_ast(hex64_code)
        self.assertIn(hex64, secrets64)

        # Regex fallback for hex
        regex_secrets = find_high_entropy_secrets_regex(hex_code)
        self.assertIn(hex32, regex_secrets)

    def test_hexadecimal_negative_cases(self):
        # Negative check: short hex string (< 24 chars) should NOT be flagged
        short_hex = "a1b2c3d4e5f60718"
        self.assertFalse(is_adaptive_high_entropy_secret(short_hex))
        self.assertEqual(find_high_entropy_secrets_ast(f'commit_key = "{short_hex}"'), [])

        # Negative check: low-entropy hex (repeated chars, entropy < 3.0) should NOT be flagged
        low_entropy_hex = "000000000000000000000000"
        self.assertFalse(is_adaptive_high_entropy_secret(low_entropy_hex))
        self.assertEqual(find_high_entropy_secrets_ast(f'dummy_secret = "{low_entropy_hex}"'), [])

    def test_mixed_high_entropy_ast_detection(self):
        code = '''
api_token = "dF4!kL9#mP2$vR8@wQ1%zX7^bN3&cJ5*tH6~"
low_key = "password1234567890"
dev_secret = "development_secret_key_for_testing"
short_key = "abc123"
'''
        secrets = find_high_entropy_secrets_ast(code)
        self.assertIn("dF4!kL9#mP2$vR8@wQ1%zX7^bN3&cJ5*tH6~", secrets)
        self.assertNotIn("password1234567890", secrets)
        self.assertNotIn("development_secret_key_for_testing", secrets)
        self.assertNotIn("abc123", secrets)

    def test_mixed_high_entropy_regex_fallback(self):
        code = 'secret_auth="xK9$mP2!vR8#wQ1%zX7^bN3&cJ5*tH6~"'
        secrets = find_high_entropy_secrets_regex(code)
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0], "xK9$mP2!vR8#wQ1%zX7^bN3&cJ5*tH6~")


class TestSecretVaultReversible(unittest.TestCase):
    """Test SecretVault two-way reversible redaction, determinism, and restoration integrity."""

    def test_empty_and_none(self):
        self.assertEqual(SecretVault.redact(""), ("", {}))
        self.assertEqual(SecretVault.restore("", {}), "")

    def test_code_without_secrets(self):
        code = """
def calculate_area(width, height):
    return width * height
"""
        redacted, vmap = SecretVault.redact(code)
        self.assertEqual(redacted, code)
        self.assertEqual(len(vmap), 0)
        restored = SecretVault.restore(redacted, vmap)
        self.assertEqual(restored, code)

    def test_deterministic_token_generation(self):
        code = f'''
AWS_KEY = "{_SYNTHETIC_AWS_KEY}"
STRIPE_KEY = "{_SYNTHETIC_STRIPE_LIVE}"
AUTH_TOKEN = "e3b0c44298fc1c149afbf4c8996fb924"
'''
        redacted1, vmap1 = SecretVault.redact(code)
        redacted2, vmap2 = SecretVault.redact(code)

        # 1. Exact string identity across calls (100% deterministic)
        self.assertEqual(redacted1, redacted2)
        self.assertEqual(vmap1, vmap2)

        # 2. SHA-256 hash identity across calls
        hash1 = hashlib.sha256(redacted1.encode("utf-8")).hexdigest()
        hash2 = hashlib.sha256(redacted2.encode("utf-8")).hexdigest()
        self.assertEqual(hash1, hash2)

        # 3. Check sequential token format f"__TCS_VAULT_TOKEN_{idx}__"
        self.assertIn("__TCS_VAULT_TOKEN_1__", redacted1)
        self.assertIn("__TCS_VAULT_TOKEN_2__", redacted1)
        self.assertIn("__TCS_VAULT_TOKEN_3__", redacted1)

        # 4. Check order of appearance in file
        self.assertEqual(vmap1["__TCS_VAULT_TOKEN_1__"], _SYNTHETIC_AWS_KEY)
        self.assertEqual(vmap1["__TCS_VAULT_TOKEN_2__"], _SYNTHETIC_STRIPE_LIVE)
        self.assertEqual(vmap1["__TCS_VAULT_TOKEN_3__"], "e3b0c44298fc1c149afbf4c8996fb924")

    def test_restoration_integrity_verification(self):
        vault_map = {
            "__TCS_VAULT_TOKEN_1__": "my_secret_key_1",
            "__TCS_VAULT_TOKEN_2__": "my_secret_key_2",
        }
        # Case 1: An unreplaced/residual token remains in code
        mangled_code = "KEY_1 = my_secret_key_1\nKEY_2 = __TCS_VAULT_TOKEN_99__"

        # Must raise VaultRestorationError (inherits from ValueError & RuntimeError)
        with self.assertRaises((VaultRestorationError, ValueError, RuntimeError)):
            SecretVault.restore(mangled_code, vault_map)

        # Safe fallback with fallback_on_error=True
        fallback_restored = SecretVault.restore(mangled_code, vault_map, fallback_on_error=True)
        self.assertIn("__TCS_VAULT_TOKEN_99__", fallback_restored)

    def test_full_roundtrip_all_providers(self):
        original_code = f'''import os

AWS_KEY = "{_SYNTHETIC_AWS_KEY}"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_GHP = "{_SYNTHETIC_GHP}"
GITHUB_PAT = "{_SYNTHETIC_PAT}"
STRIPE_KEY = "{_SYNTHETIC_STRIPE_LIVE}"
SLACK_TOKEN = "{_SYNTHETIC_SLACK}"
GOOGLE_KEY = "{_SYNTHETIC_GOOGLE}"
HEX_SECRET = "e3b0c44298fc1c149afbf4c8996fb924"
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1+r...
-----END RSA PRIVATE KEY-----"""
CUSTOM_AUTH_SECRET = "dF4!kL9#mP2$vR8@wQ1%zX7^bN3&cJ5*tH6~"

# These should NOT be redacted (low entropy or non-secrets)
LOW_ENTROPY_PASS = "password1234567890"
LOW_ENTROPY_CONF = "development_secret_key_for_testing"

def get_status():
    return "OK"
'''
        redacted, vmap = SecretVault.redact(original_code)

        # 1. Verify secrets were detected and vaulted (all 9 providers + hex + high entropy)
        self.assertGreaterEqual(len(vmap), 9)
        for token in vmap:
            self.assertTrue(token.startswith("__TCS_VAULT_TOKEN_"))
            self.assertTrue(token.endswith("__"))
            self.assertIn(token, redacted)

        # 2. Verify raw secrets are absent from redacted code
        self.assertNotIn(_SYNTHETIC_AWS_KEY, redacted)
        self.assertNotIn("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", redacted)
        self.assertNotIn(_SYNTHETIC_GHP, redacted)
        self.assertNotIn(_SYNTHETIC_STRIPE_LIVE, redacted)
        self.assertNotIn(_SYNTHETIC_SLACK, redacted)
        self.assertNotIn(_SYNTHETIC_GOOGLE, redacted)
        self.assertNotIn("e3b0c44298fc1c149afbf4c8996fb924", redacted)
        self.assertNotIn("-----BEGIN RSA PRIVATE KEY-----", redacted)
        self.assertNotIn("dF4!kL9#mP2$vR8@wQ1%zX7^bN3&cJ5*tH6~", redacted)

        # 3. Verify low-entropy strings remain untouched
        self.assertIn("password1234567890", redacted)
        self.assertIn("development_secret_key_for_testing", redacted)

        # 4. Verify 100% LOSSLESS ROUNDTRIP RESTORATION
        restored = SecretVault.restore(redacted, vmap)
        self.assertEqual(restored, original_code)
        self.assertNotIn("__TCS_VAULT_TOKEN_", restored)

    def test_instance_methods(self):
        vault = SecretVault()
        code = f'key = "{_SYNTHETIC_AWS_KEY}"'
        redacted = vault.redact_code(code)
        self.assertIn("__TCS_VAULT_TOKEN_1__", redacted)
        restored = vault.restore_code(redacted)
        self.assertEqual(restored, code)


class TestAppIntegration(unittest.TestCase):
    """Verify integration of SecretVault and SECRET_PATTERNS with app.py."""

    def test_apply_zero_leak_redaction_with_vault(self):
        from app import apply_zero_leak_redaction
        code = f'''
aws_key = "{_SYNTHETIC_AWS_KEY}"
stripe_key = "{_SYNTHETIC_STRIPE_LIVE}"
hex_key = "e3b0c44298fc1c149afbf4c8996fb924"
high_entropy_secret = "mZ9#pL2!vR8$wQ1%zX7^bN3&cJ5*tH6~"
'''
        redacted, found = apply_zero_leak_redaction(code)
        self.assertTrue(found)
        self.assertNotIn(_SYNTHETIC_AWS_KEY, redacted)
        self.assertNotIn(_SYNTHETIC_STRIPE_LIVE, redacted)
        self.assertNotIn("e3b0c44298fc1c149afbf4c8996fb924", redacted)
        self.assertNotIn("mZ9#pL2!vR8$wQ1%zX7^bN3&cJ5*tH6~", redacted)
        self.assertIn("***REDACTED_BY_TIMECODESECURITY***", redacted)

    def test_app_scan_cache_hash_determinism(self):
        from app import SecretVault
        code = f'''
api_key = "{_SYNTHETIC_AWS_KEY}"
db_pass = "e3b0c44298fc1c149afbf4c8996fb924"
'''
        v1, _ = SecretVault.redact(code)
        v2, _ = SecretVault.redact(code)
        self.assertEqual(v1, v2)
        h1 = hashlib.sha256(v1.encode()).hexdigest()
        h2 = hashlib.sha256(v2.encode()).hexdigest()
        self.assertEqual(h1, h2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
