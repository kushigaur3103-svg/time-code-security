"""Unit and integration test suite for Phase 12 Step 2 - False-Positive Filters.

Verifies:
- Network isolation (socket.connect blocked)
- PathFilter: test paths, fixtures, vendor exclusions
- TemplateFilter: .env.example, sample files, markdown exclusions
- Production retention: src/config.py, app/main.py
- DummyValueFilter: AKIA0000000000000000, dummy_token, fake_key
- ContextFilter: mock.patch, @patch, pytest.fixture
- AllowlistFilter: masked value and file:line matching
- FilterResult audit tracking (retained vs suppressed)
- Zero cleartext secret leakage in rejection logs and audit structures
- Non-destructive retention of SecretFinding attributes
- Module isolation (zero SAST/SCA engine imports)
- 50-iteration determinism verification
"""

import dataclasses
import os
import socket
import sys
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

from secret_scanner import SecretFinding, scan_text
from secret_filters import (
    FilterConfig,
    FilterResult,
    SuppressedFinding,
    filter_findings,
    evaluate_findings,
)


class TestPathFilter(unittest.TestCase):
    """Test file path and directory exclusions."""

    def setUp(self):
        # A realistic synthetic finding
        self.code = 'GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
        self.findings = scan_text(self.code, filename="dummy.py")
        self.assertEqual(len(self.findings), 1)

    def test_default_ignored_extensions_exact_value(self):
        config = FilterConfig()
        expected = (".md", ".rst", ".example", ".sample")
        self.assertEqual(config.ignored_extensions, expected)
        self.assertNotIn(".txt", config.ignored_extensions)

    def test_test_directories_suppressed(self):
        test_paths = [
            "tests/test_auth.py",
            "test/test_api.py",
            "spec/models/user_spec.rb",
            "fixtures/auth_fixtures.py",
            "mock/service_mock.py",
            "vendor/bundle/oauth.py",
            "src/tests/unit/test_keys.py",
            "c:\\project\\tests\\test_login.py",
            "./test/sub/check.py",
        ]
        for path in test_paths:
            res = evaluate_findings(self.findings, file_path=path)
            self.assertEqual(len(res.retained), 0, f"Expected 0 retained for {path}")
            self.assertEqual(len(res.suppressed), 1, f"Expected 1 suppressed for {path}")
            self.assertEqual(res.suppressed[0].filter_name, "PathFilter")
            self.assertEqual(res.suppressed[0].reason, "ignored_path")

    def test_template_and_sample_files_suppressed(self):
        template_paths = [
            ".env.example",
            ".env.sample",
            ".env.template",
            ".env.test",
            "config/sample.env",
            "docker-compose.test.yml",
        ]
        for path in template_paths:
            res = evaluate_findings(self.findings, file_path=path)
            self.assertEqual(len(res.retained), 0, f"Expected 0 retained for {path}")
            self.assertEqual(len(res.suppressed), 1)
            self.assertEqual(res.suppressed[0].reason, "ignored_filename")

    def test_documentation_files_suppressed(self):
        # Explicit CTO negative tests: README.md, docs/index.rst, .env.example
        doc_paths = ["README.md", "docs/index.rst", ".env.example"]
        for path in doc_paths:
            res = evaluate_findings(self.findings, file_path=path)
            self.assertEqual(len(res.retained), 0, f"Expected 0 retained for {path}")
            self.assertEqual(len(res.suppressed), 1, f"Expected 1 suppressed for {path}")
            self.assertIn(res.suppressed[0].reason, ("ignored_extension", "ignored_path", "ignored_filename"))

    def test_config_txt_retained(self):
        # Explicit CTO regression test: valid synthetic secret in config.txt MUST be RETAINED
        retained = filter_findings(self.findings, file_path="config.txt")
        self.assertEqual(len(retained), 1, "Expected config.txt finding to be RETAINED")
        self.assertEqual(retained[0], self.findings[0])

    def test_production_paths_retained(self):
        prod_paths = [
            "config.txt",
            "src/config.py",
            "app/main.py",
            "services/payment_gateway.py",
            "backend/auth/jwt_handler.py",
            "settings/production.py",
        ]
        for path in prod_paths:
            retained = filter_findings(self.findings, file_path=path)
            self.assertEqual(len(retained), 1, f"Expected retained for {path}")
            self.assertEqual(retained[0], self.findings[0])


class TestDummyValueFilter(unittest.TestCase):
    """Test placeholder, repetitive, and dummy token filtering."""

    def test_repeating_dummy_aws_key_suppressed(self):
        # AKIA with repetitive dummy suffix
        code = 'AWS_KEY = "AKIA0000000000000000"'
        findings = scan_text(code, filename="src/aws.py")
        self.assertEqual(len(findings), 1)
        res = evaluate_findings(findings, file_path="src/aws.py")
        self.assertEqual(len(res.retained), 0)
        self.assertEqual(len(res.suppressed), 1)
        self.assertEqual(res.suppressed[0].filter_name, "DummyValueFilter")
        self.assertEqual(res.suppressed[0].reason, "dummy_or_placeholder_value")

    def test_dummy_variable_name_in_context_suppressed(self):
        code = 'dummy_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
        findings = scan_text(code, filename="src/api.py")
        self.assertEqual(len(findings), 1)
        res = evaluate_findings(findings, file_path="src/api.py")
        self.assertEqual(len(res.retained), 0)
        self.assertEqual(len(res.suppressed), 1)
        self.assertEqual(res.suppressed[0].filter_name, "DummyValueFilter")

    def test_fake_keyword_in_comment_suppressed(self):
        code = 'KEY = "AKIA1234567890ABCD"  # fake test token'
        findings = scan_text(code, filename="src/creds.py")
        self.assertEqual(len(findings), 1)
        res = evaluate_findings(findings, file_path="src/creds.py")
        self.assertEqual(len(res.retained), 0)
        self.assertEqual(len(res.suppressed), 1)
        self.assertEqual(res.suppressed[0].reason, "dummy_or_placeholder_value")

    def test_high_confidence_production_token_retained(self):
        code = 'AWS_ACCESS_KEY_ID = "AKIA1234567890ABCD"'
        findings = scan_text(code, filename="src/config.py")
        self.assertEqual(len(findings), 1)
        res = evaluate_findings(findings, file_path="src/config.py")
        self.assertEqual(len(res.retained), 1)
        self.assertEqual(len(res.suppressed), 0)


class TestContextFilter(unittest.TestCase):
    """Test test fixture and mocking context suppression."""

    def test_mock_patch_context_suppressed(self):
        code = '@mock.patch("auth.service", api_key="ghp_1234567890abcdefghijklmnopqrstuvwxyz")'
        findings = scan_text(code, filename="src/worker.py")
        self.assertEqual(len(findings), 1)
        res = evaluate_findings(findings, file_path="src/worker.py")
        self.assertEqual(len(res.retained), 0)
        self.assertEqual(len(res.suppressed), 1)
        self.assertEqual(res.suppressed[0].filter_name, "ContextFilter")
        self.assertEqual(res.suppressed[0].reason, "mocking_or_test_fixture")

    def test_pytest_fixture_context_suppressed(self):
        code = '@pytest.fixture(params=["ghp_1234567890abcdefghijklmnopqrstuvwxyz"])'
        findings = scan_text(code, filename="src/fixtures.py")
        self.assertEqual(len(findings), 1)
        res = evaluate_findings(findings, file_path="src/fixtures.py")
        self.assertEqual(len(res.retained), 0)
        self.assertEqual(len(res.suppressed), 1)
        self.assertEqual(res.suppressed[0].filter_name, "ContextFilter")

    def test_pytest_fixture_decorator_on_preceding_line(self):
        import tempfile
        content = '@pytest.fixture\ndef auth_token():\n    return "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n'
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as tf:
            tf.write(content)
            temp_path = tf.name

        try:
            from secret_scanner import scan_file
            findings = scan_file(temp_path)
            self.assertEqual(len(findings), 1)
            res = evaluate_findings(findings, file_path=temp_path)
            self.assertEqual(len(res.retained), 0)
            self.assertEqual(len(res.suppressed), 1)
            self.assertEqual(res.suppressed[0].filter_name, "ContextFilter")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


class TestAllowlistFilter(unittest.TestCase):
    """Test explicit allowlisting by signature and location."""

    def test_allowlist_by_masked_value(self):
        code = 'AWS_KEY = "AKIA1234567890ABCD"'
        findings = scan_text(code, filename="src/auth.py")
        self.assertEqual(len(findings), 1)
        target_masked = findings[0].masked_value

        config = FilterConfig(allowlisted_entries={target_masked})
        res = evaluate_findings(findings, file_path="src/auth.py", config=config)
        self.assertEqual(len(res.retained), 0)
        self.assertEqual(len(res.suppressed), 1)
        self.assertEqual(res.suppressed[0].filter_name, "AllowlistFilter")
        self.assertEqual(res.suppressed[0].reason, "allowlisted")

    def test_allowlist_by_location(self):
        code = 'AWS_KEY = "AKIA1234567890ABCD"'
        findings = scan_text(code, filename="src/auth.py")
        self.assertEqual(len(findings), 1)

        config = FilterConfig(allowlisted_entries={"src/auth.py:1"})
        res = evaluate_findings(findings, file_path="src/auth.py", config=config)
        self.assertEqual(len(res.retained), 0)
        self.assertEqual(len(res.suppressed), 1)
        self.assertEqual(res.suppressed[0].filter_name, "AllowlistFilter")

    def test_non_allowlisted_token_retained(self):
        code = 'AWS_KEY = "AKIA1234567890ABCD"'
        findings = scan_text(code, filename="src/auth.py")
        config = FilterConfig(allowlisted_entries={"other/file.py:10"})
        res = evaluate_findings(findings, file_path="src/auth.py", config=config)
        self.assertEqual(len(res.retained), 1)
        self.assertEqual(len(res.suppressed), 0)


class TestZeroLeakageAndNonDestructive(unittest.TestCase):
    """Verify zero raw secret exposure and data integrity."""

    def test_zero_leakage_in_filter_structures(self):
        raw_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        code = f'token = "{raw_token}"  # dummy test'
        findings = scan_text(code, filename="src/test.py")
        self.assertEqual(len(findings), 1)

        res = evaluate_findings(findings, file_path="src/test.py")
        self.assertEqual(len(res.suppressed), 1)
        supp = res.suppressed[0]

        # Verify raw secret is nowhere in SuppressedFinding or FilterResult
        self.assertNotIn(raw_token, supp.reason)
        self.assertNotIn(raw_token, supp.filter_name)
        self.assertNotIn(raw_token, repr(supp))
        self.assertNotIn(raw_token, str(supp))
        self.assertNotIn(raw_token, repr(res))

    def test_non_destructive_retained_findings(self):
        code = 'AWS_KEY = "AKIA1234567890ABCD"'
        orig_findings = scan_text(code, filename="src/prod.py")
        self.assertEqual(len(orig_findings), 1)
        orig = orig_findings[0]

        retained = filter_findings(orig_findings, file_path="src/prod.py")
        self.assertEqual(len(retained), 1)
        ret = retained[0]

        self.assertEqual(ret.secret_type, orig.secret_type)
        self.assertEqual(ret.masked_value, orig.masked_value)
        self.assertEqual(ret.file, orig.file)
        self.assertEqual(ret.line_number, orig.line_number)
        self.assertEqual(ret.column_start, orig.column_start)
        self.assertEqual(ret.column_end, orig.column_end)
        self.assertEqual(ret.confidence, orig.confidence)
        self.assertEqual(ret.detector, orig.detector)
        self.assertEqual(ret.context, orig.context)


class TestIsolationAndDeterminism(unittest.TestCase):
    """Verify module isolation and determinism."""

    def test_module_isolation(self):
        forbidden = {
            "ast_scanner",
            "rule_engine",
            "suppression_resolver",
            "manifest_parser",
            "osv_client",
            "version_matcher",
            "tcs_cli",
            "sarif_adapter",
            "app",
        }
        loaded = set(sys.modules.keys())
        overlap = forbidden.intersection(loaded)
        self.assertEqual(overlap, set(), f"Forbidden modules loaded: {overlap}")

    def test_determinism_50_iterations(self):
        code = """
        # Prod file
        GITHUB = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        DUMMY = "AKIA0000000000000000"
        REAL_AWS = "AKIA1234567890ABCD"
        """
        findings = scan_text(code, filename="src/config.py")
        self.assertEqual(len(findings), 3)

        baseline = evaluate_findings(findings, file_path="src/config.py")
        self.assertEqual(len(baseline.retained), 2)
        self.assertEqual(len(baseline.suppressed), 1)

        for _ in range(50):
            current = evaluate_findings(findings, file_path="src/config.py")
            self.assertEqual(baseline, current)


class TestComprehensiveScenarios(unittest.TestCase):
    """Test mixed scenarios, configuration toggles, and edge cases."""

    def test_empty_findings_list(self):
        res = evaluate_findings([], file_path="src/app.py")
        self.assertEqual(res.retained, [])
        self.assertEqual(res.suppressed, [])

    def test_mixed_file_multi_filter_suppression(self):
        code = """
        AWS_KEY = "AKIA1234567890ABCD"
        DUMMY_KEY = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        MOCK_TOKEN = "xoxb-123456789012-abcdefghij"  # mock.patch
        ALLOWED_KEY = "AKIA1234567890WXYZ"
        """
        findings = scan_text(code, filename="src/mixed.py")
        self.assertEqual(len(findings), 4)

        # Allowlist the 4th finding by location
        config = FilterConfig(allowlisted_entries={"src/mixed.py:5"})
        res = evaluate_findings(findings, file_path="src/mixed.py", config=config)

        # Retained: only finding 1 (AWS_KEY)
        self.assertEqual(len(res.retained), 1)
        self.assertEqual(res.retained[0].secret_type, "aws_access_key")

        # Suppressed: 3 findings
        self.assertEqual(len(res.suppressed), 3)
        reasons = {s.reason for s in res.suppressed}
        self.assertIn("dummy_or_placeholder_value", reasons)
        self.assertIn("mocking_or_test_fixture", reasons)
        self.assertIn("allowlisted", reasons)

    def test_config_toggles_disable_filters(self):
        code = 'dummy_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
        findings = scan_text(code, filename="tests/test_api.py")
        self.assertEqual(len(findings), 1)

        # If we disable test path ignoring and dummy ignoring
        config = FilterConfig(ignore_test_paths=False, ignore_dummies=False)
        res = evaluate_findings(findings, file_path="tests/test_api.py", config=config)
        self.assertEqual(len(res.retained), 1)
        self.assertEqual(len(res.suppressed), 0)

    def test_all_secret_types_retained_in_prod(self):
        code = """
        -----BEGIN RSA PRIVATE KEY-----
        ghp_1234567890abcdefghijklmnopqrstuvwxyz
        xoxb-123456789012-abcdefghij
        AKIA1234567890ABCD
        postgres://user:super_secret_pw@localhost:5432/mydb
        """
        findings = scan_text(code, filename="src/credentials.py")
        self.assertEqual(len(findings), 5)

        res = evaluate_findings(findings, file_path="src/credentials.py")
        self.assertEqual(len(res.retained), 5)
        self.assertEqual(len(res.suppressed), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
