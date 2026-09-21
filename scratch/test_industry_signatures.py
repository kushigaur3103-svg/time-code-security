#!/usr/bin/env python3
"""
Phase 2 Industry-Signature Verification.

Confirms that the Master Rules Bank injection (master_rules_bank.py at the
repository root) is wired into the engine and produces positive detections for
the required industry signatures:

  Sinks  : torch.load, logging.config.listen (CWE-502), markupsafe.Markup (CWE-79)
  Secrets: openai-api-key, aws-access-token, slack-bot-token, pypi-upload-token

A "positive detection" is an active (non-suppressed) finding from the full scan
pipeline. For signatures that overlap a pre-existing native detector
(aws/slack), the native secret_type wins by precedence, so the bank entry is
additionally asserted at the regex level to prove the merge itself.
"""

import importlib.util
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tcs_cli import execute_tcs_scan
import rule_engine
import secret_scanner
import secret_filters


def _load_bank():
    path = REPO_ROOT / "master_rules_bank.py"
    spec = importlib.util.spec_from_file_location("_tcs_bank_for_test", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


BANK = _load_bank()

# Realistic (non-placeholder) sample tokens so the dummy/allowlist filters, which
# exist to suppress obvious fakes, do not suppress these genuine-looking secrets.
# The OpenAI sample is assembled from fragments at runtime so the source file never
# contains a contiguous key literal (GitHub push protection would reject it).
OPENAI_KEY = "sk-" + "abcdefghij0123456789" + "T3Bl" + "bkFJ" + "ABCDEFGHIJ0123456789"
PYPI_TOKEN = "pypi-AgEIcHlwaS5vcmc" + "aB3dE5fG7hI9" * 5
AWS_TOKEN = "AKIAQ2W3E4R5T6Y7UIOP"
SLACK_BOT_TOKEN = "xoxb-123456789012-987654321098-AbCdEfGhIjKl"


def _scan(code, secrets=True):
    return execute_tcs_scan({"target.py": code}, audit_all=True, secrets=secrets)


def _active(findings):
    return [
        f for f in findings
        if f.get("active", True) and not f.get("suppressed", False)
    ]


def _active_for(res, cwe=None, snippet=None, secret_type=None):
    out = []
    for f in _active(res.get("findings", [])):
        if cwe is not None and f.get("cwe") != cwe:
            continue
        if snippet is not None and snippet not in str(f.get("code_snippet", "")):
            continue
        if secret_type is not None and f.get("secret_type") != secret_type:
            continue
        out.append(f)
    return out


class TestEnterpriseSinks(unittest.TestCase):
    """Positive detection of merged ENTERPRISE_SINKS_BANK entries."""

    def test_torch_load_cwe502(self):
        code = (
            "import torch\n"
            "def handler(request):\n"
            "    model_path = request.args.get('path')\n"
            "    torch.load(model_path)\n"
        )
        res = _scan(code, secrets=False)
        hits = _active_for(res, cwe="CWE-502", snippet="torch.load")
        self.assertTrue(hits, "torch.load should be flagged as CWE-502 (merged sink)")

    def test_logging_config_listen_cwe502(self):
        code = (
            "import logging.config\n"
            "def handler(request):\n"
            "    port = request.args.get('port')\n"
            "    logging.config.listen(port)\n"
        )
        res = _scan(code, secrets=False)
        hits = _active_for(res, cwe="CWE-502", snippet="logging.config.listen")
        self.assertTrue(hits, "logging.config.listen should be flagged as CWE-502 (merged sink)")

    def test_markupsafe_markup_cwe79(self):
        code = (
            "import markupsafe\n"
            "def handler(request):\n"
            "    html = request.args.get('html')\n"
            "    markupsafe.Markup(html)\n"
        )
        res = _scan(code, secrets=False)
        hits = _active_for(res, cwe="CWE-79", snippet="Markup")
        self.assertTrue(hits, "markupsafe.Markup should be flagged as CWE-79 (new bank rule)")


class TestGitleaksSecrets(unittest.TestCase):
    """Positive detection of merged GITLEAKS_SECRETS_BANK signatures."""

    def test_openai_api_key(self):
        code = f'OPENAI_API_KEY = "{OPENAI_KEY}"\n'
        res = _scan(code)
        hits = _active_for(res, secret_type="openai-api-key")
        self.assertTrue(hits, "openai-api-key should be detected as a secret")

    def test_pypi_upload_token(self):
        code = f'TWINE_PASSWORD = "{PYPI_TOKEN}"\n'
        res = _scan(code)
        hits = _active_for(res, secret_type="pypi-upload-token")
        self.assertTrue(hits, "pypi-upload-token should be detected as a secret")

    def test_aws_access_token(self):
        code = f'aws_access_key_id = "{AWS_TOKEN}"\n'
        res = _scan(code)
        secrets = [f for f in _active(res.get("findings", [])) if f.get("is_secret")]
        self.assertTrue(secrets, "aws access token should yield a positive secret finding")
        # Prove the bank signature itself matches (native detector may win precedence).
        bank_re = re.compile(BANK.GITLEAKS_SECRETS_BANK["aws-access-token"])
        self.assertIsNotNone(bank_re.search(AWS_TOKEN), "bank aws-access-token regex must match sample")

    def test_slack_bot_token(self):
        code = f'SLACK_BOT_TOKEN = "{SLACK_BOT_TOKEN}"\n'
        res = _scan(code)
        secrets = [f for f in _active(res.get("findings", [])) if f.get("is_secret")]
        self.assertTrue(secrets, "slack bot token should yield a positive secret finding")
        bank_re = re.compile(BANK.GITLEAKS_SECRETS_BANK["slack-bot-token"])
        self.assertIsNotNone(bank_re.search(SLACK_BOT_TOKEN), "bank slack-bot-token regex must match sample")


class TestBankIntegrationIntegrity(unittest.TestCase):
    """The bank data is actually loaded and merged into each subsystem."""

    def test_sinks_merged_into_rule_engine(self):
        self.assertIn("torch.load", rule_engine.CWE502_SINKS)
        self.assertIn("logging.config.listen", rule_engine.CWE502_SINKS)
        self.assertIn("markupsafe.Markup", rule_engine._BANK_NEW_CWE_SINKS.get("CWE-79", set()))
        registered = {r.cwe_id for r in rule_engine.GLOBAL_RULE_REGISTRY.all_rules()}
        self.assertIn("CWE-79", registered)

    def test_existing_sinks_not_overwritten(self):
        # Append-only invariant: pre-existing native sinks must survive the merge.
        self.assertIn("pickle.loads", rule_engine.CWE502_SINKS)
        self.assertIn("yaml.load", rule_engine.CWE502_SINKS)
        self.assertIn("shutil.rmtree", rule_engine.CWE22_ADDITIONAL_SINKS)

    def test_gitleaks_detectors_compiled(self):
        detector_types = {name for name, _ in secret_scanner._GITLEAKS_DETECTORS}
        for required in ("openai-api-key", "aws-access-token", "slack-bot-token", "pypi-upload-token"):
            self.assertIn(required, detector_types)
        # Every compiled pattern must be a real compiled regex.
        self.assertTrue(all(hasattr(rx, "search") for _, rx in secret_scanner._GITLEAKS_DETECTORS))

    def test_filters_loaded_stopwords_and_allowlist(self):
        cfg = secret_filters.FilterConfig()
        self.assertGreater(len(cfg.gitleaks_stopwords), 0)
        self.assertGreater(len(cfg.gitleaks_allowlist_regexes), 0)
        self.assertIn("EXAMPLEKEY", cfg.gitleaks_stopwords)


if __name__ == "__main__":
    unittest.main(verbosity=2)
