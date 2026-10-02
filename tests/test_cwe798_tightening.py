"""Phase 8.5: CWE-798 False Positive Elimination & Dummy String Blocklist.

Covers:
  1. Function default argument password detection (legitimate TPs)
  2. Module-level assignment suppression for test placeholders
  3. Dummy string blocklist (repeated chars, test strings, etc.)

Each test asserts vulnerable shapes FIRE and safe/dummy shapes stay SILENT.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ast_scanner import TaintTracker


def _cwes_at(code: str, line: int) -> set[str]:
    """Run TaintTracker on a snippet and return CWEs at the given line."""
    tracker = TaintTracker(files={"snippet.py": code})
    sources, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    cwes: set[str] = set()
    for edge in edges:
        sink = by_id.get(edge.target_id)
        if sink is None:
            continue
        loc = sink.location
        if loc.line_start == line:
            cwe = (sink.metadata or {}).get("cwe")
            if cwe:
                cwes.add(cwe)
    return cwes


def _fires(code: str, line: int, expected_cwe: str) -> None:
    cwes = _cwes_at(code, line)
    assert expected_cwe in cwes, f"Expected {expected_cwe} at line {line}, got {cwes}"


def _silent(code: str, line: int, expected_cwe: str) -> None:
    cwes = _cwes_at(code, line)
    assert expected_cwe not in cwes, f"Unexpected {expected_cwe} at line {line}, got {cwes}"


# ─── 1. Positive cases: legitimate hardcoded passwords in function defaults ──

class TestFunctionDefaultPasswords:
    def test_def_password_with_secret(self):
        _fires('def authenticate(user, password="secret_pass_123"):\n    pass\n', 1, "CWE-798")

    def test_def_passwd_hardcoded(self):
        _fires('def connect(host, passwd="admin123"):\n    pass\n', 1, "CWE-798")

    def test_def_api_key_literal(self):
        _fires('def call_service(api_key="sk_live_abc123xyz"):\n    pass\n', 1, "CWE-798")


# ─── 2. Negative guards: test placeholders and dummy strings ─────────────────

class TestDummyStringSuppression:
    def test_module_level_test_placeholder(self):
        # From hardcoded-password-default-argument.py line 2
        _silent('password = "this-is-probably-a-test"\n', 1, "CWE-798")

    def test_repeated_x_chars(self):
        _silent('api_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n', 1, "CWE-798")

    def test_repeated_zero_chars(self):
        _silent('token = "0000000000000000"\n', 1, "CWE-798")

    def test_your_placeholder_pattern(self):
        _silent('secret = "<your-secret-here>"\n', 1, "CWE-798")

    def test_this_is_not_a_key(self):
        _silent('api_key = "this-is-not-a-key"\n', 1, "CWE-798")

    def test_empty_string_silent(self):
        _silent('password = ""\n', 1, "CWE-798")

    def test_short_string_silent(self):
        # Less than 8 characters
        _silent('password = "short"\n', 1, "CWE-798")


# ─── 3. Preserve legitimate high-entropy credentials ─────────────────────────

class TestLegitimateCredentials:
    def test_realistic_password(self):
        _fires('db_password = "SuperS3cret!@#2024"\n', 1, "CWE-798")


# ─── 4. Corpus regression guard ──────────────────────────────────────────────

class TestCorpusRegression:
    def test_hardcoded_password_default_argument_file(self):
        """Ensure only line 15 (function default) is flagged, not line 2 (module assignment)."""
        with open('external/semgrep_rules_python/python/lang/security/audit/hardcoded-password-default-argument.py', 'r') as f:
            code = f.read()

        tracker = TaintTracker(files={'test.py': code})
        sources, sinks, edges = tracker.analyze()

        # Should have exactly 1 finding on line 15
        line_15_findings = [s for s in sinks if s.location.line_start == 15]
        assert len(line_15_findings) == 1, f"Expected 1 finding on line 15, got {len(line_15_findings)}"

        # Should have NO findings on line 2
        line_2_findings = [s for s in sinks if s.location.line_start == 2]
        assert len(line_2_findings) == 0, f"Expected 0 findings on line 2, got {len(line_2_findings)}: FP not fixed!"
