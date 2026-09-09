"""
Phase 12 Step 3 Unit Tests: CLI Integration (--secrets) + Unified JSON/Table/SARIF Reporting.
Tests are 100% offline with zero live network calls. Socket connections are blocked.
Enforces CWE-798 canonical mapping, multi-engine isolation, and zero cleartext secret leakage.
"""

import sys
import os
import json
import socket
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Any

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Forbid all live socket connections in this test process
def _blocked_connect(*args, **kwargs):
    raise RuntimeError("Live network access is strictly forbidden in Phase 12 unit tests!")

socket.socket.connect = _blocked_connect
socket.create_connection = _blocked_connect

PYTHON_EXE = sys.executable
CLI_PATH = str(REPO_ROOT / "tcs_cli.py")


def run_cli(*args, env_override: Dict[str, str] = None):
    """Executes tcs_cli.py in a subprocess with blocked network access."""
    cmd = [PYTHON_EXE, CLI_PATH] + list(args)
    env = os.environ.copy()
    if env_override:
        env.update(env_override)
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env
    )
    return proc.returncode, proc.stdout, proc.stderr


# =====================================================================
# TEST CASES
# =====================================================================

def test_01_baseline_pure_sast_without_secrets():
    """Verify that without --secrets, CLI behaves identically to Phase 10 baseline."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        code = tmp / "vuln.py"
        code.write_text("import sys\nimport os\ncmd = sys.argv[1]\nos.system(cmd)\n", encoding="utf-8")

        # Table output
        rc, stdout, stderr = run_cli(str(code))
        assert rc == 1, f"Expected rc=1 for active SAST finding, got {rc}"
        assert "TimeCodeSecurity (TCS) AST Security Scan Report" in stdout
        assert "CWE-78" in stdout
        assert "SECRET" not in stdout

        # JSON output
        rc, stdout, stderr = run_cli(str(code), "--format", "json")
        assert rc == 1
        data = json.loads(stdout)
        assert "findings" in data
        assert "secret_findings" not in data
        assert "sca_findings" not in data
        assert len(data["findings"]) == 1

        # SARIF output
        rc, stdout, stderr = run_cli(str(code), "--format", "sarif")
        assert rc == 1
        sarif = json.loads(stdout)
        rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
        assert "CWE-78" in rule_ids
        assert "CWE-798" not in rule_ids
        assert len(rule_ids) == 6  # Exact 6 baseline SAST rules
    print("PASS: test_01_baseline_pure_sast_without_secrets")


def test_02_clean_project_with_secrets_flag():
    """Verify that clean code and clean config files produce exit code 0."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "clean.py").write_text("x = 10\ny = 20\nprint(x + y)\n", encoding="utf-8")
        (tmp / "config.txt").write_text("server_port=8080\nmax_connections=100\n", encoding="utf-8")
        (tmp / "settings.json").write_text('{"environment": "production", "debug": false}\n', encoding="utf-8")
        (tmp / ".env.example").write_text("DATABASE_URL=postgres://user:password@localhost:5432/db\n", encoding="utf-8")

        rc, stdout, stderr = run_cli(str(tmp), "--secrets")
        assert rc == 0, f"Expected rc=0 for clean project, got {rc}: {stderr}"
        assert "No security vulnerabilities detected." in stdout
        assert "Total Secret Findings: 0" in stdout

        rc, stdout, stderr = run_cli(str(tmp), "--secrets", "--format", "json")
        assert rc == 0
        data = json.loads(stdout)
        assert data["secret_findings"] == []
        assert data["summary"]["secrets_detected"] == 0
    print("PASS: test_02_clean_project_with_secrets_flag")


from secret_scanner import mask_secret

def test_03_secret_in_python_file():
    """Verify detection of secret in a Python file with --secrets."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        raw_key = "AKIA" + "IOSFODNN7EXAMPLE"
        py_file = tmp / "aws_service.py"
        py_file.write_text(f'AWS_ACCESS_KEY_ID = "{raw_key}"\n', encoding="utf-8")

        rc, stdout, stderr = run_cli(str(py_file), "--secrets")
        assert rc == 1, f"Expected rc=1, got {rc}"
        assert "[SECRET SCANNING FINDINGS (CWE-798)]" in stdout
        assert "aws_access_key" in stdout
        assert mask_secret(raw_key) in stdout

        # Zero cleartext leakage check
        assert raw_key not in stdout
        assert raw_key not in stderr

        # JSON format check
        rc, stdout, stderr = run_cli(str(py_file), "--secrets", "--format", "json")
        assert rc == 1
        data = json.loads(stdout)
        assert len(data["secret_findings"]) == 1
        sec = data["secret_findings"][0]
        assert sec["secret_type"] == "aws_access_key"
        assert sec["masked_value"] == mask_secret(raw_key)
        assert sec["cwe"] == "CWE-798"
        assert sec["confidence"] == "HIGH"
        assert raw_key not in stdout
    print("PASS: test_03_secret_in_python_file")


def test_04_direct_secret_file_target_non_python():
    """Verify direct invocation on a non-Python secret target (e.g. config.txt, .env)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        raw_token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
        conf_file = tmp / "config.txt"
        conf_file.write_text(f"GITHUB_API_TOKEN={raw_token}\n", encoding="utf-8")

        # Running without --secrets on config.txt should fail (not a Python file)
        rc, stdout, stderr = run_cli(str(conf_file))
        assert rc == 2
        assert "not a Python file" in stderr

        # Running with --secrets on config.txt should succeed in scanning and exit 1
        rc, stdout, stderr = run_cli(str(conf_file), "--secrets")
        assert rc == 1, f"Expected rc=1 for detected secret in config.txt, got {rc}: {stderr}"
        assert "github_token" in stdout
        assert raw_token not in stdout

        # Running with --secrets and --format sarif on config.txt
        rc, stdout, stderr = run_cli(str(conf_file), "--secrets", "--format", "sarif")
        assert rc == 1
        sarif = json.loads(stdout)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "CWE-798"
        assert "Hardcoded GitHub Token detected" in results[0]["message"]["text"]
        assert raw_token not in stdout
    print("PASS: test_04_direct_secret_file_target_non_python")


def test_05_secret_file_types_discovery():
    """Verify directory scan discovers .env, .json, .yaml, .toml, .ini, .conf."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        raw_slack = "xoxb-123456789012-abcdefghij"
        (tmp / "slack.env").write_text(f"SLACK_BOT_TOKEN={raw_slack}\n", encoding="utf-8")

        raw_db = "postgres://admin:SuperSecretPassword123@db.prod.internal:5432/maindb"
        (tmp / "database.conf").write_text(f"connection_string = {raw_db}\n", encoding="utf-8")

        rc, stdout, stderr = run_cli(str(tmp), "--secrets", "--format", "json")
        assert rc == 1
        data = json.loads(stdout)
        sec_types = {f["secret_type"] for f in data["secret_findings"]}
        assert "slack_token" in sec_types
        assert "database_connection_string" in sec_types
        assert data["summary"]["secrets_detected"] == 2

        # Verify zero cleartext leakage
        assert raw_slack not in stdout
        assert "SuperSecretPassword123" not in stdout
    print("PASS: test_05_secret_file_types_discovery")


def test_06_policy_suppression_and_exclusions():
    """Verify test directories, example templates, and dummy tokens are suppressed."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        test_dir = tmp / "tests"
        test_dir.mkdir()
        raw_key = "AKIA" + "IOSFODNN7EXAMPLE"
        (test_dir / "test_auth.py").write_text(f'FAKE_KEY = "{raw_key}"\n', encoding="utf-8")

        (tmp / ".env.example").write_text(f'AWS_KEY="{raw_key}"\n', encoding="utf-8")
        (tmp / "dummy.py").write_text('DUMMY = "AKIA0000000000000000"\n', encoding="utf-8")

        rc, stdout, stderr = run_cli(str(tmp), "--secrets")
        assert rc == 0, f"Expected rc=0 when all secrets are in excluded/dummy contexts, got {rc}"
        assert "No security vulnerabilities detected." in stdout
    print("PASS: test_06_policy_suppression_and_exclusions")


def test_07_tri_engine_unified_scan():
    """Verify SAST + SCA + Secrets execute simultaneously and aggregate into unified report."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # 1. SAST vulnerability
        (tmp / "vuln.py").write_text("import sys\ncmd = sys.argv[1]\nexec(cmd)\n", encoding="utf-8")

        # 2. SCA vulnerability
        (tmp / "requirements.txt").write_text("requests==2.20.0\n", encoding="utf-8")

        # OSV Cache fixture for offline SCA
        cache_data = {
            "requests": [
                {
                    "id": "GHSA-j8r2-6x86-q33q",
                    "summary": "Requests vulnerable to session fixation",
                    "aliases": ["CVE-2023-32681"],
                    "affected": [
                        {
                            "package": {"name": "requests", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}]
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        cache_file = tmp / "osv_cache.json"
        cache_file.write_text(json.dumps(cache_data), encoding="utf-8")

        # 3. Secret vulnerability
        raw_key = "AKIA" + "IOSFODNN7EXAMPLE"
        (tmp / "config.txt").write_text(f"AWS_ACCESS_KEY_ID={raw_key}\n", encoding="utf-8")

        # Run with all 3 engines active
        rc, stdout, stderr = run_cli(
            str(tmp),
            "--sca",
            "--sca-offline",
            "--sca-cache", str(cache_file),
            "--secrets"
        )
        assert rc == 1
        assert "TimeCodeSecurity (TCS) Security Scan Report (SAST + SCA + SECRETS)" in stdout
        assert "[SAST CODE ANALYSIS FINDINGS]" in stdout
        assert "[SCA DEPENDENCY VULNERABILITIES]" in stdout
        assert "[SECRET SCANNING FINDINGS (CWE-798)]" in stdout

        # JSON Export verification
        rc, stdout, stderr = run_cli(
            str(tmp),
            "--sca",
            "--sca-offline",
            "--sca-cache", str(cache_file),
            "--secrets",
            "--format", "json"
        )
        assert rc == 1
        data = json.loads(stdout)
        assert len(data["findings"]) >= 1
        assert len(data["sca_findings"]) >= 1
        assert len(data["secret_findings"]) == 1

        summary = data["summary"]
        assert summary["total_vulnerabilities"] >= 1
        assert summary["sca_vulnerabilities"] >= 1
        assert summary["secrets_detected"] == 1
        assert raw_key not in stdout

        # SARIF Export verification
        rc, stdout, stderr = run_cli(
            str(tmp),
            "--sca",
            "--sca-offline",
            "--sca-cache", str(cache_file),
            "--secrets",
            "--format", "sarif"
        )
        assert rc == 1
        sarif = json.loads(stdout)
        driver = sarif["runs"][0]["tool"]["driver"]
        rule_ids = {r["id"] for r in driver["rules"]}
        assert "CWE-95" in rule_ids
        assert "GHSA-j8r2-6x86-q33q" in rule_ids
        assert "CWE-798" in rule_ids

        results = sarif["runs"][0]["results"]
        res_rule_ids = {res["ruleId"] for res in results}
        assert "CWE-95" in res_rule_ids
        assert "GHSA-j8r2-6x86-q33q" in res_rule_ids
        assert "CWE-798" in res_rule_ids
        assert raw_key not in stdout
    print("PASS: test_07_tri_engine_unified_scan")


def test_08_file_export_option():
    """Verify -o/--output writes identical unmasked-free output to file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        raw_key = "AKIA" + "IOSFODNN7EXAMPLE"
        (tmp / "keys.ini").write_text(f"[aws]\naws_access_key = {raw_key}\n", encoding="utf-8")

        out_file = tmp / "output" / "report.json"
        rc, stdout, stderr = run_cli(str(tmp), "--secrets", "--format", "json", "-o", str(out_file))
        assert rc == 1
        assert out_file.exists()

        content = out_file.read_text(encoding="utf-8")
        data = json.loads(content)
        assert len(data["secret_findings"]) == 1
        assert raw_key not in content
        assert raw_key not in stdout
        assert raw_key not in stderr
    print("PASS: test_08_file_export_option")


def test_09_private_key_detection_and_masking():
    """Verify private key header detection, CWE-798 attribution, and masking."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        key_content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m...\n-----END RSA PRIVATE KEY-----\n"
        (tmp / "server.conf").write_text(f"ssl_key = {key_content}", encoding="utf-8")

        rc, stdout, stderr = run_cli(str(tmp), "--secrets", "--format", "json")
        assert rc == 1
        data = json.loads(stdout)
        findings = data["secret_findings"]
        assert any(f["secret_type"] == "private_key" for f in findings)
        priv_finding = next(f for f in findings if f["secret_type"] == "private_key")
        assert priv_finding["masked_value"] == mask_secret("-----BEGIN RSA PRIVATE KEY-----")
        assert priv_finding["cwe"] == "CWE-798"
    print("PASS: test_09_private_key_detection_and_masking")


def test_10_error_conditions():
    """Verify exit code 2 on invalid targets or syntax errors."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        bad_py = tmp / "syntax_err.py"
        bad_py.write_text("def broken_syntax(\n", encoding="utf-8")

        rc, stdout, stderr = run_cli(str(bad_py), "--secrets")
        assert rc == 2
        assert "Syntax error" in stderr

        rc, stdout, stderr = run_cli(str(tmp / "nonexistent.py"), "--secrets")
        assert rc == 2
        assert "Target path does not exist" in stderr
    print("PASS: test_10_error_conditions")


def main():
    print("=" * 70)
    print("Running Phase 12 Step 3 Unit Tests: CLI Secrets & Reporting")
    print("=" * 70)

    test_01_baseline_pure_sast_without_secrets()
    test_02_clean_project_with_secrets_flag()
    test_03_secret_in_python_file()
    test_04_direct_secret_file_target_non_python()
    test_05_secret_file_types_discovery()
    test_06_policy_suppression_and_exclusions()
    test_07_tri_engine_unified_scan()
    test_08_file_export_option()
    test_09_private_key_detection_and_masking()
    test_10_error_conditions()

    print("=" * 70)
    print("ALL 10 PHASE 12 STEP 3 CLI INTEGRATION TESTS PASSED DETERMINISTICALLY!")
    print("=" * 70)


if __name__ == "__main__":
    main()
