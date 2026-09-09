"""
Phase 13 Step 2 Test Suite: CLI GitHub Actions Bridge in tcs_cli.py.
100% offline with zero live network calls. Socket connections are blocked.
Verifies --github-actions, --step-summary-file, stdout cleanliness, and zero cleartext secret leakage.
"""

import sys
import os
import json
import socket
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Strictly block all live socket connections
def _blocked_connect(*args, **kwargs):
    raise RuntimeError("Live network access is strictly forbidden in Phase 13 unit tests!")

socket.socket.connect = _blocked_connect
socket.create_connection = _blocked_connect

PYTHON_EXE = sys.executable
CLI_PATH = str(REPO_ROOT / "tcs_cli.py")


def run_cli(*args, env_override: Dict[str, str] = None):
    """Executes tcs_cli.py in a subprocess with optional environment variables."""
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

def test_01_baseline_without_github_actions():
    """Verify that without --github-actions, CLI behavior remains identical to Phase 10-12."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        code = tmp / "vuln.py"
        code.write_text("import sys\nimport os\ncmd = sys.argv[1]\nos.system(cmd)\n", encoding="utf-8")

        rc, stdout, stderr = run_cli(str(code))
        assert rc == 1, f"Expected rc=1, got {rc}"
        assert "TimeCodeSecurity (TCS) AST Security Scan Report" in stdout
        # Without --github-actions, no workflow commands are emitted
        assert "::error" not in stderr
        assert "::warning" not in stderr
        assert "::error" not in stdout
    print("PASS: test_01_baseline_without_github_actions")


def test_02_clean_project_with_github_actions():
    """Verify that a clean project with --github-actions produces exit code 0 and zero ::error annotations."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "clean.py").write_text("a = 1\nb = 2\nprint(a + b)\n", encoding="utf-8")

        rc, stdout, stderr = run_cli(str(tmp), "--github-actions")
        assert rc == 0, f"Expected rc=0 for clean project, got {rc}: {stderr}"
        assert "No security vulnerabilities detected." in stdout
        assert "::error" not in stderr
        assert "::warning" not in stderr
        assert "::error" not in stdout
    print("PASS: test_02_clean_project_with_github_actions")


def test_03_vulnerable_project_emits_annotations_and_exit_1():
    """Verify that vulnerable projects emit ::error and ::warning commands on stderr and exit code 1."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "app.py").write_text("import sys\nx = sys.argv[1]\neval(x)\n", encoding="utf-8")

        rc, stdout, stderr = run_cli(str(tmp), "--github-actions")
        assert rc == 1, f"Expected rc=1, got {rc}"
        assert "::error " in stderr
        assert "file=app.py" in stderr
        assert "CWE-95" in stderr
    print("PASS: test_03_vulnerable_project_emits_annotations_and_exit_1")


def test_04_stdout_cleanliness_json():
    """Verify that --format json with --github-actions produces strictly parseable JSON on stdout."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "app.py").write_text("import sys\nx = sys.argv[1]\neval(x)\n", encoding="utf-8")

        rc, stdout, stderr = run_cli(str(tmp), "--github-actions", "--format", "json")
        assert rc == 1

        # Stdout must parse cleanly as JSON with zero corruption
        try:
            data = json.loads(stdout)
        except Exception as e:
            assert False, f"stdout is corrupted and failed to parse as JSON: {e}\nSTDOUT:\n{stdout}"

        assert "findings" in data
        assert len(data["findings"]) == 1

        # Annotations must NOT be present in stdout
        assert "::error" not in stdout
        assert "::warning" not in stdout

        # Annotations must be present in stderr
        assert "::error " in stderr
        assert "CWE-95" in stderr
    print("PASS: test_04_stdout_cleanliness_json")


def test_05_stdout_cleanliness_sarif():
    """Verify that --format sarif with --github-actions produces strictly parseable SARIF JSON on stdout."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "app.py").write_text("import sys\nx = sys.argv[1]\neval(x)\n", encoding="utf-8")

        rc, stdout, stderr = run_cli(str(tmp), "--github-actions", "--format", "sarif")
        assert rc == 1

        # Stdout must parse cleanly as SARIF JSON with zero corruption
        try:
            sarif = json.loads(stdout)
        except Exception as e:
            assert False, f"stdout is corrupted and failed to parse as SARIF JSON: {e}\nSTDOUT:\n{stdout}"

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 1

        # Annotations must NOT be present in stdout
        assert "::error" not in stdout
        assert "::warning" not in stdout

        # Annotations must be present in stderr
        assert "::error " in stderr
    print("PASS: test_05_stdout_cleanliness_sarif")


def test_06_step_summary_file_via_env_var():
    """Verify that GITHUB_STEP_SUMMARY environment variable receives the Markdown Step Summary."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "app.py").write_text("import sys\nx = sys.argv[1]\neval(x)\n", encoding="utf-8")

        summary_file = tmp / "step_summary.md"
        env_override = {"GITHUB_STEP_SUMMARY": str(summary_file)}

        rc, stdout, stderr = run_cli(str(tmp), "--github-actions", env_override=env_override)
        assert rc == 1

        assert summary_file.exists(), "GITHUB_STEP_SUMMARY file was not created"
        content = summary_file.read_text(encoding="utf-8")
        assert "# TimeCodeSecurity Scan" in content
        assert "| Engine | Status | Findings |" in content
        assert "| SAST | FOUND | 1 |" in content
        assert "| Security Metrics" in content or "## Security Metrics" in content
        assert "### SAST Code Analysis" in content
    print("PASS: test_06_step_summary_file_via_env_var")


def test_07_step_summary_file_via_cli_flag_override():
    """Verify that --step-summary-file overrides and creates the Markdown Step Summary."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "app.py").write_text("a = 1\nprint(a)\n", encoding="utf-8")

        custom_summary = tmp / "custom_summary.md"
        env_override = {"GITHUB_STEP_SUMMARY": str(tmp / "ignored_summary.md")}

        rc, stdout, stderr = run_cli(
            str(tmp),
            "--github-actions",
            "--step-summary-file", str(custom_summary),
            env_override=env_override
        )
        assert rc == 0

        assert custom_summary.exists(), "Explicit --step-summary-file was not created"
        assert not (tmp / "ignored_summary.md").exists(), "Environment variable was not overridden by CLI flag"

        content = custom_summary.read_text(encoding="utf-8")
        assert "# TimeCodeSecurity Scan" in content
        assert "| SAST | CLEAN | 0 |" in content
        assert "*No vulnerabilities detected across active scanners.*" in content
    print("PASS: test_07_step_summary_file_via_cli_flag_override")


def test_08_tri_engine_scan_with_github_actions_and_zero_leakage():
    """Verify combined SAST, SCA, and Secret scanning with --github-actions and zero cleartext secret leakage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # 1. SAST
        (tmp / "app.py").write_text("import sys\nx = sys.argv[1]\nexec(x)\n", encoding="utf-8")

        # 2. SCA
        (tmp / "requirements.txt").write_text("requests==2.20.0\n", encoding="utf-8")
        cache_data = {
            "requests": [
                {
                    "id": "GHSA-j8r2-6x86-q33q",
                    "summary": "Requests vulnerable to session fixation",
                    "affected": [
                        {
                            "package": {"name": "requests", "ecosystem": "PyPI"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}]}]
                        }
                    ]
                }
            ]
        }
        cache_file = tmp / "osv_cache.json"
        cache_file.write_text(json.dumps(cache_data), encoding="utf-8")

        # 3. Secret
        raw_key = "AKIA" + "IOSFODNN7EXAMPLE"
        (tmp / "config.txt").write_text(f"AWS_ACCESS_KEY_ID={raw_key}\n", encoding="utf-8")

        summary_file = tmp / "summary.md"

        rc, stdout, stderr = run_cli(
            str(tmp),
            "--sca",
            "--sca-offline",
            "--sca-cache", str(cache_file),
            "--secrets",
            "--github-actions",
            "--step-summary-file", str(summary_file),
            "--format", "json"
        )
        assert rc == 1

        # 1. Stdout must parse as valid JSON
        data = json.loads(stdout)
        assert len(data["findings"]) >= 1
        assert len(data["sca_findings"]) >= 1
        assert len(data["secret_findings"]) == 1

        # 2. Stderr must contain annotations for all three engines
        assert "::error " in stderr
        assert "CWE-95" in stderr
        assert "GHSA-j8r2-6x86-q33q" in stderr
        assert "CWE-798 (AWS Access Key)" in stderr

        # 3. Summary file must contain tables for all three engines
        assert summary_file.exists()
        summary_content = summary_file.read_text(encoding="utf-8")
        assert "| SAST | FOUND |" in summary_content
        assert "| SCA | FOUND |" in summary_content
        assert "| Secrets | FOUND |" in summary_content
        assert "### SAST Code Analysis" in summary_content
        assert "### SCA Dependencies" in summary_content
        assert "### Secret Scanning (CWE-798)" in summary_content

        # 4. Strict Zero Cleartext Leakage Verification
        assert raw_key not in stdout, "Raw secret leaked in stdout!"
        assert raw_key not in stderr, "Raw secret leaked in stderr!"
        assert raw_key not in summary_content, "Raw secret leaked in step summary!"
    print("PASS: test_08_tri_engine_scan_with_github_actions_and_zero_leakage")


def test_09_unwritable_or_invalid_summary_path_exits_2():
    """Verify that an unwritable/invalid step summary path produces [ERROR] on stderr and exits with code 2."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "clean.py").write_text("a = 1\nprint(a)\n", encoding="utf-8")

        # Create a regular file to act as a directory blocker
        blocker = tmp / "blocker.txt"
        blocker.write_text("not a directory", encoding="utf-8")
        invalid_path = blocker / "uncreatable_dir" / "summary.md"

        rc, stdout, stderr = run_cli(
            str(tmp),
            "--github-actions",
            "--step-summary-file", str(invalid_path)
        )
        assert rc == 2, f"Expected exit code 2 for unwritable summary path, got {rc}"
        assert "[ERROR] Failed to write Step Summary to" in stderr
    print("PASS: test_09_unwritable_or_invalid_summary_path_exits_2")


def test_10_missing_summary_file_env_and_override_follows_normal_exit_code():
    """Verify that when no summary file is configured (env unset and no flag), scans follow normal exit codes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # 1. Clean code -> exits 0
        (tmp / "clean.py").write_text("a = 1\nprint(a)\n", encoding="utf-8")
        env_empty = {"GITHUB_STEP_SUMMARY": ""}
        rc_clean, stdout_clean, stderr_clean = run_cli(str(tmp), "--github-actions", env_override=env_empty)
        assert rc_clean == 0, f"Expected rc=0 for clean scan without summary file, got {rc_clean}"
        assert "[ERROR]" not in stderr_clean

        # 2. Vulnerable code -> exits 1 with annotations on stderr
        (tmp / "vuln.py").write_text("import sys\nx = sys.argv[1]\neval(x)\n", encoding="utf-8")
        rc_vuln, stdout_vuln, stderr_vuln = run_cli(str(tmp), "--github-actions", env_override=env_empty)
        assert rc_vuln == 1, f"Expected rc=1 for vulnerable scan without summary file, got {rc_vuln}"
        assert "::error " in stderr_vuln
        assert "CWE-95" in stderr_vuln
        assert "[ERROR]" not in stderr_vuln
    print("PASS: test_10_missing_summary_file_env_and_override_follows_normal_exit_code")


def test_11_unwritable_summary_preserves_clean_stdout_and_stderr_annotations():
    """Verify that when summary write fails (exit 2), stdout JSON/SARIF remains clean and annotations remain on stderr."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "app.py").write_text("import sys\nx = sys.argv[1]\neval(x)\n", encoding="utf-8")

        blocker = tmp / "blocker.txt"
        blocker.write_text("blocker", encoding="utf-8")
        invalid_path = blocker / "sub" / "summary.md"

        # 1. JSON format
        rc_json, stdout_json, stderr_json = run_cli(
            str(tmp),
            "--github-actions",
            "--format", "json",
            "--step-summary-file", str(invalid_path)
        )
        assert rc_json == 2
        # Stdout must still parse as clean JSON
        try:
            data = json.loads(stdout_json)
            assert "findings" in data
        except Exception as e:
            assert False, f"stdout corrupted on exit 2 with --format json: {e}\nSTDOUT:\n{stdout_json}"
        # Stderr must have annotations AND error message
        assert "::error " in stderr_json
        assert "[ERROR] Failed to write Step Summary to" in stderr_json
        assert "::error" not in stdout_json

        # 2. SARIF format
        rc_sarif, stdout_sarif, stderr_sarif = run_cli(
            str(tmp),
            "--github-actions",
            "--format", "sarif",
            "--step-summary-file", str(invalid_path)
        )
        assert rc_sarif == 2
        # Stdout must still parse as clean SARIF
        try:
            sarif = json.loads(stdout_sarif)
            assert sarif["version"] == "2.1.0"
        except Exception as e:
            assert False, f"stdout corrupted on exit 2 with --format sarif: {e}\nSTDOUT:\n{stdout_sarif}"
        assert "::error " in stderr_sarif
        assert "[ERROR] Failed to write Step Summary to" in stderr_sarif
        assert "::error" not in stdout_sarif
    print("PASS: test_11_unwritable_summary_preserves_clean_stdout_and_stderr_annotations")


def main():
    print("=" * 75)
    print("Running Phase 13 Step 2 Tests: CLI GitHub Actions Bridge in tcs_cli.py")
    print("=" * 75)

    test_01_baseline_without_github_actions()
    test_02_clean_project_with_github_actions()
    test_03_vulnerable_project_emits_annotations_and_exit_1()
    test_04_stdout_cleanliness_json()
    test_05_stdout_cleanliness_sarif()
    test_06_step_summary_file_via_env_var()
    test_07_step_summary_file_via_cli_flag_override()
    test_08_tri_engine_scan_with_github_actions_and_zero_leakage()
    test_09_unwritable_or_invalid_summary_path_exits_2()
    test_10_missing_summary_file_env_and_override_follows_normal_exit_code()
    test_11_unwritable_summary_preserves_clean_stdout_and_stderr_annotations()

    print("=" * 75)
    print("ALL 11 PHASE 13 STEP 2 CLI GITHUB ACTIONS TESTS PASSED DETERMINISTICALLY!")
    print("=" * 75)


if __name__ == "__main__":
    main()
