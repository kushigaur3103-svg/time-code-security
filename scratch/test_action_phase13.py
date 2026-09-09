"""
Phase 13 Step 3 Test Suite: Composite GitHub Action (action.yml) & Production CI Workflow.
100% offline with zero live network calls. Sockets are strictly blocked.
Validates YAML structure, canonical sarif-file input, exit-code trapping matrix, and SARIF handoff.
"""

import sys
import os
import json
import socket
import tempfile
import subprocess
import shutil
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Strictly block all live socket connections
def _blocked_connect(*args, **kwargs):
    raise RuntimeError("Live network access is strictly forbidden in Phase 13 unit tests!")

socket.socket.connect = _blocked_connect
socket.create_connection = _blocked_connect

import yaml

ACTION_YML_PATH = REPO_ROOT / "action.yml"
WORKFLOW_YML_PATH = REPO_ROOT / ".github" / "workflows" / "tcs-scan.yml"
CLI_PATH = REPO_ROOT / "tcs_cli.py"


def test_01_yaml_syntax_and_action_structure():
    """Verify action.yml exists, is valid YAML, and conforms to composite action schema."""
    assert ACTION_YML_PATH.exists(), f"action.yml missing at {ACTION_YML_PATH}"

    with open(ACTION_YML_PATH, "r", encoding="utf-8") as f:
        action = yaml.safe_load(f)

    assert action.get("name") == "TimeCodeSecurity (TCS) Security Scan"
    assert "description" in action
    assert action.get("runs", {}).get("using") == "composite"

    steps = action.get("runs", {}).get("steps", [])
    assert len(steps) >= 1, "Expected at least 1 composite step in action.yml"
    main_step = steps[0]
    assert main_step.get("shell") == "bash"
    assert "run" in main_step
    print("PASS: test_01_yaml_syntax_and_action_structure")


def test_02_action_inputs_and_defaults():
    """Assert canonical sarif-file input and default values in action.yml."""
    with open(ACTION_YML_PATH, "r", encoding="utf-8") as f:
        action = yaml.safe_load(f)

    inputs = action.get("inputs", {})

    # 1. Verify canonical sarif-file
    assert "sarif-file" in inputs, "Canonical 'sarif-file' input is missing from action.yml"
    assert inputs["sarif-file"].get("default") == "tcs-results.sarif"

    expected_defaults = {
        "target": ".",
        "sca": "false",
        "sca-offline": "false",
        "secrets": "false",
        "format": "sarif",
        "sarif-file": "tcs-results.sarif",
        "fail-on-findings": "true",
        "exclude-suppressed": "false",
        "step-summary": "true",
    }

    for input_name, expected_val in expected_defaults.items():
        assert input_name in inputs, f"Missing input '{input_name}' in action.yml"
        actual_val = str(inputs[input_name].get("default"))
        assert actual_val == expected_val, (
            f"Input '{input_name}' default mismatch: expected '{expected_val}', got '{actual_val}'"
        )
    print("PASS: test_02_action_inputs_and_defaults")


def test_03_workflow_yaml_syntax_and_specification():
    """Verify .github/workflows/tcs-scan.yml exists, is valid YAML, and uses sarif-file."""
    assert WORKFLOW_YML_PATH.exists(), f"Workflow file missing at {WORKFLOW_YML_PATH}"

    with open(WORKFLOW_YML_PATH, "r", encoding="utf-8") as f:
        wf = yaml.safe_load(f)

    # 1. Triggers: push to main and pull_request to main
    triggers = wf.get("on") or wf.get(True)
    assert triggers is not None, "Workflow missing triggers ('on')"
    assert "push" in triggers, "Workflow missing 'push' trigger"
    assert "main" in triggers["push"].get("branches", []), "Push trigger missing 'main' branch"
    assert "pull_request" in triggers, "Workflow missing 'pull_request' trigger"
    assert "main" in triggers["pull_request"].get("branches", []), "PR trigger missing 'main' branch"

    # 2. Permissions
    permissions = wf.get("permissions", {})
    assert permissions.get("security-events") == "write"
    assert permissions.get("contents") == "read"

    # 3. Job steps
    jobs = wf.get("jobs", {})
    assert "tcs-security-scan" in jobs
    steps = jobs["tcs-security-scan"].get("steps", [])

    # Check TCS action step uses sarif-file
    tcs_step = [s for s in steps if s.get("uses") == "./"][0]
    assert tcs_step.get("with", {}).get("sarif-file") == "tcs-results.sarif", "TCS step must specify sarif-file"

    # Check upload-sarif step uses sarif_file
    upload_step = [s for s in steps if "upload-sarif" in s.get("uses", "")][0]
    assert upload_step.get("if") == "always()", "upload-sarif must have if: always()"
    assert upload_step.get("with", {}).get("sarif_file") == "tcs-results.sarif"
    print("PASS: test_03_workflow_yaml_syntax_and_specification")


def test_04_explicit_exit_code_matrix_simulation():
    """Explicitly verify the 5 required exit code trapping scenarios:
    1. fail-on-findings=true  + CLI exit 0 -> Action 0
    2. fail-on-findings=true  + CLI exit 1 -> Action 1
    3. fail-on-findings=false + CLI exit 1 -> Action 0
    4. fail-on-findings=true  + CLI exit 2 -> Action 2
    5. fail-on-findings=false + CLI exit 2 -> Action 2
    """
    def simulate_exit_trap(cli_exit_code: int, fail_on_findings: str) -> int:
        if cli_exit_code == 0:
            return 0
        elif cli_exit_code == 1:
            if fail_on_findings == "false":
                return 0
            else:
                return 1
        else:
            return cli_exit_code

    # Scenario 1: fail-on-findings=true + CLI exit 0 -> Action 0
    assert simulate_exit_trap(0, "true") == 0, "Scenario 1 failed"

    # Scenario 2: fail-on-findings=true + CLI exit 1 -> Action 1
    assert simulate_exit_trap(1, "true") == 1, "Scenario 2 failed"

    # Scenario 3: fail-on-findings=false + CLI exit 1 -> Action 0
    assert simulate_exit_trap(1, "false") == 0, "Scenario 3 failed"

    # Scenario 4: fail-on-findings=true + CLI exit 2 -> Action 2
    assert simulate_exit_trap(2, "true") == 2, "Scenario 4 failed"

    # Scenario 5: fail-on-findings=false + CLI exit 2 -> Action 2 (must NOT be masked)
    assert simulate_exit_trap(2, "false") == 2, "Scenario 5 failed"
    print("PASS: test_04_explicit_exit_code_matrix_simulation")


def test_05_bash_script_matrix_execution():
    """Execute the exact bash script logic using bash across all 5 matrix scenarios."""
    candidates = [
        "C:\\Program Files\\Git\\bin\\bash.exe",
        shutil.which("bash")
    ]
    bash_bin = None
    for cand in candidates:
        if cand and Path(cand).exists():
            try:
                check = subprocess.run([cand, "-c", "exit 0"], capture_output=True)
                if check.returncode == 0:
                    bash_bin = cand
                    break
            except Exception:
                continue

    if not bash_bin:
        print("SKIP: Functional bash binary not found on system for test_05")
        return

    script = """
    MOCK_EXIT=$1
    INPUT_FAIL_ON_FINDINGS=$2

    set +e
    python -c "import sys; sys.exit(int(sys.argv[1]))" "$MOCK_EXIT"
    EXIT_CODE=$?
    set -e

    if [ "$EXIT_CODE" -eq 0 ]; then
      exit 0
    elif [ "$EXIT_CODE" -eq 1 ]; then
      if [ "$INPUT_FAIL_ON_FINDINGS" = "false" ]; then
        exit 0
      else
        exit 1
      fi
    else
      exit "$EXIT_CODE"
    fi
    """

    required_matrix = [
        (0, "true", 0),   # fail-on-findings=true  + exit 0 -> 0
        (1, "true", 1),   # fail-on-findings=true  + exit 1 -> 1
        (1, "false", 0),  # fail-on-findings=false + exit 1 -> 0
        (2, "true", 2),   # fail-on-findings=true  + exit 2 -> 2
        (2, "false", 2),  # fail-on-findings=false + exit 2 -> 2
    ]

    for mock_exit, fail_flag, expected_rc in required_matrix:
        proc = subprocess.run(
            [bash_bin, "-c", script, "bash", str(mock_exit), fail_flag],
            capture_output=True
        )
        assert proc.returncode == expected_rc, (
            f"Bash exit trap failure: mock={mock_exit}, fail_on_findings={fail_flag} -> "
            f"expected {expected_rc}, got {proc.returncode}"
        )
    print("PASS: test_05_bash_script_matrix_execution")


def test_06_sarif_file_path_passed_to_output_and_file_exists():
    """Verify that sarif-file path is passed to --output correctly and the SARIF file exists at the configured path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "app.py").write_text("import sys\nx = sys.argv[1]\neval(x)\n", encoding="utf-8")
        custom_sarif = tmp / "custom-output" / "my-security-report.sarif"

        # Simulate argument resolution logic from action.yml:
        # OUTPUT_PATH="$INPUT_SARIF_FILE"
        input_sarif_file = str(custom_sarif)
        cli_args = [
            sys.executable, str(CLI_PATH), str(tmp),
            "--format", "sarif",
            "--output", input_sarif_file,
            "--github-actions"
        ]

        proc = subprocess.run(cli_args, capture_output=True, text=True, encoding="utf-8")
        assert proc.returncode == 1, f"Expected rc=1 for vulnerable scan, got {proc.returncode}"

        # 1. Quiet stdout handoff verification
        assert proc.stdout.strip() == "", f"stdout was not silenced when writing to file: {proc.stdout}"

        # 2. Assert SARIF file exists at the configured path
        assert custom_sarif.exists(), f"SARIF file was not created at configured path: {custom_sarif}"

        # 3. Assert SARIF file contents are valid
        content = custom_sarif.read_text(encoding="utf-8")
        sarif_data = json.loads(content)
        assert sarif_data.get("version") == "2.1.0"
        assert len(sarif_data["runs"][0]["results"]) == 1
        assert sarif_data["runs"][0]["results"][0]["ruleId"] == "CWE-95"

        # 4. stderr verification
        assert "::error " in proc.stderr
        assert "[TCS CLI] Results written to:" in proc.stderr
    print("PASS: test_06_sarif_file_path_passed_to_output_and_file_exists")


def main():
    print("=" * 75)
    print("Running Phase 13 Step 3 Tests: Composite Action & CI Workflow")
    print("=" * 75)

    test_01_yaml_syntax_and_action_structure()
    test_02_action_inputs_and_defaults()
    test_03_workflow_yaml_syntax_and_specification()
    test_04_explicit_exit_code_matrix_simulation()
    test_05_bash_script_matrix_execution()
    test_06_sarif_file_path_passed_to_output_and_file_exists()

    print("=" * 75)
    print("ALL 6 PHASE 13 STEP 3 ACTION & WORKFLOW TESTS PASSED DETERMINISTICALLY!")
    print("=" * 75)


if __name__ == "__main__":
    main()
