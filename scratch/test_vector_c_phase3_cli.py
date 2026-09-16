import sys
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON_EXE = sys.executable
TCS_CLI = REPO_ROOT / "tcs_cli.py"
FIXTURE_01 = REPO_ROOT / "tests" / "fixtures" / "vector_c" / "fixture_01_direct_call"


class TestVectorCPhase3CLI(unittest.TestCase):
    """
    Verification Suite for Vector C Phase 3 CLI & Report Integration.
    Tests CLI behavior with and without --sca-reachability.
    """

    def test_cli_scan_with_sca_reachability_flag(self):
        cmd = [
            PYTHON_EXE,
            str(TCS_CLI),
            str(FIXTURE_01),
            "--sca-reachability",
        ]
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(REPO_ROOT),
        )

        self.assertEqual(result.returncode, 0, f"CLI exited with non-zero code {result.returncode}. Stderr: {result.stderr}")
        self.assertIn("VECTOR C: DEPENDENCY REACHABILITY ANALYSIS", result.stdout)
        self.assertIn("REACHABLE_API_USE", result.stdout)
        self.assertIn("vulnlib (1.5.0) -> REACHABLE_API_USE", result.stdout)
        self.assertIn("Advisory: TCS-VEC-C-001 (HIGH)", result.stdout)
        self.assertIn("Import State: PACKAGE_IMPORTED (app.py:1)", result.stdout)
        self.assertIn("Call Path: module_level -> vulnlib.dangerous", result.stdout)

    def test_cli_scan_without_sca_reachability_flag(self):
        cmd = [
            PYTHON_EXE,
            str(TCS_CLI),
            str(FIXTURE_01),
        ]
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(REPO_ROOT),
        )

        self.assertEqual(result.returncode, 0, f"CLI exited with non-zero code {result.returncode}. Stderr: {result.stderr}")
        self.assertNotIn("VECTOR C: DEPENDENCY REACHABILITY ANALYSIS", result.stdout)
        self.assertNotIn("REACHABLE_API_USE", result.stdout)
        self.assertIn("No security vulnerabilities detected.", result.stdout)

    def test_cli_scan_json_output_with_reachability(self):
        cmd = [
            PYTHON_EXE,
            str(TCS_CLI),
            str(FIXTURE_01),
            "--sca-reachability",
            "--format",
            "json",
        ]
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(REPO_ROOT),
        )

        self.assertEqual(result.returncode, 0, f"CLI exited with non-zero code {result.returncode}. Stderr: {result.stderr}")
        import json
        data = json.loads(result.stdout)
        self.assertIn("sca_reachability_findings", data)
        self.assertEqual(len(data["sca_reachability_findings"]), 1)
        rf = data["sca_reachability_findings"][0]
        self.assertEqual(rf["package_name"], "vulnlib")
        self.assertEqual(rf["reachability_classification"], "REACHABLE_API_USE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
