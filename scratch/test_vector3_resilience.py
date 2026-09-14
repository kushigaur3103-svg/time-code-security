"""
Vector 3 Resilience Test Suite: Resource Exhaustion & Giant Files (DoS Defense).

Tests TCS defenses against:
1. Giant files (> 1MB)
2. Binary blobs disguised as .py (NUL byte in prefix)
3. Pathological minified one-liners (> 10,000 characters)
4. Circular symlink loops (with Windows privilege fallback handling)
5. SARIF and JSON output integrity for skipped files
"""

import os
import sys
import json
import tempfile
import unittest
import subprocess
from pathlib import Path
from unittest.mock import patch

# Ensure root directory is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tcs_cli import (
    check_file_resilience,
    discover_python_files,
    discover_manifest_files,
    discover_secret_files,
    MAX_FILE_SIZE_BYTES,
    MAX_LINE_LENGTH_CHARS,
    BINARY_PREFIX_BYTES
)
from sarif_adapter import to_sarif
from secret_scanner import scan_file, scan_text


class TestVector3Resilience(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_fixture_1_giant_file(self):
        """Fixture 1: 5 MiB dummy Python file must be skipped without memory blowup, exit code 0."""
        giant_file = self.work_dir / "giant_script.py"
        # Write 5 MiB of valid-looking comment characters
        file_size = 5 * 1024 * 1024
        with open(giant_file, "wb") as f:
            f.write(b"# " + b"A" * (file_size - 3) + b"\n")

        self.assertGreater(giant_file.stat().st_size, MAX_FILE_SIZE_BYTES)

        # 1. Direct resilience check
        reason = check_file_resilience(giant_file, "giant_script.py")
        self.assertIsNotNone(reason)
        self.assertIn("exceeding size limit (1MB)", reason)

        # 2. Discovery check (skipped, not loaded into memory)
        skipped = []
        discovered = discover_python_files(self.work_dir, self.work_dir, skipped_files=skipped)
        self.assertEqual(discovered, {})
        self.assertEqual(len(skipped), 1)
        self.assertIn("exceeding size limit (1MB)", skipped[0])

        # 3. secret_scanner.scan_file resilience
        secret_findings = scan_file(str(giant_file))
        self.assertEqual(secret_findings, [])

        # 4. End-to-end CLI execution
        cmd = [sys.executable, "-u", str(ROOT_DIR / "tcs_cli.py"), str(giant_file), "--format", "json"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(ROOT_DIR))
        self.assertEqual(proc.returncode, 0, f"CLI should exit 0 on clean skipped file, got {proc.returncode}. Stderr: {proc.stderr}")
        self.assertIn("Skipping file exceeding size limit (1MB)", proc.stderr)

        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["summary"]["active_vulnerabilities"], 0)
        self.assertEqual(parsed["summary"]["security_score"], 100)
        self.assertIn("giant_script.py", " ".join(parsed.get("skipped_files", [])))

    def test_fixture_2_binary_blob_disguised(self):
        """Fixture 2: Binary file disguised with .py extension containing \\x00 must be skipped, exit 0."""
        binary_file = self.work_dir / "compiled_blob.py"
        # Write fake ELF/PE binary header with NUL bytes
        with open(binary_file, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 1024)

        # 1. Direct resilience check
        reason = check_file_resilience(binary_file, "compiled_blob.py")
        self.assertIsNotNone(reason)
        self.assertIn("Skipping binary file", reason)

        # 2. Discovery check
        skipped = []
        discovered = discover_python_files(self.work_dir, self.work_dir, skipped_files=skipped)
        self.assertEqual(discovered, {})
        self.assertEqual(len(skipped), 1)
        self.assertIn("Skipping binary file", skipped[0])

        # 3. secret_scanner.scan_file resilience
        secret_findings = scan_file(str(binary_file))
        self.assertEqual(secret_findings, [])

        # 4. End-to-end CLI execution
        cmd = [sys.executable, "-u", str(ROOT_DIR / "tcs_cli.py"), str(binary_file), "--format", "json"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(ROOT_DIR))
        self.assertEqual(proc.returncode, 0, f"CLI should exit 0 on clean binary skip, got {proc.returncode}. Stderr: {proc.stderr}")
        self.assertIn("Skipping binary file", proc.stderr)

        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["summary"]["active_vulnerabilities"], 0)
        self.assertIn("compiled_blob.py", " ".join(parsed.get("skipped_files", [])))

    def test_fixture_3_minified_pathological_line(self):
        """Fixture 3: Minified one-liner with 15,000 chars must be skipped with warning, exit 0."""
        minified_file = self.work_dir / "bundle.min.py"
        # Single line exceeding 10,000 characters
        long_line = "x = " + "+".join(["1"] * 7500) + "\n"
        self.assertGreater(len(long_line), MAX_LINE_LENGTH_CHARS)
        minified_file.write_text(long_line, encoding="utf-8")

        # 1. Direct resilience check
        reason = check_file_resilience(minified_file, "bundle.min.py")
        self.assertIsNotNone(reason)
        self.assertIn("Skipping minified file exceeding line length limit (10000)", reason)

        # 2. Discovery check
        skipped = []
        discovered = discover_python_files(self.work_dir, self.work_dir, skipped_files=skipped)
        self.assertEqual(discovered, {})
        self.assertEqual(len(skipped), 1)
        self.assertIn("exceeding line length limit (10000)", skipped[0])

        # 3. secret_scanner.scan_text resilience on 15,000 char line
        secret_findings = scan_text(long_line)
        self.assertEqual(secret_findings, [])

        # 4. End-to-end CLI execution
        cmd = [sys.executable, "-u", str(ROOT_DIR / "tcs_cli.py"), str(minified_file), "--format", "json"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(ROOT_DIR))
        self.assertEqual(proc.returncode, 0, f"CLI should exit 0 on clean minified skip, got {proc.returncode}. Stderr: {proc.stderr}")
        self.assertIn("Skipping minified file exceeding line length limit (10000)", proc.stderr)

        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["summary"]["active_vulnerabilities"], 0)
        self.assertIn("bundle.min.py", " ".join(parsed.get("skipped_files", [])))

    def test_fixture_4_circular_symlink_safety(self):
        """Fixture 4: Circular symlink loop must terminate cleanly and not cause recursion/infinite loop."""
        sub_dir = self.work_dir / "nested"
        sub_dir.mkdir()
        normal_file = sub_dir / "safe.py"
        normal_file.write_text("a = 1\n", encoding="utf-8")

        symlink_created = False
        link_dir = sub_dir / "loop_link"
        try:
            os.symlink(str(sub_dir), str(link_dir), target_is_directory=True)
            symlink_created = True
        except OSError as e:
            print(f"\n[INFO] os.symlink unavailable on current OS privilege level ({e}). Testing visited-dir pruning logic directly.", file=sys.stderr)

        if symlink_created:
            # Real OS symlink test
            skipped = []
            discovered = discover_python_files(self.work_dir, self.work_dir, skipped_files=skipped)
            # Must find safe.py exactly once and terminate without recursion
            self.assertIn("nested/safe.py", discovered)
        else:
            # Test cycle prevention logic directly:
            # When an os.walk traversal yields realpath cycles, visited_dirs prunes it
            sub_path = self.work_dir / "sub"
            sub_path.mkdir(exist_ok=True)
            (sub_path / "safe.py").write_text("a = 1\n", encoding="utf-8")

            with patch("os.walk") as mocked_walk, patch("os.path.realpath") as mocked_realpath:
                mocked_walk.return_value = [
                    (str(self.work_dir), ["sub"], []),
                    (str(self.work_dir / "sub"), ["loop"], ["safe.py"]),
                    (str(self.work_dir / "sub" / "loop"), ["loop"], ["safe.py"]),
                ]
                def fake_realpath(p):
                    if "loop" in str(p):
                        return str(self.work_dir / "sub")
                    return str(p)
                mocked_realpath.side_effect = fake_realpath

                skipped = []
                discovered = discover_python_files(self.work_dir, self.work_dir, skipped_files=skipped)
                self.assertEqual(len(discovered), 1)
                self.assertIn("sub/safe.py", discovered)

    def test_secrets_and_manifests_resilience(self):
        """Verify discover_secret_files and discover_manifest_files reject giant and binary files."""
        giant_secret = self.work_dir / "giant_config.json"
        with open(giant_secret, "wb") as f:
            f.write(b"{" + b'"k": "v",' * 200000 + b'"end": 1}')
        self.assertGreater(giant_secret.stat().st_size, MAX_FILE_SIZE_BYTES)

        skipped = []
        sec_files = discover_secret_files(self.work_dir, self.work_dir, skipped_files=skipped)
        self.assertEqual(sec_files, [])
        self.assertTrue(any("giant_config.json" in s for s in skipped))

        binary_manifest = self.work_dir / "requirements.txt"
        with open(binary_manifest, "wb") as f:
            f.write(b"pkg==1.0\x00corrupt")

        skipped_man = []
        man_files = discover_manifest_files(self.work_dir, self.work_dir, skipped_files=skipped_man)
        self.assertEqual(man_files, [])
        self.assertTrue(any("Skipping binary file" in s for s in skipped_man))

    def test_sarif_notifications_include_skipped_files(self):
        """Verify SARIF output includes skipped files in toolExecutionNotifications."""
        tcs_result = {
            "findings": [],
            "syntax_errors": ["corrupt.py:1: invalid syntax"],
            "skipped_files": ["Skipping file exceeding size limit (1MB): huge.py"],
            "summary": {
                "total_files": 1,
                "lines_scanned": 0,
                "total_vulnerabilities": 0,
                "active_vulnerabilities": 0,
                "suppressed_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "security_score": 100,
                "risk_level": "CLEAN"
            }
        }
        sarif_doc = to_sarif(tcs_result)
        invocations = sarif_doc["runs"][0].get("invocations", [])
        self.assertEqual(len(invocations), 1)
        notifications = invocations[0].get("toolExecutionNotifications", [])
        self.assertEqual(len(notifications), 2)

        notif_texts = [n["message"]["text"] for n in notifications]
        self.assertTrue(any("corrupt.py" in t for t in notif_texts))
        self.assertTrue(any("huge.py" in t for t in notif_texts))


if __name__ == "__main__":
    unittest.main()
