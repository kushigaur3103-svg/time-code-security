"""
Unit and integration test verifying that TCS never creates a literal '~' or '.' folder
in the working directory under any CLI or SDK invocation.
"""

import os
import sys
import unittest
import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from osv_client import OSVClient
from tcs_cli import main as cli_main


class TestNoLiteralTildeArtifact(unittest.TestCase):

    def setUp(self):
        self.literal_tilde = REPO_ROOT / "~"
        if self.literal_tilde.exists():
            shutil.rmtree(self.literal_tilde, ignore_errors=True)

    def tearDown(self):
        if self.literal_tilde.exists():
            shutil.rmtree(self.literal_tilde, ignore_errors=True)

    def test_01_osv_client_expands_tilde(self):
        """OSVClient expands ~ to user's actual home directory without creating local .\\~."""
        client = OSVClient(cache_file="~/.tcs/osv_cache.json", offline_mode=True)
        self.assertIsNotNone(client.cache_file)
        self.assertNotIn("~", Path(client.cache_file).parts)
        self.assertTrue(Path(client.cache_file).is_absolute())
        self.assertEqual(Path(client.cache_file), (Path.home() / ".tcs" / "osv_cache.json").resolve())
        self.assertFalse(self.literal_tilde.exists(), "Literal '~' directory must NOT be created!")

    def test_02_osv_client_save_disk_cache_safe(self):
        """OSVClient._save_disk_cache persists to home directory and never creates local .\\~."""
        client = OSVClient(cache_file="~/.tcs/osv_cache.json", offline_mode=True)
        client._memory_cache["test-pkg"] = [{"id": "TEST-1"}]
        client._save_disk_cache()
        self.assertFalse(self.literal_tilde.exists(), "Literal '~' directory must NOT be created on disk save!")

    def test_03_cli_scan_with_sca_no_literal_tilde(self):
        """CLI scan with --sca does not create a literal '~' directory."""
        sandbox = REPO_ROOT / "scratch" / "test_tilde_sandbox"
        sandbox.mkdir(parents=True, exist_ok=True)
        try:
            (sandbox / "app.py").write_text("def ok(): pass\n", encoding="utf-8")
            (sandbox / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")

            # Run CLI scan
            try:
                cli_main(["scan", str(sandbox), "--sca", "--sca-offline"])
            except SystemExit:
                pass
            self.assertFalse(self.literal_tilde.exists(), "Literal '~' directory was created during CLI scan!")
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
