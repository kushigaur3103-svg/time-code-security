"""Test suite verifying robust database connection string masking and zero password leakage.

Specifically validates:
- Passwords containing '@' (e.g. 'P@ssw0rd2026!') are cleanly masked to 12 asterisks.
- The partial password is NEVER leaked as the hostname.
- Masked value strictly equals 'postgresql://d******n:************@192.168.1.150:5432/user_vault'.
- Zero leakage in SecretFinding attributes, repr, dict, or context.
"""

import dataclasses
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import secret_scanner


class TestMaskingLeak(unittest.TestCase):
    def test_database_uri_password_with_at_symbol(self):
        target_uri = "postgresql://db_admin:P@ssw0rd2026!@192.168.1.150:5432/user_vault"
        code = f'DATABASE_URL = "{target_uri}"'
        
        findings = secret_scanner.scan_text(code, filename="db_config.py")
        self.assertEqual(len(findings), 1, f"Expected 1 finding, got: {len(findings)}")
        
        f = findings[0]
        self.assertEqual(f.secret_type, "database_connection_string")
        self.assertEqual(f.detector, "database_connection_string")
        
        # 1. Exact masked value requirement
        expected_masked = "postgresql://d******n:************@192.168.1.150:5432/user_vault"
        self.assertEqual(f.masked_value, expected_masked)
        
        # 2. Strict non-leakage checks: raw password and fragments MUST NEVER appear
        leaked_fragment = "@ssw0rd2026!"
        raw_password = "P@ssw0rd2026!"
        
        self.assertNotIn(raw_password, f.masked_value)
        self.assertNotIn(leaked_fragment, f.masked_value)
        self.assertNotIn(raw_password, f.context)
        self.assertNotIn(leaked_fragment, f.context)
        self.assertNotIn(raw_password, repr(f))
        self.assertNotIn(leaked_fragment, repr(f))
        
        # 3. Serialized dict check
        finding_dict = dataclasses.asdict(f)
        for k, v in finding_dict.items():
            self.assertNotIn(raw_password, str(v))
            self.assertNotIn(leaked_fragment, str(v))

    def test_multiple_special_chars_in_password(self):
        uri = "mysql://admin_usr:My#P@ss:w0rd!2026@cluster.prod:3306/main_db"
        code = f'DB_DSN = "{uri}"'
        findings = secret_scanner.scan_text(code, filename="settings.py")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        
        # Must not contain the password or leaked fragments
        self.assertNotIn("My#P@ss:w0rd!2026", f.masked_value)
        self.assertNotIn("My#P@ss:w0rd!2026", f.context)
        self.assertIn("************", f.masked_value)
        self.assertIn("@cluster.prod:3306/main_db", f.masked_value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
