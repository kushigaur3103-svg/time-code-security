"""
Phase 13 Step 1 Test Suite: CI Annotation & GitHub Step Summary Engine (ci_reporter.py).
100% offline with zero live network calls. Socket connections are blocked.
Verifies injection safety, zero cleartext leakage, tri-engine support, and determinism.
"""

import sys
import socket
import unittest
from pathlib import Path
from typing import Dict, Any

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Strictly block all socket connections
def _blocked_connect(*args, **kwargs):
    raise RuntimeError("Live network access is strictly forbidden in Phase 13 unit tests!")

socket.socket.connect = _blocked_connect
socket.create_connection = _blocked_connect

from ci_reporter import (
    escape_property_value,
    escape_message_data,
    format_github_annotation,
    format_github_annotations,
    generate_annotations,
    generate_step_summary,
    write_step_summary,
)


class TestCIReporterPhase13(unittest.TestCase):
    """Deterministic, offline test suite for ci_reporter.py."""

    def test_01_sast_error_annotation(self):
        """CRITICAL/HIGH SAST finding produces ::error annotation with CWE title and coordinates."""
        scan_result = {
            "findings": [
                {
                    "cwe": "CWE-95",
                    "category": "code_execution",
                    "severity": "HIGH",
                    "file": "app.py",
                    "line_number": 42,
                    "column_start": 5,
                    "sink_symbol": "eval",
                    "flow_trace_summary": "Untrusted input reaches eval()",
                }
            ]
        }
        annotations = format_github_annotations(scan_result)
        self.assertEqual(len(annotations), 1)
        ann = annotations[0]
        self.assertTrue(ann.startswith("::error "))
        self.assertIn("file=app.py", ann)
        self.assertIn("line=42", ann)
        self.assertIn("col=5", ann)
        self.assertIn("title=CWE-95 (Code Execution)", ann)
        self.assertTrue(ann.endswith("::Untrusted input reaches eval()"))

    def test_02_sast_warning_annotation(self):
        """MEDIUM/LOW SAST finding produces ::warning annotation."""
        scan_result = {
            "findings": [
                {
                    "cwe": "CWE-22",
                    "category": "path_traversal",
                    "severity": "MEDIUM",
                    "file": "utils/loader.py",
                    "line_number": 88,
                    "column_start": 12,
                    "sink_symbol": "open",
                }
            ]
        }
        annotations = format_github_annotations(scan_result)
        self.assertEqual(len(annotations), 1)
        ann = annotations[0]
        self.assertTrue(ann.startswith("::warning "))
        self.assertIn("file=utils/loader.py", ann)
        self.assertIn("line=88", ann)
        self.assertIn("col=12", ann)
        self.assertIn("title=CWE-22 (Path Traversal)", ann)
        self.assertIn("Untrusted input reaches dangerous sink 'open'", ann)

    def test_03_sca_finding_annotation(self):
        """SCA finding emits annotation with manifest, line, vulnerability ID, and fixed version."""
        scan_result = {
            "sca_findings": [
                {
                    "package_name": "requests",
                    "installed_version": "2.25.0",
                    "vulnerability_id": "GHSA-j8r2-6x86-q33q",
                    "severity": "HIGH",
                    "status": "CONFIRMED",
                    "fixed_version": "2.31.0",
                    "manifest_source": "requirements.txt",
                    "line_number": 14,
                }
            ]
        }
        annotations = format_github_annotations(scan_result)
        self.assertEqual(len(annotations), 1)
        ann = annotations[0]
        self.assertTrue(ann.startswith("::error "))
        self.assertIn("file=requirements.txt", ann)
        self.assertIn("line=14", ann)
        self.assertIn("title=SCA (GHSA-j8r2-6x86-q33q)", ann)
        self.assertIn("requests 2.25.0 is affected (GHSA-j8r2-6x86-q33q); fixed in 2.31.0", ann)

    def test_04_sca_unresolved_annotation(self):
        """SCA UNRESOLVED produces ::warning, is never omitted, and surfaces clearly."""
        scan_result = {
            "sca_findings": [
                {
                    "package_name": "custom-lib",
                    "requested_specifier": ">=1.0",
                    "vulnerability_id": "UNRESOLVED",
                    "severity": "UNKNOWN",
                    "status": "UNRESOLVED",
                    "manifest_source": "Pipfile.lock",
                    "line_number": 20,
                    "summary": "Vulnerability data could not be verified for package 'custom-lib'",
                }
            ]
        }
        annotations = format_github_annotations(scan_result)
        self.assertEqual(len(annotations), 1)
        ann = annotations[0]
        self.assertTrue(ann.startswith("::warning "))
        self.assertIn("file=Pipfile.lock", ann)
        self.assertIn("line=20", ann)
        self.assertIn("title=SCA Unresolved (custom-lib)", ann)
        self.assertIn("Vulnerability data could not be verified", ann)

    def test_05_secret_annotation_zero_cleartext(self):
        """Secret annotation maps to CWE-798, formats masked value, and NEVER leaks raw secret."""
        raw_token = "AKIA" + "IOSFODNN7EXAMPLE"
        masked = "AKIA************MPLE"

        scan_result = {
            "secret_findings": [
                {
                    "secret_type": "aws_access_key",
                    "masked_value": masked,
                    "file": "config/aws.conf",
                    "line_number": 7,
                    "column_start": 1,
                    "column_end": 20,
                    "confidence": "HIGH",
                    "detector": "aws_access_key",
                    "cwe": "CWE-798",
                }
            ]
        }
        annotations = format_github_annotations(scan_result)
        self.assertEqual(len(annotations), 1)
        ann = annotations[0]
        self.assertTrue(ann.startswith("::error "))
        self.assertIn("file=config/aws.conf", ann)
        self.assertIn("line=7", ann)
        self.assertIn("col=1", ann)
        self.assertIn("endColumn=20", ann)
        self.assertIn("title=CWE-798 (AWS Access Key)", ann)
        self.assertIn(f"Hardcoded AWS Access Key detected: {masked}", ann)

        # Zero cleartext leakage check
        self.assertNotIn(raw_token, ann)

    def test_06_tri_engine_mixed_scan_annotations(self):
        """Tri-engine scan outputs annotations from SAST, SCA, and Secrets in deterministic order."""
        scan_result = {
            "findings": [
                {
                    "cwe": "CWE-89",
                    "severity": "CRITICAL",
                    "file": "src/db.py",
                    "line_number": 30,
                    "column_start": 4,
                    "sink_symbol": "cursor.execute",
                }
            ],
            "sca_findings": [
                {
                    "package_name": "flask",
                    "installed_version": "0.12.0",
                    "vulnerability_id": "GHSA-m2qf-cpw2-hp3x",
                    "severity": "HIGH",
                    "status": "CONFIRMED",
                    "fixed_version": "1.0",
                    "manifest_source": "requirements.txt",
                    "line_number": 2,
                }
            ],
            "secret_findings": [
                {
                    "secret_type": "github_token",
                    "masked_value": "ghp_********************************",
                    "file": ".env",
                    "line_number": 1,
                    "column_start": 1,
                    "column_end": 40,
                    "confidence": "HIGH",
                    "detector": "github_token",
                }
            ],
        }
        annotations = format_github_annotations(scan_result)
        self.assertEqual(len(annotations), 3)

        # Deterministic order by file: .env (Secrets), requirements.txt (SCA), src/db.py (SAST)
        self.assertIn(".env", annotations[0])
        self.assertIn("CWE-798 (GitHub Token)", annotations[0])

        self.assertIn("requirements.txt", annotations[1])
        self.assertIn("GHSA-m2qf-cpw2-hp3x", annotations[1])

        self.assertIn("src/db.py", annotations[2])
        self.assertIn("CWE-89", annotations[2])

    def test_07_clean_scan_step_summary(self):
        """Clean scan generates structured Markdown with CLEAN statuses and 0 counts."""
        scan_result = {
            "findings": [],
            "sca_findings": [],
            "secret_findings": [],
        }
        md = generate_step_summary(scan_result)
        self.assertIn("# TimeCodeSecurity Scan", md)
        self.assertIn("| Engine | Status | Findings |", md)
        self.assertIn("| SAST | CLEAN | 0 |", md)
        self.assertIn("| SCA | CLEAN | 0 |", md)
        self.assertIn("| Secrets | CLEAN | 0 |", md)
        self.assertIn("| Total findings | 0 |", md)
        self.assertIn("*No vulnerabilities detected across active scanners.*", md)

    def test_08_mixed_scan_step_summary(self):
        """Mixed scan generates complete metrics and separate findings tables."""
        raw_key = "AKIA" + "DUMMYSECRET99999"
        scan_result = {
            "findings": [
                {
                    "cwe": "CWE-95",
                    "severity": "HIGH",
                    "file": "server.py",
                    "line_number": 10,
                    "sink_symbol": "exec",
                }
            ],
            "sca_findings": [
                {
                    "package_name": "urllib3",
                    "vulnerability_id": "GHSA-q2x7-8rv6-6q7h",
                    "severity": "MEDIUM",
                    "status": "CONFIRMED",
                    "fixed_version": "1.26.5",
                    "manifest_source": "requirements.txt",
                    "line_number": 5,
                }
            ],
            "secret_findings": [
                {
                    "secret_type": "aws_access_key",
                    "masked_value": "AKIA************9999",
                    "file": "prod.env",
                    "line_number": 3,
                    "confidence": "HIGH",
                    "detector": "aws_access_key",
                }
            ],
        }
        md = generate_step_summary(scan_result)
        self.assertIn("# TimeCodeSecurity Scan", md)
        self.assertIn("| SAST | FOUND | 1 |", md)
        self.assertIn("| SCA | FOUND | 1 |", md)
        self.assertIn("| Secrets | FOUND | 1 |", md)
        self.assertIn("| Total findings | 3 |", md)

        self.assertIn("### SAST Code Analysis", md)
        self.assertIn("| CWE-95 | HIGH | `server.py:10` | exec |", md)

        self.assertIn("### SCA Dependencies", md)
        self.assertIn("| urllib3 | GHSA-q2x7-8rv6-6q7h | MEDIUM | CONFIRMED | 1.26.5 | `requirements.txt:5` |", md)

        self.assertIn("### Secret Scanning (CWE-798)", md)
        self.assertIn("| AWS Access Key | `AKIA************9999` | `prod.env:3` | HIGH | aws_access_key |", md)

        # Zero cleartext leakage
        self.assertNotIn(raw_key, md)

    def test_09_sca_unresolved_step_summary(self):
        """SCA UNRESOLVED status is surfaced in Engine Status and Security Metrics."""
        scan_result = {
            "findings": [],
            "sca_findings": [
                {
                    "package_name": "internal-pkg",
                    "vulnerability_id": "UNRESOLVED",
                    "severity": "UNKNOWN",
                    "status": "UNRESOLVED",
                    "manifest_source": "requirements.txt",
                    "line_number": 1,
                }
            ],
        }
        md = generate_step_summary(scan_result)
        self.assertIn("| SCA | UNRESOLVED | 1 |", md)
        self.assertIn("| SCA unresolved | 1 |", md)
        self.assertIn("| Total findings | 1 |", md)
        self.assertIn("UNRESOLVED", md)

    def test_10_malicious_newline_injection(self):
        """Malicious control characters in properties or messages are percent-encoded and do not inject new commands."""
        malicious_file = "config.py\r\n::error file=evil.py,line=1::INJECTED_COMMAND"
        malicious_msg = "Untrusted input\r\n::error file=evil.py,line=2::INJECTED_MESSAGE"
        malicious_title = "CWE-95\n::error::INJECTED_TITLE"

        scan_result = {
            "findings": [
                {
                    "cwe": malicious_title,
                    "severity": "HIGH",
                    "file": malicious_file,
                    "line_number": 10,
                    "flow_trace_summary": malicious_msg,
                }
            ]
        }
        annotations = format_github_annotations(scan_result)
        self.assertEqual(len(annotations), 1)
        ann = annotations[0]

        # The output must contain NO literal newlines or carriage returns
        self.assertNotIn("\r", ann)
        self.assertNotIn("\n", ann)

        # Confirm control characters and colons were percent-encoded
        self.assertIn("%0A", ann)
        self.assertIn("%0D", ann)
        self.assertIn("%3A", ann)

        # Verify output produces strictly ONE workflow command line
        lines = ann.splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("::error "))

    def test_11_path_normalization(self):
        """Windows backslashes are normalized to forward slashes in annotations and summaries."""
        scan_result = {
            "findings": [
                {
                    "cwe": "CWE-78",
                    "severity": "HIGH",
                    "file": "src\\backend\\subsystem\\runner.py",
                    "line_number": 45,
                }
            ]
        }
        annotations = format_github_annotations(scan_result)
        self.assertEqual(len(annotations), 1)
        self.assertIn("file=src/backend/subsystem/runner.py", annotations[0])
        self.assertNotIn("\\", annotations[0])

        md = generate_step_summary(scan_result)
        self.assertIn("`src/backend/subsystem/runner.py:45`", md)
        self.assertNotIn("\\", md)

    def test_12_missing_coordinates_handling(self):
        """Missing or zero line/column coordinates are cleanly omitted without fabricating '0'."""
        scan_result = {
            "findings": [
                {
                    "cwe": "CWE-502",
                    "severity": "HIGH",
                    "file": "untrusted.py",
                    "line_number": None,
                    "column_start": 0,  # 0 is not a valid 1-based coordinate
                }
            ]
        }
        annotations = format_github_annotations(scan_result)
        self.assertEqual(len(annotations), 1)
        ann = annotations[0]
        self.assertIn("file=untrusted.py", ann)
        self.assertNotIn("line=", ann)
        self.assertNotIn("col=", ann)

    def test_13_determinism_50_iterations(self):
        """Verify that identical scan results produce byte-for-byte identical output over 50 iterations."""
        scan_result = {
            "findings": [
                {"cwe": "CWE-89", "severity": "HIGH", "file": "b.py", "line_number": 10},
                {"cwe": "CWE-78", "severity": "CRITICAL", "file": "a.py", "line_number": 5},
            ],
            "sca_findings": [
                {"package_name": "pkg-z", "vulnerability_id": "GHSA-zzzz", "manifest_source": "reqs.txt", "line_number": 1},
                {"package_name": "pkg-a", "vulnerability_id": "GHSA-aaaa", "manifest_source": "reqs.txt", "line_number": 2},
            ],
            "secret_findings": [
                {"secret_type": "slack_token", "masked_value": "xoxb-********", "file": "z.env", "line_number": 1},
                {"secret_type": "aws_access_key", "masked_value": "AKIA********", "file": "a.env", "line_number": 1},
            ],
        }

        baseline_ann = format_github_annotations(scan_result)
        baseline_summary = generate_step_summary(scan_result)

        for _ in range(50):
            current_ann = format_github_annotations(scan_result)
            current_summary = generate_step_summary(scan_result)
            self.assertEqual(baseline_ann, current_ann)
            self.assertEqual(baseline_summary, current_summary)

    def test_14_zero_network_access(self):
        """Verify that opening socket connections raises RuntimeError."""
        s = socket.socket()
        try:
            with self.assertRaises(RuntimeError):
                s.connect(("127.0.0.1", 80))
        finally:
            s.close()

    def test_15_inactive_engine_representation(self):
        """When optional engines are not in the scan result, they are marked INACTIVE in step summary."""
        scan_result = {
            "findings": [
                {"cwe": "CWE-95", "severity": "HIGH", "file": "app.py", "line_number": 1}
            ]
        }
        md = generate_step_summary(scan_result)
        self.assertIn("| SAST | FOUND | 1 |", md)
        self.assertIn("| SCA | INACTIVE | - |", md)
        self.assertIn("| Secrets | INACTIVE | - |", md)

    def test_16_suppressed_sast_findings_omitted_from_annotations(self):
        """Suppressed SAST findings are omitted from active GitHub annotations."""
        scan_result = {
            "findings": [
                {
                    "cwe": "CWE-89",
                    "severity": "HIGH",
                    "file": "query.py",
                    "line_number": 15,
                    "suppressed": True,
                    "suppression_justification": "Internal static query",
                },
                {
                    "cwe": "CWE-78",
                    "severity": "HIGH",
                    "file": "shell.py",
                    "line_number": 22,
                    "suppressed": False,
                },
            ]
        }
        annotations = format_github_annotations(scan_result)
        self.assertEqual(len(annotations), 1)
        self.assertIn("shell.py", annotations[0])
        self.assertNotIn("query.py", annotations[0])

    def test_17_write_step_summary_helper(self):
        """write_step_summary correctly returns content and writes to provided stream."""
        import io
        buf = io.StringIO()
        res = write_step_summary({"findings": []}, output_stream=buf)
        self.assertEqual(res, buf.getvalue())
        self.assertIn("# TimeCodeSecurity Scan", res)


if __name__ == "__main__":
    unittest.main(verbosity=2)
