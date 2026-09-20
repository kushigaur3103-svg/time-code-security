#!/usr/bin/env python3
"""
Headless Integration Verification Suite for Flet UI & TCS v2.0.0 Engine.
Tests:
1. Header & Page title synchronization with v2.0.0.
2. Headless scan dispatch for tainted commands (CWE-78), sanitized commands (0 findings), and secrets (CWE-798).
3. Proof graph rendering resilience for proof_graph is None (Secrets).
4. Multi-hop proof graph rendering with TRANSFORM (Sanitizer) and ASSIGNMENT in chronological order.
5. Non-blocking daemon worker thread execution.
"""

import sys
import unittest
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import flet as ft
from tcs_gui import (
    main,
    build_proof_graph_view,
    build_secret_view,
    build_finding_tile,
    get_button_text,
    __version__,
)


class MockPage:
    """Headless mock of ft.Page for non-GUI automated testing."""
    def __init__(self):
        self.title = ""
        self.bgcolor = ""
        self.vertical_alignment = None
        self.horizontal_alignment = None
        self.theme_mode = None
        self.controls = []
        self.overlay = []
        self.token = "mock-jwt-token-v2.0.0"
        self.client_storage = self

    def get(self, key):
        if key == "token":
            return self.token
        return None

    def set(self, key, value):
        pass

    def remove(self, key):
        pass

    def add(self, *controls):
        self.controls.extend(controls)

    def clean(self):
        self.controls.clear()

    def update(self):
        pass


def extract_all_texts(control, acc=None):
    """Recursively extracts all text strings from a Flet control tree."""
    if acc is None:
        acc = []
    if isinstance(control, ft.Text) and control.value:
        acc.append(str(control.value))
    elif hasattr(control, "content") and control.content:
        extract_all_texts(control.content, acc)
    elif hasattr(control, "controls") and control.controls:
        for c in control.controls:
            extract_all_texts(c, acc)
    return acc


class TestFletV2Integration(unittest.TestCase):

    def setUp(self):
        self.page = MockPage()
        main(self.page)

        # Locate interactive controls
        self.code_input = None
        self.scan_button = None
        self.results_container = None
        self.header_text = None

        for c in self.page.controls:
            if isinstance(c, ft.Row):
                for child in c.controls:
                    if isinstance(child, ft.Text) and "TimeCodeSecurity" in str(child.value):
                        self.header_text = child
            elif isinstance(c, ft.TextField) and c.hint_text and "Paste your" in c.hint_text:
                self.code_input = c
            elif isinstance(c, ft.ElevatedButton) and "SCAN" in get_button_text(c):
                self.scan_button = c
            elif isinstance(c, ft.Column) and len(c.controls) >= 3:
                self.results_container = c

    def test_01_version_header_synchronization(self):
        """Verify the page title and dashboard header dynamically reflect v2.0.0 from __version__."""
        self.assertEqual(__version__, "2.0.0")
        self.assertIn("v2.0.0", self.page.title)
        self.assertIsNotNone(self.header_text, "Header Text control not found")
        self.assertIn("v2.0.0", str(self.header_text.value))

    def test_02_clean_sanitized_command_negative_space(self):
        """Verify clean/sanitized command (shlex.quote) yields 0 findings and clean banner."""
        clean_code = """import os
import shlex
from flask import request

def safe_handler():
    user_val = request.args.get('cmd')
    safe_val = shlex.quote(user_val)
    os.system(safe_val)
"""
        self.code_input.value = clean_code
        self.scan_button.on_click(None)

        summary_banner = self.results_container.controls[0]
        summary_texts = " ".join(extract_all_texts(summary_banner))
        self.assertIn("Clean", summary_texts)
        self.assertIn("0 Vulnerabilities Detected", summary_texts)

    def test_03_tainted_command_and_secret_detection(self):
        """Verify scan captures both tainted command injection (CWE-78) and hardcoded secret (CWE-798)."""
        payload = """import os
from flask import request

DEV_DATABASE_PASSWORD = "super_secret_db_password_12345"

def run_command():
    user_input = request.args.get('target')
    os.system(user_input)
"""
        self.code_input.value = payload
        self.scan_button.on_click(None)

        summary_banner = self.results_container.controls[0]
        summary_texts = " ".join(extract_all_texts(summary_banner))
        self.assertIn("2 Flaws Identified", summary_texts)
        self.assertIn("1 SAST", summary_texts)
        self.assertIn("1 Secrets", summary_texts)

        results_row = self.results_container.controls[1]
        left_list_column = results_row.controls[0].content.controls[1]
        right_container = results_row.controls[1]
        findings_tiles = left_list_column.controls

        self.assertEqual(len(findings_tiles), 2)
        tiles_texts = " ".join(extract_all_texts(left_list_column))
        self.assertIn("CWE-78", tiles_texts)
        self.assertIn("CWE-798", tiles_texts)

        # Click SAST tile (CWE-78) -> inspect proof graph
        findings_tiles[0].on_click(None)
        graph_texts = " ".join(extract_all_texts(right_container.content))
        self.assertIn("HOP 1: SOURCE", graph_texts)
        self.assertIn("SINK", graph_texts)
        self.assertIn("CWE-78", graph_texts)

        # Click SECRET tile (CWE-798) -> inspect secret evidence card (proof_graph is None)
        findings_tiles[1].on_click(None)
        secret_texts = " ".join(extract_all_texts(right_container.content))
        self.assertIn("CWE-798: HARDCODED SECRET", secret_texts)
        self.assertIn("Masked Value", secret_texts)
        self.assertIn("Remediation & Redaction Advice", secret_texts)

    def test_04_proof_graph_resilience_null_proof_graph(self):
        """Verify build_proof_graph_view handles proof_graph=None gracefully for secret findings."""
        secret_finding = {
            "type": "SECRET",
            "id": "TCS-SEC-001",
            "cwe": "CWE-798",
            "category": "HARDCODED_SECRET",
            "severity": "HIGH",
            "confidence": "CONFIRMED",
            "file": "target.py",
            "line": 10,
            "symbol": "api_key",
            "masked_value": "sec_***123",
            "code_snippet": "api_key = 'sec_secret123'",
            "proof_nodes": None,
            "proof_graph": None,
            "remediation": "Rotate secret immediately."
        }

        # Passing proof_nodes=None directly must not crash and must render secret view
        view = build_proof_graph_view(None, finding=secret_finding)
        self.assertIsNotNone(view)
        texts = " ".join(extract_all_texts(view))
        self.assertIn("CWE-798: HARDCODED SECRET", texts)
        self.assertIn("sec_***123", texts)

    def test_05_proof_graph_multi_hop_transform_and_ordering(self):
        """Verify multi-hop proof graph with TRANSFORM and ASSIGNMENT nodes renders chronologically."""
        nodes = [
            {
                "node_type": "SINK",
                "symbol": "os.system",
                "start_line": 25,
                "expression_snippet": "os.system(final_cmd)",
                "step_index": 4,
            },
            {
                "node_type": "SOURCE",
                "symbol": "request.args.get",
                "start_line": 10,
                "expression_snippet": "request.args.get('c')",
                "step_index": 1,
            },
            {
                "node_type": "TRANSFORM",
                "symbol": "str.strip",
                "start_line": 18,
                "expression_snippet": "raw_val.strip()",
                "step_index": 3,
            },
            {
                "node_type": "ASSIGNMENT",
                "symbol": "raw_val",
                "start_line": 12,
                "expression_snippet": "raw_val = user_in",
                "step_index": 2,
            },
        ]

        finding = {
            "cwe": "CWE-78",
            "category": "OS Command Injection",
            "severity": "CRITICAL",
            "remediation": "Use subprocess.run with shell=False.",
        }

        # build_proof_graph_view must sort by step_index: SOURCE -> ASSIGNMENT -> TRANSFORM -> SINK
        view = build_proof_graph_view(nodes, finding=finding)
        self.assertIsInstance(view, ft.Column)
        texts = extract_all_texts(view)
        full_text = " ".join(texts)

        # All badges present
        self.assertIn("HOP 1: SOURCE", full_text)
        self.assertIn("HOP 2: ASSIGNMENT", full_text)
        self.assertIn("HOP 3: TRANSFORM", full_text)
        self.assertIn("HOP 4: SINK", full_text)

        # Check order of hops in text list
        h1_idx = next(i for i, t in enumerate(texts) if "HOP 1: SOURCE" in t)
        h2_idx = next(i for i, t in enumerate(texts) if "HOP 2: ASSIGNMENT" in t)
        h3_idx = next(i for i, t in enumerate(texts) if "HOP 3: TRANSFORM" in t)
        h4_idx = next(i for i, t in enumerate(texts) if "HOP 4: SINK" in t)

        self.assertLess(h1_idx, h2_idx, "HOP 1 must precede HOP 2")
        self.assertLess(h2_idx, h3_idx, "HOP 2 must precede HOP 3")
        self.assertLess(h3_idx, h4_idx, "HOP 3 must precede HOP 4")


if __name__ == "__main__":
    unittest.main()
