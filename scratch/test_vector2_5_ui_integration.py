#!/usr/bin/env python3
"""
Adversarial Verification Suite for Vector 2.5 (Phase 2 & 3: Flet Graph & Secrets).

Tests:
1. Unified pipeline execution: collects BOTH SAST findings and Secrets findings into state.
2. 47-line adversarial snippet detection (4 SAST + 2 Secrets = 6 total flaws).
3. Right container Proof Graph rendering (build_proof_graph_view):
   - SOURCE hop (Amber border + Input icon)
   - Intermediate hops (Blue/Grey border + Route icon)
   - SINK hop (Red border + Danger icon)
   - Downward arrows between hops
   - Centered placeholder when unselected
4. Secret Findings integration:
   - CWE-798 secret cards with masked secrets, snippet, line number, remediation advice
5. Interactive click selection updating the right container dynamically.
"""

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

APP_ROOT = Path(r"c:\Users\aarti gaur\OneDrive\Desktop\tcas.app")
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

import flet as ft
from main import (
    main,
    build_proof_graph_view,
    build_secret_view,
    build_finding_tile,
    get_button_text,
    COLOR_AMBER,
    COLOR_BLUEGREY,
    COLOR_RED,
    ICON_INPUT,
    ICON_ROUTE,
    ICON_WARN,
    ICON_ARROW,
    ICON_KEY,
)
DUMMY_STRIPE_SECRET = "".join(["sk_", "live_", "51ABC12345678901234567890abcdef"])

SNIPPET_47_LINES = """import os
import subprocess
from flask import request

STRIPE_KEY = "__DUMMY_STRIPE_KEY__"
DATABASE_URL = "postgresql://admin:super_secret_pw123@localhost:5432/maindb"

def handle_request(cursor):
    # 1. SQLi: cursor.execute(f"...{user_query}")
    user_query = request.args.get('q')
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_query}'")

    # 2. Path Traversal: open(os.path.join(..., doc_name))
    doc_name = request.args.get('doc')
    open(os.path.join('/tmp', doc_name))

    # 3. Command Injection: subprocess.check_output(f"traceroute {target_ip}", shell=True)
    target_ip = request.args.get('ip')
    subprocess.check_output(f"traceroute {target_ip}", shell=True)

    # 4. Code Execution: eval(formula)
    formula = request.args.get('f')
    eval(formula)
""".replace("__DUMMY_STRIPE_KEY__", DUMMY_STRIPE_SECRET)


class MockPage:
    def __init__(self):
        self.title = ""
        self.bgcolor = ""
        self.vertical_alignment = None
        self.horizontal_alignment = None
        self.theme_mode = None
        self.controls = []
        self.overlay = []
        self.token = "test-token-jwt-12345"
        self.client_storage = self

    def get(self, key):
        if key == "token":
            return "test-token-jwt-12345"
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
    if acc is None:
        acc = []
    if isinstance(control, ft.Text):
        if control.value:
            acc.append(str(control.value))
    elif hasattr(control, "content") and control.content:
        extract_all_texts(control.content, acc)
    elif hasattr(control, "controls") and control.controls:
        for c in control.controls:
            extract_all_texts(c, acc)
    return acc


def extract_all_icons(control, acc=None):
    if acc is None:
        acc = []
    if isinstance(control, ft.Icon):
        val = getattr(control, "icon", None) or getattr(control, "name", None)
        if val is not None:
            acc.append(val)
    elif hasattr(control, "content") and control.content:
        extract_all_icons(control.content, acc)
    elif hasattr(control, "controls") and control.controls:
        for c in control.controls:
            extract_all_icons(c, acc)
    return acc


class TestVector25UIIntegration(unittest.TestCase):

    def test_01_empty_proof_graph_placeholder(self):
        """Verifies that an empty proof graph renders the exact placeholder."""
        view = build_proof_graph_view([])
        self.assertIsInstance(view, ft.Container)
        texts = extract_all_texts(view)
        self.assertTrue(
            any("Select a vulnerability to inspect proof path" in t for t in texts),
            f"Expected placeholder not found in texts: {texts}"
        )

    def test_02_dashboard_unified_scan(self):
        """Loads dashboard, enters 47-line snippet, runs scan, and verifies 6 findings."""
        page = MockPage()
        main(page)

        # Locate controls on dashboard
        code_input = None
        scan_button = None
        results_container = None

        for c in page.controls:
            if isinstance(c, ft.TextField) and c.hint_text and "Paste your" in c.hint_text:
                code_input = c
            elif isinstance(c, ft.ElevatedButton) and "SCAN" in get_button_text(c):
                scan_button = c
            elif isinstance(c, ft.Column) and len(c.controls) >= 3:
                results_container = c

        self.assertIsNotNone(code_input, "code_input TextField not found")
        self.assertIsNotNone(scan_button, "scan_button ElevatedButton not found")
        self.assertIsNotNone(results_container, "results_container Column not found")

        # Set 47-line adversarial code
        code_input.value = SNIPPET_47_LINES

        # Trigger scan
        scan_button.on_click(None)

        # Inspect results container components
        summary_banner = results_container.controls[0]
        results_row = results_container.controls[1]

        summary_texts = extract_all_texts(summary_banner)
        summary_str = " ".join(summary_texts)
        self.assertIn("6 Flaws Identified", summary_str)
        self.assertIn("4 SAST", summary_str)
        self.assertIn("2 Secrets", summary_str)

        # Inspect left container (Findings List)
        left_container = results_row.controls[0]
        # left_container contains a column with header and left_list_column
        left_list_column = left_container.content.controls[1]
        finding_tiles = left_list_column.controls
        self.assertEqual(len(finding_tiles), 6, f"Expected 6 finding tiles in list, got {len(finding_tiles)}")

        # Verify finding types in the list
        left_texts = extract_all_texts(left_list_column)
        left_str = " ".join(left_texts)
        self.assertIn("CWE-89", left_str)
        self.assertIn("CWE-22", left_str)
        self.assertIn("CWE-78", left_str)
        self.assertIn("CWE-95", left_str)
        self.assertIn("CWE-798", left_str)

    def test_03_sast_proof_graph_hop_structure(self):
        """Verifies each SAST finding produces the exact required hop cards and arrows."""
        page = MockPage()
        main(page)

        code_input = [c for c in page.controls if isinstance(c, ft.TextField) and "Paste" in (c.hint_text or "")][0]
        scan_button = [c for c in page.controls if isinstance(c, ft.ElevatedButton) and "SCAN" in get_button_text(c)][0]
        results_container = [c for c in page.controls if isinstance(c, ft.Column) and len(c.controls) >= 3][0]

        code_input.value = SNIPPET_47_LINES
        scan_button.on_click(None)

        results_row = results_container.controls[1]
        left_list_column = results_row.controls[0].content.controls[1]
        right_container = results_row.controls[1]

        # First 4 tiles are SAST findings
        sast_cwes_tested = set()
        for idx in range(4):
            tile = left_list_column.controls[idx]
            # Click tile to select
            tile.on_click(None)

            # Inspect right container
            graph_view = right_container.content
            self.assertIsInstance(graph_view, ft.Column, "Proof graph view must be a Column")

            graph_texts = extract_all_texts(graph_view)
            graph_str = " ".join(graph_texts)

            # 1. Verify SOURCE hop
            self.assertIn("HOP 1: SOURCE", graph_str)
            self.assertIn("Taint Origin", graph_str)

            # 2. Verify SINK hop
            self.assertIn("SINK", graph_str)
            self.assertIn("Exploitation Point", graph_str)

            # 3. Verify Downward arrow exists between hops
            icons = extract_all_icons(graph_view)
            self.assertIn(ICON_ARROW, icons, "Proof graph must contain downward arrows between hops")

            # 4. Verify input and warning icons exist
            self.assertIn(ICON_INPUT, icons, "Proof graph must contain SOURCE input icon")
            self.assertIn(ICON_WARN, icons, "Proof graph must contain SINK warning icon")

            # 5. Verify Remediation advice exists
            self.assertIn("Remediation Advice", graph_str)

            if "CWE-89" in graph_str:
                sast_cwes_tested.add("CWE-89")
                self.assertIn("cursor.execute", graph_str)
            elif "CWE-22" in graph_str:
                sast_cwes_tested.add("CWE-22")
                self.assertIn("open", graph_str)
            elif "CWE-78" in graph_str:
                sast_cwes_tested.add("CWE-78")
                self.assertIn("subprocess.check_output", graph_str)
            elif "CWE-95" in graph_str:
                sast_cwes_tested.add("CWE-95")
                self.assertIn("eval", graph_str)
                # Verify intermediate ASSIGNMENT hop for eval
                self.assertIn("ASSIGNMENT", graph_str)
                self.assertIn(ICON_ROUTE, icons, "eval finding must contain intermediate route icon")

        self.assertEqual(len(sast_cwes_tested), 4, f"All 4 SAST CWEs must be verified: {sast_cwes_tested}")

    def test_04_secret_findings_cards(self):
        """Verifies selecting secret findings renders clean Secret Cards with redaction."""
        page = MockPage()
        main(page)

        code_input = [c for c in page.controls if isinstance(c, ft.TextField) and "Paste" in (c.hint_text or "")][0]
        scan_button = [c for c in page.controls if isinstance(c, ft.ElevatedButton) and "SCAN" in get_button_text(c)][0]
        results_container = [c for c in page.controls if isinstance(c, ft.Column) and len(c.controls) >= 3][0]

        code_input.value = SNIPPET_47_LINES
        scan_button.on_click(None)

        results_row = results_container.controls[1]
        left_list_column = results_row.controls[0].content.controls[1]
        right_container = results_row.controls[1]

        # Tiles 4 and 5 are Secret findings
        secret_types_tested = set()
        for idx in (4, 5):
            tile = left_list_column.controls[idx]
            tile.on_click(None)

            secret_view = right_container.content
            self.assertIsInstance(secret_view, ft.Column)

            secret_texts = extract_all_texts(secret_view)
            secret_str = " ".join(secret_texts)

            # 1. Verify CWE-798 Header
            self.assertIn("CWE-798: HARDCODED SECRET", secret_str)
            self.assertIn("CRITICAL", secret_str)

            # 2. Verify Zero-Leak Masked Value
            self.assertIn("Masked Value (Zero-Leak Redacted)", secret_str)
            # Must NOT leak raw secret
            self.assertNotIn(DUMMY_STRIPE_SECRET, secret_str)
            self.assertNotIn("super_secret_pw123", secret_str)

            # 3. Verify Remediation advice
            self.assertIn("Remediation & Redaction Advice", secret_str)

            if "stripe_key" in secret_str:
                secret_types_tested.add("stripe_key")
                self.assertIn("Line 5", secret_str)
            elif "database_connection_string" in secret_str:
                secret_types_tested.add("database_connection_string")
                self.assertIn("Line 6", secret_str)

        self.assertEqual(len(secret_types_tested), 2, f"Both secret types must be verified: {secret_types_tested}")


if __name__ == "__main__":
    unittest.main()
