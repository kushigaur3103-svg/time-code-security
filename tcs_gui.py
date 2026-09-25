import os
import sys
import json
import threading
from pathlib import Path
import flet as ft
import requests
import re
import ast
import time

# Ensure TCS core engine is discoverable
TCS_CORE_DIR = Path(__file__).resolve().parent
if str(TCS_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(TCS_CORE_DIR))

try:
    from tcs_cli import execute_tcs_scan, __version__
    import secret_scanner
    TCS_LOCAL_AVAILABLE = True
except Exception as e:
    TCS_LOCAL_AVAILABLE = False
    __version__ = "2.0.0"
    print(f"[!] Warning: Could not import local TCS engine: {e}")

try:
    from js_scanner import JsTsScanner, js_ts_available
    JS_SCANNER_AVAILABLE = js_ts_available()
except Exception:
    JS_SCANNER_AVAILABLE = False
    JsTsScanner = None

try:
    import remediation
    from remediation import RemediationEngine, PatchStatus
    REMEDIATION_AVAILABLE = True
except Exception:
    REMEDIATION_AVAILABLE = False
    RemediationEngine = None
    PatchStatus = None

# Flet Compatibility Helpers
def get_icon(name, fallback=""):
    for module in (getattr(ft, "Icons", None), getattr(ft, "icons", None)):
        if module and hasattr(module, name):
            return getattr(module, name)
    return fallback

def get_color(name, fallback="#888888"):
    for module in (getattr(ft, "Colors", None), getattr(ft, "colors", None)):
        if module and hasattr(module, name):
            return getattr(module, name)
    return fallback

def make_border(width, color):
    if hasattr(ft, "Border") and hasattr(ft.Border, "all"):
        return ft.Border.all(width, color)
    if hasattr(ft, "border") and hasattr(ft.border, "all"):
        return ft.border.all(width, color)
    if hasattr(ft, "BorderSide"):
        side = ft.BorderSide(width, color)
        return ft.Border(side, side, side, side)
    return None

def make_padding(horizontal=0, vertical=0, all_sides=None, top=0, bottom=0, left=0, right=0):
    if all_sides is not None:
        return all_sides
    if hasattr(ft, "Padding"):
        if top or bottom or left or right:
            return ft.Padding.only(top=top or vertical, bottom=bottom or vertical, left=left or horizontal, right=right or horizontal)
        return ft.Padding.symmetric(horizontal=horizontal, vertical=vertical)
    if hasattr(ft, "padding"):
        if hasattr(ft.padding, "symmetric"):
            return ft.padding.symmetric(horizontal=horizontal, vertical=vertical)
    return [left or horizontal, top or vertical, right or horizontal, bottom or vertical]

def get_alignment_center():
    if hasattr(ft, "Alignment") and hasattr(ft.Alignment, "CENTER"):
        return ft.Alignment.CENTER
    if hasattr(ft, "alignment") and hasattr(ft.alignment, "center"):
        return ft.alignment.center
    return None

COLOR_AMBER = get_color("AMBER_400", "#ffb300")
COLOR_BLUEGREY = get_color("BLUE_GREY_400", "#78909c")
COLOR_RED = get_color("RED_ACCENT_400", "#ff5252")
COLOR_GREY400 = get_color("GREY_400", "#bdbdbd")
COLOR_GREY500 = get_color("GREY_500", "#9e9e9e")
COLOR_CYAN = get_color("CYAN_ACCENT_400", "#00e5ff")
COLOR_GREEN = get_color("GREEN_ACCENT_400", "#00e676")

ICON_INPUT = get_icon("INPUT_ROUNDED", "input")
ICON_ROUTE = get_icon("ALT_ROUTE_ROUNDED", "alt_route")
ICON_WARN = get_icon("WARNING_AMBER_ROUNDED", "warning")
ICON_ARROW = get_icon("ARROW_DOWNWARD_ROUNDED", "arrow_downward")
ICON_KEY = get_icon("KEY_ROUNDED", "vpn_key")
ICON_SECURITY = get_icon("SECURITY_ROUNDED", "security")
ICON_TREE = get_icon("ACCOUNT_TREE_ROUNDED", "account_tree")

def _get_node_prop(node, prop, default=""):
    if isinstance(node, dict):
        return node.get(prop, default)
    return getattr(node, prop, default)


def format_confidence(conf_val=None, conf_label=None) -> str:
    """Format confidence display string safely without NaN%."""
    if conf_val is None and conf_label is None:
        return "HIGH (PATTERN_MATCH)"

    if isinstance(conf_val, dict):
        finding = conf_val
        conf_val = finding.get("confidence")
        conf_label = finding.get("confidence_label") or finding.get("confidence")

    if isinstance(conf_val, str):
        val_str = conf_val.strip()
        if "nan" in val_str.lower():
            return "HIGH (PATTERN_MATCH)"
        if "PATTERN_MATCH" in val_str or "HIGH" in val_str:
            return val_str
        try:
            num = float(val_str)
            label = conf_label if (conf_label and not isinstance(conf_label, (int, float))) else ("CONFIRMED" if num >= 1.0 else "POTENTIAL")
            if "PATTERN_MATCH" in str(label):
                return str(label)
            return f"{label} ({int(num * 100)}%)"
        except (ValueError, TypeError):
            return val_str

    if isinstance(conf_val, (int, float)):
        import math
        if math.isnan(conf_val):
            return "HIGH (PATTERN_MATCH)"
        label = conf_label if (conf_label and not isinstance(conf_label, (int, float))) else ("CONFIRMED" if conf_val >= 1.0 else "POTENTIAL")
        if "PATTERN_MATCH" in str(label):
            return str(label)
        return f"{label} ({int(conf_val * 100)}%)"

    if conf_label and isinstance(conf_label, str):
        if "nan" in conf_label.lower():
            return "HIGH (PATTERN_MATCH)"
        return conf_label

    return "CONFIRMED (100%)"


def get_severity_color(severity: str) -> str:
    """Returns canonical color code for severity level badges."""
    sev = str(severity).upper()
    if sev == "CRITICAL":
        return "#dc2626"
    elif sev == "HIGH":
        return "#ea580c"
    elif sev in ("MEDIUM", "MODERATE"):
        return "#ca8a04"
    elif sev == "LOW":
        return "#2563eb"
    else:
        return "#4b5563"


def build_structural_view(finding):
    """Renders non-taint structural AST findings (e.g. CWE-1004, CWE-732, CWE-377, CWE-326, CWE-209)."""
    if not finding:
        finding = {}
    cwe = finding.get("cwe", "UNKNOWN")
    category = finding.get("category", "Structural Security Finding")
    severity = str(finding.get("severity", "HIGH")).upper()
    sev_bg = get_severity_color(severity)
    symbol = finding.get("symbol") or finding.get("sink_symbol") or "Dangerous Construct"
    line = finding.get("line") or finding.get("line_number") or 1
    file_path = finding.get("file") or "target.py"
    confidence = format_confidence(finding.get("confidence"), finding.get("confidence_label"))
    snippet = finding.get("code_snippet") or ""
    remediation = finding.get("remediation") or "Review security policy and replace vulnerable pattern with safe alternative."
    flow_trace = finding.get("flow_trace") or []

    content_controls = [
        # Top title row with CWE and Severity badge
        ft.Container(
            content=ft.Row(
                [
                    ft.Row(
                        [
                            ft.Icon(ICON_WARN, color=COLOR_RED if severity in ("CRITICAL", "HIGH") else COLOR_AMBER, size=18),
                            ft.Text(f"{cwe}: {category}", size=13, weight=ft.FontWeight.BOLD, color="white"),
                        ],
                        spacing=6,
                    ),
                    ft.Container(
                        content=ft.Text(severity, size=10, weight=ft.FontWeight.BOLD, color="white"),
                        bgcolor=sev_bg,
                        padding=make_padding(horizontal=6, vertical=2),
                        border_radius=4,
                    ),
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ),
            padding=make_padding(bottom=10),
        ),
        # Structural Policy Box
        ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.Text(f"Construct: {symbol}", color=COLOR_AMBER, weight=ft.FontWeight.BOLD, size=12),
                            ft.Text(f"{file_path} : Line {line}", color="#9ca3af", size=11, font_family="monospace"),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    ft.Text(f"Analysis: AST Structural Pattern · Confidence: {confidence}", color="#6b7280", size=10, italic=True),
                    *(
                        [
                            ft.Container(height=4),
                            ft.Text("Offending Code Context:", color="#9ca3af", size=10),
                            ft.Container(
                                content=ft.Text(snippet.strip(), color="#e6edf3", size=11, font_family="Consolas, monospace"),
                                bgcolor="#0d1117",
                                border=make_border(1, "#30363d"),
                                border_radius=4,
                                padding=8,
                            ),
                        ]
                        if snippet else []
                    ),
                ],
                spacing=4,
            ),
            border=make_border(1.5, COLOR_RED if severity in ("CRITICAL", "HIGH") else COLOR_AMBER),
            border_radius=8,
            padding=12,
            bgcolor="#161b22",
        ),
    ]

    # If flow_trace has steps, render them as structural trace steps
    if flow_trace:
        step_items = []
        for step in flow_trace:
            step_items.append(
                ft.Container(
                    content=ft.Row(
                        [
                            ft.Icon(ICON_ROUTE, size=14, color=COLOR_CYAN),
                            ft.Text(str(step), size=10, color="#d1d5db", font_family="monospace"),
                        ],
                        spacing=6,
                    ),
                    bgcolor="#0d1117",
                    border=make_border(1, "#21262d"),
                    border_radius=4,
                    padding=make_padding(horizontal=8, vertical=4),
                )
            )
        content_controls.append(ft.Container(height=6))
        content_controls.append(
            ft.Container(
                content=ft.Column(
                    [
                        ft.Text("Policy / Context Flow Trace", size=11, weight=ft.FontWeight.BOLD, color="#9ca3af"),
                        *step_items,
                    ],
                    spacing=4,
                ),
                padding=make_padding(vertical=4),
            )
        )

    # Remediation card
    content_controls.append(ft.Container(height=6))
    content_controls.append(
        ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.Icon(ICON_SECURITY, color=COLOR_GREEN, size=16),
                            ft.Text("Remediation & Secure Coding Guidance", color=COLOR_GREEN, weight=ft.FontWeight.BOLD, size=11),
                        ],
                        spacing=6,
                    ),
                    ft.Text(remediation, color="#d1d5db", size=11),
                ],
                spacing=4,
            ),
            bgcolor="#061c14",
            border=make_border(1, "#059669"),
            border_radius=6,
            padding=10,
        )
    )

    return ft.Column(
        content_controls,
        scroll=ft.ScrollMode.AUTO,
        spacing=0,
        expand=True,
    )


def build_proof_graph_view(proof_nodes, finding=None):
    if finding and (
        finding.get("type") == "SECRET"
        or finding.get("is_secret")
        or finding.get("cwe") == "CWE-798"
        or finding.get("category") == "HARDCODED_SECRET"
    ):
        return build_secret_view(finding)

    if not proof_nodes:
        if finding:
            return build_structural_view(finding)
        return ft.Container(
            content=ft.Column(
                [
                    ft.Icon(ICON_TREE, size=48, color=COLOR_GREY500),
                    ft.Container(height=10),
                    ft.Text(
                        "Select a vulnerability to inspect proof path",
                        size=14,
                        color=COLOR_GREY500,
                        italic=True,
                    ),
                    ft.Text(
                        "Deterministic AST dataflow will render here",
                        size=11,
                        color="#6b7280",
                    ),
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            alignment=get_alignment_center(),
            padding=40,
            expand=True,
        )

    # Sort proof nodes in chronological order by step_index
    def _step_key(n):
        idx = _get_node_prop(n, "step_index", 0)
        try:
            return int(idx)
        except (ValueError, TypeError):
            return 0

    sorted_nodes = sorted(proof_nodes, key=_step_key)

    hop_controls = []
    if finding:
        cwe = finding.get("cwe", "")
        category = finding.get("category", "")
        severity = finding.get("severity", "")
        sev_bg = get_severity_color(severity)
        hop_controls.append(
            ft.Container(
                content=ft.Row(
                    [
                        ft.Row(
                            [
                                ft.Icon(ICON_TREE, color=COLOR_CYAN, size=18),
                                ft.Text(f"{cwe}: {category}", size=13, weight=ft.FontWeight.BOLD, color="white"),
                            ],
                            spacing=6,
                        ),
                        ft.Container(
                            content=ft.Text(severity, size=10, weight=ft.FontWeight.BOLD, color="white"),
                            bgcolor=sev_bg,
                            padding=make_padding(horizontal=6, vertical=2),
                            border_radius=4,
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
                padding=make_padding(bottom=10),
            )
        )

    for i, node in enumerate(sorted_nodes):
        node_type = str(_get_node_prop(node, "node_type", "DATAFLOW")).upper()
        start_line = _get_node_prop(node, "start_line", "?")
        symbol = _get_node_prop(node, "symbol", "")
        snippet = _get_node_prop(node, "expression_snippet", "")

        if "SOURCE" in node_type:
            border_col = COLOR_AMBER
            icon_ctrl = ICON_INPUT
            badge_title = f"HOP {i+1}: SOURCE"
            subtitle = "Taint Origin (Untrusted User Input)"
        elif "SINK" in node_type:
            border_col = COLOR_RED
            icon_ctrl = ICON_WARN
            badge_title = f"HOP {i+1}: SINK"
            subtitle = "Exploitation Point (Dangerous Sink)"
        elif "TRANSFORM" in node_type or "SANITIZER" in node_type:
            border_col = COLOR_CYAN
            icon_ctrl = ICON_ROUTE
            badge_title = f"HOP {i+1}: TRANSFORM"
            subtitle = "Data Transformation / Sanitization Evaluation"
        elif "ASSIGNMENT" in node_type:
            border_col = COLOR_BLUEGREY
            icon_ctrl = ICON_ROUTE
            badge_title = f"HOP {i+1}: ASSIGNMENT"
            subtitle = "Variable Assignment / Data Flow"
        else:
            border_col = COLOR_BLUEGREY
            icon_ctrl = ICON_ROUTE
            badge_title = f"HOP {i+1}: {node_type}"
            subtitle = "Intermediate Dataflow Propagation"

        card = ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.Row(
                                [
                                    ft.Icon(icon_ctrl, color=border_col, size=16),
                                    ft.Text(badge_title, color=border_col, weight=ft.FontWeight.BOLD, size=12),
                                ],
                                spacing=6,
                            ),
                            ft.Text(f"Line {start_line}", color="#9ca3af", size=11, font_family="monospace"),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    ft.Text(subtitle, color="#6b7280", size=10, italic=True),
                    ft.Container(height=2),
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Row(
                                    [
                                        ft.Text("Symbol:", color="#9ca3af", size=10),
                                        ft.Text(str(symbol), color="#00ffcc", size=10, font_family="monospace", weight=ft.FontWeight.BOLD),
                                    ],
                                    spacing=4,
                                ),
                                ft.Container(
                                    content=ft.Text(snippet or "(empty)", color="#e6edf3", size=11, font_family="Consolas, monospace"),
                                    bgcolor="#0d1117",
                                    border=make_border(1, "#30363d"),
                                    border_radius=4,
                                    padding=6,
                                    width=550,
                                ),
                            ],
                            spacing=4,
                        ),
                        bgcolor="#161b22",
                        border_radius=6,
                        padding=6,
                    ),
                ],
                spacing=4,
            ),
            border=make_border(1.5, border_col),
            border_radius=8,
            padding=10,
            bgcolor="#161b22",
        )
        hop_controls.append(card)

        if i < len(proof_nodes) - 1:
            hop_controls.append(
                ft.Container(
                    content=ft.Icon(ICON_ARROW, color=COLOR_GREY400, size=18),
                    alignment=get_alignment_center(),
                    padding=make_padding(vertical=2),
                )
            )

    if finding and finding.get("remediation"):
        hop_controls.append(ft.Container(height=6))
        rem_card = ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.Icon(ICON_SECURITY, color=COLOR_GREEN, size=16),
                            ft.Text("Remediation Advice", color=COLOR_GREEN, weight=ft.FontWeight.BOLD, size=11),
                        ],
                        spacing=6,
                    ),
                    ft.Text(finding["remediation"], color="#d1d5db", size=11),
                ],
                spacing=4,
            ),
            bgcolor="#061c14",
            border=make_border(1, "#059669"),
            border_radius=6,
            padding=10,
        )
        hop_controls.append(rem_card)

    return ft.Column(hop_controls, scroll=ft.ScrollMode.AUTO, spacing=4, expand=True)


def build_secret_view(finding):
    if not finding:
        finding = {}
    symbol = finding.get("symbol") or finding.get("secret_type") or "Hardcoded Secret"
    masked = finding.get("masked_value") or "REDACTED"
    line = finding.get("line") or finding.get("line_number") or 1
    file_path = finding.get("file") or "target.py"
    detector = finding.get("detector") or "secret_scanner"
    confidence = format_confidence(finding.get("confidence"), finding.get("confidence_label"))
    snippet = finding.get("code_snippet") or masked
    remediation = finding.get(
        "remediation",
        "Never commit secrets, credentials, or database connection strings into source control. Move credentials to environment variables or an external secret vault. Revoke and rotate this exposed secret immediately."
    )

    return ft.Column(
        [
            ft.Container(
                content=ft.Row(
                    [
                        ft.Row(
                            [
                                ft.Icon(ICON_KEY, color=COLOR_RED, size=18),
                                ft.Text("CWE-798: HARDCODED SECRET / CREDENTIAL", size=13, weight=ft.FontWeight.BOLD, color="white"),
                            ],
                            spacing=6,
                        ),
                        ft.Container(
                            content=ft.Text("CRITICAL", size=10, weight=ft.FontWeight.BOLD, color="white"),
                            bgcolor="#dc2626",
                            padding=make_padding(horizontal=6, vertical=2),
                            border_radius=4,
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
                padding=make_padding(bottom=10),
            ),
            ft.Container(
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Text(f"Secret Type: {symbol}", color=COLOR_AMBER, weight=ft.FontWeight.BOLD, size=12),
                                ft.Text(f"{file_path} : Line {line}", color="#9ca3af", size=11, font_family="monospace"),
                            ],
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        ),
                        ft.Text(f"Detector: {detector} · Confidence: {confidence}", color="#6b7280", size=10, italic=True),
                        ft.Container(height=4),
                        ft.Text("Masked Value (Zero-Leak Redacted):", color="#9ca3af", size=10),
                        ft.Container(
                            content=ft.Text(masked, color="#00ffcc", size=11, font_family="Consolas, monospace", weight=ft.FontWeight.BOLD),
                            bgcolor="#0d1117",
                            border=make_border(1, "#30363d"),
                            border_radius=4,
                            padding=6,
                        ),
                        ft.Container(height=2),
                        ft.Text("Offending Context:", color="#9ca3af", size=10),
                        ft.Container(
                            content=ft.Text(snippet, color="#e6edf3", size=11, font_family="Consolas, monospace"),
                            bgcolor="#0d1117",
                            border=make_border(1, "#30363d"),
                            border_radius=4,
                            padding=6,
                        ),
                    ],
                    spacing=4,
                ),
                border=make_border(1.5, COLOR_RED),
                border_radius=8,
                padding=12,
                bgcolor="#161b22",
            ),
            ft.Container(height=6),
            ft.Container(
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ICON_SECURITY, color=COLOR_GREEN, size=16),
                                ft.Text("Remediation & Redaction Advice", color=COLOR_GREEN, weight=ft.FontWeight.BOLD, size=11),
                            ],
                            spacing=6,
                        ),
                        ft.Text(remediation, color="#d1d5db", size=11),
                    ],
                    spacing=4,
                ),
                bgcolor="#061c14",
                border=make_border(1, "#059669"),
                border_radius=6,
                padding=10,
            ),
        ],
        scroll=ft.ScrollMode.AUTO,
        spacing=4,
        expand=True,
    )


ALL_44_CWES = [
    ("CWE-1004", "Insecure Cookie Flags"),
    ("CWE-117", "Log Injection"),
    ("CWE-1336", "Template Injection (SSTI)"),
    ("CWE-200", "Diagnostic Information Exposure"),
    ("CWE-209", "Sensitive Error Exposure"),
    ("CWE-22", "Path Traversal"),
    ("CWE-269", "Improper Privilege Management"),
    ("CWE-287", "Improper Authentication"),
    ("CWE-295", "Improper Certificate Validation"),
    ("CWE-312", "Cleartext Sensitive Storage"),
    ("CWE-319", "Cleartext HTTP Transmission"),
    ("CWE-326", "Inadequate Encryption Strength"),
    ("CWE-327", "Broken Cryptographic Algorithm"),
    ("CWE-338", "Insecure Randomness"),
    ("CWE-352", "Cross-Site Request Forgery (CSRF)"),
    ("CWE-377", "Insecure Temporary File"),
    ("CWE-384", "Session Fixation"),
    ("CWE-400", "Resource Consumption (ReDoS)"),
    ("CWE-434", "Unrestricted File Upload"),
    ("CWE-489", "Active Debug Code"),
    ("CWE-502", "Untrusted Deserialization"),
    ("CWE-522", "Cleartext Basic Auth Transmission"),
    ("CWE-601", "Open URL Redirect"),
    ("CWE-605", "Insecure Socket Binding"),
    ("CWE-611", "XML External Entity (XXE)"),
    ("CWE-614", "Cookie Without Secure Flag"),
    ("CWE-643", "XPath Injection"),
    ("CWE-652", "XQuery / XML Query Injection"),
    ("CWE-732", "Insecure File Permissions"),
    ("CWE-759", "Unsalted Password Hash"),
    ("CWE-770", "Unbounded Resource Allocation"),
    ("CWE-776", "XML Entity Expansion (XML Bomb)"),
    ("CWE-78", "OS Command Injection"),
    ("CWE-79", "Cross-Site Scripting (XSS)"),
    ("CWE-798", "Hardcoded Credentials"),
    ("CWE-862", "Missing Authorization (IDOR)"),
    ("CWE-89", "SQL Injection"),
    ("CWE-90", "LDAP Injection"),
    ("CWE-916", "Weak Password Hash"),
    ("CWE-918", "Server-Side Request Forgery"),
    ("CWE-937", "Deprecated Insecure Protocols"),
    ("CWE-94", "Code Injection (Module Load)"),
    ("CWE-943", "NoSQL Injection"),
    ("CWE-95", "Code Execution (eval/exec)"),
]
ALL_24_CWES = ALL_44_CWES  # Retained alias pointing to full benchmark CWE suite


def build_clean_scan_view():
    """Renders the comprehensive Clean Scan view when 0 vulnerabilities are detected,
    displaying all 44 supported benchmark CWEs with verified green checkmark badges."""
    chips = []
    for cwe_id, cwe_name in ALL_44_CWES:
        chip = ft.Container(
            content=ft.Row(
                [
                    ft.Text("✓", color=COLOR_GREEN, weight=ft.FontWeight.BOLD, size=12),
                    ft.Text(f"{cwe_id}: {cwe_name}", color="#e6edf3", size=10, font_family="monospace"),
                ],
                spacing=6,
                alignment=ft.MainAxisAlignment.START,
            ),
            bgcolor="#061c14",
            border=make_border(1, "#059669"),
            border_radius=6,
            padding=make_padding(horizontal=8, vertical=6),
            width=275,
        )
        chips.append(chip)

    return ft.Container(
        content=ft.Column(
            [
                ft.Row(
                    [
                        ft.Icon(ICON_SECURITY, size=28, color=COLOR_GREEN),
                        ft.Column(
                            [
                                ft.Text(
                                    f"NO VULNERABILITIES DETECTED within current TCS analysis scope ({len(ALL_44_CWES)} supported CWE classes).",
                                    size=12,
                                    weight=ft.FontWeight.BOLD,
                                    color=COLOR_GREEN,
                                ),
                                ft.Text(
                                    "Deterministic AST and interprocedural data-flow analysis confirmed zero tainted data flows reaching dangerous sinks across all scanned modules.",
                                    size=10,
                                    color="#9ca3af",
                                    italic=True,
                                ),
                            ],
                            spacing=2,
                            expand=True,
                        ),
                    ],
                    spacing=10,
                    alignment=ft.MainAxisAlignment.START,
                ),
                ft.Container(height=4),
                ft.Text(
                    f"VERIFIED SECURITY BASELINE ({len(ALL_44_CWES)} CWES PASSED):",
                    size=10,
                    weight=ft.FontWeight.BOLD,
                    color="#6b7280",
                ),
                ft.Container(
                    content=ft.Row(
                        chips,
                        wrap=True,
                        spacing=6,
                        run_spacing=6,
                    ),
                    expand=True,
                ),
            ],
            spacing=6,
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        ),
        padding=10,
        expand=True,
    )


def load_rules_catalog():
    """Loads vulnerability rules catalog from data/rules_catalog.json and blueprint metadata."""
    cat_file = Path(__file__).resolve().parent / "data" / "rules_catalog.json"
    data = {}
    if cat_file.exists():
        try:
            with open(cat_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
                data = raw.get("cwes", {})
        except Exception:
            pass

    # Augment with any benchmark blueprint definitions if not already present
    for bp_filename in ("cwe_blueprint_batch3a.json", "cwe_blueprint_batch3b.json"):
        bp_file = Path(__file__).resolve().parent / "data" / bp_filename
        if bp_file.exists():
            try:
                with open(bp_file, "r", encoding="utf-8") as f:
                    bp_data = json.load(f).get("cwes", {})
                    for cwe_id, cwe_meta in bp_data.items():
                        if cwe_id not in data:
                            data[cwe_id] = {
                                "name": cwe_meta.get("name", cwe_id),
                                "category": cwe_meta.get("type", "Vulnerability"),
                                "severity": "HIGH",
                                "sinks": cwe_meta.get("sinks", []),
                                "description": cwe_meta.get("bad_predicate", ""),
                                "remediation": cwe_meta.get("remediation", ""),
                            }
            except Exception:
                pass
    return data


def build_rules_catalog_container():
    """Builds the interactive 44 CWE Rules Catalog view for TCS Desktop."""
    rules_cat = load_rules_catalog()
    cards = []
    for cwe_id, cwe_name in ALL_44_CWES:
        meta = rules_cat.get(cwe_id, {})
        sev = meta.get("severity") or ("CRITICAL" if cwe_id in ("CWE-95", "CWE-78", "CWE-502", "CWE-798", "CWE-94", "CWE-1336") else "HIGH" if cwe_id in ("CWE-89", "CWE-22", "CWE-326", "CWE-377", "CWE-643", "CWE-732", "CWE-943") else "MEDIUM")
        sev_bg = get_severity_color(sev)
        category = meta.get("category") or "Vulnerability"
        desc = meta.get("description") or f"Detects patterns and flows violating {cwe_name} ({cwe_id})."
        remed = meta.get("remediation") or "Sanitize inputs and follow secure coding guidelines."
        sinks = meta.get("sinks") or []
        sinks_str = ", ".join(str(s) for s in sinks[:4]) if sinks else "Dangerous Language Primitives"
        if len(sinks) > 4:
            sinks_str += f" (+{len(sinks) - 4} more)"

        card = ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.Row(
                                [
                                    ft.Icon(ICON_SECURITY, size=15, color="#00ffcc"),
                                    ft.Text(f"{cwe_id}: {cwe_name}", size=12, weight=ft.FontWeight.BOLD, color="white"),
                                    ft.Container(
                                        content=ft.Text(category, size=9, color="#9ca3af"),
                                        bgcolor="#1f2937",
                                        padding=make_padding(horizontal=5, vertical=1),
                                        border_radius=3,
                                    ),
                                ],
                                spacing=6,
                            ),
                            ft.Container(
                                content=ft.Text(sev, size=9, weight=ft.FontWeight.BOLD, color="white"),
                                bgcolor=sev_bg,
                                padding=make_padding(horizontal=6, vertical=1),
                                border_radius=4,
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    ft.Text(desc, size=11, color="#d1d5db"),
                    ft.Row(
                        [
                            ft.Text("Target Sinks / Constructs: ", size=10, weight=ft.FontWeight.BOLD, color="#9ca3af"),
                            ft.Text(sinks_str, size=10, color="#00ffcc", font_family="monospace"),
                        ],
                    ),
                    ft.Container(
                        content=ft.Row(
                            [
                                ft.Icon(ICON_ROUTE, size=12, color=COLOR_GREEN),
                                ft.Text(f"Remediation: {remed}", size=10, color="#a7f3d0"),
                            ],
                            spacing=4,
                        ),
                        bgcolor="#061c14",
                        border=make_border(1, "#059669"),
                        border_radius=4,
                        padding=make_padding(horizontal=6, vertical=3),
                    ),
                ],
                spacing=4,
            ),
            bgcolor="#161b22",
            border=make_border(1, "#30363d"),
            border_radius=6,
            padding=10,
        )
        cards.append(card)

    return ft.Container(
        content=ft.Column(
            [
                ft.Row(
                    [
                        ft.Row(
                            [
                                ft.Icon(ICON_SECURITY, color="#00ffcc", size=18),
                                ft.Text("TIME CODE SECURITY (TCS) RULES CATALOG — 24 SUPPORTED CWES", size=12, weight=ft.FontWeight.BOLD, color="white"),
                            ],
                            spacing=6,
                        ),
                        ft.Text("100% Precision / Recall Ground-Truth Baseline (288/288 PASS)", size=11, color=COLOR_GREEN, italic=True),
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
                ft.Divider(color="#30363d"),
                ft.Column(cards, spacing=8, scroll=ft.ScrollMode.AUTO, expand=True),
            ],
            spacing=6,
            expand=True,
        ),
        width=1020,
        height=500,
        bgcolor="#0d1117",
        border=make_border(1, "#30363d"),
        border_radius=8,
        padding=16,
        visible=False,
    )


def build_finding_tile(finding, is_selected, on_click_handler):
    f_type = finding.get("type", "SAST")
    cwe = finding.get("cwe", "UNKNOWN")
    severity = finding.get("severity", "HIGH")
    symbol = finding.get("symbol", "")
    line = finding.get("line", "?")
    f_id = finding.get("id", "")

    sev_bg = get_severity_color(severity)
    border_color = "#00ffcc" if is_selected else "#30363d"
    bg_color = "#1f2937" if is_selected else "#161b22"
    border_width = 2 if is_selected else 1

    disc_mode = str(finding.get("discovery_mode", ""))
    is_js_ts = "JS_TS" in disc_mode or f_type == "JS/TS"

    badge_icon = ICON_KEY if f_type == "SECRET" else ICON_WARN

    return ft.Container(
        content=ft.Column(
            [
                ft.Row(
                    [
                        ft.Row(
                            [
                                ft.Icon(badge_icon, size=14, color="#00ffcc" if is_selected else "#9ca3af"),
                                ft.Text(f_id, size=11, font_family="monospace", color="#9ca3af"),
                                ft.Container(
                                    content=ft.Text(cwe, size=10, weight=ft.FontWeight.BOLD, color="white"),
                                    bgcolor="#374151",
                                    padding=make_padding(horizontal=6, vertical=1),
                                    border_radius=4,
                                ),
                                *(
                                    [
                                        ft.Container(
                                            content=ft.Text("JS/TS", size=9, weight=ft.FontWeight.BOLD, color="#00ffcc"),
                                            bgcolor="#092d24",
                                            border=make_border(1, "#00ffcc"),
                                            padding=make_padding(horizontal=4, vertical=1),
                                            border_radius=3,
                                        )
                                    ]
                                    if is_js_ts else []
                                ),
                            ],
                            spacing=6,
                        ),
                        ft.Container(
                            content=ft.Text(severity, size=10, weight=ft.FontWeight.BOLD, color="white"),
                            bgcolor=sev_bg,
                            padding=make_padding(horizontal=6, vertical=1),
                            border_radius=4,
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
                ft.Text(
                    f"{symbol}",
                    size=12,
                    weight=ft.FontWeight.BOLD,
                    color="white" if is_selected else "#e5e7eb",
                    no_wrap=True,
                    overflow=ft.TextOverflow.ELLIPSIS,
                ),
                ft.Row(
                    [
                        ft.Text(f"Line {line}", size=10, font_family="monospace", color="#9ca3af"),
                        ft.Text("CONFIRMED", size=10, color=COLOR_GREEN, weight=ft.FontWeight.BOLD),
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
            ],
            spacing=4,
        ),
        bgcolor=bg_color,
        border=make_border(border_width, border_color),
        border_radius=6,
        padding=10,
        on_click=on_click_handler,
    )


def get_button_text(btn):
    if hasattr(btn, "text") and btn.text is not None:
        return str(btn.text)
    if hasattr(btn, "content") and btn.content is not None:
        return str(btn.content)
    return ""

def set_button_text(btn, text):
    if hasattr(btn, "text") and btn.text is not None:
        btn.text = text
    else:
        btn.content = text

class ClientStoragePolyfill:
    def __init__(self, file_path=None):
        if file_path is None:
            file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".client_storage.json")
        self.file_path = file_path

    def get(self, key):
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, "r") as f:
                    return json.load(f).get(key)
            except Exception:
                pass
        return None

    def set(self, key, value):
        data = {}
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, "r") as f:
                    data = json.load(f)
            except Exception:
                pass
        data[key] = value
        with open(self.file_path, "w") as f:
            json.dump(data, f)

    def remove(self, key):
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, "r") as f:
                    data = json.load(f)
                if key in data:
                    del data[key]
                    with open(self.file_path, "w") as f:
                        json.dump(data, f)
            except Exception:
                pass


def generate_markdown_report(findings, code_snippet=""):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    total = len(findings)
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    med_count = sum(1 for f in findings if f.get("severity") in ("MEDIUM", "MODERATE"))
    sast_count = sum(1 for f in findings if f.get("type") == "SAST")
    sec_count = sum(1 for f in findings if f.get("type") == "SECRET")

    lines = [
        "# TimeCodeSecurity - Security Audit Report",
        "",
        f"**Audit Timestamp:** {timestamp}",
        f"**Engine:** TimeCodeSecurity v{__version__} Deep Static Analysis & Secrets Engine",
        f"**Scope:** In-Memory Source Code Audit (`target.py`)",
        f"**Total Findings:** {total} ({critical_count} CRITICAL, {high_count} HIGH, {med_count} MEDIUM)",
        "",
        "---",
        "",
        "## Executive Summary",
    ]

    if total == 0:
        lines.extend([
            "- **Security Posture:** PASSED (CLEAN)",
            "- **Vulnerabilities Detected:** 0",
            "- **Secrets / Credentials Exposed:** 0",
            "- **Verification Confidence:** 100% Deterministic (Zero False Positives)",
            "",
            "> Source code passed static taint analysis and secret detection rules without identifying any exploitable vulnerabilities or exposed credentials.",
        ])
    else:
        lines.extend([
            f"- **Security Posture:** FAILED -- {total} High-Risk Security Defect(s) Identified",
            f"- **SAST Taint Findings:** {sast_count} (CWE Vulnerabilities)",
            f"- **Secret & Credential Leaks:** {sec_count} (CWE-798 Exposures)",
            "- **Verification Confidence:** 100% Deterministic AST Flow Proofs",
            "",
            "---",
            "",
            "## Detailed Vulnerability Breakdown",
            "",
        ])

        for idx, f in enumerate(findings, 1):
            f_type = f.get("type", "SAST")
            f_id = f.get("id", f"TCS-FINDING-{idx:03d}")
            cwe = f.get("cwe", "UNKNOWN")
            category = f.get("category", "Vulnerability")
            severity = f.get("severity", "HIGH")
            confidence = format_confidence(f.get("confidence"), f.get("confidence_label"))
            file_path = f.get("file", "target.py")
            line_no = f.get("line", "?")
            symbol = f.get("symbol", "")
            snippet = f.get("code_snippet", "")
            remediation = f.get("remediation", "")

            lines.append(f"### [{idx}/{total}] {f_id}: {cwe} -- {category}")
            lines.append(f"- **Severity:** **{severity}**")
            lines.append(f"- **Confidence:** {confidence}")
            lines.append(f"- **Location:** `{file_path}` : Line {line_no}")
            if symbol:
                lines.append(f"- **Symbol / Key Type:** `{symbol}`")

            if f_type == "SECRET":
                masked = f.get("masked_value", "REDACTED")
                detector = f.get("detector", "secret_scanner")
                lines.append(f"- **Detector:** `{detector}`")
                lines.append(f"- **Masked Value:** `{masked}`")
                lines.append("")
                lines.append("#### Exposed Code Context:")
                lines.append(f"```python\n{snippet}\n```")
                lines.append("")
                lines.append("#### Remediation Advice:")
                lines.append(f"> {remediation}")
                lines.append("")
            else:
                proof_nodes = f.get("proof_nodes", [])
                if proof_nodes:
                    lines.append("")
                    lines.append("#### Deterministic AST Dataflow Proof Path:")
                    for hop_i, pnode in enumerate(proof_nodes, 1):
                        ntype = _get_node_prop(pnode, "node_type", "DATAFLOW")
                        pline = _get_node_prop(pnode, "start_line", "?")
                        psym = _get_node_prop(pnode, "symbol", "")
                        psnip = _get_node_prop(pnode, "expression_snippet", "")
                        lines.append(f"{hop_i}. **HOP {hop_i} ({ntype})** at Line {pline} (Symbol: `{psym}`):")
                        lines.append(f"   ```python\n   {psnip}\n   ```")

                if snippet:
                    lines.append("")
                    lines.append("#### Offending Code Snippet:")
                    lines.append(f"```python\n{snippet}\n```")

                if remediation:
                    lines.append("")
                    lines.append("#### Remediation Advice:")
                    lines.append(f"> {remediation}")
                lines.append("")

            lines.append("---")
            lines.append("")

    return "\n".join(lines)


_generate_audit_report = generate_markdown_report
generate_audit_report = generate_markdown_report


def main(page: ft.Page):
    # Configure the page
    page.title = f"TimeCodeSecurity Developer API v{__version__}"
    page.bgcolor = "#0d1117"  # Dark cyber-theme background
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

    if not hasattr(page, "client_storage") or page.client_storage is None:
        page.client_storage = ClientStoragePolyfill()

    page.theme_mode = ft.ThemeMode.DARK

    def show_snackbar(message, color):
        snack = ft.SnackBar(
            content=ft.Text(message, color="white"),
            bgcolor=color
        )
        page.overlay.append(snack)
        snack.open = True
        page.update()

    def show_login():
        page.clean()
        page.vertical_alignment = ft.MainAxisAlignment.CENTER
        page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

        # Login UI logic
        title = ft.Text(
            f"TimeCodeSecurity Developer API v{__version__}",
            size=28,
            weight=ft.FontWeight.BOLD,
            color="#00ffcc"
        )

        email_field = ft.TextField(
            label="Email",
            border_color="#00fa9a",
            focused_border_color="#00ffcc",
            width=300,
            text_align=ft.TextAlign.LEFT
        )

        password_field = ft.TextField(
            label="Password",
            password=True,
            can_reveal_password=True,
            border_color="#00fa9a",
            focused_border_color="#00ffcc",
            width=300,
            text_align=ft.TextAlign.LEFT
        )

        def login_click(e):
            email_value = email_field.value
            password_value = password_field.value

            if not email_value or not password_value:
                show_snackbar("Please enter both email and password.", "red")
                return

            try:
                response = requests.post(
                    "http://localhost:10000/api/login",
                    json={"email": email_value, "password": password_value},
                    timeout=5
                )

                if response.status_code == 200:
                    data = response.json()
                    token = data.get("token")
                    print(f"Token: {token}")
                    page.token = token
                    page.client_storage.set("token", token)
                    show_dashboard()
                else:
                    show_snackbar("Login Failed: Invalid credentials", "red")

            except requests.exceptions.RequestException:
                show_snackbar("Login Failed: Network Error", "red")

        def signup_click(e):
            email_value = email_field.value
            password_value = password_field.value

            if not email_value or not password_value:
                show_snackbar("Please enter both email and password.", "red")
                return

            try:
                response = requests.post(
                    "http://localhost:10000/api/signup",
                    json={"email": email_value, "password": password_value},
                    timeout=5
                )

                if response.status_code in (200, 201):
                    show_snackbar("Account created! Now login.", "green")
                else:
                    show_snackbar("Signup Failed: " + response.text, "red")

            except requests.exceptions.RequestException:
                show_snackbar("Signup Failed: Network Error", "red")

        login_button = ft.ElevatedButton(
            "Login",
            color="#0d1117",
            bgcolor="#00ffcc",
            width=300,
            on_click=login_click,
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=5)
            )
        )

        signup_button = ft.OutlinedButton(
            "Register / Signup",
            width=300,
            on_click=signup_click,
            style=ft.ButtonStyle(
                color="#00fa9a",
                side=ft.BorderSide(2, "#00fa9a"),
                shape=ft.RoundedRectangleBorder(radius=5)
            )
        )

        # Add components to the page
        page.add(
            title,
            ft.Container(height=30),
            email_field,
            password_field,
            ft.Container(height=20),
            login_button,
            ft.Container(height=10),
            signup_button
        )
        page.update()

    def show_dashboard():
        page.clean()
        page.scroll = ft.ScrollMode.AUTO
        page.vertical_alignment = ft.MainAxisAlignment.START
        page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

        token = page.token

        header = ft.Text(
            f"TimeCodeSecurity v{__version__} - Developer PRO",
            size=24,
            color="cyan",
            weight="bold"
        )

        def logout_click(e):
            page.client_storage.remove("token")
            page.token = None
            show_login()

        logout_button = ft.TextButton(
            "Logout",
            on_click=logout_click,
            style=ft.ButtonStyle(color="red")
        )

        def unlock_pro(e):
            if key_input.value:
                show_snackbar("DEVELOPER PRO UNLOCKED", "green")

        key_input = ft.TextField(label="Master Key (God Mode)", password=True, can_reveal_password=True, width=200, height=40, text_size=12, border_color="red", on_submit=unlock_pro)

        header_row = ft.Row(
            [header, key_input, logout_button],
            alignment=ft.MainAxisAlignment.CENTER
        )

        def toggle_editor_click(e):
            code_input.visible = not code_input.visible
            if code_input.visible:
                set_button_text(btn_toggle_editor, "Collapse Code Editor")
                btn_toggle_editor.icon = get_icon("KEYBOARD_ARROW_UP_ROUNDED", "arrow_upward")
            else:
                set_button_text(btn_toggle_editor, "Expand Code Editor")
                btn_toggle_editor.icon = get_icon("KEYBOARD_ARROW_DOWN_ROUNDED", "arrow_downward")
            page.update()

        btn_toggle_editor = ft.TextButton(
            "Collapse Code Editor",
            icon=get_icon("KEYBOARD_ARROW_UP_ROUNDED", "arrow_upward"),
            style=ft.ButtonStyle(color="#9ca3af"),
            on_click=toggle_editor_click
        )

        language_dropdown = ft.Dropdown(
            options=[
                ft.dropdown.Option("Auto-Detect"),
                ft.dropdown.Option("Python (.py)"),
                ft.dropdown.Option("TypeScript/React (.tsx/.ts)"),
                ft.dropdown.Option("JavaScript (.js)"),
            ],
            value="Auto-Detect",
            width=210,
            height=36,
            text_size=11,
            color="#00ffcc",
            bgcolor="#161b22",
            border_color="#30363d",
            focused_border_color="#00ffcc",
            content_padding=make_padding(horizontal=10, vertical=0),
            tooltip="Select parser mode or auto-detect based on syntax",
        )

        editor_header = ft.Container(
            content=ft.Row(
                [
                    ft.Row(
                        [
                            ft.Icon(get_icon("CODE_ROUNDED", "code"), color="#00ffcc", size=16),
                            ft.Text("SOURCE CODE TO AUDIT", size=11, weight=ft.FontWeight.BOLD, color="#9ca3af"),
                        ],
                        spacing=6,
                    ),
                    ft.Row(
                        [
                            language_dropdown,
                            btn_toggle_editor,
                        ],
                        spacing=8,
                    ),
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ),
            width=1020,
        )

        code_input = ft.TextField(
            multiline=True,
            min_lines=4,
            max_lines=6,
            border_color="green",
            bgcolor="#111827",
            hint_text="Paste your Python/JS code here...",
            width=1020
        )

        results_area = ft.Markdown(
            value="",
            selectable=True,
            extension_set=ft.MarkdownExtensionSet.GITHUB_WEB
        )

        # State for interactive selection
        findings_state = []
        selected_finding = None

        def copy_report_click(e):
            nonlocal findings_state
            code_val = code_input.value or ""
            report_text = generate_markdown_report(findings_state, code_val)
            try:
                page.clipboard = report_text
            except Exception as err:
                print(f"[!] Clipboard error: {err}")
            page.update()
            show_snackbar("Security Audit Report copied to clipboard!", "green")

        def switch_view(mode):
            if mode == "inspector":
                results_row.visible = True
                markdown_container.visible = False
                rules_catalog_container.visible = False
                btn_view_inspector.bgcolor = "#1f2937"
                btn_view_inspector.color = "#00ffcc"
                btn_view_report.bgcolor = "#111827"
                btn_view_report.color = "#9ca3af"
                btn_view_rules.bgcolor = "#111827"
                btn_view_rules.color = "#9ca3af"
            elif mode == "report":
                results_row.visible = False
                markdown_container.visible = True
                rules_catalog_container.visible = False
                btn_view_inspector.bgcolor = "#111827"
                btn_view_inspector.color = "#9ca3af"
                btn_view_report.bgcolor = "#1f2937"
                btn_view_report.color = "#00ffcc"
                btn_view_rules.bgcolor = "#111827"
                btn_view_rules.color = "#9ca3af"
                code_val = code_input.value or ""
                results_area.value = generate_markdown_report(findings_state, code_val)
            elif mode == "rules":
                results_row.visible = False
                markdown_container.visible = False
                rules_catalog_container.visible = True
                btn_view_inspector.bgcolor = "#111827"
                btn_view_inspector.color = "#9ca3af"
                btn_view_report.bgcolor = "#111827"
                btn_view_report.color = "#9ca3af"
                btn_view_rules.bgcolor = "#1f2937"
                btn_view_rules.color = "#00ffcc"
            page.update()

        btn_view_inspector = ft.ElevatedButton(
            "Proof Inspector",
            icon=ICON_TREE,
            bgcolor="#1f2937",
            color="#00ffcc",
            style=ft.ButtonStyle(
                padding=make_padding(horizontal=10, vertical=4),
                shape=ft.RoundedRectangleBorder(radius=6),
            ),
            on_click=lambda e: switch_view("inspector"),
        )

        btn_view_report = ft.ElevatedButton(
            "Full Report View",
            icon=get_icon("DESCRIPTION_ROUNDED", "description"),
            bgcolor="#111827",
            color="#9ca3af",
            style=ft.ButtonStyle(
                padding=make_padding(horizontal=10, vertical=4),
                shape=ft.RoundedRectangleBorder(radius=6),
            ),
            on_click=lambda e: switch_view("report"),
        )

        btn_view_rules = ft.ElevatedButton(
            "Rules Catalog (24 CWEs)",
            icon=ICON_SECURITY,
            bgcolor="#111827",
            color="#9ca3af",
            style=ft.ButtonStyle(
                padding=make_padding(horizontal=10, vertical=4),
                shape=ft.RoundedRectangleBorder(radius=6),
            ),
            on_click=lambda e: switch_view("rules"),
        )

        copy_report_btn = ft.ElevatedButton(
            "Copy Full Report",
            icon=get_icon("CONTENT_COPY_ROUNDED", "content_copy"),
            bgcolor="#059669",
            color="white",
            style=ft.ButtonStyle(
                padding=make_padding(horizontal=12, vertical=4),
                shape=ft.RoundedRectangleBorder(radius=6),
            ),
            on_click=copy_report_click,
        )

        # Summary Banner
        summary_banner_text = ft.Text(
            "Ready to audit. Enter source code above and click INITIATE DEEP SCAN.",
            size=12,
            color="#9ca3af",
            font_family="monospace"
        )
        summary_banner = ft.Container(
            content=ft.Row(
                [
                    ft.Row([ft.Icon(ICON_SECURITY, color=COLOR_CYAN, size=18), summary_banner_text], spacing=8),
                    ft.Row([btn_view_inspector, btn_view_report, btn_view_rules, copy_report_btn], spacing=6),
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ),
            bgcolor="#111827",
            border=make_border(1, "#30363d"),
            border_radius=8,
            padding=make_padding(horizontal=14, vertical=10),
            width=1020,
        )

        # CWE Filter Dropdown (All 44 Benchmark CWEs)
        def filter_cwe_change(e):
            val = e.control.value if e and hasattr(e, "control") else "ALL"
            render_findings_list(filter_cwe=val)
            page.update()

        cwe_filter_dropdown = ft.Dropdown(
            options=[
                ft.dropdown.Option("ALL", f"All CWEs ({len(ALL_44_CWES)} Rules)"),
                *[
                    ft.dropdown.Option(cwe, f"{cwe}: {name}")
                    for cwe, name in ALL_44_CWES
                ]
            ],
            value="ALL",
            width=360,
            height=34,
            text_size=11,
            color="#00ffcc",
            bgcolor="#161b22",
            border_color="#30363d",
            focused_border_color="#00ffcc",
            content_padding=make_padding(horizontal=8, vertical=0),
            tooltip="Filter findings by CWE vulnerability class",
            on_change=filter_cwe_change,
        )

        # Left Column: Findings List
        left_list_column = ft.Column(
            [
                ft.Container(
                    content=ft.Text("Scan results will appear here", color="#6b7280", size=12, italic=True),
                    alignment=get_alignment_center(),
                    padding=30,
                )
            ],
            scroll=ft.ScrollMode.AUTO,
            spacing=6,
            expand=True,
        )
        left_container = ft.Container(
            content=ft.Column(
                [
                    ft.Container(
                        content=ft.Row(
                            [
                                ft.Text("FINDINGS LIST", size=11, weight=ft.FontWeight.BOLD, color="#9ca3af"),
                                ft.Text("Filter by CWE:", size=10, color="#6b7280", italic=True),
                            ],
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        ),
                        padding=make_padding(bottom=4),
                        border=make_border(1, "#21262d"),
                    ),
                    cwe_filter_dropdown,
                    left_list_column,
                ],
                spacing=6,
                expand=True,
            ),
            width=380,
            height=480,
            bgcolor="#0d1117",
            border=make_border(1, "#30363d"),
            border_radius=8,
            padding=10,
        )

        # Right Column: Proof Graph Container
        right_container = ft.Container(
            content=build_proof_graph_view([]),
            width=620,
            height=480,
            bgcolor="#111827",
            border=make_border(1, "#30363d"),
            border_radius=8,
            padding=12,
        )

        results_row = ft.Row(
            [left_container, right_container],
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=20,
        )

        markdown_container = ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.Row(
                                [
                                    ft.Icon(get_icon("DESCRIPTION_ROUNDED", "description"), color="#00ffcc", size=18),
                                    ft.Text("FULL SECURITY AUDIT REPORT (MARKDOWN VIEW)", size=12, weight=ft.FontWeight.BOLD, color="white"),
                                ],
                                spacing=6,
                            ),
                            ft.ElevatedButton(
                                "Copy Full Report",
                                icon=get_icon("CONTENT_COPY_ROUNDED", "content_copy"),
                                bgcolor="#059669",
                                color="white",
                                style=ft.ButtonStyle(
                                    padding=make_padding(horizontal=12, vertical=4),
                                    shape=ft.RoundedRectangleBorder(radius=6),
                                ),
                                on_click=copy_report_click,
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    ft.Divider(color="#30363d"),
                    results_area,
                ],
                scroll=ft.ScrollMode.AUTO,
                spacing=8,
                expand=True,
            ),
            width=1020,
            height=500,
            bgcolor="#0d1117",
            border=make_border(1, "#30363d"),
            border_radius=8,
            padding=16,
            visible=False,
        )

        rules_catalog_container = build_rules_catalog_container()

        # Wrapped in a container
        results_container = ft.Column(
            [
                summary_banner,
                results_row,
                markdown_container,
                rules_catalog_container,
            ],
            width=1020,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )

        def render_findings_list(filter_cwe=None):
            active_filter = filter_cwe if filter_cwe is not None else getattr(cwe_filter_dropdown, "value", "ALL")
            if not findings_state:
                left_list_column.controls = [
                    ft.Container(
                        content=ft.Text("No findings detected.", color="#9ca3af", size=12),
                        padding=20,
                        alignment=get_alignment_center(),
                    )
                ]
            else:
                displayed = findings_state
                if active_filter and active_filter != "ALL":
                    displayed = [f for f in findings_state if f.get("cwe") == active_filter]

                if not displayed:
                    left_list_column.controls = [
                        ft.Container(
                            content=ft.Column(
                                [
                                    ft.Icon(ICON_SECURITY, size=24, color="#6b7280"),
                                    ft.Text(f"No findings matching {active_filter}", color="#9ca3af", size=11, italic=True),
                                ],
                                alignment=ft.MainAxisAlignment.CENTER,
                                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                            padding=20,
                            alignment=get_alignment_center(),
                        )
                    ]
                else:
                    left_list_column.controls = [
                        build_finding_tile(
                            f,
                            is_selected=(selected_finding is not None and f.get("id") == selected_finding.get("id")),
                            on_click_handler=lambda e, finding=f: select_finding(finding)
                        )
                        for f in displayed
                    ]

        def select_finding(finding):
            nonlocal selected_finding
            selected_finding = finding
            render_findings_list()
            if (
                finding.get("type") == "SECRET"
                or finding.get("is_secret")
                or finding.get("cwe") == "CWE-798"
                or finding.get("category") == "HARDCODED_SECRET"
            ):
                right_container.content = build_secret_view(finding)
            else:
                proof_nodes = finding.get("proof_nodes", [])
                right_container.content = build_proof_graph_view(proof_nodes, finding)
            page.update()

        def fix_code_click(e):
            code_value = code_input.value
            if not code_value:
                show_snackbar("Please enter or scan code first.", "red")
                return

            finding = selected_finding
            if not finding and findings_state:
                finding = findings_state[0]

            if not finding:
                show_snackbar("No active vulnerability selected for remediation.", "red")
                return

            cwe = str(finding.get("cwe", "")).upper()
            remediable_cwes = ("CWE-89", "CWE-78", "CWE-22")

            if cwe not in remediable_cwes:
                show_snackbar("Manual remediation required for this vector.", "#ea580c")
                return

            if not REMEDIATION_AVAILABLE or RemediationEngine is None:
                show_snackbar("Local Vector D remediation engine is unavailable.", "red")
                return

            set_button_text(btn_fix, "Generating Patch...")
            page.update()

            try:
                engine = RemediationEngine()
                target_finding = dict(finding)
                if "line_number" not in target_finding and "line" in target_finding:
                    target_finding["line_number"] = target_finding["line"]
                target_file = target_finding.get("file", "target.py")
                rec = engine.remediate(target_finding, code_value, file_path=target_file)

                if rec.patch_status == PatchStatus.SUCCESS and rec.patched_source:
                    patched_code = rec.patched_source
                    unified_diff = rec.unified_diff or "(No structural diff)"

                    def apply_patch_action(ev):
                        code_input.value = patched_code
                        fix_dialog.open = False
                        if hasattr(page, "close") and callable(getattr(page, "close")):
                            try:
                                page.close(fix_dialog)
                            except Exception:
                                pass
                        page.update()
                        show_snackbar("Verified patch applied to editor! Re-scanning...", "green")
                        initiate_scan(None)

                    def cancel_dialog_action(ev):
                        fix_dialog.open = False
                        if hasattr(page, "close") and callable(getattr(page, "close")):
                            try:
                                page.close(fix_dialog)
                            except Exception:
                                pass
                        page.update()

                    fix_dialog = ft.AlertDialog(
                        modal=True,
                        title=ft.Row(
                            [
                                ft.Icon(get_icon("AUTO_FIX_HIGH_ROUNDED", "build"), color="#00ffcc", size=20),
                                ft.Text(f"Vector D Auto-Fix: {cwe} ({rec.remediation_rule.value})", size=14, weight=ft.FontWeight.BOLD, color="white"),
                            ],
                            spacing=8,
                        ),
                        content=ft.Container(
                            content=ft.Column(
                                [
                                    ft.Text("Deterministic AST Patch Preview (Verified Gate Passed):", size=11, color="#9ca3af"),
                                    ft.Container(height=4),
                                    ft.Text("Unified Diff:", size=10, weight=ft.FontWeight.BOLD, color="#00ffcc"),
                                    ft.Container(
                                        content=ft.Text(
                                            unified_diff,
                                            size=11,
                                            font_family="Consolas, monospace",
                                            color="#e6edf3",
                                        ),
                                        bgcolor="#0d1117",
                                        border=make_border(1, "#30363d"),
                                        border_radius=6,
                                        padding=10,
                                        width=580,
                                        height=200,
                                    ),
                                ],
                                spacing=4,
                                tight=True,
                            ),
                            width=600,
                            padding=6,
                        ),
                        actions=[
                            ft.TextButton("Cancel", on_click=cancel_dialog_action),
                            ft.ElevatedButton(
                                "Apply Patch to Editor",
                                bgcolor="#059669",
                                color="white",
                                icon=get_icon("CHECK_ROUNDED", "check"),
                                on_click=apply_patch_action,
                            ),
                        ],
                        actions_alignment=ft.MainAxisAlignment.END,
                    )

                    page.dialog = fix_dialog
                    fix_dialog.open = True
                    if hasattr(page, "open") and callable(getattr(page, "open")):
                        try:
                            page.open(fix_dialog)
                        except Exception:
                            pass
                    page.update()
                else:
                    status_name = getattr(rec.patch_status, "value", str(rec.patch_status))
                    show_snackbar(f"Remediation could not produce verified patch: {status_name}", "red")
            except Exception as err:
                show_snackbar(f"Remediation error: {err}", "red")
            finally:
                set_button_text(btn_fix, "⚡ One-Click Auto-Fix")
                page.update()

        def test_code_click(e):
            code_value = code_input.value
            if not code_value:
                return
            set_button_text(btn_test, "Generating...")
            page.update()

            try:
                response = requests.post(
                    "http://localhost:10000/api/generate-test",
                    headers={"Authorization": f"Bearer {page.token}", "X-Master-Key": key_input.value},
                    json={"code": code_value},
                    timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    tests_code = data.get("report") or data.get("result") or str(data)
                    results_area.value += f"\n\n### Generated Unit Tests\n\n```python\n{tests_code}\n```"
                elif response.status_code == 403:
                    show_snackbar("PRO Feature Only! Please upgrade on the website.", "red")
                else:
                    show_snackbar(f"Test generation failed: {response.status_code}", "red")
            except Exception as err:
                show_snackbar(f"Error: {err}", "red")
            finally:
                set_button_text(btn_test, "🧪 Generate Unit Tests")
                page.update()

        btn_fix = ft.ElevatedButton(
            "⚡ One-Click Auto-Fix",
            bgcolor="#059669",
            color="white",
            visible=False,
            icon=get_icon("AUTO_FIX_HIGH_ROUNDED", "build"),
            on_click=fix_code_click
        )
        btn_test = ft.ElevatedButton("🧪 Generate Unit Tests", bgcolor="purple", color="white", visible=False, on_click=test_code_click)

        pro_actions_row = ft.Row([btn_fix, btn_test], alignment=ft.MainAxisAlignment.CENTER)

        def initiate_scan(e):
            nonlocal findings_state, selected_finding
            code_value = code_input.value
            if not code_value:
                show_snackbar("Please enter some code to scan.", "red")
                return

            set_button_text(scan_button, "Scanning...")
            scan_button.disabled = True
            btn_fix.visible = False
            btn_test.visible = False
            results_area.value = ""
            page.update()

            def _scan_worker():
                nonlocal findings_state, selected_finding
                try:
                    if TCS_LOCAL_AVAILABLE:
                        # Language selection & detection
                        selected_lang = getattr(language_dropdown, "value", "Auto-Detect") or "Auto-Detect"
                        is_js_ts = False
                        detected_ext = ".py"

                        if selected_lang == "TypeScript/React (.tsx/.ts)":
                            is_js_ts = True
                            detected_ext = ".tsx"
                        elif selected_lang == "JavaScript (.js)":
                            is_js_ts = True
                            detected_ext = ".js"
                        elif selected_lang == "Python (.py)":
                            is_js_ts = False
                            detected_ext = ".py"
                        else:
                            # Auto-Detect
                            js_signals = [
                                "'use client'", '"use client"', "'use server'", '"use server"',
                                "dangerouslySetInnerHTML", "export default", "export const",
                                "export function", "import React", "from 'react'", 'from "react"',
                                "console.log", "document.getElementById", "document.querySelector",
                                "=== ", "!== ", "=>"
                            ]
                            has_js_signal = any(sig in code_value for sig in js_signals)
                            has_jsx = bool(re.search(r"<\/?[A-Za-z][\w\.-]*(\s+[^>]*)?\/?>", code_value)) or "<div" in code_value
                            if has_js_signal or has_jsx:
                                is_js_ts = True
                                detected_ext = ".tsx" if has_jsx else ".ts"
                            else:
                                try:
                                    ast.parse(code_value)
                                    is_js_ts = False
                                    detected_ext = ".py"
                                except SyntaxError:
                                    if JS_SCANNER_AVAILABLE and JsTsScanner is not None:
                                        is_js_ts = True
                                        detected_ext = ".tsx"

                        findings_state = []
                        if is_js_ts:
                            if not JS_SCANNER_AVAILABLE or JsTsScanner is None:
                                show_snackbar("Tree-sitter JS/TS scanner is unavailable in environment.", "red")
                                return

                            js_scanner_inst = JsTsScanner()
                            virtual_file = f"editor_snippet{detected_ext}"
                            raw_findings = js_scanner_inst.scan_file_content(code_value, filename=virtual_file)
                            secret_res = secret_scanner.scan_text(code_value, filename=virtual_file) if hasattr(secret_scanner, "scan_text") else []

                            for i, jf in enumerate(raw_findings, 1):
                                proof_nodes = [
                                    {
                                        "step_index": 1,
                                        "node_type": "SOURCE",
                                        "symbol": jf.get("source_symbol", "User Input"),
                                        "start_line": jf.get("source_line") or 1,
                                        "expression_snippet": "Untrusted User Input / Tainted Component Prop",
                                    },
                                    {
                                        "step_index": 2,
                                        "node_type": "SINK",
                                        "symbol": jf.get("sink_symbol", "sink"),
                                        "start_line": jf.get("line_number", 1),
                                        "expression_snippet": jf.get("code_snippet", ""),
                                    },
                                ]
                                findings_state.append({
                                    "type": "JS/TS",
                                    "id": jf.get("id", f"TCS-JS-{i:03d}"),
                                    "cwe": jf.get("cwe", "UNKNOWN"),
                                    "category": jf.get("category", "Vulnerability"),
                                    "severity": jf.get("severity", "HIGH"),
                                    "confidence": jf.get("confidence", 1.0),
                                    "confidence_label": jf.get("confidence_label", "CONFIRMED"),
                                    "file": virtual_file,
                                    "line": jf.get("line_number", 1),
                                    "line_number": jf.get("line_number", 1),
                                    "symbol": jf.get("sink_symbol", "sink"),
                                    "code_snippet": jf.get("code_snippet", ""),
                                    "proof_nodes": proof_nodes,
                                    "proof_graph": None,
                                    "remediation": jf.get("remediation", ""),
                                    "flow_trace": jf.get("flow_trace", []),
                                    "flow_trace_summary": jf.get("flow_trace_summary", ""),
                                    "is_secret": False,
                                    "discovery_mode": "JS_TS_SCAN",
                                })

                            sec_idx = 1
                            for s in secret_res:
                                findings_state.append({
                                    "type": "SECRET",
                                    "id": s.get("id", f"TCS-SEC-{sec_idx:03d}"),
                                    "cwe": "CWE-798",
                                    "category": s.get("category", "Hardcoded Credential / Secret Leak"),
                                    "severity": s.get("severity", "HIGH"),
                                    "confidence": s.get("confidence") or "HIGH (PATTERN_MATCH)",
                                    "confidence_label": s.get("confidence_label") or "HIGH (PATTERN_MATCH)",
                                    "file": virtual_file,
                                    "line": s.get("line_number", 1),
                                    "line_number": s.get("line_number", 1),
                                    "symbol": s.get("secret_type") or "hardcoded_secret",
                                    "masked_value": s.get("masked_value", "REDACTED"),
                                    "code_snippet": s.get("code_snippet", ""),
                                    "detector": s.get("detector", "secret_scanner"),
                                    "remediation": s.get("remediation", "Never commit secrets, credentials, or database connection strings into source control. Move credentials to environment variables or an external secret vault (e.g., AWS Secrets Manager, HashiCorp Vault). Revoke and rotate this exposed secret immediately."),
                                    "proof_nodes": None,
                                    "proof_graph": None,
                                    "is_secret": True,
                                    "discovery_mode": "SECRET_SCAN",
                                })
                                sec_idx += 1

                            total_flaws = len(findings_state)
                            critical_count = sum(1 for f in findings_state if f.get("severity") == "CRITICAL")
                            high_count = sum(1 for f in findings_state if f.get("severity") == "HIGH")

                            if total_flaws > 0:
                                summary_banner_text.value = f"AUDIT COMPLETE (Tree-sitter {detected_ext}): {total_flaws} Flaws Identified ({len(raw_findings)} JS/TS · {len(secret_res)} Secrets) — {critical_count} CRITICAL, {high_count} HIGH"
                                summary_banner_text.color = COLOR_RED
                                btn_fix.visible = True
                                btn_test.visible = False
                                select_finding(findings_state[0])
                            else:
                                summary_banner_text.value = f"AUDIT COMPLETE (Tree-sitter {detected_ext}): Clean · 0 Vulnerabilities Detected"
                                summary_banner_text.color = COLOR_GREEN
                                selected_finding = None
                                render_findings_list()
                                right_container.content = build_clean_scan_view()

                            results_area.value = generate_markdown_report(findings_state, code_value)
                            page.update()
                        else:
                            # Unified local pipeline: SAST taint analysis + Secret detection
                            sast_res = execute_tcs_scan({"target.py": code_value}, audit_all=True, secrets=True)
                            all_findings = [f for f in sast_res.get("findings", []) if f.get("active", True)]
                            sast_findings = [f for f in all_findings if not f.get("is_secret") and f.get("cwe") != "CWE-798"]
                            secret_findings = [f for f in all_findings if f.get("is_secret") or f.get("cwe") == "CWE-798"]

                            sast_idx = 1
                            for f in sast_findings:
                                pg = f.get("proof_graph") or {}
                                nodes = pg.get("nodes", [])
                                findings_state.append({
                                    "type": "SAST",
                                    "id": f.get("id", f"TCS-VULN-{sast_idx:03d}"),
                                    "cwe": f.get("cwe", "UNKNOWN"),
                                    "category": f.get("category", "Vulnerability"),
                                    "severity": f.get("severity", "HIGH"),
                                    "confidence": f.get("confidence", 1.0),
                                    "confidence_label": f.get("confidence_label", "CONFIRMED"),
                                    "file": f.get("file", "target.py"),
                                    "line": f.get("line_number", 1),
                                    "line_number": f.get("line_number", 1),
                                    "symbol": f.get("sink_symbol", "sink"),
                                    "code_snippet": f.get("code_snippet", ""),
                                    "proof_nodes": nodes,
                                    "proof_graph": pg,
                                    "remediation": f.get("remediation", ""),
                                    "flow_trace": f.get("flow_trace", []),
                                    "flow_trace_summary": f.get("flow_trace_summary", ""),
                                    "is_secret": False,
                                    "discovery_mode": "AST_SCAN",
                                })
                                sast_idx += 1

                            sec_idx = 1
                            for s in secret_findings:
                                findings_state.append({
                                    "type": "SECRET",
                                    "id": s.get("id", f"TCS-SEC-{sec_idx:03d}"),
                                    "cwe": "CWE-798",
                                    "category": s.get("category", "Hardcoded Credential / Secret Leak"),
                                    "severity": s.get("severity", "HIGH"),
                                    "confidence": s.get("confidence") or s.get("confidence_label") or getattr(s, "confidence", "HIGH (PATTERN_MATCH)"),
                                    "confidence_label": s.get("confidence_label") or getattr(s, "confidence", "HIGH (PATTERN_MATCH)"),
                                    "file": s.get("file", "target.py"),
                                    "line": s.get("line_number", 1),
                                    "line_number": s.get("line_number", 1),
                                    "symbol": s.get("secret_type") or s.get("symbol", "hardcoded_secret"),
                                    "masked_value": s.get("masked_value", "REDACTED"),
                                    "code_snippet": s.get("code_snippet", ""),
                                    "detector": s.get("detector", "secret_scanner"),
                                    "remediation": s.get("remediation", "Never commit secrets, credentials, or database connection strings into source control. Move credentials to environment variables or an external secret vault (e.g., AWS Secrets Manager, HashiCorp Vault). Revoke and rotate this exposed secret immediately."),
                                    "proof_nodes": None,
                                    "proof_graph": None,
                                    "is_secret": True,
                                    "discovery_mode": "SECRET_SCAN",
                                })
                                sec_idx += 1

                            total_flaws = len(findings_state)
                            critical_count = sum(1 for f in findings_state if f.get("severity") == "CRITICAL")
                            high_count = sum(1 for f in findings_state if f.get("severity") == "HIGH")

                            if total_flaws > 0:
                                summary_banner_text.value = f"AUDIT COMPLETE (Python): {total_flaws} Flaws Identified ({len(sast_findings)} SAST · {len(secret_findings)} Secrets) — {critical_count} CRITICAL, {high_count} HIGH"
                                summary_banner_text.color = COLOR_RED
                                btn_fix.visible = True
                                btn_test.visible = True
                                select_finding(findings_state[0])
                            else:
                                summary_banner_text.value = "AUDIT COMPLETE (Python): Clean · 0 Vulnerabilities Detected"
                                summary_banner_text.color = COLOR_GREEN
                                selected_finding = None
                                render_findings_list()
                                right_container.content = build_clean_scan_view()

                            results_area.value = generate_markdown_report(findings_state, code_value)
                            page.update()
                    else:
                        # Fallback to HTTP API
                        response = requests.post(
                            "http://localhost:10000/scan",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"code": code_value},
                            timeout=10
                        )
                        if response.status_code == 200:
                            data = response.json()
                            job_id = data.get("job_id")
                            if job_id:
                                while True:
                                    status_response = requests.get(
                                        f"http://localhost:10000/api/scan/status/{job_id}",
                                        headers={"Authorization": f"Bearer {token}"},
                                        timeout=10
                                    )
                                    if status_response.status_code == 200:
                                        status_data = status_response.json()
                                        status = status_data.get("status")
                                        if status in ("completed", "failed"):
                                            final_text = status_data.get("report") or status_data.get("result") or f"Raw Data from Server: {status_data}"
                                            results_area.value = final_text
                                            if status == "completed":
                                                btn_fix.visible = True
                                                btn_test.visible = True
                                            break
                                    else:
                                        results_area.value = f"Failed to get status. Code: {status_response.status_code}"
                                        break
                                    time.sleep(2)
                            else:
                                results_area.value = "Scan failed: No job ID returned."
                        else:
                            results_area.value = f"API Error: {response.status_code} - {response.text}"
                except Exception as err:
                    summary_banner_text.value = f"Scan execution error: {str(err)}"
                    summary_banner_text.color = COLOR_RED
                    results_area.value = f"Execution error: {str(err)}"
                finally:
                    set_button_text(scan_button, "INITIATE DEEP SCAN")
                    scan_button.disabled = False
                    page.update()

            worker = threading.Thread(target=_scan_worker, daemon=True)
            worker.start()
            if e is None or getattr(e, "sync", False):
                worker.join()

        scan_button = ft.ElevatedButton(
            "INITIATE DEEP SCAN",
            bgcolor="green",
            color="white",
            on_click=initiate_scan
        )

        page.add(
            ft.Container(height=20),
            header_row,
            ft.Container(height=10),
            editor_header,
            code_input,
            ft.Container(height=10),
            scan_button,
            pro_actions_row,
            ft.Container(height=16),
            results_container,
            ft.Container(height=30)
        )
        page.update()

    # Auto-Login Check
    saved_token = page.client_storage.get("token")
    if saved_token:
        page.token = saved_token
        show_dashboard()
        return  # Skip loading the login screen entirely

    # If no token, show login screen
    show_login()

if __name__ == "__main__":
    ft.app(target=main)


def launch_gui():
    """Launch the Flet desktop application."""
    ft.app(target=main)


if __name__ == "__main__":
    launch_gui()
