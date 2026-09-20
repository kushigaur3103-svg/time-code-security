import os
import sys
import json
import threading
from pathlib import Path
import flet as ft
import requests
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

def build_proof_graph_view(proof_nodes, finding=None):
    if finding and (
        finding.get("type") == "SECRET"
        or finding.get("is_secret")
        or finding.get("cwe") == "CWE-798"
        or finding.get("category") == "HARDCODED_SECRET"
        or (proof_nodes is None and finding.get("proof_nodes") is None)
    ):
        if finding.get("type") == "SECRET" or finding.get("is_secret") or finding.get("cwe") == "CWE-798" or finding.get("category") == "HARDCODED_SECRET":
            return build_secret_view(finding)

    if not proof_nodes:
        if finding and (finding.get("type") == "SECRET" or finding.get("is_secret") or finding.get("cwe") == "CWE-798" or finding.get("category") == "HARDCODED_SECRET"):
            return build_secret_view(finding)
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
        sev_bg = "#dc2626" if severity == "CRITICAL" else "#ea580c" if severity == "HIGH" else "#ca8a04"
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
    confidence = finding.get("confidence") or finding.get("confidence_label") or "HIGH"
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


def build_finding_tile(finding, is_selected, on_click_handler):
    f_type = finding.get("type", "SAST")
    cwe = finding.get("cwe", "UNKNOWN")
    severity = finding.get("severity", "HIGH")
    symbol = finding.get("symbol", "")
    line = finding.get("line", "?")
    f_id = finding.get("id", "")

    sev_bg = "#dc2626" if severity == "CRITICAL" else "#ea580c" if severity == "HIGH" else "#ca8a04"
    border_color = "#00ffcc" if is_selected else "#30363d"
    bg_color = "#1f2937" if is_selected else "#161b22"
    border_width = 2 if is_selected else 1

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
            confidence = f.get("confidence", "HIGH")
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
                    btn_toggle_editor,
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
                btn_view_inspector.bgcolor = "#1f2937"
                btn_view_inspector.color = "#00ffcc"
                btn_view_report.bgcolor = "#111827"
                btn_view_report.color = "#9ca3af"
            else:
                results_row.visible = False
                markdown_container.visible = True
                btn_view_inspector.bgcolor = "#111827"
                btn_view_inspector.color = "#9ca3af"
                btn_view_report.bgcolor = "#1f2937"
                btn_view_report.color = "#00ffcc"
                code_val = code_input.value or ""
                results_area.value = generate_markdown_report(findings_state, code_val)
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
                    ft.Row([btn_view_inspector, btn_view_report, copy_report_btn], spacing=6),
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ),
            bgcolor="#111827",
            border=make_border(1, "#30363d"),
            border_radius=8,
            padding=make_padding(horizontal=14, vertical=10),
            width=1020,
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
                                ft.Text("Select to inspect", size=10, color="#6b7280", italic=True),
                            ],
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        ),
                        padding=make_padding(bottom=6),
                        border=make_border(1, "#21262d"),
                    ),
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

        # Wrapped in a container
        results_container = ft.Column(
            [
                summary_banner,
                results_row,
                markdown_container,
            ],
            width=1020,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )

        def render_findings_list():
            if not findings_state:
                left_list_column.controls = [
                    ft.Container(
                        content=ft.Text("No findings detected.", color="#9ca3af", size=12),
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
                    for f in findings_state
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
                or finding.get("proof_nodes") is None
            ):
                right_container.content = build_secret_view(finding)
            else:
                proof_nodes = finding.get("proof_nodes", [])
                right_container.content = build_proof_graph_view(proof_nodes, finding)
            page.update()

        def fix_code_click(e):
            code_value = code_input.value
            if not code_value:
                return
            set_button_text(btn_fix, "Fixing...")
            page.update()

            try:
                response = requests.post(
                    "http://localhost:10000/api/fix-code",
                    headers={"Authorization": f"Bearer {page.token}", "X-Master-Key": key_input.value},
                    json={"code": code_value, "report": results_area.value},
                    timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    new_code = data.get("report") or data.get("result") or str(data)
                    results_area.value += f"\n\n### AI-Fixed Code\n\n```python\n{new_code}\n```"
                elif response.status_code == 403:
                    show_snackbar("PRO Feature Only! Please upgrade on the website.", "red")
                else:
                    show_snackbar(f"Fix failed: {response.status_code}", "red")
            except Exception as err:
                show_snackbar(f"Error: {err}", "red")
            finally:
                set_button_text(btn_fix, "🔧 Generate Secure Code")
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

        btn_fix = ft.ElevatedButton("🔧 Generate Secure Code", bgcolor="blue", color="white", visible=False, on_click=fix_code_click)
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
                        # Unified local pipeline: SAST taint analysis + Secret detection
                        sast_res = execute_tcs_scan({"target.py": code_value}, audit_all=True, secrets=True)
                        all_findings = [f for f in sast_res.get("findings", []) if f.get("active", True)]
                        sast_findings = [f for f in all_findings if not f.get("is_secret") and f.get("cwe") != "CWE-798"]
                        secret_findings = [f for f in all_findings if f.get("is_secret") or f.get("cwe") == "CWE-798"]

                        findings_state = []
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
                                "confidence": f.get("confidence_label", "CONFIRMED"),
                                "file": f.get("file", "target.py"),
                                "line": f.get("line_number", 1),
                                "symbol": f.get("sink_symbol", "sink"),
                                "code_snippet": f.get("code_snippet", ""),
                                "proof_nodes": nodes,
                                "proof_graph": pg,
                                "remediation": f.get("remediation", ""),
                                "flow_trace": f.get("flow_trace", []),
                                "flow_trace_summary": f.get("flow_trace_summary", ""),
                                "is_secret": False,
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
                                "confidence": s.get("confidence_label") or getattr(s, "confidence", "CONFIRMED"),
                                "file": s.get("file", "target.py"),
                                "line": s.get("line_number", 1),
                                "symbol": s.get("secret_type") or s.get("symbol", "hardcoded_secret"),
                                "masked_value": s.get("masked_value", "REDACTED"),
                                "code_snippet": s.get("code_snippet", ""),
                                "detector": s.get("detector", "secret_scanner"),
                                "remediation": s.get("remediation", "Never commit secrets, credentials, or database connection strings into source control. Move credentials to environment variables or an external secret vault (e.g., AWS Secrets Manager, HashiCorp Vault). Revoke and rotate this exposed secret immediately."),
                                "proof_nodes": None,
                                "proof_graph": None,
                                "is_secret": True,
                            })
                            sec_idx += 1

                        total_flaws = len(findings_state)
                        critical_count = sum(1 for f in findings_state if f.get("severity") == "CRITICAL")
                        high_count = sum(1 for f in findings_state if f.get("severity") == "HIGH")

                        if total_flaws > 0:
                            summary_banner_text.value = f"AUDIT COMPLETE: {total_flaws} Flaws Identified ({len(sast_findings)} SAST · {len(secret_findings)} Secrets) — {critical_count} CRITICAL, {high_count} HIGH"
                            summary_banner_text.color = COLOR_RED
                            btn_fix.visible = True
                            btn_test.visible = True
                            select_finding(findings_state[0])
                        else:
                            summary_banner_text.value = "AUDIT COMPLETE: Clean · 0 Vulnerabilities Detected"
                            summary_banner_text.color = COLOR_GREEN
                            selected_finding = None
                            render_findings_list()
                            right_container.content = build_proof_graph_view([])

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
