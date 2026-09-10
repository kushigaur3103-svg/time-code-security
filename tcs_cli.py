#!/usr/bin/env python3
"""
TimeCodeSecurity (TCS) Standalone CLI Scanner.
Recursively analyzes Python source code for security vulnerabilities,
applies deterministic inline suppressions, and outputs standard JSON or OASIS SARIF v2.1.0.
"""

import sys
import os
import ast
import json
import argparse
import dataclasses
from pathlib import Path
from typing import Dict, List, Any, Optional

from ast_scanner import TaintTracker
from suppression_resolver import resolve_suppressions
from sarif_adapter import to_sarif
from rule_engine import GLOBAL_RULE_REGISTRY
from manifest_parser import parse_manifest, DependencyRecord
from osv_client import OSVClient
from version_matcher import match_dependencies, SCAFinding
from secret_scanner import scan_text, SecretFinding
from secret_filters import filter_findings, FilterConfig
from ci_reporter import format_github_annotations, generate_step_summary
from config_loader import load_config, TCSConfig, ConfigValidationError


IGNORED_DIRS = {
    ".git",
    ".github",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "build",
    "dist",
    ".idea",
    ".vscode"
}


def extract_remediation_advice(cwe: str, sink_symbol: str) -> str:
    rule = GLOBAL_RULE_REGISTRY.get_rule(cwe)
    if rule and rule.remediation:
        return rule.remediation
    remediations = {
        "CWE-95": "Avoid passing untrusted input to eval(). Use ast.literal_eval() for parsing Python literals, or parse structured data using json.loads().",
        "CWE-78": "Avoid shell execution with dynamic input. Use subprocess.run() with an argument list and shell=False, e.g., subprocess.run(['cmd', arg], shell=False).",
        "CWE-89": "Use parameterized SQL queries with bind variables instead of string concatenation/formatting, e.g., cursor.execute('SELECT * FROM tbl WHERE id = ?', (user_id,)).",
        "CWE-22": "Validate and sanitize file paths using secure_path_join() or verify containment with os.path.abspath / pathlib.Path.resolve() against an allowed base directory.",
        "CWE-502": "Do not deserialize untrusted data with pickle. Use safe serialization formats such as JSON (json.loads), Protocol Buffers, or messagepack.",
        "CWE-1336": "Avoid passing user input directly into render_template_string(). Use standard render_template() with parameterized template context variables to enforce auto-escaping."
    }
    return remediations.get(cwe, "Sanitize input parameters and enforce strict input validation against an explicit allow-list before passing to dangerous operations.")


def execute_tcs_scan(
    normalized_files: Dict[str, str],
    config: Optional[TCSConfig] = None
) -> Dict[str, Any]:
    """
    Executes AST taint tracking, resolves suppressions, and computes risk scores.
    Uses relative filepaths as keys.
    """
    syntax_errors = []
    for fpath, code in normalized_files.items():
        try:
            ast.parse(code, filename=fpath)
        except SyntaxError as se:
            syntax_errors.append(f"{fpath}:{se.lineno}: {se.msg}")

    tracker = TaintTracker(files=normalized_files)
    sources, sinks, edges = tracker.analyze()

    sinks_by_id = {s.id: s for s in sinks}
    sources_by_id = {s.id: s for s in sources}

    findings = []
    seen_vulns = set()
    vuln_idx = 1

    for edge in edges:
        sink = sinks_by_id.get(edge.target_id)
        if not sink:
            continue

        cwe = sink.metadata.get("cwe", "UNKNOWN_CWE")
        if config is not None and not config.is_rule_enabled(cwe):
            continue
        category = sink.metadata.get("sink_type", "UNKNOWN_VULNERABILITY")
        confidence_val = float(edge.confidence)
        confidence_label = "CONFIRMED" if confidence_val >= 1.0 else "POTENTIAL"

        rule = GLOBAL_RULE_REGISTRY.get_rule(cwe)
        if rule:
            severity = rule.get_severity(confidence_label)
        elif cwe in ["CWE-95", "CWE-78", "CWE-502", "CWE-1336"]:
            severity = "CRITICAL" if confidence_label == "CONFIRMED" else "HIGH"
        elif cwe in ["CWE-89", "CWE-22"]:
            severity = "HIGH" if confidence_label == "CONFIRMED" else "MEDIUM"
        else:
            severity = "MEDIUM" if confidence_label == "CONFIRMED" else "LOW"

        source_node = sources_by_id.get(edge.source_id)
        sink_loc = sink.location
        source_loc = source_node.location if source_node else None

        dedup_key = (sink_loc.file, sink_loc.line_start, cwe, confidence_label)
        if dedup_key in seen_vulns:
            continue
        seen_vulns.add(dedup_key)

        target_file_content = normalized_files.get(sink_loc.file, "")
        target_lines = target_file_content.splitlines()
        offending_snippet = ""
        if 1 <= sink_loc.line_start <= len(target_lines):
            offending_snippet = target_lines[sink_loc.line_start - 1].strip()

        transform_raw = edge.transform or ""
        trace_steps = []
        if source_node:
            trace_steps.append(f"Source: {source_node.symbol} ({source_loc.file}:{source_loc.line_start})")
        else:
            trace_steps.append("Source: User Input")

        if transform_raw:
            parts = [p.strip() for p in transform_raw.split("->")]
            for p in parts:
                if p.startswith("SRC-") or p == "binary_op" or not p:
                    continue
                clean_p = p.split(":")[-1] if ":" in p else p
                if clean_p and clean_p not in trace_steps:
                    trace_steps.append(f"Variable / Flow: {clean_p}")

        trace_steps.append(f"Sink: {sink.symbol} ({sink_loc.file}:{sink_loc.line_start})")

        src_sym = source_node.symbol if source_node else "User Input"
        src_line = f"L{source_loc.line_start}" if source_loc else "L?"
        snk_sym = sink.symbol
        snk_line = f"L{sink_loc.line_start}"

        flow_summary = f"[{src_sym} ({src_line})] -> [Tainted Dataflow] -> [{snk_sym} ({snk_line})]"
        remediation = extract_remediation_advice(cwe, sink.symbol)

        findings.append({
            "id": f"TCS-VULN-{vuln_idx:03d}",
            "category": category,
            "cwe": cwe,
            "severity": severity,
            "confidence": confidence_val,
            "confidence_label": confidence_label,
            "file": sink_loc.file,
            "line_number": sink_loc.line_start,
            "sink_symbol": sink.symbol,
            "source_symbol": source_node.symbol if source_node else "USER_INPUT",
            "source_line": source_loc.line_start if source_loc else None,
            "source_file": source_loc.file if source_loc else None,
            "code_snippet": offending_snippet,
            "flow_trace": trace_steps,
            "flow_trace_summary": flow_summary,
            "remediation": remediation
        })
        vuln_idx += 1

    suppression_enabled = True if config is None else config.suppression.enabled
    if suppression_enabled:
        findings = resolve_suppressions(findings, normalized_files)
    else:
        for f in findings:
            f["suppressed"] = False
            f["suppression_justification"] = None
            f["suppression_kind"] = None
            f["active"] = True

    total_files = len(normalized_files)
    lines_scanned = sum(len(c.splitlines()) for c in normalized_files.values())
    total_vulnerabilities = len(findings)

    active_findings = [f for f in findings if not f.get("suppressed", False)]
    suppressed_findings = [f for f in findings if f.get("suppressed", False)]
    active_vulnerabilities = len(active_findings)
    suppressed_vulnerabilities = len(suppressed_findings)

    critical_count = sum(1 for f in active_findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in active_findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in active_findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in active_findings if f["severity"] == "LOW")

    security_score = max(0, 100 - (critical_count * 25 + high_count * 15 + medium_count * 5))

    if active_vulnerabilities == 0:
        risk_level = "CLEAN"
        risk_message = "NO VULNERABILITIES DETECTED within current TCS analysis scope (6 supported CWE classes)."
    elif critical_count > 0:
        risk_level = "CRITICAL"
        risk_message = "CRITICAL RISK: Arbitrary code execution or high-impact injection detected."
    elif high_count > 0:
        risk_level = "HIGH"
        risk_message = "HIGH RISK: Injection or data traversal vulnerabilities detected."
    elif medium_count > 0:
        risk_level = "MEDIUM"
        risk_message = "MEDIUM RISK: Potential data-flow flaws detected."
    else:
        risk_level = "LOW"
        risk_message = "LOW RISK: Minor security notices."

    return {
        "status": "success",
        "syntax_errors": syntax_errors,
        "enabled_rules": list(config.effective_rules) if config else [r.cwe_id for r in GLOBAL_RULE_REGISTRY.all_rules()],
        "summary": {
            "total_files": total_files,
            "lines_scanned": lines_scanned,
            "total_vulnerabilities": total_vulnerabilities,
            "active_vulnerabilities": active_vulnerabilities,
            "suppressed_vulnerabilities": suppressed_vulnerabilities,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "security_score": security_score,
            "score_label": "Security Health Score",
            "risk_level": risk_level,
            "risk_message": risk_message
        },
        "findings": findings
    }


SECRET_EXTS = {".py", ".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".txt"}


def discover_python_files(
    target_path: Path, base_dir: Path, sca_active: bool = False, secrets_active: bool = False
) -> Dict[str, str]:
    """
    Recursively discovers Python files, ignoring non-code or virtual env folders.
    Returns mapping of POSIX relative paths to text contents.
    """
    normalized_files: Dict[str, str] = {}
    manifest_names = {"requirements.txt", "pipfile.lock", "poetry.lock"}

    if target_path.is_file():
        if target_path.suffix.lower() != ".py":
            if sca_active and target_path.name.lower() in manifest_names:
                return {}
            if secrets_active and (
                target_path.suffix.lower() in SECRET_EXTS
                or target_path.name.lower().startswith(".env")
            ):
                return {}
            print(f"[ERROR] Target is not a Python file: {target_path}", file=sys.stderr)
            sys.exit(2)
        try:
            rel_path = target_path.relative_to(base_dir).as_posix()
        except ValueError:
            rel_path = target_path.name
        try:
            normalized_files[rel_path] = target_path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"[ERROR] Unable to read file '{target_path}': {e}", file=sys.stderr)
            sys.exit(2)
        return normalized_files

    for root, dirs, files in os.walk(target_path):
        # Modify dirs in place to prune ignored folders
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]

        for fname in files:
            if fname.endswith(".py") and fname != "tcs_cli.py":
                full_file = Path(root) / fname
                try:
                    rel_path = full_file.relative_to(target_path).as_posix()
                except ValueError:
                    try:
                        rel_path = full_file.relative_to(base_dir).as_posix()
                    except ValueError:
                        rel_path = full_file.name

                try:
                    normalized_files[rel_path] = full_file.read_text(encoding="utf-8")
                except Exception as e:
                    print(f"[ERROR] Unable to read file '{full_file}': {e}", file=sys.stderr)
                    sys.exit(2)

    return normalized_files


def discover_secret_files(target_path: Path, base_dir: Path) -> List[Path]:
    """
    Discovers text/configuration files to scan for hardcoded secrets and credentials.
    Supports .py, .env, .json, .yaml, .yml, .toml, .ini, .conf, .txt.
    """
    discovered: List[Path] = []

    if target_path.is_file():
        if target_path.suffix.lower() in SECRET_EXTS or target_path.name.lower().startswith(".env"):
            discovered.append(target_path)
        return discovered

    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
        for fname in files:
            p = Path(root) / fname
            if p.suffix.lower() in SECRET_EXTS or fname.lower().startswith(".env"):
                if fname != "tcs_cli.py":
                    discovered.append(p)

    discovered.sort()
    return discovered


def discover_manifest_files(target_path: Path, base_dir: Path) -> List[Path]:
    """
    Discovers supported dependency manifests within the target scope.
    Supported filenames: requirements.txt, Pipfile.lock, poetry.lock.
    """
    manifest_names = {"requirements.txt", "pipfile.lock", "poetry.lock"}
    discovered: List[Path] = []

    if target_path.is_file():
        if target_path.name.lower() in manifest_names:
            discovered.append(target_path)
        return discovered

    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
        for fname in files:
            if fname.lower() in manifest_names:
                discovered.append(Path(root) / fname)

    discovered.sort()
    return discovered


def format_table(
    results: Dict[str, Any],
    findings: List[Dict[str, Any]],
    sca_findings: Optional[List[Any]] = None,
    sca_enabled: bool = False,
    secret_findings: Optional[List[Any]] = None,
    secrets_enabled: bool = False
) -> str:
    """Renders human-readable tabular scan report for console display."""
    summary = results.get("summary", {})
    total_files = summary.get("total_files", 0)
    lines_scanned = summary.get("lines_scanned", 0)
    score = summary.get("security_score", 100)
    risk_level = summary.get("risk_level", "CLEAN")

    sca_list = [f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in (sca_findings or [])] if sca_enabled else []
    sec_list = [dataclasses.asdict(f) if hasattr(f, "__dataclass_fields__") else (f.to_dict() if hasattr(f, "to_dict") else dict(f)) for f in (secret_findings or [])] if secrets_enabled else []

    if not sca_enabled and not secrets_enabled:
        lines = [
            "=" * 88,
            "TimeCodeSecurity (TCS) AST Security Scan Report",
            "=" * 88,
            f"Scanned Files: {total_files} | Total Lines: {lines_scanned} | Security Score: {score}/100 ({risk_level})",
            f"Total Findings Displayed: {len(findings)}",
            "-" * 88
        ]

        if not findings:
            lines.append("No security vulnerabilities detected.")
            lines.append("=" * 88)
            return "\n".join(lines)

        lines.append(f"{'ID':<14} | {'SEVERITY':<8} | {'CWE':<9} | {'STATUS':<10} | {'LOCATION':<22} | {'SINK':<15}")
        lines.append("-" * 88)
        for f in findings:
            fid = f.get("id", "")
            sev = f.get("severity", "MEDIUM")
            cwe = f.get("cwe", "")
            status = "SUPPRESSED" if f.get("suppressed") else "ACTIVE"
            loc = f"{f.get('file', '')}:{f.get('line_number', '')}"
            sink = f.get("sink_symbol", "")
            lines.append(f"{fid:<14} | {sev:<8} | {cwe:<9} | {status:<10} | {loc:<22} | {sink:<15}")

        lines.append("-" * 88)
        lines.append("\nFINDING DETAILS:")
        for f in findings:
            fid = f.get("id", "")
            cwe = f.get("cwe", "")
            cat = f.get("category", "")
            status = "SUPPRESSED" if f.get("suppressed") else "ACTIVE"
            lines.append(f"\n[{fid}] {cwe} ({cat}) - Status: {status}")
            lines.append(f"  Location:     {f.get('file', '')}:{f.get('line_number', '')}")
            lines.append(f"  Severity:     {f.get('severity', '')} (Confidence: {f.get('confidence_label', '')})")
            if f.get("code_snippet"):
                lines.append(f"  Code Snippet: {f.get('code_snippet')}")
            if f.get("flow_trace_summary"):
                lines.append(f"  Flow Summary: {f.get('flow_trace_summary')}")
            if f.get("suppressed") and f.get("suppression_justification"):
                lines.append(f"  Justification:{f.get('suppression_justification')}")
            if f.get("remediation"):
                lines.append(f"  Remediation:  {f.get('remediation')}")

        lines.append("=" * 88)
        return "\n".join(lines)

    # ---------------------------------------------------------
    # Unified Multi-Engine Report (SAST, SCA, Secrets)
    # ---------------------------------------------------------
    sep = "=" * 105
    dash_sep = "-" * 105

    title_parts = ["SAST"]
    if sca_enabled:
        title_parts.append("SCA")
    if secrets_enabled:
        title_parts.append("SECRETS")
    title_str = " + ".join(title_parts)

    count_parts = [f"Total SAST Findings: {len(findings)}"]
    if sca_enabled:
        count_parts.append(f"Total SCA Findings: {len(sca_list)}")
    if secrets_enabled:
        count_parts.append(f"Total Secret Findings: {len(sec_list)}")
    count_str = " | ".join(count_parts)

    lines = [
        sep,
        f"TimeCodeSecurity (TCS) Security Scan Report ({title_str})",
        sep,
        f"Scanned Files: {total_files} | Total Lines: {lines_scanned} | Security Score: {score}/100 ({risk_level})",
        count_str,
        dash_sep
    ]

    if not findings and not sca_list and not sec_list:
        lines.append("No security vulnerabilities detected.")
        lines.append(sep)
        return "\n".join(lines)

    if findings:
        lines.append("\n[SAST CODE ANALYSIS FINDINGS]")
        lines.append(f"{'ID':<14} | {'SEVERITY':<8} | {'CWE':<9} | {'STATUS':<10} | {'LOCATION':<22} | {'SINK':<15}")
        lines.append(dash_sep)
        for f in findings:
            fid = f.get("id", "")
            sev = f.get("severity", "MEDIUM")
            cwe = f.get("cwe", "")
            status = "SUPPRESSED" if f.get("suppressed") else "ACTIVE"
            loc = f"{f.get('file', '')}:{f.get('line_number', '')}"
            sink = f.get("sink_symbol", "")
            lines.append(f"{fid:<14} | {sev:<8} | {cwe:<9} | {status:<10} | {loc:<22} | {sink:<15}")

    if sca_list:
        lines.append("\n[SCA DEPENDENCY VULNERABILITIES]")
        lines.append(f"{'PACKAGE':<16} | {'STATUS':<11} | {'INSTALLED / SPEC':<18} | {'VULN ID':<16} | {'SEVERITY':<8} | {'FIXED':<10} | {'LOCATION':<20}")
        lines.append(dash_sep)
        for sf in sca_list:
            pkg = str(sf.get("package_name", ""))[:16]
            status = str(sf.get("status", ""))[:11]
            ver_spec = str(sf.get("installed_version") or sf.get("requested_specifier") or "-")[:18]
            vid = str(sf.get("vulnerability_id", ""))[:16]
            sev = str(sf.get("severity", "UNKNOWN"))[:8]
            fixed = str(sf.get("fixed_version") or "-")[:10]
            loc_str = f"{sf.get('manifest_source', '')}:{sf.get('line_number') or '?'}"[:20]
            lines.append(f"{pkg:<16} | {status:<11} | {ver_spec:<18} | {vid:<16} | {sev:<8} | {fixed:<10} | {loc_str:<20}")

    if sec_list:
        lines.append("\n[SECRET SCANNING FINDINGS (CWE-798)]")
        lines.append(f"{'TYPE':<18} | {'MASKED VALUE':<24} | {'LOCATION':<22} | {'CONFIDENCE':<10} | {'DETECTOR':<16}")
        lines.append(dash_sep)
        for sf in sec_list:
            stype = str(sf.get("secret_type", ""))[:18]
            mv = str(sf.get("masked_value", ""))[:24]
            loc = f"{sf.get('file', '')}:{sf.get('line_number', '')}"[:22]
            conf = str(sf.get("confidence", "HIGH"))[:10]
            det = str(sf.get("detector", ""))[:16]
            lines.append(f"{stype:<18} | {mv:<24} | {loc:<22} | {conf:<10} | {det:<16}")

    lines.append(dash_sep)
    lines.append("\nFINDING DETAILS:")

    if findings:
        for f in findings:
            fid = f.get("id", "")
            cwe = f.get("cwe", "")
            cat = f.get("category", "")
            status = "SUPPRESSED" if f.get("suppressed") else "ACTIVE"
            lines.append(f"\n[SAST:{fid}] {cwe} ({cat}) - Status: {status}")
            lines.append(f"  Location:     {f.get('file', '')}:{f.get('line_number', '')}")
            lines.append(f"  Severity:     {f.get('severity', '')} (Confidence: {f.get('confidence_label', '')})")
            if f.get("code_snippet"):
                lines.append(f"  Code Snippet: {f.get('code_snippet')}")
            if f.get("flow_trace_summary"):
                lines.append(f"  Flow Summary: {f.get('flow_trace_summary')}")
            if f.get("suppressed") and f.get("suppression_justification"):
                lines.append(f"  Justification:{f.get('suppression_justification')}")
            if f.get("remediation"):
                lines.append(f"  Remediation:  {f.get('remediation')}")

    if sca_list:
        for sf in sca_list:
            vid = sf.get("vulnerability_id", "")
            pkg = sf.get("package_name", "")
            status = sf.get("status", "")
            sev = sf.get("severity", "UNKNOWN")
            cvss = sf.get("cvss_score")
            cvss_str = str(cvss) if cvss is not None else "N/A"
            ver_desc = sf.get("installed_version") or sf.get("requested_specifier") or "unspecified"
            fixed = sf.get("fixed_version") or "None / Unknown"
            matched_range = sf.get("matched_range", "")
            loc = f"{sf.get('manifest_source', '')}:{sf.get('line_number') or '?'}"
            summary = sf.get("summary", "")

            lines.append(f"\n[SCA:{vid}] {pkg} ({ver_desc}) - Status: {status}")
            lines.append(f"  Package:        {pkg}")
            lines.append(f"  Vulnerability:  {vid}")
            lines.append(f"  Status:         {status}")
            lines.append(f"  Severity:       {sev} (CVSS: {cvss_str})")
            lines.append(f"  Installed/Spec: {ver_desc}")
            lines.append(f"  Fixed Version:  {fixed}")
            lines.append(f"  Matched Range:  {matched_range}")
            lines.append(f"  Location:       {loc}")
            lines.append(f"  Summary:        {summary}")

    if sec_list:
        for sf in sec_list:
            stype = sf.get("secret_type", "")
            mv = sf.get("masked_value", "")
            loc = f"{sf.get('file', '')}:{sf.get('line_number', '')}"
            cols = f"Cols {sf.get('column_start', 1)}-{sf.get('column_end', 1)}"
            det = sf.get("detector", "")
            conf = sf.get("confidence", "HIGH")
            ctx = sf.get("context", "")

            lines.append(f"\n[SECRET:CWE-798] {stype} - Location: {loc} ({cols})")
            lines.append(f"  Type:         {stype}")
            lines.append(f"  Masked Value: {mv}")
            lines.append(f"  Location:     {loc} ({cols})")
            lines.append(f"  Confidence:   {conf}")
            lines.append(f"  Detector:     {det}")
            if ctx:
                lines.append(f"  Context:      {ctx}")
            lines.append("  Remediation:  Never commit hardcoded secrets or credentials to source control. Revoke and rotate this secret immediately.")

    lines.append(sep)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="TimeCodeSecurity (TCS) SAST & SCA Scanner CLI",
        prog="tcs_cli.py"
    )
    parser.add_argument(
        "target",
        help="Target Python file, manifest, or directory to scan"
    )
    parser.add_argument(
        "--config",
        help="Path to .tcs.yml configuration file"
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default=None,
        help="Output format: table, json, or sarif (default: table or configured in .tcs.yml)"
    )
    parser.add_argument(
        "--exclude-suppressed",
        action="store_true",
        help="Exclude suppressed findings from display, export, and exit code calculation"
    )
    parser.add_argument(
        "-o", "--output",
        help="Write formatted scan output to specified file path instead of stdout"
    )
    parser.add_argument(
        "--sca",
        dest="sca",
        action="store_true",
        default=None,
        help="Enable Software Composition Analysis (SCA) for dependency manifests"
    )
    parser.add_argument(
        "--no-sca",
        dest="sca",
        action="store_false",
        help="Disable Software Composition Analysis (SCA)"
    )
    parser.add_argument(
        "--sca-offline",
        action="store_true",
        help="Enforce offline SCA analysis using local OSV cache only (requires --sca)"
    )
    parser.add_argument(
        "--sca-cache",
        help="Path to local OSV cache JSON file"
    )
    parser.add_argument(
        "--secrets",
        dest="secrets",
        action="store_true",
        default=None,
        help="Enable Secret and Credential Scanning (CWE-798)"
    )
    parser.add_argument(
        "--no-secrets",
        dest="secrets",
        action="store_false",
        help="Disable Secret and Credential Scanning (CWE-798)"
    )
    parser.add_argument(
        "--github-actions",
        action="store_true",
        help="Enable GitHub Actions workflow annotations and step summary generation"
    )
    parser.add_argument(
        "--step-summary-file",
        help="Path to Step Summary Markdown output file (defaults to $GITHUB_STEP_SUMMARY)"
    )

    args = parser.parse_args()

    # Load configuration
    try:
        config = load_config(args.config, base_dir=Path.cwd())
    except ConfigValidationError as cve:
        print(f"[ERROR] Configuration error: {cve}", file=sys.stderr)
        sys.exit(2)

    # Resolve CLI precedence: CLI explicit > .tcs.yml > built-in defaults
    if args.sca is not None:
        active_sca = args.sca
    elif config is not None:
        active_sca = config.scan.sca
    else:
        active_sca = False

    if args.secrets is not None:
        active_secrets = args.secrets
    elif config is not None:
        active_secrets = config.scan.secrets
    else:
        active_secrets = False

    if args.format is not None:
        active_format = args.format
    elif config is not None:
        active_format = config.output.format
    else:
        active_format = "table"

    args.sca = active_sca
    args.secrets = active_secrets
    args.format = active_format

    if args.sca_offline and not args.sca:
        print("[ERROR] --sca-offline requires --sca to be enabled.", file=sys.stderr)
        sys.exit(2)

    base_dir = Path.cwd().resolve()
    target = Path(args.target).resolve()

    if not target.exists():
        print(f"[ERROR] Target path does not exist: {args.target}", file=sys.stderr)
        sys.exit(2)

    files = discover_python_files(target, base_dir, sca_active=args.sca, secrets_active=args.secrets)
    if not files and not args.sca and not args.secrets:
        print(f"[WARN] No Python (*.py) files found in: {args.target}", file=sys.stderr)

    try:
        results = execute_tcs_scan(files, config=config)
    except Exception as e:
        print(f"[ERROR] Scan execution failed: {e}", file=sys.stderr)
        sys.exit(2)

    if results.get("syntax_errors"):
        for err in results["syntax_errors"]:
            print(f"[ERROR] Syntax error in target file: {err}", file=sys.stderr)
        sys.exit(2)

    # ---------------------------------------------------------
    # SCA Analysis (if requested)
    # ---------------------------------------------------------
    sca_findings: List[SCAFinding] = []
    manifest_files: List[Path] = []

    if args.sca:
        manifest_files = discover_manifest_files(target, base_dir)
        all_deps: List[DependencyRecord] = []
        for mf in manifest_files:
            if target.is_dir():
                try:
                    rel_mf = mf.relative_to(target).as_posix()
                except ValueError:
                    try:
                        rel_mf = mf.relative_to(base_dir).as_posix()
                    except ValueError:
                        rel_mf = mf.name
            else:
                rel_mf = mf.name

            parse_res = parse_manifest(str(mf))
            for dep in parse_res.dependencies:
                if dep.source != rel_mf:
                    dep = dataclasses.replace(dep, source=rel_mf)
                all_deps.append(dep)

        if all_deps:
            package_names = [dep.name for dep in all_deps]
            cache_file = args.sca_cache or os.environ.get("TCS_OSV_CACHE", os.path.expanduser("~/.tcs/osv_cache.json"))
            osv_client = OSVClient(cache_file=cache_file, offline_mode=args.sca_offline)
            osv_results = osv_client.query_packages(package_names)
            sca_findings = match_dependencies(all_deps, osv_results)

    # ---------------------------------------------------------
    # Secret Scanning Analysis (if requested)
    # ---------------------------------------------------------
    secret_findings: List[SecretFinding] = []
    secret_files: List[Path] = []

    if args.secrets:
        secret_files = discover_secret_files(target, base_dir)
        filter_cfg = FilterConfig()
        for sf in secret_files:
            if target.is_dir():
                try:
                    rel_sf = sf.relative_to(target).as_posix()
                except ValueError:
                    try:
                        rel_sf = sf.relative_to(base_dir).as_posix()
                    except ValueError:
                        rel_sf = sf.name
            else:
                rel_sf = sf.name

            try:
                content = sf.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                print(f"[WARN] Unable to read secret target '{sf}': {e}", file=sys.stderr)
                continue

            raw_findings = scan_text(content, filename=rel_sf)
            passed_findings = filter_findings(raw_findings, file_path=rel_sf, config=filter_cfg)
            secret_findings.extend(passed_findings)

    all_findings = results.get("findings", [])
    if args.exclude_suppressed:
        effective_findings = [f for f in all_findings if not f.get("suppressed", False)]
    else:
        effective_findings = all_findings

    export_data = dict(results)
    export_data["findings"] = effective_findings
    if args.exclude_suppressed:
        summary_copy = dict(results.get("summary", {}))
        summary_copy["total_vulnerabilities"] = len(effective_findings)
        summary_copy["suppressed_vulnerabilities"] = 0
        summary_copy["active_vulnerabilities"] = len(effective_findings)
        export_data["summary"] = summary_copy

    if args.sca:
        serialized_sca = [f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in sca_findings]
        export_data["sca_findings"] = serialized_sca
        summary_copy = dict(export_data.get("summary", {}))
        summary_copy["manifests_scanned"] = len(manifest_files)
        summary_copy["sca_vulnerabilities"] = len(sca_findings)
        summary_copy["sca_confirmed"] = sum(1 for f in sca_findings if (getattr(f, "status", None) or f.get("status")) == "CONFIRMED")
        summary_copy["sca_potential"] = sum(1 for f in sca_findings if (getattr(f, "status", None) or f.get("status")) == "POTENTIAL")
        summary_copy["sca_unresolved"] = sum(1 for f in sca_findings if (getattr(f, "status", None) or f.get("status")) == "UNRESOLVED")
        export_data["summary"] = summary_copy

    if args.secrets:
        serialized_secrets = [
            {
                "secret_type": sf.secret_type,
                "masked_value": sf.masked_value,
                "file": sf.file,
                "line_number": sf.line_number,
                "column_start": sf.column_start,
                "column_end": sf.column_end,
                "confidence": sf.confidence,
                "detector": sf.detector,
                "context": sf.context,
                "cwe": "CWE-798"
            }
            for sf in secret_findings
        ]
        export_data["secret_findings"] = serialized_secrets
        summary_copy = dict(export_data.get("summary", {}))
        summary_copy["secrets_scanned"] = len(secret_files)
        summary_copy["secrets_scanned_files"] = len(secret_files)
        summary_copy["secrets_detected"] = len(secret_findings)
        export_data["summary"] = summary_copy

    if args.format.lower() == "sarif":
        sarif_doc = to_sarif(export_data, enabled_rule_ids=config.effective_rules if config else None)
        output_text = json.dumps(sarif_doc, indent=2)
    elif args.format.lower() == "json":
        output_text = json.dumps(export_data, indent=2)
    else:
        output_text = format_table(
            results,
            effective_findings,
            sca_findings=sca_findings,
            sca_enabled=args.sca,
            secret_findings=secret_findings,
            secrets_enabled=args.secrets
        )

    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_text, encoding="utf-8")
        print(f"[TCS CLI] Results written to: {args.output} (Format: {args.format})", file=sys.stderr)
    else:
        print(output_text)

    # ---------------------------------------------------------
    # GitHub Actions Workflow Commands & Step Summary
    # ---------------------------------------------------------
    if args.github_actions:
        annotations = format_github_annotations(export_data)
        for ann in annotations:
            print(ann, file=sys.stderr)

        summary_file = args.step_summary_file or os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_file:
            try:
                summary_md = generate_step_summary(export_data)
                sum_path = Path(summary_file).resolve()
                sum_path.parent.mkdir(parents=True, exist_ok=True)
                with open(sum_path, "a", encoding="utf-8") as f:
                    f.write(summary_md)
            except Exception as e:
                print(f"[ERROR] Failed to write Step Summary to '{summary_file}': {e}", file=sys.stderr)
                sys.exit(2)

    # Human status summary to stderr
    summary = results.get("summary", {})
    total = summary.get("total_vulnerabilities", 0)
    active = summary.get("active_vulnerabilities", 0)
    suppressed = summary.get("suppressed_vulnerabilities", 0)
    score = summary.get("security_score", 100)
    risk = summary.get("risk_level", "CLEAN")

    if not args.sca and not args.secrets:
        print(
            f"[TCS CLI] Scanned {len(files)} files | Findings: {total} (Active: {active}, Suppressed: {suppressed}) | Score: {score}/100 ({risk})",
            file=sys.stderr
        )
    elif args.sca and not args.secrets:
        sca_count = len(sca_findings)
        sca_confirmed = sum(1 for f in sca_findings if (getattr(f, "status", None) or f.get("status")) == "CONFIRMED")
        sca_potential = sum(1 for f in sca_findings if (getattr(f, "status", None) or f.get("status")) == "POTENTIAL")
        sca_unresolved = sum(1 for f in sca_findings if (getattr(f, "status", None) or f.get("status")) == "UNRESOLVED")
        print(
            f"[TCS CLI] Scanned {len(files)} files, {len(manifest_files)} manifests | SAST: {total} (Active: {active}, Suppressed: {suppressed}) | SCA: {sca_count} (Confirmed: {sca_confirmed}, Potential: {sca_potential}, Unresolved: {sca_unresolved}) | Score: {score}/100 ({risk})",
            file=sys.stderr
        )
    else:
        status_items = [f"{len(files)} files"]
        if args.sca:
            status_items.append(f"{len(manifest_files)} manifests")
        if args.secrets:
            status_items.append(f"{len(secret_files)} secret files")

        findings_items = [f"SAST: {total} (Active: {active}, Suppressed: {suppressed})"]
        if args.sca:
            sca_count = len(sca_findings)
            sca_confirmed = sum(1 for f in sca_findings if (getattr(f, "status", None) or f.get("status")) == "CONFIRMED")
            sca_potential = sum(1 for f in sca_findings if (getattr(f, "status", None) or f.get("status")) == "POTENTIAL")
            sca_unresolved = sum(1 for f in sca_findings if (getattr(f, "status", None) or f.get("status")) == "UNRESOLVED")
            findings_items.append(f"SCA: {sca_count} (Confirmed: {sca_confirmed}, Potential: {sca_potential}, Unresolved: {sca_unresolved})")
        if args.secrets:
            findings_items.append(f"Secrets: {len(secret_findings)} (CWE-798)")

        print(
            f"[TCS CLI] Scanned {', '.join(status_items)} | {' | '.join(findings_items)} | Score: {score}/100 ({risk})",
            file=sys.stderr
        )

    has_sast_failure = len(effective_findings) > 0
    has_sca_failure = (len(sca_findings) > 0) if args.sca else False
    has_secret_failure = (len(secret_findings) > 0) if args.secrets else False

    if has_sast_failure or has_sca_failure or has_secret_failure:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit as se:
        sys.exit(se.code)
    except Exception as exc:
        print(f"[ERROR] Internal unhandled exception: {exc}", file=sys.stderr)
        sys.exit(2)
