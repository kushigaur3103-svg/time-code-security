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
from typing import Dict, List, Any, Optional, Set

from ast_scanner import TaintTracker, render_proof_graph_ascii
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
from staged_scanner import (
    get_git_repo_root,
    get_staged_git_files,
    build_staged_dependency_closure,
    filter_findings_for_staged,
    recompute_summary_metrics,
)
from sca_reachability.engine import analyze_dependency_reachability

try:
    from importlib.metadata import version as _get_version
    __version__ = _get_version("time-code-security")
except Exception:
    __version__ = "1.5.0"


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

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_LINE_LENGTH_CHARS = 10000
BINARY_PREFIX_BYTES = 8192

# Test orchestration seam: invoked immediately before stale-source check
_PRE_WRITE_HOOK: Optional[Any] = None


def check_file_resilience(file_path: Path, display_path: str) -> Optional[str]:
    """
    Guards against resource exhaustion / DoS vectors:
    1. Giant files (> 5MB)
    2. Binary blobs (NUL bytes in prefix)
    3. Pathological minified one-liners (> 10,000 characters)

    Returns warning string if file must be skipped, or None if safe.
    """
    try:
        st = file_path.stat()
        if st.st_size > MAX_FILE_SIZE_BYTES:
            return f"Skipping file exceeding size limit (5MB): {display_path}"
    except (OSError, ValueError) as e:
        return f"Skipping inaccessible file/symlink: {display_path} ({e})"

    try:
        with open(file_path, "rb") as f:
            chunk = f.read(BINARY_PREFIX_BYTES)
            if b"\x00" in chunk:
                return f"Skipping binary file: {display_path}"
    except (OSError, ValueError) as e:
        return f"Skipping unreadable file: {display_path} ({e})"

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if len(line) > MAX_LINE_LENGTH_CHARS:
                    return f"Skipping minified file exceeding line length limit (10000): {display_path}"
    except (OSError, ValueError) as e:
        return f"Skipping unreadable file: {display_path} ({e})"

    return None


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
    config: Optional[TCSConfig] = None,
    audit_all: bool = False,
    secrets: bool = False
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

    tracker = TaintTracker(files=normalized_files, audit_all=audit_all)
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
            "remediation": remediation,
            "proof_graph": edge.proof_graph.to_dict() if edge.proof_graph else None,
            "proof_graph_ascii": render_proof_graph_ascii(edge.proof_graph) if edge.proof_graph else None,
            "discovery_mode": "STANDARD_SCAN"
        })
        vuln_idx += 1

    secret_findings_list = []
    if secrets:
        from secret_scanner import scan_text
        from secret_filters import filter_findings, FilterConfig
        filter_cfg = FilterConfig()
        for fpath, code in normalized_files.items():
            raw_sec = scan_text(code, filename=fpath)
            passed_sec = filter_findings(raw_sec, file_path=fpath, config=filter_cfg)
            for sf in passed_sec:
                sec_dict = {
                    "id": f"TCS-SEC-{vuln_idx:03d}",
                    "category": "HARDCODED_SECRET",
                    "cwe": "CWE-798",
                    "severity": "HIGH",
                    "confidence": 1.0,
                    "confidence_label": "CONFIRMED",
                    "file": sf.file,
                    "line_number": sf.line_number,
                    "column_start": sf.column_start,
                    "column_end": sf.column_end,
                    "masked_value": sf.masked_value,
                    "secret_type": sf.secret_type,
                    "detector": sf.detector,
                    "pattern": getattr(sf, "pattern", None) or sf.detector or "hardcoded_credential_variable",
                    "code_snippet": sf.context or "",
                    "flow_trace": [f"Secret: {sf.secret_type} ({sf.file}:{sf.line_number})"],
                    "flow_trace_summary": f"[{sf.secret_type} (L{sf.line_number})] -> [Hardcoded Secret] -> [CWE-798]",
                    "remediation": "Revoke and rotate the exposed credential immediately. Store secrets in environment variables or a dedicated secret management service.",
                    "proof_graph": None,
                    "proof_graph_ascii": None,
                    "discovery_mode": "STANDARD_SCAN",
                    "is_secret": True
                }
                findings.append(sec_dict)
                vuln_idx += 1
                secret_findings_list.append(sec_dict)

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

    scan_filename = list(normalized_files.keys())[0] if len(normalized_files) == 1 else "target.py"

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
            "risk_message": risk_message,
            "target_file": scan_filename,
            "filename": scan_filename,
            "scope_filename": scan_filename
        },
        "scope": {
            "target_file": scan_filename,
            "filename": scan_filename,
            "total_files": total_files,
            "lines_scanned": lines_scanned
        },
        "findings": findings
    }
    if secrets:
        ret["secret_findings"] = secret_findings_list
    return ret


SECRET_EXTS = {".py", ".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".txt"}


def discover_python_files(
    target_path: Path,
    base_dir: Path,
    sca_active: bool = False,
    secrets_active: bool = False,
    skipped_files: Optional[List[str]] = None,
) -> Dict[str, str]:
    """
    Recursively discovers Python files, ignoring non-code or virtual env folders.
    Guards against symlink loops, giant files, binary blobs, and minified bundles.
    Returns mapping of POSIX relative paths to text contents.
    """
    normalized_files: Dict[str, str] = {}
    manifest_names = {"requirements.txt", "pipfile.lock", "poetry.lock", "pyproject.toml"}

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

        skip_reason = check_file_resilience(target_path, rel_path)
        if skip_reason:
            print(f"[WARN] {skip_reason}", file=sys.stderr)
            if skipped_files is not None:
                skipped_files.append(skip_reason)
            return normalized_files

        try:
            normalized_files[rel_path] = target_path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"[ERROR] Unable to read file '{target_path}': {e}", file=sys.stderr)
            sys.exit(2)
        return normalized_files

    visited_dirs: Set[str] = set()
    for root, dirs, files in os.walk(target_path, followlinks=False):
        real_root = os.path.realpath(root)
        if real_root in visited_dirs:
            dirs[:] = []
            continue
        visited_dirs.add(real_root)

        # Modify dirs in place to prune ignored folders and directory symlinks
        pruned_dirs = []
        for d in dirs:
            dir_full = os.path.join(root, d)
            if os.path.islink(dir_full):
                continue
            if d not in IGNORED_DIRS and not d.startswith("."):
                pruned_dirs.append(d)
        dirs[:] = pruned_dirs

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

                skip_reason = check_file_resilience(full_file, rel_path)
                if skip_reason:
                    print(f"[WARN] {skip_reason}", file=sys.stderr)
                    if skipped_files is not None:
                        skipped_files.append(skip_reason)
                    continue

                try:
                    normalized_files[rel_path] = full_file.read_text(encoding="utf-8")
                except Exception as e:
                    print(f"[ERROR] Unable to read file '{full_file}': {e}", file=sys.stderr)
                    sys.exit(2)

    return normalized_files


def discover_secret_files(
    target_path: Path,
    base_dir: Path,
    skipped_files: Optional[List[str]] = None,
) -> List[Path]:
    """
    Discovers text/configuration files to scan for hardcoded secrets and credentials.
    Supports .py, .env, .json, .yaml, .yml, .toml, .ini, .conf, .txt.
    Guards against symlink loops, giant files, binary blobs, and minified bundles.
    """
    discovered: List[Path] = []

    if target_path.is_file():
        if target_path.suffix.lower() in SECRET_EXTS or target_path.name.lower().startswith(".env"):
            rel_name = target_path.name
            skip_reason = check_file_resilience(target_path, rel_name)
            if skip_reason:
                print(f"[WARN] {skip_reason}", file=sys.stderr)
                if skipped_files is not None:
                    skipped_files.append(skip_reason)
            else:
                discovered.append(target_path)
        return discovered

    visited_dirs: Set[str] = set()
    for root, dirs, files in os.walk(target_path, followlinks=False):
        real_root = os.path.realpath(root)
        if real_root in visited_dirs:
            dirs[:] = []
            continue
        visited_dirs.add(real_root)

        pruned_dirs = []
        for d in dirs:
            dir_full = os.path.join(root, d)
            if os.path.islink(dir_full):
                continue
            if d not in IGNORED_DIRS and not d.startswith("."):
                pruned_dirs.append(d)
        dirs[:] = pruned_dirs

        for fname in files:
            p = Path(root) / fname
            if p.suffix.lower() in SECRET_EXTS or fname.lower().startswith(".env"):
                if fname != "tcs_cli.py":
                    try:
                        rel_path = p.relative_to(target_path).as_posix()
                    except ValueError:
                        try:
                            rel_path = p.relative_to(base_dir).as_posix()
                        except ValueError:
                            rel_path = p.name

                    skip_reason = check_file_resilience(p, rel_path)
                    if skip_reason:
                        print(f"[WARN] {skip_reason}", file=sys.stderr)
                        if skipped_files is not None:
                            skipped_files.append(skip_reason)
                        continue
                    discovered.append(p)

    discovered.sort()
    return discovered


def discover_manifest_files(
    target_path: Path,
    base_dir: Path,
    skipped_files: Optional[List[str]] = None,
) -> List[Path]:
    """
    Discovers supported dependency manifests within the target scope.
    Supported filenames: requirements.txt, Pipfile.lock, poetry.lock.
    Guards against symlink loops, giant files, binary blobs, and minified bundles.
    """
    manifest_names = {"requirements.txt", "pipfile.lock", "poetry.lock", "pyproject.toml"}
    discovered: List[Path] = []

    if target_path.is_file():
        if target_path.name.lower() in manifest_names:
            skip_reason = check_file_resilience(target_path, target_path.name)
            if skip_reason:
                print(f"[WARN] {skip_reason}", file=sys.stderr)
                if skipped_files is not None:
                    skipped_files.append(skip_reason)
            else:
                discovered.append(target_path)
        return discovered

    visited_dirs: Set[str] = set()
    for root, dirs, files in os.walk(target_path, followlinks=False):
        real_root = os.path.realpath(root)
        if real_root in visited_dirs:
            dirs[:] = []
            continue
        visited_dirs.add(real_root)

        pruned_dirs = []
        for d in dirs:
            dir_full = os.path.join(root, d)
            if os.path.islink(dir_full):
                continue
            if d not in IGNORED_DIRS and not d.startswith("."):
                pruned_dirs.append(d)
        dirs[:] = pruned_dirs

        for fname in files:
            if fname.lower() in manifest_names:
                p = Path(root) / fname
                try:
                    rel_path = p.relative_to(target_path).as_posix()
                except ValueError:
                    try:
                        rel_path = p.relative_to(base_dir).as_posix()
                    except ValueError:
                        rel_path = p.name

                skip_reason = check_file_resilience(p, rel_path)
                if skip_reason:
                    print(f"[WARN] {skip_reason}", file=sys.stderr)
                    if skipped_files is not None:
                        skipped_files.append(skip_reason)
                    continue
                discovered.append(p)

    discovered.sort()
    return discovered


def format_reachability_section(reachability_findings: List[Dict[str, Any]]) -> str:
    if not reachability_findings:
        return ""

    reachable_count = sum(1 for f in reachability_findings if f.get("reachability_classification") == "REACHABLE_API_USE")
    active_count = sum(1 for f in reachability_findings if f.get("reachability_classification") == "DEPENDENCY_ACTIVE")
    dormant_count = sum(1 for f in reachability_findings if f.get("reachability_classification") == "DEPENDENCY_DORMANT")
    transitive_count = sum(1 for f in reachability_findings if f.get("reachability_classification") == "TRANSITIVE_VULNERABLE")

    lines = [
        "=" * 55,
        "VECTOR C: DEPENDENCY REACHABILITY ANALYSIS",
        "=" * 55,
        f"[Status Summary: {reachable_count} Reachable | {active_count} Active | {dormant_count} Dormant | {transitive_count} Transitive]",
        ""
    ]

    for rf in reachability_findings:
        pkg = rf.get("package_name", "")
        ver = rf.get("declared_version") or "unknown"
        cls = rf.get("reachability_classification", "")
        adv_id = rf.get("advisory_id", "")
        sev = rf.get("severity", "UNKNOWN")
        imp_status = rf.get("import_status", "")
        imp_ev = rf.get("import_evidence") or {}
        file_loc = imp_ev.get("file", "-")
        line_loc = imp_ev.get("line", "-")
        loc_str = f"{file_loc}:{line_loc}" if file_loc != "-" else "-"
        call_path = rf.get("call_path", [])
        path_str = " -> ".join(call_path) if call_path else "None"
        depth = rf.get("call_depth", 0)
        edge = rf.get("edge_type", "UNRESOLVED_EDGE")
        limitations = rf.get("limitations", [])

        lines.append(f"- [PKG] {pkg} ({ver}) -> {cls}")
        lines.append(f"  Advisory: {adv_id} ({sev})")
        lines.append(f"  Import State: {imp_status} ({loc_str})")
        lines.append(f"  Call Path: {path_str} (Depth: {depth}, Edge: {edge})")
        if limitations:
            lines.append(f"  Limitations: {'; '.join(limitations)}")
        lines.append("")

    return "\n".join(lines).rstrip()


def format_table(
    results: Dict[str, Any],
    findings: List[Dict[str, Any]],
    sca_findings: Optional[List[Any]] = None,
    sca_enabled: bool = False,
    secret_findings: Optional[List[Any]] = None,
    secrets_enabled: bool = False,
    reachability_findings: Optional[List[Any]] = None,
    reachability_enabled: bool = False
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
            if results.get("unresolved_dependencies"):
                lines.append("PARTIAL ANALYSIS: Analysis incomplete due to unresolved / deleted dependencies.")
                lines.append("\n[UNRESOLVED DEPENDENCIES]")
                for unres_item in results.get("unresolved_dependencies", []):
                    lines.append(f"  {unres_item}")
            else:
                lines.append("No security vulnerabilities detected.")
            if results.get("syntax_errors") or results.get("skipped_files"):
                lines.append("\n[PARSER & RESOURCE WARNINGS (SKIPPED FILES)]")
                for err in results.get("syntax_errors", []):
                    lines.append(f"  Skipping AST analysis for unparseable file: {err}")
                for skip in results.get("skipped_files", []):
                    lines.append(f"  {skip}")
            if reachability_enabled and reachability_findings:
                lines.append("\n" + format_reachability_section(reachability_findings))
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

        if results.get("syntax_errors") or results.get("skipped_files"):
            lines.append("\n[PARSER & RESOURCE WARNINGS (SKIPPED FILES)]")
            for err in results.get("syntax_errors", []):
                lines.append(f"  Skipping AST analysis for unparseable file: {err}")
            for skip in results.get("skipped_files", []):
                lines.append(f"  {skip}")

        if reachability_enabled and reachability_findings:
            lines.append("\n" + format_reachability_section(reachability_findings))

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
        if results.get("unresolved_dependencies"):
            lines.append("PARTIAL ANALYSIS: Analysis incomplete due to unresolved / deleted dependencies.")
            lines.append("\n[UNRESOLVED DEPENDENCIES]")
            for unres_item in results.get("unresolved_dependencies", []):
                lines.append(f"  {unres_item}")
        else:
            lines.append("No security vulnerabilities detected.")
        if results.get("syntax_errors") or results.get("skipped_files"):
            lines.append("\n[PARSER & RESOURCE WARNINGS (SKIPPED FILES)]")
            for err in results.get("syntax_errors", []):
                lines.append(f"  Skipping AST analysis for unparseable file: {err}")
            for skip in results.get("skipped_files", []):
                lines.append(f"  {skip}")
        if reachability_enabled and reachability_findings:
            lines.append("\n" + format_reachability_section(reachability_findings))
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

    if results.get("syntax_errors") or results.get("skipped_files"):
        lines.append("\n[PARSER & RESOURCE WARNINGS (SKIPPED FILES)]")
        for err in results.get("syntax_errors", []):
            lines.append(f"  Skipping AST analysis for unparseable file: {err}")
        for skip in results.get("skipped_files", []):
            lines.append(f"  {skip}")

    if reachability_enabled and reachability_findings:
        lines.append("\n" + format_reachability_section(reachability_findings))

    lines.append(sep)
    return "\n".join(lines)


from remediation import (
    PatchStatus,
    RemediationRecord,
    ProjectRemediationResult,
    format_remediation_section,
    remediate_project,
    RemediationEngine,
    RuleDispatcher,
    RemediationVerifier,
)


def discover_remediation_findings(
    files: Dict[str, str],
    config: Optional[TCSConfig],
    conservative_findings: List[Dict[str, Any]],
    start_vuln_idx: int = 1
) -> List[Dict[str, Any]]:
    """
    Dedicated Remediation-Oriented Discovery Pass (v1.0.1).

    Discovers findings eligible for automated remediation when conservative scan
    classified the flow as uncalled function parameter / POTENTIAL taint.

    Hard Invariants:
    1. Reuses existing execute_tcs_scan(files, config=config, audit_all=True) as candidate discovery feeder.
    2. UNKNOWN findings are NEVER auto-remediated (strictly prohibited).
    3. POTENTIAL findings are eligible ONLY for explicitly approved CWE patterns (CWE-89, CWE-78, CWE-22).
    4. Strict Semantic Correlation: Reuses RemediationVerifier.is_matching_finding to avoid duplicate admission.
    5. Full 7-Stage Verification Gate: Transformer success, syntax validation, semantic re-scan,
       target disappearance, and negative space check must ALL pass before candidate is admitted.
    6. Candidate Provenance: Admitted findings preserve their original confidence (CONFIRMED/POTENTIAL)
       and record discovery_mode = "REMEDIATION_DISCOVERY".
    """
    if not files:
        return []

    discovery_scan_results = execute_tcs_scan(files, config=config, audit_all=True)
    candidate_findings = discovery_scan_results.get("findings", [])
    if not candidate_findings:
        return []

    verifier = RemediationVerifier()
    engine = RemediationEngine(verifier=verifier)
    admitted: List[Dict[str, Any]] = []
    vuln_idx = start_vuln_idx

    for cf in candidate_findings:
        # Strict semantic duplicate check against existing conservative findings & already admitted candidates
        is_dup = any(verifier.is_matching_finding(cf, ef) for ef in conservative_findings)
        if not is_dup:
            is_dup = any(verifier.is_matching_finding(cf, af) for af in admitted)
        if is_dup:
            continue

        # Strict UNKNOWN Policy: UNKNOWN is NEVER auto-remediated under any circumstances
        conf_label = str(cf.get("confidence_label", "")).strip().upper()
        status_label = str(cf.get("status", "")).strip().upper()
        if conf_label == "UNKNOWN" or status_label == "UNKNOWN" or float(cf.get("confidence", 0.0)) <= 0.0:
            continue

        # Confidence gating: only CONFIRMED and approved POTENTIAL
        if conf_label not in ("CONFIRMED", "POTENTIAL"):
            continue

        # Explicit CWE-specific policy: only CWE-89, CWE-78, CWE-22 are supported for automated remediation
        cwe = str(cf.get("cwe", "")).strip().upper()
        if cwe not in ("CWE-89", "CWE-78", "CWE-22"):
            continue

        # Dispatcher check
        transformer = engine.dispatcher.get_transformer(cwe=cwe)
        if not transformer:
            continue

        # Complete 7-stage verification gate via engine.remediate
        rel_file = cf.get("file")
        source_code = files.get(rel_file)
        if source_code is None:
            continue

        try:
            rec = engine.remediate(cf, source_code, file_path=rel_file)
        except Exception:
            continue

        if rec.patch_status == PatchStatus.SUCCESS and rec.verification_passed and rec.patched_source:
            admitted_finding = dict(cf)
            admitted_finding["id"] = f"TCS-VULN-{vuln_idx:03d}"
            admitted_finding["discovery_mode"] = "REMEDIATION_DISCOVERY"
            admitted_finding["confidence"] = cf.get("confidence", 0.50)
            admitted_finding["confidence_label"] = conf_label
            admitted.append(admitted_finding)
            vuln_idx += 1

    return admitted


def main(argv: Optional[List[str]] = None):
    parser = argparse.ArgumentParser(
        description="TimeCodeSecurity (TCS) SAST & SCA Scanner CLI",
        prog="tcs"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=__version__,
        help="Show program's version number and exit"
    )
    parser.add_argument(
        "targets",
        nargs="*",
        default=[],
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
        "--sca-reachability",
        action="store_true",
        help="Enable Vector C AST-grounded dependency reachability analysis"
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
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat syntax errors as fatal (exit code 2)"
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Scan only git-staged changes with full cross-file semantic dependency closure"
    )
    parser.add_argument(
        "--audit-all",
        action="store_true",
        help="Emit speculative POTENTIAL findings for unresolved function parameters without known taint bindings"
    )
    parser.add_argument(
        "--fix", "--remediate",
        dest="fix",
        action="store_true",
        default=False,
        help="Generate automated AST remediation patches for eligible vulnerabilities"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Preview remediation patches without modifying files (default behavior for --fix)"
    )
    parser.add_argument(
        "--write",
        action="store_true",
        default=False,
        help="Authorize writing verified remediation patches to disk"
    )

    args = parser.parse_args(argv)

    fix_active = getattr(args, "fix", False) or getattr(args, "remediate", False)
    args.fix = fix_active
    args.remediate = fix_active

    if args.dry_run and args.write:
        print("[ERROR] Cannot specify both --dry-run and --write.", file=sys.stderr)
        sys.exit(2)

    if getattr(args, "staged", False) and fix_active:
        print("Error: --fix/--remediate is currently not supported with --staged mode. Run on working tree targets directly.", file=sys.stderr)
        sys.exit(2)

    raw_targets = [t for t in args.targets if t != "scan"]
    if len(raw_targets) == 0:
        args.target = "scan" if "scan" in args.targets else None
    else:
        args.target = raw_targets[0]

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
    elif getattr(args, "audit_all", False):
        active_secrets = True
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
    all_skipped_files: List[str] = []
    staged_unresolved_deps: List[str] = []

    if args.staged:
        if args.target is None or args.target == "scan":
            target = base_dir
        else:
            target = Path(os.path.expanduser(str(args.target))).resolve()
            if not target.exists():
                print(f"[ERROR] Target path does not exist: {args.target}", file=sys.stderr)
                sys.exit(2)

        repo_root = get_git_repo_root(target if target.is_dir() else target.parent)
        if repo_root is None:
            print(f"[WARN] --staged requested but '{target}' is not in a git repository.", file=sys.stderr)
            files = {}
            results = {
                "status": "success",
                "syntax_errors": [],
                "enabled_rules": list(config.effective_rules) if config else [r.cwe_id for r in GLOBAL_RULE_REGISTRY.all_rules()],
                "summary": {
                    "total_files": 0,
                    "lines_scanned": 0,
                    "total_vulnerabilities": 0,
                    "active_vulnerabilities": 0,
                    "suppressed_vulnerabilities": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "security_score": 100,
                    "score_label": "Security Health Score",
                    "risk_level": "CLEAN",
                    "risk_message": "NO VULNERABILITIES DETECTED within current TCS analysis scope (6 supported CWE classes)."
                },
                "findings": [],
                "skipped_files": []
            }
        else:
            staged_py, staged_d, staged_r, non_py = get_staged_git_files(repo_root)
            if not staged_py:
                print("[INFO] No staged Python files to scan.", file=sys.stderr)
                files = {}
                results = {
                    "status": "success",
                    "syntax_errors": [],
                    "enabled_rules": list(config.effective_rules) if config else [r.cwe_id for r in GLOBAL_RULE_REGISTRY.all_rules()],
                    "summary": {
                        "total_files": 0,
                        "lines_scanned": 0,
                        "total_vulnerabilities": 0,
                        "active_vulnerabilities": 0,
                        "suppressed_vulnerabilities": 0,
                        "critical_count": 0,
                        "high_count": 0,
                        "medium_count": 0,
                        "low_count": 0,
                        "security_score": 100,
                        "score_label": "Security Health Score",
                        "risk_level": "CLEAN",
                        "risk_message": "NO VULNERABILITIES DETECTED within current TCS analysis scope (6 supported CWE classes)."
                    },
                    "findings": [],
                    "skipped_files": []
                }
            else:
                files, staged_set, unres = build_staged_dependency_closure(
                    repo_root, staged_py, staged_deleted=staged_d
                )
                staged_unresolved_deps = unres
                for u in unres:
                    print(f"[ERROR] Unresolved dependency: {u}", file=sys.stderr)
                if unres:
                    print("[ERROR] Staged changes contain unresolved/deleted dependencies; analysis cannot prove CLEAN.", file=sys.stderr)
                try:
                    results = execute_tcs_scan(files, config=config, audit_all=getattr(args, "audit_all", False))
                except Exception as e:
                    print(f"[ERROR] Scan execution failed: {e}", file=sys.stderr)
                    sys.exit(2)
                raw_findings = results.get("findings", [])
                affected_findings = filter_findings_for_staged(raw_findings, staged_set)
                results["findings"] = affected_findings
                results["summary"] = recompute_summary_metrics(
                    results["summary"],
                    affected_findings,
                    total_files=len(files),
                    lines_scanned=sum(len(c.splitlines()) for c in files.values())
                )
                if unres:
                    results["status"] = "partial_analysis"
                    results["unresolved_dependencies"] = unres
                    if results["summary"]["active_vulnerabilities"] == 0:
                        results["summary"]["risk_level"] = "PARTIAL_ANALYSIS"
                        results["summary"]["risk_message"] = (
                            f"PARTIAL ANALYSIS: {len(unres)} unresolved dependency(ies) detected in staged changes; "
                            f"safety cannot be verified."
                        )
                        results["summary"]["security_score"] = 0
    else:
        if not args.target:
            print("[ERROR] Target path is required when --staged is not specified.", file=sys.stderr)
            parser.print_help(sys.stderr)
            sys.exit(2)

        target = Path(os.path.expanduser(str(args.target))).resolve()
        if not target.exists():
            print(f"[ERROR] Target path does not exist: {args.target}", file=sys.stderr)
            sys.exit(2)

        files = discover_python_files(target, base_dir, sca_active=args.sca, secrets_active=args.secrets, skipped_files=all_skipped_files)
        if not files and not args.sca and not args.secrets:
            print(f"[WARN] No Python (*.py) files found in: {args.target}", file=sys.stderr)

        try:
            results = execute_tcs_scan(files, config=config, audit_all=getattr(args, "audit_all", False))
        except Exception as e:
            print(f"[ERROR] Scan execution failed: {e}", file=sys.stderr)
            sys.exit(2)

    results["skipped_files"] = all_skipped_files

    if results.get("syntax_errors"):
        for err in results["syntax_errors"]:
            print(f"[WARN] Skipping AST analysis for unparseable file: {err}", file=sys.stderr)
        if getattr(args, "strict", False):
            print("[ERROR] Strict mode enabled and syntax errors encountered. Aborting.", file=sys.stderr)
            sys.exit(2)

    # ---------------------------------------------------------
    # Software Composition Analysis (SCA) - (if requested)
    # ---------------------------------------------------------
    sca_findings: List[SCAFinding] = []
    manifest_files: List[Path] = []
    all_deps: List[DependencyRecord] = []
    if args.sca:
        manifest_files = discover_manifest_files(target, base_dir, skipped_files=all_skipped_files)
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
            raw_cache = args.sca_cache or os.environ.get("TCS_OSV_CACHE")
            if raw_cache:
                cache_file = str(Path(os.path.expanduser(str(raw_cache))).resolve())
            else:
                cache_dir = (Path.home() / ".tcs").resolve()
                cache_dir.mkdir(parents=True, exist_ok=True)
                cache_file = str(cache_dir / "osv_cache.json")
            osv_client = OSVClient(cache_file=cache_file, offline_mode=args.sca_offline)
            osv_results = osv_client.query_packages(package_names)
            sca_findings = match_dependencies(all_deps, osv_results)

    # ---------------------------------------------------------
    # Secret Scanning Analysis (if requested)
    # ---------------------------------------------------------
    secret_findings: List[SecretFinding] = []
    secret_files: List[Path] = []

    if args.secrets:
        secret_files = discover_secret_files(target, base_dir, skipped_files=all_skipped_files)
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

    # ---------------------------------------------------------
    # Dedicated Remediation Discovery Pass (--fix without --audit-all)
    # ---------------------------------------------------------
    if args.fix and not getattr(args, "audit_all", False):
        admitted = discover_remediation_findings(
            files=files,
            config=config,
            conservative_findings=results.get("findings", []),
            start_vuln_idx=len(results.get("findings", [])) + 1
        )
        if admitted:
            all_combined = list(results.get("findings", [])) + admitted
            results["findings"] = all_combined
            results["summary"] = recompute_summary_metrics(
                original_summary=results.get("summary", {}),
                filtered_findings=all_combined,
                total_files=len(files),
                lines_scanned=sum(len(c.splitlines()) for c in files.values())
            )

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
                "confidence": "HIGH" if "HIGH" in str(sf.confidence) else str(sf.confidence),
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

    export_data["skipped_files"] = all_skipped_files
    if all_skipped_files:
        summary_copy = dict(export_data.get("summary", {}))
        summary_copy["skipped_files_count"] = len(all_skipped_files)
        export_data["summary"] = summary_copy

    if staged_unresolved_deps:
        export_data["status"] = "partial_analysis"
        export_data["unresolved_dependencies"] = staged_unresolved_deps

    # ---------------------------------------------------------
    # Vector C Reachability Analysis (if requested)
    # ---------------------------------------------------------
    reachability_findings: List[Dict[str, Any]] = []
    if getattr(args, "sca_reachability", False):
        cand_manifests = []
        cand_sources = []
        if target.is_dir():
            for mf_name in ("poetry.lock", "requirements.txt"):
                mf_candidate = target / mf_name
                if mf_candidate.exists():
                    cand_manifests.append(mf_candidate)
            for root, dirs, files_in_dir in os.walk(target):
                dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
                for f in files_in_dir:
                    if f.endswith(".py") and f != "tcs_cli.py":
                        cand_sources.append(Path(root) / f)
        else:
            if target.name in ("poetry.lock", "requirements.txt"):
                cand_manifests.append(target)
                for root, dirs, files_in_dir in os.walk(target.parent):
                    dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
                    for f in files_in_dir:
                        if f.endswith(".py") and f != "tcs_cli.py":
                            cand_sources.append(Path(root) / f)
            elif target.suffix == ".py":
                cand_sources.append(target)
                for mf_name in ("poetry.lock", "requirements.txt"):
                    mf_candidate = target.parent / mf_name
                    if mf_candidate.exists():
                        cand_manifests.append(mf_candidate)

        if cand_manifests and cand_sources:
            selected_mf = cand_manifests[0]
            try:
                rf_objs = analyze_dependency_reachability(selected_mf, cand_sources)
                reachability_findings = [f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in rf_objs]
            except Exception as e:
                print(f"[WARN] Vector C reachability analysis failed: {e}", file=sys.stderr)

        export_data["sca_reachability_findings"] = reachability_findings

    # ---------------------------------------------------------
    # Vector D Remediation Engine (delegated to remediation.orchestrator)
    # ---------------------------------------------------------
    remediation_res: Optional[ProjectRemediationResult] = None
    remediation_records: List[RemediationRecord] = []
    written_files: List[str] = []
    stale_files: List[str] = []
    unwritten_eligible_files: List[str] = []
    remediation_candidates = [f for f in effective_findings if not f.get("suppressed", False)]
    findings_by_file: Dict[str, List[Dict[str, Any]]] = {}

    if args.fix:
        remediation_res = remediate_project(
            files=files,
            effective_findings=effective_findings,
            target=target,
            base_dir=base_dir,
            is_write=args.write,
            pre_write_hook=_PRE_WRITE_HOOK
        )
        export_data["remediations"] = [rec.to_dict() for rec in remediation_res.remediation_records]
        export_data["remediation_summary"] = remediation_res.summary
        remediation_records = remediation_res.remediation_records
        written_files = remediation_res.written_files
        stale_files = remediation_res.stale_files
        unwritten_eligible_files = remediation_res.unwritten_eligible_files
        remediation_candidates = getattr(remediation_res, "remediation_candidates", remediation_candidates)
        findings_by_file = getattr(remediation_res, "findings_by_file", findings_by_file)

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
            secrets_enabled=args.secrets,
            reachability_findings=reachability_findings,
            reachability_enabled=args.sca_reachability
        )
        if args.fix:
            output_text += "\n\n" + format_remediation_section(
                remediation_records,
                written_files=written_files,
                is_write=args.write
            )

    if args.output:
        out_path = Path(os.path.expanduser(str(args.output))).resolve()
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
                sum_path = Path(os.path.expanduser(str(summary_file))).resolve()
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

        findings_items = [f"Findings: {total} (Active: {active}, Suppressed: {suppressed})"]
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

    if args.fix:
        if args.write:
            success_rems = sum(1 for r in remediation_records if r.patch_status == PatchStatus.SUCCESS and r.original_file in written_files)
            print(f"[TCS REMEDIATION] Wrote {len(written_files)} verified file(s) ({success_rems} patch(es) applied).", file=sys.stderr)
        else:
            success_rems = sum(1 for r in remediation_records if r.patch_status == PatchStatus.SUCCESS)
            print(f"[TCS REMEDIATION] Dry-run preview: {success_rems} verified patch(es) available. Run with --write to apply.", file=sys.stderr)

    has_sast_failure = len(effective_findings) > 0
    has_sca_failure = (len(sca_findings) > 0) if args.sca else False
    has_secret_failure = (len(secret_findings) > 0) if args.secrets else False

    if args.fix:
        total_eligible = len(remediation_candidates)
        all_remediated = (
            total_eligible > 0
            and len(remediation_records) == total_eligible
            and all(r.patch_status == PatchStatus.SUCCESS and r.verification_passed for r in remediation_records)
            and len(stale_files) == 0
            and len(unwritten_eligible_files) == 0
            and len(written_files) == len(findings_by_file)
        )
        if args.write and all_remediated and not has_sca_failure and not has_secret_failure:
            sys.exit(0)
        elif total_eligible == 0 and not has_sast_failure and not has_sca_failure and not has_secret_failure:
            sys.exit(0)
        else:
            sys.exit(1)
    else:
        if has_sast_failure or has_sca_failure or has_secret_failure:
            sys.exit(1)
        elif staged_unresolved_deps:
            sys.exit(2)
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
