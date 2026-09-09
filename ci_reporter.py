"""
TimeCodeSecurity (TCS) CI/CD Reporter & GitHub Step Summary Engine.
Converts unified TCS scan results (SAST, SCA, Secrets) into safe, deterministic
GitHub Actions workflow commands (::error, ::warning) and Markdown step summaries.

Invariants:
- 100% pure formatting; zero network I/O; zero file side-effects.
- Injection-immune workflow commands with strict percent-encoding of control characters.
- Zero raw secret exposure: only masked values and redacted contexts are serialized.
- Never False Clean: SCA UNRESOLVED states are explicitly preserved and surfaced.
- Deterministic byte-for-byte output via strict multi-attribute sorting.
"""

from typing import Dict, List, Any, Optional, Tuple


__all__ = [
    "escape_property_value",
    "escape_message_data",
    "format_github_annotation",
    "format_github_annotations",
    "generate_annotations",
    "generate_step_summary",
    "write_step_summary",
]


# Canonical display labels for secret types
_SECRET_TYPE_LABELS: Dict[str, str] = {
    "aws_access_key": "AWS Access Key",
    "github_token": "GitHub Token",
    "slack_token": "Slack Token",
    "private_key": "Private Key",
    "database_connection_string": "Database Connection String",
}


def escape_property_value(val: Any) -> str:
    """
    Escapes a property value (file, title, line, col, etc.) for GitHub Actions workflow commands.

    GitHub Actions workflow command specification requires:
      %  -> %25
      \\r -> %0D
      \\n -> %0A
      :  -> %3A
      ,  -> %2C

    Encoding % first is required to prevent double-encoding.
    Strictly neutralizes CRLF injection across all property parameters.
    """
    if val is None:
        return ""
    s = str(val)
    return (
        s.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def escape_message_data(val: Any) -> str:
    """
    Escapes message text for GitHub Actions workflow commands.

    GitHub Actions workflow command specification requires:
      %  -> %25
      \\r -> %0D
      \\n -> %0A

    Strictly ensures the message remains on a single line and cannot inject new commands.
    """
    if val is None:
        return ""
    s = str(val)
    return (
        s.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def _normalize_path(path: Any) -> str:
    """Normalizes file paths by converting backslashes to forward slashes and stripping redundant prefixes."""
    if not path:
        return ""
    norm = str(path).replace("\\", "/")
    if norm.startswith("./"):
        norm = norm[2:]
    return norm


def _extract_int_coord(val: Any) -> Optional[int]:
    """Extracts a valid 1-based coordinate integer, or returns None if missing/0/invalid."""
    if val is None:
        return None
    try:
        iv = int(val)
        return iv if iv > 0 else None
    except (ValueError, TypeError):
        return None


def format_github_annotation(
    level: str,
    message: str,
    file_path: Optional[str] = None,
    line: Optional[int] = None,
    col: Optional[int] = None,
    end_line: Optional[int] = None,
    end_col: Optional[int] = None,
    title: Optional[str] = None,
) -> str:
    """
    Constructs a single safe GitHub Actions workflow command line.

    Format:
      ::(error|warning|notice) file=...,line=...,col=...,title=...::message
    """
    cmd_level = level.lower()
    if cmd_level not in ("error", "warning", "notice"):
        cmd_level = "warning"

    props: List[str] = []
    if file_path:
        norm_file = _normalize_path(file_path)
        if norm_file:
            props.append(f"file={escape_property_value(norm_file)}")

    line_val = _extract_int_coord(line)
    if line_val is not None:
        props.append(f"line={line_val}")

    col_val = _extract_int_coord(col)
    if col_val is not None:
        props.append(f"col={col_val}")

    end_line_val = _extract_int_coord(end_line)
    if end_line_val is not None:
        props.append(f"endLine={end_line_val}")

    end_col_val = _extract_int_coord(end_col)
    if end_col_val is not None:
        props.append(f"endColumn={end_col_val}")

    if title:
        props.append(f"title={escape_property_value(title)}")

    prop_str = f" {','.join(props)}" if props else ""
    escaped_msg = escape_message_data(message)

    return f"::{cmd_level}{prop_str}::{escaped_msg}"


def _format_sast_annotation(finding: Dict[str, Any]) -> Tuple[Tuple[str, int, int, int, str], str]:
    """Formats a SAST finding into a GitHub Actions annotation with sorting tuple."""
    cwe = finding.get("cwe") or "CWE-UNKNOWN"
    sev = str(finding.get("severity") or "HIGH").upper()
    level = "error" if sev in ("CRITICAL", "HIGH") else "warning"

    file_path = finding.get("file") or ""
    line = _extract_int_coord(finding.get("line_number"))
    col = _extract_int_coord(finding.get("column_start"))

    raw_cat = finding.get("category") or ""
    cat_label = raw_cat.replace("_", " ").title() if raw_cat else ""
    title = f"{cwe} ({cat_label})" if cat_label else cwe

    # Extract informative message
    sink_sym = finding.get("sink_symbol")
    trace_summary = finding.get("flow_trace_summary")
    code_snip = finding.get("code_snippet")

    if trace_summary:
        msg = trace_summary
    elif sink_sym:
        msg = f"Untrusted input reaches dangerous sink '{sink_sym}'"
    elif code_snip:
        msg = f"Vulnerable code pattern: {code_snip.strip()}"
    else:
        msg = f"{cwe} security vulnerability detected"

    sort_key = (_normalize_path(file_path), line or 0, col or 0, 1, cwe)
    ann = format_github_annotation(
        level=level,
        message=msg,
        file_path=file_path,
        line=line,
        col=col,
        title=title,
    )
    return sort_key, ann


def _format_sca_annotation(finding: Any) -> Tuple[Tuple[str, int, int, int, str], str]:
    """Formats an SCA finding into a GitHub Actions annotation with sorting tuple."""
    # Support dict or dataclass
    if hasattr(finding, "to_dict"):
        sf = finding.to_dict()
    elif isinstance(finding, dict):
        sf = finding
    else:
        sf = getattr(finding, "__dict__", {})

    pkg = sf.get("package_name") or "unknown-package"
    vuln_id = sf.get("vulnerability_id") or "SCA-ADVISORY"
    status = str(sf.get("status") or "POTENTIAL").upper()
    sev = str(sf.get("severity") or "UNKNOWN").upper()
    manifest = sf.get("manifest_source") or ""
    line = _extract_int_coord(sf.get("line_number"))

    installed_ver = sf.get("installed_version")
    req_spec = sf.get("requested_specifier")
    fixed_ver = sf.get("fixed_version")
    summary = sf.get("summary")

    ver_desc = installed_ver or req_spec or "unspecified"

    if status == "UNRESOLVED":
        level = "warning"
        title = f"SCA Unresolved ({pkg})" if pkg != "unknown-package" else "SCA Unresolved"
        msg = summary or f"Vulnerability data could not be verified for package '{pkg}'"
    else:
        level = "error" if sev in ("CRITICAL", "HIGH") else "warning"
        title = f"SCA ({vuln_id})"
        fixed_part = f"; fixed in {fixed_ver}" if fixed_ver else ""
        msg = f"{pkg} {ver_desc} is affected ({vuln_id}){fixed_part}"

    sort_key = (_normalize_path(manifest), line or 0, 0, 2, vuln_id)
    ann = format_github_annotation(
        level=level,
        message=msg,
        file_path=manifest,
        line=line,
        title=title,
    )
    return sort_key, ann


def _format_secret_annotation(finding: Any) -> Tuple[Tuple[str, int, int, int, str], str]:
    """Formats a Secret finding into a safe, non-leaking GitHub Actions annotation with sorting tuple."""
    # Support dict or dataclass
    if hasattr(finding, "to_dict"):
        sec = finding.to_dict()
    elif isinstance(finding, dict):
        sec = finding
    else:
        sec = getattr(finding, "__dict__", {})

    sec_type = sec.get("secret_type") or "secret"
    label = _SECRET_TYPE_LABELS.get(sec_type, sec_type.replace("_", " ").title())
    masked_val = sec.get("masked_value") or "********"

    file_path = sec.get("file") or ""
    line = _extract_int_coord(sec.get("line_number"))
    col = _extract_int_coord(sec.get("column_start"))
    end_col = _extract_int_coord(sec.get("column_end"))

    # Canonical vulnerability mapping: CWE-798
    title = f"CWE-798 ({label})"
    # Zero raw secret exposure: only masked value is emitted
    msg = f"Hardcoded {label} detected: {masked_val}"

    sort_key = (_normalize_path(file_path), line or 0, col or 0, 3, sec_type)
    ann = format_github_annotation(
        level="error",
        message=msg,
        file_path=file_path,
        line=line,
        col=col,
        end_col=end_col,
        title=title,
    )
    return sort_key, ann


def format_github_annotations(scan_result: Dict[str, Any]) -> List[str]:
    """
    Converts unified TCS scan results into a deterministically ordered list of
    GitHub Actions workflow command annotations (::error, ::warning).

    Sort order: (file, line, col, engine, rule/vuln/secret_type).
    """
    if not isinstance(scan_result, dict):
        return []

    staged_items: List[Tuple[Tuple[str, int, int, int, str], str]] = []

    # 1. SAST Findings
    sast_findings = scan_result.get("findings", [])
    if isinstance(sast_findings, list):
        for f in sast_findings:
            if not isinstance(f, dict):
                continue
            # Respect suppressed flag (omit from active annotations)
            if f.get("suppressed", False):
                continue
            staged_items.append(_format_sast_annotation(f))

    # 2. SCA Findings
    sca_findings = scan_result.get("sca_findings", [])
    if isinstance(sca_findings, list):
        for sf in sca_findings:
            staged_items.append(_format_sca_annotation(sf))

    # 3. Secret Findings
    secret_findings = scan_result.get("secret_findings", [])
    if isinstance(secret_findings, list):
        for sec in secret_findings:
            staged_items.append(_format_secret_annotation(sec))

    # Deterministic sort
    staged_items.sort(key=lambda x: x[0])
    return [item[1] for item in staged_items]


# Alias for format_github_annotations
generate_annotations = format_github_annotations


def generate_step_summary(scan_result: Dict[str, Any]) -> str:
    """
    Generates a deterministic Markdown summary document suitable for $GITHUB_STEP_SUMMARY.

    Sections:
      1. # TimeCodeSecurity Scan (Title)
      2. Engine Status Table (SAST, SCA, Secrets)
      3. Security Metrics Table
      4. Findings Tables (SAST, SCA, Secrets) or Clean Message
    """
    if not isinstance(scan_result, dict):
        scan_result = {}

    lines: List[str] = ["# TimeCodeSecurity Scan", ""]

    # ---------------------------------------------------------
    # 1. Engine Status Determination
    # ---------------------------------------------------------
    # SAST
    sast_findings = scan_result.get("findings", [])
    active_sast = [f for f in sast_findings if isinstance(f, dict) and not f.get("suppressed", False)] if isinstance(sast_findings, list) else []
    sast_status = "FOUND" if len(active_sast) > 0 else "CLEAN"
    sast_count_str = str(len(active_sast))

    # SCA
    has_sca_key = "sca_findings" in scan_result
    sca_findings = scan_result.get("sca_findings", []) if has_sca_key else []
    if not isinstance(sca_findings, list):
        sca_findings = []

    if has_sca_key:
        sca_unresolved_count = 0
        for sf in sca_findings:
            st = sf.get("status") if isinstance(sf, dict) else getattr(sf, "status", "")
            if str(st).upper() == "UNRESOLVED":
                sca_unresolved_count += 1

        if sca_unresolved_count > 0:
            sca_status = "UNRESOLVED"
        elif len(sca_findings) > 0:
            sca_status = "FOUND"
        else:
            sca_status = "CLEAN"
        sca_count_str = str(len(sca_findings))
    else:
        sca_status = "INACTIVE"
        sca_count_str = "-"
        sca_unresolved_count = 0

    # Secrets
    has_sec_key = "secret_findings" in scan_result
    sec_findings = scan_result.get("secret_findings", []) if has_sec_key else []
    if not isinstance(sec_findings, list):
        sec_findings = []

    if has_sec_key:
        sec_status = "FOUND" if len(sec_findings) > 0 else "CLEAN"
        sec_count_str = str(len(sec_findings))
    else:
        sec_status = "INACTIVE"
        sec_count_str = "-"

    # Render Engine Status Table
    lines.append("| Engine | Status | Findings |")
    lines.append("|---|---|---:|")
    lines.append(f"| SAST | {sast_status} | {sast_count_str} |")
    lines.append(f"| SCA | {sca_status} | {sca_count_str} |")
    lines.append(f"| Secrets | {sec_status} | {sec_count_str} |")
    lines.append("")

    # ---------------------------------------------------------
    # 2. Security Metrics Table
    # ---------------------------------------------------------
    total_findings = len(active_sast) + len(sca_findings) + len(sec_findings)

    lines.append("## Security Metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| SAST findings | {len(active_sast)} |")
    lines.append(f"| SCA findings | {len(sca_findings)} |")
    lines.append(f"| SCA unresolved | {sca_unresolved_count} |")
    lines.append(f"| Secret findings | {len(sec_findings)} |")
    lines.append(f"| Total findings | {total_findings} |")
    lines.append("")

    # ---------------------------------------------------------
    # 3. Finding Details Tables
    # ---------------------------------------------------------
    lines.append("## Findings")
    lines.append("")

    if total_findings == 0:
        lines.append("*No vulnerabilities detected across active scanners.*")
        return "\n".join(lines)

    # SAST Table
    if active_sast:
        sorted_sast = sorted(
            active_sast,
            key=lambda f: (
                _normalize_path(f.get("file")),
                int(f.get("line_number") or 0),
                int(f.get("column_start") or 0),
                str(f.get("cwe", "")),
            )
        )
        lines.append("### SAST Code Analysis")
        lines.append("")
        lines.append("| CWE | Severity | Location | Sink / Details |")
        lines.append("|---|---|---|---|")
        for f in sorted_sast:
            cwe = f.get("cwe") or "CWE-UNKNOWN"
            sev = str(f.get("severity") or "HIGH").upper()
            loc = f"`{_normalize_path(f.get('file', ''))}:{f.get('line_number', '')}`"
            detail = f.get("sink_symbol") or f.get("flow_trace_summary") or f.get("code_snippet") or "Dataflow vulnerability"
            clean_detail = str(detail).replace("|", "\\|").replace("\n", " ").strip()
            lines.append(f"| {cwe} | {sev} | {loc} | {clean_detail} |")
        lines.append("")

    # SCA Table
    if sca_findings:
        def _sca_sort_key(item: Any):
            sf = item if isinstance(item, dict) else (item.to_dict() if hasattr(item, "to_dict") else getattr(item, "__dict__", {}))
            return (
                _normalize_path(sf.get("manifest_source")),
                int(sf.get("line_number") or 0),
                str(sf.get("package_name", "")),
                str(sf.get("vulnerability_id", "")),
            )

        sorted_sca = sorted(sca_findings, key=_sca_sort_key)
        lines.append("### SCA Dependencies")
        lines.append("")
        lines.append("| Package | Vulnerability | Severity | Status | Fixed Version | Manifest |")
        lines.append("|---|---|---|---|---|---|")
        for item in sorted_sca:
            sf = item if isinstance(item, dict) else (item.to_dict() if hasattr(item, "to_dict") else getattr(item, "__dict__", {}))
            pkg = sf.get("package_name") or "-"
            vid = sf.get("vulnerability_id") or "-"
            sev = str(sf.get("severity") or "UNKNOWN").upper()
            st = str(sf.get("status") or "POTENTIAL").upper()
            fixed = sf.get("fixed_version") or "-"
            line_str = f":{sf.get('line_number')}" if sf.get("line_number") else ""
            manifest = f"`{_normalize_path(sf.get('manifest_source', ''))}{line_str}`"
            lines.append(f"| {pkg} | {vid} | {sev} | {st} | {fixed} | {manifest} |")
        lines.append("")

    # Secrets Table
    if sec_findings:
        def _sec_sort_key(item: Any):
            sec = item if isinstance(item, dict) else (item.to_dict() if hasattr(item, "to_dict") else getattr(item, "__dict__", {}))
            return (
                _normalize_path(sec.get("file")),
                int(sec.get("line_number") or 0),
                int(sec.get("column_start") or 0),
                str(sec.get("secret_type", "")),
            )

        sorted_sec = sorted(sec_findings, key=_sec_sort_key)
        lines.append("### Secret Scanning (CWE-798)")
        lines.append("")
        lines.append("| Type | Masked Value | Location | Confidence | Detector |")
        lines.append("|---|---|---|---|---|")
        for item in sorted_sec:
            sec = item if isinstance(item, dict) else (item.to_dict() if hasattr(item, "to_dict") else getattr(item, "__dict__", {}))
            stype = sec.get("secret_type") or "secret"
            label = _SECRET_TYPE_LABELS.get(stype, stype.replace("_", " ").title())
            # Zero raw secret exposure: only masked value is formatted
            mv = f"`{sec.get('masked_value', '********')}`"
            line_str = f":{sec.get('line_number')}" if sec.get("line_number") else ""
            loc = f"`{_normalize_path(sec.get('file', ''))}{line_str}`"
            conf = str(sec.get("confidence") or "HIGH").upper()
            det = sec.get("detector") or stype
            lines.append(f"| {label} | {mv} | {loc} | {conf} | {det} |")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_step_summary(scan_result: Dict[str, Any], output_stream=None) -> str:
    """
    Helper to render and optionally write the step summary to a stream (e.g. sys.stdout or open file).
    Returns the generated Markdown string.
    """
    content = generate_step_summary(scan_result)
    if output_stream is not None:
        output_stream.write(content)
    return content
