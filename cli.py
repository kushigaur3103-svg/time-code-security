"""Standalone command-line interface for the TimeCodeSecurity AST scanner."""

import argparse
import ast
import fnmatch
import json
import os
from pathlib import Path
import re
import shutil
import sys
import subprocess
import time
import traceback
from typing import Optional
from cross_file_engine import CrossFileTaintEngine
from ast_scanner import TaintTracker
from ci_reporter import sanitize_symbol_display
from html_auditor import audit_templates, is_template_path
from iac_auditor import audit_iac_files, is_iac_path
from rule_engine import get_rule
from remediation.patch_engine import RemediationEngine
from sarif_adapter import bound_sarif_document
from sarif_exporter import atomic_write_text

try:
    from js_scanner import js_ts_available, run_js_ts_scan_isolated
    _JS_TS_SCANNER_AVAILABLE = True
except ImportError:
    _JS_TS_SCANNER_AVAILABLE = False

    def js_ts_available() -> bool:
        return False

    def run_js_ts_scan_isolated(target, base_dir=None, skipped_files=None):
        return []


SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
IGNORED_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "build", "dist"}

# Every finding belongs to exactly one analysis scope: template and IaC paths are routed to
# their auditors, everything else is Python. --scope selects which collectors run.
SCOPE_ORDER = ("python", "docker", "html")
SCOPE_LABELS = {"python": "Python Code", "docker": "Container/Config", "html": "HTML Templates"}


def _scope_of(path):
    lowered = str(path).lower()
    if is_template_path(lowered):
        return "html"
    if is_iac_path(lowered):
        return "docker"
    return "python"


def _file_key(path, cwd):
    try:
        return path.resolve().relative_to(cwd).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _parse_exclude_patterns(raw):
    if not raw:
        return None
    return [p.strip() for p in raw.split(",") if p.strip()] or None


def _is_excluded(path, root, exclude_patterns):
    """True when `path` matches any exclude pattern.

    Patterns are matched three ways because users write all three: a bare directory
    name (`tests`), a filename glob (`test_*.py`) and a rooted relative glob
    (`contrib/*/tests/*`). Matching only the basename or only the full relative path
    silently keeps nested hits, which is how `--exclude tests` used to survive
    `django/contrib/auth/tests/models.py`.

    Relative paths are normalised to POSIX before fnmatch, whose separator handling
    is not portable: on Windows `str(Path.relative_to())` yields backslashes, so a
    pattern containing `/` could never match.
    """
    if not exclude_patterns:
        return False
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    rel_posix = rel.as_posix()
    name = path.name
    parts = rel.parts
    for pattern in exclude_patterns:
        if fnmatch.fnmatchcase(rel_posix, pattern):
            return True
        if fnmatch.fnmatchcase(name, pattern):
            return True
        if any(fnmatch.fnmatchcase(part, pattern) for part in parts):
            return True
    return False


def _progress(message):
    """Emit one progress line on stderr so a stalled scan names the file it stuck on.

    stderr keeps stdout parsable (`--format json` consumers read stdout only) and
    flush=True means the line lands even if the process is killed mid-file.
    """
    print(f"[progress] {message}", file=sys.stderr, flush=True)


def _iter_tree_files(root):
    """Yield the real files under `root`, never following a symlink.

    Traversal guard (CWE-59): `Path.rglob` semantics are version dependent — Python
    3.13+ follows symlinked directories by default, so one link back into an ancestor
    makes the crawl loop. os.walk with followlinks=False plus explicit symlink pruning
    keeps discovery inside the real tree. Ignored directories are pruned before
    descending, so `node_modules` is never walked just to be filtered out again.
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in IGNORED_DIRS
            and not os.path.islink(os.path.join(dirpath, name))
        )
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if os.path.islink(path):
                continue
            yield path


def _collect_files(scan_path, exclude_patterns=None):
    """Collect Python files from scan path, optionally excluding by glob patterns.

    Args:
        scan_path: Path object (file or directory)
        exclude_patterns: List of glob patterns to exclude (e.g., ['tests', 'test_*'])
    """
    cwd = Path.cwd().resolve()
    if not scan_path.exists():
        raise FileNotFoundError(f"Path does not exist: {scan_path}")
    if scan_path.is_file():
        if scan_path.suffix.lower() != ".py":
            raise ValueError(f"Expected a Python file: {scan_path}")
        paths = [scan_path]
    elif scan_path.is_dir():
        paths = sorted(
            path for path in _iter_tree_files(scan_path)
            if path.suffix.lower() == ".py"
            and not any(part in IGNORED_DIRS for part in path.parts)
            and not _is_excluded(path, scan_path, exclude_patterns)
        )
    else:
        raise ValueError(f"Path is not a regular file or directory: {scan_path}")

    if not paths:
        raise ValueError(f"No Python files found: {scan_path}")

    files = {}
    skipped = 0
    total = len(paths)
    _progress(f"discovered {total} python file(s) under {scan_path}")
    for index, path in enumerate(paths, 1):
        _progress(f"reading python ({index}/{total}) {path}")
        try:
            files[_file_key(path, cwd)] = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            # A single unreadable file must not abort the scan of the whole tree.
            skipped += 1
            print(f"Warning: skipping unreadable file {path}: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
    if skipped:
        print(f"Warning: skipped {skipped} of {len(paths)} Python files; "
              f"{len(files)} scanned.", file=sys.stderr)
    return files


def _collect_auxiliary_files(scan_path, exclude_patterns=None):
    """Collect non-Python artefacts in one walk: (templates, IaC documents).

    Keys match _collect_files so findings share a single path namespace, and
    `--exclude` applies here too: a template under an excluded directory is just as
    out of scope as a .py file under it.
    """
    cwd = Path.cwd().resolve()
    if not scan_path.exists():
        raise FileNotFoundError(f"Path does not exist: {scan_path}")

    if scan_path.is_file():
        paths = [scan_path]
    elif scan_path.is_dir():
        paths = sorted(
            path for path in _iter_tree_files(scan_path)
            if not any(part in IGNORED_DIRS for part in path.parts)
            and not _is_excluded(path, scan_path, exclude_patterns)
        )
    else:
        return {}, {}

    templates = {}
    iac = {}
    buckets = {}
    for path in paths:
        relative = str(path).replace("\\", "/")
        if is_template_path(relative):
            buckets[path] = templates
        elif is_iac_path(relative):
            buckets[path] = iac

    total = len(buckets)
    _progress(f"discovered {total} template/IaC file(s) under {scan_path}")
    for index, (path, bucket) in enumerate(buckets.items(), 1):
        _progress(f"reading auxiliary ({index}/{total}) {path}")
        try:
            bucket[_file_key(path, cwd)] = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise OSError(f"Unable to read {path}: {exc}") from exc
    return templates, iac


def _merge_findings(*finding_groups):
    """Merge auditor findings with AST findings in a deterministic order."""
    seen = set()
    unique = []
    for group in finding_groups:
        for item in group:
            identity = (item["file"], item["line"], item["cwe"], item.get("category"))
            if identity in seen:
                continue
            seen.add(identity)
            unique.append(item)
    return sorted(unique, key=lambda entry: (entry["file"], entry["line"], entry["cwe"]))


# Several CWEs describe one *attribute* of the same defect: a single weak-digest call can
# be simultaneously a broken algorithm (327/328) and a storage-strength failure (759/916),
# and one set_cookie() can lack Secure (614), HttpOnly (1004) and SameSite (1275). Reporting
# every attribute as its own alert multiplies the count without adding an actionable site.
# An unbounded `f.read()` is the same case from the other direction: the rule engine calls it
# CWE-400 and the structural batch calls the identical call node CWE-770, so one sink is
# counted as two findings.
# The families below collapse to one finding per (file, line); the surviving CWEs are kept
# in `consolidated_from` so nothing is lost. This is presentation-only: the engine still emits
# every CWE, which is what the benchmark scores per rule.
FAMILY_PRIORITY = {
    "CRYPTO_HASH": ("CWE-327", "CWE-916", "CWE-759", "CWE-328"),
    "INSECURE_COOKIE": ("CWE-614", "CWE-1004", "CWE-1275"),
    "RESOURCE_EXHAUSTION": ("CWE-770", "CWE-400"),
}
FAMILY_OF_CWE = {
    cwe: family for family, members in FAMILY_PRIORITY.items() for cwe in members
}
COOKIE_FLAG_BY_CWE = {"CWE-614": "Secure", "CWE-1004": "HttpOnly", "CWE-1275": "SameSite"}
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _family_message(family, primary, members_by_cwe):
    """Alert text naming what the collapsed CWEs actually proved."""
    if family == "INSECURE_COOKIE":
        flags = [COOKIE_FLAG_BY_CWE[cwe] for cwe in FAMILY_PRIORITY[family] if cwe in members_by_cwe]
        return f"{primary}: Insecure Cookie Configuration (Missing {', '.join(flags)})"
    source = members_by_cwe[primary][0]["message"]
    operation = source.split(":", 1)[1].strip() if ":" in source else source
    secondaries = [cwe for cwe in FAMILY_PRIORITY[family] if cwe in members_by_cwe and cwe != primary]
    suffix = f" (consolidated: {', '.join(secondaries)})" if secondaries else ""
    return f"{primary}: {operation}{suffix}"


def _consolidate_family(family, group):
    members_by_cwe = {}
    for finding in group:
        members_by_cwe.setdefault(finding["cwe"], []).append(finding)
    priority = FAMILY_PRIORITY[family]
    primary = next(cwe for cwe in priority if cwe in members_by_cwe)
    representative = members_by_cwe[primary][0]
    consolidated = []
    for cwe in priority:
        consolidated.extend(member for member in members_by_cwe.get(cwe, []) if member is not representative)
    return {
        **representative,
        "cwe": primary,
        "line": min(member["line"] for member in group),
        "severity": max(
            (member["severity"] for member in group),
            key=lambda value: SEVERITY_RANK.get(value, 0),
        ),
        "message": _family_message(family, primary, members_by_cwe),
        "consolidated_from": [f"{member['cwe']}@{member['line']}" for member in consolidated],
    }


def consolidate_findings(findings):
    """Collapse same-site CWE families into one finding, preserving scan order."""
    buckets = {}
    for finding in findings:
        family = FAMILY_OF_CWE.get(finding["cwe"])
        if family:
            buckets.setdefault((family, finding["file"], finding["line"]), []).append(finding)

    emitted = set()
    consolidated = []
    for finding in findings:
        family = FAMILY_OF_CWE.get(finding["cwe"])
        if not family:
            consolidated.append(finding)
            continue
        key = (family, finding["file"], finding["line"])
        if key in emitted:
            continue
        emitted.add(key)
        consolidated.append(_consolidate_family(family, buckets[key]))
    return sorted(consolidated, key=lambda item: (item["file"], item["line"], item["cwe"]))


def _findings_for(tracker, edges):
    sinks = {sink.id: sink for sink in tracker.sinks}
    findings = []
    seen = set()
    for edge in edges:
        sink = sinks.get(edge.target_id)
        if sink is None:
            continue
        cwe = sink.metadata.get("cwe")
        if not cwe and edge.proof_graph is not None:
            cwe = edge.proof_graph.cwe
        cwe = cwe or "UNKNOWN_CWE"
        rule = get_rule(cwe)
        confidence_label = "CONFIRMED" if edge.kind == "CONFIRMED_DATA_FLOW" else "POTENTIAL"
        severity = rule.get_severity(confidence_label).upper() if rule else "HIGH"
        location = sink.location
        finding = {
            "file": location.file.replace("\\", "/"),
            "line": location.line_start,
            "cwe": cwe,
            "severity": severity,
            "category": sink.metadata.get("category") or (rule.category if rule else "Security"),
            "message": sink.metadata.get("message") or \
                f"{cwe}: {sink.metadata.get('operation') or sanitize_symbol_display(sink.symbol)}",
        }
        identity = (finding["file"], finding["line"], finding["cwe"])
        if identity not in seen:
            seen.add(identity)
            findings.append(finding)
    return sorted(findings, key=lambda item: (item["file"], item["line"], item["cwe"]))


def _parse_line_ranges(spec):
    """Parse a --lines value like '4-5' or '4-5,10' into inclusive (start, end) ranges.

    Returns None when the spec is empty/absent, meaning a full-file scan.
    Raises ValueError on malformed input so the CLI can report it cleanly.
    """
    if not spec:
        return None
    ranges = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        bounds = part.split("-", 1)
        try:
            start = int(bounds[0].strip())
            end = int(bounds[1].strip()) if len(bounds) > 1 else start
        except ValueError as exc:
            raise ValueError(f"Invalid --lines range {part!r}; expected START[-END]") from exc
        if start < 1 or end < start:
            raise ValueError(f"Invalid --lines range {part!r}; lines must be positive and ordered")
        ranges.append((start, end))
    return ranges or None


def _in_line_ranges(line, ranges):
    return ranges is None or any(start <= line <= end for start, end in ranges)


def _scope_findings_to_lines(findings, ranges):
    """Keep findings whose sink line intersects the requested ranges.

    Findings without a usable line number are kept: dropping them would turn an
    incremental scan into a false-negative source.
    """
    if ranges is None:
        return findings
    scoped = []
    for finding in findings:
        line = finding.get("line")
        if not isinstance(line, int):
            scoped.append(finding)
            continue
        if _in_line_ranges(line, ranges):
            scoped.append(finding)
    return scoped


def _statement_span(source_code, line_number):
    """Return the (start, end) line span of the smallest statement covering line_number.

    Falls back to (line_number, line_number) when the source is unparseable or no
    statement covers the requested line.
    """
    try:
        tree = ast.parse(source_code)
    except (SyntaxError, ValueError, RecursionError):
        return line_number, line_number

    candidates = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.stmt)
        and getattr(node, "lineno", 0)
        and node.lineno <= line_number <= (node.end_lineno or node.lineno)
    ]
    if not candidates:
        return line_number, line_number

    stmt = min(candidates, key=lambda n: (n.end_lineno or n.lineno) - n.lineno)
    return stmt.lineno, (stmt.end_lineno or stmt.lineno)


def _generate_autofix(finding, source_code, file_path, engine=None):
    """
    Generate an autofix object for a finding by running the RemediationEngine.
    
    Returns a dict with autofix schema or None if no deterministic fix is available.
    
    Autofix schema:
    {
        "type": "ast_patch",
        "description": str,
        "replacement_text": str,
        "range": {
            "start_line": int,
            "start_col": int,
            "end_line": int,
            "end_col": int
        },
        "diff": str (optional),
        "verification_passed": bool
    }
    """
    if engine is None:
        engine = RemediationEngine()
    
    # Map CLI finding to remediation engine format
    remediation_finding = {
        "id": f"TimeCodeSecurity-{finding['cwe'].replace('-', '')}-{finding['line']}",
        "cwe": finding["cwe"],
        "line_number": finding["line"],
        "file": finding["file"],
        "code_snippet": "",  # Will be extracted from source
    }
    
    try:
        record = engine.remediate(remediation_finding, source_code, file_path)
    except Exception:
        # If remediation fails entirely, return None
        return None
    
    # Only attach autofix for successful patches
    if record.patch_status.value != "SUCCESS":
        return None
    
    # The autofix replaces the whole original statement, so derive the range from
    # the statement span in the UNPATCHED source. The snippet's own line count is
    # not used: a multi-line replacement still overwrites a single-line statement.
    stmt_start, stmt_end = _statement_span(source_code, record.line_number)
    start_line = stmt_start
    end_line = stmt_end

    source_lines = source_code.split("\n")
    if 0 < end_line <= len(source_lines):
        end_col = len(source_lines[end_line - 1].rstrip("\r"))
    else:
        end_col = 0

    autofix = {
        "type": "ast_patch",
        "description": f"Apply {record.remediation_rule.value} transformation for {record.cwe}",
        "replacement_text": record.patched_code_snippet,
        "range": {
            "start_line": start_line,
            "start_col": 0,
            "end_line": end_line,
            "end_col": end_col
        },
        "diff": record.unified_diff,
        "verification_passed": record.verification_passed
    }
    
    return autofix


def _attach_autofixes(findings, source_cache, autofix_engine=None):
    """
    Attach autofix objects to findings where deterministic fixes are available.
    
    Args:
        findings: List of finding dicts
        source_cache: Dict mapping file paths to source code strings
        autofix_engine: Optional RemediationEngine instance
    
    Returns:
        List of findings with autofix objects attached where applicable
    """
    if autofix_engine is None:
        autofix_engine = RemediationEngine()
    
    enhanced_findings = []
    for finding in findings:
        file_path = finding["file"]
        source_code = source_cache.get(file_path)
        
        if source_code:
            autofix = _generate_autofix(finding, source_code, file_path, autofix_engine)
            if autofix:
                finding_copy = finding.copy()
                finding_copy["autofix"] = autofix
                enhanced_findings.append(finding_copy)
            else:
                enhanced_findings.append(finding)
        else:
            enhanced_findings.append(finding)
    
    return enhanced_findings


def _ascii_table(findings):
    headers = ("#", "File", "Line", "CWE", "Severity", "Category")
    max_widths = (3, 15, 4, 8, 8, 22)
    rows = [
        (str(index), item["file"], str(item["line"]), item["cwe"], item["severity"], item["category"].replace("_", " "))
        for index, item in enumerate(findings, 1)
    ]
    widths = [
        min(max_widths[index], max([len(headers[index])] + [len(row[index]) for row in rows]))
        for index in range(len(headers))
    ]

    def fit(value, width, keep_end=False):
        if len(value) <= width:
            return value.ljust(width)
        if keep_end:
            return "..." + value[-(width - 3):]
        return value[:width - 3] + "..."

    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    lines = [border, "| " + " | ".join(headers[i].ljust(widths[i]) for i in range(len(headers))) + " |", border]
    for row in rows:
        cells = [fit(row[index], widths[index], keep_end=index == 1) for index in range(len(headers))]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append(border)
    return "\n".join(lines)


def _sarif_rule(cwe, category, severity):
    """Build one driver rule carrying the same required members the SARIF adapter emits."""
    digits = re.search(r"\d+", str(cwe))
    rule_meta = get_rule(cwe)
    short = str(category).replace("_", " ")
    return {
        "id": cwe,
        "name": str(cwe).replace("-", "_"),
        "shortDescription": {"text": short},
        "fullDescription": {"text": rule_meta.name if rule_meta else short},
        "helpUri": (
            f"https://cwe.mitre.org/data/definitions/{digits.group()}.html"
            if digits else "https://cwe.mitre.org/data/definitions/index.html"
        ),
        "defaultConfiguration": {
            "level": "error" if severity in ("CRITICAL", "HIGH") else "warning"
        },
        "properties": {"tags": ["security", str(cwe).lower()]},
    }


def _sarif_uri(path, cwd):
    """Normalize a filesystem path into a valid SARIF artifactLocation URI."""
    resolved = Path(str(path).replace("\\", "/")).resolve()
    try:
        return resolved.relative_to(cwd).as_posix()
    except ValueError:
        return resolved.as_uri()


def _sarif_code_flows(flow_trace, cwd):
    """Wrap a cross-file trace in SARIF codeFlows/threadFlows for GHAS and VS Code viewers."""
    locations = []
    for step, hop in enumerate(flow_trace, 1):
        locations.append({
            "location": {
                "message": {"text": f"{hop['role']} : {hop['label']}"},
                "physicalLocation": {
                    "artifactLocation": {"uri": _sarif_uri(hop["file"], cwd)},
                    "region": {"startLine": max(1, hop["line"]), "startColumn": 1},
                },
            },
            "executionOrder": step,
            "importance": "essential",
        })
    return [{
        "message": {"text": "Cross-file taint execution path"},
        "threadFlows": [{"locations": locations}],
    }]


def _sarif_document(findings, cwd):
    rules = []
    rule_indexes = {}
    for finding in findings:
        cwe = finding["cwe"]
        if cwe in rule_indexes:
            continue
        rule_indexes[cwe] = len(rules)
        rules.append(_sarif_rule(cwe, finding["category"], finding["severity"]))

    level_by_severity = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "UNKNOWN": "note"}
    results = []
    for finding in findings:
        result = {
            "ruleId": finding["cwe"],
            "ruleIndex": rule_indexes[finding["cwe"]],
            "level": level_by_severity.get(finding["severity"], "warning"),
            "message": {"text": finding["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _sarif_uri(finding["file"], cwd)},
                    "region": {"startLine": max(1, finding["line"]), "startColumn": 1},
                }
            }],
        }
        flow_trace = finding.get("flow_trace")
        if flow_trace:
            result["codeFlows"] = _sarif_code_flows(flow_trace, cwd)
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "TimeCodeSecurity", "rules": rules}},
            "results": results,
        }],
    }


def _scope_breakdown(findings):
    counts = {scope: 0 for scope in SCOPE_ORDER}
    for finding in findings:
        counts[_scope_of(finding["file"])] += 1
    return counts


def _print_summary(file_count, duration_ms, findings, file_counts=None,
                   discovered_files=None, fast_path_skipped_files=0,
                   unparseable_files=0, parse_governor=None):
    counts = {severity: 0 for severity in SEVERITIES}
    scope_counts = _scope_breakdown(findings)
    for finding in findings:
        severity = finding["severity"]
        counts[severity if severity in counts else "UNKNOWN"] += 1
    if discovered_files is not None:
        print(f"\nTotal discovered files: {discovered_files}")
    print(f"Total scanned files: {file_count}")
    if file_counts:
        print("Files scanned by scope: " + ", ".join(
            f"{SCOPE_LABELS[scope]}: {file_counts[scope]}" for scope in SCOPE_ORDER
        ))
        skipped = discovered_files - file_count if discovered_files is not None else 0
        if skipped:
            print(f"Files not scanned: {skipped} "
                  f"({fast_path_skipped_files} fast-path skipped, "
                  f"{unparseable_files} unparseable)")
    if parse_governor:
        workers = parse_governor.get("workers_final", parse_governor.get("workers_used"))
        print(f"Parser: {parse_governor.get('parse_mode', 'unknown')} mode, "
              f"{workers} worker(s), "
              f"{parse_governor.get('governor_events', 0)} governor reduction(s)")
    print(f"Scan duration: {duration_ms:.2f} ms")
    print("Findings by severity: " + ", ".join(f"{severity.title()}: {counts[severity]}" for severity in SEVERITIES))
    print("Findings by scope: " + ", ".join(
        f"{SCOPE_LABELS[scope]}: {scope_counts[scope]}" for scope in SCOPE_ORDER
    ))


def _cross_trace_report(findings, cwd):
    """Render the multi-hop attack path for every cross-file finding, or '' if none."""
    traced = [
        (index, finding)
        for index, finding in enumerate(findings, 1)
        if finding.get("category") == "cross_file" and finding.get("flow_trace")
    ]
    if not traced:
        return ""

    rule = "-" * 80
    lines = ["", rule, "        TIMECODESECURITY - CROSS-FILE EXPLOIT CHAINS", rule]
    for index, finding in traced:
        rule_meta = get_rule(finding["cwe"])
        label = (rule_meta.category if rule_meta else finding.get("category", "")).replace("_", " ").upper()
        lines.append(f"[TRACE] Finding #{index}: {finding['cwe']} ({label})")
        for step, hop in enumerate(finding["flow_trace"], 1):
            location = _file_key(Path(hop["file"]), cwd)
            lines.append(f"  {step}. {hop['role'].ljust(7)}: {location}:{hop['line']} ({hop['label']})")
        lines.append(rule)
    return "\n".join(lines)



class CrossFinding(dict):
    """Hybrid finding: acts as dict and object simultaneously."""
    def __init__(self, cwe, file_path, lineno, message, severity="HIGH", flow_trace=None):
        super().__init__(
            cwe=cwe,
            rule_id=cwe,
            severity="HIGH",
            file_path=file_path,
            file=file_path,
            path=file_path,
            lineno=lineno,
            line=lineno,
            message=message,
            desc=message,
            description=message,
            category="cross_file",
            flow_trace=flow_trace or [],
        )
        self.category = "cross_file"
        self.flow_trace = flow_trace or []
        self.cwe = cwe
        self.rule_id = cwe
        self.severity = "HIGH"
        self.file_path = file_path
        self.file = file_path
        self.path = file_path
        self.lineno = lineno
        self.line = lineno
        self.message = message
        self.desc = message
        self.description = message

def _run_cross_scan(target_path):
    """Executes CrossFileTaintEngine. Returns (findings, engine).

    An engine failure is fatal rather than empty: swallowing the exception made a broken
    cross-file analysis indistinguishable from a clean scan, silently dropping both the
    cross-file findings and the sanitizer suppression that depends on the engine.
    """
    try:
        engine = CrossFileTaintEngine(target_path)
        raw_findings = engine.run()
    except Exception as exc:
        print(f"[FATAL] CrossFileTaintEngine crashed: {exc}", file=sys.stderr)
        traceback.print_exc()
        raise SystemExit(1)

    results = []
    for cf in raw_findings:
        msg = f"Cross-file leak: {cf.caller_func} flows into {cf.callee_func} ({cf.callee_sink_name}) at {cf.callee_file}:{cf.callee_sink_lineno}"
        results.append(CrossFinding(
            cwe=cf.cwe,
            file_path=cf.caller_file,
            lineno=cf.caller_lineno,
            message=msg,
            severity="HIGH",
            flow_trace=[
                {"role": hop.role, "file": hop.file_path, "line": hop.lineno, "label": hop.label}
                for hop in getattr(cf, "flow_trace", None) or []
            ],
        ))
    return results, engine


def _suppress_cross_file_sanitized(findings, engine):
    """Drop single-file findings whose tainted arguments a cross-file sanitizer neutralized.

    The AST scanner has no visibility into callee contracts, so `cmd = format_command(x)`
    followed by `os.system(cmd)` is reported as injectable even when the helper escapes its
    argument. Cross-file findings are left untouched: that engine already honours contracts.

    A failure here is fatal, not ignored: returning the findings unchanged would silently
    re-introduce every sanitizer false positive and still report a successful scan.
    """
    try:
        sanitized_sites = {
            (_normalize_compare_path(file_path), lineno)
            for file_path, lineno in engine.sanitized_sink_locations()
        }
    except Exception as exc:
        print(f"[FATAL] CrossFileTaintEngine sanitizer analysis crashed: {exc}", file=sys.stderr)
        traceback.print_exc()
        raise SystemExit(1)
    if not sanitized_sites:
        return findings

    kept = []
    for finding in findings:
        if finding.get("category") == "cross_file":
            kept.append(finding)
            continue
        identity = (_normalize_compare_path(finding["file"]), finding["line"])
        if identity in sanitized_sites:
            continue
        kept.append(finding)
    return kept

def _js_ts_findings(path):
    """Map the isolated tree-sitter JS/TS findings onto this module's finding shape."""
    mapped = []
    for finding in run_js_ts_scan_isolated(path, base_dir=Path.cwd().resolve()):
        mapped.append({
            "file": str(finding.get("file", "")).replace("\\", "/"),
            "line": finding.get("line_number") or 1,
            "cwe": finding.get("cwe") or "UNKNOWN_CWE",
            "severity": str(finding.get("severity") or "HIGH").upper(),
            "category": finding.get("category") or "Security",
            "message": finding.get("message") or "",
        })
    return sorted(mapped, key=lambda item: (item["file"], item["line"], item["cwe"]))


def _scan_failure(args, exc):
    """A crashed scan still owes CI parsable artefacts, then reports exit 2.

    Without this the process dies on a traceback: stdout JSON stays empty (0-byte file
    after redirection) and the SARIF target never exists, which GitHub's uploader
    reports as an unrelated failure.
    """
    message = f"{type(exc).__name__}: {exc}"
    print(f"[FATAL] TimeCodeSecurity scan aborted: {message}", file=sys.stderr)
    if getattr(args, "format", "") == "json":
        print(json.dumps({
            "scope": getattr(args, "scope", "all"),
            "status": "incomplete",
            "error": message,
            "total_discovered_files": 0,
            "scanned_files": 0,
            "fast_path_skipped_files": 0,
            "unparseable_files": 0,
            "findings": [],
        }, indent=2))
    if getattr(args, "sarif", None):
        try:
            document = bound_sarif_document(_sarif_document([], Path.cwd().resolve()))
            atomic_write_text(Path(args.sarif), json.dumps(document, indent=2) + "\n")
        except OSError as write_exc:
            print(f"Error writing fallback SARIF file: {write_exc}", file=sys.stderr)
    return 2


def _parse_workers_arg(workers_str: Optional[str]) -> int:
    """Parse --workers argument into integer worker count.
    
    Args:
        workers_str: String value from CLI ('1', '2', '4', '8', 'auto', or None)
    
    Returns:
        Integer worker count (defaults to os.cpu_count() for full multi-core utilization)
    """
    if workers_str is None:
        workers_str = "auto"
    
    workers_str = workers_str.strip().lower()
    
    if workers_str == "auto":
        try:
            import os
            cpu_count = os.cpu_count() or 4
            # Use all available CPU cores (dynamic multi-core concurrency)
            return max(1, cpu_count)
        except Exception:
            return 4
    
    try:
        n = int(workers_str)
        if n < 1:
            print("Warning: --workers must be >= 1, using 1", file=sys.stderr)
            return 1
        if n > 64:
            print(f"Warning: --workers={n} is excessive, capping at 32", file=sys.stderr)
            return 32
        return n
    except ValueError:
        print(f"Warning: invalid --workers value '{workers_str}', using auto-detect", file=sys.stderr)
        try:
            import os
            return os.cpu_count() or 4
        except Exception:
            return 4


def _scan(args):
    scope = args.scope
    
    # Parse workers argument and pass to TaintTracker
    workers = _parse_workers_arg(getattr(args, "workers", None))
    
    try:
        line_ranges = _parse_line_ranges(getattr(args, "lines", None))
        exclude_patterns = _parse_exclude_patterns(getattr(args, "exclude", None))
        templates, iac = _collect_auxiliary_files(args.path, exclude_patterns)
        if scope not in ("all", "html"):
            templates = {}
        if scope not in ("all", "docker"):
            iac = {}
        tracker = None
        files = {}
        if scope in ("all", "python"):
            try:
                files = _collect_files(args.path, exclude_patterns=exclude_patterns)
            except ValueError:
                if not templates and not iac:
                    raise
        
        # TimeCodeSecurity: Capture pre-scan memory stats
        try:
            import psutil
            mem_before = psutil.virtual_memory()
            available_ram_before_gb = mem_before.available / (1024 ** 3)
            rss_before_mb = psutil.Process().memory_info().rss / (1024 ** 2)
        except ImportError:
            available_ram_before_gb = 0
            rss_before_mb = 0
        
        started = time.perf_counter()
        if files:
            _progress(f"parsing {len(files)} python file(s) with {workers} worker(s)")
            tracker = TaintTracker(files=files, max_workers=workers)
            for fpath, reason in sorted(tracker.skipped_files.items()):
                print(f"Warning: skipping unparseable file {fpath}: {reason}", file=sys.stderr)
            _, _, edges = tracker.analyze()
            ast_findings = _findings_for(tracker, edges)
            _progress(f"parsed + traced, {len(ast_findings)} AST finding(s) so far")
        else:
            ast_findings = []
        file_counts = {
            "python": len(tracker.modules) if tracker else 0,
            "docker": len(iac),
            "html": len(templates),
        }
        scanned_files = sum(file_counts.values())
        parse_stats = getattr(tracker, "parse_stats", None) or {}
        python_discovered = parse_stats.get("discovered", len(files))
        fast_path_skipped_files = parse_stats.get("fast_path_skipped", 0)
        unparseable_files = parse_stats.get(
            "unparseable", len(tracker.skipped_files) if tracker else 0)
        scope_breakdown = {
            "python": {
                "discovered": python_discovered,
                "scanned": file_counts["python"],
                "fast_path_skipped": fast_path_skipped_files,
                "unparseable": unparseable_files,
            },
            "docker": {
                "discovered": len(iac),
                "scanned": file_counts["docker"],
            },
            "html": {
                "discovered": len(templates),
                "scanned": file_counts["html"],
            },
        }
        total_discovered_files = sum(bucket["discovered"] for bucket in scope_breakdown.values())
        parse_governor = {
            key: parse_stats[key]
            for key in ("parse_mode", "workers_used", "workers_initial",
                        "workers_final", "governor_events")
            if key in parse_stats
        }
        findings = _merge_findings(ast_findings, audit_templates(templates), audit_iac_files(iac))
        findings = consolidate_findings(findings)
        if scope in ("all", "python"):
            cross_findings, cross_engine = _run_cross_scan(args.path)
            findings = _suppress_cross_file_sanitized(findings, cross_engine)
            findings.extend(cross_findings)

        # Incremental scan: keep only diagnostics intersecting the modified lines.
        # Applied before autofix generation so patching work is scoped too.
        findings = _scope_findings_to_lines(findings, line_ranges)

        # Opt-in tree-sitter JS/TS pass. Off by default: the grammar is a native
        # extension whose access violation takes the whole process down.
        if getattr(args, "include_js", False) and _JS_TS_SCANNER_AVAILABLE and js_ts_available():
            findings = _merge_findings(findings, _js_ts_findings(args.path))

        # Generate autofix suggestions if requested (JSON only)
        if args.with_autofix and args.format == "json" and files:
            # Build source cache from scanned files
            source_cache = {}
            for file_path in files:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        source_cache[file_path.replace("\\", "/")] = f.read()
                except (OSError, UnicodeDecodeError):
                    pass
            
            # Attach autofixes where deterministic fixes are available
            autofix_engine = RemediationEngine()
            findings = _attach_autofixes(findings, source_cache, autofix_engine)
        
        duration_ms = (time.perf_counter() - started) * 1000
        
        # TimeCodeSecurity: Capture post-scan memory stats
        try:
            import psutil
            mem_after = psutil.virtual_memory()
            available_ram_after_gb = mem_after.available / (1024 ** 3)
            rss_after_mb = psutil.Process().memory_info().rss / (1024 ** 2)
            peak_rss_mb = rss_after_mb
            available_ram_gb = min(available_ram_before_gb, available_ram_after_gb)
        except ImportError:
            peak_rss_mb = 0
            available_ram_gb = 0
    except (OSError, ValueError) as exc:
        return _scan_failure(args, exc)

    if args.format == "json":
        print(json.dumps({
            "scope": scope,
            "line_filter": [list(r) for r in line_ranges] if line_ranges else None,
            "total_discovered_files": total_discovered_files,
            "scanned_files": scanned_files,
            "scanned_files_by_scope": file_counts,
            "fast_path_skipped_files": fast_path_skipped_files,
            "unparseable_files": unparseable_files,
            "scope_breakdown": scope_breakdown,
            "parse_governor": parse_governor,
            "duration_ms": round(duration_ms, 2),
            "findings_by_scope": _scope_breakdown(findings),
            "findings": findings,
        }, indent=2))
    else:
        print(_ascii_table(findings) if findings else "[+] No vulnerabilities found. Clean scan!")
        _print_summary(scanned_files, duration_ms, findings, file_counts,
                       discovered_files=total_discovered_files,
                       fast_path_skipped_files=fast_path_skipped_files,
                       unparseable_files=unparseable_files,
                       parse_governor=parse_governor)
        traces = _cross_trace_report(findings, Path.cwd().resolve())
        if traces:
            print(traces)

    if args.sarif:
        try:
            document = bound_sarif_document(_sarif_document(findings, Path.cwd().resolve()))
            sarif_path = Path(args.sarif)
            atomic_write_text(sarif_path, json.dumps(document, indent=2) + "\n")
            sarif_size_mb = sarif_path.stat().st_size / (1024 ** 2) if sarif_path.exists() else 0
        except OSError as exc:
            print(f"Error writing SARIF file: {exc}", file=sys.stderr)
            return 2
    else:
        sarif_size_mb = 0
    
    # TimeCodeSecurity: Print performance metrics to stderr
    if files and tracker:
        try:
            from tcs.parallel_scanner import HARD_SAFETY_THRESHOLD_MB

            print("\n" + "="*70, file=sys.stderr)
            print("TimeCodeSecurity - Performance Metrics", file=sys.stderr)
            print("="*70, file=sys.stderr)
            print(f"Wall-Clock Scan Time:     {duration_ms/1000:.2f}s ({duration_ms:.0f}ms)", file=sys.stderr)
            print(f"Parser Mode:              {parse_governor.get('parse_mode', 'unknown')}", file=sys.stderr)
            print(f"Worker Count Utilized:    {parse_governor.get('workers_final', parse_governor.get('workers_used', 'n/a'))}"
                  f" (governor start: {parse_governor.get('workers_initial', parse_governor.get('workers_used', 'n/a'))}, "
                  f"reductions: {parse_governor.get('governor_events', 0)})", file=sys.stderr)
            print(f"Governor RAM Floor:       {HARD_SAFETY_THRESHOLD_MB} MB", file=sys.stderr)
            print(f"Peak Memory RSS:          {peak_rss_mb:.1f} MB", file=sys.stderr)
            print(f"Available RAM (min):      {available_ram_gb:.2f} GB", file=sys.stderr)
            print(f"Total Findings:           {len(findings)}", file=sys.stderr)
            if args.sarif:
                print(f"SARIF File Size:          {sarif_size_mb:.2f} MB {'✓' if sarif_size_mb < 10 else '⚠ EXCEEDS 10 MB'}", file=sys.stderr)
            print(f"Files Discovered:         {total_discovered_files} "
                  f"(python: {python_discovered}, docker: {len(iac)}, html: {len(templates)})", file=sys.stderr)
            print(f"Files Scanned:            {scanned_files} "
                  f"(python: {file_counts['python']}, docker: {file_counts['docker']}, html: {file_counts['html']})", file=sys.stderr)
            print(f"Zero-Risk Fast-Path Skip: {fast_path_skipped_files} skipped", file=sys.stderr)
            print(f"Unparseable Files:        {unparseable_files} skipped", file=sys.stderr)
            print("="*70, file=sys.stderr)
        except ImportError:
            pass  # Parallel scanner not available, skip metrics

    # Exit-code parity with `tcs_cli.py`: a scan that finds something exits 1, so CI can gate
    # on either entry point. 2 stays reserved for an internal error (see the crash handler).
    # `--fail-on-critical` narrows what blocks: only Critical/High findings count.
    if args.fail_on_critical:
        blocking = [item for item in findings if item["severity"] in ("CRITICAL", "HIGH")]
    else:
        blocking = findings
    return 1 if blocking else 0


def _normalize_compare_path(value):
    return os.path.normcase(str(Path(value).resolve()))


def _normalize_cwes(value):
    if isinstance(value, dict):
        value = value.get("id", "")
    values = value if isinstance(value, list) else [value]
    cwes = set()
    for item in values:
        if isinstance(item, dict):
            item = item.get("id", "")
        text = str(item or "").upper()
        cwes.update(f"CWE-{number}" for number in re.findall(r"\bCWE[-_ ]?(\d+)\b", text))
        if text.isdigit():
            cwes.add(f"CWE-{text}")
    return sorted(cwes) if cwes else ["UNKNOWN_CWE"]


def _competitor_findings(tool, data):
    findings = []
    if tool == "semgrep":
        for item in data.get("results", []):
            metadata = item.get("extra", {}).get("metadata", {})
            cwes = _normalize_cwes(metadata.get("cwe"))
            if cwes == ["UNKNOWN_CWE"]:
                cwes = _normalize_cwes(item.get("check_id", ""))
            path = item.get("path", "")
            line = item.get("start", {}).get("line", 0)
            rule = item.get("check_id", "")
            message = item.get("extra", {}).get("message", "")
            for cwe in cwes:
                findings.append({"file": _normalize_compare_path(path), "line": line, "cwe": cwe, "rule": rule, "message": message})
    else:
        for item in data.get("results", []):
            cwes = _normalize_cwes(item.get("issue_cwe"))
            path = item.get("filename", "")
            line = item.get("line_number", 0)
            rule = item.get("test_id", "")
            message = item.get("issue_text", "")
            for cwe in cwes:
                findings.append({"file": _normalize_compare_path(path), "line": line, "cwe": cwe, "rule": rule, "message": message})
    return findings


def _run_competitor(tool, scan_path):
    executable = shutil.which(tool)
    if executable is None:
        print(f"Error: {tool} is not installed or not available on PATH.", file=sys.stderr)
        return None, None, 127
    if tool == "semgrep":
        command = [executable, "scan", "--json", "--config", "auto", str(scan_path)]
    else:
        command = [executable, "-r", "-f", "json", str(scan_path)]

    started = time.perf_counter()
    try:
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    except OSError as exc:
        print(f"Error: unable to run {tool}: {exc}", file=sys.stderr)
        return None, None, 2
    duration_ms = (time.perf_counter() - started) * 1000
    try:
        data = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        detail = completed.stderr.strip() or completed.stdout.strip() or f"process exited with status {completed.returncode}"
        print(f"Error: {tool} did not return valid JSON: {detail}", file=sys.stderr)
        return None, None, 2
    return _competitor_findings(tool, data), duration_ms, 0


def _compare_findings(tcs_findings, competitor_findings, tolerance):
    matched = []
    matched_tcs = set()
    competitor_only = []
    for competitor in competitor_findings:
        candidates = [
            (index, finding) for index, finding in enumerate(tcs_findings)
            if finding["_normalized_file"] == competitor["file"]
            and finding["cwe"] == competitor["cwe"]
            and abs(finding["line"] - competitor["line"]) <= tolerance
        ]
        if candidates:
            tcs_index, finding = min(candidates, key=lambda pair: abs(pair[1]["line"] - competitor["line"]))
            matched_tcs.add(tcs_index)
            matched.append({"cwe": competitor["cwe"], "file": finding["file"], "tcs_line": finding["line"], "competitor_line": competitor["line"], "rule": competitor["rule"]})
        else:
            competitor_only.append(competitor)

    tcs_only = [finding for index, finding in enumerate(tcs_findings) if index not in matched_tcs]
    return matched, tcs_only, competitor_only


def _cwe_breakdown(matched, tcs_only, competitor_only):
    cwes = sorted({item["cwe"] for item in matched + tcs_only + competitor_only})
    return [
        {
            "cwe": cwe,
            "both": sum(item["cwe"] == cwe for item in matched),
            "tcs_only": sum(item["cwe"] == cwe for item in tcs_only),
            "competitor_only": sum(item["cwe"] == cwe for item in competitor_only),
        }
        for cwe in cwes
    ]


def _print_compare_scoreboard(tool, tcs_ms, competitor_ms, matched, tcs_only, competitor_only, breakdown):
    summary_rows = [
        ("Execution speed", f"TimeCodeSecurity {tcs_ms:.2f} ms vs {tool.title()} {competitor_ms:.2f} ms"),
        ("Matched Findings (both)", str(len(matched))),
        ("TimeCodeSecurity Exclusive Findings", str(len(tcs_only))),
        (f"{tool.title()} Only Findings", str(len(competitor_only))),
    ]
    summary_headers = ("Metric", "Result")
    summary_widths = [max(len(summary_headers[index]), *(len(row[index]) for row in summary_rows)) for index in range(len(summary_headers))]
    summary_border = "+" + "+".join("-" * (width + 2) for width in summary_widths) + "+"
    print("Comparison Scoreboard")
    print(summary_border)
    print("| " + " | ".join(summary_headers[index].ljust(summary_widths[index]) for index in range(len(summary_headers))) + " |")
    print(summary_border)
    for row in summary_rows:
        print("| " + " | ".join(row[index].ljust(summary_widths[index]) for index in range(len(summary_headers))) + " |")
    print(summary_border)
    rows = [(item["cwe"], str(item["both"]), str(item["tcs_only"]), str(item["competitor_only"])) for item in breakdown]
    headers = ("CWE", "Both", "TimeCodeSecurity only", f"{tool.title()} only")
    widths = [max(len(headers[index]), *(len(row[index]) for row in rows)) for index in range(len(headers))]
    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    print("\nCWE Breakdown")
    print(border)
    print("| " + " | ".join(headers[index].ljust(widths[index]) for index in range(len(headers))) + " |")
    print(border)
    for row in rows:
        print("| " + " | ".join(row[index].ljust(widths[index]) for index in range(len(headers))) + " |")
    print(border)


def _compare(args):
    try:
        exclude_patterns = _parse_exclude_patterns(getattr(args, "exclude", None))
        templates, iac = _collect_auxiliary_files(args.path, exclude_patterns)

        try:
            files = _collect_files(args.path, exclude_patterns=exclude_patterns)
        except ValueError:
            if not templates and not iac:
                raise
            files = {}
        started = time.perf_counter()
        if files:
            tracker = TaintTracker(files=files)
            _, _, edges = tracker.analyze()
            ast_findings = _findings_for(tracker, edges)
        else:
            ast_findings = []
        tcs_findings = _merge_findings(ast_findings, audit_templates(templates), audit_iac_files(iac))
        tcs_ms = (time.perf_counter() - started) * 1000
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    for finding in tcs_findings:
        finding["_normalized_file"] = _normalize_compare_path(finding["file"])
    competitor_findings, competitor_ms, status = _run_competitor(args.vs, args.path)
    if status:
        return status

    matched, tcs_only, competitor_only = _compare_findings(tcs_findings, competitor_findings, args.tolerance)
    breakdown = _cwe_breakdown(matched, tcs_only, competitor_only)
    _print_compare_scoreboard(args.vs, tcs_ms, competitor_ms, matched, tcs_only, competitor_only, breakdown)

    report = {
        "competitor": args.vs,
        "tolerance": args.tolerance,
        "execution_ms": {"tcs": round(tcs_ms, 2), "competitor": round(competitor_ms, 2)},
        "counts": {"both": len(matched), "tcs_only": len(tcs_only), "competitor_only": len(competitor_only)},
        "cwe_breakdown": breakdown,
        "matched": matched,
        "tcs_exclusive": [{key: value for key, value in item.items() if not key.startswith("_")} for item in tcs_only],
        "competitor_only_findings": competitor_only,
    }
    if args.output_json:
        try:
            atomic_write_text(Path(args.output_json), json.dumps(report, indent=2) + "\n")
        except OSError as exc:
            print(f"Error writing comparison report: {exc}", file=sys.stderr)
            return 2
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cli.py", description="Standalone TimeCodeSecurity scanner")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="Scan a Python file or directory")
    scan_parser.add_argument("path", type=Path, help="Python file or directory to scan")
    scan_parser.add_argument("--sarif", metavar="OUTPUT_PATH", help="Write findings as SARIF 2.1.0 JSON")
    scan_parser.add_argument("--fail-on-critical", action="store_true", help="Only exit 1 on a Critical or High finding (default: any finding exits 1, matching tcs_cli.py)")
    scan_parser.add_argument("--format", choices=("table", "json"), default="table", help="Output format (default: table)")
    scan_parser.add_argument(
        "--scope", choices=("all", "python", "docker", "html"), default="all",
        help="Limit analysis to Python code, container/config files, or HTML templates (default: all)",
    )
    scan_parser.add_argument(
        "--with-autofix", action="store_true", default=False,
        help="Include deterministic autofix suggestions in JSON output (only for supported CWEs)",
    )
    scan_parser.add_argument(
        "--lines", metavar="START[-END][,START[-END]...]", default=None,
        help="Incremental scan: restrict findings to the given 1-indexed line ranges, e.g. --lines 4-5",
    )
    scan_parser.add_argument(
        "--include-js", dest="include_js", action="store_true", default=False,
        help="Also run the tree-sitter JS/TS scanner (CWE-79/CWE-95 in .js/.jsx/.ts/.tsx). "
             "Off by default so the analysis stays scoped to Python",
    )
    scan_parser.add_argument(
        "--workers", type=str, default="auto",
        help="Number of parallel worker processes for scanning. Use integer (1-64) or 'auto' (default: auto = all available CPU cores via os.cpu_count())",
    )
    scan_parser.add_argument(
        "--exclude", type=str, default=None,
        help="Comma-separated glob patterns to exclude from scanning (e.g., tests,test_*,*_test.py,migrations)",
    )
    compare_parser = commands.add_parser("compare", help="Compare TimeCodeSecurity findings with Semgrep or Bandit")
    compare_parser.add_argument("path", type=Path, help="Python file or directory to compare")
    compare_parser.add_argument("--vs", choices=("semgrep", "bandit"), default="semgrep", help="Competitor scanner (default: semgrep)")
    compare_parser.add_argument("--tolerance", type=int, default=5, help="Maximum line distance for a match (default: 5)")
    compare_parser.add_argument("--output-json", metavar="REPORT_PATH", help="Write detailed comparison report as JSON")
    args = parser.parse_args(argv)
    if args.command == "scan":
        try:
            return _scan(args)
        except Exception as exc:
            # Anything unhandled is an internal error: emit the fallback artefacts and
            # exit 2 instead of dying on a traceback with an empty report.
            traceback.print_exc()
            return _scan_failure(args, exc)
    if args.tolerance < 0:
        parser.error("--tolerance must be zero or greater")
    return _compare(args)


if __name__ == "__main__":
    sys.exit(main())
