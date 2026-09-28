"""Standalone command-line interface for the TimeCodeSecurity AST scanner."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys
import subprocess
import time
from cross_file_engine import CrossFileTaintEngine
from ast_scanner import TaintTracker
from html_auditor import audit_templates, is_template_path
from iac_auditor import audit_iac_files, is_iac_path
from rule_engine import get_rule


SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
IGNORED_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "build", "dist"}


def _file_key(path, cwd):
    try:
        return path.resolve().relative_to(cwd).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _collect_files(scan_path):
    cwd = Path.cwd().resolve()
    if not scan_path.exists():
        raise FileNotFoundError(f"Path does not exist: {scan_path}")
    if scan_path.is_file():
        if scan_path.suffix.lower() != ".py":
            raise ValueError(f"Expected a Python file: {scan_path}")
        paths = [scan_path]
    elif scan_path.is_dir():
        paths = sorted(
            path for path in scan_path.rglob("*.py")
            if not any(part in IGNORED_DIRS for part in path.parts)
        )
    else:
        raise ValueError(f"Path is not a regular file or directory: {scan_path}")

    if not paths:
        raise ValueError(f"No Python files found: {scan_path}")

    files = {}
    for path in paths:
        try:
            files[_file_key(path, cwd)] = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise OSError(f"Unable to read {path}: {exc}") from exc
    return files


def _collect_auxiliary_files(scan_path):
    """Collect non-Python artefacts in one walk: (templates, IaC documents).

    Keys match _collect_files so findings share a single path namespace.
    """
    cwd = Path.cwd().resolve()
    if not scan_path.exists():
        raise FileNotFoundError(f"Path does not exist: {scan_path}")

    if scan_path.is_file():
        paths = [scan_path]
    elif scan_path.is_dir():
        paths = sorted(
            path for path in scan_path.rglob("*")
            if path.is_file() and not any(part in IGNORED_DIRS for part in path.parts)
        )
    else:
        return {}, {}

    templates = {}
    iac = {}
    for path in paths:
        relative = str(path).replace("\\", "/")
        if is_template_path(relative):
            bucket = templates
        elif is_iac_path(relative):
            bucket = iac
        else:
            continue
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
            "message": f"{cwe}: {sink.metadata.get('operation') or sink.symbol}",
        }
        identity = (finding["file"], finding["line"], finding["cwe"])
        if identity not in seen:
            seen.add(identity)
            findings.append(finding)
    return sorted(findings, key=lambda item: (item["file"], item["line"], item["cwe"]))


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
        rules.append({
            "id": cwe,
            "name": cwe.replace("-", "_"),
            "shortDescription": {"text": finding["category"].replace("_", " ")},
            "defaultConfiguration": {
                "level": "error" if finding["severity"] in ("CRITICAL", "HIGH") else "warning"
            },
            "properties": {"tags": ["security", cwe.lower()]},
        })

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


def _print_summary(file_count, duration_ms, findings):
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = finding["severity"]
        counts[severity if severity in counts else "UNKNOWN"] += 1
    print(f"\nTotal scanned files: {file_count}")
    print(f"Scan duration: {duration_ms:.2f} ms")
    print("Findings by severity: " + ", ".join(f"{severity.title()}: {counts[severity]}" for severity in SEVERITIES))


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
    lines = ["", rule, "        TIMECODESECURITY (TCS) - CROSS-FILE EXPLOIT CHAINS", rule]
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
    """Executes CrossFileTaintEngine cleanly. Returns (findings, engine-or-None)."""
    try:
        from cross_file_engine import CrossFileTaintEngine
        engine = CrossFileTaintEngine(target_path)
        raw_findings = engine.run()
    except Exception:
        return [], None

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
    """
    if engine is None:
        return findings
    try:
        sanitized_sites = {
            (_normalize_compare_path(file_path), lineno)
            for file_path, lineno in engine.sanitized_sink_locations()
        }
    except Exception:
        return findings
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

def _scan(args):
    try:
        templates, iac = _collect_auxiliary_files(args.path)
        try:
            files = _collect_files(args.path)
        except ValueError:
            if not templates and not iac:
                raise
            files = {}
        started = time.perf_counter()
        if files:
            tracker = TaintTracker(files=files)
            _, _, edges = tracker.analyze()
            ast_findings = _findings_for(tracker, edges)
            scanned_files = len(tracker.modules) + len(templates) + len(iac)
        else:
            ast_findings = []
            scanned_files = len(templates) + len(iac)
        findings = _merge_findings(ast_findings, audit_templates(templates), audit_iac_files(iac))
        cross_findings, cross_engine = _run_cross_scan(args.path)
        findings = _suppress_cross_file_sanitized(findings, cross_engine)
        findings.extend(cross_findings)
        duration_ms = (time.perf_counter() - started) * 1000
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps({
            "scanned_files": scanned_files,
            "duration_ms": round(duration_ms, 2),
            "findings": findings,
        }, indent=2))
    else:
        print(_ascii_table(findings) if findings else "[+] No vulnerabilities found. Clean scan!")
        _print_summary(scanned_files, duration_ms, findings)
        traces = _cross_trace_report(findings, Path.cwd().resolve())
        if traces:
            print(traces)

    if args.sarif:
        try:
            output_path = Path(args.sarif)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(_sarif_document(findings, Path.cwd().resolve()), indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Error writing SARIF file: {exc}", file=sys.stderr)
            return 2

    if args.fail_on_critical and any(item["severity"] in ("CRITICAL", "HIGH") for item in findings):
        return 1
    return 0


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
        ("Execution speed", f"TCS {tcs_ms:.2f} ms vs {tool.title()} {competitor_ms:.2f} ms"),
        ("Matched Findings (both)", str(len(matched))),
        ("TCS Exclusive Findings", str(len(tcs_only))),
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
    headers = ("CWE", "Both", "TCS only", f"{tool.title()} only")
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
        templates, iac = _collect_auxiliary_files(args.path)
        try:
            files = _collect_files(args.path)
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
            output_path = Path(args.output_json)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
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
    scan_parser.add_argument("--fail-on-critical", action="store_true", help="Exit 1 when a Critical or High finding is detected")
    scan_parser.add_argument("--format", choices=("table", "json"), default="table", help="Output format (default: table)")
    compare_parser = commands.add_parser("compare", help="Compare TCS findings with Semgrep or Bandit")
    compare_parser.add_argument("path", type=Path, help="Python file or directory to compare")
    compare_parser.add_argument("--vs", choices=("semgrep", "bandit"), default="semgrep", help="Competitor scanner (default: semgrep)")
    compare_parser.add_argument("--tolerance", type=int, default=5, help="Maximum line distance for a match (default: 5)")
    compare_parser.add_argument("--output-json", metavar="REPORT_PATH", help="Write detailed comparison report as JSON")
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    if args.tolerance < 0:
        parser.error("--tolerance must be zero or greater")
    return _compare(args)


if __name__ == "__main__":
    sys.exit(main())
