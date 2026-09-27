"""
scripts/compare_pygoat.py
Precise CWE + Line-level differential comparison on OWASP PyGoat:
TimeCodeSecurity (TCS) vs Semgrep.
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import benchmark.runner as br
TaintTracker = getattr(br, "TaintTracker")

PYGOAT_DIR = ROOT_DIR / "external" / "pygoat"
REPORTS_DIR = ROOT_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


def norm_path(p: str | Path) -> str:
    return os.path.normcase(str(Path(p).resolve()))


def extract_sink_line(sink) -> int:
    """Robustly extract the line number from TCS Sink or AST Node."""
    for attr in ("lineno", "line", "line_number"):
        val = getattr(sink, attr, None)
        if val and isinstance(val, int) and val > 0:
            return val

    node = getattr(sink, "node", None)
    if node and hasattr(node, "lineno") and node.lineno > 0:
        return node.lineno

    meta = getattr(sink, "metadata", {})
    if isinstance(meta, dict):
        for k in ("lineno", "line", "line_number"):
            if k in meta and isinstance(meta[k], int) and meta[k] > 0:
                return meta[k]

    return 0


def extract_sink_name(sink) -> str:
    """Extract descriptive sink name."""
    meta = getattr(sink, "metadata", {})
    if isinstance(meta, dict) and "sink_name" in meta:
        return str(meta["sink_name"])
    return getattr(sink, "name", getattr(sink, "id", "sink"))


def extract_cwes_from_semgrep(finding: dict) -> list[str]:
    """Extract normalized CWE identifiers (e.g. CWE-89) from Semgrep metadata."""
    cwes = []
    metadata = finding.get("extra", {}).get("metadata", {})
    raw_cwes = metadata.get("cwe", [])

    if isinstance(raw_cwes, str):
        raw_cwes = [raw_cwes]

    for item in raw_cwes:
        matches = re.findall(r"CWE-\d+", str(item).upper())
        cwes.extend(matches)

    if not cwes:
        matches = re.findall(r"CWE-\d+", finding.get("check_id", "").upper())
        cwes.extend(matches)

    return sorted(list(set(cwes)))


def get_pygoat_files() -> list[Path]:
    py_files = []
    for p in PYGOAT_DIR.rglob("*.py"):
        if any(skip in p.parts for skip in (".git", "__pycache__", "venv")):
            continue
        py_files.append(p)
    return sorted(py_files)


def run_semgrep() -> dict[str, list[dict]]:
    print("[*] 1/2: Running Semgrep with auto ruleset...")
    cmd = ["semgrep", "scan", "--config", "auto", "--json", str(PYGOAT_DIR)]
    res = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        shell=True,
    )

    findings: dict[str, list[dict]] = {}
    if not res.stdout.strip():
        return findings

    try:
        data = json.loads(res.stdout)
    except Exception:
        return findings

    for item in data.get("results", []):
        f_path = norm_path(item.get("path", ""))
        cwes = extract_cwes_from_semgrep(item)
        line = item.get("start", {}).get("line", 0)
        message = item.get("extra", {}).get("message", "")[:80]
        rule = item.get("check_id", "")

        for cwe in (cwes if cwes else ["UNKNOWN_CWE"]):
            findings.setdefault(f_path, []).append({
                "cwe": cwe,
                "line": line,
                "rule": rule,
                "message": message,
            })

    return findings


def run_tcs(py_files: list[Path]) -> dict[str, list[dict]]:
    print(f"[*] 2/2: Running TCS engine across {len(py_files)} files...")
    findings: dict[str, list[dict]] = {}

    for py_file in py_files:
        try:
            code = py_file.read_text(encoding="utf-8", errors="replace")
            rel_name = str(py_file.relative_to(ROOT_DIR))
            tracker = TaintTracker(files={rel_name: code}, audit_all=True)
            sources, sinks, edges = tracker.analyze()

            sinks_by_id = {s.id: s for s in sinks}
            for edge in edges:
                sink = sinks_by_id.get(edge.target_id)
                if sink:
                    cwe = sink.metadata.get("cwe")
                    if cwe:
                        findings.setdefault(norm_path(py_file), []).append({
                            "cwe": cwe.upper(),
                            "sink": extract_sink_name(sink),
                            "line": extract_sink_line(sink),
                        })
        except Exception:
            pass

    return findings


def is_line_match(line1: int, line2: int, tolerance: int = 5) -> bool:
    if line1 == 0 or line2 == 0:
        return True
    return abs(line1 - line2) <= tolerance


def main():
    py_files = get_pygoat_files()
    start_sg = time.perf_counter()
    sg_findings = run_semgrep()
    sg_time = time.perf_counter() - start_sg

    start_tcs = time.perf_counter()
    tcs_findings = run_tcs(py_files)
    tcs_time = time.perf_counter() - start_tcs

    both_caught = []
    sg_only = []
    tcs_only = []

    for f_path in py_files:
        k = norm_path(f_path)
        s_list = sg_findings.get(k, [])
        t_list = tcs_findings.get(k, [])
        rel = str(f_path.relative_to(PYGOAT_DIR))

        matched_sg_indices = set()
        matched_tcs_indices = set()

        for s_idx, s in enumerate(s_list):
            for t_idx, t in enumerate(t_list):
                if t_idx in matched_tcs_indices:
                    continue
                if s["cwe"] == t["cwe"] and is_line_match(s["line"], t["line"]):
                    both_caught.append({
                        "file": rel,
                        "cwe": s["cwe"],
                        "sg_line": s["line"],
                        "tcs_line": t["line"],
                    })
                    matched_sg_indices.add(s_idx)
                    matched_tcs_indices.add(t_idx)
                    break

        for s_idx, s in enumerate(s_list):
            if s_idx not in matched_sg_indices:
                sg_only.append({
                    "file": rel,
                    "line": s["line"],
                    "cwe": s["cwe"],
                    "rule": s["rule"],
                    "message": s["message"],
                })

        for t_idx, t in enumerate(t_list):
            if t_idx not in matched_tcs_indices:
                tcs_only.append({
                    "file": rel,
                    "line": t["line"],
                    "cwe": t["cwe"],
                    "sink": t["sink"],
                })

    print("\n" + "=" * 70)
    print("      REAL-WORLD DIFFERENTIAL MATRIX (CWE + LINE ACCURACY)")
    print("=" * 70)
    print(f"Agreement (Both Flagged Same CWE & Area) : {len(both_caught)}")
    print(f"Semgrep ONLY (Real Deviations Missed by TCS): {len(sg_only)}")
    print(f"TCS Engine ONLY (Caught by TCS, Missed by Semgrep): {len(tcs_only)}")
    print("-" * 70)
    print(f"Performance: Semgrep={sg_time:.2f}s | TCS={tcs_time:.2f}s (Speedup: {sg_time / max(tcs_time, 0.001):.1f}x)")
    print("=" * 70)

    if sg_only:
        print("\n[!] TOP 10 REAL DEVIATIONS MISSED BY TCS (Actionable Gaps):")
        for item in sg_only[:10]:
            print(f" - [{item['cwe']}] {item['file']}:{item['line']} -> {item['rule']}")
            print(f"   Context: {item['message']}")

    if tcs_only:
        print("\n[*] TOP 5 TCS EXCLUSIVE FINDINGS:")
        for item in tcs_only[:5]:
            print(f" - [{item['cwe']}] {item['file']}:{item['line']} -> Sink: {item['sink']}")

    out_file = REPORTS_DIR / "pygoat_differential_cwe_line.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "both": both_caught,
            "missed_by_tcs": sg_only,
            "tcs_exclusive": tcs_only,
        }, f, indent=2)
    print(f"\n[+] Detailed report saved to: {out_file}")


if __name__ == "__main__":
    main()