"""
scripts/compare_pygoat.py
Real-world differential scan on OWASP PyGoat: TCS vs Semgrep.
Catches real-world edge cases and unknown deviations.
"""

import json
import os
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


def get_pygoat_python_files() -> list[Path]:
    """Find all valid Python source files in PyGoat, ignoring git metadata."""
    py_files = []
    for p in PYGOAT_DIR.rglob("*.py"):
        # Skip virtualenvs or git caches if any
        parts = p.parts
        if ".git" in parts or "__pycache__" in parts or "venv" in parts:
            continue
        py_files.append(p)
    return sorted(py_files)


def run_semgrep_on_pygoat() -> dict[str, list[dict]]:
    """Runs Semgrep scan on the PyGoat directory."""
    print("[*] 1/2: Running Semgrep scan on real-world PyGoat app...")
    cmd = [
        "semgrep",
        "scan",
        "--config", "auto",
        "--json",
        str(PYGOAT_DIR),
    ]
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
        print("[!] Warning: Semgrep returned empty output.")
        return findings

    try:
        data = json.loads(res.stdout)
    except Exception as e:
        print(f"[!] Semgrep JSON parse error: {e}")
        return findings

    for item in data.get("results", []):
        file_key = norm_path(item.get("path", ""))
        findings.setdefault(file_key, []).append(item)

    return findings


def run_tcs_on_pygoat(py_files: list[Path]) -> dict[str, list[dict]]:
    """Runs TCS TaintTracker file-by-file on PyGoat."""
    print(f"[*] 2/2: Running TCS engine across {len(py_files)} PyGoat Python files...")
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
                    sink_name = sink.metadata.get("sink_name", "unknown_sink")
                    line = getattr(sink, "lineno", getattr(sink, "line", 0))
                    findings.setdefault(norm_path(py_file), []).append({
                        "cwe": cwe,
                        "sink": sink_name,
                        "line": line,
                    })
        except Exception as e:
            # Catch file syntax / parser issues
            pass

    return findings


def main():
    if not PYGOAT_DIR.exists():
        print(f"[ERROR] PyGoat directory not found at: {PYGOAT_DIR}")
        sys.exit(1)

    py_files = get_pygoat_python_files()
    print(f"[*] Discovered {len(py_files)} Python source files in PyGoat.")

    # 1. Run Scanners
    start_sg = time.perf_counter()
    sg_findings = run_semgrep_on_pygoat()
    sg_duration = time.perf_counter() - start_sg

    start_tcs = time.perf_counter()
    tcs_findings = run_tcs_on_pygoat(py_files)
    tcs_duration = time.perf_counter() - start_tcs

    # 2. Count Totals
    sg_total = sum(len(v) for v in sg_findings.values())
    tcs_total = sum(len(v) for v in tcs_findings.values())

    print("\n" + "=" * 65)
    print("        REAL-WORLD COMPARISON: OWASP PYGOAT APP")
    print("=" * 65)
    print(f"{'Scanner':<20} | {'Total Findings':<16} | {'Scan Duration':<12}")
    print("-" * 65)
    print(f"{'Semgrep (--config auto)':<20} | {sg_total:<16} | {sg_duration:.2f}s")
    print(f"{'TCS Engine':<20} | {tcs_total:<16} | {tcs_duration:.2f}s")
    print("=" * 65)

    # 3. Analyze Hidden Deviations (Where Semgrep caught things TCS missed)
    semgrep_only = []
    tcs_only = []

    for f_path in py_files:
        k = norm_path(f_path)
        sg_hits = sg_findings.get(k, [])
        tcs_hits = tcs_findings.get(k, [])
        rel = f_path.relative_to(PYGOAT_DIR)

        if sg_hits and not tcs_hits:
            for hit in sg_hits:
                semgrep_only.append({
                    "file": str(rel),
                    "line": hit.get("start", {}).get("line"),
                    "rule": hit.get("check_id"),
                    "message": hit.get("extra", {}).get("message", "")[:90],
                })
        elif tcs_hits and not sg_hits:
            for hit in tcs_hits:
                tcs_only.append({
                    "file": str(rel),
                    "line": hit.get("line"),
                    "cwe": hit.get("cwe"),
                    "sink": hit.get("sink"),
                })

    print(f"\n[!] Findings caught by Semgrep but MISSED by TCS (Potential Unknown Deviations): {len(semgrep_only)}")
    for item in semgrep_only[:8]:
        print(f"  - [{item['file']}:{item['line']}] {item['rule']}")
        print(f"    Reason: {item['message']}")

    print(f"\n[*] Findings caught by TCS but MISSED by Semgrep: {len(tcs_only)}")
    for item in tcs_only[:5]:
        print(f"  - [{item['file']}:{item['line']}] {item['cwe']} ({item['sink']})")

    # Save detailed JSON
    out_file = REPORTS_DIR / "pygoat_comparison.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "summary": {
                "py_files": len(py_files),
                "semgrep_total": sg_total,
                "tcs_total": tcs_total,
            },
            "missed_by_tcs": semgrep_only,
            "missed_by_semgrep": tcs_only,
        }, f, indent=2)

    print(f"\n[+] Full report saved to: {out_file}")


if __name__ == "__main__":
    main()