"""TimeCodeSecurity (TCS) Benchmark Execution & Confusion Matrix Engine.

Executes ground-truth benchmark test suites against the TCS static analysis engine,
computes formal Confusion Matrix metrics (TP, FP, TN, FN, Precision, Recall, Specificity, F1),
and enforces the enterprise Quality Gate (Precision >= 0.95, Recall >= 0.95).
"""

from __future__ import annotations
import argparse
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# Add repository root to Python path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ast_scanner import TaintTracker
from benchmark.manifest import BenchmarkTestCase, get_benchmark_cases


@dataclass
class TestCaseResult:
    case: BenchmarkTestCase
    detected_cwes: Set[str]
    classification: str  # 'TP', 'FP', 'TN', 'FN'
    duration_ms: float
    error: Optional[str] = None


@dataclass
class ConfusionMatrix:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return float(self.tp) / denom if denom > 0 else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return float(self.tp) / denom if denom > 0 else 1.0

    @property
    def specificity(self) -> float:
        denom = self.tn + self.fp
        return float(self.tn) / denom if denom > 0 else 1.0

    @property
    def f1_score(self) -> float:
        p = self.precision
        r = self.recall
        denom = p + r
        return (2.0 * p * r) / denom if denom > 0 else 0.0

    @property
    def accuracy(self) -> float:
        denom = self.total
        return float(self.tp + self.tn) / denom if denom > 0 else 1.0


@dataclass
class BenchmarkReport:
    total_cases: int
    case_results: List[TestCaseResult]
    cwe_matrices: Dict[str, ConfusionMatrix]
    global_matrix: ConfusionMatrix
    total_duration_ms: float
    threshold_passed: bool
    precision_threshold: float = 0.95
    recall_threshold: float = 0.95


class BenchmarkRunner:
    """Orchestrates test case execution, metric derivation, and report generation."""

    def __init__(self, precision_threshold: float = 0.95, recall_threshold: float = 0.95):
        self.precision_threshold = precision_threshold
        self.recall_threshold = recall_threshold

    def run_case(self, case: BenchmarkTestCase) -> TestCaseResult:
        """Runs the static analysis engine against a single test case."""
        abs_path = case.get_absolute_path()
        if not os.path.isfile(abs_path):
            return TestCaseResult(
                case=case,
                detected_cwes=set(),
                classification="FN" if case.is_vulnerable else "FP",
                duration_ms=0.0,
                error=f"Corpus file not found: {abs_path}"
            )

        try:
            with open(abs_path, "r", encoding="utf-8") as f:
                code = f.read()
        except Exception as e:
            return TestCaseResult(
                case=case,
                detected_cwes=set(),
                classification="FN" if case.is_vulnerable else "FP",
                duration_ms=0.0,
                error=f"Failed to read file: {e}"
            )

        start = time.perf_counter()
        try:
            tracker = TaintTracker(files={case.file_path: code}, audit_all=True)
            sources, sinks, edges = tracker.analyze()
            sinks_by_id = {s.id: s for s in sinks}
            detected_cwes: Set[str] = set()
            for edge in edges:
                sink = sinks_by_id.get(edge.target_id)
                if sink:
                    cwe = sink.metadata.get("cwe")
                    if cwe:
                        detected_cwes.add(cwe)
            duration_ms = (time.perf_counter() - start) * 1000.0
            error = None
        except Exception as e:
            duration_ms = (time.perf_counter() - start) * 1000.0
            detected_cwes = set()
            error = str(e)

        # Classification against target CWE
        target_detected = case.cwe in detected_cwes
        if case.is_vulnerable:
            classification = "TP" if target_detected else "FN"
        else:
            classification = "FP" if target_detected else "TN"

        return TestCaseResult(
            case=case,
            detected_cwes=detected_cwes,
            classification=classification,
            duration_ms=duration_ms,
            error=error
        )

    def run_suite(self, cwe_filter: Optional[str] = None) -> BenchmarkReport:
        """Executes the entire suite or a filtered subset and builds the full report."""
        cases = get_benchmark_cases(cwe=cwe_filter)
        case_results: List[TestCaseResult] = []
        cwe_matrices: Dict[str, ConfusionMatrix] = {}
        global_matrix = ConfusionMatrix()

        start_all = time.perf_counter()
        for case in cases:
            res = self.run_case(case)
            case_results.append(res)

            matrix = cwe_matrices.setdefault(case.cwe, ConfusionMatrix())
            if res.classification == "TP":
                matrix.tp += 1
                global_matrix.tp += 1
            elif res.classification == "FP":
                matrix.fp += 1
                global_matrix.fp += 1
            elif res.classification == "TN":
                matrix.tn += 1
                global_matrix.tn += 1
            elif res.classification == "FN":
                matrix.fn += 1
                global_matrix.fn += 1

        total_duration_ms = (time.perf_counter() - start_all) * 1000.0

        threshold_passed = (
            global_matrix.precision >= self.precision_threshold and
            global_matrix.recall >= self.recall_threshold
        )

        return BenchmarkReport(
            total_cases=len(cases),
            case_results=case_results,
            cwe_matrices=cwe_matrices,
            global_matrix=global_matrix,
            total_duration_ms=total_duration_ms,
            threshold_passed=threshold_passed,
            precision_threshold=self.precision_threshold,
            recall_threshold=self.recall_threshold
        )

    def render_ascii_report(self, report: BenchmarkReport, verbose: bool = False) -> str:
        """Renders an ASCII summary table, confusion matrix, and quality gate verdict."""
        lines = []
        width = 114
        bar = "=" * width
        thin_bar = "-" * width

        lines.append(bar)
        lines.append("            TIME CODE SECURITY (TCS) GROUND-TRUTH BENCHMARK HARNESS            ".center(width))
        lines.append("                 NIST Juliet / OWASP Evaluation Suite & Confusion Matrix                ".center(width))
        lines.append(bar)

        if verbose:
            lines.append("INDIVIDUAL TEST RESULTS:")
            for r in report.case_results:
                status = f"[{r.classification}]"
                err = f" (ERROR: {r.error})" if r.error else ""
                lines.append(
                    f"  * {r.case.test_id:25} {r.case.cwe:8} {'(Bad)' if r.case.is_vulnerable else '(Good)':6} "
                    f"-> {status:6} Detected: {sorted(r.detected_cwes)} ({r.duration_ms:.1f}ms){err}"
                )
            lines.append(thin_bar)

        # Portable ASCII Table Header
        lines.append("+----------+-------+------+------+------+------+-----------+----------+-------------+----------+--------+")
        lines.append("| CWE ID   | Tests |  TP  |  FP  |  TN  |  FN  | Precision |  Recall  | Specificity | F1-Score | Status |")
        lines.append("+----------+-------+------+------+------+------+-----------+----------+-------------+----------+--------+")

        for cwe, m in sorted(report.cwe_matrices.items()):
            p_str = f"{m.precision * 100:6.1f}%"
            r_str = f"{m.recall * 100:6.1f}%"
            s_str = f"{m.specificity * 100:6.1f}%"
            f1_str = f"{m.f1_score:6.4f}"
            cwe_pass = (m.precision >= report.precision_threshold and m.recall >= report.recall_threshold)
            status_str = "[PASS]" if cwe_pass else "[FAIL]"
            lines.append(
                f"| {cwe:8} | {m.total:5d} | {m.tp:4d} | {m.fp:4d} | {m.tn:4d} | {m.fn:4d} | "
                f"{p_str:9} | {r_str:8} | {s_str:11} | {f1_str:8} | {status_str:6} |"
            )

        # Total Row
        lines.append("+----------+-------+------+------+------+------+-----------+----------+-------------+----------+--------+")
        gm = report.global_matrix
        gp_str = f"{gm.precision * 100:6.1f}%"
        gr_str = f"{gm.recall * 100:6.1f}%"
        gs_str = f"{gm.specificity * 100:6.1f}%"
        gf1_str = f"{gm.f1_score:6.4f}"
        g_status = "[PASS]" if report.threshold_passed else "[FAIL]"
        lines.append(
            f"| {'TOTAL':8} | {gm.total:5d} | {gm.tp:4d} | {gm.fp:4d} | {gm.tn:4d} | {gm.fn:4d} | "
            f"{gp_str:9} | {gr_str:8} | {gs_str:11} | {gf1_str:8} | {g_status:6} |"
        )
        lines.append("+----------+-------+------+------+------+------+-----------+----------+-------------+----------+--------+")

        # Global Confusion Matrix Table
        lines.append("")
        lines.append(thin_bar)
        lines.append("                                        GLOBAL CONFUSION MATRIX                                           ")
        lines.append(thin_bar)
        lines.append("                                   Predicted Vulnerable          Predicted Safe")
        lines.append(f"     Actual Vulnerable (Bad)             TP = {gm.tp:4d}                    FN = {gm.fn:4d}")
        lines.append(f"     Actual Safe (Good)                  FP = {gm.fp:4d}                    TN = {gm.tn:4d}")
        lines.append(thin_bar)
        lines.append("METRIC EVALUATION SUMMARY:")
        p_eval = "PASS" if gm.precision >= report.precision_threshold else "FAIL"
        r_eval = "PASS" if gm.recall >= report.recall_threshold else "FAIL"
        lines.append(f"  * Global Precision:   {gm.precision * 100:6.2f}%  (Target >= {report.precision_threshold * 100:.1f}%) -> {p_eval}")
        lines.append(f"  * Global Recall:      {gm.recall * 100:6.2f}%  (Target >= {report.recall_threshold * 100:.1f}%) -> {r_eval}")
        lines.append(f"  * Global Specificity: {gm.specificity * 100:6.2f}%")
        lines.append(f"  * Global F1-Score:    {gm.f1_score:6.4f}")
        lines.append(f"  * Global Accuracy:    {gm.accuracy * 100:6.2f}%")
        lines.append(f"  * Total Runtime:      {report.total_duration_ms:.2f} ms")
        lines.append("")
        verdict_str = "QUALITY GATE PASSED: Engine meets or exceeds precision and recall criteria." if report.threshold_passed else "QUALITY GATE FAILED: Engine fell below required threshold."
        lines.append(f"OVERALL VERDICT: {g_status} - {verdict_str}")
        lines.append(bar)

        return "\n".join(lines)


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="TCS Ground-Truth Benchmark Harness & Confusion Matrix Generator")
    parser.add_argument("--cwe", type=str, default=None, help="Filter benchmark tests by specific CWE (e.g. CWE-89)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print per-case detection breakdown")
    parser.add_argument("--precision-gate", type=float, default=0.95, help="Minimum acceptable Precision (default: 0.95)")
    parser.add_argument("--recall-gate", type=float, default=0.95, help="Minimum acceptable Recall (default: 0.95)")
    args = parser.parse_args()

    runner = BenchmarkRunner(
        precision_threshold=args.precision_gate,
        recall_threshold=args.recall_gate
    )
    report = runner.run_suite(cwe_filter=args.cwe)
    report_text = runner.render_ascii_report(report, verbose=args.verbose)
    print(report_text)

    return 0 if report.threshold_passed else 1


if __name__ == "__main__":
    sys.exit(main())
