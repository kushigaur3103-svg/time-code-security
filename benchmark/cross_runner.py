"""TimeCodeSecurity (TCS) Cross-File Ground-Truth Benchmark Harness.

Proves the inter-procedural engine (symbol index -> function contracts -> cross-file taint)
and the sanitizer suppression pipeline against labelled mini-project fixtures, one directory
per test case. Metrics are derived from the same confusion matrix as the single-file suite.

Each case carries exact ground truth at finding granularity: the precise set of cross-file
findings (CWE, file, line) the engine must emit, and the precise set of caller-side sites the
suppression pipeline must drop. A case only passes on exact set equality, so an unexpected
extra finding fails the gate even when the expected one was also found.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ast_scanner import TaintTracker
from cli import _collect_files, _findings_for, _suppress_cross_file_sanitized
from cross_file_engine import CrossFileTaintEngine
from benchmark.runner import ConfusionMatrix

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "cross_file"

FindingKey = Tuple[str, str, int]  # (cwe, path relative to the case directory, line)
SiteKey = Tuple[str, int]          # (path relative to the case directory, line)


def _gate_passed(results: List["CaseResult"], matrix: ConfusionMatrix) -> bool:
    """Precision/recall at 100% and every case satisfying its exact ground-truth contract."""
    return (
        matrix.precision == 1.0
        and matrix.recall == 1.0
        and all(r.error == "" and r.exact and r.suppression_ok for r in results)
    )


@dataclass(frozen=True)
class CrossFileCase:
    test_id: str
    is_vulnerable: bool
    expected_findings: frozenset = frozenset()
    expected_suppressed: frozenset = frozenset()


CASE_GROUND_TRUTH: Dict[str, CrossFileCase] = {
    case.test_id: case
    for case in (
        CrossFileCase(
            test_id="case_01_multihop_sqli",
            is_vulnerable=True,
            # views01.py -> service01.load_profile -> repo01.fetch_row -> cursor.execute
            expected_findings=frozenset({("CWE-89", "views01.py", 6)}),
        ),
        CrossFileCase(
            test_id="case_02_kwargs_command",
            is_vulnerable=True,
            # keyword argument bound to the sink-reaching parameter
            expected_findings=frozenset({("CWE-78", "api02.py", 6)}),
        ),
        CrossFileCase(
            test_id="case_03_oop_instance_sqli",
            is_vulnerable=True,
            # receiver resolved to UserService.search through a local construction
            expected_findings=frozenset({("CWE-89", "views03.py", 7)}),
        ),
        CrossFileCase(
            test_id="case_04_aliased_import_sqli",
            is_vulnerable=True,
            # `import exec_query as run_q`: the alias must bind to the aliased contract
            expected_findings=frozenset({("CWE-89", "caller04.py", 6)}),
        ),
        CrossFileCase(
            test_id="case_05_sanitizer_middle_layer",
            is_vulnerable=False,
            # build_safe escapes its argument, so the caller's os.system is not injectable.
            # The single-file scanner reports views05.py:9; the pipeline must drop it.
            expected_suppressed=frozenset({("views05.py", 9)}),
        ),
        CrossFileCase(
            test_id="case_06_untainted_constant",
            is_vulnerable=False,
        ),
        CrossFileCase(
            test_id="case_07_safe_name_collision",
            is_vulnerable=False,
            # fetch_count is also defined by the star-imported danger07 with a sink; the
            # explicit import must win, otherwise this reports a CWE-89 false positive.
        ),
        CrossFileCase(
            test_id="case_08_cross_file_inheritance_bad",
            is_vulnerable=True,
            # UserService declares no methods, so the call must bind to BaseRepo.fetch_rows.
            expected_findings=frozenset({("CWE-89", "controller.py", 7)}),
        ),
        CrossFileCase(
            test_id="case_09_abstract_interface_override_good",
            is_vulnerable=False,
            # SafeHandler overrides the unsafe BaseHandler fallback with DB-API parameter
            # binding, so neither the override nor the inherited fallback is injectable.
        ),
        CrossFileCase(
            test_id="case_10_circular_import_bad",
            is_vulnerable=True,
            # mod_a <-> mod_b import each other; the cycle must not stop the leak being found.
            expected_findings=frozenset({("CWE-78", "mod_a.py", 8)}),
        ),
        CrossFileCase(
            test_id="case_11_circular_import_benign_good",
            is_vulnerable=False,
            # Same cycle, but the sink receives a module constant while the request-derived
            # value stays unused, so the call is not injectable.
        ),
        CrossFileCase(
            test_id="case_12_aliased_module_namespace_bad",
            is_vulnerable=True,
            # `import service as db_svc` binds a namespace, so db_svc.execute_query must be
            # resolved through the alias to the service module's contract.
            expected_findings=frozenset({("CWE-89", "controller.py", 6)}),
        ),
        CrossFileCase(
            test_id="case_13_shadowed_sink_name_good",
            is_vulnerable=False,
            # local_lib.execute matches a sink name but its contract holds no sink, so the
            # resolved call must not be reported.
        ),
        CrossFileCase(
            test_id="case_14_deep_4hop_transitive_bad",
            is_vulnerable=True,
            # controller -> gateway -> service -> repo: the sink contract must lift three hops.
            expected_findings=frozenset({("CWE-89", "controller.py", 6)}),
        ),
    )
}


def discover_cases(fixture_root: Optional[Path] = None) -> Tuple[CrossFileCase, ...]:
    """Every fixture directory under the root, alphabetically, paired with its label.

    Discovery is automatic so a new mini-project folder is executed without editing the
    runner, but a directory with no label (or a label with no directory) is a hard error:
    silently skipping a case, or quietly running a stale one, would inflate the metrics.

    The root is read at call time rather than as a default argument, so callers pointing the
    suite at another tree get the same directories they set.
    """
    root = fixture_root or FIXTURE_ROOT
    found = sorted(path.name for path in root.iterdir() if path.is_dir())
    unlabelled = [name for name in found if name not in CASE_GROUND_TRUTH]
    orphaned = [name for name in CASE_GROUND_TRUTH if name not in found]
    if unlabelled or orphaned:
        raise ValueError(
            "Fixture tree and ground truth are out of sync. "
            f"Unlabelled directories: {unlabelled or 'none'}. "
            f"Labels without a directory: {orphaned or 'none'}."
        )
    return tuple(CASE_GROUND_TRUTH[name] for name in found)


@dataclass
class CaseResult:
    case: CrossFileCase
    emitted: Set[FindingKey] = field(default_factory=set)
    suppressed: Set[SiteKey] = field(default_factory=set)
    single_file: Set[FindingKey] = field(default_factory=set)
    kept_pipeline: Set[FindingKey] = field(default_factory=set)
    classification: str = "TN"
    exact: bool = True
    suppression_ok: bool = True
    duration_ms: float = 0.0
    error: str = ""

    @property
    def missing(self) -> Set[FindingKey]:
        return set(self.case.expected_findings) - self.emitted

    @property
    def unexpected(self) -> Set[FindingKey]:
        return self.emitted - set(self.case.expected_findings)


class CrossFileBenchmarkRunner:
    """Runs the shipped cross-file pipeline over each fixture and scores it."""

    def run_case(self, case: CrossFileCase) -> CaseResult:
        case_dir = FIXTURE_ROOT / case.test_id
        result = CaseResult(case=case)
        started = time.perf_counter()
        try:
            if not case_dir.is_dir():
                raise FileNotFoundError(f"Fixture directory not found: {case_dir}")

            engine = CrossFileTaintEngine(case_dir)
            raw_findings = engine.run()
            rel_paths = self._relative_path_map(case_dir)

            result.emitted = {
                (finding.cwe, rel_paths[Path(finding.caller_file).resolve()], finding.caller_lineno)
                for finding in raw_findings
            }
            result.suppressed = {
                (rel_paths[Path(file_path).resolve()], lineno)
                for file_path, lineno in engine.sanitized_sink_locations()
                if Path(file_path).resolve() in rel_paths
            }

            files = _collect_files(case_dir)
            tracker = TaintTracker(files=files, audit_all=True)
            _, _, edges = tracker.analyze()
            single_findings = _findings_for(tracker, edges)
            result.single_file = {
                (item["cwe"], rel_paths[Path(item["file"]).resolve()], item["line"])
                for item in single_findings
                if Path(item["file"]).resolve() in rel_paths
            }

            # Same composition as cli._scan: single-file findings, sanitizer suppression,
            # then the cross-file findings appended untouched.
            kept = _suppress_cross_file_sanitized(list(single_findings), engine)
            result.kept_pipeline = {
                (item["cwe"], rel_paths[Path(item["file"]).resolve()], item["line"])
                for item in kept
                if Path(item["file"]).resolve() in rel_paths
            }
        except Exception as exc:
            result.classification = "FN" if case.is_vulnerable else "FP"
            result.error = f"{type(exc).__name__}: {exc}"
            result.exact = result.suppression_ok = False
            result.duration_ms = (time.perf_counter() - started) * 1000.0
            return result

        result.duration_ms = (time.perf_counter() - started) * 1000.0

        if case.is_vulnerable:
            result.classification = "TP" if not result.missing else "FN"
        else:
            result.classification = "FP" if result.emitted else "TN"

        result.exact = not result.missing and not result.unexpected
        result.suppression_ok = (
            set(case.expected_suppressed) == result.suppressed
            and not (set(case.expected_suppressed) & result.kept_pipeline)
        )
        return result

    @staticmethod
    def _relative_path_map(case_dir: Path) -> Dict[Path, str]:
        """Resolve every file under the fixture to its case-relative POSIX name."""
        return {
            path.resolve(): path.resolve().relative_to(case_dir.resolve()).as_posix()
            for path in case_dir.rglob("*.py")
        }

    def run_suite(self) -> Tuple[List[CaseResult], ConfusionMatrix, float]:
        results: List[CaseResult] = []
        matrix = ConfusionMatrix()
        started = time.perf_counter()
        for case in discover_cases():
            result = self.run_case(case)
            results.append(result)
            attr = {"TP": "tp", "FP": "fp", "TN": "tn", "FN": "fn"}[result.classification]
            setattr(matrix, attr, getattr(matrix, attr) + 1)
        return results, matrix, (time.perf_counter() - started) * 1000.0

    def render_report(
        self,
        results: List[CaseResult],
        matrix: ConfusionMatrix,
        duration_ms: float,
        verbose: bool = False,
    ) -> str:
        width = 100
        bar = "=" * width
        thin = "-" * width
        gate_ok = _gate_passed(results, matrix)

        headers = ("#", "Case", "Set", "Expect", "Found", "FP", "FN", "TN", "Supp", "Status")
        rows = []
        for index, result in enumerate(results, 1):
            ok = result.error == "" and result.exact and result.suppression_ok
            rows.append((
                str(index),
                result.case.test_id,
                "Bad" if result.case.is_vulnerable else "Good",
                str(len(result.case.expected_findings)),
                str(len(set(result.case.expected_findings) & result.emitted)),
                str(len(result.unexpected)),
                str(len(result.missing)),
                "1" if (not result.case.is_vulnerable and not result.emitted) else "0",
                str(len(result.suppressed)),
                "[PASS]" if ok else "[FAIL]",
            ))
        rows.append((
            "",
            f"TOTAL ({len(results)} cases)",
            "",
            str(sum(len(r.case.expected_findings) for r in results)),
            str(sum(len(set(r.case.expected_findings) & r.emitted) for r in results)),
            str(matrix.fp),
            str(matrix.fn),
            str(matrix.tn),
            str(sum(len(r.suppressed) for r in results)),
            "[PASS]" if gate_ok else "[FAIL]",
        ))

        lines = [bar, "  TCS CROSS-FILE GROUND-TRUTH BENCHMARK HARNESS  ".center(width), bar]
        lines.extend(self._ascii_rows(headers, rows))
        for result in results:
            if result.error:
                lines.append(f"  ERROR in {result.case.test_id}: {result.error}")
        lines.extend([
            "",
            thin,
            "CROSS-FILE CONFUSION MATRIX",
            thin,
            f"  * Cross-File True Positives  (Bad case, leak reported):   {matrix.tp}",
            f"  * Cross-File False Positives (Good case, leak reported):  {matrix.fp}",
            f"  * Cross-File True Negatives  (Good case, stayed silent):  {matrix.tn}",
            f"  * Cross-File False Negatives (Bad case, missed):          {matrix.fn}",
            thin,
            f"  * Cross-File Precision = TP/(TP+FP) = {matrix.precision * 100:6.2f}%  "
            f"(Target == 100.00%) -> {'PASS' if matrix.precision == 1.0 else 'FAIL'}",
            f"  * Cross-File Recall    = TP/(TP+FN) = {matrix.recall * 100:6.2f}%  "
            f"(Target == 100.00%) -> {'PASS' if matrix.recall == 1.0 else 'FAIL'}",
            f"  * Cross-File F1-Score:               {matrix.f1_score:6.4f}",
            f"  * Suppressed sanitizer sites:        {sum(len(r.suppressed) for r in results)}",
            f"  * Exact-set match on all cases:      {'YES' if all(r.exact for r in results) else 'NO'}",
            f"  * Suppression contract all cases:    {'YES' if all(r.suppression_ok for r in results) else 'NO'}",
            f"  * Total Runtime:                     {duration_ms:.2f} ms",
            thin,
        ])

        if verbose:
            for result in results:
                lines.append(f"  {result.case.test_id}:")
                lines.append(f"    emitted cross-file : {sorted(result.emitted)}")
                lines.append(f"    expected cross-file: {sorted(result.case.expected_findings)}")
                lines.append(f"    single-file        : {sorted(result.single_file)}")
                lines.append(f"    pipeline kept      : {sorted(result.kept_pipeline)}")
                lines.append(f"    suppressed sites   : {sorted(result.suppressed)}")
            lines.append(thin)

        verdict = (
            "QUALITY GATE PASSED: cross-file analysis shows zero false positives and zero false negatives."
            if gate_ok else
            "QUALITY GATE FAILED: cross-file precision/recall or ground-truth set equality was not met."
        )
        lines.append(f"OVERALL VERDICT: {'[PASS]' if gate_ok else '[FAIL]'} - {verdict}")
        lines.append(bar)
        return "\n".join(lines)

    @staticmethod
    def _ascii_rows(headers: Tuple[str, ...], rows: List[Tuple[str, ...]]) -> List[str]:
        """Render rows with column widths derived from their content."""
        widths = [
            max(len(headers[i]), *(len(row[i]) for row in rows)) if rows else len(headers[i])
            for i in range(len(headers))
        ]
        border = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

        def line(cells: Tuple[str, ...]) -> str:
            return "| " + " | ".join(cells[i].ljust(widths[i]) for i in range(len(cells))) + " |"

        return [border, line(headers), border, *(line(row) for row in rows), border]


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point. argv defaults to the process arguments, so `python -m benchmark.cross_runner`
    is unchanged while callers such as scripts/run_all_checks.py can invoke it in-process."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="TCS Cross-File Ground-Truth Benchmark Harness")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print per-case finding sets")
    args = parser.parse_args(argv)

    if not FIXTURE_ROOT.is_dir():
        print(f"Fixture root missing: {FIXTURE_ROOT}", file=sys.stderr)
        return 1

    runner = CrossFileBenchmarkRunner()
    results, matrix, duration_ms = runner.run_suite()
    print(runner.render_report(results, matrix, duration_ms, verbose=args.verbose))

    return 0 if _gate_passed(results, matrix) else 1


if __name__ == "__main__":
    sys.exit(main())
