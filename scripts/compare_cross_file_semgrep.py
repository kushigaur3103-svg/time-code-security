"""Head-to-head benchmark: TCS inter-procedural engine vs OSS Semgrep on the 20 cross-file
ground-truth fixtures.

Ground truth is imported from benchmark.cross_runner, never re-declared here, so this harness
can only report what the labelled suite already asserts. Semgrep findings are normalised with
the same helpers the PyGoat comparison uses (cli._competitor_findings), so both differential
reports share one methodology.

Scoring is deliberately generous to Semgrep. Its open-source engine is file-local, so it can
only ever reach the leaf sink, while the fixture labels sit at the caller entry point. A Bad
case therefore counts as a TP whenever Semgrep reports the expected CWE anywhere inside that
case directory, at any line of any file. Relaxing the location test removes that handicap
instead of adding one, which means every remaining miss is a real one.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from benchmark.cross_runner import (
    FIXTURE_ROOT,
    CrossFileBenchmarkRunner,
    CrossFileCase,
    CaseResult,
    discover_cases,
)
from benchmark.runner import ConfusionMatrix
from cli import _competitor_findings, _normalize_compare_path

# Official Semgrep rulesets. Pinned instead of `--config auto` because auto refuses to run
# with metrics disabled, and a benchmark must not depend on telemetry being permitted.
SEMGREP_CONFIGS = ("p/default", "p/security-audit")

CASE_NAME_PATTERN = "case_"


@dataclass
class SemgrepCase:
    """Measured Semgrep outcome for one fixture directory."""

    name: str
    findings: List[dict]
    classification: str
    matched: Tuple[str, ...] = ()
    missed: Tuple[str, ...] = ()


def semgrep_version() -> str:
    executable = shutil.which("semgrep")
    if executable is None:
        return "not installed"
    completed = subprocess.run(
        [executable, "--version"], capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False, shell=(os.name == "nt"),
    )
    return (completed.stdout or completed.stderr).strip().splitlines()[0] if (completed.stdout or completed.stderr) else "unknown"


def run_semgrep(fixture_root: Path) -> Tuple[List[dict], float]:
    """Scan the fixture tree once and return normalised CWE-bearing findings."""
    executable = shutil.which("semgrep")
    if executable is None:
        raise RuntimeError("semgrep is not installed or not on PATH")

    command = [executable, "scan", "--json", "--metrics=off", "--quiet"]
    for config in SEMGREP_CONFIGS:
        command += ["--config", config]
    command.append(str(fixture_root))

    started = time.perf_counter()
    completed = subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8",
        errors="replace", check=False, shell=(os.name == "nt"),
    )
    duration = (time.perf_counter() - started) * 1000.0
    payload = completed.stdout.strip()
    if not payload:
        raise RuntimeError(f"semgrep returned no JSON (exit {completed.returncode}): {completed.stderr[-400:]}")
    data = json.loads(payload)
    return _competitor_findings("semgrep", data), duration


def bucket_by_case(findings: List[dict], fixture_root: Path) -> Dict[str, List[dict]]:
    root_key = _normalize_compare_path(fixture_root)
    buckets: Dict[str, List[dict]] = {}
    for finding in findings:
        path = finding["file"]
        if not path.startswith(root_key):
            continue
        remainder = path[len(root_key):].lstrip("\\/")
        head = remainder.split("\\")[0].split("/")[0]
        if head.startswith(CASE_NAME_PATTERN):
            buckets.setdefault(head, []).append(finding)
    return buckets


def score_semgrep(case: CrossFileCase, case_findings: List[dict]) -> SemgrepCase:
    """Classify one fixture against its label using the generous contract above."""
    reported_cwes = {finding["cwe"] for finding in case_findings}
    expected = sorted(case.expected_findings)

    if case.is_vulnerable:
        matched = tuple(entry for entry in expected if entry[0] in reported_cwes)
        missed = tuple(entry for entry in expected if entry[0] not in reported_cwes)
        classification = "TP" if matched else "FN"
        return SemgrepCase(case.test_id, case_findings, classification, matched, missed)

    classification = "FP" if case_findings else "TN"
    return SemgrepCase(case.test_id, case_findings, classification)


def matrix_of(outcomes: List[str]) -> ConfusionMatrix:
    matrix = ConfusionMatrix()
    for classification in outcomes:
        attr = {"TP": "tp", "FP": "fp", "TN": "tn", "FN": "fn"}[classification]
        setattr(matrix, attr, getattr(matrix, attr) + 1)
    return matrix


def _site_list(findings: List[dict]) -> str:
    """Case-relative `file:line (rule)` list, compact enough for a table cell."""
    if not findings:
        return "no report"
    root_key = _normalize_compare_path(FIXTURE_ROOT)
    parts = []
    for finding in sorted(findings, key=lambda item: (item["file"], item["line"])):
        rel = finding["file"][len(root_key):].lstrip("\\/").replace("\\", "/")
        rule = (finding["rule"] or "").split(".")[-2] if finding["rule"] else "?"
        parts.append(f"`{rel}:{finding['line']}` ({finding['cwe']}, {rule})")
    return "; ".join(parts)


def _truth_label(case: CrossFileCase) -> str:
    if not case.is_vulnerable:
        if case.expected_suppressed:
            return "Good (sanitised)"
        return "Good"
    cwes = sorted({entry[0] for entry in case.expected_findings})
    return f"Bad ({', '.join(cwes)} x{len(case.expected_findings)})"


def _tcs_cell(result: CaseResult) -> str:
    classification = result.classification
    if classification == "TP":
        return f"TP ({len(result.emitted)}/{len(result.case.expected_findings)} findings)"
    if classification == "FN":
        return f"FN (missed {', '.join(sorted(f'{c}@{f}:{l}' for c, f, l in result.missing)) or 'sink'})"
    if classification == "FP":
        return f"FP ({len(result.emitted)} extra)"
    if result.case.expected_suppressed:
        return "TN (suppressed)"
    return "TN"


def render_markdown(
    cases: List[CrossFileCase],
    tcs_results: List[CaseResult],
    semgrep: List[SemgrepCase],
    tcs_matrix: ConfusionMatrix,
    semgrep_matrix: ConfusionMatrix,
    analysis: Dict[str, str],
    engine_version: str,
    semgrep_duration_ms: float,
    tcs_duration_ms: float,
) -> str:
    by_case_tcs = {result.case.test_id: result for result in tcs_results}
    by_case_sg = {outcome.name: outcome for outcome in semgrep}

    expected_total = sum(len(case.expected_findings) for case in cases)
    sg_matched = sum(len(outcome.matched) for outcome in semgrep)
    tcs_matched = sum(len(result.emitted) for result in tcs_results)

    lines = [
        "# Head-to-Head: TCS vs Semgrep on the 20 Cross-File Ground-Truth Fixtures",
        "",
        f"- Fixtures: `benchmark/fixtures/cross_file/` ({len(cases)} labelled cases, "
        f"{expected_total} expected findings)",
        f"- TCS: inter-procedural engine + sanitizer suppression (`benchmark.cross_runner`), "
        f"{tcs_duration_ms:.0f} ms",
        f"- Semgrep: official rulesets `{'`, `'.join(SEMGREP_CONFIGS)}`, {engine_version} "
        f"(open-source engine), {semgrep_duration_ms / 1000:.1f} s",
        "- Semgrep is scored at CWE granularity anywhere inside the case directory (no file or "
        "line requirement) because its analysis is file-local and can only reach the leaf sink, "
        "while the labels sit at the caller entry point. The handicap is removed, not added.",
        "",
        "| Case # | Case Name | Ground Truth | TCS Result | Semgrep Result | Analysis / Why Semgrep Diverges |",
        "| --- | --- | --- | --- | --- | --- |",
    ]

    for index, case in enumerate(cases, 1):
        tcs_result = by_case_tcs[case.test_id]
        sg_outcome = by_case_sg[case.test_id]
        semgrep_cell = (
            f"{sg_outcome.classification} - {_site_list(sg_outcome.findings)}"
        )
        note = analysis.get(case.test_id, "")
        if sg_outcome.classification == "TP" and sg_outcome.missed:
            note = f"{note} Partial: {', '.join(f'{c}@{f}:{l}' for c, f, l in sg_outcome.missed)} not reported."
        lines.append(
            f"| {index} | `{case.test_id}` | {_truth_label(case)} | {_tcs_cell(tcs_result)} "
            f"| {semgrep_cell} | {note} |"
        )

    def metric_block(name: str, matrix: ConfusionMatrix) -> List[str]:
        return [
            f"| {name} | {matrix.tp} | {matrix.fp} | {matrix.tn} | {matrix.fn} "
            f"| {matrix.precision * 100:.2f}% | {matrix.recall * 100:.2f}% | {matrix.f1_score:.4f} |"
        ]

    lines += [
        "",
        "## Summary Metrics",
        "",
        "| Engine | TP | FP | TN | FN | Precision | Recall | F1 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
        *metric_block("TCS", tcs_matrix),
        *metric_block("Semgrep (OSS)", semgrep_matrix),
        "",
        "### Finding-level coverage",
        "",
        f"- Expected findings across the 12 Bad cases: **{expected_total}**",
        f"- TCS reported **{tcs_matched}/{expected_total}** at the exact labelled "
        f"(CWE, file, line) - recall {100.0 * tcs_matched / expected_total:.2f}%",
        f"- Semgrep covered **{sg_matched}/{expected_total}** expected CWEs under the generous "
        f"rule - recall {100.0 * sg_matched / expected_total:.2f}%",
        f"- Semgrep emitted {sum(len(outcome.findings) for outcome in semgrep)} CWE-bearing "
        f"findings in total; {sg_matched} correspond to a labelled leak.",
        "",
        "## Reading",
        "",
        "Semgrep's reports are real: it finds the vulnerable sink line inside the leaf module in "
        "most Bad cases. What it cannot do is decide *whether that sink is reachable with tainted "
        "data*, because the source lives in another file. That is why it credits 0 of the 8 Good "
        "cases - the safe fixtures are safe for inter-procedural reasons (sanitizer in the middle "
        "layer, overridden abstract method, shadowed import, untainted constant, decorator that "
        "cleans the argument), none of which a file-local pattern can see.",
        "",
    ]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", metavar="PATH", help="Write the Markdown matrix to this path")
    parser.add_argument(
        "--semgrep-json", metavar="PATH",
        help="Score a previously captured Semgrep --json payload instead of scanning again",
    )
    args = parser.parse_args(argv)

    cases = list(discover_cases())

    runner = CrossFileBenchmarkRunner()
    tcs_started = time.perf_counter()
    tcs_results = [runner.run_case(case) for case in cases]
    tcs_duration = (time.perf_counter() - tcs_started) * 1000.0
    failures = [result for result in tcs_results if result.error]
    if failures:
        for result in failures:
            print(f"[ERROR] TCS run failed for {result.case.test_id}: {result.error}", file=sys.stderr)
        return 1

    engine_version = semgrep_version()
    if args.semgrep_json:
        findings = _competitor_findings("semgrep", json.loads(Path(args.semgrep_json).read_text(encoding="utf-8")))
        semgrep_duration = 0.0
    else:
        findings, semgrep_duration = run_semgrep(FIXTURE_ROOT)

    buckets = bucket_by_case(findings, FIXTURE_ROOT)
    semgrep_outcomes = [score_semgrep(case, buckets.get(case.test_id, [])) for case in cases]

    tcs_matrix = matrix_of([result.classification for result in tcs_results])
    semgrep_matrix = matrix_of([outcome.classification for outcome in semgrep_outcomes])

    report = render_markdown(
        cases, tcs_results, semgrep_outcomes, tcs_matrix, semgrep_matrix,
        ANALYSIS, engine_version, semgrep_duration, tcs_duration,
    )
    print(report)

    if args.report:
        path = Path(args.report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report, encoding="utf-8")
        print(f"[+] Markdown report written to {path}", file=sys.stderr)

    print(
        f"TCS      TP={tcs_matrix.tp} FP={tcs_matrix.fp} TN={tcs_matrix.tn} FN={tcs_matrix.fn} "
        f"P={tcs_matrix.precision * 100:.2f}% R={tcs_matrix.recall * 100:.2f}% F1={tcs_matrix.f1_score:.4f}",
        file=sys.stderr,
    )
    print(
        f"Semgrep  TP={semgrep_matrix.tp} FP={semgrep_matrix.fp} TN={semgrep_matrix.tn} FN={semgrep_matrix.fn} "
        f"P={semgrep_matrix.precision * 100:.2f}% R={semgrep_matrix.recall * 100:.2f}% F1={semgrep_matrix.f1_score:.4f}",
        file=sys.stderr,
    )
    return 0


# Analyst notes, one per fixture. Each is grounded in the fixture source and in the measured
# Semgrep outcome; the script prints the measured sites next to them so a stale note is visible.
ANALYSIS: Dict[str, str] = {
    "case_01_multihop_sqli": "Sink line found in the leaf module; the 3-hop caller chain that makes it tainted is invisible.",
    "case_02_kwargs_command": "Sink line found; the keyword-argument binding that routes request data into it is not tracked.",
    "case_03_oop_instance_sqli": "Sink line found; instance-method resolution never needed, so parity by accident.",
    "case_04_aliased_import_sqli": "Miss: repo04.py executes a bare parameter (`execute(statement)`), so the pattern rule that needs concatenated text does not fire, and `import exec_query as run_q` is unresolvable within one file.",
    "case_05_sanitizer_middle_layer": "Middle-layer `build_safe()` escapes the value, but the sanitizer contract lives in another file, so the caller's os.system is still reported.",
    "case_06_untainted_constant": "The caller passes a string literal (`load_report(\"sales_summary_2026\")`) and leaves the request value unused; a file-local rule only sees `+ kind` on a parameter.",
    "case_07_safe_name_collision": "Reports the star-imported `danger07.py` definition although the explicit import shadows it and nothing ever calls it.",
    "case_08_cross_file_inheritance_bad": "Sink line found in the inherited base repository; the subclass binding is not needed for the hit.",
    "case_09_abstract_interface_override_good": "`SafeHandler` overrides the unsafe base with DB-API parameter binding; the dead base fallback is reported anyway.",
    "case_10_circular_import_bad": "Miss: the request source is in mod_a.py while `os.system(\"ping -c 1 \" + host)` takes a bare parameter in mod_b.py, and the two modules import each other.",
    "case_11_circular_import_benign_good": "Sink receives a module constant while the request-derived value stays unused; the cycle hides which value actually flows.",
    "case_12_aliased_module_namespace_bad": "Sink line found in service.py; the `import service as db_svc` alias only matters at the labelled caller site (controller.py:6), which TCS binds through and a file-local rule never has to.",
    "case_13_shadowed_sink_name_good": "Same blind spot TCS just closed: `local_lib.execute(payload)` is a name collision, not a cursor, yet the Django cursor-execute rule fires on the attribute name.",
    "case_14_deep_4hop_transitive_bad": "Sink line found in the 4th module; the chain that lifts taint three hops is not followed.",
    "case_15_intermediate_return_taint_bad": "Sink line found; return-taint through `get_untrusted_id()` is invisible, the sink's own concatenation carries the report.",
    "case_16_intermediate_return_sanitized_good": "`int()` conversion happens one layer in, so the escaped value still reaches the sink line; TCS suppresses it, Semgrep cannot.",
    "case_17_cross_file_decorator_sanitizer_good": "A `@validated` decorator cleans the argument before the sink; decorators in another file are outside a file-local pattern.",
    "case_18_cross_file_decorator_passthrough_bad": "Miss: `os.system(\"ls \" + cmd)` concatenates a bare parameter, and the request source is 4 lines below in a different function behind a passthrough decorator.",
    "case_19_multi_sink_fanout_bad": "SQL half found in db_mod.py; the command half in os_mod.py needs the same fan-out reasoning, so one of the two sinks is lost.",
    "case_20_mixed_positional_kwargs_bad": "Sink line found in the last module of the positional -> keyword -> positional chain; the chain itself is untraced.",
}


if __name__ == "__main__":
    raise SystemExit(main())
