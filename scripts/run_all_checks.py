#!/usr/bin/env python3
"""
TimeCodeSecurity (TCS) Master Automated Verification Suite.

Executes end-to-end post-commit sanity and compliance checks in one shot:
1. Ground-Truth Benchmark Suite:
   - Evaluates all 288 test cases (144 bad, 144 good across 24 CWEs).
   - Strictly asserts 288/288 PASS, 100.0% Precision, 100.0% Recall (0 FP, 0 FN).
2. SARIF v2.1.0 Export & Schema Validation:
   - Scans representative benchmark corpus files across multiple vulnerability classes.
   - Generates an OASIS SARIF v2.1.0 JSON export file.
   - Validates official SARIF schema compliance, including driver metadata,
     107 driver rules from rules catalog, and valid ruleIndex cross-referencing.
3. Desktop GUI Component & Rules Catalog Verification:
   - Verifies all 24 benchmark CWEs are registered and present in data/rules_catalog.json.
   - Instantiates interactive GUI components (rules catalog container, structural view,
     proof graph view, secret view) ensuring headless execution without runtime crash.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Set

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmark.runner import BenchmarkRunner, BenchmarkReport
from benchmark.manifest import get_benchmark_cases
from tcs_cli import execute_tcs_scan
from sarif_exporter import export_sarif
from sarif_adapter import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    TOOL_NAME,
    get_supported_rules,
)
import tcs_gui


def print_header(title: str) -> None:
    width = 75
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width)


def check_benchmark_suite() -> bool:
    """Check 1: Evaluates the complete 288-case ground-truth benchmark suite."""
    print_header("CHECK 1/3: Benchmark Ground-Truth Suite (288 cases)")
    start_time = time.perf_counter()

    target_24 = {cwe for cwe, _ in tcs_gui.ALL_24_CWES}
    cases_24 = [c for c in get_benchmark_cases() if c.cwe in target_24]
    assert len(cases_24) == 288, f"Expected 288 baseline test cases, got {len(cases_24)}"

    runner = BenchmarkRunner(precision_threshold=1.0, recall_threshold=1.0)
    from benchmark.runner import ConfusionMatrix
    gm = ConfusionMatrix()
    cwe_matrices = {}

    for case in cases_24:
        res = runner.run_case(case)
        cm = cwe_matrices.setdefault(case.cwe, ConfusionMatrix())
        if res.classification == "TP":
            cm.tp += 1
            gm.tp += 1
        elif res.classification == "TN":
            cm.tn += 1
            gm.tn += 1
        elif res.classification == "FP":
            cm.fp += 1
            gm.fp += 1
        elif res.classification == "FN":
            cm.fn += 1
            gm.fn += 1

    elapsed = time.perf_counter() - start_time

    print(f"  Cases Evaluated : {len(cases_24)}")
    print(f"  True Positives  : {gm.tp} (expected 144)")
    print(f"  True Negatives  : {gm.tn} (expected 144)")
    print(f"  False Positives : {gm.fp} (expected 0)")
    print(f"  False Negatives : {gm.fn} (expected 0)")
    print(f"  Precision       : {gm.precision * 100:.1f}%")
    print(f"  Recall          : {gm.recall * 100:.1f}%")
    print(f"  F1 Score        : {gm.f1_score * 100:.1f}%")
    print(f"  Suite Duration  : {elapsed:.2f}s")

    # Strict assertion of 100% precision & 100% recall
    assert gm.tp == 144, f"Expected 144 True Positives, got {gm.tp}"
    assert gm.tn == 144, f"Expected 144 True Negatives, got {gm.tn}"
    assert gm.fp == 0, f"Expected 0 False Positives, got {gm.fp}"
    assert gm.fn == 0, f"Expected 0 False Negatives, got {gm.fn}"
    assert gm.precision == 1.0, f"Expected 1.0 precision, got {gm.precision}"
    assert gm.recall == 1.0, f"Expected 1.0 recall, got {gm.recall}"

    # Per-CWE validation (assert all 24 CWEs have 0 FP and 0 FN)
    for cwe_id, cm in cwe_matrices.items():
        assert cm.fp == 0, f"CWE {cwe_id} had {cm.fp} False Positives"
        assert cm.fn == 0, f"CWE {cwe_id} had {cm.fn} False Negatives"
        assert cm.tp == 6, f"CWE {cwe_id} expected 6 TP, got {cm.tp}"
        assert cm.tn == 6, f"CWE {cwe_id} expected 6 TN, got {cm.tn}"

    print(f"  -> [PASS] Ground-truth suite: 288/288 PASS (100.0% Precision, 100.0% Recall)")
    return True


def check_sarif_export() -> bool:
    """Check 2: Executes scan on benchmark corpus and verifies SARIF 2.1.0 compliance."""
    print_header("CHECK 2/3: SARIF v2.1.0 Export & Schema Validation (107 Rules)")
    start_time = time.perf_counter()

    # Select representative cases across Batch 1 and Batch 2 CWEs
    cases = get_benchmark_cases()
    target_cwes = [
        "CWE-89", "CWE-78", "CWE-22", "CWE-95", "CWE-79",
        "CWE-1004", "CWE-732", "CWE-326", "CWE-377", "CWE-209",
        "CWE-643", "CWE-943", "CWE-117", "CWE-94"
    ]
    sample_cases = [c for c in cases if c.cwe in target_cwes and c.is_vulnerable][:20]

    files_to_scan: Dict[str, str] = {}
    for case in sample_cases:
        abs_path = case.get_absolute_path()
        with open(abs_path, "r", encoding="utf-8") as f:
            files_to_scan[case.file_path] = f.read()

    print(f"  Scanning {len(files_to_scan)} corpus test cases across {len(target_cwes)} CWEs...")
    scan_result = execute_tcs_scan(files_to_scan, audit_all=True)
    findings = scan_result.get("findings", [])
    print(f"  Scan Findings Identified : {len(findings)}")
    assert len(findings) > 0, "Expected at least 1 finding from vulnerable test cases"

    # Export to SARIF
    output_dir = REPO_ROOT / "scratch"
    output_dir.mkdir(parents=True, exist_ok=True)
    sarif_file = output_dir / "verification_scan.sarif"

    sarif_doc = export_sarif(scan_result, output_file=sarif_file)
    elapsed = time.perf_counter() - start_time

    # Validate SARIF file was created and is valid JSON
    assert sarif_file.is_file(), f"SARIF output file not found: {sarif_file}"
    with open(sarif_file, "r", encoding="utf-8") as f:
        loaded_doc = json.load(f)

    # Validate OASIS SARIF v2.1.0 Schema fields
    assert loaded_doc.get("$schema") == SARIF_SCHEMA_URI, f"Invalid $schema: {loaded_doc.get('$schema')}"
    assert loaded_doc.get("version") == SARIF_VERSION, f"Invalid version: {loaded_doc.get('version')}"
    assert isinstance(loaded_doc.get("runs"), list) and len(loaded_doc["runs"]) > 0, "Missing or empty 'runs'"

    run = loaded_doc["runs"][0]
    tool = run.get("tool", {})
    driver = tool.get("driver", {})
    assert driver.get("name") == TOOL_NAME, f"Invalid tool name: {driver.get('name')}"

    rules = driver.get("rules", [])
    print(f"  Driver Rules Loaded      : {len(rules)} (expected 107)")
    assert len(rules) == 107, f"Expected 107 driver rules in SARIF export, got {len(rules)}"

    # Validate rule structure
    rule_ids = set()
    for rule in rules:
        assert "id" in rule and rule["id"], "Rule missing 'id'"
        assert "name" in rule, f"Rule {rule['id']} missing 'name'"
        assert "shortDescription" in rule, f"Rule {rule['id']} missing 'shortDescription'"
        assert "fullDescription" in rule, f"Rule {rule['id']} missing 'fullDescription'"
        assert "helpUri" in rule, f"Rule {rule['id']} missing 'helpUri'"
        assert "defaultConfiguration" in rule, f"Rule {rule['id']} missing 'defaultConfiguration'"
        assert "properties" in rule, f"Rule {rule['id']} missing 'properties'"
        rule_ids.add(rule["id"])

    # Validate results mapping to rules
    results = run.get("results", [])
    print(f"  SARIF Results Serialized : {len(results)}")
    assert len(results) > 0, "Expected SARIF results list to be populated"

    for r_idx, res in enumerate(results):
        rule_id = res.get("ruleId")
        rule_index = res.get("ruleIndex")
        assert rule_id in rule_ids, f"Result {r_idx} ruleId {rule_id} not in driver rules"
        assert isinstance(rule_index, int), f"Result {r_idx} ruleIndex is not int: {rule_index}"
        assert 0 <= rule_index < len(rules), f"Result {r_idx} ruleIndex out of range: {rule_index}"
        assert rules[rule_index]["id"] == rule_id, (
            f"Result {r_idx} ruleIndex mismatch: ruleIndex {rule_index} is {rules[rule_index]['id']}, expected {rule_id}"
        )
        assert res.get("level") in ("error", "warning", "note"), f"Invalid level: {res.get('level')}"
        assert "message" in res and res["message"].get("text"), f"Result {r_idx} missing message text"
        assert "locations" in res and len(res["locations"]) > 0, f"Result {r_idx} missing locations"

        loc = res["locations"][0].get("physicalLocation", {})
        assert loc.get("artifactLocation", {}).get("uri"), f"Result {r_idx} missing uri"
        start_line = loc.get("region", {}).get("startLine", 0)
        assert start_line >= 1, f"Result {r_idx} invalid startLine: {start_line}"

    print(f"  Export & Verification Time: {elapsed:.2f}s")
    print(f"  -> [PASS] SARIF v2.1.0 valid | 107 rules loaded | All results correctly cross-indexed")
    return True


def check_gui_components() -> bool:
    """Check 3: Verifies 24 CWE rules catalog and GUI structural/proof-graph components."""
    print_header("CHECK 3/3: GUI Component & Rules Catalog Verification (24 CWEs)")
    start_time = time.perf_counter()

    # 1. Verify 24 CWEs registry
    assert len(tcs_gui.ALL_24_CWES) == 24, f"Expected 24 CWEs in ALL_24_CWES, got {len(tcs_gui.ALL_24_CWES)}"
    print(f"  GUI Registry Entries     : {len(tcs_gui.ALL_24_CWES)} CWEs")

    # 2. Verify rules catalog loading
    rules_cat = tcs_gui.load_rules_catalog()
    assert len(rules_cat) >= 24, f"Rules catalog contains fewer than 24 CWEs: {len(rules_cat)}"
    for cwe_id, cwe_name in tcs_gui.ALL_24_CWES:
        assert cwe_id in rules_cat, f"Benchmark CWE {cwe_id} missing from data/rules_catalog.json"
    print(f"  Catalog Rules Loaded     : {len(rules_cat)} CWEs (all 24 benchmark CWEs present)")

    # 3. Instantiate rules catalog interactive view
    cat_view = tcs_gui.build_rules_catalog_container()
    assert cat_view is not None, "build_rules_catalog_container returned None"
    assert hasattr(cat_view, "content"), "cat_view missing content"
    cards_column = cat_view.content.controls[2]
    assert len(cards_column.controls) == 24, f"Expected 24 cards in rules catalog, got {len(cards_column.controls)}"
    print(f"  Rules Catalog Container  : Instantiated with 24 interactive rule cards")

    # 4. Instantiate structural view across structural CWEs
    structural_cwes_to_test = [
        ("CWE-1004", "Insecure Cookie Flags", "set_cookie", "response.set_cookie('token', val, httponly=False)"),
        ("CWE-732", "Insecure File Permissions", "os.chmod", "os.chmod('file.txt', 0o777)"),
        ("CWE-326", "Inadequate Encryption Strength", "RSA.generate", "RSA.generate(1024)"),
        ("CWE-377", "Insecure Temporary File", "tempfile.mktemp", "tempfile.mktemp()"),
        ("CWE-209", "Sensitive Error Exposure", "traceback.format_exc", "return traceback.format_exc()"),
    ]

    for cwe_id, category, symbol, snippet in structural_cwes_to_test:
        finding = {
            "cwe": cwe_id,
            "category": category,
            "severity": "HIGH",
            "symbol": symbol,
            "line": 15,
            "file": "test_app.py",
            "code_snippet": snippet,
            "flow_trace": [f"{category} detected at line 15 with construct {symbol}"],
            "remediation": f"Refactor construct {symbol} following secure coding policy.",
            "confidence": 1.0,
            "confidence_label": "CONFIRMED",
        }
        # Direct structural view
        s_view = tcs_gui.build_structural_view(finding)
        assert s_view is not None, f"build_structural_view returned None for {cwe_id}"

        # Proof graph view delegating to structural view
        pg_view = tcs_gui.build_proof_graph_view([], finding)
        assert pg_view is not None, f"build_proof_graph_view returned None for structural {cwe_id}"

    print(f"  Structural View Testing  : 5 structural CWEs verified (CWE-1004, 732, 326, 377, 209)")

    # 5. Instantiate secret finding view
    secret_finding = {
        "cwe": "CWE-798",
        "category": "Hardcoded Credential / Secret Leak",
        "severity": "CRITICAL",
        "symbol": "aws_secret_access_key",
        "masked_value": "AKIA****************",
        "line": 8,
        "file": "config.py",
        "code_snippet": "AWS_SECRET = 'AKIAIOSFODNN7EXAMPLE'",
        "remediation": "Move credentials to an external secret vault.",
        "is_secret": True,
    }
    sec_view = tcs_gui.build_proof_graph_view([], secret_finding)
    assert sec_view is not None, "build_proof_graph_view returned None for secret finding"
    print(f"  Secret View Testing      : CWE-798 Hardcoded secret view verified")

    # 6. Instantiate multi-hop taint dataflow proof graph view
    taint_nodes = [
        {
            "step_index": 1,
            "node_type": "SOURCE",
            "symbol": "request.args.get('input')",
            "start_line": 5,
            "expression_snippet": "cmd = request.args.get('input')",
        },
        {
            "step_index": 2,
            "node_type": "ASSIGNMENT",
            "symbol": "cmd",
            "start_line": 7,
            "expression_snippet": "full_cmd = 'sh ' + cmd",
        },
        {
            "step_index": 3,
            "node_type": "SINK",
            "symbol": "subprocess.Popen",
            "start_line": 10,
            "expression_snippet": "subprocess.Popen(full_cmd, shell=True)",
        },
    ]
    taint_finding = {
        "cwe": "CWE-78",
        "category": "OS Command Injection",
        "severity": "CRITICAL",
        "line": 10,
        "file": "server.py",
        "remediation": "Avoid passing unsanitized shell commands; use shlex.quote() or argument lists.",
    }
    t_view = tcs_gui.build_proof_graph_view(taint_nodes, taint_finding)
    assert t_view is not None, "build_proof_graph_view returned None for taint dataflow"
    print(f"  Taint Proof Graph View   : 3-hop dataflow graph verified (SOURCE -> ASSIGNMENT -> SINK)")

    # 7. Test empty state proof graph view and clean scan view
    empty_view = tcs_gui.build_proof_graph_view([])
    assert empty_view is not None, "build_proof_graph_view returned None for empty state"

    clean_view = tcs_gui.build_clean_scan_view()
    assert clean_view is not None, "build_clean_scan_view returned None"
    chips_row = clean_view.content.controls[3].content
    assert len(chips_row.controls) == 24, f"Expected 24 checkmark tiles in clean scan view, got {len(chips_row.controls)}"
    print(f"  Clean Scan View Testing  : 24 CWE green checkmark cards verified")

    # 8. Test helper functions
    assert tcs_gui.get_severity_color("CRITICAL") == "#dc2626"
    assert tcs_gui.get_severity_color("HIGH") == "#ea580c"
    assert tcs_gui.get_severity_color("MEDIUM") == "#ca8a04"
    assert tcs_gui.get_severity_color("LOW") == "#2563eb"
    assert tcs_gui.format_confidence(float("nan")) == "HIGH (PATTERN_MATCH)"
    assert tcs_gui.format_confidence(1.0) == "CONFIRMED (100%)"

    elapsed = time.perf_counter() - start_time
    print(f"  GUI Verification Time    : {elapsed:.2f}s")
    print(f"  -> [PASS] All GUI components instantiated headlessly without crash")
    return True


def main() -> int:
    total_start = time.perf_counter()
    print("=" * 75)
    print("  TimeCodeSecurity (TCS) - Master Automated Verification Engine")
    print("=" * 75)

    try:
        check_benchmark_suite()
        check_sarif_export()
        check_gui_components()

        total_elapsed = time.perf_counter() - total_start
        print("\n" + "=" * 75)
        print("  ALL VERIFICATION CHECKS PASSED (3/3 GREEN)")
        print(f"  Total Wall-Clock Time: {total_elapsed:.2f}s")
        print("  Exit Status: 0 (SUCCESS)")
        print("=" * 75 + "\n")
        return 0

    except AssertionError as ae:
        print(f"\n[!] ASSERTION FAILURE: {ae}")
        return 1
    except Exception as ex:
        import traceback
        print(f"\n[!] UNHANDLED EXCEPTION: {ex}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
