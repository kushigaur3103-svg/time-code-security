import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sarif_adapter import to_sarif, get_supported_rules, SUPPORTED_RULES, RULE_INDEX_BY_ID
from rule_engine import GLOBAL_RULE_REGISTRY, get_rule

def run_phase10_step1_validation():
    print("=" * 80)
    print("PHASE 10 STEP 1: UNIFIED SARIF METADATA VALIDATION")
    print("=" * 80)

    # 1. Verify driver rules directly from Rule Engine
    driver_rules = get_supported_rules()
    print(f"Driver rules count: {len(driver_rules)}")
    assert len(driver_rules) == 6, f"Expected 6 rules, got {len(driver_rules)}"

    rule_ids = [r["id"] for r in driver_rules]
    expected_cwes = ["CWE-89", "CWE-95", "CWE-78", "CWE-22", "CWE-502", "CWE-1336"]
    for cwe in expected_cwes:
        assert cwe in rule_ids, f"Rule {cwe} missing from driver rules"
        rule = get_rule(cwe)
        assert rule is not None, f"Rule {cwe} missing from GLOBAL_RULE_REGISTRY"

        # Verify metadata fields match canonical Rule Engine
        sarif_meta = next(r for r in driver_rules if r["id"] == cwe)
        assert sarif_meta["id"] == rule.sarif_metadata["id"] == cwe
        assert sarif_meta["name"] == rule.sarif_metadata["name"] == rule.name
        assert sarif_meta["shortDescription"]["text"] == rule.sarif_metadata["shortDescription"]["text"]
        assert sarif_meta["fullDescription"]["text"] == rule.sarif_metadata["fullDescription"]["text"]
        assert sarif_meta["helpUri"] == rule.sarif_metadata["helpUri"]
        assert sarif_meta["defaultConfiguration"]["level"] == "error"
        assert "tags" in sarif_meta["properties"]
        assert f"external/cwe/{cwe.lower()}" in sarif_meta["properties"]["tags"]
        print(f"[PASS] Rule Engine canonical metadata verified for {cwe}")

    # 2. Build mock scan results containing all 6 CWEs plus 1 suppressed finding
    mock_findings = []
    cwe_samples = [
        ("CWE-89", "cursor.execute", "SQL_INJECTION", "HIGH", False, None),
        ("CWE-95", "eval", "CODE_EXECUTION", "CRITICAL", False, None),
        ("CWE-78", "os.system", "COMMAND_INJECTION", "CRITICAL", False, None),
        ("CWE-22", "open", "PATH_TRAVERSAL", "HIGH", False, None),
        ("CWE-502", "pickle.loads", "UNSAFE_DESERIALIZATION", "CRITICAL", True, "verified safe internally"),
        ("CWE-1336", "render_template_string", "TEMPLATE_INJECTION", "CRITICAL", False, None),
    ]

    for idx, (cwe, sink, cat, sev, supp, just) in enumerate(cwe_samples, 1):
        f = {
            "id": f"TCS-{idx:03d}",
            "cwe": cwe,
            "category": cat,
            "severity": sev,
            "confidence": 1.0,
            "confidence_label": "CONFIRMED",
            "sink_symbol": sink,
            "file": f"module_{idx}.py",
            "line_number": idx * 10,
            "code_snippet": f"{sink}(tainted_var)",
            "flow_trace": [
                f"Source: request.args.get('input') (module_{idx}.py:1)",
                f"Taint propagation (module_{idx}.py:5)",
                f"Sink: {sink}(tainted_var) (module_{idx}.py:{idx * 10})"
            ],
            "flow_trace_summary": f"Data flow to {sink}",
            "remediation": get_rule(cwe).remediation,
            "suppressed": supp
        }
        if supp:
            f["suppression_kind"] = "inSource"
            f["suppression_justification"] = just
        mock_findings.append(f)

    # 3. Generate SARIF document
    sarif_doc = to_sarif({"findings": mock_findings})
    assert sarif_doc["version"] == "2.1.0"
    assert sarif_doc["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    results = sarif_doc["runs"][0]["results"]
    assert len(results) == 6, f"Expected 6 results, got {len(results)}"

    # 4. Verify each finding in SARIF
    for idx, res in enumerate(results):
        cwe = res["ruleId"]
        rule = get_rule(cwe)
        assert rule is not None

        # Verify ruleIndex points to driver rules
        rule_idx = res.get("ruleIndex")
        assert rule_idx is not None, f"ruleIndex missing for {cwe}"
        assert driver_rules[rule_idx]["id"] == cwe, f"ruleIndex mismatch: {driver_rules[rule_idx]['id']} != {cwe}"

        # Verify severity level
        assert res["level"] == "error"

        # Verify message text includes rule remediation and category
        msg_text = res["message"]["text"]
        assert cwe in msg_text
        assert rule.category.replace("_", " ") in msg_text
        assert rule.remediation in msg_text

        # Verify physical location
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == f"module_{idx+1}.py"
        assert loc["region"]["startLine"] == (idx + 1) * 10
        assert loc["region"]["snippet"]["text"] == f"{cwe_samples[idx][1]}(tainted_var)"

        # Verify codeFlows
        cf = res["codeFlows"][0]
        tf = cf["threadFlows"][0]
        assert len(tf["locations"]) == 3
        assert tf["locations"][0]["importance"] == "essential"
        assert tf["locations"][-1]["importance"] == "essential"
        assert tf["locations"][1]["importance"] == "important"

        # Verify suppression on CWE-502
        if cwe == "CWE-502":
            assert "suppressions" in res, "suppressions array missing on suppressed finding"
            supp = res["suppressions"][0]
            assert supp["kind"] == "inSource"
            assert supp["status"] == "accepted"
            assert supp["justification"] == "verified safe internally"
            print(f"[PASS] Suppressed finding verification for {cwe}")
        else:
            assert "suppressions" not in res, f"Unexpected suppressions on unsuppressed finding {cwe}"

        print(f"[PASS] SARIF result verified for {cwe} (ruleId, ruleIndex, level, locations, codeFlows)")

    # 5. Verify Unknown CWE handling
    unknown_finding = {
        "id": "TCS-999",
        "cwe": "CWE-9999",
        "category": "CUSTOM_VULN",
        "severity": "LOW",
        "confidence": 0.5,
        "confidence_label": "POTENTIAL",
        "sink_symbol": "custom_sink",
        "file": "custom.py",
        "line_number": 5,
        "code_snippet": "custom_sink()",
        "flow_trace": ["Source (custom.py:1)", "Sink: custom_sink() (custom.py:5)"],
        "flow_trace_summary": "Trace"
    }
    unknown_sarif = to_sarif({"findings": [unknown_finding]})
    unk_res = unknown_sarif["runs"][0]["results"][0]
    assert unk_res["ruleId"] == "CWE-9999"
    assert "ruleIndex" not in unk_res, "ruleIndex should not be set for unknown rule"
    assert len(unknown_sarif["runs"][0]["tool"]["driver"]["rules"]) == 6, "Driver rules must NOT fabricate unknown rule"
    assert unk_res["level"] == "note"
    print("[PASS] Unknown CWE handling verified (no fabricated rule, safe fallback)")

    # 6. JSON serialization check
    serialized = json.dumps(sarif_doc, indent=2)
    deserialized = json.loads(serialized)
    assert len(deserialized["runs"][0]["results"]) == 6
    print("[PASS] Complete SARIF document serialized and deserialized successfully")

    print("\n" + "=" * 80)
    print("ALL PHASE 10 STEP 1 VALIDATION CHECKS PASSED (100%)")
    print("=" * 80)

if __name__ == "__main__":
    run_phase10_step1_validation()
