"""
SARIF v2.1.0 Export Adapter for TimeCodeSecurity (TCS).
Translates TCS AST scan results into the OASIS SARIF v2.1.0 JSON format
compatible with GitHub Advanced Security / Code Scanning.
"""

import re
from typing import Dict, Any, List, Optional
from rule_engine import GLOBAL_RULE_REGISTRY, get_rule

SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "TimeCodeSecurity"
TOOL_VERSION = "1.0.0"
TOOL_INFORMATION_URI = "https://time-code-security.onrender.com"


def get_supported_rules() -> List[Dict[str, Any]]:
    """Retrieve SARIF v2.1.0 rule definitions dynamically from the Rule Engine."""
    return [
        rule.sarif_metadata
        for rule in GLOBAL_RULE_REGISTRY.all_rules()
        if rule.sarif_metadata
    ]


# Backward-compatibility facade: dynamically sourced from Rule Engine
SUPPORTED_RULES: List[Dict[str, Any]] = get_supported_rules()
RULE_INDEX_BY_ID: Dict[str, int] = {rule["id"]: idx for idx, rule in enumerate(SUPPORTED_RULES)}

LEVEL_MAP: Dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note"
}


def _parse_step_location(step_text: str, default_file: str, default_line: int) -> tuple[str, int]:
    """
    Extract (file, line) from a flow trace step string if present in format (file:line).
    Example: 'Source: request.args.get(...) (app.py:10)' -> ('app.py', 10)
    """
    match = re.search(r'\(([^:]+):(\d+)\)$', step_text.strip())
    if match:
        step_file = match.group(1).strip()
        try:
            step_line = int(match.group(2))
            return step_file, step_line
        except ValueError:
            pass
    return default_file, default_line


def to_sarif(tcs_scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Translates a TCS scan result dictionary into a valid OASIS SARIF v2.1.0 document.

    :param tcs_scan_result: Standard dictionary returned by TCS AST scan.
    :return: OASIS SARIF v2.1.0 formatted dictionary.
    """
    findings = tcs_scan_result.get("findings", []) if isinstance(tcs_scan_result, dict) else []
    results: List[Dict[str, Any]] = []
    driver_rules = get_supported_rules()
    rule_index_by_id = {rule["id"]: idx for idx, rule in enumerate(driver_rules)}

    for f in findings:
        cwe = f.get("cwe", "UNKNOWN_CWE")
        rule = get_rule(cwe)
        rule_idx = rule_index_by_id.get(cwe)
        severity = str(f.get("severity") or (rule.get_severity(f.get("confidence_label", "CONFIRMED")) if rule else "HIGH")).upper()
        level = LEVEL_MAP.get(severity, "error")
        file_uri = f.get("file") or "app.py"
        line_num = int(f.get("line_number") or 1)
        code_snippet = f.get("code_snippet") or ""
        sink_symbol = f.get("sink_symbol") or "sink"
        raw_category = f.get("category") or (rule.category if rule else "Vulnerability")
        category = raw_category.replace("_", " ")
        remediation = f.get("remediation") or (rule.remediation if rule else "")

        # Result primary message
        message_text = (
            f"{cwe} ({category}): Tainted data flow reaching dangerous sink '{sink_symbol}'. "
            f"{remediation}".strip()
        )

        # Primary location
        primary_location: Dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": file_uri,
                    "uriBaseId": "%SRCROOT%"
                },
                "region": {
                    "startLine": line_num,
                    "startColumn": 1
                }
            }
        }
        if code_snippet:
            primary_location["physicalLocation"]["region"]["snippet"] = {
                "text": code_snippet
            }

        # Build threadFlowLocations from flow_trace
        flow_steps = f.get("flow_trace", [])
        thread_flow_locations: List[Dict[str, Any]] = []

        if isinstance(flow_steps, list):
            for step_idx, step in enumerate(flow_steps):
                step_str = str(step)
                step_file, step_line = _parse_step_location(step_str, file_uri, line_num)
                is_essential = (step_idx == 0 or step_idx == len(flow_steps) - 1)

                thread_flow_locations.append({
                    "location": {
                        "message": {
                            "text": step_str
                        },
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": step_file,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": step_line,
                                "startColumn": 1
                            }
                        }
                    },
                    "importance": "essential" if is_essential else "important",
                    "executionOrder": step_idx + 1
                })

        code_flows: List[Dict[str, Any]] = []
        if thread_flow_locations:
            code_flows.append({
                "message": {
                    "text": f.get("flow_trace_summary") or f"Data-flow trace from source to sink for {cwe}"
                },
                "threadFlows": [
                    {
                        "locations": thread_flow_locations
                    }
                ]
            })

        result_obj: Dict[str, Any] = {
            "ruleId": cwe,
            "level": level,
            "message": {
                "text": message_text
            },
            "locations": [primary_location]
        }

        if rule_idx is not None:
            result_obj["ruleIndex"] = rule_idx

        if code_flows:
            result_obj["codeFlows"] = code_flows

        if f.get("suppressed"):
            supp_entry: Dict[str, Any] = {
                "kind": f.get("suppression_kind") or "inSource",
                "status": "accepted"
            }
            if f.get("suppression_justification") is not None:
                supp_entry["justification"] = f.get("suppression_justification")
            result_obj["suppressions"] = [supp_entry]

        result_obj["properties"] = {
            "confidence": f.get("confidence", 1.0),
            "confidenceLabel": f.get("confidence_label", "CONFIRMED"),
            "category": f.get("category", ""),
            "sinkSymbol": sink_symbol,
            "flowTraceSummary": f.get("flow_trace_summary", "")
        }

        results.append(result_obj)

    sarif_doc: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_INFORMATION_URI,
                        "rules": driver_rules
                    }
                },
                "results": results
            }
        ]
    }

    return sarif_doc
