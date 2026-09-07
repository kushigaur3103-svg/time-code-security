"""
SARIF v2.1.0 Export Adapter for TimeCodeSecurity (TCS).
Translates TCS AST scan results into the OASIS SARIF v2.1.0 JSON format
compatible with GitHub Advanced Security / Code Scanning.
"""

import re
from typing import Dict, Any, List, Optional

SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "TimeCodeSecurity"
TOOL_VERSION = "1.0.0"
TOOL_INFORMATION_URI = "https://time-code-security.onrender.com"

# The 6 supported CWE rule definitions according to the SARIF v2.1.0 specification
SUPPORTED_RULES: List[Dict[str, Any]] = [
    {
        "id": "CWE-89",
        "name": "SqlInjection",
        "shortDescription": {
            "text": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
        },
        "fullDescription": {
            "text": "The software constructs an SQL command using untrusted input from an upstream component without parameterization or proper escaping, allowing arbitrary SQL execution."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/89.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "8.5",
            "tags": ["security", "external/cwe/cwe-89"]
        }
    },
    {
        "id": "CWE-78",
        "name": "CommandInjection",
        "shortDescription": {
            "text": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
        },
        "fullDescription": {
            "text": "The software executes an OS command using untrusted input without proper neutralization, allowing attackers to execute arbitrary system commands."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/78.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "9.5",
            "tags": ["security", "external/cwe/cwe-78"]
        }
    },
    {
        "id": "CWE-22",
        "name": "PathTraversal",
        "shortDescription": {
            "text": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"
        },
        "fullDescription": {
            "text": "The software uses external input to construct a pathname without sufficient validation or containment checking, resolving to locations outside intended directories."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/22.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "7.5",
            "tags": ["security", "external/cwe/cwe-22"]
        }
    },
    {
        "id": "CWE-502",
        "name": "UnsafeDeserialization",
        "shortDescription": {
            "text": "Deserialization of Untrusted Data"
        },
        "fullDescription": {
            "text": "The application deserializes untrusted data using pickle without verifying its validity, enabling arbitrary object instantiation and code execution."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/502.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "9.8",
            "tags": ["security", "external/cwe/cwe-502"]
        }
    },
    {
        "id": "CWE-95",
        "name": "CodeExecution",
        "shortDescription": {
            "text": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"
        },
        "fullDescription": {
            "text": "The software receives input from an upstream source and executes it via eval() or exec() without proper sanitization, allowing arbitrary code execution."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/95.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "9.8",
            "tags": ["security", "external/cwe/cwe-95"]
        }
    },
    {
        "id": "CWE-1336",
        "name": "ServerSideTemplateInjection",
        "shortDescription": {
            "text": "Improper Neutralization of Special Elements Used in a Template Engine ('Server-Side Template Injection')"
        },
        "fullDescription": {
            "text": "The application passes untrusted user input directly into template constructors or render_template_string, allowing attackers to inject template directives and achieve arbitrary code execution."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/1336.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "9.0",
            "tags": ["security", "external/cwe/cwe-1336"]
        }
    }
]

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

    for f in findings:
        cwe = f.get("cwe", "UNKNOWN_CWE")
        rule_idx = RULE_INDEX_BY_ID.get(cwe)
        severity = str(f.get("severity", "HIGH")).upper()
        level = LEVEL_MAP.get(severity, "error")
        file_uri = f.get("file") or "app.py"
        line_num = int(f.get("line_number") or 1)
        code_snippet = f.get("code_snippet") or ""
        sink_symbol = f.get("sink_symbol") or "sink"
        category = (f.get("category") or "Vulnerability").replace("_", " ")

        # Result primary message
        message_text = (
            f"{cwe} ({category}): Tainted data flow reaching dangerous sink '{sink_symbol}'. "
            f"{f.get('remediation', '')}".strip()
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
                        "rules": SUPPORTED_RULES
                    }
                },
                "results": results
            }
        ]
    }

    return sarif_doc
