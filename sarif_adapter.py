"""
SARIF v2.1.0 Export Adapter for TimeCodeSecurity (TCS).
Translates TCS AST scan results into the OASIS SARIF v2.1.0 JSON format
compatible with GitHub Advanced Security / Code Scanning.
"""

import re
from typing import Dict, Any, List, Optional, Set, FrozenSet, Union
from rule_engine import GLOBAL_RULE_REGISTRY, get_rule

SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "TimeCodeSecurity"
TOOL_VERSION = "1.0.0"
TOOL_INFORMATION_URI = "https://time-code-security.onrender.com"


def get_supported_rules(enabled_rule_ids=None):
    rules = {r.sarif_metadata.get('id'): r.sarif_metadata for r in GLOBAL_RULE_REGISTRY.all_rules() if getattr(r, 'sarif_metadata', None)}
    try:
        import json, os
        cp = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'rules_catalog.json')
        if os.path.isfile(cp):
            for cid, meta in json.load(open(cp, encoding='utf-8')).get('cwes', {}).items():
                if cid not in rules:
                    num = cid.split('-')[-1]
                    rules[cid] = {'id': cid, 'name': meta.get('name', cid).replace(' ', '_'), 'shortDescription': {'text': meta.get('name', cid)}, 'fullDescription': {'text': meta.get('description', cid)}, 'helpUri': f'https://cwe.mitre.org/data/definitions/{num}.html', 'defaultConfiguration': {'level': 'error' if str(meta.get('severity')).upper() in ('CRITICAL', 'HIGH') else 'warning'}, 'properties': {'tags': ['security', f'external/cwe/cwe-{num.lower()}']}}
    except Exception:
        pass
    return [r for r in rules.values() if r.get('id') in set(enabled_rule_ids)] if enabled_rule_ids else list(rules.values())

# Backward-compatibility facade: dynamically sourced from Rule Engine
SUPPORTED_RULES: List[Dict[str, Any]] = get_supported_rules()
RULE_INDEX_BY_ID: Dict[str, int] = {rule["id"]: idx for idx, rule in enumerate(SUPPORTED_RULES)}

LEVEL_MAP: Dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "UNKNOWN": "note"
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


def to_sarif(
    tcs_scan_result: Dict[str, Any],
    enabled_rule_ids: Optional[Union[Set[str], FrozenSet[str], List[str]]] = None
) -> Dict[str, Any]:
    """
    Translates a TCS scan result dictionary into a valid OASIS SARIF v2.1.0 document.

    :param tcs_scan_result: Standard dictionary returned by TCS AST scan.
    :param enabled_rule_ids: Optional collection of enabled rule IDs to include in driver.rules.
                             If omitted, uses tcs_scan_result.get("enabled_rules") if present,
                             or defaults to all rules in GLOBAL_RULE_REGISTRY.
    :return: OASIS SARIF v2.1.0 formatted dictionary.
    """
    if enabled_rule_ids is None and isinstance(tcs_scan_result, dict):
        raw_enabled = tcs_scan_result.get("enabled_rules")
        if raw_enabled is not None:
            enabled_rule_ids = raw_enabled

    findings = tcs_scan_result.get("findings", []) if isinstance(tcs_scan_result, dict) else []
    results: List[Dict[str, Any]] = []
    driver_rules = get_supported_rules(enabled_rule_ids=enabled_rule_ids)
    rule_index_by_id = {rule["id"]: idx for idx, rule in enumerate(driver_rules)}

    for f in findings:
        cwe = f.get("cwe", "UNKNOWN_CWE")
        rule = get_rule(cwe)
        
        # Ensure driver rules and ruleIndex are always 100% complete
        if cwe not in rule_index_by_id:
            cwe_num = cwe.split("-")[-1] if "-" in cwe else cwe
            fallback_rule_def = {
                "id": cwe,
                "name": (rule.name if rule else cwe.replace("-", "_")),
                "shortDescription": {
                    "text": (rule.name if rule else f"Security rule {cwe}")
                },
                "fullDescription": {
                    "text": (rule.remediation if rule else f"Security vulnerability rule for {cwe}")
                },
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                "defaultConfiguration": {
                    "level": "error"
                },
                "properties": {
                    "tags": ["security", f"external/cwe/cwe-{cwe_num.lower()}"]
                }
            }
            rule_index_by_id[cwe] = len(driver_rules)
            driver_rules.append(fallback_rule_def)

        rule_idx = rule_index_by_id.get(cwe)
        severity = str(f.get("severity") or (rule.get_severity(f.get("confidence_label", "CONFIRMED")) if rule else "HIGH")).upper()
        level = LEVEL_MAP.get(severity, "error")
        raw_file = f.get("file") or "app.py"
        file_uri = str(raw_file).replace("\\", "/")
        try:
            line_num = max(1, int(f.get("line_number") or 1))
        except (ValueError, TypeError):
            line_num = 1
        code_snippet = f.get("code_snippet") or ""
        sink_symbol = f.get("sink_symbol") or "sink"
        raw_category = f.get("category") or (rule.category if rule else "Vulnerability")
        category = raw_category.replace("_", " ")
        remediation = f.get("remediation") or (rule.remediation if rule else "")

        # Extract proof_graph and flow_trace to determine flow structure
        proof_graph = f.get("proof_graph")
        flow_steps = f.get("flow_trace", [])
        pg_nodes = []
        if proof_graph is not None:
            pg_nodes = proof_graph.nodes if hasattr(proof_graph, "nodes") else (proof_graph.get("nodes", []) if isinstance(proof_graph, dict) else [])

        # Result primary message (aware of structural vs taint-flow findings)
        is_structural = bool(not pg_nodes and not flow_steps) or cwe in ("CWE-1004", "CWE-209", "CWE-295", "CWE-326", "CWE-327", "CWE-338", "CWE-377", "CWE-732", "CWE-798") or "STRUCTURAL" in str(f.get("discovery_mode", ""))
        if is_structural:
            message_text = (
                f"{cwe} ({category}): Security rule violation detected at dangerous sink or construct '{sink_symbol}'. "
                f"{remediation}".strip()
            )
        else:
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

        # Build threadFlowLocations from proof_graph (preferred) or flow_trace (fallback)
        thread_flow_locations: List[Dict[str, Any]] = []

        if pg_nodes:
            for step_idx, node in enumerate(pg_nodes):
                is_obj = hasattr(node, "node_type")
                node_type = node.node_type.value if (is_obj and hasattr(node.node_type, "value")) else (node.node_type if is_obj else node.get("node_type", "FLOW"))
                raw_step_file = node.file_path if is_obj else node.get("file_path", file_uri)
                step_file = str(raw_step_file or file_uri).replace("\\", "/")

                raw_start = getattr(node, "start_line", None) if is_obj else node.get("start_line")
                try:
                    start_line = max(1, int(raw_start) if raw_start is not None else line_num)
                except (ValueError, TypeError):
                    start_line = line_num

                raw_end = getattr(node, "end_line", None) if is_obj else node.get("end_line")
                try:
                    end_line = max(start_line, int(raw_end) if raw_end is not None else start_line)
                except (ValueError, TypeError):
                    end_line = start_line

                symbol = (getattr(node, "symbol", None) if is_obj else node.get("symbol")) or ""
                snippet_text = (getattr(node, "expression_snippet", None) if is_obj else node.get("expression_snippet")) or ""
                scope_id = (getattr(node, "scope_id", None) if is_obj else node.get("scope_id")) or ""
                is_essential = (step_idx == 0 or step_idx == len(pg_nodes) - 1)

                msg_text = f"[{step_idx}. {node_type}] {symbol}" + (f" in {scope_id}" if scope_id else "")
                loc_entry: Dict[str, Any] = {
                    "location": {
                        "message": {
                            "text": msg_text
                        },
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": step_file,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": start_line,
                                "endLine": end_line,
                                "startColumn": 1
                            }
                        }
                    },
                    "importance": "essential" if is_essential else "important",
                    "executionOrder": step_idx + 1
                }
                if snippet_text:
                    loc_entry["location"]["physicalLocation"]["region"]["snippet"] = {
                        "text": snippet_text
                    }
                thread_flow_locations.append(loc_entry)
        elif isinstance(flow_steps, list) and flow_steps:
            for step_idx, step in enumerate(flow_steps):
                step_str = str(step)
                step_file, step_line = _parse_step_location(step_str, file_uri, line_num)
                step_file = str(step_file).replace("\\", "/")
                try:
                    step_line = max(1, int(step_line) if step_line is not None else 1)
                except (ValueError, TypeError):
                    step_line = 1
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


    # ---------------------------------------------------------
    # SCA (Software Composition Analysis) Findings
    # ---------------------------------------------------------
    sca_findings = tcs_scan_result.get("sca_findings", []) if isinstance(tcs_scan_result, dict) else []

    # Collect and deduplicate dynamic SCA rules deterministically
    sca_rules_to_add: Dict[str, Dict[str, Any]] = {}

    for item in sca_findings:
        sf = item.to_dict() if hasattr(item, "to_dict") else dict(item)
        vuln_id = sf.get("vulnerability_id") or "UNKNOWN"
        pkg_name = sf.get("package_name") or "package"
        severity = str(sf.get("severity") or "UNKNOWN").upper()
        level = LEVEL_MAP.get(severity, "note")
        status = sf.get("status") or "POTENTIAL"
        if status == "UNRESOLVED" and level == "note":
            level = "warning"

        if vuln_id not in rule_index_by_id and vuln_id not in sca_rules_to_add:
            rule_desc = sf.get("summary") or f"Vulnerability {vuln_id} affecting {pkg_name}"
            sca_rules_to_add[vuln_id] = {
                "id": vuln_id,
                "name": vuln_id,
                "shortDescription": {
                    "text": f"Dependency advisory {vuln_id} for {pkg_name}"
                },
                "fullDescription": {
                    "text": rule_desc
                },
                "defaultConfiguration": {
                    "level": level
                },
                "properties": {
                    "tags": ["security", "sca", "dependency"],
                    "package": pkg_name,
                    "aliases": list(sf.get("aliases", []))
                }
            }

    # Add dynamic SCA rules sorted deterministically
    for vuln_id in sorted(sca_rules_to_add.keys()):
        rule_def = sca_rules_to_add[vuln_id]
        rule_index_by_id[vuln_id] = len(driver_rules)
        driver_rules.append(rule_def)

    # Serialize each SCA finding into a SARIF result
    for item in sca_findings:
        sf = item.to_dict() if hasattr(item, "to_dict") else dict(item)
        vuln_id = sf.get("vulnerability_id") or "UNKNOWN"
        pkg_name = sf.get("package_name") or "package"
        installed_ver = sf.get("installed_version")
        req_spec = sf.get("requested_specifier")
        ver_desc = installed_ver or req_spec or "unspecified"
        status = sf.get("status") or "POTENTIAL"
        fixed_ver = sf.get("fixed_version")
        summary = sf.get("summary") or ""
        severity = str(sf.get("severity") or "UNKNOWN").upper()
        level = LEVEL_MAP.get(severity, "note")
        if status == "UNRESOLVED" and level == "note":
            level = "warning"

        fixed_msg = f" Fixed version: {fixed_ver}." if fixed_ver else ""
        if status == "UNRESOLVED":
            msg_text = f"[UNRESOLVED] Vulnerability status for {pkg_name} ({ver_desc}) against {vuln_id} could not be determined: {summary}"
        else:
            msg_text = f"[{status}] Dependency '{pkg_name}' ({ver_desc}) is affected by {vuln_id}.{fixed_msg} {summary}".strip()

        # Physical location: normalize manifest path with forward slashes
        raw_manifest = sf.get("manifest_source") or "requirements.txt"
        manifest_uri = raw_manifest.replace("\\", "/")
        line_num = sf.get("line_number")

        phys_loc: Dict[str, Any] = {
            "artifactLocation": {
                "uri": manifest_uri,
                "uriBaseId": "%SRCROOT%"
            }
        }
        if line_num is not None and isinstance(line_num, int) and line_num > 0:
            phys_loc["region"] = {
                "startLine": line_num,
                "startColumn": 1
            }

        rule_idx = rule_index_by_id.get(vuln_id)
        sca_res: Dict[str, Any] = {
            "ruleId": vuln_id,
            "level": level,
            "message": {
                "text": msg_text
            },
            "locations": [
                {
                    "physicalLocation": phys_loc
                }
            ],
            "properties": {
                "sca": True,
                "packageName": pkg_name,
                "installedVersion": installed_ver,
                "requestedSpecifier": req_spec,
                "fixedVersion": fixed_ver,
                "status": status,
                "confidence": sf.get("confidence", 0.0),
                "matchedRange": sf.get("matched_range", ""),
                "cvssScore": sf.get("cvss_score")
            }
        }
        if rule_idx is not None:
            sca_res["ruleIndex"] = rule_idx

        results.append(sca_res)

    # ---------------------------------------------------------
    # Secret Scanning Findings (CWE-798)
    # ---------------------------------------------------------
    secret_findings = tcs_scan_result.get("secret_findings", []) if isinstance(tcs_scan_result, dict) else []

    if secret_findings and "CWE-798" not in rule_index_by_id:
        cwe_798_rule = {
            "id": "CWE-798",
            "name": "HardcodedCredentials",
            "shortDescription": {
                "text": "Use of Hard-coded Credentials"
            },
            "fullDescription": {
                "text": "The software contains hard-coded credentials, such as a password, token, or cryptographic key, which can be extracted and used to gain unauthorized access."
            },
            "defaultConfiguration": {
                "level": "error"
            },
            "properties": {
                "tags": ["security", "credentials", "cwe-798"]
            }
        }
        rule_index_by_id["CWE-798"] = len(driver_rules)
        driver_rules.append(cwe_798_rule)

    _SECRET_TYPE_LABELS = {
        "aws_access_key": "AWS Access Key",
        "github_token": "GitHub Token",
        "slack_token": "Slack Token",
        "stripe_key": "Stripe API Key",
        "private_key": "Private Key",
        "database_connection_string": "Database Connection String",
    }

    for item in secret_findings:
        if hasattr(item, "to_dict"):
            sf = item.to_dict()
        elif hasattr(item, "__dict__"):
            sf = item.__dict__
        else:
            sf = dict(item)

        secret_type = getattr(item, "secret_type", sf.get("secret_type", "unknown"))
        masked_val = getattr(item, "masked_value", sf.get("masked_value", ""))
        raw_file = getattr(item, "file", sf.get("file", "unknown")) or "unknown"
        file_uri = str(raw_file).replace("\\", "/")
        line_num = int(getattr(item, "line_number", sf.get("line_number", 1)) or 1)
        col_start = int(getattr(item, "column_start", sf.get("column_start", 1)) or 1)
        col_end = int(getattr(item, "column_end", sf.get("column_end", 1)) or 1)
        detector = getattr(item, "detector", sf.get("detector", "secret_scanner"))
        confidence = getattr(item, "confidence", sf.get("confidence", "HIGH"))
        context = getattr(item, "context", sf.get("context"))

        label = _SECRET_TYPE_LABELS.get(secret_type, secret_type.replace("_", " ").title())
        msg_text = f"Hardcoded {label} detected: {masked_val}"

        phys_loc = {
            "artifactLocation": {
                "uri": file_uri,
                "uriBaseId": "%SRCROOT%"
            },
            "region": {
                "startLine": line_num,
                "startColumn": col_start,
                "endColumn": col_end
            }
        }
        if context:
            phys_loc["region"]["snippet"] = {"text": context}

        rule_idx = rule_index_by_id.get("CWE-798")
        sec_res: Dict[str, Any] = {
            "ruleId": "CWE-798",
            "level": "error",
            "message": {
                "text": msg_text
            },
            "locations": [
                {
                    "physicalLocation": phys_loc
                }
            ],
            "properties": {
                "secret_type": secret_type,
                "detector": detector,
                "confidence": confidence
            }
        }
        if rule_idx is not None:
            sec_res["ruleIndex"] = rule_idx

        results.append(sec_res)

    run_obj: Dict[str, Any] = {
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

    syntax_errors = tcs_scan_result.get("syntax_errors") if isinstance(tcs_scan_result, dict) else []
    skipped_files = tcs_scan_result.get("skipped_files") if isinstance(tcs_scan_result, dict) else []
    notifications = []
    for err in (syntax_errors or []):
        notifications.append({
            "message": {
                "text": f"Skipping AST analysis for unparseable file: {err}"
            },
            "level": "warning"
        })
    for skip in (skipped_files or []):
        skip_msg = skip if isinstance(skip, str) else str(skip)
        notifications.append({
            "message": {
                "text": f"Resource limit warning: {skip_msg}"
            },
            "level": "warning"
        })
    if notifications:
        run_obj["invocations"] = [
            {
                "executionSuccessful": True,
                "toolExecutionNotifications": notifications
            }
        ]

    sarif_doc: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run_obj]
    }

    return sarif_doc
