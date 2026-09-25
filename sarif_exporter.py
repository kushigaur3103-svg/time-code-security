"""
SARIF v2.1.0 Exporter Module for TimeCodeSecurity (TCS).
Provides high-level export utilities and serves as an official exporter facade
to sarif_adapter for GitHub Advanced Security and CodeQL/SARIF consumers.
"""

from typing import Dict, Any, List, Optional, Set, FrozenSet, Union
import json
from pathlib import Path

from sarif_adapter import (
    to_sarif,
    get_supported_rules,
    SUPPORTED_RULES,
    RULE_INDEX_BY_ID,
    LEVEL_MAP,
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    TOOL_NAME,
    TOOL_VERSION,
    TOOL_INFORMATION_URI,
)


def export_sarif(
    tcs_scan_result: Dict[str, Any],
    output_file: Optional[Union[str, Path]] = None,
    enabled_rule_ids: Optional[Union[Set[str], FrozenSet[str], List[str]]] = None,
    indent: int = 2
) -> Dict[str, Any]:
    """
    Serializes TCS AST and multi-engine scan results into OASIS SARIF v2.1.0 JSON format.
    Optionally writes the formatted JSON directly to output_file.

    :param tcs_scan_result: Standard dictionary returned by TCS AST scan.
    :param output_file: Optional file path to write SARIF output.
    :param enabled_rule_ids: Optional collection of enabled rule IDs to include in driver.rules.
    :param indent: JSON indentation formatting (default: 2).
    :return: OASIS SARIF v2.1.0 formatted dictionary.
    """
    sarif_doc = to_sarif(tcs_scan_result, enabled_rule_ids=enabled_rule_ids)

    if output_file is not None:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=indent)

    return sarif_doc


__all__ = [
    "export_sarif",
    "to_sarif",
    "get_supported_rules",
    "SUPPORTED_RULES",
    "RULE_INDEX_BY_ID",
    "LEVEL_MAP",
    "SARIF_SCHEMA_URI",
    "SARIF_VERSION",
    "TOOL_NAME",
    "TOOL_VERSION",
    "TOOL_INFORMATION_URI",
]
