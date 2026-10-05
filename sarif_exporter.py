"""
SARIF v2.1.0 Exporter Module for TimeCodeSecurity.
Provides high-level export utilities and serves as an official exporter facade
to sarif_adapter for GitHub Advanced Security and CodeQL/SARIF consumers.
"""

from typing import Dict, Any, List, Optional, Set, FrozenSet, Union
import json
import os
from pathlib import Path

from sarif_adapter import (
    to_sarif,
    get_supported_rules,
    bound_sarif_document,
    SUPPORTED_RULES,
    RULE_INDEX_BY_ID,
    LEVEL_MAP,
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    TOOL_NAME,
    TOOL_VERSION,
    TOOL_INFORMATION_URI,
)


def atomic_write_text(output_path: Union[str, Path], text: str, encoding: str = "utf-8") -> Path:
    """Publish a report in one step: a crash or kill mid-write must never leave a
    0-byte or half-written JSON/SARIF artefact for CI to choke on."""
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_name(out_path.name + ".tmp")
    try:
        with open(tmp_path, "w", encoding=encoding) as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, out_path)
    except BaseException:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise
    return out_path


def export_sarif(
    tcs_scan_result: Dict[str, Any],
    output_file: Optional[Union[str, Path]] = None,
    enabled_rule_ids: Optional[Union[Set[str], FrozenSet[str], List[str]]] = None,
    indent: int = 2
) -> Dict[str, Any]:
    """
    Serializes TimeCodeSecurity AST and multi-engine scan results into OASIS SARIF v2.1.0 JSON format.
    Optionally writes the formatted JSON directly to output_file.

    :param tcs_scan_result: Standard dictionary returned by TimeCodeSecurity AST scan.
    :param output_file: Optional file path to write SARIF output.
    :param enabled_rule_ids: Optional collection of enabled rule IDs to include in driver.rules.
    :param indent: JSON indentation formatting (default: 2).
    :return: OASIS SARIF v2.1.0 formatted dictionary.
    """
    sarif_doc = bound_sarif_document(
        to_sarif(tcs_scan_result, enabled_rule_ids=enabled_rule_ids), indent=indent
    )

    if output_file is not None:
        atomic_write_text(output_file, json.dumps(sarif_doc, indent=indent) + "\n")

    return sarif_doc


__all__ = [
    "export_sarif",
    "atomic_write_text",
    "bound_sarif_document",
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
