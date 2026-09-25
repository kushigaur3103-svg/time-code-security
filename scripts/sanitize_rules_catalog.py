"""
Deterministic sanitizer for data/rules_catalog.json.

Splits each CWE's `sinks` list into:
  - `sinks`: strictly callable sinks (identifiers, dotted attribute chains,
    optionally with empty parens). Argument-bearing call expressions whose
    base chain is callable are normalized by stripping the trailing (...).
  - `structural_checks`: concept labels, chained calls, assignments,
    decorators, and arbitrary expressions that are not directly callable
    sink names.

Idempotent: re-running on an already-sanitized catalog produces no changes.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "rules_catalog.json"

CALLABLE_SINK_RE = re.compile(
    r"^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*(\(\))?$"
)

# Matches "<dotted-chain>(<anything>)" with no trailing chars after the parens.
ARG_CALL_RE = re.compile(
    r"^([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\([^()]*\)$"
)


def classify_sink(raw: str) -> tuple[str, str] | None:
    """
    Classify a single sink entry.

    Returns ("callable", normalized_name) for callable sinks,
    ("structural", raw) for structural checks.
    """
    entry = raw.strip()
    if not entry:
        return None

    if CALLABLE_SINK_RE.match(entry):
        return ("callable", entry)

    m = ARG_CALL_RE.match(entry)
    if m:
        base = m.group(1)
        if CALLABLE_SINK_RE.match(base):
            return ("callable", base)

    return ("structural", entry)


def sanitize_catalog(catalog: dict) -> tuple[dict, dict]:
    """
    Sanitize the catalog in place and return it with a stats report.

    stats keys: callable_retained, structural_moved, cwe_ids_cleaned.
    """
    cwes = catalog.get("cwes")
    if not isinstance(cwes, (list, dict)):
        raise ValueError("catalog has no recognizable 'cwes' collection")

    items = cwes.items() if isinstance(cwes, dict) else enumerate(cwes)

    callable_retained = 0
    structural_moved = 0
    cleaned: list[str] = []

    for key, cwe in items:
        if not isinstance(cwe, dict):
            continue
        cwe_id = str(cwe.get("cwe_id") or cwe.get("id") or key)

        sinks = cwe.get("sinks") or []
        if not isinstance(sinks, list):
            continue

        existing_structural = cwe.get("structural_checks") or []
        if not isinstance(existing_structural, list):
            existing_structural = []

        new_sinks: list[str] = []
        new_structural: list[str] = []
        changed = False

        for raw in sinks:
            if not isinstance(raw, str):
                new_structural.append(raw)
                changed = True
                continue
            verdict = classify_sink(raw)
            if verdict is None:
                changed = True
                continue
            kind, value = verdict
            target = new_sinks if kind == "callable" else new_structural
            if value not in target:
                target.append(value)
            if kind == "structural" or value != raw.strip():
                changed = True

        for raw in existing_structural:
            if raw not in new_structural:
                new_structural.append(raw)
            if raw in sinks:
                changed = True

        # Drop structural_checks key entirely when empty and absent before.
        had_structural_key = "structural_checks" in cwe
        if new_structural:
            cwe["structural_checks"] = new_structural
        elif had_structural_key:
            del cwe["structural_checks"]

        cwe["sinks"] = new_sinks

        callable_retained += len(new_sinks)
        structural_moved += len(new_structural)
        if changed:
            cleaned.append(cwe_id)

    return catalog, {
        "callable_retained": callable_retained,
        "structural_moved": structural_moved,
        "cwe_ids_cleaned": cleaned,
    }


def main() -> int:
    with CATALOG_PATH.open("r", encoding="utf-8") as fh:
        catalog = json.load(fh)

    cwes = catalog.get("cwes")
    cwe_count = len(cwes) if cwes is not None else 0

    catalog, stats = sanitize_catalog(catalog)

    with CATALOG_PATH.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(catalog, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print(f"Catalog sanitized: {CATALOG_PATH}")
    print(f"  CWEs processed:              {cwe_count}")
    print(f"  Total callable sinks kept:   {stats['callable_retained']}")
    print(f"  Total structural checks:     {stats['structural_moved']}")
    print(f"  CWEs cleaned (changed):      {len(stats['cwe_ids_cleaned'])}")
    if stats["cwe_ids_cleaned"]:
        print("  Cleaned CWE IDs:")
        for cwe_id in stats["cwe_ids_cleaned"]:
            print(f"    - {cwe_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
