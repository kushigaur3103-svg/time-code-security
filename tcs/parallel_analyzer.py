"""TimeCodeSecurity — File-level parallel scanner with deterministic merge.

This module parallelizes scanning across multiple files while ensuring:
- All 14 structural inspectors run on every file
- Full taint tracking engine executes per-worker
- Findings are deterministically merged and deduplicated
- Zero accuracy regression between --workers 1 and --workers N

Architecture:
- Each worker gets a subset of files
- Worker creates independent TaintTracker instance
- Worker runs full analyze() pipeline (all phases)
- Main process merges findings with deterministic sort + dedup
"""
from __future__ import annotations

import ast
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import psutil
except ImportError:
    # Declared optional on purpose. A hard module-level `import psutil` made this whole module
    # unimportable wherever psutil was absent, and `ast_scanner._phase2_worker_count` then fell
    # back to 1 worker silently -- that is how a 2-vCPU / 7 GB runner spent 283 s collecting
    # statements serially. `available_ram_mb()` covers the same decision without it.
    psutil = None


# ─── Worker RAM Budget for Analysis ──────────────────────────────────────────

ANALYSIS_WORKER_RAM_BUDGET_MB = 600  # Budget 600 MB per analysis worker
HARD_SAFETY_THRESHOLD_MB = 900       # Drop to 1 worker if RAM < 900 MB
CI_TWO_CORE_RAM_MB = 1600            # Minimum free RAM before any second worker is opened
MAX_PHASE2_WORKERS = 4               # Phase 2 caps here; the parent holds every parsed tree


def available_ram_mb():
    """Free RAM in MB, or None when it cannot be measured.

    psutil is the accurate source. Without it, Linux reports the same number in
    `/proc/meminfo` as MemAvailable. Other platforms without psutil return None, and every caller
    treats "unknown" as "no evidence of headroom" and stays on one worker.
    """
    if psutil is not None:
        return psutil.virtual_memory().available / (1024 * 1024)
    try:
        with open("/proc/meminfo", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    return float(line.split()[1]) / 1024.0
    except (OSError, ValueError, IndexError):
        return None
    return None


def compute_analysis_workers() -> int:
    """Compute safe worker count for analysis phase (heavier than parsing)."""
    free_ram_mb = available_ram_mb()
    if free_ram_mb is None:
        return 1
    # Hard safety threshold
    if free_ram_mb < HARD_SAFETY_THRESHOLD_MB:
        return 1

    cpu_count = os.cpu_count() or 4
    # The old rule kept 2 cores free (`cpu_count - 2`), which collapses a 2-vCPU GitHub runner to
    # zero and then to one worker, so the runner never used the machine it was given. `cpu_count`
    # capped at 4 keeps a core for the parent, and the RAM terms below still bound the pool:
    # every worker needs ANALYSIS_WORKER_RAM_BUDGET_MB of its own, and multi-worker only starts
    # once free RAM clears CI_TWO_CORE_RAM_MB.
    cpu_capacity = min(cpu_count, MAX_PHASE2_WORKERS) if free_ram_mb >= CI_TWO_CORE_RAM_MB else 1
    ram_capacity = max(1, int(free_ram_mb // ANALYSIS_WORKER_RAM_BUDGET_MB))
    return max(1, min(cpu_capacity, ram_capacity))


def _scan_file_batch(args: Tuple[List[str], str, Dict[str, Any]]) -> Dict[str, Any]:
    """Scan a batch of files in a worker process.
    
    This runs the FULL TaintTracker pipeline on assigned files.
    
    Args:
        args: (file_paths_list, scope, options_dict) tuple
    
    Returns:
        Dict with keys: findings (list of finding dicts), error (str or None)
    """
    file_paths, scope, options = args
    
    try:
        # Import here to ensure clean worker state
        from ast_scanner import TaintTracker
        
        # Collect source code for all files
        files = {}
        for fpath in file_paths:
            try:
                with open(fpath, 'r', encoding='utf-8') as f:
                    files[fpath] = f.read()
            except (OSError, UnicodeDecodeError):
                continue
        
        if not files:
            return {
                "findings": [],
                "error": None,
                "file_count": len(file_paths),
            }
        
        # Create TaintTracker and run full analysis
        tracker = TaintTracker(files=files)
        _, _, edges = tracker.analyze()
        
        # Extract findings using the same logic as cli.py
        findings = _extract_findings_from_tracker(tracker, edges)
        
        return {
            "findings": findings,
            "error": None,
            "file_count": len(file_paths),
        }
        
    except Exception as exc:
        return {
            "findings": [],
            "error": f"{type(exc).__name__}: {exc}"[:200],
            "file_count": len(file_paths),
        }


def _extract_findings_from_tracker(tracker, edges) -> List[Dict[str, Any]]:
    """Extract findings from TaintTracker matching cli.py logic.
    
    This mirrors the _findings_for() function in cli.py to ensure parity.
    """
    findings = []
    
    # Iterate through all sinks and generate findings
    for sink in tracker.sinks:
        finding = {
            "file": getattr(sink, 'location', {}).get('file', ''),
            "line": getattr(sink, 'location', {}).get('line', 0),
            "column": getattr(sink, 'location', {}).get('column', 0),
            "cwe": sink.metadata.get('cwe', '') if hasattr(sink, 'metadata') else '',
            "severity": sink.metadata.get('severity', 'MEDIUM') if hasattr(sink, 'metadata') else 'MEDIUM',
            "rule_id": sink.metadata.get('operation', '') if hasattr(sink, 'metadata') else '',
            "message": f"{sink.metadata.get('operation', 'Vulnerability')} detected",
        }
        findings.append(finding)
    
    return findings


def parallel_scan_files(
    file_paths: List[str],
    scope: str = "python",
    max_workers: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """Scan files in parallel with deterministic merge.
    
    Args:
        file_paths: List of absolute file paths to scan
        scope: Scan scope ("python", "all", etc.)
        max_workers: Override worker count (None = auto-compute)
    
    Returns:
        (merged_findings, total_files_scanned) where findings are sorted
        deterministically by (file, line, cwe, rule_id)
    """
    if max_workers is None:
        max_workers = compute_analysis_workers()
    
    total_files = len(file_paths)
    
    print(
        f"TimeCodeSecurity [PARALLEL] Scanning {total_files} files with {max_workers} workers",
        file=sys.stderr,
    )
    
    # For small workloads, skip parallelism
    if total_files <= 10 or max_workers == 1:
        result = _scan_file_batch((file_paths, scope, {}))
        if result["error"]:
            print(
                f"TimeCodeSecurity [WARN] Batch scan failed: {result['error']}",
                file=sys.stderr,
            )
        return result.get("findings", []), result.get("file_count", 0)
    
    # Partition files into batches (one per worker ideally)
    batch_size = max(1, total_files // max_workers)
    batches = []
    for i in range(0, total_files, batch_size):
        batch = file_paths[i:i + batch_size]
        batches.append(batch)
    
    all_findings = []
    total_scanned = 0
    start_time = time.time()
    
    # Process batches in parallel
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_batch = {
            executor.submit(_scan_file_batch, (batch, scope, {})): idx
            for idx, batch in enumerate(batches)
        }
        
        for future in as_completed(future_to_batch):
            batch_idx = future_to_batch[future]
            try:
                result = future.result(timeout=300)  # 5-minute timeout per batch
                if result["error"]:
                    print(
                        f"TimeCodeSecurity [WARN] Batch {batch_idx} failed: {result['error']}",
                        file=sys.stderr,
                    )
                else:
                    all_findings.extend(result["findings"])
                    total_scanned += result.get("file_count", 0)
            except Exception as exc:
                print(
                    f"TimeCodeSecurity [WARN] Batch {batch_idx} exception: {exc}",
                    file=sys.stderr,
                )
    
    elapsed = time.time() - start_time
    print(
        f"TimeCodeSecurity [PARALLEL] Completed in {elapsed:.2f}s "
        f"({len(all_findings)} findings from {total_scanned} files)",
        file=sys.stderr,
    )
    
    # Deterministic sort and deduplication
    merged_findings = _merge_and_deduplicate_findings(all_findings)
    
    return merged_findings, total_scanned


def _merge_and_deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge findings from multiple workers with deterministic sort and dedup.
    
    Deduplicates by (file, line, cwe, rule_id) tuple.
    Sorts by (file, line, cwe, rule_id) for reproducibility.
    """
    # Deduplicate
    seen = set()
    unique_findings = []
    
    for finding in findings:
        key = (
            finding.get("file", ""),
            finding.get("line", 0),
            finding.get("cwe", ""),
            finding.get("rule_id", ""),
        )
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    
    # Deterministic sort
    unique_findings.sort(
        key=lambda x: (x.get("file", ""), x.get("line", 0), x.get("cwe", ""), x.get("rule_id", ""))
    )
    
    return unique_findings


if __name__ == "__main__":
    # Safety guard for Windows multiprocessing
    print("TimeCodeSecurity parallel scanner module loaded successfully.")
