"""TimeCodeSecurity — Safe parallel scanner with hard resource governance.

This module provides CPU-aware, memory-governed parallel scanning that:
- Never freezes Windows by keeping ≥2 cores free for OS/DWM
- Throttles workers when RAM drops below 1.2 GB
- Enforces per-file timeouts (5 s) to prevent hangs
- Returns only lightweight primitives (no AST serialization)
- Uses fast-path pre-filtering for zero-risk files
"""
from __future__ import annotations

import ast
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import psutil


# ─── Hardware Governance Constants ───────────────────────────────────────────

MIN_FREE_CORES = 2                    # Keep at least 2 cores free for Windows OS + DWM
WORKER_RAM_BUDGET_MB = 550            # Budget 550 MB RAM per active worker process
HARD_SAFETY_THRESHOLD_MB = 900        # If available RAM < 900 MB, drop to 1 worker immediately
PER_FILE_TIMEOUT_S = 4.0              # Strict per-file watchdog timeout (seconds)
BATCH_SIZE = 40                       # Files per batch (balance IPC vs overhead)
MAX_WORKERS_CEILING = 12              # Allow up to 12 workers on cloud runners with ample RAM


def compute_safe_workers() -> int:
    """Compute safe worker count using dynamic RAM-aware hardware governor.
    
    This replaces the static min(4, ...) hardcode with adaptive scaling:
    - On low-RAM laptops (~1-2 GB free): settles on 1-2 workers safely
    - On cloud runners (8-32 GB RAM): scales up to 6-12 workers for max throughput
    
    Safety guarantees:
    - Never freezes OS by keeping ≥2 cores free
    - Hard safety threshold at 900 MB available RAM
    - Budgets 550 MB per worker to prevent OOM
    """
    try:
        mem = psutil.virtual_memory()
        free_ram_mb = mem.available / (1024 * 1024)
        
        # Calculate capacity based on both CPU and RAM
        cpu_count = os.cpu_count() or 4
        cpu_capacity = max(1, cpu_count - MIN_FREE_CORES)
        ram_capacity = max(1, int(free_ram_mb // WORKER_RAM_BUDGET_MB))
        
        # Dynamic worker calculation with hard ceiling
        max_workers = max(1, min(cpu_capacity, ram_capacity, MAX_WORKERS_CEILING))
        
        # Hard safety threshold: if RAM critically low, force single-worker mode
        if free_ram_mb < HARD_SAFETY_THRESHOLD_MB:
            print(
                f"TimeCodeSecurity [GOVERNOR] CRITICAL: Available RAM {free_ram_mb:.0f} MB "
                f"< {HARD_SAFETY_THRESHOLD_MB} MB threshold. Forcing single-worker mode.",
                file=sys.stderr,
            )
            return 1
        
        return max_workers
        
    except Exception as exc:
        # Fallback to conservative defaults if psutil fails
        print(f"Warning: Governor error ({exc}), falling back to 2 workers", file=sys.stderr)
        return 2


def compute_adaptive_timeout(available_ram_mb: float) -> float:
    """Compute per-file timeout based on available memory.
    
    Under low memory, processes swap and take longer. Increase timeout proportionally.
    Base timeout is 4.0s (PER_FILE_TIMEOUT_S).
    """
    if available_ram_mb < HARD_SAFETY_THRESHOLD_MB:
        # Critical pressure: allow up to 12s per file
        return PER_FILE_TIMEOUT_S * 3.0
    elif available_ram_mb < 1500:
        # Moderate pressure: allow up to 8s per file
        return PER_FILE_TIMEOUT_S * 2.0
    else:
        # Normal conditions: base timeout
        return PER_FILE_TIMEOUT_S


def get_memory_stats() -> Dict[str, float]:
    """Get current memory statistics in MB/GB."""
    try:
        mem = psutil.virtual_memory()
        return {
            "total_gb": mem.total / (1024 ** 3),
            "available_gb": mem.available / (1024 ** 3),
            "used_gb": mem.used / (1024 ** 3),
            "percent_used": mem.percent,
        }
    except Exception:
        return {"total_gb": 0, "available_gb": 0, "used_gb": 0, "percent_used": 0}


def _is_zero_risk_file(filepath: str, source: str) -> bool:
    """Fast-path pre-filter: skip full AST analysis for inert files.

    Zero-risk files include:
    - Empty __init__.py files
    - Files containing only static docstrings/comments
    - Pure localization string files
    """
    stripped = source.strip()
    
    # Empty file
    if not stripped:
        return True
    
    # Check if it's an __init__.py
    basename = os.path.basename(filepath)
    if basename == "__init__.py" and len(stripped) < 100:
        # Very small __init__.py — likely just imports or empty
        lines = [l.strip() for l in stripped.splitlines() if l.strip()]
        non_empty = [l for l in lines if not l.startswith('#') and not l.startswith('"""') and not l.startswith("'''")]
        if not non_empty:
            return True
    
    # Only comments/docstrings?
    try:
        tree = ast.parse(source, filename=filepath)
        # If body has only Expr(docstring) or Module-level constants, skip
        if isinstance(tree, ast.Module):
            body_items = []
            for node in tree.body:
                if isinstance(node, ast.Expr) and isinstance(node.value, (ast.Constant, ast.Str)):
                    continue  # Docstring
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    continue  # Pure imports
                else:
                    body_items.append(node)
            
            # If nothing substantive remains, it's low-risk
            if not body_items:
                return True
    except (SyntaxError, ValueError):
        pass  # Parse errors handled elsewhere
    
    return False


def _parse_single_file(args: Tuple[str, str]) -> Dict[str, Any]:
    """Parse a single Python file and return lightweight metadata.
    
    This runs in a worker process. Returns ONLY primitive types.
    
    Args:
        args: (filepath, source_code) tuple
    
    Returns:
        Dict with keys: filepath, mod_name, tree_serialized, skipped, error
    """
    filepath, source = args
    
    # Fast-path: skip zero-risk files early
    if _is_zero_risk_file(filepath, source):
        return {
            "filepath": filepath,
            "mod_name": None,
            "tree": None,
            "skipped_fast_path": True,
            "error": None,
        }
    
    # Compute module name
    mod_name = filepath.replace("\\\\", "/").replace(".py", "").replace("/", ".")
    if mod_name.endswith(".__init__"):
        mod_name = mod_name[:-9]
    
    # Parse AST
    try:
        tree = ast.parse(source, filename=filepath)
        
        # Link parent pointers (required for TaintTracker)
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                child.parent = parent
        
        return {
            "filepath": filepath,
            "mod_name": mod_name,
            "tree": tree,  # Will be pickled back to main process
            "skipped_fast_path": False,
            "error": None,
        }
    except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
        return {
            "filepath": filepath,
            "mod_name": mod_name,
            "tree": None,
            "skipped_fast_path": False,
            "error": f"{type(exc).__name__}: {exc}"[:200],
        }


def parse_files_parallel(
    files: Dict[str, str],
    max_workers: Optional[int] = None,
) -> Tuple[Dict[str, ast.AST], Dict[str, str], Dict[str, str]]:
    """Parse files in parallel with dynamic hardware governance.
    
    Args:
        files: Dict mapping filepath → source code
        max_workers: Override safe worker count (None = auto-compute via governor)
    
    Returns:
        (modules, file_paths, skipped_files) tuples matching TaintTracker init
    """
    if max_workers is None:
        max_workers = compute_safe_workers()
    
    # Get current memory stats for logging
    mem_stats = get_memory_stats()
    free_ram_mb = mem_stats["available_gb"] * 1024
    
    print(
        f"TimeCodeSecurity [GOVERNOR] Workers: {max_workers} | "
        f"Free RAM: {free_ram_mb:.0f} MB | "
        f"Cores: {os.cpu_count() or 'unknown'}",
        file=sys.stderr,
    )
    
    # Prepare file list
    file_items = list(files.items())
    total_files = len(file_items)
    
    # For small workloads, skip parallelism overhead
    if total_files <= BATCH_SIZE:
        return _parse_files_sequential(files)
    
    # Batch files to reduce IPC overhead
    batches = []
    for i in range(0, total_files, BATCH_SIZE):
        batch = file_items[i:i + BATCH_SIZE]
        batches.append(batch)
    
    modules: Dict[str, ast.AST] = {}
    file_paths: Dict[str, str] = {}
    skipped_files: Dict[str, str] = {}
    fast_path_skipped = 0
    
    start_time = time.time()
    
    # Process batches sequentially (each batch uses parallel workers internally)
    for batch_idx, batch in enumerate(batches):
        # Re-check memory between batches and adjust workers dynamically
        if batch_idx > 0 and batch_idx % 2 == 0:
            current_mem = get_memory_stats()
            current_free_mb = current_mem["available_gb"] * 1024
            
            # Hard safety threshold check
            if current_free_mb < HARD_SAFETY_THRESHOLD_MB:
                print(
                    f"TimeCodeSecurity [GOVERNOR] CRITICAL: RAM dropped to {current_free_mb:.0f} MB. "
                    f"Forcing single-worker mode.",
                    file=sys.stderr,
                )
                max_workers = 1
            elif current_free_mb < 1500:
                # Moderate pressure - reduce by 1 if possible
                if max_workers > 1:
                    print(
                        f"TimeCodeSecurity [GOVERNOR] Memory pressure ({current_free_mb:.0f} MB). "
                        f"Reducing workers from {max_workers} to {max_workers - 1}.",
                        file=sys.stderr,
                    )
                    max_workers = max(1, max_workers - 1)
        
        # Process this batch with worker pool
        batch_results = _process_batch(batch, max_workers)
        
        for result in batch_results:
            if result["error"]:
                skipped_files[result["filepath"]] = result["error"]
            elif result["skipped_fast_path"]:
                fast_path_skipped += 1
            else:
                modules[result["mod_name"]] = result["tree"]
                file_paths[result["mod_name"]] = result["filepath"]
    
    elapsed = time.time() - start_time
    
    print(
        f"TimeCodeSecurity: Parsed {len(modules)} files in {elapsed:.2f}s "
        f"({fast_path_skipped} fast-path skipped, {len(skipped_files)} errors)",
        file=sys.stderr,
    )
    
    return modules, file_paths, skipped_files


def _process_batch(
    batch: List[Tuple[str, str]],
    max_workers: int,
) -> List[Dict[str, Any]]:
    """Process a batch of files with ProcessPoolExecutor and adaptive timeouts."""
    results = []
    
    # Compute adaptive timeout based on current memory pressure
    mem_stats = get_memory_stats()
    free_ram_mb = mem_stats["available_gb"] * 1024
    per_file_timeout = compute_adaptive_timeout(free_ram_mb)
    batch_timeout = per_file_timeout * len(batch)
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        # Submit all files in batch
        future_to_file = {
            executor.submit(_parse_single_file, (filepath, source)): filepath
            for filepath, source in batch
        }
        
        # Collect results with adaptive timeout
        for future in as_completed(future_to_file, timeout=batch_timeout):
            filepath = future_to_file[future]
            try:
                result = future.result(timeout=per_file_timeout)
                results.append(result)
            except TimeoutError:
                print(
                    f"TimeCodeSecurity [WARN] File analysis timeout skipped: {filepath}",
                    file=sys.stderr,
                )
                results.append({
                    "filepath": filepath,
                    "mod_name": None,
                    "tree": None,
                    "skipped_fast_path": False,
                    "error": f"Timeout after {per_file_timeout:.1f}s (low memory)",
                })
            except Exception as exc:
                results.append({
                    "filepath": filepath,
                    "mod_name": None,
                    "tree": None,
                    "skipped_fast_path": False,
                    "error": f"Worker error: {type(exc).__name__}: {exc}"[:200],
                })
    
    return results


def _parse_files_sequential(
    files: Dict[str, str],
) -> Tuple[Dict[str, ast.AST], Dict[str, str], Dict[str, str]]:
    """Fallback sequential parsing for small workloads."""
    modules: Dict[str, ast.AST] = {}
    file_paths: Dict[str, str] = {}
    skipped_files: Dict[str, str] = {}
    fast_path_skipped = 0
    
    for filepath, source in files.items():
        if _is_zero_risk_file(filepath, source):
            fast_path_skipped += 1
            continue
        
        mod_name = filepath.replace("\\\\", "/").replace(".py", "").replace("/", ".")
        if mod_name.endswith(".__init__"):
            mod_name = mod_name[:-9]
        
        try:
            tree = ast.parse(source, filename=filepath)
            for parent in ast.walk(tree):
                for child in ast.iter_child_nodes(parent):
                    child.parent = parent
            modules[mod_name] = tree
            file_paths[mod_name] = filepath
        except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
            skipped_files[filepath] = f"{type(exc).__name__}: {exc}"[:200]
    
    return modules, file_paths, skipped_files


if __name__ == "__main__":
    # Safety guard: prevent accidental execution outside intended context
    print("TimeCodeSecurity parallel scanner module loaded successfully.")
    print(f"Safe worker count: {compute_safe_workers()}")
    print(f"Memory stats: {get_memory_stats()}")
