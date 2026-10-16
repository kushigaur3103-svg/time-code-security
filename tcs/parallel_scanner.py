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
import pathlib
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil
except ImportError:
    # `ast_scanner` imports this module inside `try/except ImportError` to set
    # PARALLEL_PARSING_AVAILABLE, so one undeclared optional dependency here silently disabled
    # parallel parsing *and* the Phase 2 fan-out that rides on it. RAM is read through
    # `tcs.parallel_analyzer.available_ram_mb()`, which works with or without psutil.
    psutil = None


# ─── Hardware Governance Constants ───────────────────────────────────────────

MIN_FREE_CORES = 2                    # Keep at least 2 cores free for Windows OS + DWM
WORKER_RAM_BUDGET_MB = 550            # Budget 550 MB RAM per active worker process
HARD_SAFETY_THRESHOLD_MB = 900        # If available RAM < 900 MB, drop to 1 worker immediately
PER_FILE_TIMEOUT_S = 4.0              # Strict per-file watchdog timeout (seconds)
# Extra head-room on top of the queue-aware deadline below. The parent itself does work between
# collections (merging results, reading files), so a deadline measured exactly to the millisecond
# would blame that bookkeeping on the worker. 1.0s on a 4.0s parse budget, nothing more.
QUEUE_BUDGET_SLACK_S = 1.0
BATCH_SIZE = 40                       # Files per batch (balance IPC vs overhead)
MAX_WORKERS_CEILING = 12              # Allow up to 12 workers on cloud runners with ample RAM
CI_TWO_CORE_RAM_MB = 1600             # 2-core CI runner gets its second worker above this much RAM


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
        from tcs.parallel_analyzer import available_ram_mb
        free_ram_mb = available_ram_mb()
        if free_ram_mb is None:
            # No measurable free RAM means no evidence the pool fits, so the 900 MB floor is
            # honoured by default rather than assumed.
            print("TimeCodeSecurity [GOVERNOR] free RAM unmeasurable: staying on 1 worker.",
                  file=sys.stderr)
            return 1
        
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

        # Same carve-out as `tcs/parallel_analyzer.compute_analysis_workers`: a 2-core runner would
        # otherwise collapse to 1 worker through `cpu_count - MIN_FREE_CORES` and never use the
        # machine CI gave it. The 900 MB floor above still wins whenever free RAM drops.
        if cpu_count == 2 and max_workers == 1 and free_ram_mb >= CI_TWO_CORE_RAM_MB:
            return 2

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


def _parse_single_file(args: Tuple[str, Optional[str]]) -> Dict[str, Any]:
    """Parse a single Python file and return lightweight metadata.
    
    This runs in a worker process. Returns ONLY primitive types.
    
    Args:
        args: (filepath, source_code) tuple. A None source means "stream it from disk here":
            the parent never buffers the repository for a fan-out it does not need.
    
    Returns:
        Dict with keys: filepath, mod_name, tree_serialized, skipped, error
    """
    filepath, source = args
    if source is None:
        try:
            source = pathlib.Path(filepath).read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError) as exc:
            return {
                "filepath": filepath,
                "mod_name": None,
                "tree": None,
                "skipped_fast_path": False,
                "error": f"{type(exc).__name__}: {exc}"[:200],
            }
    
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
) -> Tuple[Dict[str, ast.AST], Dict[str, str], Dict[str, str], Dict[str, Any]]:
    """Parse files in parallel with dynamic hardware governance.

    Args:
        files: Dict mapping filepath → source code
        max_workers: Override safe worker count (None = auto-compute via governor)

    Returns:
        (modules, file_paths, skipped_files, parse_stats) matching TaintTracker init.
        parse_stats reports every file the discovery walk handed over and where it went,
        so "scanned_files" is never mistaken for "files considered".
    """
    if max_workers is None:
        max_workers = compute_safe_workers()

    workers_initial = max_workers
    governor_events = 0

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

    modules: Dict[str, ast.AST] = {}
    file_paths: Dict[str, str] = {}
    skipped_files: Dict[str, str] = {}
    fast_path_skipped = 0
    start_time = time.time()

    def _merge(result: Dict[str, Any]) -> None:
        # The same three-way branch the batch loop used to run, just fed in file order.
        nonlocal fast_path_skipped
        if result["error"]:
            skipped_files[result["filepath"]] = result["error"]
        elif result["skipped_fast_path"]:
            fast_path_skipped += 1
        else:
            modules[result["mod_name"]] = result["tree"]
            file_paths[result["mod_name"]] = result["filepath"]

    # A governor that lands on one worker used to keep the fan-out anyway: a brand new
    # ProcessPoolExecutor for every BATCH_SIZE slice, each file pickled into the child and its AST
    # pickled back. Measured on the 609-file corpus: 4.91 s that way against 0.15 s in process, for
    # identical trees - and the per-slice spawn multiplies by 267 slices on a 10k-file repository.
    # So one worker parses in the parent, and several workers share ONE pool for the whole run
    # instead of paying a fresh interpreter per slice.
    governor_events = 0
    in_process = max_workers <= 1
    slices = [file_items[i:i + BATCH_SIZE] for i in range(0, total_files, BATCH_SIZE)]

    if in_process:
        for filepath, source in file_items:
            _merge(_parse_here(filepath, source))
        max_workers = 1
    else:
        executor: Optional[ProcessPoolExecutor] = None
        try:
            for slice_idx, batch in enumerate(slices):
                # Re-check memory between slices and adjust the pool dynamically. Once the run has
                # fallen back to the parent there is no pool left to protect, so the check stops.
                if executor is not None and slice_idx > 0 and slice_idx % 2 == 0:
                    current_free_mb = get_memory_stats()["available_gb"] * 1024
                    if current_free_mb < HARD_SAFETY_THRESHOLD_MB:
                        print(
                            f"TimeCodeSecurity [GOVERNOR] CRITICAL: RAM dropped to "
                            f"{current_free_mb:.0f} MB. Finishing this run in the parent.",
                            file=sys.stderr,
                        )
                        # A ProcessPoolExecutor cannot shrink, and "1 worker" through a pool is the
                        # pickling round-trip this change removes. The remaining slices run here:
                        # one process instead of N is the strict RAM win the governor is for.
                        # Nothing is in flight at this point (`_parse_slice` collected every
                        # future), so waiting costs nothing and leaves no orphan worker behind.
                        executor.shutdown(wait=True)
                        executor = None
                        in_process = True
                        max_workers = 1
                        governor_events += 1
                    elif current_free_mb < 1500 and max_workers > 2:
                        print(
                            f"TimeCodeSecurity [GOVERNOR] Memory pressure "
                            f"({current_free_mb:.0f} MB). Reducing workers from "
                            f"{max_workers} to {max_workers - 1}.",
                            file=sys.stderr,
                        )
                        max_workers = max_workers - 1
                        governor_events += 1
                        # Tear the pool down so the next slice rebuilds it at the smaller size: a
                        # live ProcessPoolExecutor cannot give workers back, and a log line claiming
                        # a reduction that did not happen would be the governor lying about RAM.
                        executor.shutdown(wait=True)
                        executor = None
                if in_process:
                    for filepath, source in batch:
                        _merge(_parse_here(filepath, source))
                    continue
                if executor is None:
                    executor = ProcessPoolExecutor(max_workers=max_workers)
                free_mb = get_memory_stats()["available_gb"] * 1024
                for result in _parse_slice(executor, batch, free_mb, max_workers):
                    _merge(result)
        finally:
            if executor is not None:
                executor.shutdown(wait=True)

    elapsed = time.time() - start_time

    print(
        f"TimeCodeSecurity: Parsed {len(modules)} files in {elapsed:.2f}s "
        f"({fast_path_skipped} fast-path skipped, {len(skipped_files)} errors)",
        file=sys.stderr,
    )

    parse_stats = {
        "discovered": total_files,
        "parsed": len(modules),
        "fast_path_skipped": fast_path_skipped,
        "unparseable": len(skipped_files),
        "parse_mode": "inline" if in_process else "parallel",
        "workers_initial": workers_initial,
        "workers_final": max_workers,
        "governor_events": governor_events,
    }
    return modules, file_paths, skipped_files, parse_stats




def _parse_here(filepath: str, source: Optional[str]) -> Dict[str, Any]:
    """Run the worker body in the parent. It cannot raise: it is where a lost worker lands."""
    try:
        return _parse_single_file((filepath, source))
    except Exception as exc:
        return {
            "filepath": filepath,
            "mod_name": None,
            "tree": None,
            "skipped_fast_path": False,
            "error": f"{type(exc).__name__}: {exc}"[:200],
        }


def _parse_slice(
    executor: ProcessPoolExecutor,
    batch: List[Tuple[str, Optional[str]]],
    free_ram_mb: float,
    workers: int = 1,
) -> List[Dict[str, Any]]:
    """Parse one slice on the shared pool and hand the results back in file order.

    Two properties the per-slice pool did not have:
    - the executor is created once for the whole run, so a 10k-file repository pays one spawn
      instead of one per 40 files;
    - results are collected by index, not by `as_completed`. Completion order made `modules`
      insertion order - and therefore the sink ids every later phase hands out from it - depend on
      which worker happened to finish first. Files now always land in discovery order.

    Only one slice is ever in flight, so the returned ASTs are bounded by BATCH_SIZE per parent
    instead of the whole tree sitting in the result queue.

    Queue wait is NOT parse time. `future.result(timeout=…)` was previously given the bare
    per-file parse budget, so a file that simply sat behind `idx // workers` predecessors in the
    FIFO queue burned its own watchdog while doing nothing: Home Assistant's
    `tests/components/mqtt/test_init.py` (2,797 bytes, 0.8 ms to parse) was dropped that way at
    14,893 MB free RAM, next to a "(low memory)" message that had never looked at RAM. Each file
    now gets the same parse budget, extended only by the queue depth it must wait behind - a
    genuinely stuck worker still hits a bounded deadline, a merely queued file never does.
    """
    per_file_timeout = compute_adaptive_timeout(free_ram_mb)
    workers = max(1, int(workers))
    _slice_t0 = time.perf_counter()
    futures = [executor.submit(_parse_single_file, (filepath, source))
               for filepath, source in batch]
    results: List[Dict[str, Any]] = [None] * len(batch)
    timed_out: List[Tuple[int, Any, str, Optional[str]]] = []
    for idx, ((filepath, source), future) in enumerate(zip(batch, futures)):
        # Files are collected in submission order, and the pool is FIFO, so the task at `idx`
        # cannot even START before `idx // workers` predecessors have finished. Its deadline is
        # therefore the parse budget multiplied by that queue depth.
        budget = per_file_timeout * (1 + idx // workers) + QUEUE_BUDGET_SLACK_S
        try:
            results[idx] = future.result(
                timeout=max(0.0, budget - (time.perf_counter() - _slice_t0)))
        except TimeoutError:
            timed_out.append((idx, future, filepath, source, budget))
        except Exception as exc:
            # A dead worker is a local fault, not a reason to lose a file: re-parse it here.
            print(
                f"TimeCodeSecurity [GOVERNOR] worker lost for {filepath} "
                f"({type(exc).__name__}); re-parsing in parent",
                file=sys.stderr,
            )
            results[idx] = _parse_here(filepath, source)
    # A second look at the timed-out files, costing zero wall time: later files in the slice
    # were collected while earlier workers kept running, so a future that first reported a
    # timeout may be done by now. Take those results; the parse completed anyway, and dropping
    # it lost a security-relevant file (Home Assistant's websocket_api/test_init.py) for no time
    # saved. Anything still running keeps the original skip policy, unchanged.
    for idx, future, filepath, source, budget in timed_out:
        if future.done():
            try:
                results[idx] = future.result()
                print(
                    f"TimeCodeSecurity [INFO] Recovered timed-out parse: {filepath}",
                    file=sys.stderr,
                )
                continue
            except Exception as exc:
                # Completed-with-error is the same local fault the first pass already treats as a
                # lost worker (`_parse_single_file` itself never raises - an exception here means
                # the pool or the result transport failed). Route it to the identical, pre-existing
                # fallback: `_parse_here` cannot raise and fail-closes, so a genuine parser failure
                # still lands as an error entry, never as a silently successful parse.
                print(
                    f"TimeCodeSecurity [GOVERNOR] worker lost for {filepath} "
                    f"({type(exc).__name__}); re-parsing in parent",
                    file=sys.stderr,
                )
                results[idx] = _parse_here(filepath, source)
                continue
        print(
            f"TimeCodeSecurity [WARN] File analysis timeout skipped: {filepath}",
            file=sys.stderr,
        )
        results[idx] = {
            "filepath": filepath,
            "mod_name": None,
            "tree": None,
            "skipped_fast_path": False,
            # Truthful accounting: the budget, why it is that size, and the RAM the governor saw.
            # The old string blamed "(low memory)" unconditionally, which is what made a 14.9 GB
            # runner log two files as low-memory skips.
            "error": (f"Timeout after {budget:.1f}s deadline "
                      f"(parse limit {per_file_timeout:.1f}s x queue depth "
                      f"{1 + idx // workers}, {workers} worker(s), "
                      f"{free_ram_mb:.0f} MB free RAM)"),
        }
    return results

def _parse_files_sequential(
    files: Dict[str, str],
) -> Tuple[Dict[str, ast.AST], Dict[str, str], Dict[str, str], Dict[str, Any]]:
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

    parse_stats = {
        "discovered": len(files),
        "parsed": len(modules),
        "fast_path_skipped": fast_path_skipped,
        "unparseable": len(skipped_files),
        "workers_used": 1,
        "governor_events": 0,
        "parse_mode": "sequential",
    }
    return modules, file_paths, skipped_files, parse_stats


def _read_and_parse_path(path: str) -> Dict[str, Any]:
    """Worker entry: read one file from disk and parse it, so the parent never does either.

    The path, not the source text, is what crosses the process boundary. A second serial
    read + `ast.parse` pass over the whole tree (the cross-file symbol indexer's) used to run in
    the parent while every other core sat idle; passing paths is what lets that pass fan out
    without pickling the repository's source through the queue first.
    """
    entry = {"path": path, "source": None, "tree": None, "error": None}
    try:
        source = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError) as exc:
        entry["error"] = f"read {type(exc).__name__}: {exc}"[:200]
        return entry
    entry["source"] = source
    try:
        entry["tree"] = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
        entry["error"] = f"parse {type(exc).__name__}: {exc}"[:200]
    return entry


def _read_and_parse_here(path: str) -> Dict[str, Any]:
    """Same contract in-process, and it cannot raise: this is the path a worker failure lands on.

    A lost worker must never mean a lost file. The serial re-do here is what keeps the parallel
    fan-out findings-identical to the loop it replaced.
    """
    try:
        return _read_and_parse_path(path)
    except Exception as exc:
        return {"path": path, "source": None, "tree": None,
                "error": f"{type(exc).__name__}: {exc}"[:200]}


def read_and_parse_paths(paths: List[str],
                         max_workers: Optional[int] = None) -> List[Dict[str, Any]]:
    """Read and parse *paths* in parallel, returning one entry per path **in the given order**.

    Ordering is the whole contract: callers build dicts from these results and later phases walk
    dict insertion order, so a completion-order fan-out would reshuffle findings. Entries come
    back by index, never by whoever finished first.

    Each entry is `{"path", "source", "tree", "error"}`; `tree` is None exactly when the serial
    loop would have `continue`d, so the caller's decisions are unchanged.
    """
    if not paths:
        return []
    workers = compute_safe_workers() if max_workers is None else max(1, int(max_workers))
    if workers <= 1:
        return [_read_and_parse_here(p) for p in paths]
    available_mb = get_memory_stats()["available_gb"] * 1024
    # Generous, because a timeout here is not a skip: the file is re-read and re-parsed in the
    # parent below. The watchdog exists to stop a wedged worker, not to drop work.
    file_timeout = max(PER_FILE_TIMEOUT_S * 4, compute_adaptive_timeout(available_mb) * 4)
    try:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_read_and_parse_path, p) for p in paths]
            entries: List[Dict[str, Any]] = []
            for path, future in zip(paths, futures):
                try:
                    entries.append(future.result(timeout=file_timeout))
                except Exception as exc:
                    print(f"TimeCodeSecurity [GOVERNOR] worker lost for {path} "
                          f"({type(exc).__name__}: {exc}); re-parsing in parent",
                          file=sys.stderr)
                    entries.append(_read_and_parse_here(path))
        return entries
    except Exception as exc:
        print(f"TimeCodeSecurity [GOVERNOR] path fan-out unavailable "
              f"({type(exc).__name__}: {exc}); serial read+parse of {len(paths)} file(s)",
              file=sys.stderr)
        return [_read_and_parse_here(p) for p in paths]


if __name__ == "__main__":
    # Safety guard: prevent accidental execution outside intended context
    print("TimeCodeSecurity parallel scanner module loaded successfully.")
    print(f"Safe worker count: {compute_safe_workers()}")
    print(f"Memory stats: {get_memory_stats()}")
