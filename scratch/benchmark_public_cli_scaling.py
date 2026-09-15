#!/usr/bin/env python3
"""
TimeCodeSecurity (TCS) - Vector B Public CLI Performance Benchmark & Optimization Experiment.

Compares:
  1. Current Baseline Implementation (unbatched git show calls)
  2. Optimized Implementation (batched git cat-file --batch reader)

Evaluates the REAL public CLI invocation:
    python tcs_cli.py --staged --format json
across 4 repository scales:
  - Scale 1: 5 files
  - Scale 2: 50 files
  - Scale 3: 250 files
  - Scale 4: 1000 files

Measures:
  - Median (ms)
  - p95 (ms)
  - Min (ms)
  - Max (ms)
"""

import sys
import os
import stat
import time
import shutil
import tempfile
import subprocess
import json
from pathlib import Path
from typing import Tuple, Dict, Any, List

PROJECT_ROOT = Path(r"c:\Users\aarti gaur\OneDrive\Desktop\time code security").resolve()
CLI_SCRIPT = PROJECT_ROOT / "tcs_cli.py"


def _handle_remove_readonly(func, path, exc):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def setup_benchmark_repo(file_count: int) -> Path:
    repo_dir = Path(tempfile.mkdtemp(prefix=f"tcs_bench_{file_count}_"))
    subprocess.run(["git", "init"], cwd=str(repo_dir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    subprocess.run(["git", "config", "user.name", "Benchmarker"], cwd=str(repo_dir), check=True)
    subprocess.run(["git", "config", "user.email", "bench@tcs.local"], cwd=str(repo_dir), check=True)

    pkg_dir = repo_dir / "modules"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "__init__.py").write_text("", encoding="utf-8")

    # Generate unstaged repo background files
    for i in range(file_count - 2):
        f = pkg_dir / f"mod_{i}.py"
        f.write_text(f"def helper_{i}(x):\n    return x + {i}\n", encoding="utf-8")

    # Shared dependency module
    db_py = repo_dir / "db.py"
    db_py.write_text(
        "import sqlite3\n"
        "def query_db(s):\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute(s)\n",
        encoding="utf-8"
    )

    # Initial commit of all background files
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True)
    subprocess.run(["git", "commit", "-m", f"init {file_count} files"], cwd=str(repo_dir), check=True)

    # Staged candidate file importing db
    caller_py = repo_dir / "caller.py"
    caller_py.write_text(
        "from flask import request\n"
        "from db import query_db\n"
        "def endpoint():\n"
        "    query_db(request.args.get('q'))\n",
        encoding="utf-8"
    )
    subprocess.run(["git", "add", "caller.py"], cwd=str(repo_dir), check=True)

    return repo_dir


def benchmark_scale(repo_dir: Path, file_count: int, disable_batch: bool, iterations: int = 3) -> Dict[str, Any]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    if disable_batch:
        env["TCS_DISABLE_GIT_BATCH"] = "1"
    else:
        env.pop("TCS_DISABLE_GIT_BATCH", None)

    cmd = [sys.executable, str(CLI_SCRIPT), "--staged", "--format", "json"]

    timings = []
    for _ in range(iterations):
        start = time.perf_counter()
        res = subprocess.run(
            cmd,
            cwd=str(repo_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            check=False
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert res.returncode == 1, f"Expected 1, got {res.returncode}. Stderr: {res.stderr}"
        data = json.loads(res.stdout)
        assert len(data["findings"]) == 1
        timings.append(elapsed_ms)

    timings.sort()
    median = timings[len(timings) // 2]
    p95 = timings[int(len(timings) * 0.95)]
    return {
        "scale": file_count,
        "mode": "Current (Unbatched)" if disable_batch else "Optimized (Batched)",
        "min_ms": round(timings[0], 2),
        "median_ms": round(median, 2),
        "p95_ms": round(p95, 2),
        "max_ms": round(timings[-1], 2),
        "runs": [round(t, 2) for t in timings]
    }


def main():
    print("=" * 80)
    print("REAL PUBLIC CLI BENCHMARK: CURRENT BASELINE vs OPTIMIZED (BATCHED)")
    print("=" * 80)

    scales = [5, 50, 250, 1000]
    current_results = []
    optimized_results = []

    for s in scales:
        print(f"\nSetting up repository with {s} files...")
        repo_dir = setup_benchmark_repo(s)
        try:
            # 1. Current Baseline (Unbatched git show)
            res_cur = benchmark_scale(repo_dir, s, disable_batch=True, iterations=3)
            current_results.append(res_cur)
            print(f"  [Current Baseline]   Median: {res_cur['median_ms']:6.2f} ms | p95: {res_cur['p95_ms']:6.2f} ms | Min: {res_cur['min_ms']:6.2f} ms | Max: {res_cur['max_ms']:6.2f} ms")

            # 2. Optimized (Batched git cat-file)
            res_opt = benchmark_scale(repo_dir, s, disable_batch=False, iterations=3)
            optimized_results.append(res_opt)
            print(f"  [Optimized Batched]  Median: {res_opt['median_ms']:6.2f} ms | p95: {res_opt['p95_ms']:6.2f} ms | Min: {res_opt['min_ms']:6.2f} ms | Max: {res_opt['max_ms']:6.2f} ms")
        finally:
            shutil.rmtree(repo_dir, onerror=_handle_remove_readonly)

    print("\n" + "=" * 80)
    print(f"{'Scale':<8} | {'Mode':<22} | {'Median (ms)':<12} | {'p95 (ms)':<10} | {'Min (ms)':<10} | {'Max (ms)':<10}")
    print("-" * 80)
    for c, o in zip(current_results, optimized_results):
        print(f"{c['scale']:<8} | {c['mode']:<22} | {c['median_ms']:<12.2f} | {c['p95_ms']:<10.2f} | {c['min_ms']:<10.2f} | {c['max_ms']:<10.2f}")
        print(f"{o['scale']:<8} | {o['mode']:<22} | {o['median_ms']:<12.2f} | {o['p95_ms']:<10.2f} | {o['min_ms']:<10.2f} | {o['max_ms']:<10.2f}")
        diff = c['median_ms'] - o['median_ms']
        pct = (diff / c['median_ms']) * 100
        print(f"         --> Optimization Delta: {diff:+.2f} ms ({pct:+.1f}%)")
        print("-" * 80)
    print("=" * 80)


if __name__ == "__main__":
    main()
