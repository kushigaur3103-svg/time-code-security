#!/usr/bin/env python3
"""
Vector B Architectural Audit & Feasibility Test Suite
Tests Git-staged extraction, dirty worktree adversarial resilience,
cross-file dependency closure, ProofGraph semantic equivalence,
and latency profiling without modifying any production code.
"""

import os
import sys
import shutil
import tempfile
import subprocess
import time
import ast
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any

# Ensure project root is in sys.path
PROJECT_ROOT = Path(r"c:\Users\aarti gaur\OneDrive\Desktop\time code security")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ast_scanner import TaintTracker, ProofNodeType, render_proof_graph_ascii
from tcs_cli import execute_tcs_scan, check_file_resilience


# ==============================================================================
# PROPOSED VECTOR B CORE IMPLEMENTATION FOR FEASIBILITY TESTING
# ==============================================================================

def get_git_repo_root(cwd: Path) -> Optional[Path]:
    """Resolves the root of the current Git repository, or None if not inside git."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        if res.returncode == 0 and res.stdout.strip():
            return Path(res.stdout.strip()).resolve()
    except Exception:
        pass
    return None


def get_staged_git_files(repo_root: Path) -> Tuple[List[str], List[str], List[Tuple[str, str]]]:
    """
    Queries git index for staged changes.
    Returns:
        (added_or_modified_py_files, deleted_py_files, renamed_py_files)
    Uses NUL-delimited output to handle arbitrary characters/spaces safely.
    """
    res = subprocess.run(
        ["git", "diff", "--cached", "--name-status", "-z"],
        cwd=str(repo_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False
    )
    if res.returncode != 0:
        return [], [], []

    raw = res.stdout
    parts = raw.split(b"\x00")
    
    staged_acm: List[str] = []
    staged_d: List[str] = []
    staged_r: List[Tuple[str, str]] = []

    idx = 0
    while idx < len(parts):
        token = parts[idx].decode("utf-8", errors="replace").strip()
        if not token:
            idx += 1
            continue
        status = token[0]
        if status in ("A", "C", "M"):
            if idx + 1 < len(parts):
                path = parts[idx + 1].decode("utf-8", errors="replace").replace("\\", "/")
                if path.endswith(".py"):
                    staged_acm.append(path)
                idx += 2
            else:
                idx += 1
        elif status == "D":
            if idx + 1 < len(parts):
                path = parts[idx + 1].decode("utf-8", errors="replace").replace("\\", "/")
                if path.endswith(".py"):
                    staged_d.append(path)
                idx += 2
            else:
                idx += 1
        elif status.startswith("R"):  # e.g., R100, R095
            if idx + 2 < len(parts):
                old_path = parts[idx + 1].decode("utf-8", errors="replace").replace("\\", "/")
                new_path = parts[idx + 2].decode("utf-8", errors="replace").replace("\\", "/")
                if new_path.endswith(".py"):
                    staged_acm.append(new_path)
                    staged_r.append((old_path, new_path))
                idx += 3
            else:
                idx += 1
        else:
            if idx + 1 < len(parts):
                idx += 2
            else:
                idx += 1

    return staged_acm, staged_d, staged_r


def read_git_index_blob(repo_root: Path, rel_path: str) -> Optional[str]:
    """
    Extracts the EXACT content of a file from Git index stage 0 (:0:path).
    Guarantees scanner_input == staged_index_content, completely immune
    to dirty working-tree edits.
    """
    posix_path = rel_path.replace("\\", "/")
    res = subprocess.run(
        ["git", "show", f":0:{posix_path}"],
        cwd=str(repo_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False
    )
    if res.returncode == 0:
        if b"\x00" in res.stdout[:8192]:
            return None
        if len(res.stdout) > 5 * 1024 * 1024:
            return None
        text = res.stdout.decode("utf-8", errors="replace")
        for line in text.splitlines():
            if len(line) > 10000:
                return None
        return text
    return None


def discover_ast_imports(code: str) -> Set[str]:
    """Statically discovers local module names imported in python code."""
    imported_modules: Set[str] = set()
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return imported_modules

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_modules.add(node.module.split(".")[0])
    return imported_modules


def build_staged_dependency_closure(
    repo_root: Path,
    staged_acm: List[str],
    unstaged_source: str = "index"
) -> Tuple[Dict[str, str], Set[str]]:
    """
    Constructs the complete semantic universe for staged files:
    1. Loads staged files strictly from Git index (:0:path).
    2. Recursively computes forward import dependency closure.
    3. Loads required unstaged dependencies from either index (HEAD) or working tree.
    Returns:
        (files_for_tracker, staged_set)
    """
    files: Dict[str, str] = {}
    staged_set: Set[str] = set(staged_acm)

    for sf in staged_acm:
        content = read_git_index_blob(repo_root, sf)
        if content is not None:
            files[sf] = content

    repo_py_files: Dict[str, Path] = {}
    for p in repo_root.rglob("*.py"):
        try:
            rel = p.relative_to(repo_root).as_posix()
            if not any(part in {".git", ".venv", "venv", "node_modules", "__pycache__"} for part in p.parts):
                mod_name = rel[:-3].replace("/", ".")
                repo_py_files[mod_name] = p
                bare_name = p.stem
                if bare_name not in repo_py_files:
                    repo_py_files[bare_name] = p
        except Exception:
            pass

    to_process = list(files.keys())
    visited_files = set(to_process)

    while to_process:
        curr_file = to_process.pop(0)
        curr_code = files.get(curr_file, "")
        imports = discover_ast_imports(curr_code)

        for imp in imports:
            target_path = repo_py_files.get(imp)
            if target_path:
                try:
                    rel_dep = target_path.relative_to(repo_root).as_posix()
                except ValueError:
                    rel_dep = target_path.name

                if rel_dep not in visited_files:
                    visited_files.add(rel_dep)
                    dep_content = None
                    if unstaged_source == "index":
                        dep_content = read_git_index_blob(repo_root, rel_dep)
                    if dep_content is None:
                        try:
                            dep_content = target_path.read_text(encoding="utf-8", errors="replace")
                        except Exception:
                            dep_content = None

                    if dep_content is not None:
                        files[rel_dep] = dep_content
                        to_process.append(rel_dep)

    return files, staged_set


def filter_findings_for_staged(findings: List[Dict[str, Any]], staged_set: Set[str]) -> List[Dict[str, Any]]:
    """
    Selects only findings whose ProofGraph intersects at least one staged file.
    Guarantees:
        loaded for analysis != changed / affected
    """
    affected_findings = []
    for f in findings:
        pg = f.get("proof_graph")
        if not pg:
            if f.get("file") in staged_set or f.get("source_file") in staged_set:
                affected_findings.append(f)
            continue

        nodes = pg.get("nodes", [])
        graph_files = {n.get("file_path") for n in nodes if n.get("file_path")}
        if graph_files.intersection(staged_set):
            affected_findings.append(f)

    return affected_findings


# ==============================================================================
# ADVERSARIAL TEST SUITE
# ==============================================================================

class StagedScannerAuditRunner:
    def __init__(self):
        self.results = {}

    def setup_git_repo(self) -> Tuple[Path, str]:
        temp_dir = Path(tempfile.mkdtemp(prefix="tcs_vectorB_"))
        subprocess.run(["git", "init"], cwd=str(temp_dir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        subprocess.run(["git", "config", "user.name", "TCS-Tester"], cwd=str(temp_dir), check=True)
        subprocess.run(["git", "config", "user.email", "tester@timecodesecurity.com"], cwd=str(temp_dir), check=True)
        return temp_dir, str(temp_dir)

    def teardown_git_repo(self, temp_dir: Path):
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

    def run_case_1(self) -> bool:
        temp_dir, _ = self.setup_git_repo()
        try:
            db_py = temp_dir / "db.py"
            db_py.write_text(
                "import sqlite3\n"
                "def execute_helper(sql_arg):\n"
                "    conn = sqlite3.connect(':memory:')\n"
                "    cursor = conn.cursor()\n"
                "    cursor.execute(sql_arg)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "db.py"], cwd=str(temp_dir), check=True)
            subprocess.run(["git", "commit", "-m", "add db.py"], cwd=str(temp_dir), check=True)

            routes_py = temp_dir / "routes.py"
            routes_py.write_text(
                "from flask import request\n"
                "from db import execute_helper\n"
                "def route_handler():\n"
                "    param = request.args.get('q')\n"
                "    execute_helper(param)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "routes.py"], cwd=str(temp_dir), check=True)

            full_files = {
                "db.py": db_py.read_text(encoding="utf-8"),
                "routes.py": routes_py.read_text(encoding="utf-8")
            }
            full_scan_res = execute_tcs_scan(full_files)
            full_findings = [f for f in full_scan_res["findings"] if not f.get("suppressed")]

            staged_acm, _, _ = get_staged_git_files(temp_dir)
            staged_universe, staged_set = build_staged_dependency_closure(temp_dir, staged_acm)
            staged_scan_res = execute_tcs_scan(staged_universe)
            staged_findings = filter_findings_for_staged(
                [f for f in staged_scan_res["findings"] if not f.get("suppressed")],
                staged_set
            )

            assert len(full_findings) == 1, f"Full scan expected 1 finding, got {len(full_findings)}"
            assert len(staged_findings) == 1, f"Staged scan expected 1 finding, got {len(staged_findings)}"

            f_full = full_findings[0]
            f_staged = staged_findings[0]

            assert f_staged["cwe"] == "CWE-89"
            assert f_staged["confidence"] == 1.0
            assert f_staged["confidence_label"] == "CONFIRMED"
            assert f_staged["cwe"] == f_full["cwe"]
            assert f_staged["confidence"] == f_full["confidence"]

            pg = f_staged["proof_graph"]
            assert pg is not None
            node_types = [n["node_type"] for n in pg["nodes"]]
            assert ProofNodeType.SOURCE.value in node_types
            assert ProofNodeType.PARAM_BINDING.value in node_types
            assert ProofNodeType.SINK.value in node_types

            src_nodes = [n for n in pg["nodes"] if n["node_type"] == ProofNodeType.SOURCE.value]
            param_nodes = [n for n in pg["nodes"] if n["node_type"] == ProofNodeType.PARAM_BINDING.value]
            sink_nodes = [n for n in pg["nodes"] if n["node_type"] == ProofNodeType.SINK.value]

            assert src_nodes[0]["file_path"] == "routes.py"
            assert param_nodes[0]["file_path"] == "db.py"
            assert sink_nodes[0]["file_path"] == "db.py"

            self.results["case_1"] = {
                "status": "PASS",
                "cwe": f_staged["cwe"],
                "confidence": f_staged["confidence"],
                "nodes": len(pg["nodes"]),
                "node_types": node_types
            }
            return True
        finally:
            self.teardown_git_repo(temp_dir)

    def run_case_2(self) -> bool:
        temp_dir, _ = self.setup_git_repo()
        try:
            db_py = temp_dir / "db.py"
            db_py.write_text(
                "import sqlite3\n"
                "def execute_helper(sql_arg):\n"
                "    conn = sqlite3.connect(':memory:')\n"
                "    cursor = conn.cursor()\n"
                "    cursor.execute(sql_arg)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "db.py"], cwd=str(temp_dir), check=True)
            subprocess.run(["git", "commit", "-m", "add db.py"], cwd=str(temp_dir), check=True)

            routes_clean = temp_dir / "routes_clean.py"
            routes_clean.write_text(
                "from db import execute_helper\n"
                "def route_handler():\n"
                "    param = 'SELECT id FROM static_table'\n"
                "    execute_helper(param)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "routes_clean.py"], cwd=str(temp_dir), check=True)

            staged_acm, _, _ = get_staged_git_files(temp_dir)
            staged_universe, staged_set = build_staged_dependency_closure(temp_dir, staged_acm)
            staged_scan_res = execute_tcs_scan(staged_universe)
            staged_findings = filter_findings_for_staged(
                [f for f in staged_scan_res["findings"] if not f.get("suppressed")],
                staged_set
            )

            assert len(staged_findings) == 0, f"Expected 0 active findings, got {len(staged_findings)}"
            self.results["case_2"] = {"status": "PASS", "active_findings": 0}
            return True
        finally:
            self.teardown_git_repo(temp_dir)

    def run_case_3(self) -> bool:
        temp_dir, _ = self.setup_git_repo()
        try:
            app_py = temp_dir / "app.py"
            app_py.write_text(
                "from flask import request\n"
                "import os\n"
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    os.system(cmd)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "app.py"], cwd=str(temp_dir), check=True)
            app_py.write_text(
                "import os\n"
                "def handler():\n"
                "    cmd = 'echo clean'\n"
                "    os.system(cmd)\n",
                encoding="utf-8"
            )

            staged_acm, _, _ = get_staged_git_files(temp_dir)
            staged_universe, staged_set = build_staged_dependency_closure(temp_dir, staged_acm)
            staged_scan_res = execute_tcs_scan(staged_universe)
            staged_findings = filter_findings_for_staged(
                [f for f in staged_scan_res["findings"] if not f.get("suppressed")],
                staged_set
            )

            assert len(staged_findings) == 1, "Subcase 3a failed: Did not detect staged vulnerable version!"
            assert staged_findings[0]["cwe"] == "CWE-78"

            app_py.write_text(
                "import os\n"
                "def handler():\n"
                "    cmd = 'echo clean'\n"
                "    os.system(cmd)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "app.py"], cwd=str(temp_dir), check=True)
            app_py.write_text(
                "from flask import request\n"
                "import os\n"
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    os.system(cmd)\n",
                encoding="utf-8"
            )

            staged_acm, _, _ = get_staged_git_files(temp_dir)
            staged_universe, staged_set = build_staged_dependency_closure(temp_dir, staged_acm)
            staged_scan_res = execute_tcs_scan(staged_universe)
            staged_findings = filter_findings_for_staged(
                [f for f in staged_scan_res["findings"] if not f.get("suppressed")],
                staged_set
            )

            assert len(staged_findings) == 0, "Subcase 3b failed: Leaked dirty disk vulnerable version!"

            self.results["case_3"] = {
                "status": "PASS",
                "subcase_3a": "PASS (staged vuln detected despite clean disk)",
                "subcase_3b": "PASS (staged clean honored despite dirty vuln disk)"
            }
            return True
        finally:
            self.teardown_git_repo(temp_dir)

    def run_case_4(self) -> bool:
        temp_dir, _ = self.setup_git_repo()
        try:
            target_py = temp_dir / "target.py"
            target_py.write_text("print('hello')", encoding="utf-8")
            subprocess.run(["git", "add", "target.py"], cwd=str(temp_dir), check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=str(temp_dir), check=True)

            subprocess.run(["git", "rm", "target.py"], cwd=str(temp_dir), check=True)

            staged_acm, staged_d, _ = get_staged_git_files(temp_dir)
            assert "target.py" in staged_d
            assert "target.py" not in staged_acm

            staged_universe, staged_set = build_staged_dependency_closure(temp_dir, staged_acm)
            staged_scan_res = execute_tcs_scan(staged_universe)
            staged_findings = filter_findings_for_staged(
                [f for f in staged_scan_res["findings"] if not f.get("suppressed")],
                staged_set
            )

            assert len(staged_findings) == 0
            self.results["case_4"] = {"status": "PASS", "deleted_files": staged_d, "active_findings": 0}
            return True
        finally:
            self.teardown_git_repo(temp_dir)

    def run_case_5(self) -> bool:
        temp_dir, _ = self.setup_git_repo()
        try:
            old_py = temp_dir / "old_helper.py"
            old_py.write_text("def helper():\n    return 'clean'\n", encoding="utf-8")
            subprocess.run(["git", "add", "old_helper.py"], cwd=str(temp_dir), check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=str(temp_dir), check=True)

            subprocess.run(["git", "mv", "old_helper.py", "new_helper.py"], cwd=str(temp_dir), check=True)

            staged_acm, staged_d, staged_r = get_staged_git_files(temp_dir)
            assert "new_helper.py" in staged_acm
            assert any(r[0] == "old_helper.py" and r[1] == "new_helper.py" for r in staged_r)

            staged_universe, staged_set = build_staged_dependency_closure(temp_dir, staged_acm)
            assert "new_helper.py" in staged_universe
            staged_scan_res = execute_tcs_scan(staged_universe)
            staged_findings = filter_findings_for_staged(
                [f for f in staged_scan_res["findings"] if not f.get("suppressed")],
                staged_set
            )

            assert len(staged_findings) == 0
            self.results["case_5"] = {"status": "PASS", "renames": staged_r, "analyzed_new": "new_helper.py"}
            return True
        finally:
            self.teardown_git_repo(temp_dir)

    def run_case_6(self) -> bool:
        temp_dir, _ = self.setup_git_repo()
        try:
            db_py = temp_dir / "db.py"
            db_py.write_text(
                "import sqlite3\n"
                "def execute_helper(sql_arg):\n"
                "    conn = sqlite3.connect(':memory:')\n"
                "    cursor = conn.cursor()\n"
                "    cursor.execute(sql_arg)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "db.py"], cwd=str(temp_dir), check=True)
            subprocess.run(["git", "commit", "-m", "vulnerable db.py"], cwd=str(temp_dir), check=True)

            routes_py = temp_dir / "routes.py"
            routes_py.write_text(
                "from flask import request\n"
                "from db import execute_helper\n"
                "def route_handler():\n"
                "    param = request.args.get('q')\n"
                "    execute_helper(param)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "routes.py"], cwd=str(temp_dir), check=True)

            db_py.write_text(
                "import sqlite3\n"
                "def execute_helper(sql_arg):\n"
                "    clean = int(sql_arg)\n"
                "    conn = sqlite3.connect(':memory:')\n"
                "    cursor = conn.cursor()\n"
                "    cursor.execute(str(clean))\n",
                encoding="utf-8"
            )

            staged_acm, _, _ = get_staged_git_files(temp_dir)
            staged_universe_idx, staged_set = build_staged_dependency_closure(
                temp_dir, staged_acm, unstaged_source="index"
            )
            scan_res_idx = execute_tcs_scan(staged_universe_idx)
            findings_idx = filter_findings_for_staged(
                [f for f in scan_res_idx["findings"] if not f.get("suppressed")],
                staged_set
            )

            staged_universe_wt, staged_set = build_staged_dependency_closure(
                temp_dir, staged_acm, unstaged_source="working_tree"
            )
            scan_res_wt = execute_tcs_scan(staged_universe_wt)
            findings_wt = filter_findings_for_staged(
                [f for f in scan_res_wt["findings"] if not f.get("suppressed")],
                staged_set
            )

            assert len(findings_idx) == 1, "Index-based resolution must evaluate commit state"
            assert len(findings_wt) == 0, "Working-tree resolution evaluated uncommitted disk state"

            self.results["case_6"] = {
                "status": "PASS",
                "index_findings_count": len(findings_idx),
                "wt_findings_count": len(findings_wt),
                "conclusion": "Index-based resolution prevents uncommitted working-tree drift from masking commit-stage vulnerabilities"
            }
            return True
        finally:
            self.teardown_git_repo(temp_dir)

    def run_case_7(self) -> bool:
        temp_dir, _ = self.setup_git_repo()
        try:
            db_py = temp_dir / "db_branch.py"
            db_py.write_text(
                "def execute_branched(user_val, cond):\n"
                "    if cond:\n"
                "        branch_a = user_val\n"
                "        x = branch_a\n"
                "    else:\n"
                "        branch_b = user_val\n"
                "        x = branch_b\n"
                "    cursor.execute(x)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "db_branch.py"], cwd=str(temp_dir), check=True)
            subprocess.run(["git", "commit", "-m", "add db_branch.py"], cwd=str(temp_dir), check=True)

            caller_py = temp_dir / "caller.py"
            caller_py.write_text(
                "from flask import request\n"
                "from db_branch import execute_branched\n"
                "def handle(cond):\n"
                "    user_input = request.args.get('val')\n"
                "    execute_branched(user_input, cond)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "caller.py"], cwd=str(temp_dir), check=True)

            staged_acm, _, _ = get_staged_git_files(temp_dir)
            staged_universe, staged_set = build_staged_dependency_closure(temp_dir, staged_acm)
            scan_res = execute_tcs_scan(staged_universe)
            staged_findings = filter_findings_for_staged(
                [f for f in scan_res["findings"] if not f.get("suppressed")],
                staged_set
            )

            assert len(staged_findings) == 1
            pg = staged_findings[0]["proof_graph"]
            assert pg is not None
            edges = pg["edges"]
            nodes = pg["nodes"]
            in_degrees = {}
            out_degrees = {}
            for e in edges:
                out_degrees[e["from_node_id"]] = out_degrees.get(e["from_node_id"], 0) + 1
                in_degrees[e["to_node_id"]] = in_degrees.get(e["to_node_id"], 0) + 1

            max_out = max(out_degrees.values()) if out_degrees else 1
            max_in = max(in_degrees.values()) if in_degrees else 1
            assert max_out >= 2, f"Expected node with out-degree >= 2, got {max_out}"
            assert max_in >= 2, f"Expected node with in-degree >= 2, got {max_in}"

            self.results["case_7"] = {
                "status": "PASS",
                "nodes": len(nodes),
                "edges": len(edges),
                "max_out_degree": max_out,
                "max_in_degree": max_in
            }
            return True
        finally:
            self.teardown_git_repo(temp_dir)

    def run_case_8(self) -> bool:
        temp_dir, _ = self.setup_git_repo()
        try:
            sanitizer_py = temp_dir / "sanitizers.py"
            sanitizer_py.write_text(
                "def sanitize_to_int(raw):\n"
                "    return int(raw)\n",
                encoding="utf-8"
            )
            sink_py = temp_dir / "sink_db.py"
            sink_py.write_text(
                "import sqlite3\n"
                "def exec_sql(val):\n"
                "    conn = sqlite3.connect(':memory:')\n"
                "    conn.cursor().execute(f'SELECT * FROM users WHERE id = {val}')\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "sanitizers.py", "sink_db.py"], cwd=str(temp_dir), check=True)
            subprocess.run(["git", "commit", "-m", "add helpers"], cwd=str(temp_dir), check=True)

            caller_py = temp_dir / "caller_sanitized.py"
            caller_py.write_text(
                "from flask import request\n"
                "from sanitizers import sanitize_to_int\n"
                "from sink_db import exec_sql\n"
                "def handle():\n"
                "    user_in = request.args.get('id')\n"
                "    safe_id = sanitize_to_int(user_in)\n"
                "    exec_sql(safe_id)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "caller_sanitized.py"], cwd=str(temp_dir), check=True)

            full_files = {
                "sanitizers.py": sanitizer_py.read_text(encoding="utf-8"),
                "sink_db.py": sink_py.read_text(encoding="utf-8"),
                "caller_sanitized.py": caller_py.read_text(encoding="utf-8")
            }
            full_scan_res = execute_tcs_scan(full_files)
            full_findings = [f for f in full_scan_res["findings"] if not f.get("suppressed")]

            staged_acm, _, _ = get_staged_git_files(temp_dir)
            staged_universe, staged_set = build_staged_dependency_closure(temp_dir, staged_acm)
            staged_scan_res = execute_tcs_scan(staged_universe)
            staged_findings = filter_findings_for_staged(
                [f for f in staged_scan_res["findings"] if not f.get("suppressed")],
                staged_set
            )

            assert len(full_findings) == 0, f"Full scan expected 0 findings, got {len(full_findings)}"
            assert len(staged_findings) == 0, f"Staged scan expected 0 findings, got {len(staged_findings)}"

            self.results["case_8"] = {
                "status": "PASS",
                "full_findings": 0,
                "staged_findings": 0,
                "sanitizer_preserved": True
            }
            return True
        finally:
            self.teardown_git_repo(temp_dir)

    def run_case_9(self) -> bool:
        temp_dir = Path(tempfile.mkdtemp(prefix="tcs_nogit_"))
        try:
            repo_root = get_git_repo_root(temp_dir)
            assert repo_root is None, "Expected None for directory without .git"

            self.results["case_9"] = {
                "status": "PASS",
                "repo_root": None,
                "exit_code": 0,
                "handled_gracefully": True
            }
            return True
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def run_case_10(self) -> bool:
        temp_dir, _ = self.setup_git_repo()
        try:
            staged_acm, staged_d, staged_r = get_staged_git_files(temp_dir)
            assert len(staged_acm) == 0
            assert len(staged_d) == 0
            assert len(staged_r) == 0

            staged_universe, staged_set = build_staged_dependency_closure(temp_dir, staged_acm)
            assert len(staged_universe) == 0
            scan_res = execute_tcs_scan(staged_universe)
            assert scan_res["summary"]["active_vulnerabilities"] == 0
            assert scan_res["summary"]["risk_level"] == "CLEAN"

            self.results["case_10"] = {
                "status": "PASS",
                "staged_count": 0,
                "exit_code": 0,
                "risk_level": "CLEAN"
            }
            return True
        finally:
            self.teardown_git_repo(temp_dir)


def benchmark_latency() -> Dict[str, Any]:
    temp_dir = Path(tempfile.mkdtemp(prefix="tcs_bench_"))
    try:
        subprocess.run(["git", "init"], cwd=str(temp_dir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        subprocess.run(["git", "config", "user.name", "Bench"], cwd=str(temp_dir), check=True)
        subprocess.run(["git", "config", "user.email", "bench@test.com"], cwd=str(temp_dir), check=True)

        for i in range(15):
            p = temp_dir / f"dep_{i}.py"
            p.write_text(f"def util_{i}(x):\n    return x + {i}\n", encoding="utf-8")
        
        db_p = temp_dir / "db_bench.py"
        db_p.write_text(
            "import sqlite3\n"
            "def exec_query(sql):\n"
            "    conn = sqlite3.connect(':memory:')\n"
            "    conn.cursor().execute(sql)\n",
            encoding="utf-8"
        )

        subprocess.run(["git", "add", "."], cwd=str(temp_dir), check=True)
        subprocess.run(["git", "commit", "-m", "init multi-file repo"], cwd=str(temp_dir), check=True)

        routes_p = temp_dir / "routes_bench.py"
        routes_p.write_text(
            "from flask import request\n"
            "from db_bench import exec_query\n"
            "def handle():\n"
            "    q = request.args.get('query')\n"
            "    exec_query(q)\n",
            encoding="utf-8"
        )
        subprocess.run(["git", "add", "routes_bench.py"], cwd=str(temp_dir), check=True)

        iterations = 10
        git_times = []
        dep_times = []
        sem_times = []
        filt_times = []
        total_staged_times = []
        total_full_times = []

        full_repo_files = {}
        for f in temp_dir.glob("*.py"):
            full_repo_files[f.name] = f.read_text(encoding="utf-8")

        for iteration in range(iterations):
            t0_full = time.perf_counter()
            execute_tcs_scan(full_repo_files)
            t1_full = time.perf_counter()
            total_full_times.append((t1_full - t0_full) * 1000.0)

            t0 = time.perf_counter()
            staged_acm, _, _ = get_staged_git_files(temp_dir)
            t1 = time.perf_counter()

            staged_universe, staged_set = build_staged_dependency_closure(temp_dir, staged_acm)
            t2 = time.perf_counter()

            scan_res = execute_tcs_scan(staged_universe)
            t3 = time.perf_counter()

            filter_findings_for_staged(scan_res["findings"], staged_set)
            t4 = time.perf_counter()

            git_times.append((t1 - t0) * 1000.0)
            dep_times.append((t2 - t1) * 1000.0)
            sem_times.append((t3 - t2) * 1000.0)
            filt_times.append((t4 - t3) * 1000.0)
            total_staged_times.append((t4 - t0) * 1000.0)

        def stats(vals):
            s = sorted(vals)
            n = len(s)
            p95_idx = int(0.95 * n) if n > 1 else 0
            return {
                "min": round(min(s), 2),
                "median": round(s[n // 2], 2),
                "p95": round(s[p95_idx], 2),
                "max": round(max(s), 2)
            }

        return {
            "iterations": iterations,
            "cold_staged_ms": round(total_staged_times[0], 2),
            "warm_staged_median_ms": round(stats(total_staged_times[1:])["median"], 2),
            "total_staged_stats": stats(total_staged_times),
            "total_full_stats": stats(total_full_times),
            "breakdown": {
                "git_extraction_ms": stats(git_times),
                "dependency_discovery_ms": stats(dep_times),
                "semantic_analysis_ms": stats(sem_times),
                "filtering_serialization_ms": stats(filt_times)
            }
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def main():
    print("=" * 60)
    print("VECTOR B STAGED SCANNER AUDIT & ADVERSARIAL TEST SUITE")
    print("=" * 60)

    runner = StagedScannerAuditRunner()

    tests = [
        ("Case 1: Vulnerable staged + unstaged dependency", runner.run_case_1),
        ("Case 2: Clean staged + unstaged dependency", runner.run_case_2),
        ("Case 3: Staged differs from working tree (Dirty tree)", runner.run_case_3),
        ("Case 4: Deleted file (git rm)", runner.run_case_4),
        ("Case 5: Renamed file (git mv)", runner.run_case_5),
        ("Case 6: Unstaged dependency modified", runner.run_case_6),
        ("Case 7: Cross-file branch / merge DAG", runner.run_case_7),
        ("Case 8: Cross-file sanitizer", runner.run_case_8),
        ("Case 9: Missing .git directory", runner.run_case_9),
        ("Case 10: No staged files", runner.run_case_10),
    ]

    passed = 0
    for name, fn in tests:
        try:
            ok = fn()
            if ok:
                print(f"[PASS] {name}")
                passed += 1
            else:
                print(f"[FAIL] {name}")
        except Exception as e:
            print(f"[FAIL] {name}: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 60)
    print(f"ADVERSARIAL SUITE SUMMARY: {passed}/{len(tests)} PASSED")
    print("=" * 60)

    print("\nRunning Performance Benchmark (10 iterations)...")
    bench = benchmark_latency()
    print(f"Cold Staged Scan: {bench['cold_staged_ms']} ms")
    print(f"Warm Staged Median: {bench['warm_staged_median_ms']} ms")
    print(f"Full Scan Median: {bench['total_full_stats']['median']} ms")
    print(f"Staged Stats: {bench['total_staged_stats']}")
    print(f"Full Stats: {bench['total_full_stats']}")
    print(f"Staged Breakdown (Median):")
    print(f"  - Git extraction: {bench['breakdown']['git_extraction_ms']['median']} ms")
    print(f"  - Dependency discovery: {bench['breakdown']['dependency_discovery_ms']['median']} ms")
    print(f"  - Semantic analysis: {bench['breakdown']['semantic_analysis_ms']['median']} ms")
    print(f"  - Result filtering: {bench['breakdown']['filtering_serialization_ms']['median']} ms")

    if passed == len(tests):
        print("\nALL VECTOR B ADVERSARIAL & SEMANTIC AUDIT TESTS PASSED!")
        return 0
    else:
        print("\nSOME TESTS FAILED!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
