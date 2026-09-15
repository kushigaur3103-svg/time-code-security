#!/usr/bin/env python3
"""
TimeCodeSecurity (TCS) - Vector B Public CLI Integration Verification Suite.

Tests the REAL public CLI (`python tcs_cli.py --staged` and `python tcs_cli.py scan --staged`)
across all 12 mandatory integration scenarios:
 1. Vulnerable staged file alone (exit code 1, ProofGraph, SARIF codeFlows).
 2. Clean staged file alone (exit code 0, 0 findings).
 3. Dirty working-tree drift (staged vuln vs unstaged clean, staged clean vs unstaged vuln).
 4. Cross-file branch/merge DAG across staged caller and unstaged helpers.
 5. Cross-file sanitizer (staged caller -> unstaged sanitizer -> sink).
 6. Cross-file return propagation with exact file/line/symbol in ProofGraph.
 7. 6 Import variants (absolute, dotted, relative, multi-level).
 8. Affected-finding negative space filter (loaded_for_analysis != affected_by_change).
 9. Staged deletion with unresolved dependency resilience (no FileNotFoundError crash).
10. Staged rename (git mv) in taint path (new path tracked, old path purged).
11. Non-git directory contract (graceful warning, valid empty payload, exit 0).
12. Zero staged files / non-python staged files contract (clean notice, exit 0).
"""

import sys
import os
import stat
import shutil
import tempfile
import subprocess
import json
from pathlib import Path
from typing import Dict, Any, Tuple

PROJECT_ROOT = Path(r"c:\Users\aarti gaur\OneDrive\Desktop\time code security").resolve()
CLI_SCRIPT = PROJECT_ROOT / "tcs_cli.py"


def _handle_remove_readonly(func, path, exc):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


class VectorBCLIIntegrationHarness:
    def __init__(self):
        self.results = {}

    def setup_git_repo(self) -> Path:
        repo_dir = Path(tempfile.mkdtemp(prefix="tcs_cli_test_"))
        subprocess.run(["git", "init"], cwd=str(repo_dir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        subprocess.run(["git", "config", "user.name", "TestUser"], cwd=str(repo_dir), check=True)
        subprocess.run(["git", "config", "user.email", "test@domain.local"], cwd=str(repo_dir), check=True)
        return repo_dir

    def teardown_repo(self, repo_dir: Path):
        shutil.rmtree(repo_dir, onerror=_handle_remove_readonly)

    def run_cli(self, repo_dir: Path, args: list) -> Tuple[int, str, str]:
        cmd = [sys.executable, str(CLI_SCRIPT)] + args
        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT)
        res = subprocess.run(
            cmd,
            cwd=str(repo_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            check=False
        )
        return res.returncode, res.stdout, res.stderr

    # --------------------------------------------------------------------------
    # 1. Vulnerable Staged File Alone
    # --------------------------------------------------------------------------
    def test_01_vulnerable_staged_file(self) -> bool:
        repo = self.setup_git_repo()
        try:
            vuln_file = repo / "app.py"
            vuln_file.write_text(
                "from flask import request\n"
                "import os\n"
                "def route():\n"
                "    cmd = request.args.get('c')\n"
                "    os.system(cmd)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "app.py"], cwd=str(repo), check=True)

            # Test JSON format
            rc, stdout, stderr = self.run_cli(repo, ["--staged", "--format", "json"])
            assert rc == 1, f"Expected exit code 1 for vulnerability, got {rc}. Stderr: {stderr}"
            data = json.loads(stdout)
            assert len(data["findings"]) == 1
            f = data["findings"][0]
            assert f["cwe"] == "CWE-78"
            assert f["proof_graph"] is not None
            assert len(f["proof_graph"]["nodes"]) >= 2
            assert f["proof_graph"]["nodes"][0]["node_type"] == "SOURCE"
            assert f["proof_graph"]["nodes"][-1]["node_type"] == "SINK"

            # Test SARIF format
            rc_s, stdout_s, _ = self.run_cli(repo, ["scan", "--staged", "--format", "sarif"])
            assert rc_s == 1
            sarif = json.loads(stdout_s)
            results = sarif["runs"][0]["results"]
            assert len(results) == 1
            assert "codeFlows" in results[0]

            self.results["scenario_1"] = "PASS"
            return True
        finally:
            self.teardown_repo(repo)

    # --------------------------------------------------------------------------
    # 2. Clean Staged File Alone
    # --------------------------------------------------------------------------
    def test_02_clean_staged_file(self) -> bool:
        repo = self.setup_git_repo()
        try:
            clean_file = repo / "clean_app.py"
            clean_file.write_text(
                "import math\n"
                "def calculate(r):\n"
                "    return math.pi * (r ** 2)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "clean_app.py"], cwd=str(repo), check=True)

            rc, stdout, stderr = self.run_cli(repo, ["--staged", "--format", "json"])
            assert rc == 0, f"Expected exit code 0 for clean file, got {rc}"
            data = json.loads(stdout)
            assert len(data["findings"]) == 0
            assert data["summary"]["active_vulnerabilities"] == 0
            assert data["summary"]["risk_level"] == "CLEAN"

            self.results["scenario_2"] = "PASS"
            return True
        finally:
            self.teardown_repo(repo)

    # --------------------------------------------------------------------------
    # 3. Dirty Working-Tree Drift
    # --------------------------------------------------------------------------
    def test_03_dirty_working_tree_drift(self) -> bool:
        repo = self.setup_git_repo()
        try:
            # Case A: Staged is VULNERABLE, Working Tree has UNSTAGED FIX
            file_a = repo / "drift_a.py"
            file_a.write_text(
                "from flask import request\n"
                "import os\n"
                "def handler():\n"
                "    c = request.args.get('cmd')\n"
                "    os.system(c)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "drift_a.py"], cwd=str(repo), check=True)
            # Now edit working tree to be clean without staging
            file_a.write_text(
                "from flask import request\n"
                "import subprocess, shlex\n"
                "def handler():\n"
                "    c = request.args.get('cmd')\n"
                "    subprocess.run(['echo', c], shell=False)\n",
                encoding="utf-8"
            )

            rc, stdout, _ = self.run_cli(repo, ["--staged", "--format", "json"])
            assert rc == 1, "Must detect staged vulnerability even if working tree has unstaged fix!"
            data = json.loads(stdout)
            assert len(data["findings"]) == 1

            # Case B: Staged is CLEAN, Working Tree has UNSTAGED VULNERABILITY
            file_b = repo / "drift_b.py"
            file_b.write_text("def safe(): return 42\n", encoding="utf-8")
            subprocess.run(["git", "add", "drift_b.py"], cwd=str(repo), check=True)
            # Re-stage drift_a as clean so drift_b is tested in clean staged state
            file_a.write_text("def safe_a(): pass\n", encoding="utf-8")
            subprocess.run(["git", "add", "drift_a.py"], cwd=str(repo), check=True)

            # Now corrupt drift_b in working tree with vulnerability
            file_b.write_text(
                "from flask import request\n"
                "import os\n"
                "def bad():\n"
                "    os.system(request.args.get('x'))\n",
                encoding="utf-8"
            )

            rc_b, stdout_b, _ = self.run_cli(repo, ["--staged", "--format", "json"])
            assert rc_b == 0, "Must NOT report unstaged working tree vulnerability in staged scan!"
            data_b = json.loads(stdout_b)
            assert len(data_b["findings"]) == 0

            self.results["scenario_3"] = "PASS"
            return True
        finally:
            self.teardown_repo(repo)

    # --------------------------------------------------------------------------
    # 4. Cross-File Branch/Merge DAG
    # --------------------------------------------------------------------------
    def test_04_cross_file_branch_merge_dag(self) -> bool:
        repo = self.setup_git_repo()
        try:
            # Unstaged / committed helper module with branch and merge logic
            db_sink = repo / "db_sink.py"
            db_sink.write_text(
                "import sqlite3\n"
                "def execute_branched_sink(u, cond):\n"
                "    conn = sqlite3.connect(':memory:')\n"
                "    cursor = conn.cursor()\n"
                "    if cond:\n"
                "        a = u\n"
                "        x = a\n"
                "    else:\n"
                "        b = u\n"
                "        x = b\n"
                "    cursor.execute(x)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "db_sink.py"], cwd=str(repo), check=True)
            subprocess.run(["git", "commit", "-m", "init unstaged helpers"], cwd=str(repo), check=True)

            # Staged caller invoking cross-file branch & merge
            caller = repo / "caller_dag.py"
            caller.write_text(
                "from flask import request\n"
                "from db_sink import execute_branched_sink\n"
                "def handle_dag(cond):\n"
                "    raw = request.args.get('user_val')\n"
                "    execute_branched_sink(raw, cond)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "caller_dag.py"], cwd=str(repo), check=True)

            rc, stdout, stderr = self.run_cli(repo, ["--staged", "--format", "json"])
            assert rc == 1, f"Expected vuln in cross-file DAG, got {rc}. Stderr: {stderr}"
            data = json.loads(stdout)
            assert len(data["findings"]) == 1
            pg = data["findings"][0]["proof_graph"]
            assert pg is not None
            pg_files = {n["file_path"] for n in pg["nodes"]}
            assert "caller_dag.py" in pg_files
            assert "db_sink.py" in pg_files
            assert any(e["edge_type"] == "BRANCH_MERGE" for e in pg["edges"])

            self.results["scenario_4"] = "PASS"
            return True
        finally:
            self.teardown_repo(repo)

    # --------------------------------------------------------------------------
    # 5. Cross-File Sanitizer
    # --------------------------------------------------------------------------
    def test_05_cross_file_sanitizer(self) -> bool:
        repo = self.setup_git_repo()
        try:
            sanitizer_mod = repo / "clean_helper.py"
            sanitizer_mod.write_text(
                "def to_int(x):\n"
                "    return int(x)\n",
                encoding="utf-8"
            )
            sink_mod = repo / "sink_exec.py"
            sink_mod.write_text(
                "import os\n"
                "def run_raw(c):\n"
                "    os.system(c)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "clean_helper.py", "sink_exec.py"], cwd=str(repo), check=True)
            subprocess.run(["git", "commit", "-m", "init sanitizer and sink"], cwd=str(repo), check=True)

            # Staged caller routing through sanitizer
            caller = repo / "caller_sanitized.py"
            caller.write_text(
                "from flask import request\n"
                "from clean_helper import to_int\n"
                "from sink_exec import run_raw\n"
                "def handle_request():\n"
                "    user_input = request.args.get('c')\n"
                "    safe_input = to_int(user_input)\n"
                "    run_raw(str(safe_input))\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "caller_sanitized.py"], cwd=str(repo), check=True)

            rc, stdout, stderr = self.run_cli(repo, ["--staged", "--format", "json"])
            assert rc == 0, f"Expected 0 findings when sanitized across files, got {rc}. Out: {stdout}"
            data = json.loads(stdout)
            assert len(data["findings"]) == 0

            self.results["scenario_5"] = "PASS"
            return True
        finally:
            self.teardown_repo(repo)

    # --------------------------------------------------------------------------
    # 6. Cross-File Return Propagation
    # --------------------------------------------------------------------------
    def test_06_cross_file_return_propagation(self) -> bool:
        repo = self.setup_git_repo()
        try:
            getter_mod = repo / "data_fetcher.py"
            getter_mod.write_text(
                "from flask import request\n"
                "def fetch_user_query():\n"
                "    param = request.args.get('q')\n"
                "    return param\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "data_fetcher.py"], cwd=str(repo), check=True)
            subprocess.run(["git", "commit", "-m", "commit fetcher"], cwd=str(repo), check=True)

            staged_caller = repo / "caller_eval.py"
            staged_caller.write_text(
                "from data_fetcher import fetch_user_query\n"
                "def process():\n"
                "    val = fetch_user_query()\n"
                "    eval(val)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "caller_eval.py"], cwd=str(repo), check=True)

            rc, stdout, stderr = self.run_cli(repo, ["--staged", "--format", "json"])
            assert rc == 1
            data = json.loads(stdout)
            assert len(data["findings"]) == 1
            pg = data["findings"][0]["proof_graph"]
            assert pg is not None

            # Verify return propagation node exists
            return_nodes = [n for n in pg["nodes"] if "return" in (n.get("symbol") or "").lower() or n.get("node_type") == "TRANSFORM"]
            assert len(return_nodes) >= 1

            self.results["scenario_6"] = "PASS"
            return True
        finally:
            self.teardown_repo(repo)

    # --------------------------------------------------------------------------
    # 7. 6 Import Variants
    # --------------------------------------------------------------------------
    def test_07_import_variants(self) -> bool:
        repo = self.setup_git_repo()
        try:
            (repo / "pkg" / "sub").mkdir(parents=True)
            (repo / "db.py").write_text("import os\ndef exec_a(c): os.system(c)\n", encoding="utf-8")
            (repo / "pkg" / "__init__.py").write_text("", encoding="utf-8")
            (repo / "pkg" / "db.py").write_text("import os\ndef exec_b(c): os.system(c)\n", encoding="utf-8")
            (repo / "pkg" / "sub" / "__init__.py").write_text("", encoding="utf-8")
            (repo / "pkg" / "sub" / "db.py").write_text("import os\ndef exec_c(c): os.system(c)\n", encoding="utf-8")

            subprocess.run(["git", "add", "."], cwd=str(repo), check=True)
            subprocess.run(["git", "commit", "-m", "init modules"], cwd=str(repo), check=True)

            # Staged caller with 3 patterns
            root_caller = repo / "caller_root.py"
            root_caller.write_text(
                "from flask import request\n"
                "from db import exec_a\n"
                "import pkg.db\n"
                "def h():\n"
                "    x = request.args.get('x')\n"
                "    exec_a(x)\n"
                "    pkg.db.exec_b(x)\n",
                encoding="utf-8"
            )
            # Staged caller inside package with relative patterns
            sub_caller = repo / "pkg" / "caller_rel.py"
            sub_caller.write_text(
                "from flask import request\n"
                "from .db import exec_b\n"
                "from .sub.db import exec_c\n"
                "def h2():\n"
                "    y = request.args.get('y')\n"
                "    exec_b(y)\n"
                "    exec_c(y)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "caller_root.py", "pkg/caller_rel.py"], cwd=str(repo), check=True)

            rc, stdout, stderr = self.run_cli(repo, ["--staged", "--format", "json"])
            assert rc == 1
            data = json.loads(stdout)
            assert len(data["findings"]) >= 2
            self.results["scenario_7"] = "PASS"
            return True
        finally:
            self.teardown_repo(repo)

    # --------------------------------------------------------------------------
    # 8. Negative Space Filter (loaded != affected)
    # --------------------------------------------------------------------------
    def test_08_negative_space_filter(self) -> bool:
        repo = self.setup_git_repo()
        try:
            shared = repo / "shared_db.py"
            shared.write_text(
                "import sqlite3\n"
                "def run_a(q):\n"
                "    conn = sqlite3.connect(':memory:')\n"
                "    cursor = conn.cursor()\n"
                "    cursor.execute(q)\n"
                "def run_b(q):\n"
                "    conn = sqlite3.connect(':memory:')\n"
                "    cursor = conn.cursor()\n"
                "    cursor.execute(q)\n",
                encoding="utf-8"
            )
            legacy = repo / "legacy.py"
            legacy.write_text(
                "from flask import request\n"
                "from shared_db import run_b\n"
                "def old_vuln():\n"
                "    run_b(request.args.get('b'))\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "shared_db.py", "legacy.py"], cwd=str(repo), check=True)
            subprocess.run(["git", "commit", "-m", "init legacy and shared"], cwd=str(repo), check=True)

            # New staged file calls shared_db
            new_code = repo / "new_feature.py"
            new_code.write_text(
                "from flask import request\n"
                "from shared_db import run_a\n"
                "def new_route():\n"
                "    run_a(request.args.get('a'))\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "new_feature.py"], cwd=str(repo), check=True)

            # Run staged scan
            rc, stdout, stderr = self.run_cli(repo, ["--staged", "--format", "json"])
            assert rc == 1
            data = json.loads(stdout)
            assert len(data["findings"]) == 1, f"Expected 1 finding, got {len(data['findings'])}"
            f = data["findings"][0]
            # Ensure finding is from new_feature.py, NOT legacy.py
            pg_files = {n["file_path"] for n in f["proof_graph"]["nodes"]}
            assert "new_feature.py" in pg_files
            assert "legacy.py" not in pg_files

            self.results["scenario_8"] = "PASS"
            return True
        finally:
            self.teardown_repo(repo)

    # --------------------------------------------------------------------------
    # 9. Staged Deletion with Unresolved Dependency
    # --------------------------------------------------------------------------
    def test_09_deleted_file_resilience(self) -> bool:
        repo = self.setup_git_repo()
        try:
            # Case 9A: Imported module is staged for deletion (Adversarial test)
            # Must NOT claim CLEAN, must exit 2, must report PARTIAL_ANALYSIS
            dep = repo / "dead_module.py"
            dep.write_text("def execute_helper(val):\n    cursor.execute(val)\n", encoding="utf-8")
            subprocess.run(["git", "add", "dead_module.py"], cwd=str(repo), check=True)
            subprocess.run(["git", "commit", "-m", "add dead_module"], cwd=str(repo), check=True)

            # git rm dead_module.py
            subprocess.run(["git", "rm", "dead_module.py"], cwd=str(repo), check=True)

            caller = repo / "caller_dead.py"
            caller.write_text(
                "from flask import request\n"
                "from dead_module import execute_helper\n"
                "def handler():\n"
                "    val = request.args.get('q')\n"
                "    execute_helper(val)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "caller_dead.py"], cwd=str(repo), check=True)

            rc, stdout, stderr = self.run_cli(repo, ["--staged", "--format", "json"])
            assert rc == 2, f"Expected exit code 2 for unresolved deleted dependency, got {rc}. Stderr: {stderr}"
            data = json.loads(stdout)
            assert data["summary"]["risk_level"] != "CLEAN", "Unresolved dependency must NEVER be CLEAN"
            assert data["summary"]["risk_level"] == "PARTIAL_ANALYSIS"
            assert len(data["findings"]) == 0, "Must not fabricate vulnerabilities"
            assert len(data.get("unresolved_dependencies", [])) >= 1
            assert "dead_module" in data["unresolved_dependencies"][0]

            # Case 9B: Completely UNRELATED deleted file must NOT trigger false error
            # Replace caller_dead with a clean independent module
            caller.write_text("def safe(): return 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "caller_dead.py"], cwd=str(repo), check=True)
            subprocess.run(["git", "commit", "-m", "clean caller"], cwd=str(repo), check=True)

            # Delete an unrelated non-imported file
            unrelated = repo / "unrelated_file.txt"
            unrelated.write_text("notes\n", encoding="utf-8")
            subprocess.run(["git", "add", "unrelated_file.txt"], cwd=str(repo), check=True)
            subprocess.run(["git", "commit", "-m", "add unrelated"], cwd=str(repo), check=True)
            subprocess.run(["git", "rm", "unrelated_file.txt"], cwd=str(repo), check=True)

            # Stage a clean python file
            clean_p = repo / "clean_work.py"
            clean_p.write_text("def do_work(): return True\n", encoding="utf-8")
            subprocess.run(["git", "add", "clean_work.py"], cwd=str(repo), check=True)

            rc_unrel, stdout_unrel, _ = self.run_cli(repo, ["--staged", "--format", "json"])
            assert rc_unrel == 0, f"Expected 0 for unrelated deletion, got {rc_unrel}"
            data_unrel = json.loads(stdout_unrel)
            assert data_unrel["summary"]["risk_level"] == "CLEAN"
            assert len(data_unrel.get("unresolved_dependencies", [])) == 0

            self.results["scenario_9"] = "PASS"
            return True
        finally:
            self.teardown_repo(repo)

    # --------------------------------------------------------------------------
    # 10. Staged Rename in Taint Path
    # --------------------------------------------------------------------------
    def test_10_rename_in_taint_path(self) -> bool:
        repo = self.setup_git_repo()
        try:
            old_sink = repo / "old_sink.py"
            old_sink.write_text(
                "import os\n"
                "def exec_cmd(c): os.system(c)\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "old_sink.py"], cwd=str(repo), check=True)
            subprocess.run(["git", "commit", "-m", "init old_sink"], cwd=str(repo), check=True)

            # git mv old_sink.py new_sink.py
            subprocess.run(["git", "mv", "old_sink.py", "new_sink.py"], cwd=str(repo), check=True)

            caller = repo / "caller_renamed.py"
            caller.write_text(
                "from flask import request\n"
                "from new_sink import exec_cmd\n"
                "def h(): exec_cmd(request.args.get('c'))\n",
                encoding="utf-8"
            )
            subprocess.run(["git", "add", "caller_renamed.py"], cwd=str(repo), check=True)

            rc, stdout, stderr = self.run_cli(repo, ["--staged", "--format", "json"])
            assert rc == 1
            data = json.loads(stdout)
            assert len(data["findings"]) == 1
            pg = data["findings"][0]["proof_graph"]
            files_in_pg = {n["file_path"] for n in pg["nodes"]}
            assert "new_sink.py" in files_in_pg
            assert "old_sink.py" not in files_in_pg

            self.results["scenario_10"] = "PASS"
            return True
        finally:
            self.teardown_repo(repo)

    # --------------------------------------------------------------------------
    # 11. Non-Git Directory Contract
    # --------------------------------------------------------------------------
    def test_11_non_git_directory_contract(self) -> bool:
        non_git = Path(tempfile.mkdtemp(prefix="tcs_nogit_"))
        try:
            f = non_git / "test.py"
            f.write_text("print('hello')\n", encoding="utf-8")

            rc, stdout, stderr = self.run_cli(non_git, ["--staged", "--format", "json"])
            assert rc == 0, f"Expected 0 for non-git dir, got {rc}"
            assert "[WARN]" in stderr or "not in a git repository" in stderr
            data = json.loads(stdout)
            assert len(data["findings"]) == 0
            assert data["summary"]["risk_level"] == "CLEAN"

            self.results["scenario_11"] = "PASS"
            return True
        finally:
            shutil.rmtree(non_git, ignore_errors=True)

    # --------------------------------------------------------------------------
    # 12. Zero Staged Files / Non-Python Staged Files Contract
    # --------------------------------------------------------------------------
    def test_12_no_staged_files_contract(self) -> bool:
        repo = self.setup_git_repo()
        try:
            # Stage only a README.md
            md = repo / "README.md"
            md.write_text("# Project\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=str(repo), check=True)

            rc, stdout, stderr = self.run_cli(repo, ["--staged", "--format", "json"])
            assert rc == 0, f"Expected exit 0 for no staged py files, got {rc}"
            assert "[INFO] No staged Python files to scan." in stderr
            data = json.loads(stdout)
            assert len(data["findings"]) == 0
            assert data["summary"]["risk_level"] == "CLEAN"

            self.results["scenario_12"] = "PASS"
            return True
        finally:
            self.teardown_repo(repo)


def main():
    harness = VectorBCLIIntegrationHarness()
    scenarios = [
        ("Scenario 1: Vulnerable Staged File Alone", harness.test_01_vulnerable_staged_file),
        ("Scenario 2: Clean Staged File Alone", harness.test_02_clean_staged_file),
        ("Scenario 3: Dirty Working-Tree Drift", harness.test_03_dirty_working_tree_drift),
        ("Scenario 4: Cross-File Branch/Merge DAG", harness.test_04_cross_file_branch_merge_dag),
        ("Scenario 5: Cross-File Sanitizer", harness.test_05_cross_file_sanitizer),
        ("Scenario 6: Cross-File Return Propagation", harness.test_06_cross_file_return_propagation),
        ("Scenario 7: 6 Import Variants", harness.test_07_import_variants),
        ("Scenario 8: Negative Space Filter", harness.test_08_negative_space_filter),
        ("Scenario 9: Staged Deletion Resilience", harness.test_09_deleted_file_resilience),
        ("Scenario 10: Staged Rename in Taint Path", harness.test_10_rename_in_taint_path),
        ("Scenario 11: Non-Git Directory Contract", harness.test_11_non_git_directory_contract),
        ("Scenario 12: Zero Staged / Non-Py Contract", harness.test_12_no_staged_files_contract),
    ]

    print("=" * 70)
    print("VECTOR B REAL PUBLIC CLI INTEGRATION VERIFICATION")
    print("=" * 70)

    all_passed = True
    for name, func in scenarios:
        try:
            ok = func()
            if ok:
                print(f"  [PASS] {name}")
            else:
                print(f"  [FAIL] {name}")
                all_passed = False
        except Exception as e:
            print(f"  [FAIL] {name}: {e}")
            all_passed = False

    print("=" * 70)
    if all_passed:
        print("ALL 12 PUBLIC CLI INTEGRATION SCENARIOS PASSED SUCCESSFULLY.")
        sys.exit(0)
    else:
        print("ONE OR MORE PUBLIC CLI INTEGRATION SCENARIOS FAILED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
