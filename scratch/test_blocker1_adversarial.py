import sys
import os
import subprocess
import json
import tempfile
import shutil
import stat
from pathlib import Path

PROJECT_ROOT = Path(r"c:\Users\aarti gaur\OneDrive\Desktop\time code security").resolve()
CLI_SCRIPT = PROJECT_ROOT / "tcs_cli.py"

def _rm(func, path, exc):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass

def run_test():
    repo = Path(tempfile.mkdtemp(prefix="tcs_blocker1_"))
    try:
        subprocess.run(["git", "init"], cwd=str(repo), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(repo), check=True)
        subprocess.run(["git", "config", "user.email", "tester@domain.com"], cwd=str(repo), check=True)

        # 1. Adversarial Case: staged deletion imported by staged caller
        dead = repo / "dead_module.py"
        dead.write_text("def execute_helper(value):\n    cursor.execute(value)\n", encoding="utf-8")
        subprocess.run(["git", "add", "dead_module.py"], cwd=str(repo), check=True)
        subprocess.run(["git", "commit", "-m", "init dead"], cwd=str(repo), check=True)

        # Stage deletion of dead_module.py
        subprocess.run(["git", "rm", "dead_module.py"], cwd=str(repo), check=True)

        # Staged caller importing the deleted module
        caller = repo / "caller.py"
        caller.write_text(
            "from flask import request\n"
            "from dead_module import execute_helper\n"
            "def handler():\n"
            "    value = request.args.get('q')\n"
            "    execute_helper(value)\n",
            encoding="utf-8"
        )
        subprocess.run(["git", "add", "caller.py"], cwd=str(repo), check=True)

        # Run REAL public CLI with JSON format
        cmd = [sys.executable, str(CLI_SCRIPT), "--staged", "--format", "json"]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT)
        res = subprocess.run(cmd, cwd=str(repo), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)

        print("=== CASE 1: DELETED MODULE IMPORTED ===")
        print("Exit code:", res.returncode)
        print("Stderr:\n", res.stderr.strip())
        print("Stdout:\n", res.stdout.strip())

        assert res.returncode == 2, f"Expected exit code 2, got {res.returncode}"
        data = json.loads(res.stdout)
        assert data["summary"]["risk_level"] != "CLEAN", "MUST NOT BE CLEAN"
        assert data["summary"]["risk_level"] == "PARTIAL_ANALYSIS"
        assert len(data["findings"]) == 0, "Must not fabricate a vulnerability"
        assert len(data.get("unresolved_dependencies", [])) >= 1
        assert "dead_module" in data["unresolved_dependencies"][0]

        # 2. Case: Unrelated deleted file MUST NOT trigger false error
        # Commit caller without dead_module import
        caller.write_text("def safe():\n    return 42\n", encoding="utf-8")
        subprocess.run(["git", "add", "caller.py"], cwd=str(repo), check=True)

        # Stage deletion of an unrelated file
        unrelated = repo / "unrelated_doc.txt"
        unrelated.write_text("documentation\n", encoding="utf-8")
        subprocess.run(["git", "add", "unrelated_doc.txt"], cwd=str(repo), check=True)
        subprocess.run(["git", "commit", "-m", "add unrelated doc"], cwd=str(repo), check=True)
        subprocess.run(["git", "rm", "unrelated_doc.txt"], cwd=str(repo), check=True)

        res_unrel = subprocess.run(cmd, cwd=str(repo), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        print("\n=== CASE 2: UNRELATED DELETED FILE ===")
        print("Exit code:", res_unrel.returncode)
        print("Stderr:\n", res_unrel.stderr.strip())
        assert res_unrel.returncode == 0, f"Expected exit code 0 for unrelated deleted file, got {res_unrel.returncode}"
        data_unrel = json.loads(res_unrel.stdout)
        assert data_unrel["summary"]["risk_level"] == "CLEAN"
        assert len(data_unrel.get("unresolved_dependencies", [])) == 0

        print("\n[SUCCESS] BLOCKER 1 ADVERSARIAL TEST VERIFIED 100% PASS!")
    finally:
        shutil.rmtree(repo, onerror=_rm)

if __name__ == "__main__":
    run_test()
