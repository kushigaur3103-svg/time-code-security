import sys
from ast_scanner import TaintTracker

code_chained = """
from flask import request
def run_query(conn):
    q = request.args.get("user")
    conn.cursor().execute(f"SELECT * FROM users WHERE name = '{q}'")
"""

code_noise = """
def add_numbers(a, b):
    return a + b
"""

code_cwe78 = """
import subprocess
from flask import request
def ping():
    ip = request.args.get("ip")
    subprocess.check_output(f"ping {ip}", shell=True)
"""

t1 = TaintTracker(files={"test_chained.py": code_chained})
_, _, edges1 = t1.analyze()
assert len(edges1) == 1
assert edges1[0].proof_graph.cwe == "CWE-89"
print("CHAINED_CALL_CWE89: PASS -", edges1[0].proof_graph.nodes[-1].symbol)

t2 = TaintTracker(files={"test_noise.py": code_noise}, audit_all=False)
_, _, edges2 = t2.analyze()
assert len(edges2) == 0
print("NOISE_SUPPRESSION: PASS - 0 findings")

t3 = TaintTracker(files={"test_cwe78.py": code_cwe78})
_, _, edges3 = t3.analyze()
assert len(edges3) == 1
assert edges3[0].proof_graph.cwe == "CWE-78"
print("CWE78_SUBPROCESS: PASS -", edges3[0].proof_graph.nodes[-1].symbol)
