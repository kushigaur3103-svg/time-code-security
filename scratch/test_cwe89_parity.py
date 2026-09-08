import os
import sys

WORKSPACE = r"c:\Users\aarti gaur\OneDrive\Desktop\time code security"
if WORKSPACE not in sys.path:
    sys.path.insert(0, WORKSPACE)
os.chdir(WORKSPACE)

from app import execute_tcs_ast_scan
from rule_engine import GLOBAL_RULE_REGISTRY

print("================================================================================")
print("FOCUSED CWE-89 PARITY TEST SUITE (PILOT MIGRATION VERIFICATION)")
print("================================================================================")

EXPECTED_REMEDIATION = (
    "Use parameterized SQL queries with bind variables instead of string concatenation/formatting, "
    "e.g., cursor.execute('SELECT * FROM tbl WHERE id = ?', (user_id,))."
)

test_cases = [
    {
        "name": "1. Vulnerable direct execute",
        "code": """from flask import request
x = request.args.get('x')
db.execute(x)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-89",
        "expected_sev": "HIGH",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "db.execute",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "2. Vulnerable execute through aliases/wrappers",
        "code": """from flask import request
x = request.args.get('x')
y = x
def helper(val):
    return val
cursor.execute(helper(y))
""",
        "expected_count": 1,
        "expected_cwe": "CWE-89",
        "expected_sev": "HIGH",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "cursor.execute",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "3. Parameterized query (safe-negative)",
        "code": """from flask import request
x = request.args.get('x')
db.execute('SELECT * FROM users WHERE id = ?', (x,))
""",
        "expected_count": 0
    },
    {
        "name": "4. Execute with multiple arguments (safe-negative)",
        "code": """from flask import request
x = request.args.get('x')
db.execute('SELECT * FROM users WHERE id = %s', x, 'extra')
""",
        "expected_count": 0
    },
    {
        "name": "5. Constant query (safe-negative)",
        "code": """db.execute('SELECT * FROM users')
""",
        "expected_count": 0
    },
    {
        "name": "6. Potential SQL flow (unknown wrapper)",
        "code": """from flask import request
x = request.args.get('x')
y = wrap_unknown(x)
cursor.execute(y)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-89",
        "expected_sev": "MEDIUM",
        "expected_conf_label": "POTENTIAL",
        "expected_conf_val": 0.5,
        "expected_sink": "cursor.execute",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "7. Deep SQL flow (interprocedural chain)",
        "code": """from flask import request

def get_data():
    return request.args.get('val')

def transform(v):
    return "SELECT * FROM t WHERE a = " + v

def run_it(q):
    db.execute(q)

run_it(transform(get_data()))
""",
        "expected_count": 1,
        "expected_cwe": "CWE-89",
        "expected_sev": "HIGH",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "db.execute",
        "expected_source": "request.args.get(...)"
    }
]

total_passed = 0
total_failed = 0

for tc in test_cases:
    name = tc["name"]
    code = tc["code"]
    res = execute_tcs_ast_scan({"app.py": code})
    findings = res.get("findings", [])
    
    try:
        if len(findings) != tc["expected_count"]:
            raise AssertionError(f"Expected {tc['expected_count']} findings, got {len(findings)}")
        
        if tc["expected_count"] > 0:
            f = findings[0]
            if f["cwe"] != tc["expected_cwe"]:
                raise AssertionError(f"CWE mismatch: expected {tc['expected_cwe']}, got {f['cwe']}")
            if f["severity"] != tc["expected_sev"]:
                raise AssertionError(f"Severity mismatch: expected {tc['expected_sev']}, got {f['severity']}")
            if f["confidence_label"] != tc["expected_conf_label"]:
                raise AssertionError(f"Confidence label mismatch: expected {tc['expected_conf_label']}, got {f['confidence_label']}")
            if f["confidence"] != tc["expected_conf_val"]:
                raise AssertionError(f"Confidence val mismatch: expected {tc['expected_conf_val']}, got {f['confidence']}")
            if f["sink_symbol"] != tc["expected_sink"]:
                raise AssertionError(f"Sink symbol mismatch: expected {tc['expected_sink']}, got {f['sink_symbol']}")
            if f["source_symbol"] != tc["expected_source"]:
                raise AssertionError(f"Source symbol mismatch: expected {tc['expected_source']}, got {f['source_symbol']}")
            if f["remediation"] != EXPECTED_REMEDIATION:
                raise AssertionError(f"Remediation text mismatch: got {f['remediation']}")
            if not f["flow_trace"] or len(f["flow_trace"]) < 2:
                raise AssertionError(f"Flow trace incomplete: {f['flow_trace']}")
            if not f["flow_trace_summary"]:
                raise AssertionError(f"Flow trace summary missing")
                
        print(f"[PASS] {name} -> Finding Count: {len(findings)} | Parity Confirmed")
        total_passed += 1
    except Exception as e:
        print(f"[FAIL] {name} -> Error: {e}")
        total_failed += 1

print("\n================================================================================")
print(f"PARITY SUMMARY: {total_passed} PASSED, {total_failed} FAILED (out of {len(test_cases)})")
print("================================================================================")

if total_failed > 0:
    sys.exit(1)
