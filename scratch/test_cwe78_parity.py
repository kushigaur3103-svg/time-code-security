import os
import sys

WORKSPACE = r"c:\Users\aarti gaur\OneDrive\Desktop\time code security"
if WORKSPACE not in sys.path:
    sys.path.insert(0, WORKSPACE)
os.chdir(WORKSPACE)

from app import execute_tcs_ast_scan
from rule_engine import GLOBAL_RULE_REGISTRY

print("================================================================================")
print("FOCUSED CWE-78 PARITY TEST SUITE (STRANGLER FIG MIGRATION VERIFICATION)")
print("================================================================================")

EXPECTED_REMEDIATION = (
    "Avoid shell execution with dynamic input. Use subprocess.run() with an argument list "
    "and shell=False, e.g., subprocess.run(['cmd', arg], shell=False)."
)

test_cases = [
    {
        "name": "1. Direct os.system(tainted)",
        "code": """from flask import request
import os
x = request.args.get('cmd')
os.system(x)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-78",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "os.system",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "2. Direct subprocess.run(tainted, shell=True)",
        "code": """from flask import request
import subprocess
x = request.args.get('cmd')
subprocess.run(x, shell=True)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-78",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "subprocess.run",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "3. Direct subprocess.call(tainted, shell=True)",
        "code": """from flask import request
import subprocess
x = request.args.get('cmd')
subprocess.call(x, shell=True)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-78",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "subprocess.call",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "4. Direct subprocess.Popen(tainted, shell=True)",
        "code": """from flask import request
import subprocess
x = request.args.get('cmd')
subprocess.Popen(x, shell=True)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-78",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "subprocess.Popen",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "5. from subprocess import run as sp_run",
        "code": """from flask import request
from subprocess import run as sp_run
x = request.args.get('cmd')
sp_run(x, shell=True)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-78",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "subprocess.run",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "6. import subprocess as sp; sp.Popen",
        "code": """from flask import request
import subprocess as sp
x = request.args.get('cmd')
sp.Popen(x, shell=True)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-78",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "subprocess.Popen",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "7. subprocess.run(tainted, shell=False)",
        "code": """from flask import request
import subprocess
x = request.args.get('cmd')
subprocess.run(x, shell=False)
""",
        "expected_count": 0
    },
    {
        "name": "8. subprocess.run(['echo', tainted])",
        "code": """from flask import request
import subprocess
x = request.args.get('cmd')
subprocess.run(["echo", x])
""",
        "expected_count": 0
    },
    {
        "name": "9. subprocess.run(['echo', tainted], shell=False)",
        "code": """from flask import request
import subprocess
x = request.args.get('cmd')
subprocess.run(["echo", x], shell=False)
""",
        "expected_count": 0
    },
    {
        "name": "10. Constant os.system",
        "code": """import os
os.system("ls -la")
""",
        "expected_count": 0
    },
    {
        "name": "11. Constant subprocess.run",
        "code": """import subprocess
subprocess.run("id", shell=True)
""",
        "expected_count": 0
    },
    {
        "name": "12. Unknown wrapper producing POTENTIAL flow",
        "code": """from flask import request
import os
x = request.args.get('cmd')
y = wrap_unknown(x)
os.system(y)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-78",
        "expected_sev": "HIGH",
        "expected_conf_label": "POTENTIAL",
        "expected_conf_val": 0.5,
        "expected_sink": "os.system",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "13. Deep interprocedural confirmed flow",
        "code": """from flask import request
import subprocess

def fetch_data():
    return request.args.get('cmd')

def build_command(c):
    return "cat " + c

def execute_cmd(command_str):
    subprocess.run(command_str, shell=True)

execute_cmd(build_command(fetch_data()))
""",
        "expected_count": 1,
        "expected_cwe": "CWE-78",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "subprocess.run",
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
            if not f.get("flow_trace") or len(f["flow_trace"]) < 2:
                raise AssertionError(f"Flow trace incomplete: {f.get('flow_trace')}")
                
        print(f"[PASS] {name} -> Finding Count: {len(findings)} | Parity Confirmed")
        total_passed += 1
    except Exception as e:
        print(f"[FAIL] {name}: {e}")
        total_failed += 1

# Case 14 & 15: Exact severity mapping and exact remediation advice in Rule Engine
print("\n--- Testing Case 14 & 15: Exact severity mapping and remediation advice ---")
rule = GLOBAL_RULE_REGISTRY.get_rule("CWE-78")
if rule is None:
    print("[FAIL] Cases 14 & 15: CWE-78 rule not found in GLOBAL_RULE_REGISTRY")
    total_failed += 2
else:
    # 14. Exact severity
    if rule.confirmed_severity != "CRITICAL" or rule.potential_severity != "HIGH":
        print(f"[FAIL] 14. Severity mapping mismatch: confirmed={rule.confirmed_severity}, potential={rule.potential_severity}")
        total_failed += 1
    else:
        print("[PASS] 14. Exact severity mapping -> CONFIRMED=CRITICAL, POTENTIAL=HIGH")
        total_passed += 1
        
    # 15. Exact remediation
    if rule.remediation != EXPECTED_REMEDIATION:
        print(f"[FAIL] 15. Remediation mismatch:\n  Expected: {EXPECTED_REMEDIATION}\n  Got:      {rule.remediation}")
        total_failed += 1
    else:
        print("[PASS] 15. Exact remediation advice byte-for-byte match -> Match Confirmed")
        total_passed += 1

print("\n" + "=" * 80)
print(f"CWE-78 PARITY SUMMARY: {total_passed} PASSED, {total_failed} FAILED (out of 15)")
print("=" * 80)

if total_failed > 0:
    sys.exit(1)
