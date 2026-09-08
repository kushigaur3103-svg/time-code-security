import os
import sys

WORKSPACE = r"c:\Users\aarti gaur\OneDrive\Desktop\time code security"
if WORKSPACE not in sys.path:
    sys.path.insert(0, WORKSPACE)
os.chdir(WORKSPACE)

from app import execute_tcs_ast_scan
from rule_engine import GLOBAL_RULE_REGISTRY

print("================================================================================")
print("FOCUSED CWE-95 PARITY TEST SUITE (STRANGLER FIG MIGRATION VERIFICATION)")
print("================================================================================")

EXPECTED_REMEDIATION = (
    "Avoid passing untrusted input to eval(). Use ast.literal_eval() for parsing Python literals, "
    "or parse structured data using json.loads()."
)

test_cases = [
    {
        "name": "1. Direct eval(tainted)",
        "code": """from flask import request
tainted = request.args.get('code')
eval(tainted)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-95",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "eval",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "2. Direct exec(tainted)",
        "code": """from flask import request
tainted = request.args.get('code')
exec(tainted)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-95",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "exec",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "3. Aliased import (from builtins import eval as my_eval)",
        "code": """from builtins import eval as my_eval
from flask import request
tainted = request.args.get('code')
my_eval(tainted)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-95",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "builtins.eval",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "4. Parameter shadowing: def test(eval): eval(tainted)",
        "code": """from flask import request
tainted = request.args.get('code')
def test(eval):
    eval(tainted)
""",
        "expected_count": 0
    },
    {
        "name": "5. Variable shadowing: eval = fn; eval(tainted)",
        "code": """from flask import request
tainted = request.args.get('code')
def safe_func(arg):
    pass
eval = safe_func
eval(tainted)
""",
        "expected_count": 0
    },
    {
        "name": "6. Function definition shadowing: def eval(): ...; eval()",
        "code": """from flask import request
tainted = request.args.get('code')
def eval(val):
    return val
eval(tainted)
""",
        "expected_count": 0
    },
    {
        "name": "7. compile() data-flow: c = compile(tainted, '', 'eval'); eval(c)",
        "code": """from flask import request
tainted = request.args.get('code')
c = compile(tainted, '', 'eval')
eval(c)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-95",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "eval",
        "expected_source": "request.args.get(...)",
        "check_compile_in_trace": True
    },
    {
        "name": "8. Constant evaluation: eval('1 + 1')",
        "code": """eval('1 + 1')
""",
        "expected_count": 0
    },
    {
        "name": "9. Context sanitizer: eval(safe_eval_input(tainted))",
        "code": """from flask import request
tainted = request.args.get('code')
eval(safe_eval_input(tainted))
""",
        "expected_count": 0
    },
    {
        "name": "10. Irrelevant sanitizer: eval(secure_path_join('/', tainted))",
        "code": """from flask import request
tainted = request.args.get('code')
eval(secure_path_join('/', tainted))
""",
        "expected_count": 1,
        "expected_cwe": "CWE-95",
        "expected_sev": "HIGH",
        "expected_conf_label": "POTENTIAL",
        "expected_conf_val": 0.5,
        "expected_sink": "eval",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "11. Potential taint flow (unknown wrapper)",
        "code": """from flask import request
tainted = request.args.get('code')
y = wrap_unknown(tainted)
eval(y)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-95",
        "expected_sev": "HIGH",
        "expected_conf_label": "POTENTIAL",
        "expected_conf_val": 0.5,
        "expected_sink": "eval",
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
            if tc.get("check_compile_in_trace"):
                trace_str = " -> ".join(f.get("flow_trace", []))
                if "compile" not in trace_str:
                    raise AssertionError(f"'compile' not found in flow trace: {trace_str}")
                
        print(f"[PASS] {name} -> Finding Count: {len(findings)} | Parity Confirmed")
        total_passed += 1
    except Exception as e:
        print(f"[FAIL] {name}: {e}")
        total_failed += 1

# Case 12: Exact remediation advice byte-for-byte match in Rule Engine
print("\n--- Testing Case 12: Exact remediation advice byte-for-byte match ---")
rule = GLOBAL_RULE_REGISTRY.get_rule("CWE-95")
if rule is None:
    print("[FAIL] Case 12: CWE-95 rule not found in GLOBAL_RULE_REGISTRY")
    total_failed += 1
elif rule.remediation != EXPECTED_REMEDIATION:
    print(f"[FAIL] Case 12: Remediation mismatch:\n  Expected: {EXPECTED_REMEDIATION}\n  Got:      {rule.remediation}")
    total_failed += 1
else:
    print("[PASS] 12. Exact remediation advice byte-for-byte match -> Match Confirmed")
    total_passed += 1

print("\n" + "=" * 80)
print(f"CWE-95 PARITY SUMMARY: {total_passed} PASSED, {total_failed} FAILED (out of 12)")
print("=" * 80)

if total_failed > 0:
    sys.exit(1)
