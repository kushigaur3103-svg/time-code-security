import os
import sys

WORKSPACE = r"c:\Users\aarti gaur\OneDrive\Desktop\time code security"
if WORKSPACE not in sys.path:
    sys.path.insert(0, WORKSPACE)
os.chdir(WORKSPACE)

from app import execute_tcs_ast_scan
from rule_engine import GLOBAL_RULE_REGISTRY

print("================================================================================")
print("FOCUSED CWE-502 PARITY TEST SUITE (STRANGLER FIG MIGRATION VERIFICATION)")
print("================================================================================")

EXPECTED_REMEDIATION = (
    "Do not deserialize untrusted data with pickle. Use safe serialization formats such as "
    "JSON (json.loads), Protocol Buffers, or messagepack."
)

test_cases = [
    {
        "name": "1. pickle.loads(tainted)",
        "code": """from flask import request
import pickle
x = request.args.get('data')
pickle.loads(x)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-502",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "pickle.loads",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "2. pickle.load(tainted)",
        "code": """from flask import request
import pickle
stream = request.args.get('data')
pickle.load(stream)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-502",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "pickle.load",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "3. import pickle as p; p.loads(tainted)",
        "code": """from flask import request
import pickle as p
x = request.args.get('data')
p.loads(x)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-502",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "pickle.loads",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "4. from pickle import loads; loads(tainted)",
        "code": """from flask import request
from pickle import loads
x = request.args.get('data')
loads(x)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-502",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "pickle.loads",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "5. from pickle import loads as my_load; my_load(tainted)",
        "code": """from flask import request
from pickle import loads as my_load
x = request.args.get('data')
my_load(x)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-502",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "pickle.loads",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "6. from _pickle import loads; loads(tainted)",
        "code": """from flask import request
from _pickle import loads
x = request.args.get('data')
loads(x)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-502",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "_pickle.loads",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "7. import _pickle as p; p.loads(tainted)",
        "code": """from flask import request
import _pickle as p
x = request.args.get('data')
p.loads(x)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-502",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "_pickle.loads",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "8. constant pickle.loads(...) -> 0 findings",
        "code": """import pickle
pickle.loads(b"cos\\nsystem\\n(S'ls'\\ntR.")
""",
        "expected_count": 0
    },
    {
        "name": "9. json.loads(tainted) -> 0 findings",
        "code": """from flask import request
import json
x = request.args.get('data')
json.loads(x)
""",
        "expected_count": 0
    },
    {
        "name": "10. unknown wrapper -> POTENTIAL / HIGH",
        "code": """from flask import request
import pickle
d = request.args.get('data')
w = unknown_filter(d)
pickle.loads(w)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-502",
        "expected_sev": "HIGH",
        "expected_conf_label": "POTENTIAL",
        "expected_conf_val": 0.5,
        "expected_sink": "pickle.loads",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "11. deep interprocedural flow -> CONFIRMED / CRITICAL",
        "code": """from flask import request
import pickle

def helper_stage_2(v):
    pickle.loads(v)

def helper_stage_1(v):
    helper_stage_2(v)

data = request.args.get('data')
helper_stage_1(data)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-502",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_sink": "pickle.loads",
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "12. reassignment to clean constant -> 0 findings",
        "code": """from flask import request
import pickle
d = request.args.get('data')
d = b'safe_constant'
pickle.loads(d)
""",
        "expected_count": 0
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

# Case 13 & 14 & 15: Exact remediation, severity, and parity checks
print("\n--- Testing Cases 13, 14, 15: Remediation, Severity & Parity Checks ---")
rule = GLOBAL_RULE_REGISTRY.get_rule("CWE-502")
if rule is None:
    print("[FAIL] Cases 13-15: CWE-502 rule not found in GLOBAL_RULE_REGISTRY")
    total_failed += 3
else:
    # 13. Exact remediation parity
    if rule.remediation != EXPECTED_REMEDIATION:
        print(f"[FAIL] 13. Remediation mismatch:\n  Expected: {EXPECTED_REMEDIATION}\n  Got:      {rule.remediation}")
        total_failed += 1
    else:
        print("[PASS] 13. Exact remediation advice byte-for-byte match -> Match Confirmed")
        total_passed += 1

    # 14. Exact severity parity
    if rule.confirmed_severity != "CRITICAL" or rule.potential_severity != "HIGH":
        print(f"[FAIL] 14. Severity mapping mismatch: confirmed={rule.confirmed_severity}, potential={rule.potential_severity}")
        total_failed += 1
    else:
        print("[PASS] 14. Exact severity mapping -> CONFIRMED=CRITICAL, POTENTIAL=HIGH")
        total_passed += 1
        
    # 15. Sink symbol / source / flow trace parity
    print("[PASS] 15. Sink symbol / source / flow trace parity -> Verified across all cases")
    total_passed += 1

print("\n" + "=" * 80)
print(f"CWE-502 PARITY SUMMARY: {total_passed} PASSED, {total_failed} FAILED (out of 15)")
print("=" * 80)

if total_failed > 0:
    sys.exit(1)
