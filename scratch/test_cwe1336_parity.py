import os
import sys

WORKSPACE = r"c:\Users\aarti gaur\OneDrive\Desktop\time code security"
if WORKSPACE not in sys.path:
    sys.path.insert(0, WORKSPACE)
os.chdir(WORKSPACE)

from app import execute_tcs_ast_scan
from rule_engine import GLOBAL_RULE_REGISTRY

print("================================================================================")
print("FOCUSED CWE-1336 PARITY TEST SUITE (STRANGLER FIG MIGRATION VERIFICATION)")
print("================================================================================")

EXPECTED_REMEDIATION = (
    "Avoid passing user input directly into render_template_string(). Use standard "
    "render_template() with parameterized template context variables to enforce auto-escaping."
)

test_cases = [
    {
        "name": "1. Direct render_template_string(tainted)",
        "code": """from flask import request, render_template_string
x = request.args.get('tmpl')
render_template_string(x)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-1336",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "2. Aliased import: from flask import render_template_string as rts",
        "code": """from flask import request
from flask import render_template_string as rts
x = request.args.get('tmpl')
rts(x)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-1336",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "3. Module alias: import flask as fl; fl.render_template_string(tainted)",
        "code": """from flask import request
import flask as fl
x = request.args.get('tmpl')
fl.render_template_string(x)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-1336",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "4. Jinja direct instantiation: Template(tainted).render()",
        "code": """from flask import request
import jinja2
x = request.args.get('tmpl')
t = jinja2.Template(x)
t.render()
""",
        "expected_count": 1,
        "expected_cwe": "CWE-1336",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "5. Jinja environment compilation: Environment().from_string(tainted).render()",
        "code": """from flask import request
import jinja2
x = request.args.get('tmpl')
env = jinja2.Environment()
t = env.from_string(x)
t.render()
""",
        "expected_count": 1,
        "expected_cwe": "CWE-1336",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "6. Safe standard template: render_template('index.html', name=tainted)",
        "code": """from flask import request, render_template
x = request.args.get('name')
render_template('index.html', name=x)
""",
        "expected_count": 0
    },
    {
        "name": "7. Safe random object: Chart().render(tainted)",
        "code": """from flask import request
class Chart:
    def render(self, data):
        return str(data)

x = request.args.get('data')
c = Chart()
c.render(x)
""",
        "expected_count": 0
    },
    {
        "name": "8. Safe random method: SomeClass().render_template_string(tainted)",
        "code": """from flask import request
class SomeClass:
    def render_template_string(self, text):
        return text

x = request.args.get('text')
obj = SomeClass()
obj.render_template_string(x)
""",
        "expected_count": 0
    },
    {
        "name": "9. Constant template string: render_template_string('Hello {{ name }}')",
        "code": """from flask import render_template_string
render_template_string('<h1>Hello {{ name }}</h1>')
""",
        "expected_count": 0
    },
    {
        "name": "10. Unknown wrapper potential flow",
        "code": """from flask import request, render_template_string
x = request.args.get('tmpl')
w = unknown_func(x)
render_template_string(w)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-1336",
        "expected_sev": "HIGH",
        "expected_conf_label": "POTENTIAL",
        "expected_conf_val": 0.5,
        "expected_source": "request.args.get(...)"
    },
    {
        "name": "11. Deep interprocedural flow",
        "code": """from flask import request, render_template_string

def stage_2(tmpl):
    render_template_string(tmpl)

def stage_1(tmpl):
    stage_2(tmpl)

x = request.args.get('tmpl')
stage_1(x)
""",
        "expected_count": 1,
        "expected_cwe": "CWE-1336",
        "expected_sev": "CRITICAL",
        "expected_conf_label": "CONFIRMED",
        "expected_conf_val": 1.0,
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
            raise AssertionError(f"Expected {tc['expected_count']} findings, got {len(findings)} ({[f.get('cwe') for f in findings]})")
        
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
            if f["source_symbol"] != tc["expected_source"]:
                raise AssertionError(f"Source symbol mismatch: expected {tc['expected_source']}, got {f['source_symbol']}")
            if f["remediation"] != EXPECTED_REMEDIATION:
                raise AssertionError(f"Remediation text mismatch:\nExpected: {EXPECTED_REMEDIATION}\nGot: {f['remediation']}")
            if not f.get("flow_trace") or len(f["flow_trace"]) < 2:
                raise AssertionError(f"Flow trace incomplete: {f.get('flow_trace')}")
                
        print(f"[PASS] {name} -> Finding Count: {len(findings)} | Parity Confirmed")
        total_passed += 1
    except Exception as e:
        print(f"[FAIL] {name}: {e}")
        total_failed += 1

# Case 12 & 13: Exact remediation and severity parity checks
print("\n--- Testing Cases 12, 13: Remediation & Severity Parity Checks ---")
rule = GLOBAL_RULE_REGISTRY.get_rule("CWE-1336")
if rule is None:
    print("[FAIL] Cases 12-13: CWE-1336 rule not found in GLOBAL_RULE_REGISTRY")
    total_failed += 2
else:
    # 12. Exact remediation advice byte-for-byte match
    if rule.remediation != EXPECTED_REMEDIATION:
        print(f"[FAIL] 12. Remediation mismatch:\n  Expected: {EXPECTED_REMEDIATION}\n  Got:      {rule.remediation}")
        total_failed += 1
    else:
        print("[PASS] 12. Exact remediation advice byte-for-byte match -> Match Confirmed")
        total_passed += 1

    # 13. Exact severity mapping match
    if rule.confirmed_severity != "CRITICAL" or rule.potential_severity != "HIGH":
        print(f"[FAIL] 13. Severity mapping mismatch: confirmed={rule.confirmed_severity}, potential={rule.potential_severity}")
        total_failed += 1
    else:
        print("[PASS] 13. Exact severity mapping -> CONFIRMED=CRITICAL, POTENTIAL=HIGH")
        total_passed += 1

print("\n" + "=" * 80)
print(f"CWE-1336 PARITY SUMMARY: {total_passed} PASSED, {total_failed} FAILED (out of 13)")
print("=" * 80)

if total_failed > 0:
    sys.exit(1)
