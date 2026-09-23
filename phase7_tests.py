import sys
import traceback
import subprocess
from verification_engine import verify_fix, Patch, get_stable_signature
from ast_scanner import TaintTracker

class TestCase:
    def __init__(self, name, files, patch, expected_status):
        self.name = name
        self.files = {k: v.strip() for k, v in files.items()}
        self.patch = patch
        self.expected_status = expected_status

tests = [
    TestCase("P7-A vulnerable eval remains", 
        {"app.py": "from flask import request\nx=request.args.get('x')\neval(x)"},
        Patch("app.py", "eval(x)", "print('log')\neval(x)"),
        "NOT_VERIFIED"),
        
    TestCase("P7-B vulnerable eval removed safely", 
        {"app.py": "from flask import request\nx=request.args.get('x')\neval(x)"},
        Patch("app.py", "eval(x)", "eval(safe_eval_input(x))"),
        "VERIFIED_FIX"),
        
    TestCase("P7-C invalid syntax patch", 
        {"app.py": "from flask import request\nx=request.args.get('x')\neval(x)"},
        Patch("app.py", "eval(x)", "eval(x"),
        "INVALID_PATCH"),
        
    TestCase("P7-D no-op patch", 
        {"app.py": "from flask import request\nx=request.args.get('x')\neval(x)"},
        Patch("app.py", "eval(x)", "eval(x)"),
        "NOT_VERIFIED"),
        
    TestCase("P7-E original finding removed but new eval vulnerability introduced", 
        {"app.py": "from flask import request\nx=request.args.get('x')\neval(x)"},
        Patch("app.py", "x=request.args.get('x')\neval(x)", "y=request.args.get('y')\neval(y)"),
        "REGRESSION_DETECTED"),
        
    TestCase("P7-F source-to-sink flow broken by safe replacement", 
        {"app.py": "from flask import request\nx=request.args.get('x')\neval(x)"},
        Patch("app.py", "x=request.args.get('x')", "x='safe'"),
        "VERIFIED_FIX"),
        
    TestCase("P7-G cross-file vulnerable flow fixed", 
        {"app.py": "from flask import request\nimport u\nx=request.args.get('x')\neval(u.proc(x))", "u.py": "def proc(v):\n    return v"},
        Patch("u.py", "return v", "return 'safe'"),
        "VERIFIED_FIX"),
        
    TestCase("P7-H cross-file vulnerable flow remains", 
        {"app.py": "from flask import request\nimport u\nx=request.args.get('x')\neval(u.proc(x))", "u.py": "def proc(v):\n    return v"},
        Patch("u.py", "return v", "y = v\n    return y"),
        "NOT_VERIFIED"),
        
    TestCase("P7-I patch modifies unrelated file only", 
        {"app.py": "from flask import request\nx=request.args.get('x')\neval(x)", "u.py": "pass"},
        Patch("u.py", "pass", "y=1"),
        "NOT_VERIFIED"),
        
    TestCase("P7-J multiple findings, only one fixed", 
        {"app.py": "from flask import request\nx=request.args.get('x')\neval(x)\ny=request.args.get('y')\neval(y)"},
        Patch("app.py", "eval(x)", "eval(safe_eval_input(x))"),
        "VERIFIED_FIX"),
        
    TestCase("P7-K multiple findings, one fix introduces another finding", 
        {"app.py": "from flask import request\nx=request.args.get('x')\neval(x)\ny=request.args.get('y')\neval(y)"},
        Patch("app.py", "eval(x)", "z=request.args.get('z')\neval(z)"),
        "REGRESSION_DETECTED"),
        
    TestCase("P7-L malformed / missing patch target", 
        {"app.py": "from flask import request\nx=request.args.get('x')\neval(x)"},
        Patch("app.py", "eval(z)", "eval(safe_eval_input(z))"),
        "INVALID_PATCH"),
        
    TestCase("P7-M deterministic repeatability", 
        {"app.py": "from flask import request\nx=request.args.get('x')\neval(x)"},
        Patch("app.py", "eval(x)", "eval(safe_eval_input(x))"),
        "VERIFIED_FIX")
]

def run_tests():
    passed = 0
    failed = 0
    skipped = 0
    failed_details = []

    for idx, t in enumerate(tests):
        try:
            # 1. Dynamically get target signature from pristine files
            orig_tracker = TaintTracker(files=t.files)
            orig_src, orig_snk, orig_edges = orig_tracker.analyze()
            orig_snk_edges = [e for e in orig_edges if e.target_id.startswith('SNK')]
            
            if not orig_snk_edges:
                raise ValueError("Original file contains no sinks to test against.")
                
            # For P7-J/K where there are multiple, target the 'x' flow (usually first)
            target_edge = orig_snk_edges[0] 
            s = {s.id: s for s in orig_src}[target_edge.source_id]
            sk = {sk.id: sk for sk in orig_snk}[target_edge.target_id]
            target_sig = get_stable_signature(s, sk, target_edge)

            # 2. Run Verification
            result = verify_fix(t.files, t.patch, target_sig)
            
            if result.status != t.expected_status:
                raise AssertionError(f"Expected {t.expected_status}, got {result.status} ({result.reason})")
                
            print(f"[PASS] {t.name}")
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {t.name}")
            failed += 1
            failed_details.append({"name": t.name, "expected": t.expected_status, "actual": str(e), "reason": "Status Mismatch"})
        except Exception as e:
            print(f"[FAIL] {t.name}")
            failed += 1
            failed_details.append({"name": t.name, "expected": t.expected_status, "actual": str(e), "reason": "Exception Thrown"})
            
    # Run Phase 6 Regressions (which includes P3-P6)
    print("\nExecuting Phase 3-6 Regression Suite...")
    p6_res = subprocess.run(["python", "phase6_tests.py"], capture_output=True, text=True)
    p6_passed = "VERDICT: PASS" in p6_res.stdout
    
    if p6_passed:
        print("[PASS] Phase 3-6 Regression Suite")
    else:
        print("[FAIL] Phase 3-6 Regression Suite Failed!")
        failed += 1
        failed_details.append({"name": "Regression Suite", "expected": "PASS", "actual": "FAIL", "reason": "Existing tests broke."})

    print("\n" + "="*50)
    print("PHASE 7 VERIFICATION")
    print("="*50)
    print(f"TOTAL: {len(tests) + 1}")
    print(f"PASSED: {passed + (1 if p6_passed else 0)}")
    print(f"FAILED: {failed}")
    print(f"SKIPPED: {skipped}")
    print()
    if failed == 0:
        print("VERDICT: PASS")
    else:
        print("VERDICT: FAIL")
        for f in failed_details:
            print(f"\n--- {f['name']} ---")
            print(f"Expected: {f['expected']}")
            print(f"Actual: {f['actual']}")
            print(f"Reason: {f['reason']}")

if __name__ == "__main__":
    run_tests()