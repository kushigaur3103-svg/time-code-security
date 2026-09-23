import sys
import traceback
from ast_scanner import TaintTracker

class TestCase:
    def __init__(self, name, files, expected_edges, expected_kind=None, expected_conf=None):
        self.name = name
        self.files = {k: v.strip() for k, v in files.items()}
        self.expected_edges = expected_edges
        self.expected_kind = expected_kind
        self.expected_conf = expected_conf

tests = [
    # ---------------------------------------------------------
    # PHASE 6 CROSS-FILE TESTS
    # ---------------------------------------------------------
    TestCase(
        "P6-A direct cross-file parameter propagation",
        {
            "app.py": "from utils import process\nfrom flask import request\nx = request.args.get('x')\neval(process(x))",
            "utils.py": "def process(val): return val"
        },
        expected_edges=1, expected_kind="CONFIRMED_DATA_FLOW", expected_conf=1.00
    ),
    TestCase(
        "P6-B cross-file parameter -> local -> return",
        {
            "app.py": "import utils\nfrom flask import request\nx = request.args.get('x')\neval(utils.process(x))",
            "utils.py": "def process(val):\n    y = val\n    return y"
        },
        expected_edges=1, expected_kind="CONFIRMED_DATA_FLOW", expected_conf=1.00
    ),
    TestCase(
        "P6-C cross-file caller -> callee -> sink",
        {
            "app.py": "from flask import request\nimport utils\nx = request.args.get('expr')\ny = utils.process(x)\neval(y)",
            "utils.py": "def process(val): return val"
        },
        expected_edges=1, expected_kind="CONFIRMED_DATA_FLOW", expected_conf=1.00
    ),
    TestCase(
        "P6-D safe and unsafe call sites across modules",
        {
            "app.py": "from flask import request\nimport utils\neval(utils.process('safe'))\neval(utils.process(request.args.get('x')))",
            "utils.py": "def process(val): return val"
        },
        expected_edges=1, expected_kind="CONFIRMED_DATA_FLOW", expected_conf=1.00
    ),
    TestCase(
        "P6-E multiple modules with module-aware identity",
        {
            "app.py": "from flask import request\nimport a\nimport b\neval(a.process(request.args.get('x')))",
            "a.py": "def process(val): return val",
            "b.py": "def process(val): return 'safe'"
        },
        expected_edges=1, expected_kind="CONFIRMED_DATA_FLOW", expected_conf=1.00
    ),
    TestCase(
        "P6-F cross-file sanitizer",
        {
            "app.py": "from flask import request\nimport utils\neval(utils.clean(request.args.get('x')))",
            "utils.py": "def clean(val): return safe_eval_input(val)"
        },
        expected_edges=0
    ),
    TestCase(
        "P6-G cross-file irrelevant sanitizer",
        {
            "app.py": "from flask import request\nimport utils\neval(utils.bad_clean(request.args.get('x')))",
            "utils.py": "import html\ndef bad_clean(val): return html.escape(val)"
        },
        expected_edges=1, expected_kind="POTENTIAL_DATA_FLOW", expected_conf=0.50
    ),
    TestCase(
        "P6-H unresolved import/function",
        {
            "app.py": "from flask import request\nfrom unknown_lib import missing_func\neval(missing_func(request.args.get('x')))"
        },
        expected_edges=1, expected_kind="POTENTIAL_DATA_FLOW", expected_conf=0.50
    ),
    TestCase(
        "P6-I import alias",
        {
            "app.py": "from flask import request\nimport utils as u\neval(u.process(request.args.get('x')))",
            "utils.py": "def process(val): return val"
        },
        expected_edges=1, expected_kind="CONFIRMED_DATA_FLOW", expected_conf=1.00
    ),
    TestCase(
        "P6-J from-import alias",
        {
            "app.py": "from flask import request\nfrom utils import process as p\neval(p(request.args.get('x')))",
            "utils.py": "def process(val): return val"
        },
        expected_edges=1, expected_kind="CONFIRMED_DATA_FLOW", expected_conf=1.00
    ),
    TestCase(
        "P6-K relative import",
        {
            "pkg/app.py": "from flask import request\nfrom .utils import process\neval(process(request.args.get('x')))",
            "pkg/utils.py": "def process(val): return val"
        },
        expected_edges=1, expected_kind="CONFIRMED_DATA_FLOW", expected_conf=1.00
    ),
    TestCase(
        "P6-L import cycle",
        {
            "a.py": "from flask import request\nimport b\ndef a_func(val): return b.b_func(val)\neval(a_func(request.args.get('x')))",
            "b.py": "import a\ndef b_func(val): return a.a_func(val)"
        },
        expected_edges=1, expected_kind="POTENTIAL_DATA_FLOW", expected_conf=0.50
    ),
    TestCase(
        "P6-M three-module chain",
        {
            "app.py": "from flask import request\nimport utils\nx = request.args.get('x')\neval(utils.process(x))",
            "utils.py": "import helpers\ndef process(val): return helpers.helper(val)",
            "helpers.py": "def helper(val): return val"
        },
        expected_edges=1, expected_kind="CONFIRMED_DATA_FLOW", expected_conf=1.00
    ),
    TestCase(
        "P6-N multiple sources and sinks across files",
        {
            "app.py": "from flask import request\nimport a\nimport b\nx = request.args.get('x')\ny = request.args.get('y')\neval(a.process(x))\neval(b.process(y))",
            "a.py": "def process(val): return val",
            "b.py": "def process(val): return val"
        },
        expected_edges=2, expected_kind="CONFIRMED_DATA_FLOW", expected_conf=1.00
    ),
    TestCase(
        "P6-O negative constant flow",
        {
            "app.py": "import utils\neval(utils.process('safe'))",
            "utils.py": "def process(val): return val"
        },
        expected_edges=0
    ),
    TestCase(
        "P6-P negative unrelated source/sink",
        {
            "app.py": "from flask import request\nx = request.args.get('x')",
            "utils.py": "eval('safe')"
        },
        expected_edges=0
    ),
    TestCase(
        "P6-Q no cross-module variable contamination",
        {
            "app.py": "from flask import request\nimport utils\nx = request.args.get('x')\neval(utils.get_x())",
            "utils.py": "x = 'safe'\ndef get_x(): return x"
        },
        expected_edges=0
    ),

    # ---------------------------------------------------------
    # PHASE 3 REGRESSIONS
    # ---------------------------------------------------------
    TestCase("P3-A Aliasing",
        {"target.py": "from flask import request\nx = request.args.get('x')\ny = x\neval(y)"},
        expected_edges=1, expected_kind="CONFIRMED_DATA_FLOW", expected_conf=1.00),
    TestCase("P3-B Unknown Wrapper",
        {"target.py": "from flask import request\neval(unknown_helper(request.args.get('x')))"},
        expected_edges=1, expected_kind="POTENTIAL_DATA_FLOW", expected_conf=0.50),
    TestCase("P3-C Irrelevant Sanitizer",
        {"target.py": "from flask import request\neval(html.escape(request.args.get('x')))"},
        expected_edges=1, expected_kind="POTENTIAL_DATA_FLOW", expected_conf=0.50),
    TestCase("P3-D Approved Context Sanitizer",
        {"target.py": "from flask import request\neval(safe_eval_input(request.args.get('x')))"},
        expected_edges=0),

    # ---------------------------------------------------------
    # PHASE 4 REGRESSIONS
    # ---------------------------------------------------------
    TestCase("P4-A Scope Isolation",
        {"target.py": "from flask import request\ndef f1(): eval(request.args.get('x'))\ndef f2(): eval('safe')"},
        expected_edges=1, expected_kind="CONFIRMED_DATA_FLOW", expected_conf=1.00),
    TestCase("P4-B Definite Reassignment",
        {"target.py": "from flask import request\nx = request.args.get('x')\nx = 'safe'\neval(x)"},
        expected_edges=0),
    TestCase("P4-C Conditional Tainted Assignment",
        {"target.py": "from flask import request\nx = 'safe_constant'\nif cond:\n    x = request.args.get('expr')\neval(x)"},
        expected_edges=1, expected_kind="POTENTIAL_DATA_FLOW", expected_conf=0.50),

    # ---------------------------------------------------------
    # PHASE 5 REGRESSIONS
    # ---------------------------------------------------------
    TestCase("P5-A Direct param",
        {"target.py": "from flask import request\ndef f(val): return val\neval(f(request.args.get('x')))"},
        expected_edges=1, expected_kind="CONFIRMED_DATA_FLOW", expected_conf=1.00),
    TestCase("P5-B Param -> local -> return",
        {"target.py": "from flask import request\ndef process(val):\n    y = val\n    return y\neval(process(request.args.get('x')))"},
        expected_edges=1, expected_kind="CONFIRMED_DATA_FLOW", expected_conf=1.00),
    TestCase("P5-C Nested function scope",
        {"target.py": "from flask import request\ndef handler():\n    x = request.args.get('a')\n    def process(val): return val\n    z = process(x)\n    return eval(z)"},
        expected_edges=1, expected_kind="CONFIRMED_DATA_FLOW", expected_conf=1.00),
    TestCase("P5-D Recursive call",
        {"target.py": "from flask import request\ndef a_func(val): return b_func(val)\ndef b_func(val): return a_func(val)\neval(a_func(request.args.get('x')))"},
        expected_edges=1, expected_kind="POTENTIAL_DATA_FLOW", expected_conf=0.50),
]

passed = 0
failed = 0
skipped = 0
failed_details = []

for idx, t in enumerate(tests):
    try:
        tracker = TaintTracker(files=t.files)
        _, sinks, edges = tracker.analyze()
        
        sink_edges = [e for e in edges if e.target_id.startswith("SNK")]
        
        if len(sink_edges) != t.expected_edges:
            raise AssertionError(f"Expected {t.expected_edges} edges, got {len(sink_edges)}")
        
        if t.expected_edges > 0:
            for edge in sink_edges:
                if t.expected_kind and edge.kind != t.expected_kind:
                    raise AssertionError(f"Expected kind {t.expected_kind}, got {edge.kind}")
                if t.expected_conf is not None and edge.confidence != t.expected_conf:
                    raise AssertionError(f"Expected conf {t.expected_conf}, got {edge.confidence}")
                if not edge.transform or edge.transform == "none":
                    raise AssertionError(f"Missing valid path transformation evidence")
                if t.name == "P6-M three-module chain":
                    if "app.py" not in edge.transform or "utils.py" not in edge.transform or "helpers.py" not in edge.transform:
                        raise AssertionError(f"Missing full module path evidence in {edge.transform}")

        print(f"[PASS] {t.name}")
        passed += 1
    except AssertionError as e:
        print(f"[FAIL] {t.name}")
        failed += 1
        failed_details.append({"name": t.name, "expected": f"Edges={t.expected_edges}, Kind={t.expected_kind}, Conf={t.expected_conf}", "actual": str(e), "reason": "Assertion Mismatch"})
    except Exception as e:
        print(f"[FAIL] {t.name}")
        failed += 1
        failed_details.append({"name": t.name, "expected": "Success execution", "actual": traceback.format_exc(), "reason": "Crash"})

print("\n" + "="*50)
print("PHASE 6 VERIFICATION")
print("="*50)
print(f"Passed: {passed}")
print(f"Failed: {failed}")
print(f"Skipped: {skipped}")
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