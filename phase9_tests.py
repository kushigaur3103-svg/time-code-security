import sys
import subprocess
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
    # P9: COMMAND INJECTION
    # ---------------------------------------------------------
    TestCase("P9-CI-1 direct taint", 
        {"app.py": "from flask import request\nx = request.args.get('x')\nos.system(x)"}, 1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-CI-2 alias", 
        {"app.py": "from flask import request\nx = request.args.get('x')\ny=x\nsubprocess.call(y)"}, 1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-CI-3 unknown wrapper", 
        {"app.py": "from flask import request\nx = request.args.get('x')\ny=wrap(x)\nos.system(y)"}, 1, "POTENTIAL_DATA_FLOW", 0.5),
    TestCase("P9-CI-4 shell=True", 
        {"app.py": "from flask import request\nimport subprocess\nx = request.args.get('x')\nsubprocess.run(x, shell=True)"}, 1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-CI-5 shell=False safe", 
        {"app.py": "from flask import request\nimport subprocess\nx = request.args.get('x')\nsubprocess.run(['ls', x], shell=False)"}, 0),
    TestCase("P9-CI-6 constant safe command", 
        {"app.py": "os.system('ls -la')"}, 0),
    TestCase("P9-CI-7 cross-file", 
        {"app.py": "import u\nimport os\nfrom flask import request\nx=request.args.get('x')\nos.system(u.run_cmd(x))", "u.py": "def run_cmd(v): return v"}, 1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-CI-8 multiple sources/sinks", 
        {"app.py": "from flask import request\nx=request.args.get('x')\ny=request.args.get('y')\nos.system(x)\neval(y)"}, 2, "CONFIRMED_DATA_FLOW", 1.0),

    # ---------------------------------------------------------
    # P9: SQL INJECTION
    # ---------------------------------------------------------
    TestCase("P9-SQL-1 direct", 
        {"app.py": "from flask import request\nx = request.args.get('x')\ndb.execute(x)"}, 1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-SQL-2 string formatting", 
        {"app.py": "from flask import request\nx = request.args.get('x')\nq = 'SELECT ' + x\ndb.execute(q)"}, 1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-SQL-3 parameterized safe query", 
        {"app.py": "from flask import request\nx = request.args.get('x')\ndb.execute('SELECT * FROM u WHERE id=?', x)"}, 0),
    TestCase("P9-SQL-4 alias", 
        {"app.py": "from flask import request\nx = request.args.get('x')\ny=x\ncursor.execute(y)"}, 1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-SQL-5 cross-file", 
        {"app.py": "import u\nfrom flask import request\nx=request.args.get('x')\ndb.execute(u.run_sql(x))", "u.py": "def run_sql(v): return v"}, 1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-SQL-6 unknown wrapper", 
        {"app.py": "from flask import request\nx = request.args.get('x')\ny=wrap(x)\ncursor.execute(y)"}, 1, "POTENTIAL_DATA_FLOW", 0.5),
    TestCase("P9-SQL-7 safe constant", 
        {"app.py": "cursor.execute('SELECT * FROM users')"}, 0),

    # ---------------------------------------------------------
    # P9: PATH TRAVERSAL
    # ---------------------------------------------------------
    TestCase("P9-PT-1 direct user path", 
        {"app.py": "from flask import request\nx = request.args.get('x')\nopen(x)"}, 1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-PT-2 alias", 
        {"app.py": "from flask import request\nx = request.args.get('x')\ny=x\nopen(y)"}, 1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-PT-3 cross-file", 
        {"app.py": "import u\nfrom flask import request\nx=request.args.get('x')\nopen(u.read_file(x))", "u.py": "def read_file(v): return v"}, 1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-PT-4 safe constant", 
        {"app.py": "open('config.json')"}, 0),
    TestCase("P9-PT-5 proven safe containment", 
        {"app.py": "from flask import request\nx = request.args.get('x')\ny=secure_path_join('/var/www', x)\nopen(y)"}, 0),
    TestCase("P9-PT-6 unknown helper", 
        {"app.py": "from flask import request\nx = request.args.get('x')\ny=wrap(x)\nopen(y)"}, 1, "POTENTIAL_DATA_FLOW", 0.5),

    # ---------------------------------------------------------
    # P9: UNSAFE DESERIALIZATION
    # ---------------------------------------------------------
    TestCase("P9-UD-1 pickle.loads user input", 
        {"app.py": "from flask import request\nimport pickle\nx = request.args.get('x')\npickle.loads(x)"}, 1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-UD-2 alias", 
        {"app.py": "from flask import request\nimport pickle\nx = request.args.get('x')\ny=x\npickle.loads(y)"}, 1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-UD-3 cross-file", 
        {"app.py": "import u\nimport pickle\nfrom flask import request\nx=request.args.get('x')\npickle.loads(u.load_data(x))", "u.py": "def load_data(v): return v"}, 1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-UD-4 json.loads safe", 
        {"app.py": "from flask import request\nimport json\nx = request.args.get('x')\njson.loads(x)"}, 0),
    TestCase("P9-UD-5 constant input", 
        {"app.py": "import pickle\npickle.loads(b'safe')"}, 0),

    # ---------------------------------------------------------
    # P9: SSTI
    # ---------------------------------------------------------
    TestCase("P9-SSTI-1 supported dangerous pattern", 
        {"app.py": "from flask import request, render_template_string\nx = request.args.get('x')\nrender_template_string(x)"}, 1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-SSTI-2 safe template pattern", 
        {"app.py": "from flask import render_template_string\nrender_template_string('<h1>Hello</h1>')"}, 0),
    TestCase("P9-SSTI-3 unknown wrapper", 
        {"app.py": "from flask import request, render_template_string\nx = request.args.get('x')\ny=wrap(x)\nrender_template_string(y)"}, 1, "POTENTIAL_DATA_FLOW", 0.5),
    TestCase("P9-SSTI-4 cross-file", 
        {"app.py": "import u\nfrom flask import request, render_template_string\nx=request.args.get('x')\nrender_template_string(u.render(x))", "u.py": "def render(v): return v"}, 1, "CONFIRMED_DATA_FLOW", 1.0),

    # ---------------------------------------------------------
    # P9-FIX: MANDATORY FOCUSED FLOW TESTS
    # ---------------------------------------------------------
    TestCase("P9-FIX-01 direct CWE-502",
        {"app.py": "from flask import request\nimport pickle\ndata = request.args.get('data')\npickle.loads(data)"},
        1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-FIX-02 pickle import alias",
        {"app.py": "from flask import request\nimport pickle as pk\ndata = request.args.get('data')\npk.loads(data)"},
        1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-FIX-03 pickle module alias",
        {"app.py": "from flask import request\nimport pickle\nserializer = pickle\ndata = request.args.get('data')\nserializer.loads(data)"},
        1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-FIX-04 function argument -> parameter -> sink",
        {"app.py": "from flask import request\nimport pickle\ndef dangerous(value):\n    pickle.loads(value)\ndata = request.args.get('data')\ndangerous(data)"},
        1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-FIX-05 function return -> caller -> sink",
        {"app.py": "from flask import request\nimport pickle\ndef get_data():\n    return request.args.get('data')\ndata = get_data()\npickle.loads(data)"},
        1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-FIX-06 nested function flow",
        {"app.py": "from flask import request\nimport pickle\ndef outer():\n    def inner(val):\n        pickle.loads(val)\n    d = request.args.get('d')\n    inner(d)\nouter()"},
        1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-FIX-07 deep alias",
        {"app.py": "from flask import request\nimport pickle\na = request.args.get('d')\nb = a\nc = b\nd = c\ne = d\npickle.loads(e)"},
        1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-FIX-08 unknown wrapper conservative",
        {"app.py": "from flask import request\nimport pickle\nd = request.args.get('d')\nw = unknown_func(d)\npickle.loads(w)"},
        1, "POTENTIAL_DATA_FLOW", 0.5),
    TestCase("P9-FIX-09 reassignment removes taint",
        {"app.py": "from flask import request\nimport pickle\nd = request.args.get('d')\nd = b'safe_constant'\npickle.loads(d)"},
        0),
    TestCase("P9-FIX-10 constant pickle safe-negative",
        {"app.py": "import pickle\npickle.loads(b'constant_payload')"},
        0),
    TestCase("P9-FIX-11 cross-file CWE-502",
        {
            "routes.py": "from flask import request\nimport handler\nd = request.args.get('d')\nhandler.process(d)",
            "handler.py": "import pickle\ndef process(data):\n    pickle.loads(data)"
        },
        1, "CONFIRMED_DATA_FLOW", 1.0),
    TestCase("P9-FIX-12 realistic mixed application",
        {"app.py": """from flask import Flask, request, render_template_string
import os
import sqlite3
import pickle
import subprocess

app = Flask(__name__)

def get_user():
    return request.args.get("user")

def get_payload():
    return request.args.get("payload")

def build_query(user_id):
    return f"SELECT * FROM users WHERE id = {user_id}"

def execute_query(db, query):
    return db.execute(query)

def load_data(data):
    return pickle.loads(data)

def render_page(template):
    return render_template_string(template)

def execute_command(command):
    return os.system(command)

@app.route("/test")
def test():
    user = get_user()
    payload = get_payload()

    eval(user)

    execute_command(user)

    subprocess.run(user, shell=True)

    db = sqlite3.connect("app.db")
    query = build_query(user)
    execute_query(db, query)

    load_data(payload)

    render_page(payload)
"""},
        6, "CONFIRMED_DATA_FLOW", 1.0)
]

def run_tests():
    passed = 0
    failed = 0
    skipped = 0
    failed_details = []

    print("==================================================")
    print("PHASE 9: VULNERABILITY COVERAGE EXPANSION")
    print("==================================================")

    for idx, t in enumerate(tests):
        try:
            tracker = TaintTracker(files=t.files)
            _, sinks, edges = tracker.analyze()
            sink_edges = [e for e in edges if e.target_id.startswith("SNK")]
            
            if len(sink_edges) != t.expected_edges:
                raise AssertionError(f"Expected {t.expected_edges} edges, got {len(sink_edges)}")
            
            if t.expected_edges > 0:
                best_edge = max(sink_edges, key=lambda e: e.confidence)
                if best_edge.kind != t.expected_kind:
                    raise AssertionError(f"Expected kind {t.expected_kind}, got {best_edge.kind}")
                if best_edge.confidence != t.expected_conf:
                    raise AssertionError(f"Expected conf {t.expected_conf}, got {best_edge.confidence}")
            
            print(f"[PASS] {t.name}")
            passed += 1
        except Exception as e:
            print(f"[FAIL] {t.name}")
            failed += 1
            failed_details.append(f"{t.name}: {e}")

    # Run regressions
    print("\nExecuting Phase 8 Regression Suite...")
    p8_res = subprocess.run(["python", "phase8_tests.py"], capture_output=True, text=True)
    p8_passed = "VERDICT: PASS" in p8_res.stdout
    if p8_passed:
        print("[PASS] Phase 3-8 Regression Suite")
    else:
        print("[FAIL] Phase 3-8 Regression Suite Failed!")
        failed += 1
        failed_details.append("Regression Suite Failed.")

    print("\n==================================================")
    print(f"Passed: {passed + (1 if p8_passed else 0)}")
    print(f"Failed: {failed}")
    print(f"Skipped: {skipped}")
    if failed == 0:
        print("VERDICT: PASS")
    else:
        print("VERDICT: FAIL")
        for f in failed_details:
            print(f"  -> {f}")

if __name__ == "__main__":
    run_tests()