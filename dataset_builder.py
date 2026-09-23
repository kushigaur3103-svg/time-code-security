import json

manifest = []


def add_sample(sid, cat, files, exp_kind, exp_conf, exp_src=None, exp_snk=None, exp_path=None):
    manifest.append({
        "sample_id": sid,
        "category": cat,
        "files": files,
        "expected_kind": exp_kind,
        "expected_confidence": exp_conf,
        "expected_source": exp_src,
        "expected_sink": exp_snk,
        "expected_path": exp_path
    })


# 1. Structurally varying Alias Depths (100 TP)
for i in range(1, 101):
    lines = ["from flask import request", "v0 = request.args.get('x')"]
    path_nodes = ["SRC", "app.py:v0"]
    for j in range(1, i + 1):
        lines.append(f"v{j} = v{j-1}")
        path_nodes.append(f"app.py:v{j}")
    lines.append(f"eval(v{i})")
    add_sample(
        sid=f"TP_ALIAS_{i}",
        cat="Alias",
        files={"app.py": "\n".join(lines)},
        exp_kind="CONFIRMED_DATA_FLOW",
        exp_conf=1.0,
        exp_src="request.args.get",
        exp_snk="eval",
        exp_path=" -> ".join(path_nodes)
    )

# 2. Safe Overwrites / Negative Controls (100 TN)
for i in range(1, 101):
    mid = max(1, i // 2)
    lines = ["from flask import request", "v0 = request.args.get('x')"]
    for j in range(1, mid + 1):
        lines.append(f"v{j} = v{j-1}")
    lines.append(f"v{mid} = 'safe'")
    for j in range(mid + 1, i + 1):
        lines.append(f"v{j} = v{j-1}")
    lines.append(f"eval(v{i})")
    add_sample(
        sid=f"TN_OVERWRITE_{i}",
        cat="Overwrite",
        files={"app.py": "\n".join(lines)},
        exp_kind="NO DATA FLOW",
        exp_conf=None,
        exp_src=None,
        exp_snk=None,
        exp_path=None
    )

# 3. Cross-File Module Propagation (50 TP + 50 TN)
for i in range(1, 51):
    add_sample(
        sid=f"TP_CROSS_{i}",
        cat="CrossFile",
        files={
            "app.py": "import u\nfrom flask import request\nx = request.args.get('x')\neval(u.p(x))",
            "u.py": "def p(v): return v"
        },
        exp_kind="CONFIRMED_DATA_FLOW",
        exp_conf=1.0,
        exp_src="request.args.get",
        exp_snk="eval",
        exp_path="SRC -> app.py:x -> u.py:v -> return:u.py:1 -> return_from:u.py:p"
    )

for i in range(1, 51):
    add_sample(
        sid=f"TN_CROSS_{i}",
        cat="CrossFile",
        files={
            "app.py": "import u\nfrom flask import request\nx=request.args.get('x')\neval(u.p(x))",
            "u.py": "def p(v): return 'safe'"
        },
        exp_kind="NO DATA FLOW",
        exp_conf=None,
        exp_src=None,
        exp_snk=None,
        exp_path=None
    )

# 4. Unknown / Ambiguous Transformations (50 POT)
for i in range(1, 51):
    add_sample(
        sid=f"POT_UNK_{i}",
        cat="Unknown",
        files={
            "app.py": "from flask import request\nx=request.args.get('x')\ny=unknown_wrapper(x)\neval(y)"
        },
        exp_kind="POTENTIAL_DATA_FLOW",
        exp_conf=0.5,
        exp_src="request.args.get",
        exp_snk="eval",
        exp_path="SRC -> app.py:x -> app.py:unknown_wrapper() -> app.py:y"
    )

# 5. Sanitizer Valid Negative Controls (25 TN)
for i in range(1, 26):
    add_sample(
        sid=f"TN_SAN_{i}",
        cat="Sanitizer_Valid",
        files={
            "app.py": "from flask import request\nx=request.args.get('x')\ny=safe_eval_input(x)\neval(y)"
        },
        exp_kind="NO DATA FLOW",
        exp_conf=None,
        exp_src=None,
        exp_snk=None,
        exp_path=None
    )

# 6. Sanitizer Irrelevant Potential Flow (25 POT)
for i in range(1, 26):
    add_sample(
        sid=f"POT_SAN_{i}",
        cat="Sanitizer_Irrelevant",
        files={
            "app.py": "from flask import request\nimport html\nx=request.args.get('x')\ny=html.escape(x)\neval(y)"
        },
        exp_kind="POTENTIAL_DATA_FLOW",
        exp_conf=0.5,
        exp_src="request.args.get",
        exp_snk="eval",
        exp_path="SRC -> app.py:x -> app.py:html.escape() -> app.py:y"
    )

# 7. Framework Sources & Modern Patterns

# 7a. FastAPI Query(...)
add_sample(
    sid="TP_FASTAPI_QUERY",
    cat="Framework_FastAPI",
    files={"app.py": "from fastapi import Query\nq = Query(...)\neval(q)"},
    exp_kind="CONFIRMED_DATA_FLOW",
    exp_conf=1.0,
    exp_src="fastapi.Query",
    exp_snk="eval",
    exp_path="SRC -> app.py:q"
)

add_sample(
    sid="TN_FASTAPI_QUERY",
    cat="Framework_FastAPI",
    files={"app.py": "from fastapi import Query\nq = Query(...)\nq = 'safe'\neval(q)"},
    exp_kind="NO DATA FLOW",
    exp_conf=None,
    exp_src=None,
    exp_snk=None,
    exp_path=None
)

# 7b. FastAPI Header(...)
add_sample(
    sid="TP_FASTAPI_HEADER",
    cat="Framework_FastAPI",
    files={"app.py": "from fastapi import Header\nh = Header(...)\neval(h)"},
    exp_kind="CONFIRMED_DATA_FLOW",
    exp_conf=1.0,
    exp_src="fastapi.Header",
    exp_snk="eval",
    exp_path="SRC -> app.py:h"
)

add_sample(
    sid="TN_FASTAPI_HEADER",
    cat="Framework_FastAPI",
    files={"app.py": "from fastapi import Header\nh = Header(...)\nh = 'safe'\neval(h)"},
    exp_kind="NO DATA FLOW",
    exp_conf=None,
    exp_src=None,
    exp_snk=None,
    exp_path=None
)

# 7c. Django request.META
add_sample(
    sid="TP_DJANGO_META",
    cat="Framework_Django",
    files={"app.py": "def view(request):\n    meta = request.META\n    eval(meta)"},
    exp_kind="CONFIRMED_DATA_FLOW",
    exp_conf=1.0,
    exp_src="request.META",
    exp_snk="eval",
    exp_path="SRC -> app.py:meta"
)

add_sample(
    sid="TP_DJANGO_META_GET",
    cat="Framework_Django",
    files={"app.py": "def view(request):\n    meta = request.META.get('HTTP_USER_AGENT')\n    eval(meta)"},
    exp_kind="CONFIRMED_DATA_FLOW",
    exp_conf=1.0,
    exp_src="request.META",
    exp_snk="eval",
    exp_path="SRC -> app.py:get() -> app.py:meta"
)

add_sample(
    sid="TN_DJANGO_META",
    cat="Framework_Django",
    files={"app.py": "def view(request):\n    meta = request.META\n    meta = 'safe'\n    eval(meta)"},
    exp_kind="NO DATA FLOW",
    exp_conf=None,
    exp_src=None,
    exp_snk=None,
    exp_path=None
)

# 7d. Django request.FILES
add_sample(
    sid="TP_DJANGO_FILES",
    cat="Framework_Django",
    files={"app.py": "def view(request):\n    f = request.FILES\n    eval(f)"},
    exp_kind="CONFIRMED_DATA_FLOW",
    exp_conf=1.0,
    exp_src="request.FILES",
    exp_snk="eval",
    exp_path="SRC -> app.py:f"
)

add_sample(
    sid="TP_DJANGO_FILES_GET",
    cat="Framework_Django",
    files={"app.py": "def view(request):\n    f = request.FILES.get('upload')\n    eval(f)"},
    exp_kind="CONFIRMED_DATA_FLOW",
    exp_conf=1.0,
    exp_src="request.FILES",
    exp_snk="eval",
    exp_path="SRC -> app.py:get() -> app.py:f"
)

add_sample(
    sid="TN_DJANGO_FILES",
    cat="Framework_Django",
    files={"app.py": "def view(request):\n    f = request.FILES\n    f = 'safe'\n    eval(f)"},
    exp_kind="NO DATA FLOW",
    exp_conf=None,
    exp_src=None,
    exp_snk=None,
    exp_path=None
)

# 7e. List concatenation taint (base + [tainted])
add_sample(
    sid="TP_LIST_CONCAT",
    cat="List_Concat",
    files={"app.py": "from flask import request\nbase = ['safe']\ntainted = request.args.get('x')\ncombined = base + [tainted]\neval(combined)"},
    exp_kind="CONFIRMED_DATA_FLOW",
    exp_conf=1.0,
    exp_src="request.args.get",
    exp_snk="eval",
    exp_path="app.py:base -> SRC -> app.py:tainted -> app.py:collection -> binary_op -> app.py:combined"
)

add_sample(
    sid="TP_LIST_CONCAT_SUB",
    cat="List_Concat",
    files={"app.py": "from flask import request\nbase = ['safe']\ntainted = request.args.get('x')\ncombined = base + [tainted]\neval(combined[1])"},
    exp_kind="CONFIRMED_DATA_FLOW",
    exp_conf=1.0,
    exp_src="request.args.get",
    exp_snk="eval",
    exp_path="app.py:base -> SRC -> app.py:tainted -> app.py:collection -> binary_op -> app.py:combined -> app.py:subscript"
)

add_sample(
    sid="TN_LIST_CONCAT",
    cat="List_Concat",
    files={"app.py": "from flask import request\nbase = ['safe']\ntainted = request.args.get('x')\ncombined = base + ['safe2']\neval(combined)"},
    exp_kind="NO DATA FLOW",
    exp_conf=None,
    exp_src=None,
    exp_snk=None,
    exp_path=None
)

# Persistence: dump generated dataset to benchmark_manifest.json
with open("benchmark_manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)

print(f"Generated {len(manifest)} benchmark samples in benchmark_manifest.json")
