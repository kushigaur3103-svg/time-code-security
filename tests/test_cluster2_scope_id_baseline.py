"""The scope each cluster2 sink is recorded under, pinned against the unmodified engine.

cluster2 resolves a sink's scope by climbing `node.parent` until it reaches a function registered
in `function_scopes` (`_scope_for`, ast_scanner.py:12549), and it climbs that chain once per node in
each of three full passes over the module, plus again inside `_add`. That is the work a memoisation
would remove, and `SinkRecord.scope_id` is the value it must reproduce exactly.

Nothing else in the pipeline reads that value on the way out: it is in no finding key, and the
parity tuple is `(file, line, cwe, category, message, severity)`. So a memo that answers for the
wrong node would pass the 425-key parity gate and the 609-file engine dump without a single symptom
- it would only move a sink between scopes, and taint and attribution follow it silently. This file
is the missing oracle, recorded before any memo exists.

Provenance is tested, not assumed. Each pinned tuple disappears when
`_collect_cluster2_structural_findings` is replaced by a no-op, and nothing else appears, so the
six records really are cluster2's own and not an earlier collector that reaches the same line. The
shapes are chosen for exactly that reason: the obvious `ssl._create_default_https_context` and
`urllib3.PoolManager(cert_reqs="CERT_NONE")` spellings are already claimed by a collector that runs
before cluster2, so cluster2 only merges into them and records nothing - pinning those would have
asserted another collector's scope.

The three scope forms `_scope_for` can return are all present: a module-global sink
(`<mod>:global`), a function whose import is written inside the function body (`<mod>:function:<name>`),
and a class method (`<mod>:function:<Class>.<method>`). `ml_shape.py` adds the crossing of the last
two - an import written *inside the method* - because that is the one case where the scope that
`_resolve_chain` uses to make the call resolvable and the scope `_scope_for` reports could disagree.

Run it either way:
    python tests/test_cluster2_scope_id_baseline.py
    python -m pytest tests/test_cluster2_scope_id_baseline.py -q
"""
from __future__ import annotations

import ast
import contextlib
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ast_scanner import TaintTracker  # noqa: E402

# Each module is scanned under its own name, so each one exercises one scope shape on its own.
FILES = {
    # (c) module-global sink: the call is at top level, so no registered function is ever found
    # and `_scope_for` must return the `<mod>:global` fallback.
    "g_shape.py": 'import http.client\n\nconn = http.client.HTTPSConnection("api.example.com")\n',
    # (a) function-local import: `http.client` is bound inside the body, so the import binding and
    # the sink both sit in the function scope, not the module scope.
    "f_shape.py": ('def handler(cfg):\n    import http.client\n\n'
                   '    return http.client.HTTPSConnection("api.example.com")\n'),
    # (b) class method: the answer must carry the class prefix, which only a climb through
    # ClassDef -> FunctionDef reaches.
    "m_shape.py": ('import http.client\n\n\nclass View:\n'
                   '    def get(self, request):\n        return http.client.HTTPSConnection("api.example.com")\n'),
    # (b)+(a) crossed: the import is written inside the method body, so the call is only resolvable
    # through the method scope, and the reported scope must still be the method, not the module.
    "ml_shape.py": ('class View:\n'
                    '    def get(self, request):\n        import http.client\n\n'
                    '        return http.client.HTTPSConnection("api.example.com")\n'),
    # A second method, different rule family, so the oracle is not one predicate's opinion.
    "pool_m.py": ('import urllib3\n\n\nclass View:\n'
                  '    def get(self):\n        return urllib3.HTTPConnectionPool("api.example.com")\n'),
    # A second module-global, different rule family and a different CWE.
    "cors_g.py": ('from fastapi.middleware.cors import CORSMiddleware\n\n'
                  'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n'),
}

# (file, line, operation, cwe, scope_id) - read off the engine at commit 3ef25f3, not inferred.
EXPECTED = sorted([
    ("cors_g.py", 3, "PERMISSIVE_CORS_POLICY", "CWE-942", "cors_g:global"),
    ("f_shape.py", 4, "UNVERIFIED_HTTPS_CONNECTION", "CWE-295", "f_shape:function:handler"),
    ("g_shape.py", 3, "UNVERIFIED_HTTPS_CONNECTION", "CWE-295", "g_shape:global"),
    ("m_shape.py", 6, "UNVERIFIED_HTTPS_CONNECTION", "CWE-295", "m_shape:function:View.get"),
    ("ml_shape.py", 5, "UNVERIFIED_HTTPS_CONNECTION", "CWE-295", "ml_shape:function:View.get"),
    ("pool_m.py", 6, "CLEARTEXT_HTTP_CONNECTION_POOL", "CWE-319", "pool_m:function:View.get"),
])


def _records(disable_cluster2=False):
    """(file, line, operation, cwe, scope_id) for every sink record the full pipeline leaves behind."""
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
        tracker = TaintTracker(files=dict(FILES), audit_all=True)
        if disable_cluster2:
            tracker._collect_cluster2_structural_findings = lambda: None
        tracker.analyze()
    return sorted((r.security_node.location.file, r.lineno, r.security_node.operation,
                   (r.security_node.metadata or {}).get("cwe"), r.scope_id)
                  for r in tracker.sink_records)


def test_pinned_scope_ids_match_the_engine():
    got = _records()
    assert got == EXPECTED, f"cluster2 scope records drifted:\n got={got}\n pin={EXPECTED}"


def test_pinned_records_really_belong_to_cluster2():
    """Non-vacuity: with the collector stubbed out nothing is recorded, so the pin is its output."""
    without = _records(disable_cluster2=True)
    assert without == [], f"these fixtures are not cluster2-only: {without}"
    assert {t[:4] for t in EXPECTED} - {t[:4] for t in without} == {t[:4] for t in EXPECTED}


def test_all_three_scope_shapes_are_covered():
    """A future fixture edit must not quietly drop the only case that pins a scope form."""
    scopes = {t[4] for t in EXPECTED}
    assert any(scope.endswith(":global") for scope in scopes), scopes
    assert any(":function:" in scope and "." not in scope.split(":function:")[1]
               for scope in scopes), scopes
    assert any(":function:" in scope and "." in scope.split(":function:")[1]
               for scope in scopes), scopes


def test_method_local_import_reports_the_method_scope():
    """The crossing case: only the method scope makes the call resolvable, so only it can be right."""
    module = ast.parse(FILES["ml_shape.py"])
    assert not any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in module.body), \
        "ml_shape must keep its import inside the method or this case stops testing the crossing"
    method = module.body[0].body[0]
    assert any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(method)), \
        "the import has to live in the method body"
    rows = [t for t in _records() if t[0] == "ml_shape.py"]
    assert rows == [("ml_shape.py", 5, "UNVERIFIED_HTTPS_CONNECTION", "CWE-295",
                     "ml_shape:function:View.get")], rows
    without = [t for t in _records(disable_cluster2=True) if t[0] == "ml_shape.py"]
    assert without == [], f"this record is not cluster2's own: {without}"


def test_output_is_deterministic_across_repeats():
    """The oracle has to be reproducible before anything is allowed to depend on it."""
    first = _records()
    for _ in range(2):
        assert _records() == first, "scope_id records are not reproducible run to run"


if __name__ == "__main__":
    failures = 0
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            try:
                _fn()
                print(f"  PASS  {_name}")
            except AssertionError as exc:
                failures += 1
                print(f"  FAIL  {_name}: {exc}")
    sys.exit(1 if failures else 0)
