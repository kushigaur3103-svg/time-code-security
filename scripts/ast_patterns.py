#!/usr/bin/env python3
"""
Standalone AST analysis patterns for five engine blind spots.

Each function is pure (no engine imports, no side effects), deterministic,
and operates directly on nodes produced by Python's `ast` module.

1. CWE-295  Disabled SSL via session attribute assignment (`s.verify = False`)
2. CWE-338  Insecure random bound to a security-sensitive dict key
3. CWE-22   Sanitizer-state preservation through dict store/retrieve
4. CWE-918  Allowlist membership branch guard clearing URL taint
5. CWE-79   Direct HTML f-string / concatenation returned as a web response

Run `python scripts/ast_patterns.py` to execute the built-in self-tests.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

WEAK_RANDOM_CALLABLES: FrozenSet[str] = frozenset({
    "random.random", "random.randint", "random.randrange", "random.choice",
    "random.choices", "random.sample", "random.uniform", "random.getrandbits",
    "random.shuffle", "randint", "random", "randrange", "choice", "getrandbits",
})

SENSITIVE_KEY_PATTERN = re.compile(
    r"(secret|token|password|passwd|pwd|api[_-]?key|auth|session|credential|otp|nonce|salt)",
    re.IGNORECASE,
)

HTML_TAG_PATTERN = re.compile(r"</?[a-zA-Z][a-zA-Z0-9]*(\s[^<>]*)?/?>")

ESCAPE_CALLABLES: FrozenSet[str] = frozenset({
    "escape", "html.escape", "markupsafe.escape", "markup", "e",
    "bleach.clean", "cgi.escape", "quote", "urllib.parse.quote",
})

PATH_SANITIZERS: FrozenSet[str] = frozenset({
    "os.path.basename", "os.path.realpath", "os.path.abspath",
    "posixpath.basename", "ntpath.basename", "secure_filename",
    "werkzeug.utils.secure_filename", "shlex.quote", "quote",
})


def callable_name(node: ast.expr) -> Optional[str]:
    """Resolve a call target expression to a dotted name ('random.randint')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = callable_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def is_sensitive_key(node: Optional[ast.expr]) -> bool:
    """True when a dict/subscript key is a constant string naming a secret."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return bool(SENSITIVE_KEY_PATTERN.search(node.value))
    return False


# ---------------------------------------------------------------------------
# 1. CWE-295 - Disabled SSL via session attribute assignment
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DisabledSSLAssignment:
    lineno: int
    col_offset: int
    object_name: str
    attribute: str


def detect_disabled_ssl_session_attr(
    tree: ast.AST,
    attributes: Iterable[str] = ("verify",),
    insecure_values: Iterable[object] = (False,),
) -> List[DisabledSSLAssignment]:
    """
    Detect `obj.verify = False` style assignments (e.g. requests.Session).

    Matches ast.Assign / ast.AnnAssign whose target is an ast.Attribute with
    a monitored attribute name and whose assigned value is the constant
    False (or another configured insecure constant such as 0 or 'none').
    """
    monitored = set(attributes)
    insecure: Set[object] = set(insecure_values)
    insecure.update({0, "none", "cert_none", "ssl_verify_none"})
    findings: List[DisabledSSLAssignment] = []

    for node in ast.walk(tree):
        targets_values: List[Tuple[List[ast.expr], Optional[ast.expr]]] = []
        if isinstance(node, ast.Assign):
            targets_values.append((node.targets, node.value))
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets_values.append(([node.target], node.value))
        else:
            continue

        for targets, value in targets_values:
            literal = None
            if isinstance(value, ast.Constant):
                literal = value.value
            elif isinstance(value, ast.Attribute):
                # ssl.CERT_NONE style
                literal = value.attr.lower()
            elif isinstance(value, ast.Name):
                literal = value.id.lower()
            if literal is None:
                continue
            normalized = literal.lower() if isinstance(literal, str) else literal
            if normalized not in insecure:
                continue
            for target in targets:
                if isinstance(target, ast.Attribute) and target.attr in monitored:
                    obj_name = callable_name(target.value) or "<expr>"
                    findings.append(DisabledSSLAssignment(
                        lineno=node.lineno,
                        col_offset=node.col_offset,
                        object_name=obj_name,
                        attribute=target.attr,
                    ))
    return findings


# ---------------------------------------------------------------------------
# 2. CWE-338 - Insecure random bound to a security-sensitive dict key
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InsecureRandomSecret:
    lineno: int
    col_offset: int
    key: str
    random_callable: str


def _is_weak_random_call(node: ast.expr) -> Optional[str]:
    if isinstance(node, ast.Call):
        name = callable_name(node.func)
        if name and (name in WEAK_RANDOM_CALLABLES or name.split(".")[-1] in WEAK_RANDOM_CALLABLES):
            return name
    return None


def detect_insecure_random_secret_values(tree: ast.AST) -> List[InsecureRandomSecret]:
    """
    Detect weak randomness feeding secret material, in both shapes:

      * dict literals:   cfg = {"auth_secret": random.random(), ...}
      * subscript store: data["token"] = random.randint(0, 9999)

    A finding requires BOTH a security-sensitive constant string key and a
    value that is a direct call to a `random` module function.
    """
    findings: List[InsecureRandomSecret] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if key is None:  # ** unpacking
                    continue
                weak = _is_weak_random_call(value)
                if weak and is_sensitive_key(key):
                    findings.append(InsecureRandomSecret(
                        lineno=value.lineno,
                        col_offset=value.col_offset,
                        key=str(key.value),
                        random_callable=weak,
                    ))
        elif isinstance(node, ast.Assign):
            weak = _is_weak_random_call(node.value)
            if not weak:
                continue
            for target in node.targets:
                if (
                    isinstance(target, ast.Subscript)
                    and is_sensitive_key(target.slice)
                ):
                    findings.append(InsecureRandomSecret(
                        lineno=node.lineno,
                        col_offset=node.col_offset,
                        key=str(target.slice.value),
                        random_callable=weak,
                    ))
    return findings


# ---------------------------------------------------------------------------
# 3. CWE-22 - Sanitizer-state preservation through dict store/retrieve
# ---------------------------------------------------------------------------

CLEAN = "CLEAN"
TAINTED = "TAINTED"
UNKNOWN = "UNKNOWN"


@dataclass
class DictTaintTracker:
    """
    Minimal intra-procedural taint map preserving sanitizer verdicts across
    dict store/retrieve cycles:

        clean = os.path.basename(user_input)   # clean -> CLEAN (sanitized)
        data["safe_path"] = clean              # (data, "safe_path") -> CLEAN
        open(data["safe_path"])                # retrieval stays CLEAN

    State keys:
      * variable name            -> "x"
      * composite container slot -> "data['safe_path']"
    """
    taint_sources: FrozenSet[str] = frozenset({
        "request.args.get", "request.form.get", "request.get_json",
        "input", "sys.argv", "os.environ.get",
    })
    sanitizers: FrozenSet[str] = PATH_SANITIZERS
    var_state: Dict[str, str] = field(default_factory=dict)
    slot_state: Dict[str, str] = field(default_factory=dict)

    # -- expression classification -----------------------------------------

    def expr_state(self, node: ast.expr) -> str:
        if isinstance(node, ast.Constant):
            return CLEAN
        if isinstance(node, ast.Name):
            return self.var_state.get(node.id, UNKNOWN)
        if isinstance(node, ast.Subscript):
            slot = self._slot_key(node)
            if slot in self.slot_state:
                return self.slot_state[slot]
            return self.expr_state(node.value) if self._is_container(node.value) else UNKNOWN
        if isinstance(node, ast.Call):
            name = callable_name(node.func) or ""
            if name in self.sanitizers or name.split(".")[-1] in self.sanitizers:
                return CLEAN
            if name in self.taint_sources or name.split(".")[-1] in {"get", "getlist"} and self._tainted_receiver(node):
                return TAINTED
            arg_states = [self.expr_state(a) for a in node.args]
            if TAINTED in arg_states:
                return TAINTED
            return UNKNOWN
        if isinstance(node, ast.BinOp):
            left, right = self.expr_state(node.left), self.expr_state(node.right)
            if TAINTED in (left, right):
                return TAINTED
            if left == CLEAN and right == CLEAN:
                return CLEAN
            return UNKNOWN
        if isinstance(node, ast.JoinedStr):
            states = [self.expr_state(v.value) for v in node.values if isinstance(v, ast.FormattedValue)]
            if TAINTED in states:
                return TAINTED
            return UNKNOWN
        if isinstance(node, ast.Attribute):
            return self.expr_state(node.value)
        return UNKNOWN

    def _tainted_receiver(self, call: ast.Call) -> bool:
        if isinstance(call.func, ast.Attribute):
            return self.expr_state(call.func.value) == TAINTED
        return False

    def _is_container(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return True
        return False

    @staticmethod
    def _slot_key(node: ast.Subscript) -> Optional[str]:
        base = callable_name(node.value)
        key = node.slice
        if base and isinstance(key, ast.Constant) and isinstance(key.value, (str, int)):
            return f"{base}[{key.value!r}]"
        return None

    # -- statement handling --------------------------------------------------

    def visit(self, node: ast.stmt) -> None:
        """Process one statement in source order (call sequentially per scope)."""
        if isinstance(node, ast.Assign):
            value_state = self.expr_state(node.value)
            for target in node.targets:
                self._assign(target, value_state)
        elif isinstance(node, ast.AnnAssign) and node.value is not None and node.target is not None:
            self._assign(node.target, self.expr_state(node.value))
        elif isinstance(node, ast.AugAssign):
            merged = self.expr_state(node.target)
            rhs = self.expr_state(node.value)
            self._assign(node.target, TAINTED if TAINTED in (merged, rhs) else merged)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            # Container mutation methods: data.update({...}) / data.pop(k)
            self._handle_container_call(node.value)

    def _assign(self, target: ast.expr, value_state: str) -> None:
        if isinstance(target, ast.Name):
            if value_state == UNKNOWN:
                self.var_state.pop(target.id, None)
            else:
                self.var_state[target.id] = value_state
        elif isinstance(target, ast.Subscript):
            slot = self._slot_key(target)
            if slot is None:
                return
            # Store preserves sanitizer verdict: CLEAN stays CLEAN on retrieve.
            if value_state == UNKNOWN:
                self.slot_state.pop(slot, None)
            else:
                self.slot_state[slot] = value_state
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign(elt, value_state)

    def _handle_container_call(self, call: ast.Call) -> None:
        name = callable_name(call.func)
        if not name or not isinstance(call.func, ast.Attribute):
            return
        method = call.func.attr
        base = callable_name(call.func.value)
        if method == "update" and base and call.args and isinstance(call.args[0], ast.Dict):
            for key, value in zip(call.args[0].keys, call.args[0].values):
                if key is None:
                    continue
                if isinstance(key, ast.Constant) and isinstance(key.value, (str, int)):
                    slot = f"{base}[{key.value!r}]"
                    state = self.expr_state(value)
                    if state == UNKNOWN:
                        self.slot_state.pop(slot, None)
                    else:
                        self.slot_state[slot] = state
        elif method == "pop" and base and call.args:
            if isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, (str, int)):
                self.slot_state.pop(f"{base}[{call.args[0].value!r}]", None)

    def retrieval_state(self, node: ast.Subscript) -> str:
        """Authoritative answer for `data["key"]` reads at the current point."""
        return self.expr_state(node)


def analyze_dict_sanitizer_flow(function_body: Iterable[ast.stmt]) -> DictTaintTracker:
    """Convenience driver: replay statements of one scope in order."""
    tracker = DictTaintTracker()
    for stmt in function_body:
        tracker.visit(stmt)
    return tracker


# ---------------------------------------------------------------------------
# 4. CWE-918 - Allowlist membership branch guard clears taint
# ---------------------------------------------------------------------------

ALLOWLIST_NAME_PATTERN = re.compile(r"(allow|white|safe|trusted|approved|permitted)", re.IGNORECASE)


@dataclass(frozen=True)
class AllowlistGuardVerdict:
    guarded_name: str
    body_clears: bool
    orelse_clears: bool
    guard_kind: str  # "membership" | "equality"


def _is_allowlist_operand(node: ast.expr) -> bool:
    if isinstance(node, (ast.Set, ast.List, ast.Tuple, ast.Frozenset if hasattr(ast, "Frozenset") else ast.Set)):
        return True
    if isinstance(node, ast.Call) and callable_name(node.func) in {"set", "frozenset", "list", "tuple"}:
        return True
    if isinstance(node, ast.Name):
        return bool(ALLOWLIST_NAME_PATTERN.search(node.id)) or node.id.isupper()
    if isinstance(node, ast.Attribute):
        return bool(ALLOWLIST_NAME_PATTERN.search(node.attr)) or node.attr.isupper()
    return False


def detect_allowlist_guard(
    if_node: ast.If,
    tainted_names: Set[str],
) -> List[AllowlistGuardVerdict]:
    """
    Inspect an ast.If test for allowlist membership / equality guards:

        if target_url in ALLOWED_HOSTS:        -> body_clears for target_url
        if parsed.netloc not in ALLOWED:       -> orelse_clears for parsed.netloc
        if host == "trusted.com":              -> body_clears for host

    Inside the cleared branch the guarded name's taint may be downgraded to
    CLEAN (SSRF verdict suppressed), deterministically and only when the
    comparison operand is a literal collection or allowlist-named constant.
    """
    verdicts: List[AllowlistGuardVerdict] = []
    test = if_node.test

    comparisons = [test] if isinstance(test, ast.Compare) else []
    if isinstance(test, ast.BoolOp) and all(isinstance(v, ast.Compare) for v in test.values):
        comparisons = list(test.values)

    for cmp_node in comparisons:
        if len(cmp_node.ops) != 1:
            continue
        op = cmp_node.ops[0]
        left, right = cmp_node.left, cmp_node.comparators[0]

        guarded_expr, allow_operand, kind = None, None, None
        if isinstance(op, (ast.In, ast.NotIn)):
            guarded_expr, allow_operand, kind = left, right, "membership"
        elif isinstance(op, (ast.Eq, ast.NotEq)):
            if isinstance(right, ast.Constant) and isinstance(right.value, str):
                guarded_expr, allow_operand, kind = left, right, "equality"
            elif _is_allowlist_operand(right):
                guarded_expr, allow_operand, kind = left, right, "equality"
        if guarded_expr is None:
            continue

        name = callable_name(guarded_expr)
        if name is None or name not in tainted_names:
            continue

        positive = isinstance(op, (ast.In, ast.Eq))
        if kind == "membership" and not _is_allowlist_operand(allow_operand):
            continue

        verdicts.append(AllowlistGuardVerdict(
            guarded_name=name,
            body_clears=positive,
            orelse_clears=not positive,
            guard_kind=kind,
        ))
    return verdicts


# ---------------------------------------------------------------------------
# 5. CWE-79 - Direct HTML f-string / concatenation returned as a response
# ---------------------------------------------------------------------------

ROUTE_DECORATOR_PATTERN = re.compile(
    r"^(route|get|post|put|delete|patch|app\.route|blueprint\.route|bp\.route|"
    r"api\.route|.*\.route|.*\.get|.*\.post)$"
)

RESPONSE_WRAPPERS: FrozenSet[str] = frozenset({
    "Response", "make_response", "JSONResponse", "HTMLResponse",
    "flask.Response", "fastapi.responses.HTMLResponse", "HttpResponse",
})


@dataclass(frozen=True)
class HtmlInjectionFinding:
    lineno: int
    col_offset: int
    function_name: str
    construct: str  # "f-string" | "concatenation"
    is_route_handler: bool


def _literal_html_fragments(node: ast.expr) -> List[str]:
    """Extract constant string fragments from JoinedStr / BinOp chains."""
    fragments: List[str] = []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        fragments.append(node.value)
    elif isinstance(node, ast.JoinedStr):
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                fragments.append(part.value)
    elif isinstance(node, ast.BinOp):
        fragments.extend(_literal_html_fragments(node.left))
        fragments.extend(_literal_html_fragments(node.right))
    return fragments


def _has_dynamic_part(node: ast.expr) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp):
        return not (
            isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant)
        )
    return False


def _dynamic_parts_escaped(node: ast.expr) -> bool:
    """True when every interpolated expression passes through an escaper."""
    expressions: List[ast.expr] = []
    if isinstance(node, ast.JoinedStr):
        expressions = [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
    elif isinstance(node, ast.BinOp):
        for side in (node.left, node.right):
            if not isinstance(side, ast.Constant):
                expressions.append(side)

    for expr in expressions:
        if isinstance(expr, ast.Call):
            name = callable_name(expr.func) or ""
            if name in ESCAPE_CALLABLES or name.split(".")[-1] in ESCAPE_CALLABLES:
                continue
        return False
    return bool(expressions)


def _is_route_handler(func: ast.FunctionDef) -> bool:
    for dec in func.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = callable_name(target)
        if name and ROUTE_DECORATOR_PATTERN.match(name):
            return True
    return False


def _unwrap_response_call(node: ast.expr) -> ast.expr:
    """make_response(f"...") / Response("..." + x) -> inner payload expr."""
    if isinstance(node, ast.Call):
        name = callable_name(node.func) or ""
        if name in RESPONSE_WRAPPERS or name.split(".")[-1] in RESPONSE_WRAPPERS:
            if node.args:
                return node.args[0]
    return node


def detect_direct_html_responses(tree: ast.Module) -> List[HtmlInjectionFinding]:
    """
    Flag route handlers (or any function when no routes exist) that directly
    return HTML built via f-string or string concatenation with unescaped
    dynamic parts:

        @app.route("/greet")
        def greet():
            name = request.args.get("name")
            return f"<div>Hello {name}</div>"          # FINDING
            return "<h1>" + escape(name) + "</h1>"     # clean
    """
    findings: List[HtmlInjectionFinding] = []

    for func in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        is_route = _is_route_handler(func)
        for node in ast.walk(func):
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            payload = _unwrap_response_call(node.value)
            if not isinstance(payload, (ast.JoinedStr, ast.BinOp)):
                continue
            fragments = _literal_html_fragments(payload)
            if not any(HTML_TAG_PATTERN.search(frag) for frag in fragments):
                continue
            if not _has_dynamic_part(payload):
                continue  # fully constant HTML - not injectable
            if _dynamic_parts_escaped(payload):
                continue
            construct = "f-string" if isinstance(payload, ast.JoinedStr) else "concatenation"
            findings.append(HtmlInjectionFinding(
                lineno=node.lineno,
                col_offset=node.col_offset,
                function_name=func.name,
                construct=construct,
                is_route_handler=is_route,
            ))
    return findings


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _parse(code: str) -> ast.Module:
    return ast.parse(code)


def _selftest() -> None:
    # 1. CWE-295
    tree = _parse(
        "import requests\n"
        "s = requests.Session()\n"
        "s.verify = False\n"
        "ctx.check_hostname = False\n"
        "t.verify = True\n"
    )
    hits = detect_disabled_ssl_session_attr(tree)
    assert len(hits) == 1 and hits[0].object_name == "s" and hits[0].lineno == 3, hits

    # 2. CWE-338
    tree = _parse(
        "import random\n"
        "cfg = {'auth_secret': random.random(), 'label': random.choice(['a'])}\n"
        "data = {}\n"
        "data['session_token'] = random.randint(0, 9999)\n"
        "data['username'] = random.random()\n"
    )
    hits = detect_insecure_random_secret_values(tree)
    assert {(h.key, h.random_callable) for h in hits} == {
        ("auth_secret", "random.random"),
        ("session_token", "random.randint"),
    }, hits

    # 3. CWE-22 sanitizer state through dicts
    tree = _parse(
        "def handler(request):\n"
        "    raw = request.args.get('p')\n"
        "    clean = os.path.basename(raw)\n"
        "    data = {}\n"
        "    data['safe_path'] = clean\n"
        "    data['raw_path'] = raw\n"
        "    open(data['safe_path'])\n"
        "    open(data['raw_path'])\n"
    )
    import os.path  # noqa: F401 (ensures sanitizer name space matches)
    body = tree.body[0].body
    tracker = analyze_dict_sanitizer_flow(body)
    retrieval = [n for n in ast.walk(body[-2]) if isinstance(n, ast.Subscript)][0]
    assert tracker.retrieval_state(retrieval) == CLEAN
    retrieval_raw = [n for n in ast.walk(body[-1]) if isinstance(n, ast.Subscript)][0]
    assert tracker.retrieval_state(retrieval_raw) == TAINTED

    # 4. CWE-918 allowlist guard
    tree = _parse(
        "if target_url in ALLOWED_HOSTS:\n"
        "    fetch(target_url)\n"
        "if host not in WHITELIST:\n"
        "    reject()\n"
        "else:\n"
        "    fetch(host)\n"
        "if evil in user_list:\n"
        "    fetch(evil)\n"
    )
    tainted = {"target_url", "host", "evil"}
    v1 = detect_allowlist_guard(tree.body[0], tainted)
    assert len(v1) == 1 and v1[0].body_clears and not v1[0].orelse_clears
    v2 = detect_allowlist_guard(tree.body[1], tainted)
    assert len(v2) == 1 and v2[0].orelse_clears and not v2[0].body_clears
    v3 = detect_allowlist_guard(tree.body[2], tainted)
    assert v3 == [], "user_list is not an allowlist-named operand"

    # 5. CWE-79 direct HTML responses
    tree = _parse(
        "from flask import Flask, request, escape\n"
        "app = Flask(__name__)\n"
        "@app.route('/vuln')\n"
        "def vuln():\n"
        "    name = request.args.get('n')\n"
        "    return f\"<div>{name}</div>\"\n"
        "@app.route('/concat')\n"
        "def concat():\n"
        "    name = request.args.get('n')\n"
        "    return '<h1>' + name + '</h1>'\n"
        "@app.route('/safe')\n"
        "def safe():\n"
        "    name = request.args.get('n')\n"
        "    return f'<div>{escape(name)}</div>'\n"
        "@app.route('/const')\n"
        "def const():\n"
        "    return '<b>static</b>'\n"
    )
    hits = detect_direct_html_responses(tree)
    assert {(h.function_name, h.construct) for h in hits} == {
        ("vuln", "f-string"), ("concat", "concatenation"),
    }, hits
    assert all(h.is_route_handler for h in hits)

    print("All 5 blind-spot pattern self-tests passed.")


if __name__ == "__main__":
    _selftest()
