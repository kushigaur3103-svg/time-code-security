from __future__ import annotations
import ast
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from rule_engine import match_sink_rule, check_sink_safety_rules, get_rule

class NodeType(str, Enum):
    SOURCE = "source"
    TRANSFORM = "transform"
    SINK = "sink"

class TaintState(str, Enum):
    CLEAN = "CLEAN"
    TAINTED = "TAINTED"
    UNKNOWN = "UNKNOWN"

@dataclass(frozen=True)
class CodeLocation:
    file: str
    line_start: int
    line_end: int
    column_start: int = 0
    column_end: int = 0

@dataclass
class SecurityNode:
    id: str
    node_type: NodeType
    symbol: str
    operation: str
    location: CodeLocation
    metadata: dict = field(default_factory=dict)

@dataclass
class DataFlowEdge:
    source_id: str
    target_id: str
    kind: str
    confidence: float
    transform: Optional[str] = None

@dataclass
class TaintValue:
    state: TaintState
    source_id: Optional[str] = None
    confidence: float = 1.0
    path: list[str] = field(default_factory=list)
    last_operation: Optional[str] = None

@dataclass
class SecuritySlice:
    source: SecurityNode
    sink: SecurityNode
    edges: list[DataFlowEdge]
    code: str

@dataclass
class AssignmentRecord:
    target_name: str
    value_node: ast.AST
    lineno: int
    scope_id: str
    is_conditional: bool

@dataclass
class SinkRecord:
    node: ast.Call
    security_node: SecurityNode
    lineno: int
    scope_id: str

SOURCE_REGISTRY = {
    "request.args.get": {"operation": "HTTP_QUERY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.args.getlist": {"operation": "HTTP_QUERY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.form.get": {"operation": "HTTP_BODY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.form.getlist": {"operation": "HTTP_BODY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.values.get": {"operation": "HTTP_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.values.getlist": {"operation": "HTTP_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.get_json": {"operation": "HTTP_BODY_JSON_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.headers.get": {"operation": "HTTP_HEADER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.cookies.get": {"operation": "HTTP_COOKIE_ACCESS", "source_type": "USER_CONTROLLED"},
}

SANITIZER_REGISTRY = {
    "html.escape": {"protected_cwes": {"CWE-79"}, "protected_sinks": {"XSS"}},
    "safe_eval_input": {"protected_cwes": {"CWE-95"}, "protected_sinks": {"CODE_EXECUTION"}},
    "secure_path_join": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL"}},
}

SINK_REGISTRY = {
    "eval": {"operation": "ARBITRARY_CODE_EXECUTION", "category": "CODE_EXECUTION", "cwe": "CWE-95"},
    "exec": {"operation": "ARBITRARY_CODE_EXECUTION", "category": "CODE_EXECUTION", "cwe": "CWE-95"},
    "os.system": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.run": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.call": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.Popen": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "pickle.loads": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},
    "pickle.load": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},
    "open": {"operation": "FILE_ACCESS", "category": "PATH_TRAVERSAL", "cwe": "CWE-22"},
    "render_template_string": {"operation": "TEMPLATE_EVALUATION", "category": "SSTI", "cwe": "CWE-1336"},
    "flask.render_template_string": {"operation": "TEMPLATE_EVALUATION", "category": "SSTI", "cwe": "CWE-1336"},
}

def location(node: ast.AST, file_path: str) -> CodeLocation:
    return CodeLocation(
        file=file_path,
        line_start=getattr(node, "lineno", 1),
        line_end=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
        column_start=getattr(node, "col_offset", 0),
        column_end=getattr(node, "end_col_offset", getattr(node, "col_offset", 0)),
    )

def dotted_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        if parent: return f"{parent}.{node.attr}"
        return node.attr
    return None

class TaintTracker:
    def __init__(self, files: dict[str, str] = None, source: str = None, file_path: str = "target.py"):
        self.files = files if files is not None else {file_path: source}
        self.modules: dict[str, ast.AST] = {}
        self.file_paths: dict[str, str] = {}
        for fpath, code in self.files.items():
            mod_name = fpath.replace("\\\\", "/").replace(".py", "").replace("/", ".")
            if mod_name.endswith(".__init__"): mod_name = mod_name[:-9]
            try:
                self.modules[mod_name] = ast.parse(code, filename=fpath)
                self.file_paths[mod_name] = fpath
            except SyntaxError:
                pass
        self.imports = {m: {} for m in self.modules}
        self.sources: list[SecurityNode] = []
        self.sinks: list[SecurityNode] = []
        self.edges: list[DataFlowEdge] = []
        self.assignments_by_scope: dict[tuple[str, str], list[AssignmentRecord]] = {}
        self.sink_records: list[SinkRecord] = []
        self.functions: dict[str, ast.FunctionDef] = {}
        self.returns_by_scope: dict[str, list[ast.Return]] = {}
        self.raw_calls: list[tuple[ast.Call, str, int]] = []
        self.call_sites_by_target: dict[str, list[tuple[ast.Call, str, int]]] = {}
        self.containment_guards: list[dict] = []
        self._source_counter = 0
        self._sink_counter = 0

    def next_source_id(self) -> str:
        self._source_counter += 1
        return f"SRC-{self._source_counter:03d}"

    def next_sink_id(self) -> str:
        self._sink_counter += 1
        return f"SNK-{self._sink_counter:03d}"

    def resolve_canonical_name(self, node: ast.AST, scope_id: str = "", visited: Optional[set[str]] = None) -> Optional[str]:
        if visited is None:
            visited = set()
        mod_name = scope_id.split(":")[0] if scope_id else ""

        if isinstance(node, ast.Name):
            if mod_name and mod_name in self.imports and node.id in self.imports[mod_name]:
                return self.imports[mod_name][node.id]

            var_key = f"{scope_id}:{node.id}"
            if var_key not in visited:
                visited.add(var_key)
                current_scope = scope_id
                found_record = None
                while current_scope:
                    recs = self.assignments_by_scope.get((current_scope, node.id), [])
                    if recs:
                        uncond = [r for r in recs if not r.is_conditional]
                        found_record = uncond[-1] if uncond else recs[-1]
                        break
                    if "." in current_scope and "function" in current_scope:
                        current_scope = current_scope.rsplit(".", 1)[0]
                    elif ":function" in current_scope:
                        current_scope = f"{mod_name}:global"
                    elif current_scope != f"{mod_name}:global":
                        current_scope = f"{mod_name}:global"
                    else:
                        break

                if found_record:
                    resolved = self.resolve_canonical_name(found_record.value_node, found_record.scope_id, visited)
                    if resolved:
                        return resolved
                    if node.id in ("exec", "eval", "open"):
                        return f"shadowed:{node.id}"

            return node.id

        if isinstance(node, ast.Attribute):
            base_canon = self.resolve_canonical_name(node.value, scope_id, visited)
            if base_canon:
                full_name = f"{base_canon}.{node.attr}"
                if mod_name and mod_name in self.imports and full_name in self.imports[mod_name]:
                    return self.imports[mod_name][full_name]
                return full_name
            return node.attr

        if isinstance(node, ast.Call):
            call_name = dotted_name(node.func)
            if call_name:
                func_scope = self._resolve_function_scope(call_name, scope_id)
                if func_scope and func_scope not in visited:
                    visited.add(func_scope)
                    returns = self.returns_by_scope.get(func_scope, [])
                    if returns:
                        ret_canons = [self.resolve_canonical_name(r.value, func_scope, visited) for r in returns if r.value]
                        if ret_canons and all(c == ret_canons[0] and c is not None for c in ret_canons):
                            return ret_canons[0]

        return None

    def is_source_call(self, node: ast.AST, scope_id: str = "") -> bool:
        if not isinstance(node, ast.Call): return False
        canon = self.resolve_canonical_name(node.func, scope_id) if scope_id else dotted_name(node.func)
        if canon:
            if canon in SOURCE_REGISTRY: return True
            if canon.startswith("flask.") and canon[6:] in SOURCE_REGISTRY: return True
        name = dotted_name(node.func)
        if name in SOURCE_REGISTRY: return True
        if name and name.startswith("flask.") and name[6:] in SOURCE_REGISTRY: return True
        return False

    def get_or_create_source(self, node: ast.Call, file_path: str, scope_id: str = "") -> SecurityNode:
        loc = location(node, file_path)
        for existing in self.sources:
            if existing.location == loc: return existing
        source_id = self.next_source_id()
        canon_name = self.resolve_canonical_name(node.func, scope_id) if scope_id else None
        name = dotted_name(node.func)
        lookup_name = canon_name if (canon_name and canon_name in SOURCE_REGISTRY) else name
        if lookup_name not in SOURCE_REGISTRY and canon_name and canon_name.startswith("flask."):
            unq = canon_name[6:]
            if unq in SOURCE_REGISTRY: lookup_name = unq
        if lookup_name not in SOURCE_REGISTRY and name and name.startswith("flask."):
            unq = name[6:]
            if unq in SOURCE_REGISTRY: lookup_name = unq
        meta = SOURCE_REGISTRY.get(lookup_name, {})
        source = SecurityNode(
            id=source_id, node_type=NodeType.SOURCE, symbol=f"{lookup_name}(...)",
            operation=meta.get("operation", "USER_INPUT_ACCESS"), location=loc,
            metadata={"source_type": meta.get("source_type", "USER_CONTROLLED")}
        )
        self.sources.append(source)
        return source

    def _is_builtin_shadowed(self, name: str, scope_id: str, lineno: int = 0) -> bool:
        if name not in ("exec", "eval", "open"):
            return False

        mod_name = scope_id.split(":")[0] if scope_id else ""
        curr_scope = scope_id
        while curr_scope:
            f_node = self.functions.get(curr_scope)
            if f_node:
                all_args = [a.arg for a in f_node.args.args]
                if getattr(f_node.args, "vararg", None):
                    all_args.append(f_node.args.vararg.arg)
                if getattr(f_node.args, "kwarg", None):
                    all_args.append(f_node.args.kwarg.arg)
                for kw in getattr(f_node.args, "kwonlyargs", []):
                    all_args.append(kw.arg)
                for p in getattr(f_node.args, "posonlyargs", []):
                    all_args.append(p.arg)
                if name in all_args:
                    return True

            recs = self.assignments_by_scope.get((curr_scope, name), [])
            valid_recs = [r for r in recs if r.lineno < lineno] if (curr_scope == scope_id and lineno > 0) else recs
            if valid_recs:
                last_rec = valid_recs[-1]
                target_canon = self.resolve_canonical_name(last_rec.value_node, last_rec.scope_id)
                if target_canon in (name, f"builtins.{name}"):
                    return False
                return True

            test_func_scope = f"{curr_scope}.{name}" if ":function" in curr_scope else f"{mod_name}:function:{name}"
            if test_func_scope in self.functions:
                return True

            if "." in curr_scope and "function" in curr_scope:
                curr_scope = curr_scope.rsplit(".", 1)[0]
            elif ":function" in curr_scope:
                curr_scope = f"{mod_name}:global"
            elif curr_scope != f"{mod_name}:global":
                curr_scope = f"{mod_name}:global"
            else:
                break

        if f"{mod_name}:function:{name}" in self.functions:
            return True

        return False

    def is_sink_call(self, node: ast.AST, scope_id: str = "", lineno: int = 0) -> bool:
        if not isinstance(node, ast.Call): return False
        call_lineno = lineno or getattr(node, "lineno", 0)
        name = dotted_name(node.func) or ""
        canon = self.resolve_canonical_name(node.func, scope_id) if scope_id else name
        if canon:
            if canon.startswith("shadowed:"):
                return False
            if name and not name.startswith("builtins.") and not name.startswith("flask.") and scope_id and self._is_builtin_shadowed(name, scope_id, call_lineno):
                return False
            matched = match_sink_rule(node, name, canon)
            if matched:
                if isinstance(node.func, ast.Attribute) and node.func.attr == "render":
                    if not self._is_jinja_template_expr(node.func.value, scope_id):
                        return False
                return True

        if name:
            if scope_id and not name.startswith("builtins.") and not name.startswith("flask.") and self._is_builtin_shadowed(name, scope_id, call_lineno):
                return False
            matched = match_sink_rule(node, name, canon)
            if matched:
                if isinstance(node.func, ast.Attribute) and node.func.attr == "render":
                    if not self._is_jinja_template_expr(node.func.value, scope_id):
                        return False
                return True

        if isinstance(node.func, ast.Attribute):
            if node.func.attr in {"read_text", "read_bytes", "write_text", "write_bytes"}:
                return True
            if node.func.attr == "open" and self._is_path_expr(node.func.value, scope_id):
                return True
            if node.func.attr == "render" and self._is_jinja_template_expr(node.func.value, scope_id):
                return True
        return False

    def check_sink_safety(self, node: ast.Call, sink_name: str) -> bool:
        if check_sink_safety_rules(node, sink_name):
            return True
        return False

    def get_or_create_sink(self, node: ast.Call, file_path: str, scope_id: str = "") -> SecurityNode:
        loc = location(node, file_path)
        for existing in self.sinks:
            if existing.location == loc: return existing
        sink_id = self.next_sink_id()
        canon_name = self.resolve_canonical_name(node.func, scope_id) if scope_id else None
        name = dotted_name(node.func) or "sink"
        matched_rule = match_sink_rule(node, name, canon_name)
        if matched_rule and isinstance(node.func, ast.Attribute) and node.func.attr == "render":
            if not self._is_jinja_template_expr(node.func.value, scope_id):
                matched_rule = None
        if matched_rule:
            meta = {"operation": matched_rule.operation, "category": matched_rule.category, "cwe": matched_rule.cwe_id}
        else:
            meta = {}
        if not meta and isinstance(node.func, ast.Attribute):
            if node.func.attr in {"read_text", "read_bytes", "write_text", "write_bytes"} or (node.func.attr == "open" and self._is_path_expr(node.func.value, scope_id)):
                cwe22_rule = get_rule("CWE-22")
                if cwe22_rule:
                    meta = {"operation": cwe22_rule.operation, "category": cwe22_rule.category, "cwe": cwe22_rule.cwe_id}
                else:
                    meta = {"operation": "FILE_ACCESS", "category": "PATH_TRAVERSAL", "cwe": "CWE-22"}
        sink = SecurityNode(
            id=sink_id, node_type=NodeType.SINK, symbol=canon_name or name,
            operation=meta.get("operation", "UNKNOWN_OPERATION"), location=loc,
            metadata={"sink_type": meta.get("category", "UNKNOWN_CATEGORY"), "cwe": meta.get("cwe", "UNKNOWN_CWE")}
        )
        self.sinks.append(sink)
        return sink

    def sanitizer_protects_context(self, function_name: str, sink: SecurityNode) -> bool:
        rule = SANITIZER_REGISTRY.get(function_name)
        if not rule: return False
        return (sink.metadata.get("cwe") in rule.get("protected_cwes", set()) or 
                sink.metadata.get("sink_type") in rule.get("protected_sinks", set()))

    def _extract_target_from_parents_attr(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Attribute) and node.attr == "parents":
            val = node.value
            if isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute) and val.func.attr == "resolve":
                return dotted_name(val.func.value)
            return dotted_name(val)
        return None

    def _extract_target_from_relative_to(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "is_relative_to":
            val = node.func.value
            if isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute) and val.func.attr == "resolve":
                return dotted_name(val.func.value)
            return dotted_name(val)
        return None

    def _extract_containment_pairs(self, test_node: ast.AST) -> list[tuple[str, ast.AST]]:
        pairs = []
        if isinstance(test_node, ast.Compare):
            for op, comp in zip(test_node.ops, test_node.comparators):
                if isinstance(op, ast.In):
                    target_name = self._extract_target_from_parents_attr(comp)
                    if target_name:
                        pairs.append((target_name, test_node.left))
        elif isinstance(test_node, ast.Call):
            if isinstance(test_node.func, ast.Attribute) and test_node.func.attr == "is_relative_to":
                target_name = self._extract_target_from_relative_to(test_node)
                base_arg = test_node.args[0] if test_node.args else None
                if target_name and base_arg:
                    pairs.append((target_name, base_arg))
        elif isinstance(test_node, ast.BoolOp) and isinstance(test_node.op, ast.And):
            for val in test_node.values:
                pairs.extend(self._extract_containment_pairs(val))
        return pairs

    def is_var_contained(self, var_name: str, scope_id: str, lineno: int, sink: Optional[SecurityNode] = None, visited: Optional[set[str]] = None) -> bool:
        if sink is not None:
            cwe = sink.metadata.get("cwe")
            stype = sink.metadata.get("sink_type")
            if cwe != "CWE-22" and stype not in ("PATH_TRAVERSAL", "FILE_ACCESS"):
                return False

        if visited is not None and f"guard_check:{scope_id}:{var_name}" in visited:
            return False

        sink_line = sink.location.line_start if (sink and hasattr(sink, "location") and sink.location) else lineno

        for guard in self.containment_guards:
            if guard["var_name"] == var_name:
                if guard["scope_id"] == scope_id or scope_id.startswith(guard["scope_id"] + "."):
                    is_in_body = (guard["start_line"] <= lineno <= guard["end_line"]) or (guard["start_line"] <= sink_line <= guard["end_line"])
                    if is_in_body:
                        # Check if var_name was reassigned between check_line and current evaluation line
                        check_pt = max(lineno, sink_line)
                        recs = self.assignments_by_scope.get((guard["scope_id"], var_name), [])
                        reassigned = any(guard["check_line"] < r.lineno <= check_pt for r in recs)
                        if reassigned:
                            continue

                        # Check if base_node is clean (not tainted by user input)
                        base_node = guard.get("base_node")
                        if base_node:
                            base_visited = visited.copy() if visited is not None else set()
                            base_visited.add(f"guard_check:{guard['scope_id']}:{var_name}")
                            base_taint = self.resolve_expression(base_node, sink, guard["scope_id"], guard["check_line"], base_visited)
                            if base_taint.state == TaintState.TAINTED:
                                continue
                        return True
        return False

    def _resolve_function_scope(self, call_name: str, current_scope: str) -> str | None:
        mod_name = current_scope.split(":")[0]
        if "function:" in current_scope:
            nested = f"{current_scope}.{call_name}"
            if nested in self.functions: return nested
        local_glob = f"{mod_name}:function:{call_name}"
        if local_glob in self.functions: return local_glob
        parts = call_name.split(".")

        if len(parts) > 1:
            for i in range(len(parts)-1, 0, -1):
                r_mod = ".".join(parts[:i])
                r_func = ".".join(parts[i:])
                test_scope = f"{r_mod}:function:{r_func}"
                if test_scope in self.functions: return test_scope

        base_name = parts[0]
        # Check if base_name is a variable holding a class instance (e.g. loader = Loader(); loader.method)
        if len(parts) > 1:
            method_attr = ".".join(parts[1:])
            curr = current_scope
            while curr:
                recs = self.assignments_by_scope.get((curr, base_name), [])
                if recs:
                    latest = recs[-1]
                    if isinstance(latest.value_node, ast.Call):
                        cls_name = dotted_name(latest.value_node.func)
                        if cls_name:
                            shadowed = False
                            cls_recs = [r for r in self.assignments_by_scope.get((curr, cls_name), []) if r.lineno < latest.lineno]
                            if cls_recs:
                                last_cls_rec = cls_recs[-1]
                                if not isinstance(last_cls_rec.value_node, ast.Name):
                                    shadowed = True

                            if not shadowed:
                                candidate = f"{mod_name}:function:{cls_name}.{method_attr}"
                                if candidate in self.functions: return candidate

                                resolved_cls = None
                                if cls_name in self.imports.get(mod_name, {}):
                                    resolved_cls = self.imports[mod_name][cls_name]
                                else:
                                    cls_parts = cls_name.split(".")
                                    if cls_parts[0] in self.imports.get(mod_name, {}):
                                        res_base = self.imports[mod_name][cls_parts[0]]
                                        resolved_cls = res_base + "." + ".".join(cls_parts[1:])

                                if resolved_cls:
                                    parts_cls = resolved_cls.split(".")
                                    for i in range(len(parts_cls)-1, 0, -1):
                                        r_mod = ".".join(parts_cls[:i])
                                        r_cls = ".".join(parts_cls[i:])
                                        cand = f"{r_mod}:function:{r_cls}.{method_attr}"
                                        if cand in self.functions: return cand
                    break
                if "." in curr and "function" in curr: curr = curr.rsplit(".", 1)[0]
                elif ":function" in curr: curr = f"{mod_name}:global"
                elif curr != f"{mod_name}:global": curr = f"{mod_name}:global"
                else: break

        if base_name in self.imports.get(mod_name, {}):
            resolved_base = self.imports[mod_name][base_name]
            resolved_full = resolved_base + "." + ".".join(parts[1:]) if len(parts) > 1 else resolved_base
            parts2 = resolved_full.split(".")
            for i in range(len(parts2)-1, 0, -1):
                r_mod = ".".join(parts2[:i])
                r_func = ".".join(parts2[i:])
                test_scope = f"{r_mod}:function:{r_func}"
                if test_scope in self.functions: return test_scope
        return None

    def merge_taints(self, taints: list[TaintValue], node_id: str) -> TaintValue:
        if not taints: return TaintValue(state=TaintState.CLEAN)
        if all(t.state == TaintState.CLEAN for t in taints):
            return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"clean:{node_id}")
        all_tainted = all(t.state == TaintState.TAINTED for t in taints)
        first_tainted = next((t for t in taints if t.state != TaintState.CLEAN), taints[0])
        combined_path = []
        for t in taints:
            if t.state != TaintState.CLEAN: combined_path.extend(t.path)
        combined_path.append(node_id)
        if all_tainted:
            return TaintValue(state=TaintState.TAINTED, source_id=first_tainted.source_id, confidence=min(t.confidence for t in taints), path=combined_path, last_operation=f"merged:{node_id}")
        return TaintValue(state=TaintState.UNKNOWN, source_id=first_tainted.source_id, confidence=0.50, path=combined_path, last_operation=f"path_dependent:{node_id}")

    def _collect_calls_in_expr(self, expr: ast.AST, scope_id: str, lineno: int):
        for subnode in ast.walk(expr):
            if isinstance(subnode, ast.Call):
                self.raw_calls.append((subnode, scope_id, getattr(subnode, "lineno", lineno)))

    def collect_statements(self, statements: list[ast.stmt], scope_id: str, is_conditional: bool = False):
        for stmt in statements:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                child_scope = f"{scope_id}.{stmt.name}" if ":global" not in scope_id else f"{scope_id.split(':')[0]}:function:{stmt.name}"
                self.functions[child_scope] = stmt
                self.collect_statements(stmt.body, scope_id=child_scope, is_conditional=False)
            elif isinstance(stmt, ast.ClassDef):
                mod_name = scope_id.split(":")[0]
                class_scope = f"{scope_id}.{stmt.name}" if ":global" not in scope_id else f"{mod_name}:function:{stmt.name}"
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_scope = f"{mod_name}:function:{stmt.name}.{item.name}"
                        self.functions[method_scope] = item
                        self.collect_statements(item.body, scope_id=method_scope, is_conditional=False)
                    else:
                        self.collect_statements([item], scope_id=class_scope, is_conditional=is_conditional)
            elif isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        record = AssignmentRecord(target_name=target.id, value_node=stmt.value, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                        self.assignments_by_scope.setdefault((scope_id, target.id), []).append(record)
                self.scan_for_sinks(stmt.value, scope_id, stmt.lineno)
                self._collect_calls_in_expr(stmt.value, scope_id, stmt.lineno)
            elif isinstance(stmt, ast.AnnAssign):
                if isinstance(stmt.target, ast.Name) and stmt.value:
                    record = AssignmentRecord(target_name=stmt.target.id, value_node=stmt.value, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                    self.assignments_by_scope.setdefault((scope_id, stmt.target.id), []).append(record)
                    self.scan_for_sinks(stmt.value, scope_id, stmt.lineno)
                    self._collect_calls_in_expr(stmt.value, scope_id, stmt.lineno)
            elif isinstance(stmt, ast.If):
                self.scan_for_sinks(stmt.test, scope_id, stmt.lineno)
                self._collect_calls_in_expr(stmt.test, scope_id, stmt.lineno)
                pairs = self._extract_containment_pairs(stmt.test)
                if pairs and stmt.body:
                    body_start = stmt.body[0].lineno
                    body_end = max(getattr(s, "end_lineno", s.lineno) for s in stmt.body)
                    for target_name, base_node in pairs:
                        self.containment_guards.append({
                            "var_name": target_name,
                            "base_node": base_node,
                            "scope_id": scope_id,
                            "check_line": stmt.lineno,
                            "start_line": body_start,
                            "end_line": body_end,
                        })
                self.collect_statements(stmt.body, scope_id=scope_id, is_conditional=True)
                self.collect_statements(stmt.orelse, scope_id=scope_id, is_conditional=True)
            elif isinstance(stmt, (ast.For, ast.While)):
                if isinstance(stmt, ast.While):
                    self.scan_for_sinks(stmt.test, scope_id, stmt.lineno)
                    self._collect_calls_in_expr(stmt.test, scope_id, stmt.lineno)
                self.collect_statements(stmt.body, scope_id=scope_id, is_conditional=True)
                self.collect_statements(stmt.orelse, scope_id=scope_id, is_conditional=True)
            elif isinstance(stmt, ast.Try):
                self.collect_statements(stmt.body, scope_id=scope_id, is_conditional=True)
                for handler in stmt.handlers: self.collect_statements(handler.body, scope_id=scope_id, is_conditional=True)
                self.collect_statements(stmt.orelse, scope_id=scope_id, is_conditional=True)
                self.collect_statements(stmt.finalbody, scope_id=scope_id, is_conditional=False)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    self.scan_for_sinks(item.context_expr, scope_id, stmt.lineno)
                    self._collect_calls_in_expr(item.context_expr, scope_id, stmt.lineno)
                self.collect_statements(stmt.body, scope_id=scope_id, is_conditional=is_conditional)
            elif isinstance(stmt, ast.Return):
                self.returns_by_scope.setdefault(scope_id, []).append(stmt)
                if stmt.value:
                    self.scan_for_sinks(stmt.value, scope_id, stmt.lineno)
                    self._collect_calls_in_expr(stmt.value, scope_id, stmt.lineno)
            elif isinstance(stmt, ast.Expr):
                self.scan_for_sinks(stmt.value, scope_id, stmt.lineno)
                self._collect_calls_in_expr(stmt.value, scope_id, stmt.lineno)

    def scan_for_sinks(self, expr: ast.AST, scope_id: str, lineno: int):
        mod_name = scope_id.split(":")[0]
        file_path = self.file_paths.get(mod_name, "unknown.py")
        for subnode in ast.walk(expr):
            call_lineno = getattr(subnode, "lineno", lineno)
            if isinstance(subnode, ast.Call) and self.is_sink_call(subnode, scope_id, call_lineno):
                canon_name = self.resolve_canonical_name(subnode.func, scope_id) or dotted_name(subnode.func) or ""
                if not self.check_sink_safety(subnode, canon_name):
                    sink_node = self.get_or_create_sink(subnode, file_path, scope_id)
                    self.sink_records.append(SinkRecord(node=subnode, security_node=sink_node, lineno=call_lineno, scope_id=scope_id))

    def _is_string_expr(self, expr_node: ast.AST, scope_id: str) -> bool:
        if isinstance(expr_node, ast.Constant) and isinstance(expr_node.value, str):
            return True
        if isinstance(expr_node, ast.JoinedStr):
            return True
        if isinstance(expr_node, ast.Name):
            curr = scope_id
            mod_name = scope_id.split(":")[0]
            while curr:
                recs = self.assignments_by_scope.get((curr, expr_node.id), [])
                if recs:
                    latest = recs[-1]
                    if isinstance(latest.value_node, ast.Constant) and isinstance(latest.value_node.value, str):
                        return True
                    if isinstance(latest.value_node, ast.JoinedStr):
                        return True
                    break
                if "." in curr and "function" in curr: curr = curr.rsplit(".", 1)[0]
                elif ":function" in curr: curr = f"{mod_name}:global"
                elif curr != f"{mod_name}:global": curr = f"{mod_name}:global"
                else: break
        return False

    def _is_path_expr(self, expr_node: ast.AST, scope_id: str) -> bool:
        if isinstance(expr_node, ast.Call):
            fname = self.resolve_canonical_name(expr_node.func, scope_id) or dotted_name(expr_node.func) or ""
            if fname in ("Path", "pathlib.Path"):
                return True
            if isinstance(expr_node.func, ast.Attribute) and expr_node.func.attr == "resolve":
                return self._is_path_expr(expr_node.func.value, scope_id)
        if isinstance(expr_node, ast.BinOp) and isinstance(expr_node.op, ast.Div):
            return self._is_path_expr(expr_node.left, scope_id) or self._is_path_expr(expr_node.right, scope_id)
        if isinstance(expr_node, ast.Name):
            curr = scope_id
            mod_name = scope_id.split(":")[0]
            while curr:
                recs = self.assignments_by_scope.get((curr, expr_node.id), [])
                if recs:
                    latest = recs[-1]
                    if self._is_path_expr(latest.value_node, curr):
                        return True
                    break
                if "." in curr and "function" in curr: curr = curr.rsplit(".", 1)[0]
                elif ":function" in curr: curr = f"{mod_name}:global"
                elif curr != f"{mod_name}:global": curr = f"{mod_name}:global"
                else: break
        return False

    def _is_jinja_imported(self, mod_name: str) -> bool:
        if not mod_name or mod_name not in self.imports:
            return False
        return any(v == "jinja2" or v.startswith("jinja2.") for v in self.imports[mod_name].values())

    def _is_jinja_env_expr(self, expr_node: ast.AST, scope_id: str, visited: Optional[set[str]] = None) -> bool:
        if visited is None: visited = set()
        mod_name = scope_id.split(":")[0] if scope_id else ""

        if isinstance(expr_node, ast.Call):
            fname = self.resolve_canonical_name(expr_node.func, scope_id) or dotted_name(expr_node.func) or ""
            if fname == "jinja2.Environment":
                return True
            if fname == "Environment" and (self._is_jinja_imported(mod_name) or not self.imports.get(mod_name)):
                if not self._resolve_function_scope("Environment", scope_id):
                    return True

            func_scope = self._resolve_function_scope(fname, scope_id)
            if func_scope and func_scope not in visited:
                visited.add(func_scope)
                returns = self.returns_by_scope.get(func_scope, [])
                for r in returns:
                    if r.value and self._is_jinja_env_expr(r.value, func_scope, visited.copy()):
                        return True

        if isinstance(expr_node, ast.Name):
            var_key = f"{scope_id}:{expr_node.id}"
            if var_key in visited: return False
            visited.add(var_key)
            curr = scope_id
            while curr:
                recs = self.assignments_by_scope.get((curr, expr_node.id), [])
                if recs:
                    latest = recs[-1]
                    return self._is_jinja_env_expr(latest.value_node, curr, visited.copy())
                if "." in curr and "function" in curr: curr = curr.rsplit(".", 1)[0]
                elif ":function" in curr: curr = f"{mod_name}:global"
                elif curr != f"{mod_name}:global": curr = f"{mod_name}:global"
                else: break

        return False

    def _is_jinja_template_expr(self, expr_node: ast.AST, scope_id: str, visited: Optional[set[str]] = None) -> bool:
        if visited is None: visited = set()
        mod_name = scope_id.split(":")[0] if scope_id else ""

        if isinstance(expr_node, ast.Call):
            fname = self.resolve_canonical_name(expr_node.func, scope_id) or dotted_name(expr_node.func) or ""
            # 1. Direct instantiation: Call to Template() or jinja2.Template() (matching resolved import)
            if fname == "jinja2.Template":
                return True
            if fname == "Template" and (self._is_jinja_imported(mod_name) or not self.imports.get(mod_name)):
                if not self._resolve_function_scope("Template", scope_id):
                    return True

            # 2. Direct constructor calls: Environment().from_string()
            if isinstance(expr_node.func, ast.Attribute) and expr_node.func.attr == "from_string":
                if self._is_jinja_env_expr(expr_node.func.value, scope_id):
                    return True
            if fname in ("jinja2.Environment.from_string", "Environment.from_string"):
                return True

            # 3. Interprocedural return: Resolving the called function's AST return statement
            func_scope = self._resolve_function_scope(fname, scope_id)
            if func_scope and func_scope not in visited:
                visited.add(func_scope)
                returns = self.returns_by_scope.get(func_scope, [])
                for r in returns:
                    if r.value and self._is_jinja_template_expr(r.value, func_scope, visited.copy()):
                        return True

        # 4. Local variable assignments pointing back to 1, 2, or 3
        if isinstance(expr_node, ast.Name):
            var_key = f"{scope_id}:{expr_node.id}"
            if var_key in visited: return False
            visited.add(var_key)
            curr = scope_id
            while curr:
                recs = self.assignments_by_scope.get((curr, expr_node.id), [])
                if recs:
                    latest = recs[-1]
                    return self._is_jinja_template_expr(latest.value_node, curr, visited.copy())
                if "." in curr and "function" in curr: curr = curr.rsplit(".", 1)[0]
                elif ":function" in curr: curr = f"{mod_name}:global"
                elif curr != f"{mod_name}:global": curr = f"{mod_name}:global"
                else: break

        return False

    def resolve_expression(self, node: ast.AST, sink: SecurityNode, scope_id: str, current_lineno: int, visited: Optional[set[str]] = None, call_context: Optional[dict[str, TaintValue]] = None) -> TaintValue:
        if visited is None: visited = set()
        if call_context is None: call_context = {}
        mod_name = scope_id.split(":")[0]
        file_name = self.file_paths.get(mod_name, f"{mod_name}.py")

        # Handle Python f-strings (ast.JoinedStr)
        if isinstance(node, ast.JoinedStr):
            part_values = []
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    part_values.append(self.resolve_expression(part.value, sink, scope_id, current_lineno, visited.copy(), call_context))
                elif isinstance(part, ast.Constant):
                    part_values.append(TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="constant"))
                else:
                    part_values.append(self.resolve_expression(part, sink, scope_id, current_lineno, visited.copy(), call_context))

            tainted_parts = [p for p in part_values if p.state == TaintState.TAINTED]
            if tainted_parts:
                best_p = max(tainted_parts, key=lambda p: p.confidence)
                return TaintValue(state=TaintState.TAINTED, source_id=best_p.source_id, confidence=best_p.confidence, path=[*best_p.path, f"{file_name}:f_string"], last_operation="f_string")
            unknown_parts = [p for p in part_values if p.state != TaintState.CLEAN]
            if unknown_parts:
                first_u = unknown_parts[0]
                return TaintValue(state=TaintState.UNKNOWN, source_id=first_u.source_id, confidence=0.50, path=[*first_u.path, f"{file_name}:f_string"], last_operation="f_string_unknown")
            return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="constant")

        if isinstance(node, ast.Call) and self.is_source_call(node, scope_id):
            source = self.get_or_create_source(node, file_name, scope_id)
            return TaintValue(state=TaintState.TAINTED, source_id=source.id, confidence=1.0, path=[source.id], last_operation=dotted_name(node.func) or "source")

        if isinstance(node, ast.Attribute):
            attr_name = dotted_name(node)
            if attr_name and self.is_var_contained(attr_name, scope_id, current_lineno, sink, visited):
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, path=[f"{file_name}:{attr_name}", "path_containment_proven"], last_operation="path_containment_proven")
            canon_attr = self.resolve_canonical_name(node, scope_id) or attr_name
            norm_attr = canon_attr[6:] if (canon_attr and canon_attr.startswith("flask.")) else canon_attr
            if norm_attr in ("request.data", "request.json", "request.query_string") or (attr_name in ("request.data", "request.json", "request.query_string")):
                loc = location(node, file_name)
                for existing in self.sources:
                    if existing.location == loc:
                        return TaintValue(state=TaintState.TAINTED, source_id=existing.id, confidence=1.0, path=[existing.id], last_operation=norm_attr)
                source_id = self.next_source_id()
                src = SecurityNode(id=source_id, node_type=NodeType.SOURCE, symbol=norm_attr, operation="HTTP_BODY_ACCESS", location=loc, metadata={"source_type": "USER_CONTROLLED"})
                self.sources.append(src)
                return TaintValue(state=TaintState.TAINTED, source_id=source_id, confidence=1.0, path=[source_id], last_operation=norm_attr)

        if isinstance(node, ast.Name):
            if self.is_var_contained(node.id, scope_id, current_lineno, sink, visited):
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, path=[f"{file_name}:{node.id}", "path_containment_proven"], last_operation="path_containment_proven")

            var_key = f"{scope_id}:{node.id}"
            if var_key in visited: return TaintValue(state=TaintState.UNKNOWN, confidence=0.50, path=[f"{file_name}:{node.id}"], last_operation="circular_reference")
            visited.add(var_key)
            current_scope = scope_id
            records_before = []
            is_param_in_context = False

            while current_scope:
                records = self.assignments_by_scope.get((current_scope, node.id), [])
                records_before = [r for r in records if r.lineno < current_lineno]
                if records_before: break
                if current_scope == scope_id and node.id in call_context:
                    is_param_in_context = True
                    break
                if "." in current_scope and "function" in current_scope: current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope: current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global": current_scope = f"{mod_name}:global"
                else: break

            base_taint = None
            if is_param_in_context:
                ctx_t = call_context[node.id]
                base_taint = TaintValue(state=ctx_t.state, source_id=ctx_t.source_id, confidence=ctx_t.confidence, path=[*ctx_t.path, f"{file_name}:{node.id}"], last_operation=f"{file_name}:{node.id}")

            if not records_before:
                if base_taint: return base_taint

                # Interprocedural argument -> parameter flow resolution (supports closures and outer scopes)
                enc_scope = scope_id
                target_func_node = None
                target_scope = None
                while enc_scope:
                    f_node = self.functions.get(enc_scope)
                    if f_node and any(a.arg == node.id for a in f_node.args.args):
                        target_func_node = f_node
                        target_scope = enc_scope
                        break
                    if "." in enc_scope:
                        enc_scope = enc_scope.rsplit(".", 1)[0]
                    else:
                        break

                if target_func_node and target_scope:
                    param_names = [a.arg for a in target_func_node.args.args]
                    param_idx = param_names.index(node.id)
                    call_sites = self.call_sites_by_target.get(target_scope, [])
                    if call_sites:
                        caller_taints = []
                        for call_node, caller_scope, call_lineno in call_sites:
                            arg_expr = None
                            for kw in getattr(call_node, "keywords", []):
                                if kw.arg == node.id:
                                    arg_expr = kw.value
                                    break
                            if arg_expr is None:
                                pos_idx = param_idx
                                if param_names and param_names[0] in ("self", "cls"):
                                    pos_idx = param_idx - 1
                                if 0 <= pos_idx < len(call_node.args):
                                    arg_expr = call_node.args[pos_idx]

                            if arg_expr is not None:
                                call_site_key = f"param_flow:{target_scope}:{node.id}:{caller_scope}:{call_lineno}"
                                if call_site_key not in visited:
                                    v_copy = visited.copy()
                                    v_copy.add(call_site_key)
                                    caller_taint = self.resolve_expression(arg_expr, sink, caller_scope, call_lineno, v_copy)
                                    caller_taints.append(caller_taint)

                        # If any caller is confirmed tainted, preserve confirmed taint
                        tainted_callers = [t for t in caller_taints if t.state == TaintState.TAINTED]
                        if tainted_callers:
                            best_t = max(tainted_callers, key=lambda t: t.confidence)
                            return TaintValue(state=TaintState.TAINTED, source_id=best_t.source_id, confidence=best_t.confidence, path=[*best_t.path, f"{file_name}:{node.id}"], last_operation=f"param:{node.id}")
                        elif caller_taints:
                            merged = self.merge_taints(caller_taints, f"{file_name}:{node.id}")
                            if merged.state != TaintState.CLEAN:
                                return merged

                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"untracked:{node.id}")

            last_uncond_idx = -1
            for idx, r in enumerate(records_before):
                if not r.is_conditional: last_uncond_idx = idx

            if last_uncond_idx != -1:
                reaching = [records_before[last_uncond_idx]] + [r for r in records_before[last_uncond_idx + 1:] if r.is_conditional]
                base_taint = None 
            else:
                reaching = records_before

            if len(reaching) == 1 and not reaching[0].is_conditional and not base_taint:
                target_rec = reaching[0]
                resolved = self.resolve_expression(target_rec.value_node, sink, target_rec.scope_id, target_rec.lineno, visited, call_context)
                return TaintValue(state=resolved.state, source_id=resolved.source_id, confidence=resolved.confidence, path=[*resolved.path, f"{file_name}:{node.id}"], last_operation=f"variable:{node.id}")
            else:
                resolved_list = [self.resolve_expression(r.value_node, sink, r.scope_id, r.lineno, visited.copy(), call_context) for r in reaching]
                if base_taint: resolved_list.append(base_taint)
                return self.merge_taints(resolved_list, f"{file_name}:{node.id}")

        if isinstance(node, ast.Call):
            canon_name = self.resolve_canonical_name(node.func, scope_id)
            function_name = canon_name or dotted_name(node.func) or "<unknown_function>"
            arg_values = [self.resolve_expression(arg, sink, scope_id, current_lineno, visited.copy(), call_context) for arg in node.args]

            if function_name in SANITIZER_REGISTRY and self.sanitizer_protects_context(function_name, sink):
                first_tainted = next((arg for arg in arg_values if arg.state != TaintState.CLEAN), None)
                if first_tainted:
                    return TaintValue(state=TaintState.CLEAN, source_id=None, confidence=1.0, path=[*first_tainted.path, f"{file_name}:{function_name}()"], last_operation=f"sanitized:{function_name}")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=function_name)

            if function_name in SANITIZER_REGISTRY:
                first_tainted = next((arg for arg in arg_values if arg.state != TaintState.CLEAN), None)
                if first_tainted:
                    return TaintValue(state=TaintState.TAINTED, source_id=first_tainted.source_id, confidence=0.50, path=[*first_tainted.path, f"{file_name}:{function_name}()"], last_operation=f"irrelevant_sanitizer:{function_name}")

            # Receiver .get() / .getlist() / .pop() on tainted dictionary or object (e.g. payload = request.get_json(); payload.get("x"))
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "getlist", "pop"):
                recv_taint = self.resolve_expression(node.func.value, sink, scope_id, current_lineno, visited.copy(), call_context)
                if recv_taint.state != TaintState.CLEAN and recv_taint.source_id:
                    return TaintValue(state=recv_taint.state, source_id=recv_taint.source_id, confidence=recv_taint.confidence, path=[*recv_taint.path, f"{file_name}:{node.func.attr}()"], last_operation=f"{node.func.attr}()")

            # Format calls on string literals or templates
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format" and self._is_string_expr(node.func.value, scope_id):
                format_args = [self.resolve_expression(arg, sink, scope_id, current_lineno, visited.copy(), call_context) for arg in node.args]
                for kw in getattr(node, "keywords", []):
                    format_args.append(self.resolve_expression(kw.value, sink, scope_id, current_lineno, visited.copy(), call_context))
                tainted_args = [a for a in format_args if a.state == TaintState.TAINTED]
                if tainted_args:
                    best_arg = max(tainted_args, key=lambda a: a.confidence)
                    return TaintValue(state=TaintState.TAINTED, source_id=best_arg.source_id, confidence=best_arg.confidence, path=[*best_arg.path, f"{file_name}:format()"], last_operation="format")
                unknown_args = [a for a in format_args if a.state != TaintState.CLEAN]
                if unknown_args:
                    first_u = unknown_args[0]
                    return TaintValue(state=TaintState.UNKNOWN, source_id=first_u.source_id, confidence=0.50, path=[*first_u.path, f"{file_name}:format()"], last_operation="format")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="format")

            # Path constructor (Path or pathlib.Path)
            if function_name in ("Path", "pathlib.Path"):
                if node.args:
                    arg_taint = self.resolve_expression(node.args[0], sink, scope_id, current_lineno, visited.copy(), call_context)
                    if arg_taint.state == TaintState.TAINTED:
                        return TaintValue(state=TaintState.TAINTED, source_id=arg_taint.source_id, confidence=arg_taint.confidence, path=[*arg_taint.path, f"{file_name}:Path()"], last_operation="path_construct")
                    elif arg_taint.state == TaintState.UNKNOWN:
                        return TaintValue(state=TaintState.UNKNOWN, source_id=arg_taint.source_id, confidence=0.50, path=[*arg_taint.path, f"{file_name}:Path()"], last_operation="path_construct")
                    else:
                        return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="path_construct")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="path_construct")

            # Path.resolve() call
            if isinstance(node.func, ast.Attribute) and node.func.attr == "resolve":
                recv_taint = self.resolve_expression(node.func.value, sink, scope_id, current_lineno, visited.copy(), call_context)
                if recv_taint.state == TaintState.TAINTED:
                    return TaintValue(state=TaintState.TAINTED, source_id=recv_taint.source_id, confidence=recv_taint.confidence, path=[*recv_taint.path, f"{file_name}:resolve()"], last_operation="path_resolve")
                elif recv_taint.state == TaintState.UNKNOWN:
                    return TaintValue(state=TaintState.UNKNOWN, source_id=recv_taint.source_id, confidence=0.50, path=[*recv_taint.path, f"{file_name}:resolve()"], last_operation="path_resolve")
                else:
                    return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="path_resolve")

            # os.path.join
            if function_name in ("os.path.join", "posixpath.join", "ntpath.join"):
                arg_taints = [self.resolve_expression(arg, sink, scope_id, current_lineno, visited.copy(), call_context) for arg in node.args]
                tainted_args = [a for a in arg_taints if a.state == TaintState.TAINTED]
                if tainted_args:
                    best_arg = max(tainted_args, key=lambda a: a.confidence)
                    combined_path = []
                    for a in arg_taints:
                        if a.path: combined_path.extend(a.path)
                    combined_path.append(f"{file_name}:os.path.join()")
                    return TaintValue(state=TaintState.TAINTED, source_id=best_arg.source_id, confidence=best_arg.confidence, path=combined_path, last_operation="os.path.join")
                unknown_args = [a for a in arg_taints if a.state != TaintState.CLEAN]
                if unknown_args:
                    first_u = unknown_args[0]
                    return TaintValue(state=TaintState.UNKNOWN, source_id=first_u.source_id, confidence=0.50, path=[*first_u.path, f"{file_name}:os.path.join()"], last_operation="os.path.join")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="os.path.join")

            # os.path.normpath (does not sanitize directory traversal)
            if function_name in ("os.path.normpath", "posixpath.normpath", "ntpath.normpath"):
                if node.args:
                    arg_taint = self.resolve_expression(node.args[0], sink, scope_id, current_lineno, visited.copy(), call_context)
                    if arg_taint.state == TaintState.TAINTED:
                        return TaintValue(state=TaintState.TAINTED, source_id=arg_taint.source_id, confidence=arg_taint.confidence, path=[*arg_taint.path, f"{file_name}:os.path.normpath()"], last_operation="os.path.normpath")
                    elif arg_taint.state == TaintState.UNKNOWN:
                        return TaintValue(state=TaintState.UNKNOWN, source_id=arg_taint.source_id, confidence=0.50, path=[*arg_taint.path, f"{file_name}:os.path.normpath()"], last_operation="os.path.normpath")
                    else:
                        return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="os.path.normpath")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="os.path.normpath")

            # Builtin compile(...) transformation
            if function_name in ("compile", "builtins.compile"):
                source_expr = None
                if node.args:
                    source_expr = node.args[0]
                else:
                    for kw in getattr(node, "keywords", []):
                        if kw.arg == "source":
                            source_expr = kw.value
                            break

                if source_expr is not None:
                    arg_taint = self.resolve_expression(source_expr, sink, scope_id, current_lineno, visited.copy(), call_context)
                    if arg_taint.state == TaintState.TAINTED:
                        return TaintValue(state=TaintState.TAINTED, source_id=arg_taint.source_id, confidence=arg_taint.confidence, path=[*arg_taint.path, f"{file_name}:compile()"], last_operation="compile")
                    elif arg_taint.state == TaintState.UNKNOWN:
                        return TaintValue(state=TaintState.UNKNOWN, source_id=arg_taint.source_id, confidence=0.50, path=[*arg_taint.path, f"{file_name}:compile()"], last_operation="compile")
                    else:
                        return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="compile")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="compile")

            # Jinja2 Template(...) constructor
            if function_name == "jinja2.Template" or (function_name == "Template" and (self._is_jinja_imported(mod_name) or not self.imports.get(mod_name)) and not self._resolve_function_scope("Template", scope_id)):
                source_expr = None
                if node.args:
                    source_expr = node.args[0]
                else:
                    for kw in getattr(node, "keywords", []):
                        if kw.arg in ("source", "template"):
                            source_expr = kw.value
                            break

                if source_expr is not None:
                    arg_taint = self.resolve_expression(source_expr, sink, scope_id, current_lineno, visited.copy(), call_context)
                    if arg_taint.state == TaintState.TAINTED:
                        return TaintValue(state=TaintState.TAINTED, source_id=arg_taint.source_id, confidence=arg_taint.confidence, path=[*arg_taint.path, f"{file_name}:Template()"], last_operation="template_construct")
                    elif arg_taint.state == TaintState.UNKNOWN:
                        return TaintValue(state=TaintState.UNKNOWN, source_id=arg_taint.source_id, confidence=0.50, path=[*arg_taint.path, f"{file_name}:Template()"], last_operation="template_construct")
                    else:
                        return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="template_construct")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="template_construct")

            # Jinja2 Environment.from_string(...)
            if (isinstance(node.func, ast.Attribute) and node.func.attr == "from_string" and self._is_jinja_env_expr(node.func.value, scope_id)) or function_name in ("Environment.from_string", "jinja2.Environment.from_string"):
                source_expr = None
                if node.args:
                    source_expr = node.args[0]
                else:
                    for kw in getattr(node, "keywords", []):
                        if kw.arg in ("source", "template", "s"):
                            source_expr = kw.value
                            break

                if source_expr is not None:
                    arg_taint = self.resolve_expression(source_expr, sink, scope_id, current_lineno, visited.copy(), call_context)
                    if arg_taint.state == TaintState.TAINTED:
                        return TaintValue(state=TaintState.TAINTED, source_id=arg_taint.source_id, confidence=arg_taint.confidence, path=[*arg_taint.path, f"{file_name}:from_string()"], last_operation="template_from_string")
                    elif arg_taint.state == TaintState.UNKNOWN:
                        return TaintValue(state=TaintState.UNKNOWN, source_id=arg_taint.source_id, confidence=0.50, path=[*arg_taint.path, f"{file_name}:from_string()"], last_operation="template_from_string")
                    else:
                        return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="template_from_string")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="template_from_string")

            func_scope = self._resolve_function_scope(function_name, scope_id)
            if func_scope:
                call_sig = f"call:{func_scope}:{current_lineno}"
                if call_sig in visited: return TaintValue(state=TaintState.UNKNOWN, confidence=0.50, path=[f"recursive_call:{function_name}"], last_operation="recursion")
                visited.add(call_sig)

                func_node = self.functions[func_scope]
                param_names = [arg.arg for arg in func_node.args.args]
                new_call_context = {}
                for i, p_name in enumerate(param_names):
                    if i < len(arg_values): new_call_context[p_name] = arg_values[i]
                    else: new_call_context[p_name] = TaintValue(state=TaintState.CLEAN, confidence=1.0)

                # Process keyword arguments for interprocedural call context
                for kw in getattr(node, "keywords", []):
                    if kw.arg and kw.arg in param_names:
                        new_call_context[kw.arg] = self.resolve_expression(kw.value, sink, scope_id, current_lineno, visited.copy(), call_context)

                returns = self.returns_by_scope.get(func_scope, [])
                if not returns: return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"void_return:{function_name}")

                ret_taints = []
                for ret in returns:
                    if ret.value: ret_taints.append(self.resolve_expression(ret.value, sink, func_scope, ret.lineno, visited.copy(), new_call_context))
                    else: ret_taints.append(TaintValue(state=TaintState.CLEAN, confidence=1.0))

                callee_mod = func_scope.split(":")[0]
                callee_file = self.file_paths.get(callee_mod, "unknown.py")
                callee_func = func_scope.split(":")[-1]

                merged_ret = self.merge_taints(ret_taints, f"return")
                if merged_ret.state != TaintState.CLEAN:
                    src_id = merged_ret.source_id
                    if not src_id:
                        for a in arg_values:
                            if a.source_id: src_id = a.source_id; break
                        if not src_id:
                            for kw in new_call_context.values():
                                if kw.source_id: src_id = kw.source_id; break
                    return TaintValue(state=merged_ret.state, source_id=src_id, confidence=merged_ret.confidence, path=[*merged_ret.path, f"return_from:{callee_file}:{callee_func}"], last_operation=f"call:{function_name}")
                return merged_ret

            tainted_args = [arg for arg in arg_values if arg.state != TaintState.CLEAN]
            # Check keyword arguments for unknown wrappers as well
            for kw in getattr(node, "keywords", []):
                kw_val = self.resolve_expression(kw.value, sink, scope_id, current_lineno, visited.copy(), call_context)
                if kw_val.state != TaintState.CLEAN:
                    tainted_args.append(kw_val)
            if not tainted_args: return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=function_name)

            first_tainted = tainted_args[0]
            return TaintValue(state=TaintState.UNKNOWN, source_id=first_tainted.source_id, confidence=0.50, path=[*first_tainted.path, f"{file_name}:{function_name}()"], last_operation=f"unknown_wrapper:{function_name}")

        if isinstance(node, ast.Subscript):
            val_taint = self.resolve_expression(node.value, sink, scope_id, current_lineno, visited.copy(), call_context)
            if val_taint.state != TaintState.CLEAN and val_taint.source_id:
                return TaintValue(state=val_taint.state, source_id=val_taint.source_id, confidence=val_taint.confidence, path=[*val_taint.path, f"{file_name}:subscript"], last_operation="subscript")
            canon_val = self.resolve_canonical_name(node.value, scope_id) or dotted_name(node.value)
            norm_val = canon_val[6:] if (canon_val and canon_val.startswith("flask.")) else canon_val
            dname_val = dotted_name(node.value)
            if norm_val in ("request.args", "request.form", "request.values", "request.headers", "request.cookies") or dname_val in ("request.args", "request.form", "request.values", "request.headers", "request.cookies"):
                loc = location(node, file_name)
                for existing in self.sources:
                    if existing.location == loc:
                        return TaintValue(state=TaintState.TAINTED, source_id=existing.id, confidence=1.0, path=[existing.id], last_operation=f"{norm_val}[]")
                source_id = self.next_source_id()
                src = SecurityNode(id=source_id, node_type=NodeType.SOURCE, symbol=f"{norm_val}[...]", operation="HTTP_PARAMETER_ACCESS", location=loc, metadata={"source_type": "USER_CONTROLLED"})
                self.sources.append(src)
                return TaintValue(state=TaintState.TAINTED, source_id=source_id, confidence=1.0, path=[source_id], last_operation=f"{norm_val}[]")
            if val_taint.state == TaintState.CLEAN:
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="subscript")

        if isinstance(node, (ast.Constant, ast.List, ast.Tuple, ast.Set, ast.Dict)): return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="constant")
        if isinstance(node, ast.BinOp):
            left = self.resolve_expression(node.left, sink, scope_id, current_lineno, visited.copy(), call_context)
            right = self.resolve_expression(node.right, sink, scope_id, current_lineno, visited.copy(), call_context)
            if left.state == TaintState.CLEAN and right.state == TaintState.CLEAN: return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="binary_op")

            is_str_add = isinstance(node.op, ast.Add) and (self._is_string_expr(node.left, scope_id) or self._is_string_expr(node.right, scope_id))
            is_str_mod = isinstance(node.op, ast.Mod) and self._is_string_expr(node.left, scope_id)
            is_path_div = isinstance(node.op, ast.Div) and (self._is_path_expr(node.left, scope_id) or self._is_path_expr(node.right, scope_id))

            if is_str_add or is_str_mod or is_path_div:
                if left.state == TaintState.TAINTED or right.state == TaintState.TAINTED:
                    best_t = left if left.state == TaintState.TAINTED else right
                    if left.state == TaintState.TAINTED and right.state == TaintState.TAINTED:
                        best_t = left if left.confidence >= right.confidence else right
                    op_label = "path_join" if is_path_div else "binary_op"
                    combined_path = [*left.path, *right.path, op_label]
                    return TaintValue(state=TaintState.TAINTED, source_id=best_t.source_id, confidence=best_t.confidence, path=combined_path, last_operation=op_label)
                else:
                    src_id = left.source_id or right.source_id
                    op_label = "path_join" if is_path_div else "binary_op"
                    combined_path = [*left.path, *right.path, op_label]
                    return TaintValue(state=TaintState.UNKNOWN, source_id=src_id, confidence=0.50, path=combined_path, last_operation=op_label)

            src_id = left.source_id or right.source_id
            return TaintValue(state=TaintState.TAINTED if (left.state == TaintState.TAINTED and right.state == TaintState.TAINTED) else TaintState.UNKNOWN, source_id=src_id, confidence=min(left.confidence, right.confidence), path=[*left.path, *right.path, "binary_op"], last_operation="binary_op")
        return TaintValue(state=TaintState.UNKNOWN, confidence=0.50, last_operation="unknown_expression")

    def analyze(self):
        for mod_name, tree in self.modules.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names: self.imports[mod_name][alias.asname or alias.name] = alias.name
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if getattr(node, 'level', 0) > 0:
                        parts = mod_name.split(".")
                        base = ".".join(parts[:-node.level]) if len(parts) > node.level else ""
                        module = f"{base}.{module}" if base and module else base or module
                    for alias in node.names: self.imports[mod_name][alias.asname or alias.name] = f"{module}.{alias.name}" if module else alias.name
        for mod_name, tree in self.modules.items():
            self.collect_statements(tree.body, scope_id=f"{mod_name}:global", is_conditional=False)

        # Index call sites by target function scope
        for call_node, caller_scope, lineno in self.raw_calls:
            canon_name = self.resolve_canonical_name(call_node.func, caller_scope)
            fname = canon_name or dotted_name(call_node.func)
            if fname:
                func_scope = self._resolve_function_scope(fname, caller_scope)
                if func_scope:
                    self.call_sites_by_target.setdefault(func_scope, []).append((call_node, caller_scope, lineno))

        for mod_name, tree in self.modules.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and self.is_source_call(node, f"{mod_name}:global"):
                    self.get_or_create_source(node, self.file_paths.get(mod_name, "unknown.py"), f"{mod_name}:global")
        for record in self.sink_records:
            sink = record.security_node
            target_expr = None
            if isinstance(record.node.func, ast.Attribute) and (record.node.func.attr in {"read_text", "read_bytes", "write_text", "write_bytes"} or (record.node.func.attr == "open" and self._is_path_expr(record.node.func.value, record.scope_id))):
                target_expr = record.node.func.value
            elif isinstance(record.node.func, ast.Attribute) and record.node.func.attr == "render":
                if self._is_jinja_template_expr(record.node.func.value, record.scope_id):
                    target_expr = record.node.func.value
                else:
                    if sink in self.sinks:
                        self.sinks.remove(sink)
                    continue
            elif record.node.args:
                target_expr = record.node.args[0]
            elif getattr(record.node, "keywords", []):
                for kw in record.node.keywords:
                    if kw.arg in ("source", "template", "s"):
                        target_expr = kw.value
                        break
            else:
                continue

            taint = self.resolve_expression(target_expr, sink, record.scope_id, record.lineno)
            full_path_str = " -> ".join(taint.path) if taint.path else taint.last_operation
            if taint.state == TaintState.TAINTED:
                kind = "CONFIRMED_DATA_FLOW" if taint.confidence >= 1.0 else "POTENTIAL_DATA_FLOW"
                self.edges.append(DataFlowEdge(source_id=taint.source_id or "UNKNOWN", target_id=sink.id, kind=kind, confidence=taint.confidence, transform=full_path_str))
            elif taint.state == TaintState.UNKNOWN:
                self.edges.append(DataFlowEdge(source_id=taint.source_id or "UNKNOWN", target_id=sink.id, kind="POTENTIAL_DATA_FLOW", confidence=0.50, transform=full_path_str))
        return self.sources, self.sinks, self.edges