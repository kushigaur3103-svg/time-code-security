from __future__ import annotations
import ast
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

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
}

SANITIZER_REGISTRY = {
    "html.escape": {"protected_cwes": {"CWE-79"}, "protected_sinks": {"XSS"}},
    "safe_eval_input": {"protected_cwes": {"CWE-95"}, "protected_sinks": {"CODE_EXECUTION"}},
    "secure_path_join": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL"}},
}

SINK_REGISTRY = {
    "eval": {"operation": "ARBITRARY_CODE_EXECUTION", "category": "CODE_EXECUTION", "cwe": "CWE-95"},
    "os.system": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.run": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.call": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.Popen": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "pickle.loads": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},
    "pickle.load": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},
    "open": {"operation": "FILE_ACCESS", "category": "PATH_TRAVERSAL", "cwe": "CWE-22"},
    "pathlib.Path": {"operation": "FILE_ACCESS", "category": "PATH_TRAVERSAL", "cwe": "CWE-22"},
    "render_template_string": {"operation": "TEMPLATE_EVALUATION", "category": "SSTI", "cwe": "CWE-1336"},
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
        if canon in SOURCE_REGISTRY: return True
        return dotted_name(node.func) in SOURCE_REGISTRY

    def get_or_create_source(self, node: ast.Call, file_path: str, scope_id: str = "") -> SecurityNode:
        loc = location(node, file_path)
        for existing in self.sources:
            if existing.location == loc: return existing
        source_id = self.next_source_id()
        canon_name = self.resolve_canonical_name(node.func, scope_id) if scope_id else None
        name = dotted_name(node.func)
        lookup_name = canon_name if (canon_name and canon_name in SOURCE_REGISTRY) else name
        meta = SOURCE_REGISTRY.get(lookup_name, {})
        source = SecurityNode(
            id=source_id, node_type=NodeType.SOURCE, symbol=f"{lookup_name}(...)",
            operation=meta.get("operation", "USER_INPUT_ACCESS"), location=loc,
            metadata={"source_type": meta.get("source_type", "USER_CONTROLLED")}
        )
        self.sources.append(source)
        return source

    def is_sink_call(self, node: ast.AST, scope_id: str = "") -> bool:
        if not isinstance(node, ast.Call): return False
        canon = self.resolve_canonical_name(node.func, scope_id) if scope_id else dotted_name(node.func)
        if canon and canon in SINK_REGISTRY: return True
        if canon and canon.endswith(".execute"): return True
        name = dotted_name(node.func)
        if name and name in SINK_REGISTRY: return True
        if name and name.endswith(".execute"): return True
        return False

    def check_sink_safety(self, node: ast.Call, sink_name: str) -> bool:
        if sink_name in ["subprocess.run", "subprocess.call", "subprocess.Popen"]:
            shell_kw = next((kw.value.value for kw in getattr(node, 'keywords', []) if kw.arg == "shell" and isinstance(kw.value, ast.Constant)), None)
            if shell_kw is False: return True
            if shell_kw is None and node.args and isinstance(node.args[0], ast.List): return True
        if sink_name and sink_name.endswith(".execute"):
            if len(node.args) > 1 or getattr(node, 'keywords', []): return True
        return False

    def get_or_create_sink(self, node: ast.Call, file_path: str, scope_id: str = "") -> SecurityNode:
        loc = location(node, file_path)
        for existing in self.sinks:
            if existing.location == loc: return existing
        sink_id = self.next_sink_id()
        canon_name = self.resolve_canonical_name(node.func, scope_id) if scope_id else None
        name = dotted_name(node.func) or "sink"
        lookup_name = canon_name if (canon_name and canon_name in SINK_REGISTRY) else name
        meta = SINK_REGISTRY.get(lookup_name, {})
        if not meta and (name.endswith(".execute") or (canon_name and canon_name.endswith(".execute"))):
            meta = {"operation": "SQL_EXECUTION", "category": "SQL_INJECTION", "cwe": "CWE-89"}
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
            if isinstance(subnode, ast.Call) and self.is_sink_call(subnode, scope_id):
                canon_name = self.resolve_canonical_name(subnode.func, scope_id) or dotted_name(subnode.func) or ""
                if not self.check_sink_safety(subnode, canon_name):
                    sink_node = self.get_or_create_sink(subnode, file_path, scope_id)
                    self.sink_records.append(SinkRecord(node=subnode, security_node=sink_node, lineno=getattr(subnode, "lineno", lineno), scope_id=scope_id))

    def resolve_expression(self, node: ast.AST, sink: SecurityNode, scope_id: str, current_lineno: int, visited: Optional[set[str]] = None, call_context: Optional[dict[str, TaintValue]] = None) -> TaintValue:
        if visited is None: visited = set()
        if call_context is None: call_context = {}
        mod_name = scope_id.split(":")[0]
        file_name = self.file_paths.get(mod_name, f"{mod_name}.py")

        if isinstance(node, ast.Call) and self.is_source_call(node, scope_id):
            source = self.get_or_create_source(node, file_name, scope_id)
            return TaintValue(state=TaintState.TAINTED, source_id=source.id, confidence=1.0, path=[source.id], last_operation=dotted_name(node.func) or "source")

        if isinstance(node, ast.Name):
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

        if isinstance(node, (ast.Constant, ast.List, ast.Tuple, ast.Set, ast.Dict)): return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="constant")
        if isinstance(node, ast.BinOp):
            left = self.resolve_expression(node.left, sink, scope_id, current_lineno, visited.copy(), call_context)
            right = self.resolve_expression(node.right, sink, scope_id, current_lineno, visited.copy(), call_context)
            if left.state == TaintState.CLEAN and right.state == TaintState.CLEAN: return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="binary_op")
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
            if not record.node.args: continue
            
            taint = self.resolve_expression(record.node.args[0], sink, record.scope_id, record.lineno)
            full_path_str = " -> ".join(taint.path) if taint.path else taint.last_operation
            if taint.state == TaintState.TAINTED:
                kind = "CONFIRMED_DATA_FLOW" if taint.confidence >= 1.0 else "POTENTIAL_DATA_FLOW"
                self.edges.append(DataFlowEdge(source_id=taint.source_id or "UNKNOWN", target_id=sink.id, kind=kind, confidence=taint.confidence, transform=full_path_str))
            elif taint.state == TaintState.UNKNOWN:
                self.edges.append(DataFlowEdge(source_id=taint.source_id or "UNKNOWN", target_id=sink.id, kind="POTENTIAL_DATA_FLOW", confidence=0.50, transform=full_path_str))
        return self.sources, self.sinks, self.edges