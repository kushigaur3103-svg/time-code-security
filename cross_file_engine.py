"""
TimeCodeSecurity (TCS) - Phase 4: Inter-Procedural / Cross-File Taint Engine
Stitches global symbol index and function taint contracts to detect multi-file exploit paths.
"""

from __future__ import annotations

import ast
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from symbol_indexer import GlobalSymbolIndex, SymbolDefinition
from function_summarizer import KNOWN_SANITIZERS, FunctionSummarizer, FunctionSummary, ParamSinkEdge


# Common web entrypoint sources
TAINT_SOURCE_PATTERNS = {
    "request.GET", "request.POST", "request.data", "request.body",
    "request.args", "request.form", "request.params", "request.headers",
    "request.COOKIES", "request.query_params"
}


_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _ordered_nodes(root: ast.AST, skip_scopes: bool = False):
    """Yield nodes in source (pre-order) sequence so assignment state is chronological.

    With skip_scopes, nested function/class bodies are not descended into, keeping the
    traversal to the root node's own lexical scope.
    """
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        if skip_scopes and node is not root and isinstance(node, _SCOPES):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _contracted_functions(tree: ast.AST):
    """Yield (node, qualname) pairs using the same keys FunctionSummarizer indexes by."""
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield stmt, stmt.name
        elif isinstance(stmt, ast.ClassDef):
            for item in stmt.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield item, f"{stmt.name}.{item.name}"


def _name_uses(expr: ast.expr) -> Set[str]:
    """Names an expression reads, excluding the callee identifiers of the calls inside it.

    `int(record_id)` reads one value, `record_id`; without this the sanitizer's own name
    would count as a second input and block an argument that is provably cleaned.
    """
    excluded = set()
    for node in ast.walk(expr):
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
            excluded.update(id(child) for child in ast.walk(node.func))
    return {
        node.id
        for node in ast.walk(expr)
        if isinstance(node, ast.Name) and id(node) not in excluded
    }


@dataclass(slots=True)
class TraceHop:
    """One labelled node in an exploit path: role is SOURCE, ROUTE or SINK."""
    role: str
    file_path: str
    lineno: int
    label: str


@dataclass(slots=True)
class CrossFileFinding:
    cwe: str
    caller_file: str
    caller_lineno: int
    caller_func: str
    callee_file: str
    callee_func: str
    callee_sink_name: str
    callee_sink_lineno: int
    tainted_param: str
    flow_trace: List[TraceHop] = field(default_factory=list)


class CrossFileTaintEngine:
    """Pass 2: Traces data flow across modules using precomputed contracts."""

    def __init__(self, root_dir: str | Path):
        self.root_dir = Path(root_dir).resolve()
        self.indexer = GlobalSymbolIndex(self.root_dir)
        self.summarizer: Optional[FunctionSummarizer] = None
        self.contracts: dict[tuple[str, str], FunctionSummary] = {}
        self.findings: list[CrossFileFinding] = []
        # ParamSinkEdge carries no file field, so transitively lifted edges record the
        # module that actually owns the sink here: (mod, qualname, param_idx, sink, lineno) -> path.
        self.sink_origins: dict[tuple[str, str, int, str, int], str] = {}
        # Forwarding call sites between the caller and the ultimate sink, outermost first:
        # (mod, qualname, param_idx, sink, lineno) -> [(file, lineno, callee label), ...].
        self.sink_route: dict[tuple[str, str, int, str, int], List[tuple[str, int, str]]] = {}
        # Cached per-callee decorator analysis: (mod, qualname) -> sanitised parameter indices.
        self._decorator_slots: dict[tuple[str, str], Set[int]] = {}

    def run(self) -> list[CrossFileFinding]:
        # 1. Build Index & Contracts
        self.indexer.build()
        self.summarizer = FunctionSummarizer(self.indexer)
        self.contracts = self.summarizer.build_all_summaries()
        self._propagate_transitive_sink_contracts()

        # 2. Analyze Callers across all modules
        for mod_name, mod_idx in self.indexer.modules.items():
            tree = self.indexer._ast_cache.get(mod_name)
            if not tree:
                continue
            self._analyze_module_calls(mod_name, mod_idx.file_path, tree)

        return self.findings

    def _propagate_transitive_sink_contracts(self) -> None:
        """Fixed-point lift of callee sink contracts into pass-through callers.

        A function that forwards one of its own parameters straight into a callee argument
        inherits that callee's sink obligations, so a 3-layer chain (controller -> service
        -> repo) becomes visible from the outermost call site. Only direct parameter
        forwarding propagates, which keeps the lift alias-free and terminating.
        """
        while True:
            changed = False
            for mod_name, mod_idx in self.indexer.modules.items():
                tree = self.indexer._ast_cache.get(mod_name)
                if not tree:
                    continue
                for func_node, qualname in _contracted_functions(tree):
                    summary = self.contracts.get((mod_name, qualname))
                    if summary is None or not summary.params:
                        continue
                    if self._lift_callee_sinks(mod_name, summary, func_node):
                        changed = True
            if not changed:
                return

    def _lift_callee_sinks(
        self,
        caller_mod: str,
        summary: FunctionSummary,
        func_node: ast.AST,
    ) -> bool:
        param_index = {name: idx for idx, name in enumerate(summary.params)}
        known = {
            (edge.param_idx, edge.sink_cwe, edge.sink_name, edge.lineno)
            for edge in summary.param_sinks
        }
        added = False
        receivers = self._instance_bindings(caller_mod, summary.qualname, func_node)

        for call in (n for n in ast.walk(func_node) if isinstance(n, ast.Call)):
            resolved = self._resolve_call_contract(caller_mod, call, receivers)
            if resolved is None:
                continue
            callee_mod, callee_summary = resolved
            if not callee_summary.param_sinks:
                continue
            # A slot the callee's decorator sanitises carries no sink obligation, so it must
            # not lift either; otherwise the same leak would reappear one layer further out.
            neutralized = self._decorator_sanitized_params(callee_mod, callee_summary)

            for arg_idx, arg in sorted(
                self._bind_call_args(
                    call,
                    callee_summary.params,
                    self._receiver_offset(caller_mod, call, callee_summary),
                ).items()
            ):
                if arg_idx in neutralized:
                    continue
                if not isinstance(arg, ast.Name):
                    continue
                caller_param_idx = param_index.get(arg.id)
                if caller_param_idx is None:
                    continue

                for edge in callee_summary.param_sinks:
                    if edge.param_idx != arg_idx:
                        continue
                    key = (caller_param_idx, edge.sink_cwe, edge.sink_name, edge.lineno)
                    if key in known:
                        continue
                    known.add(key)
                    summary.param_sinks.append(ParamSinkEdge(
                        param_idx=caller_param_idx,
                        param_name=summary.params[caller_param_idx],
                        sink_cwe=edge.sink_cwe,
                        sink_name=edge.sink_name,
                        lineno=edge.lineno,
                    ))
                    origin_key = (callee_mod, callee_summary.qualname,
                                  edge.param_idx, edge.sink_name, edge.lineno)
                    lifted_key = (caller_mod, summary.qualname, caller_param_idx,
                                  edge.sink_name, edge.lineno)
                    self.sink_origins[lifted_key] = self.sink_origins.get(
                        origin_key, callee_summary.file_path
                    )
                    self.sink_route[lifted_key] = [
                        (summary.file_path, call.lineno,
                         f"{caller_mod}.{summary.qualname}")
                    ] + self.sink_route.get(origin_key, [])
                    added = True

        return added

    def sanitized_sink_locations(self) -> Set[tuple[str, int]]:
        """Call sites whose locally-assigned arguments were all neutralized by a
        cross-file sanitizer contract.

        Single-file scanners cannot see the callee contract, so they report these sites
        as injectable. The returned keys are (resolved file path, call lineno).
        """
        suppressed: Set[tuple[str, int]] = set()
        if not any(summary.is_sanitizer for summary in self.contracts.values()):
            return suppressed
        for mod_name, mod_idx in self.indexer.modules.items():
            tree = self.indexer._ast_cache.get(mod_name)
            if not tree:
                continue
            file_key = str(Path(mod_idx.file_path).resolve())
            qualnames = {id(node): name for node, name in _contracted_functions(tree)}
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    suppressed.update(
                        self._sanitized_sites(
                            mod_name, file_key, node, qualnames.get(id(node), node.name)
                        )
                    )
        return suppressed

    def _sanitized_sites(
        self,
        mod_name: str,
        file_key: str,
        func_node: ast.AST,
        caller_func: str,
    ) -> Set[tuple[str, int]]:
        sites: Set[tuple[str, int]] = set()
        assigned: Set[str] = set()
        sanitized: Set[str] = set()
        receivers = self._instance_bindings(mod_name, caller_func, func_node)

        for node in _ordered_nodes(func_node):
            if isinstance(node, ast.Assign):
                summary = self._resolve_call_summary(mod_name, node.value, receivers)
                neutralized = bool(summary and summary.is_sanitizer)
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigned.add(target.id)
                        if neutralized:
                            sanitized.add(target.id)
                        else:
                            sanitized.discard(target.id)

            elif isinstance(node, ast.Call):
                relevant = {
                    n.id
                    for n in ast.walk(node)
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in assigned
                }
                if relevant and relevant <= sanitized:
                    sites.add((file_key, node.lineno))

        return sites

    def _analyze_module_calls(self, mod_name: str, file_path: Path, tree: ast.AST) -> None:
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._analyze_function_body(mod_name, str(file_path), stmt.name, stmt)
            elif isinstance(stmt, ast.ClassDef):
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._analyze_function_body(mod_name, str(file_path), f"{stmt.name}.{item.name}", item)

    def _analyze_function_body(
        self,
        caller_mod: str,
        caller_file: str,
        caller_func_name: str,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        # Step A: Identify tainted variables inside caller function
        tainted_vars: set[str] = set()

        # Check function parameters (e.g. 'request')
        for arg in func_node.args.args:
            if arg.arg in ("request", "req"):
                tainted_vars.add(arg.arg)

        # Track local assignments from sources
        receivers = self._instance_bindings(caller_mod, caller_func_name, func_node)
        for stmt in func_node.body:
            if isinstance(stmt, ast.Assign):
                rhs_repr = ast.unparse(stmt.value) if hasattr(ast, "unparse") else ""
                is_source = any(src in rhs_repr for src in TAINT_SOURCE_PATTERNS)

                # Contract-aware propagation: a resolved callee summary is authoritative
                # for whether its return value carries the taint of an argument.
                summary = self._resolve_call_summary(caller_mod, stmt.value, receivers)
                if summary is not None:
                    if summary.is_sanitizer:
                        is_derived = False
                    else:
                        is_derived = self._returns_tainted_arg(
                            stmt.value, summary.params, summary.tainted_returns, tainted_vars,
                            self._receiver_offset(caller_mod, stmt.value, summary),
                        )
                else:
                    is_derived = any(t_var in rhs_repr for t_var in tainted_vars)

                if is_source or is_derived:
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            tainted_vars.add(target.id)

            # Step B: Check external calls in this statement
            for call_node in [n for n in ast.walk(stmt) if isinstance(n, ast.Call)]:
                self._check_call_against_contracts(
                    caller_mod,
                    caller_file,
                    caller_func_name,
                    call_node,
                    tainted_vars,
                    receivers,
                )

    def _bind_call_args(
        self,
        call: ast.Call,
        param_names: List[str],
        arg_offset: int = 0,
    ) -> Dict[int, ast.AST]:
        """Maps parameter index -> argument AST expression for both args and kwargs.

        ``param_names`` comes from FunctionSummary.params, which drops the implicit
        ``self``/``cls`` receiver, so binding a normal method call needs no offset.
        ``arg_offset`` skips the leading positional argument of an unbound call; binding
        against SymbolDefinition.params (which keeps ``self``) would shift every
        parameter position by one instead.
        """
        bound: Dict[int, ast.AST] = {}
        # Positional
        for idx, arg in enumerate(call.args):
            param_idx = idx - arg_offset
            if 0 <= param_idx < len(param_names):
                bound[param_idx] = arg
        # Keywords
        param_to_idx = {name: idx for idx, name in enumerate(param_names)}
        for kw in call.keywords:
            if kw.arg and kw.arg in param_to_idx:
                bound[param_to_idx[kw.arg]] = kw.value
        return bound

    def _receiver_offset(self, caller_mod: str, call: ast.Call, summary: FunctionSummary) -> int:
        """1 when the callee is a method invoked unbound as `Class.method(receiver, ...)`.

        Contract parameter indices exclude the bound receiver, so the leading positional
        argument of an unbound call is the instance and must be skipped.
        """
        if not summary.takes_receiver or not isinstance(call.func, ast.Attribute):
            return 0
        receiver = call.func.value
        if not isinstance(receiver, ast.Name):
            return 0
        class_ref = self._class_of_name(receiver.id, caller_mod)
        if class_ref is None:
            return 0
        callee_class = summary.qualname.split(".", 1)[0]
        callee_mod = self.indexer.file_to_module.get(Path(summary.file_path).resolve())
        return 1 if class_ref == (callee_class, callee_mod) else 0

    def _resolve_call_contract(
        self,
        caller_mod: str,
        value: ast.expr,
        receivers: Optional[Dict[str, tuple[str, str]]] = None,
    ) -> Optional[tuple[str, FunctionSummary]]:
        """Return (callee module, contract) for a direct call expression, or None."""
        if not isinstance(value, ast.Call):
            return None

        if isinstance(value.func, ast.Name):
            call_name = value.func.id
        elif isinstance(value.func, ast.Attribute):
            resolved_method = self._resolve_method_contract(value.func, caller_mod, receivers)
            if resolved_method is not None:
                return resolved_method
            resolved_module = self._resolve_module_attribute_contract(value.func, caller_mod)
            if resolved_module is not None:
                return resolved_module
            call_name = value.func.attr
        else:
            return None

        symbol_def = self.indexer.resolve_symbol(caller_mod, call_name)
        if not symbol_def:
            return None

        callee_mod = self.indexer.file_to_module.get(Path(symbol_def.file_path).resolve())
        if not callee_mod:
            return None

        summary = self.contracts.get((callee_mod, symbol_def.name))
        if summary is None:
            return None
        return callee_mod, summary

    def _resolve_method_contract(
        self,
        func: ast.Attribute,
        caller_mod: str,
        receivers: Optional[Dict[str, tuple[str, str]]],
    ) -> Optional[tuple[str, FunctionSummary]]:
        """Resolve `receiver.method(...)` against the owning class's contract.

        FunctionSummarizer indexes methods under the qualified name 'Class.method', which a
        call site never spells out, so the receiver's class must be recovered from the local
        bindings, an inline construction, or the named class itself (unbound call). Returns
        None when the receiver type is unknown, letting the caller fall back to bare names.
        """
        class_ref: Optional[tuple[str, str]] = None
        if isinstance(func.value, ast.Name):
            class_ref = (receivers or {}).get(func.value.id) or self._class_of_name(func.value.id, caller_mod)
        elif isinstance(func.value, ast.Call):
            class_ref = self._instantiated_class(func.value, caller_mod)
        if class_ref is None:
            return None

        class_name, class_mod = class_ref
        return self._resolve_inherited_method((class_name, class_mod), func.attr)

    def _resolve_inherited_method(
        self,
        class_ref: tuple[str, str],
        attr: str,
    ) -> Optional[tuple[str, FunctionSummary]]:
        """Find `attr`'s contract on the class or, failing that, on its base classes.

        Contracts are keyed by the declaring class, so a call through a subclass instance
        never spells out the qualified name the base was indexed under. The search is
        breadth-first from the concrete class, which makes an override on the subclass win
        over an unsafe inherited fallback, and a visited set bounds the walk on cyclic or
        repeated inheritance.
        """
        pending = [class_ref]
        seen: Set[tuple[str, str]] = set()
        while pending:
            name, mod = pending.pop(0)
            if (name, mod) in seen:
                continue
            seen.add((name, mod))

            summary = self.contracts.get((mod, f"{name}.{attr}"))
            if summary is not None:
                return mod, summary

            for parent in self._base_classes(name, mod):
                if parent not in seen:
                    pending.append(parent)
        return None

    def _base_classes(self, class_name: str, class_mod: str) -> List[tuple[str, str]]:
        """Resolve the base classes of `class_name` to (class, module) pairs, in source order."""
        node = self._class_node(class_mod, class_name)
        if node is None:
            return []

        parents: List[tuple[str, str]] = []
        for base in node.bases:
            # Only a bare or dotted name identifies an inheritable class; call and subscript
            # bases (Generic[T], metaclass kwargs) carry no statically named class.
            if isinstance(base, ast.Name):
                parent = self._class_of_name(base.id, class_mod)
            elif isinstance(base, ast.Attribute):
                parent = self._class_of_name(base.attr, class_mod)
            else:
                parent = None
            if parent is not None:
                parents.append(parent)
        return parents

    def _class_node(self, mod_name: str, class_name: str) -> Optional[ast.ClassDef]:
        """Top-level ClassDef node for a module, as indexed by GlobalSymbolIndex."""
        tree = self.indexer._ast_cache.get(mod_name)
        if tree is None:
            return None
        for stmt in tree.body:
            if isinstance(stmt, ast.ClassDef) and stmt.name == class_name:
                return stmt
        return None

    def _resolve_module_attribute_contract(
        self,
        func: ast.Attribute,
        caller_mod: str,
    ) -> Optional[tuple[str, FunctionSummary]]:
        """Resolve `alias.func(...)` where the alias names an imported module.

        `import service as db_svc` binds a namespace rather than a symbol, so the function
        behind `db_svc.execute_query` is invisible to symbol resolution, which only knows
        explicitly imported names. Recovering the module from the import table and looking the
        attribute up in its contracts keeps the aliased call as precise as the direct one.
        """
        if not isinstance(func.value, ast.Name):
            return None
        target_mod = self._imported_module_of(func.value.id, caller_mod)
        if target_mod is None:
            return None
        summary = self.contracts.get((target_mod, func.attr))
        return None if summary is None else (target_mod, summary)

    def _imported_module_of(self, name: str, caller_mod: str) -> Optional[str]:
        """Module a bare Name refers to when it was bound by `import x[.y] [as name]`."""
        mod_idx = self.indexer.modules.get(caller_mod)
        if mod_idx is None:
            return None
        binding = mod_idx.imports.get(name)
        if binding is None or binding.imported_name:
            return None
        return self.indexer._match_registered_module(binding.source_module)

    def _decorator_sanitized_params(self, callee_mod: str, summary: FunctionSummary) -> Set[int]:
        """Parameter indices that a validating decorator neutralises before the body runs.

        ``@validated def view(record_id)`` whose wrapper calls ``func(int(record_id))`` can
        never observe a raw value in that slot, so a tainted argument there is not injectable
        and the call site must not be reported. Only one shape is trusted, because it is the
        only one that is provable: the decorator declares a nested wrapper, that wrapper takes
        the decorated function's parameters positionally without ``*args``/``**kwargs``, and
        its call to the wrapped function passes, per position, either the parameter untouched
        or a known sanitizer applied to exactly that parameter. A passthrough decorator
        therefore stays transparent, which is what keeps a timed or logged sink reportable.
        """
        key = (callee_mod, summary.qualname)
        cached = self._decorator_slots.get(key)
        if cached is not None:
            return cached

        node = self._function_node(callee_mod, summary.qualname)
        sanitized: Set[int] = set()
        if node is not None and summary.params:
            for decorator in node.decorator_list:
                definition = self._decorator_definition(callee_mod, decorator)
                if definition is not None:
                    sanitized |= self._wrapper_sanitized_slots(definition, summary.params)
        self._decorator_slots[key] = sanitized
        return sanitized

    def _decorator_definition(self, caller_mod: str, expr: ast.expr) -> Optional[ast.FunctionDef]:
        """FunctionDef of the decorator itself, resolving its name through the import table."""
        name = expr.id if isinstance(expr, ast.Name) else (
            expr.attr if isinstance(expr, ast.Attribute) else None
        )
        if name is None:
            return None
        symbol_def = self.indexer.resolve_symbol(caller_mod, name)
        if symbol_def is None or symbol_def.kind not in ("function", "async_function"):
            return None
        decorator_mod = self.indexer.file_to_module.get(Path(symbol_def.file_path).resolve())
        if decorator_mod is None:
            return None
        return self._function_node(decorator_mod, symbol_def.name)

    @staticmethod
    def _wrapper_sanitized_slots(
        decorator: ast.FunctionDef,
        decorated_params: List[str],
    ) -> Set[int]:
        """Slots the decorator's wrapper rebuilds through a sanitizer before calling through."""
        wrapper = next(
            (
                stmt
                for stmt in decorator.body
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
            ),
            None,
        )
        if (
            wrapper is None
            or wrapper.args.vararg
            or wrapper.args.kwarg
            or wrapper.args.kwonlyargs
        ):
            return set()

        wrapper_params = [arg.arg for arg in wrapper.args.args]
        if len(wrapper_params) != len(decorated_params):
            return set()

        wrapped_names = {arg.arg for arg in decorator.args.args}
        forwarded = next(
            (
                node
                for node in ast.walk(wrapper)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in wrapped_names
            ),
            None,
        )
        if forwarded is None or forwarded.keywords or len(forwarded.args) != len(decorated_params):
            return set()

        slots: Set[int] = set()
        for index, argument in enumerate(forwarded.args):
            source = wrapper_params[index]
            if _name_uses(argument) - {source}:
                continue
            if isinstance(argument, ast.Call):
                callee = argument.func
                callee_name = callee.id if isinstance(callee, ast.Name) else (
                    callee.attr if isinstance(callee, ast.Attribute) else None
                )
                if callee_name in KNOWN_SANITIZERS:
                    slots.add(index)
        return slots

    def _function_node(self, mod_name: str, qualname: str) -> Optional[ast.FunctionDef]:
        """FunctionDef node for a module and qualified name, as indexed by GlobalSymbolIndex."""
        tree = self.indexer._ast_cache.get(mod_name)
        if tree is None:
            return None
        head, _, tail = qualname.partition(".")
        for stmt in tree.body:
            if not tail:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name == head:
                    return stmt
            elif isinstance(stmt, ast.ClassDef) and stmt.name == head:
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == tail:
                        return item
        return None

    def _class_of_name(self, name: str, caller_mod: str) -> Optional[tuple[str, str]]:
        """(class name, defining module) when `name` resolves to an indexed class."""
        symbol_def = self.indexer.resolve_symbol(caller_mod, name)
        if symbol_def is None or symbol_def.kind != "class":
            return None
        class_mod = self.indexer.file_to_module.get(Path(symbol_def.file_path).resolve())
        if class_mod is None:
            return None
        return symbol_def.name, class_mod

    def _instantiated_class(
        self,
        call: ast.Call,
        caller_mod: str,
    ) -> Optional[tuple[str, str]]:
        """Class of a freshly built object: `ClassName(...).method()`."""
        ctor = call.func
        if not isinstance(ctor, ast.Name):
            return None
        return self._class_of_name(ctor.id, caller_mod)

    def _instance_bindings(
        self,
        caller_mod: str,
        caller_func: str,
        func_node: ast.AST,
    ) -> Dict[str, tuple[str, str]]:
        """Map receiver identifiers to (class name, defining module) inside one function.

        Collects `var = ClassName(...)` bindings in source order (a later rebinding wins) and,
        for methods, the implicit `self`/`cls` receiver derived from the qualified caller name.
        """
        bindings: Dict[str, tuple[str, str]] = {}
        if "." in caller_func:
            owning_class = (caller_func.split(".", 1)[0], caller_mod)
            bindings["self"] = owning_class
            bindings["cls"] = owning_class

        for node in _ordered_nodes(func_node, skip_scopes=True):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                continue
            ctor = node.value.func
            if not isinstance(ctor, ast.Name):
                continue
            class_ref = self._class_of_name(ctor.id, caller_mod)
            if class_ref is None:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bindings[target.id] = class_ref

        return bindings

    def _resolve_call_summary(
        self,
        caller_mod: str,
        value: ast.expr,
        receivers: Optional[Dict[str, tuple[str, str]]] = None,
    ) -> Optional[FunctionSummary]:
        """Return the contract for a direct call expression, or None if unresolved."""
        resolved = self._resolve_call_contract(caller_mod, value, receivers)
        return resolved[1] if resolved else None

    def _returns_tainted_arg(
        self,
        value: ast.Call,
        param_names: List[str],
        tainted_returns: Set[int],
        tainted_vars: Set[str],
        arg_offset: int = 0,
    ) -> bool:
        """True when an argument in a taint-propagating parameter position is tainted."""
        bound = self._bind_call_args(value, param_names, arg_offset)
        for param_idx in sorted(tainted_returns):
            arg = bound.get(param_idx)
            if arg is None:
                continue
            arg_names = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}
            if arg_names & tainted_vars:
                return True
        return False

    def _check_call_against_contracts(
        self,
        caller_mod: str,
        caller_file: str,
        caller_func_name: str,
        call: ast.Call,
        tainted_vars: set[str],
        receivers: Dict[str, tuple[str, str]],
    ) -> None:
        # Resolve callee symbol and contract (module-level call or class instance method)
        resolved = self._resolve_call_contract(caller_mod, call, receivers)
        if not resolved:
            return
        callee_mod, summary = resolved

        # Check if caller passed tainted arguments into callee's sink parameters
        neutralized = self._decorator_sanitized_params(callee_mod, summary)
        for arg_idx, arg in sorted(
            self._bind_call_args(call, summary.params, self._receiver_offset(caller_mod, call, summary)).items()
        ):
            if arg_idx in neutralized:
                continue
            arg_repr = ast.unparse(arg) if hasattr(ast, "unparse") else ""
            is_tainted_arg = any(t in arg_repr for t in tainted_vars) or any(src in arg_repr for src in TAINT_SOURCE_PATTERNS)

            if is_tainted_arg:
                # Check target sinks
                for sink in summary.param_sinks:
                    if sink.param_idx != arg_idx:
                        continue

                    trace_key = (callee_mod, summary.qualname, sink.param_idx,
                                 sink.sink_name, sink.lineno)
                    sink_file = self.sink_origins.get(trace_key, summary.file_path)
                    call_line = getattr(call, "lineno", 0)
                    flow_trace = [
                        TraceHop("SOURCE", caller_file, call_line,
                                 f"{caller_mod}.{caller_func_name}")
                    ]
                    flow_trace.extend(
                        TraceHop("ROUTE", route_file, route_line, route_func)
                        for route_file, route_line, route_func
                        in self.sink_route.get(trace_key, [])
                    )
                    flow_trace.append(
                        TraceHop("SINK", sink_file, sink.lineno,
                                 self._sink_descriptor(sink_file, sink.lineno, sink.sink_name))
                    )

                    self.findings.append(
                        CrossFileFinding(
                            cwe=sink.sink_cwe,
                            caller_file=caller_file,
                            caller_lineno=call_line,
                            caller_func=f"{caller_mod}.{caller_func_name}",
                            callee_file=sink_file,
                            callee_func=f"{callee_mod}.{summary.qualname}",
                            callee_sink_name=sink.sink_name,
                            callee_sink_lineno=sink.lineno,
                            tainted_param=sink.param_name,
                            flow_trace=flow_trace,
                        )
                    )

    def _sink_descriptor(self, file_path: str, lineno: int, fallback: str) -> str:
        """Recover how the sink was written (e.g. 'cursor.execute') from its source line."""
        mod_name = self.indexer.file_to_module.get(Path(file_path).resolve())
        tree = self.indexer._ast_cache.get(mod_name) if mod_name else None
        if tree is None or not hasattr(ast, "unparse"):
            return fallback

        candidates = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and getattr(node, "lineno", 0) == lineno
        ]
        if not candidates:
            return fallback
        for node in candidates:
            if isinstance(node.func, ast.Attribute):
                tail = node.func.attr
            elif isinstance(node.func, ast.Name):
                tail = node.func.id
            else:
                tail = None
            if tail == fallback:
                return ast.unparse(node.func)
        return ast.unparse(candidates[0].func)


if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[*] Starting TimeCodeSecurity Cross-File Taint Engine on: {target_dir}")
    t0 = time.perf_counter()

    engine = CrossFileTaintEngine(target_dir)
    findings = engine.run()
    elapsed = (time.perf_counter() - t0) * 1000

    print("\n=================================================================")
    print("        TIMECODESECURITY (TCS) - CROSS-FILE ANALYSIS REPORT       ")
    print("=================================================================")
    print(f"Execution Time:              {elapsed:.2f} ms")
    print(f"Total Cross-File Exploits:   {len(findings)}")
    print("-----------------------------------------------------------------")

    if findings:
        for i, f in enumerate(findings, 1):
            print(f"\n[{i}] VULNERABILITY: {f.cwe}")
            print(f"    Source Call-site: {f.caller_func} ({f.caller_file}:{f.caller_lineno})")
            print(f"    Flows Into:       {f.callee_func} (Param: '{f.tainted_param}')")
            print(f"    Exploit Sink:     {f.callee_sink_name} at {f.callee_file}:{f.callee_sink_lineno}")
    else:
        print("[+] No unhandled cross-file taint leaks detected.")