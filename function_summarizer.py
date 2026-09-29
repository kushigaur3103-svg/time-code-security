"""
TimeCodeSecurity (TCS) - Phase 4: Function Summary Extractor
Extracts deterministic taint contracts (Param -> Return, Param -> Sink) per function.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from symbol_indexer import GlobalSymbolIndex, SymbolDefinition


KNOWN_SINKS = {
    # CWE-89: SQL Injection
    "execute": "CWE-89",
    "executemany": "CWE-89",
    "raw": "CWE-89",
    # CWE-78: Command Injection
    "system": "CWE-78",
    "popen": "CWE-78",
    "check_output": "CWE-78",
    "call": "CWE-78",
    "run": "CWE-78",
    # CWE-95 / 94: Code Exec
    "eval": "CWE-95",
    "exec": "CWE-94",
    # CWE-502: Deserialization
    "loads": "CWE-502",
    "load": "CWE-502",
    # CWE-22: Path Traversal
    "open": "CWE-22",
}

KNOWN_SANITIZERS = {
    "int", "float", "bool", "len", "escape", "quote", "sha256", "md5"
}


def _has_static_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True for a @staticmethod, whose first parameter is a real argument, not a receiver."""
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id == "staticmethod":
            return True
        if isinstance(decorator, ast.Attribute) and decorator.attr == "staticmethod":
            return True
    return False


def _const_str(node: Optional[ast.AST]) -> Optional[str]:
    """The literal string a key expression holds, or None when it is not one."""
    if isinstance(node, ast.Index):  # Python < 3.9 keeps `d["k"]` as ast.Index
        node = node.value
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


@dataclass(slots=True)
class ParamSinkEdge:
    param_idx: int
    param_name: str
    sink_cwe: str
    sink_name: str
    lineno: int


@dataclass
class FunctionSummary:
    qualname: str
    file_path: str
    lineno: int
    params: list[str] = field(default_factory=list)
    tainted_returns: set[int] = field(default_factory=set)  # indices of params that reach 'return'
    param_sinks: list[ParamSinkEdge] = field(default_factory=list)  # params that hit an internal sink
    is_sanitizer: bool = False
    # True when the signature opens with self/cls, i.e. params excludes a bound receiver.
    # Callers that invoke the method unbound (Class.method(instance, ...)) must skip one
    # positional argument so parameter indices stay aligned with params.
    takes_receiver: bool = False


class FunctionSummarizer:
    """Pass 1.5: Computes taint contracts for all indexed functions."""

    def __init__(self, indexer: GlobalSymbolIndex):
        self.indexer = indexer
        self.summaries: dict[tuple[str, str], FunctionSummary] = {}  # (mod_name, func_name) -> Summary

    def build_all_summaries(self) -> dict[tuple[str, str], FunctionSummary]:
        for mod_name, mod_idx in self.indexer.modules.items():
            tree = self.indexer._ast_cache.get(mod_name)
            if not tree:
                continue

            for stmt in tree.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    summary = self._summarize_function(stmt, mod_name, str(mod_idx.file_path))
                    self.summaries[(mod_name, stmt.name)] = summary
                elif isinstance(stmt, ast.ClassDef):
                    for item in stmt.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            qual = f"{stmt.name}.{item.name}"
                            summary = self._summarize_function(
                                item, mod_name, str(mod_idx.file_path),
                                qualname=qual, is_method=True,
                            )
                            self.summaries[(mod_name, qual)] = summary

        return self.summaries

    def _summarize_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        mod_name: str,
        file_path: str,
        qualname: Optional[str] = None,
        is_method: bool = False,
    ) -> FunctionSummary:
        name = qualname or node.name
        takes_receiver = bool(
            is_method
            and not _has_static_decorator(node)
            and node.args.args
            and node.args.args[0].arg in ("self", "cls")
        )
        params = [a.arg for a in (node.args.args[1:] if takes_receiver else node.args.args)]
        kw_containers, kw_slots = self._kwarg_slots(node, params)
        params = params + kw_slots
        param_to_idx = {p: i for i, p in enumerate(params)}

        summary = FunctionSummary(
            qualname=name,
            file_path=file_path,
            lineno=node.lineno,
            params=params,
            takes_receiver=takes_receiver,
        )

        # Sanitizer heuristic
        if any(san in name.lower() for san in KNOWN_SANITIZERS):
            summary.is_sanitizer = True

        # Intra-function variable flow tracking
        # Maps local_var -> set of param indices it was derived from
        alias_map: dict[str, set[int]] = {p: {i} for i, p in enumerate(params)}

        for stmt in node.body:
            for sub in ast.walk(stmt):
                # 1. Track assignments: local_var = param
                if isinstance(sub, ast.Assign):
                    val_params = self._resolve_referenced_params(sub.value, alias_map, kw_containers)
                    if val_params:
                        for target in sub.targets:
                            if isinstance(target, ast.Name):
                                alias_map.setdefault(target.id, set()).update(val_params)

                # 2. Track Returns: return param / return expr(param)
                elif isinstance(sub, ast.Return) and sub.value is not None:
                    ret_params = self._resolve_referenced_params(sub.value, alias_map, kw_containers)
                    summary.tainted_returns.update(ret_params)

                # 3. Track Sinks: sink_call(param)
                elif isinstance(sub, ast.Call):
                    call_name = ""
                    if isinstance(sub.func, ast.Name):
                        call_name = sub.func.id
                    elif isinstance(sub.func, ast.Attribute):
                        call_name = sub.func.attr

                    cwe = KNOWN_SINKS.get(call_name)
                    if cwe:
                        for position, arg in enumerate(sub.args):
                            # DB-API semantics: execute(operation, parameters) interpolates
                            # only the operation slot into the statement, so taint that reaches
                            # the parameters slot is bound by the driver and not injectable.
                            if cwe == "CWE-89" and position > 0:
                                continue
                            arg_params = self._resolve_referenced_params(arg, alias_map, kw_containers)
                            for p_idx in arg_params:
                                edge = ParamSinkEdge(
                                    param_idx=p_idx,
                                    param_name=params[p_idx],
                                    sink_cwe=cwe,
                                    sink_name=call_name,
                                    lineno=getattr(sub, "lineno", stmt.lineno),
                                )
                                summary.param_sinks.append(edge)

        # Body-level sanitizer evidence: the name heuristic above misses helpers such as
        # `format_command` that sanitize through a call rather than through their own name.
        if not summary.is_sanitizer and params and not summary.param_sinks:
            sanitized_locals = self._sanitized_locals(node)
            propagating = [
                ret.value
                for ret in ast.walk(node)
                if isinstance(ret, ast.Return)
                and ret.value is not None
                and self._resolve_referenced_params(ret.value, alias_map, kw_containers)
            ]
            if propagating and all(
                self._is_sanitized_expr(expr, sanitized_locals) for expr in propagating
            ):
                summary.is_sanitizer = True

        return summary

    @staticmethod
    def _callee_name(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    def _sanitized_locals(self, node: ast.AST) -> Set[str]:
        """Local names bound to a value produced by a known sanitizer call."""
        sanitized: Set[str] = set()
        for stmt in node.body:
            for sub in ast.walk(stmt):
                if not isinstance(sub, ast.Assign):
                    continue
                callee = self._callee_name(sub.value.func) if isinstance(sub.value, ast.Call) else None
                produced_by_sanitizer = callee in KNOWN_SANITIZERS
                for target in sub.targets:
                    if isinstance(target, ast.Name):
                        if produced_by_sanitizer:
                            sanitized.add(target.id)
                        else:
                            sanitized.discard(target.id)
        return sanitized

    def _is_sanitized_expr(self, expr: ast.AST, sanitized_locals: Set[str]) -> bool:
        if isinstance(expr, ast.Call):
            return self._callee_name(expr.func) in KNOWN_SANITIZERS
        if isinstance(expr, ast.Name):
            return expr.id in sanitized_locals
        return False

    def _resolve_referenced_params(
        self,
        expr: ast.AST,
        alias_map: dict[str, set[int]],
        kw_containers: frozenset[str] = frozenset(),
    ) -> set[int]:
        referenced: set[int] = set()
        for node in ast.walk(expr):
            if isinstance(node, ast.Name) and node.id in alias_map:
                referenced.update(alias_map[node.id])
            elif kw_containers:
                slot = self._kwarg_slot(node, kw_containers)
                if slot is not None and f"{slot[0]}[{slot[1]}]" in alias_map:
                    referenced.update(alias_map[f"{slot[0]}[{slot[1]}]"])
        return referenced

    @staticmethod
    def _kwarg_slot(node: ast.AST, kw_containers: frozenset[str]) -> Optional[tuple[str, str]]:
        """(container, literal key) for `kwargs["k"]` / `kwargs.get("k")` reads."""
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            if node.value.id in kw_containers:
                key = _const_str(node.slice)
                return (node.value.id, key) if key is not None else None
            return None
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("get", "pop") and node.args
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in kw_containers):
            key = _const_str(node.args[0])
            return (node.func.value.id, key) if key is not None else None
        return None

    @staticmethod
    def _kwarg_slots(
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        params: list[str],
    ) -> tuple[frozenset[str], list[str]]:
        """Per-key contract slots for a `**kwargs` parameter.

        Django signal receivers take their payload through `**kwargs`, so a receiver such as
        `def on_event(sender, **kwargs): os.system(kwargs["payload"])` has no positional
        parameter to bind the emission keyword onto. Only the literal keys the body actually
        reads become slots, which keeps each payload key tracked on its own instead of tainting
        the whole mapping.
        """
        if node.args.kwarg is None:
            return frozenset(), []
        container = node.args.kwarg.arg
        if container in params:
            return frozenset(), []
        slots: list[str] = []
        seen = {container}
        for sub in ast.walk(node):
            slot = FunctionSummarizer._kwarg_slot(sub, frozenset({container}))
            if slot is None:
                continue
            virtual = f"{slot[0]}[{slot[1]}]"
            if virtual not in seen:
                seen.add(virtual)
                slots.append(virtual)
        return frozenset({container}), slots


if __name__ == "__main__":
    import time

    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[*] Building Symbol Index for: {target_dir}")
    indexer = GlobalSymbolIndex(target_dir).build()

    print("[*] Extracting Function Taint Contracts...")
    t0 = time.perf_counter()
    summarizer = FunctionSummarizer(indexer)
    contracts = summarizer.build_all_summaries()
    elapsed = (time.perf_counter() - t0) * 1000

    total_funcs = len(contracts)
    funcs_with_sinks = sum(1 for c in contracts.values() if c.param_sinks)
    funcs_with_returns = sum(1 for c in contracts.values() if c.tainted_returns)

    print("\n--- FUNCTION TAINT CONTRACTS SUMMARY ---")
    print(f"Total Functions Summarized:     {total_funcs}")
    print(f"Functions Propagating to Return: {funcs_with_returns}")
    print(f"Functions Leading to Sinks:     {funcs_with_sinks}")
    print(f"Contract Analysis Time:         {elapsed:.2f} ms")

    # Sample dangerous sink contracts
    if funcs_with_sinks > 0:
        print("\n[+] Top Identified Sink Contracts:")
        count = 0
        for (m, f), c in contracts.items():
            for s in c.param_sinks:
                print(f"  • {m}.{f}(param '{s.param_name}') -> {s.sink_name} [{s.sink_cwe}] at line {s.lineno}")
                count += 1
                if count >= 5:
                    break
            if count >= 5:
                break